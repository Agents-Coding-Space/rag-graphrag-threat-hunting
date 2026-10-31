from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest

from threat_hunting.ground_truth import (
    build_ground_truth_core,
    validate_ground_truth_document,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "build_mshta_ground_truth.py"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "ground_truth" / "builder"
INPUT_FILES = {
    "scenario_evidence": "scenario_evidence.json",
    "sigma_review": "sigma_match_review.json",
    "mitre_resolution": "mitre_resolution.json",
    "build_config": "build_config.json",
}
PATH_FLAGS = {
    "scenario_evidence": "--scenario-evidence",
    "sigma_review": "--sigma-review",
    "mitre_resolution": "--mitre-resolution",
    "build_config": "--build-config",
}
HASH_FLAGS = {
    "scenario_evidence": "--expected-scenario-evidence-sha256",
    "sigma_review": "--expected-sigma-review-sha256",
    "mitre_resolution": "--expected-mitre-resolution-sha256",
    "build_config": "--expected-build-config-sha256",
}
PROVENANCE_IDS = {
    "scenario_evidence": "scenario-evidence-input",
    "sigma_review": "sigma-review-input",
    "mitre_resolution": "mitre-resolution-input",
}
FORBIDDEN_QUESTION_FIELDS = {
    "evaluation_questions",
    "expected_answers",
    "question_id",
    "question_text",
    "expected_answer",
    "answer_id",
}


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _write_json(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _copy_inputs(tmp_path: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for label, filename in INPUT_FILES.items():
        destination = tmp_path / filename
        shutil.copyfile(FIXTURE_ROOT / filename, destination)
        paths[label] = destination
    return paths


def _command(
    paths: dict[str, Path],
    output: Path,
    *,
    overwrite: bool = False,
    expected_overrides: dict[str, str] | None = None,
) -> list[str]:
    expected_overrides = expected_overrides or {}
    command = [sys.executable, str(SCRIPT)]
    for label in INPUT_FILES:
        command.extend((PATH_FLAGS[label], str(paths[label])))
    command.extend(("--output", str(output)))
    for label in INPUT_FILES:
        command.extend(
            (
                HASH_FLAGS[label],
                expected_overrides.get(label, _sha256(paths[label])),
            )
        )
    if overwrite:
        command.append("--overwrite")
    return command


def _run(
    paths: dict[str, Path],
    output: Path,
    *,
    overwrite: bool = False,
    expected_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(
            paths,
            output,
            overwrite=overwrite,
            expected_overrides=expected_overrides,
        ),
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _successful_build(tmp_path: Path) -> tuple[dict[str, Path], Path, dict[str, Any]]:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    completed = _run(paths, output)
    assert completed.returncode == 0, completed.stderr
    return paths, output, json.loads(completed.stdout)


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def test_cli_builds_synthetic_ground_truth_and_reports_complete_stats(
    tmp_path: Path,
) -> None:
    _, output, stats = _successful_build(tmp_path)

    assert output.is_file()
    assert stats == {
        "analysis_status": "draft_reviewable",
        "entities": 3,
        "evidence": 2,
        "facts": 2,
        "input_provenance": 3,
        "input_sha256": {
            label: _sha256(tmp_path / filename)
            for label, filename in INPUT_FILES.items()
        },
        "mitre_assessments": 2,
        "output_path": output.name,
        "output_sha256": _sha256(output),
        "relationships": 2,
        "review_status": "pending_human_review",
        "scenario_id": "scenario-synthetic-builder",
        "schema_version": "scenario-ground-truth/v1",
        "sigma_findings": 2,
    }


def test_cli_output_passes_ground_truth_validator(tmp_path: Path) -> None:
    _, output, _ = _successful_build(tmp_path)

    validate_ground_truth_document(_json(output))


def test_cli_output_equals_direct_builder_result(tmp_path: Path) -> None:
    paths, output, _ = _successful_build(tmp_path)
    documents = {label: _json(path) for label, path in paths.items()}
    provenance = [
        {
            "input_id": PROVENANCE_IDS[label],
            "input_type": label,
            "path": paths[label].name,
            "schema_version": documents[label]["schema_version"],
            "sha256": _sha256(paths[label]),
            "scenario_id": documents[label]["scenario_id"],
        }
        for label in ("scenario_evidence", "sigma_review", "mitre_resolution")
    ]

    expected = build_ground_truth_core(
        scenario_evidence=documents["scenario_evidence"],
        sigma_review=documents["sigma_review"],
        mitre_resolution=documents["mitre_resolution"],
        input_provenance=provenance,
        build_config=documents["build_config"],
    )
    assert _json(output) == expected


def test_input_provenance_has_exact_artifact_types_paths_and_hashes(
    tmp_path: Path,
) -> None:
    paths, output, _ = _successful_build(tmp_path)
    provenance = _json(output)["input_provenance"]

    assert len(provenance) == 3
    assert {item["input_type"] for item in provenance} == {
        "scenario_evidence",
        "sigma_review",
        "mitre_resolution",
    }
    for item in provenance:
        label = item["input_type"]
        source = _json(paths[label])
        assert item == {
            "input_id": PROVENANCE_IDS[label],
            "input_type": label,
            "path": paths[label].name,
            "schema_version": source["schema_version"],
            "sha256": _sha256(paths[label]),
            "scenario_id": source["scenario_id"],
        }


def test_two_cli_runs_are_byte_identical(tmp_path: Path) -> None:
    paths, output, first_stats = _successful_build(tmp_path)
    first_bytes = output.read_bytes()

    second = _run(paths, output, overwrite=True)

    assert second.returncode == 0, second.stderr
    assert output.read_bytes() == first_bytes
    assert json.loads(second.stdout) == first_stats


def test_overwrite_replaces_existing_output(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    output.write_bytes(b"obsolete\n")

    completed = _run(paths, output, overwrite=True)

    assert completed.returncode == 0, completed.stderr
    validate_ground_truth_document(_json(output))


def test_existing_output_is_rejected_without_overwrite(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    original = b"do not replace\n"
    output.write_bytes(original)

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "--overwrite" in completed.stderr
    assert output.read_bytes() == original


@pytest.mark.parametrize("label", tuple(INPUT_FILES))
def test_expected_input_hash_mismatch_is_rejected(
    tmp_path: Path, label: str
) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"

    completed = _run(paths, output, expected_overrides={label: "0" * 64})

    assert completed.returncode == 2
    assert "SHA-256 mismatch" in completed.stderr
    assert label in completed.stderr
    assert not output.exists()


def test_duplicate_json_object_key_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    paths["build_config"].write_text(
        '{"schema_version":"ground-truth-build-config/v1",'
        '"schema_version":"ground-truth-build-config/v1"}\n',
        encoding="utf-8",
    )

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "duplicate JSON object key" in completed.stderr
    assert not output.exists()


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    paths["sigma_review"].write_text('{"schema_version": ', encoding="utf-8")

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "malformed JSON" in completed.stderr
    assert not output.exists()


def test_non_object_json_top_level_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    paths["scenario_evidence"].write_text("[]\n", encoding="utf-8")

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "JSON top level must be an object" in completed.stderr
    assert not output.exists()


def test_artifact_schema_mismatch_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    document = _json(paths["mitre_resolution"])
    document["schema_version"] = "mitre-resolution/v999"
    _write_json(paths["mitre_resolution"], document)

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "schema_version" in completed.stderr
    assert not output.exists()


def test_cross_artifact_scenario_mismatch_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    document = _json(paths["sigma_review"])
    document["scenario_id"] = "scenario-other"
    _write_json(paths["sigma_review"], document)

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert "scenario_id" in completed.stderr
    assert not output.exists()


def test_builder_error_leaves_no_partial_output(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"
    config = _json(paths["build_config"])
    config["facts"][0]["evidence_ids"] = ["missing-evidence"]
    _write_json(paths["build_config"], config)

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert not output.exists()


def test_cli_leaves_no_temporary_file_after_success_or_failure(
    tmp_path: Path,
) -> None:
    paths, output, _ = _successful_build(tmp_path)
    output.unlink()
    config = _json(paths["build_config"])
    config["facts"][0]["evidence_ids"] = ["missing-evidence"]
    _write_json(paths["build_config"], config)

    completed = _run(paths, output)

    assert completed.returncode == 2
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_cli_does_not_modify_any_input(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    before = {label: path.read_bytes() for label, path in paths.items()}
    output = tmp_path / "scenario_ground_truth.json"

    completed = _run(paths, output)

    assert completed.returncode == 0, completed.stderr
    assert {label: path.read_bytes() for label, path in paths.items()} == before


def test_output_contains_no_confirmed_status(tmp_path: Path) -> None:
    _, output, _ = _successful_build(tmp_path)

    assert all(
        not (isinstance(value, str) and value.casefold() == "confirmed")
        for value in _walk(_json(output))
    )


def test_output_contains_no_question_or_expected_answer_fields(tmp_path: Path) -> None:
    _, output, _ = _successful_build(tmp_path)

    values = _walk(_json(output))
    assert all(field not in values for field in FORBIDDEN_QUESTION_FIELDS)


def test_script_logic_has_no_production_behavior_or_knowledge_ids() -> None:
    source = SCRIPT.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta.exe",
        "powershell.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:275",
        "jsonl:line:398",
    ):
        assert forbidden not in source


def test_all_explicit_arguments_allow_unrelated_synthetic_fixture(
    tmp_path: Path,
) -> None:
    paths, output, stats = _successful_build(tmp_path)

    assert stats["scenario_id"] == "scenario-synthetic-builder"
    assert all("mshta" not in item["path"].casefold() for item in _json(output)["input_provenance"])
    assert paths["build_config"].name not in {
        item["path"] for item in _json(output)["input_provenance"]
    }


def test_invalid_expected_hash_format_is_rejected_before_build(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "scenario_ground_truth.json"

    completed = _run(
        paths,
        output,
        expected_overrides={"scenario_evidence": "not-a-sha256"},
    )

    assert completed.returncode == 2
    assert "exactly 64 hexadecimal characters" in completed.stderr
    assert not output.exists()


def test_source_fixture_documents_are_not_mutated_in_memory(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    before = {label: deepcopy(_json(path)) for label, path in paths.items()}
    output = tmp_path / "scenario_ground_truth.json"

    completed = _run(paths, output)

    assert completed.returncode == 0, completed.stderr
    assert {label: _json(path) for label, path in paths.items()} == before
