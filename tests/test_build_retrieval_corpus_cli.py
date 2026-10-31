from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from threat_hunting.ground_truth import load_ground_truth_document
from threat_hunting.retrieval import (
    build_retrieval_corpus,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)


REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "build_retrieval_corpus.py"
GROUND_TRUTH_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "ground_truth"
    / "builder"
    / "expected_ground_truth.json"
)
EXPECTED_CHUNK_COUNTS = {
    "entity": 3,
    "evidence": 2,
    "fact": 2,
    "limitation": 1,
    "mitre_assessment": 2,
    "relationship": 2,
    "scenario_summary": 1,
    "sigma_finding": 2,
}
FORBIDDEN_FIELDS = {
    "answer_id",
    "embedding",
    "embedding_model",
    "evaluation_questions",
    "expected_answer",
    "expected_answers",
    "llm_response",
    "question_id",
    "question_text",
    "questions",
    "vector",
}


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _copy_input(tmp_path: Path) -> Path:
    input_path = tmp_path / "ground_truth.json"
    shutil.copyfile(GROUND_TRUTH_FIXTURE, input_path)
    return input_path


def _command(
    input_path: Path,
    output_path: Path,
    *,
    expected_hash: str | None = None,
    expected_scenario: str = "scenario-synthetic-builder",
    overwrite: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--expected-input-sha256",
        expected_hash or _sha256(input_path),
        "--expected-scenario-id",
        expected_scenario,
    ]
    if overwrite:
        command.append("--overwrite")
    return command


def _run(
    input_path: Path,
    output_path: Path,
    **kwargs: object,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(input_path, output_path, **kwargs),  # type: ignore[arg-type]
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _successful_build(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"
    result = _run(input_path, output_path)
    assert result.returncode == 0, result.stderr
    return input_path, output_path, json.loads(result.stdout)


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def test_cli_builds_expected_chunk_distribution_and_stats(tmp_path: Path) -> None:
    input_path, output_path, stats = _successful_build(tmp_path)
    corpus = _json(output_path)

    assert stats == {
        "chunk_counts": EXPECTED_CHUNK_COUNTS,
        "corpus_id": corpus["corpus_id"],
        "input_path": input_path.name,
        "input_sha256": _sha256(input_path),
        "output_path": output_path.name,
        "output_sha256": _sha256(output_path),
        "review_status": "pending_human_review",
        "scenario_id": "scenario-synthetic-builder",
        "schema_version": "retrieval-corpus/v1",
        "total_chunks": 15,
    }


def test_cli_output_passes_retrieval_loader_and_validator(tmp_path: Path) -> None:
    _, output_path, _ = _successful_build(tmp_path)

    corpus = load_retrieval_corpus(output_path)
    validate_retrieval_corpus(corpus)


def test_cli_output_equals_direct_builder_result(tmp_path: Path) -> None:
    input_path, output_path, _ = _successful_build(tmp_path)
    ground_truth = load_ground_truth_document(input_path)
    expected = build_retrieval_corpus(
        ground_truth,
        source_ground_truth_path=input_path.name,
        source_ground_truth_sha256=_sha256(input_path),
    )

    assert _json(output_path) == expected


def test_cli_rejects_input_hash_mismatch_without_output(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path, expected_hash="0" * 64)

    assert result.returncode == 2
    assert "SHA-256 mismatch before build" in result.stderr
    assert not output_path.exists()


def test_cli_rejects_scenario_mismatch_without_output(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(
        input_path,
        output_path,
        expected_scenario="different-synthetic-scenario",
    )

    assert result.returncode == 2
    assert "scenario_id mismatch" in result.stderr
    assert not output_path.exists()


def test_cli_rejects_wrong_ground_truth_schema_version(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    document = _json(input_path)
    document["schema_version"] = "scenario-ground-truth/v0"
    input_path.write_text(json.dumps(document), encoding="utf-8")
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert "schema_version" in result.stderr
    assert not output_path.exists()


def test_cli_rejects_malformed_json(tmp_path: Path) -> None:
    input_path = tmp_path / "ground_truth.json"
    input_path.write_text('{"schema_version":', encoding="utf-8")
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert "Cannot read ground truth document" in result.stderr
    assert "Expecting value" in result.stderr
    assert not output_path.exists()


def test_cli_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    text = input_path.read_text(encoding="utf-8")
    text = text.replace(
        '"schema_version": "scenario-ground-truth/v1",',
        '"schema_version": "scenario-ground-truth/v1",\n'
        '  "schema_version": "scenario-ground-truth/v1",',
        1,
    )
    input_path.write_text(text, encoding="utf-8")
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert "duplicate JSON object key" in result.stderr
    assert not output_path.exists()


def test_cli_rejects_non_object_json(tmp_path: Path) -> None:
    input_path = tmp_path / "ground_truth.json"
    input_path.write_text("[]", encoding="utf-8")
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert "JSON object" in result.stderr
    assert not output_path.exists()


def test_cli_refuses_existing_output_without_overwrite(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"
    original = b"existing-output-must-survive"
    output_path.write_bytes(original)

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert "--overwrite" in result.stderr
    assert output_path.read_bytes() == original


def test_cli_overwrites_existing_output_when_requested(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"
    output_path.write_bytes(b"old-output")

    result = _run(input_path, output_path, overwrite=True)

    assert result.returncode == 0, result.stderr
    assert load_retrieval_corpus(output_path)["schema_version"] == (
        "retrieval-corpus/v1"
    )


def test_two_cli_runs_are_byte_identical(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"

    first = _run(input_path, output_path)
    first_bytes = output_path.read_bytes()
    second = _run(input_path, output_path, overwrite=True)

    assert first.returncode == second.returncode == 0
    assert output_path.read_bytes() == first_bytes


def test_cli_leaves_no_temporary_file_after_success(tmp_path: Path) -> None:
    _, output_path, _ = _successful_build(tmp_path)

    assert not output_path.with_name(f".{output_path.name}.tmp").exists()


def test_cli_leaves_no_temporary_file_after_validation_failure(
    tmp_path: Path,
) -> None:
    input_path = _copy_input(tmp_path)
    document = _json(input_path)
    del document["scenario"]
    input_path.write_text(json.dumps(document), encoding="utf-8")
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path)

    assert result.returncode == 2
    assert not output_path.exists()
    assert not output_path.with_name(f".{output_path.name}.tmp").exists()


def test_cli_does_not_modify_input_bytes_or_hash(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    before = input_path.read_bytes()
    before_hash = _sha256(input_path)

    result = _run(input_path, tmp_path / "retrieval_corpus.json")

    assert result.returncode == 0, result.stderr
    assert input_path.read_bytes() == before
    assert _sha256(input_path) == before_hash


def test_cli_records_portable_relative_source_path(tmp_path: Path) -> None:
    input_path, output_path, _ = _successful_build(tmp_path)
    source_path = _json(output_path)["source_ground_truth"]["path"]

    assert source_path == input_path.name
    assert "\\" not in source_path
    assert not Path(source_path).is_absolute()


def test_cli_output_never_contains_confirmed(tmp_path: Path) -> None:
    _, output_path, _ = _successful_build(tmp_path)

    assert all(
        not (isinstance(value, str) and value.casefold() == "confirmed")
        for value in _walk(_json(output_path))
    )


def test_cli_output_has_no_question_or_expected_answer_fields(
    tmp_path: Path,
) -> None:
    _, output_path, _ = _successful_build(tmp_path)
    string_values = {value for value in _walk(_json(output_path)) if isinstance(value, str)}

    assert FORBIDDEN_FIELDS.isdisjoint(string_values)


def test_cli_output_has_no_embedding_vector_or_llm_fields(tmp_path: Path) -> None:
    _, output_path, _ = _successful_build(tmp_path)
    string_values = {value for value in _walk(_json(output_path)) if isinstance(value, str)}

    assert {"embedding", "embedding_model", "vector", "llm_response"}.isdisjoint(
        string_values
    )


def test_cli_source_has_no_production_scenario_hash_or_ids() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta-powershell",
        "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
        "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
        "t1059.007",
        "t1140",
        "t1218.005",
        "mshta.exe",
        "powershell.exe",
    ):
        assert forbidden not in source


def test_cli_source_has_no_clock_random_or_uuid_logic() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "datetime.now",
        "time.time",
        "import random",
        "import uuid",
        "uuid4",
    ):
        assert forbidden not in source


def test_cli_rejects_same_input_and_output_without_modifying_input(
    tmp_path: Path,
) -> None:
    input_path = _copy_input(tmp_path)
    before = input_path.read_bytes()

    result = _run(input_path, input_path, overwrite=True)

    assert result.returncode == 2
    assert "different paths" in result.stderr
    assert input_path.read_bytes() == before


def test_cli_rejects_invalid_expected_hash_format(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "retrieval_corpus.json"

    result = _run(input_path, output_path, expected_hash="not-a-sha256")

    assert result.returncode == 2
    assert "64 hexadecimal" in result.stderr
    assert not output_path.exists()


def test_cli_does_not_mutate_loaded_document_in_process(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    before = deepcopy(load_ground_truth_document(input_path))

    result = _run(input_path, tmp_path / "retrieval_corpus.json")

    assert result.returncode == 0, result.stderr
    assert load_ground_truth_document(input_path) == before
