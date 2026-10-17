from __future__ import annotations

import json
from pathlib import Path

import scripts.extract_mshta_evidence as cli
from threat_hunting.schemas.canonical_event import canonical_schema_document


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "evidence"
    / "mshta_powershell_canonical.jsonl"
)


def _schema(path: Path) -> Path:
    path.write_text(
        json.dumps(canonical_schema_document(), ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def test_cli_extracts_fixture_with_auditable_counts_and_valid_output(
    tmp_path: Path,
    capsys,
) -> None:
    schema = _schema(tmp_path / "canonical_schema.json")
    output = tmp_path / "scenario_evidence.json"
    original_input = FIXTURE.read_bytes()

    exit_code = cli.main(
        [
            "--input",
            str(FIXTURE),
            "--canonical-schema",
            str(schema),
            "--output",
            str(output),
            "--expected-event-count",
            "4",
        ]
    )

    assert exit_code == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats == {
        "canonical_schema_version": "canonical-event/v2",
        "output_schema_version": "scenario-evidence/v1",
        "input_events": 4,
        "examined_events": 4,
        "matched_events": 4,
        "unmatched_events": 0,
        "entities": 3,
        "relationships": 2,
        "evidence": 2,
        "source_references": 4,
        "correlated_telemetry_pairs": 2,
        "rejected_events": 0,
        "unprocessed_events": 0,
        "warnings": [],
        "output_path": str(output.resolve()),
    }
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == "scenario-evidence/v1"
    assert document["analysis_status"] == "draft_reviewable"
    assert len(document["observed_entities"]) == 3
    assert len(document["relationships"]) == 2
    assert len(document["evidence"]) == 2
    assert FIXTURE.read_bytes() == original_input


def test_cli_overwrite_is_deterministic(tmp_path: Path, capsys) -> None:
    schema = _schema(tmp_path / "canonical_schema.json")
    output = tmp_path / "scenario_evidence.json"
    arguments = [
        "--input",
        str(FIXTURE),
        "--canonical-schema",
        str(schema),
        "--output",
        str(output),
        "--expected-event-count",
        "4",
        "--overwrite",
    ]

    assert cli.main(arguments) == 0
    first = output.read_bytes()
    capsys.readouterr()
    assert cli.main(arguments) == 0
    second = output.read_bytes()

    assert first == second


def test_cli_rejects_wrong_count_without_output(
    tmp_path: Path,
    capsys,
) -> None:
    schema = _schema(tmp_path / "canonical_schema.json")
    output = tmp_path / "scenario_evidence.json"

    exit_code = cli.main(
        [
            "--input",
            str(FIXTURE),
            "--canonical-schema",
            str(schema),
            "--output",
            str(output),
            "--expected-event-count",
            "5",
        ]
    )

    assert exit_code == 2
    assert "expected 5, found 4" in capsys.readouterr().err
    assert not output.exists()


def test_cli_rejects_wrong_schema_without_output(
    tmp_path: Path,
    capsys,
) -> None:
    schema_document = canonical_schema_document()
    schema_document["schema_version"] = "canonical-event/v1"
    schema = tmp_path / "canonical_schema.json"
    schema.write_text(json.dumps(schema_document), encoding="utf-8")
    output = tmp_path / "scenario_evidence.json"

    exit_code = cli.main(
        [
            "--input",
            str(FIXTURE),
            "--canonical-schema",
            str(schema),
            "--output",
            str(output),
            "--expected-event-count",
            "4",
        ]
    )

    assert exit_code == 2
    assert "Expected canonical-event/v2" in capsys.readouterr().err
    assert not output.exists()
