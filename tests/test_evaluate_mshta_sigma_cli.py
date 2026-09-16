from __future__ import annotations

import hashlib
import json
from pathlib import Path

import scripts.evaluate_mshta_sigma as cli
from threat_hunting.evidence import extract_mshta_powershell_evidence
from threat_hunting.schemas.canonical_event import canonical_schema_document


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
CANONICAL_FIXTURE = FIXTURE_ROOT / "evidence" / "mshta_powershell_canonical.jsonl"
RULES = (
    FIXTURE_ROOT / "sigma" / "mshta_execution.yml",
    FIXTURE_ROOT / "sigma" / "mshta_child.yml",
)


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    schema = tmp_path / "canonical_schema.json"
    schema.write_text(
        json.dumps(canonical_schema_document(), ensure_ascii=False),
        encoding="utf-8",
    )
    events = [
        json.loads(line)
        for line in CANONICAL_FIXTURE.read_text(encoding="utf-8").splitlines()
        if line
    ]
    evidence = tmp_path / "scenario_evidence.json"
    evidence.write_text(
        json.dumps(extract_mshta_powershell_evidence(events), ensure_ascii=False),
        encoding="utf-8",
    )
    return schema, evidence


def _arguments(schema: Path, evidence: Path, output: Path) -> list[str]:
    return [
        "--rule",
        str(RULES[0]),
        "--rule",
        str(RULES[1]),
        "--input",
        str(CANONICAL_FIXTURE),
        "--canonical-schema",
        str(schema),
        "--evidence",
        str(evidence),
        "--expected-event-count",
        "4",
        "--output",
        str(output),
    ]


def test_cli_builds_auditable_review_and_preserves_all_inputs(
    tmp_path: Path,
    capsys,
) -> None:
    schema, evidence = _inputs(tmp_path)
    output = tmp_path / "sigma_match_review.json"
    inputs = (*RULES, CANONICAL_FIXTURE, schema, evidence)
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}

    assert cli.main(_arguments(schema, evidence, output)) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["output_schema_version"] == "sigma-match-review/v1"
    assert stats["analysis_status"] == "needs_review"
    assert stats["rules_loaded"] == 2
    assert stats["canonical_events_examined"] == 4
    assert stats["observation_matches"] == 4
    assert set(stats["observation_matches_by_rule"].values()) == {2}
    assert stats["behavior_matches"] == 2
    assert set(stats["behavior_matches_by_rule"].values()) == {1}
    assert stats["unmatched_events"] == 0
    assert stats["unsupported_fields"] == []
    assert stats["unsupported_constructs"] == []
    assert stats["known_unmapped_fields"] == ["OriginalFileName"]
    assert stats["warnings"] == []
    assert stats["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["evidence_input"]["observation_count"] == 4
    assert document["evidence_input"]["behavior_count"] == 2
    assert "No ATT&CK technique is confirmed" in " ".join(document["review_notes"])
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs} == before


def test_cli_rejects_existing_output_without_overwrite(
    tmp_path: Path,
    capsys,
) -> None:
    schema, evidence = _inputs(tmp_path)
    output = tmp_path / "sigma_match_review.json"
    output.write_text("existing", encoding="utf-8")

    assert cli.main(_arguments(schema, evidence, output)) == 2
    assert "use --overwrite" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "existing"


def test_cli_atomic_overwrite_is_deterministic(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    schema, evidence = _inputs(tmp_path)
    output = tmp_path / "sigma_match_review.json"
    arguments = [*_arguments(schema, evidence, output), "--overwrite"]

    assert cli.main(arguments) == 0
    first = output.read_bytes()
    first_stats = json.loads(capsys.readouterr().out)

    replacements: list[tuple[Path, Path]] = []
    real_replace = cli.os.replace

    def recording_replace(source: str | Path, target: str | Path) -> None:
        replacements.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(cli.os, "replace", recording_replace)
    assert cli.main(arguments) == 0
    second = output.read_bytes()
    second_stats = json.loads(capsys.readouterr().out)

    assert first == second
    assert first_stats["output_sha256"] == second_stats["output_sha256"]
    assert replacements
    assert replacements[-1][1] == output
    assert replacements[-1][0].name.startswith(f".{output.name}.")
    assert not list(tmp_path.glob(f".{output.name}.*.tmp"))
