"""Evaluate selected Sigma rules and build a review-only MSHTA artifact."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threat_hunting.evidence import SCENARIO_EVIDENCE_SCHEMA_VERSION
from threat_hunting.schemas.canonical_event import (
    CANONICAL_FIELDS,
    CANONICAL_SCHEMA_VERSION,
)
from threat_hunting.sigma import (
    DEFAULT_CANONICAL_FIELD_MAPPING,
    SIGMA_MATCH_ANALYSIS_STATUS,
    SIGMA_MATCH_REVIEW_SCHEMA_VERSION,
    SigmaEvaluationError,
    SigmaReviewError,
    SigmaRuleError,
    build_sigma_match_review,
    evaluate_sigma_rules,
    load_sigma_rules,
    serialize_sigma_match_review,
)


DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "sigma_match_review.json"
)
DEFAULT_SCENARIO_ID = "mshta-powershell"
DEFAULT_EXPECTED_EVENT_COUNT = 1127
_CANONICAL_FIELD_NAMES = tuple(str(field["name"]) for field in CANONICAL_FIELDS)
_MSHTA_REVIEW_NOTES = (
    "Sigma matches are candidate detection hypotheses and require human review.",
    "T1218.005, T1140, and T1059.007 are retained only as tags from the loaded rules; no MITRE resolver is implemented in this milestone.",
    "Current matched evidence does not demonstrate T1140, and T1059.007 does not fit the observed VBScript command line.",
    "T1059 is a parent technique and is not used as a direct mapping when a supported sub-technique is selected.",
    "No ATT&CK technique is confirmed by this artifact.",
    "Không quan sát thấy download, C2, credential theft hoặc destructive behavior trong bốn matched evidence observations.",
    "Q14 and Q15 remain pending because this milestone does not perform a full-dataset negative scan.",
)


class SigmaReviewRunError(RuntimeError):
    """Raised when production inputs or output fail validation."""


@dataclass(frozen=True)
class SigmaReviewStats:
    """Auditable counts printed after a successful production run."""

    output_schema_version: str
    analysis_status: str
    rules_loaded: int
    rule_hashes: dict[str, str]
    canonical_events_examined: int
    observation_matches: int
    observation_matches_by_rule: dict[str, int]
    behavior_matches: int
    behavior_matches_by_rule: dict[str, int]
    unmatched_events: int
    unsupported_fields: tuple[str, ...]
    unsupported_constructs: tuple[str, ...]
    known_unmapped_fields: tuple[str, ...]
    warnings: tuple[str, ...]
    output_sha256: str
    output_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def _load_canonical_schema(path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigmaReviewRunError(f"Cannot load canonical schema {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise SigmaReviewRunError(f"Canonical schema must be a JSON object: {path}")
    if document.get("schema_version") != CANONICAL_SCHEMA_VERSION:
        raise SigmaReviewRunError(
            f"Expected {CANONICAL_SCHEMA_VERSION} at {path}, found "
            f"{document.get('schema_version')!r}"
        )
    fields = document.get("fields")
    if not isinstance(fields, list) or any(
        not isinstance(field, dict) or not isinstance(field.get("name"), str)
        for field in fields
    ):
        raise SigmaReviewRunError(f"Canonical schema fields are invalid: {path}")
    if tuple(str(field["name"]) for field in fields) != _CANONICAL_FIELD_NAMES:
        raise SigmaReviewRunError(
            f"Canonical schema fields do not match {CANONICAL_SCHEMA_VERSION}: {path}"
        )


def _load_canonical_events(
    path: Path,
    *,
    expected_event_count: int,
) -> list[dict[str, object]]:
    if expected_event_count < 0:
        raise SigmaReviewRunError("expected_event_count must be non-negative")
    events: list[dict[str, object]] = []
    references: set[tuple[str, str]] = set()
    try:
        stream = path.open("r", encoding="utf-8-sig")
    except OSError as exc:
        raise SigmaReviewRunError(f"Cannot open canonical events {path}: {exc}") from exc
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise SigmaReviewRunError(
                    f"Blank canonical JSONL line at {path}:{line_number}"
                )
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SigmaReviewRunError(
                    f"Invalid canonical JSONL at {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(event, dict) or tuple(event) != _CANONICAL_FIELD_NAMES:
                raise SigmaReviewRunError(
                    f"Canonical field order or membership is invalid at {path}:{line_number}"
                )
            source_file = event.get("source_file")
            raw_record_ref = event.get("raw_record_ref")
            if not isinstance(source_file, str) or not source_file.strip():
                raise SigmaReviewRunError(
                    f"Invalid source_file at {path}:{line_number}"
                )
            if not isinstance(raw_record_ref, str) or not raw_record_ref.strip():
                raise SigmaReviewRunError(
                    f"Invalid raw_record_ref at {path}:{line_number}"
                )
            reference = (source_file, raw_record_ref)
            if reference in references:
                raise SigmaReviewRunError(
                    f"Duplicate canonical provenance at {path}:{line_number}: {reference!r}"
                )
            references.add(reference)
            events.append(event)
    if len(events) != expected_event_count:
        raise SigmaReviewRunError(
            f"Canonical event count mismatch for {path}: expected "
            f"{expected_event_count}, found {len(events)}"
        )
    return events


def _load_evidence(path: Path, scenario_id: str) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigmaReviewRunError(f"Cannot load scenario evidence {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise SigmaReviewRunError(f"Scenario evidence must be a JSON object: {path}")
    if document.get("schema_version") != SCENARIO_EVIDENCE_SCHEMA_VERSION:
        raise SigmaReviewRunError(
            f"Expected {SCENARIO_EVIDENCE_SCHEMA_VERSION} at {path}"
        )
    if document.get("scenario_id") != scenario_id:
        raise SigmaReviewRunError(
            f"Evidence scenario_id does not match {scenario_id!r}: {path}"
        )
    return document


def _evidence_counts(document: dict[str, object]) -> tuple[int, int]:
    evidence = document.get("evidence")
    if not isinstance(evidence, list):
        raise SigmaReviewRunError("Scenario evidence field 'evidence' must be a list")
    observations = 0
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("observations"), list):
            raise SigmaReviewRunError("Scenario evidence items are invalid")
        observations += len(item["observations"])
    return observations, len(evidence)


def _validate_review_payload(payload: bytes, expected: dict[str, object]) -> None:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigmaReviewRunError("Sigma review output is not valid UTF-8 JSON") from exc
    if parsed != expected:
        raise SigmaReviewRunError("Sigma review changed during serialization")
    if parsed.get("schema_version") != SIGMA_MATCH_REVIEW_SCHEMA_VERSION:
        raise SigmaReviewRunError("Sigma review schema version is invalid")
    if parsed.get("analysis_status") != SIGMA_MATCH_ANALYSIS_STATUS:
        raise SigmaReviewRunError("Sigma review analysis status is invalid")
    if any(item.get("status") != "candidate" for item in parsed["observation_matches"]):
        raise SigmaReviewRunError("Observation match status must remain candidate")
    if any(
        item.get("status") != "candidate"
        or item.get("review_status") != "needs_review"
        for item in parsed["behavior_matches"]
    ):
        raise SigmaReviewRunError("Behavior match status must remain reviewable")
    if any(item.get("analysis_status") != "candidate" for item in parsed["rules"]):
        raise SigmaReviewRunError("Rule analysis status must remain candidate")


def _write_review(
    output_path: Path,
    document: dict[str, object],
    *,
    overwrite: bool,
) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not overwrite:
        raise SigmaReviewRunError(
            f"Output already exists; use --overwrite: {output_path}"
        )
    payload = serialize_sigma_match_review(document)
    temporary = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_review_payload(temporary.read_bytes(), document)
        if output_path.exists() and not overwrite:
            raise SigmaReviewRunError(
                f"Output already exists; use --overwrite: {output_path}"
            )
        os.replace(temporary, output_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return hashlib.sha256(payload).hexdigest()


def run_review(
    *,
    rule_paths: list[Path],
    canonical_events_path: Path,
    canonical_schema_path: Path,
    evidence_path: Path,
    output_path: Path,
    scenario_id: str = DEFAULT_SCENARIO_ID,
    expected_event_count: int = DEFAULT_EXPECTED_EVENT_COUNT,
    overwrite: bool = False,
) -> SigmaReviewStats:
    """Validate inputs, evaluate rules, link evidence, and atomically publish."""

    inputs = [*rule_paths, canonical_events_path, canonical_schema_path, evidence_path]
    resolved_inputs = [path.resolve() for path in inputs]
    if len(resolved_inputs) != len(set(resolved_inputs)):
        raise SigmaReviewRunError("Input paths must be unique")
    if output_path.resolve() in set(resolved_inputs):
        raise SigmaReviewRunError("Output path must not overwrite an input")
    input_hashes = {path: _file_sha256(path) for path in resolved_inputs}

    _load_canonical_schema(canonical_schema_path)
    events = _load_canonical_events(
        canonical_events_path,
        expected_event_count=expected_event_count,
    )
    evidence_document = _load_evidence(evidence_path, scenario_id)
    evidence_observations, evidence_behaviors = _evidence_counts(evidence_document)
    source_paths = {path: _portable_path(path) for path in rule_paths}
    rules = load_sigma_rules(rule_paths, source_paths=source_paths)
    evaluations = evaluate_sigma_rules(rules, events)
    canonical_source_files = sorted(
        {str(event["source_file"]) for event in events}
    )
    document = build_sigma_match_review(
        scenario_id=scenario_id,
        canonical_input={
            "path": _portable_path(canonical_events_path),
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "sha256": input_hashes[canonical_events_path.resolve()],
            "event_count": len(events),
            "source_files": canonical_source_files,
        },
        evidence_input={
            "path": _portable_path(evidence_path),
            "schema_version": SCENARIO_EVIDENCE_SCHEMA_VERSION,
            "sha256": input_hashes[evidence_path.resolve()],
            "observation_count": evidence_observations,
            "behavior_count": evidence_behaviors,
        },
        evidence_document=evidence_document,
        evaluations=evaluations,
        field_mapping=DEFAULT_CANONICAL_FIELD_MAPPING,
        review_notes=_MSHTA_REVIEW_NOTES,
    )
    for path, before in input_hashes.items():
        after = _file_sha256(path)
        if after != before:
            raise SigmaReviewRunError(
                f"Input changed during Sigma evaluation: {path}; "
                f"before={before}, after={after}"
            )
    output_sha256 = _write_review(output_path, document, overwrite=overwrite)

    observation_by_rule = {
        rule.rule_id: len(evaluation.observation_matches)
        for rule, evaluation in zip(rules, evaluations, strict=True)
    }
    behavior_by_rule = {
        rule.rule_id: sum(
            item["rule_id"] == rule.rule_id for item in document["behavior_matches"]
        )
        for rule in rules
    }
    return SigmaReviewStats(
        output_schema_version=SIGMA_MATCH_REVIEW_SCHEMA_VERSION,
        analysis_status=SIGMA_MATCH_ANALYSIS_STATUS,
        rules_loaded=len(rules),
        rule_hashes={rule.rule_id: rule.sha256 for rule in rules},
        canonical_events_examined=len(events),
        observation_matches=len(document["observation_matches"]),
        observation_matches_by_rule=observation_by_rule,
        behavior_matches=len(document["behavior_matches"]),
        behavior_matches_by_rule=behavior_by_rule,
        unmatched_events=int(document["unmatched_events"]),
        unsupported_fields=tuple(document["unsupported_fields"]),
        unsupported_constructs=tuple(document["unsupported_constructs"]),
        known_unmapped_fields=tuple(document["known_unmapped_fields"]),
        warnings=tuple(document["warnings"]),
        output_sha256=output_sha256,
        output_path=str(output_path.resolve()),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate selected Sigma rules against canonical MSHTA events and "
            "link matches to scenario-evidence/v1."
        )
    )
    parser.add_argument(
        "--rule",
        action="append",
        required=True,
        type=Path,
        help="Sigma YAML path; repeat for each selected rule",
    )
    parser.add_argument("--input", required=True, type=Path, help="Canonical JSONL")
    parser.add_argument(
        "--canonical-schema",
        required=True,
        type=Path,
        help="canonical-event/v2 schema JSON",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="scenario-evidence/v1 JSON used for behavior grouping",
    )
    parser.add_argument("--scenario-id", default=DEFAULT_SCENARIO_ID)
    parser.add_argument(
        "--expected-event-count",
        type=int,
        default=DEFAULT_EXPECTED_EVENT_COUNT,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace an existing output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        stats = run_review(
            rule_paths=[path.resolve() for path in arguments.rule],
            canonical_events_path=arguments.input.resolve(),
            canonical_schema_path=arguments.canonical_schema.resolve(),
            evidence_path=arguments.evidence.resolve(),
            output_path=arguments.output.resolve(),
            scenario_id=arguments.scenario_id,
            expected_event_count=arguments.expected_event_count,
            overwrite=arguments.overwrite,
        )
    except (
        OSError,
        SigmaEvaluationError,
        SigmaReviewError,
        SigmaReviewRunError,
        SigmaRuleError,
        ValueError,
    ) as exc:
        print(f"evaluate_mshta_sigma: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(stats.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
