"""Run the MSHTA evidence extractor on validated canonical JSONL input."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import sys
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threat_hunting.evidence import (
    SCENARIO_EVIDENCE_SCHEMA_VERSION,
    classify_process_creation,
    extract_mshta_powershell_evidence,
    scenario_evidence_schema_document,
)
from threat_hunting.schemas.canonical_event import (
    CANONICAL_FIELDS,
    CANONICAL_SCHEMA_VERSION,
)


EXPECTED_SOURCE_FILE = "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
EXPECTED_EVENT_COUNT = 1127
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "scenario_evidence.json"
)
_CANONICAL_FIELD_NAMES = tuple(str(field["name"]) for field in CANONICAL_FIELDS)


class EvidenceExtractionRunError(RuntimeError):
    """Raised when production input or output fails validation."""


@dataclass(frozen=True)
class EvidenceExtractionStats:
    """Auditable production counts emitted after a successful extraction."""

    canonical_schema_version: str
    output_schema_version: str
    input_events: int
    examined_events: int
    matched_events: int
    unmatched_events: int
    entities: int
    relationships: int
    evidence: int
    source_references: int
    correlated_telemetry_pairs: int
    rejected_events: int
    unprocessed_events: int
    warnings: tuple[str, ...]
    output_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _load_canonical_schema(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            schema = json.load(stream)
    except json.JSONDecodeError as exc:
        raise EvidenceExtractionRunError(
            f"Invalid canonical schema JSON at {path}: {exc.msg}"
        ) from exc
    if not isinstance(schema, dict):
        raise EvidenceExtractionRunError(
            f"Canonical schema must be a JSON object: {path}"
        )
    if schema.get("schema_version") != CANONICAL_SCHEMA_VERSION:
        raise EvidenceExtractionRunError(
            f"Expected {CANONICAL_SCHEMA_VERSION} at {path}, found "
            f"{schema.get('schema_version')!r}"
        )
    fields = schema.get("fields")
    if not isinstance(fields, list) or any(
        not isinstance(field, dict) or not isinstance(field.get("name"), str)
        for field in fields
    ):
        raise EvidenceExtractionRunError(
            f"Canonical schema fields are invalid: {path}"
        )
    field_names = tuple(str(field["name"]) for field in fields)
    if field_names != _CANONICAL_FIELD_NAMES:
        raise EvidenceExtractionRunError(
            f"Canonical schema fields do not match {CANONICAL_SCHEMA_VERSION}: {path}"
        )


def _load_canonical_events(
    path: Path,
    *,
    expected_event_count: int,
) -> list[dict[str, object]]:
    if expected_event_count < 0:
        raise EvidenceExtractionRunError(
            "expected_event_count must be a non-negative integer"
        )
    events: list[dict[str, object]] = []
    provenance: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise EvidenceExtractionRunError(
                    f"Blank canonical JSONL line at {path}:{line_number}"
                )
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceExtractionRunError(
                    f"Invalid canonical JSONL at {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(event, dict):
                raise EvidenceExtractionRunError(
                    f"Canonical JSONL line is not an object at {path}:{line_number}"
                )
            if tuple(event) != _CANONICAL_FIELD_NAMES:
                raise EvidenceExtractionRunError(
                    f"Canonical field order or membership is invalid at "
                    f"{path}:{line_number}"
                )
            source_file = event["source_file"]
            raw_record_ref = event["raw_record_ref"]
            if source_file != EXPECTED_SOURCE_FILE:
                raise EvidenceExtractionRunError(
                    f"Unexpected source_file at {path}:{line_number}: "
                    f"{source_file!r}"
                )
            if not isinstance(raw_record_ref, str) or not raw_record_ref.strip():
                raise EvidenceExtractionRunError(
                    f"Invalid raw_record_ref at {path}:{line_number}"
                )
            reference = (source_file, raw_record_ref)
            if reference in provenance:
                raise EvidenceExtractionRunError(
                    f"Duplicate canonical provenance at {path}:{line_number}: "
                    f"{source_file!r}, {raw_record_ref!r}"
                )
            provenance.add(reference)
            events.append(event)
    if len(events) != expected_event_count:
        raise EvidenceExtractionRunError(
            f"Canonical event count mismatch for {path}: expected "
            f"{expected_event_count}, found {len(events)}"
        )
    return events


def _serialized_document(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def _validate_serialized_document(
    payload: bytes,
    expected: dict[str, object],
) -> None:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceExtractionRunError(
            "Serialized scenario evidence did not parse as UTF-8 JSON"
        ) from exc
    if parsed != expected:
        raise EvidenceExtractionRunError(
            "Scenario evidence changed during serialization"
        )
    expected_fields = tuple(
        scenario_evidence_schema_document()["top_level_fields"]
    )
    if not isinstance(parsed, dict) or tuple(parsed) != expected_fields:
        raise EvidenceExtractionRunError(
            "Scenario evidence top-level schema fields are invalid"
        )
    if parsed.get("schema_version") != SCENARIO_EVIDENCE_SCHEMA_VERSION:
        raise EvidenceExtractionRunError(
            "Scenario evidence schema version is invalid"
        )


def _write_document(
    output_path: Path,
    document: dict[str, object],
    *,
    overwrite: bool,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not overwrite:
        raise EvidenceExtractionRunError(
            f"Output already exists; use --overwrite: {output_path}"
        )
    temporary_path = output_path.with_name(
        f".{output_path.name}.{uuid.uuid4().hex}.tmp"
    )
    payload = _serialized_document(document)
    try:
        with temporary_path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_serialized_document(temporary_path.read_bytes(), document)
        if output_path.exists() and not overwrite:
            raise EvidenceExtractionRunError(
                f"Output already exists; use --overwrite: {output_path}"
            )
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def run_extraction(
    canonical_events_path: Path,
    canonical_schema_path: Path,
    output_path: Path,
    *,
    expected_event_count: int = EXPECTED_EVENT_COUNT,
    correlation_tolerance_seconds: float = 1.0,
    overwrite: bool = False,
) -> EvidenceExtractionStats:
    """Validate one MSHTA canonical file, extract evidence, and publish JSON."""

    _load_canonical_schema(canonical_schema_path)
    events = _load_canonical_events(
        canonical_events_path,
        expected_event_count=expected_event_count,
    )
    matched_events = sum(
        classify_process_creation(event) is not None for event in events
    )
    document = extract_mshta_powershell_evidence(
        events,
        correlation_tolerance_seconds=correlation_tolerance_seconds,
    )
    observations = [
        observation
        for item in document["evidence"]
        for observation in item["observations"]
    ]
    source_references = {
        (observation["source_file"], observation["raw_record_ref"])
        for observation in observations
    }
    correlated_pairs = sum(
        len(item["observations"]) == 2 for item in document["evidence"]
    )
    _write_document(output_path, document, overwrite=overwrite)
    return EvidenceExtractionStats(
        canonical_schema_version=CANONICAL_SCHEMA_VERSION,
        output_schema_version=str(document["schema_version"]),
        input_events=len(events),
        examined_events=len(events),
        matched_events=matched_events,
        unmatched_events=len(events) - matched_events,
        entities=len(document["observed_entities"]),
        relationships=len(document["relationships"]),
        evidence=len(document["evidence"]),
        source_references=len(source_references),
        correlated_telemetry_pairs=correlated_pairs,
        rejected_events=0,
        unprocessed_events=0,
        warnings=(),
        output_path=str(output_path.resolve()),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract draft-reviewable MSHTA-to-PowerShell evidence from "
            "canonical-event/v2 JSONL."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Canonical MSHTA events JSONL",
    )
    parser.add_argument(
        "--canonical-schema",
        required=True,
        type=Path,
        help="canonical-event/v2 schema JSON used by the normalization run",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Scenario evidence JSON (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--expected-event-count",
        type=int,
        default=EXPECTED_EVENT_COUNT,
        help=f"Required input event count (default: {EXPECTED_EVENT_COUNT})",
    )
    parser.add_argument(
        "--correlation-tolerance-seconds",
        type=float,
        default=1.0,
        help="Maximum Security 4688/Sysmon 1 timestamp difference (default: 1.0)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace an existing output file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        stats = run_extraction(
            arguments.input.resolve(),
            arguments.canonical_schema.resolve(),
            arguments.output.resolve(),
            expected_event_count=arguments.expected_event_count,
            correlation_tolerance_seconds=arguments.correlation_tolerance_seconds,
            overwrite=arguments.overwrite,
        )
    except (EvidenceExtractionRunError, OSError, ValueError) as exc:
        print(f"extract_mshta_evidence: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(stats.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
