"""Streaming, atomic persistence for normalized canonical events and issues."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import uuid

from threat_hunting.mordor.parser import SupportedFormat
from threat_hunting.normalizer import iter_normalized_records
from threat_hunting.schemas.canonical_event import CANONICAL_FIELDS
from threat_hunting.schemas.canonical_mapping import (
    DEFAULT_MAPPING_REGISTRY,
    MappingRegistry,
)


CANONICAL_EVENTS_FILENAME = "canonical_events.jsonl"
NORMALIZATION_ISSUES_FILENAME = "normalization_issues.jsonl"
NORMALIZATION_ISSUE_SCHEMA_VERSION = "normalization-issue/v1"
_CANONICAL_FIELD_NAMES = tuple(str(field["name"]) for field in CANONICAL_FIELDS)
_ISSUE_FIELD_NAMES = (
    "schema_version",
    "source_file",
    "raw_record_ref",
    "code",
    "canonical_field",
    "source_path",
    "message",
    "review_status",
)


class NormalizationWriteError(RuntimeError):
    """Raised when normalized output cannot be validated or published safely."""


@dataclass(frozen=True)
class NormalizationWriteStats:
    """Small aggregate returned after a successful streaming write."""

    input_record_count: int
    output_event_count: int
    dropped_record_count: int
    event_with_issues_count: int
    issue_count: int
    issue_counts: dict[str, int]
    timestamp_null_count: int
    canonical_events_path: Path
    normalization_issues_path: Path


def _temporary_path(final_path: Path, suffix: str = "tmp") -> Path:
    return final_path.with_name(
        f".{final_path.name}.{uuid.uuid4().hex}.{suffix}"
    )


def _write_json_line(stream: object, payload: dict[str, object]) -> None:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    )
    stream.write(serialized)  # type: ignore[attr-defined]
    stream.write("\n")  # type: ignore[attr-defined]


def _validate_canonical_jsonl(path: Path, expected_count: int) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise NormalizationWriteError(
                    f"Blank canonical JSONL line at {path}:{line_number}"
                )
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NormalizationWriteError(
                    f"Invalid canonical JSONL at {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise NormalizationWriteError(
                    f"Canonical JSONL line is not an object at {path}:{line_number}"
                )
            if tuple(payload) != _CANONICAL_FIELD_NAMES:
                raise NormalizationWriteError(
                    f"Canonical field order or membership is invalid at "
                    f"{path}:{line_number}"
                )
            for field_name in ("raw_record_ref", "source_file"):
                value = payload[field_name]
                if not isinstance(value, str) or not value.strip():
                    raise NormalizationWriteError(
                        f"Invalid {field_name} at {path}:{line_number}"
                    )
            count += 1
    if count != expected_count:
        raise NormalizationWriteError(
            f"Canonical event validation count mismatch: expected "
            f"{expected_count}, found {count}"
        )
    return count


def _validate_issue_jsonl(path: Path, expected_count: int) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise NormalizationWriteError(
                    f"Blank issue JSONL line at {path}:{line_number}"
                )
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NormalizationWriteError(
                    f"Invalid issue JSONL at {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict) or tuple(payload) != _ISSUE_FIELD_NAMES:
                raise NormalizationWriteError(
                    f"Issue field order or membership is invalid at "
                    f"{path}:{line_number}"
                )
            if payload["schema_version"] != NORMALIZATION_ISSUE_SCHEMA_VERSION:
                raise NormalizationWriteError(
                    f"Invalid issue schema version at {path}:{line_number}"
                )
            for field_name in (
                "source_file",
                "raw_record_ref",
                "code",
                "message",
                "review_status",
            ):
                value = payload[field_name]
                if not isinstance(value, str) or not value.strip():
                    raise NormalizationWriteError(
                        f"Invalid issue {field_name} at {path}:{line_number}"
                    )
            count += 1
    if count != expected_count:
        raise NormalizationWriteError(
            f"Normalization issue validation count mismatch: expected "
            f"{expected_count}, found {count}"
        )
    return count


def _publish_pair(
    temporary_pairs: tuple[tuple[Path, Path], ...],
    *,
    overwrite: bool,
) -> None:
    backups: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        if overwrite:
            for _, final_path in temporary_pairs:
                if final_path.exists():
                    backup = _temporary_path(final_path, "bak")
                    os.replace(final_path, backup)
                    backups.append((final_path, backup))
        else:
            existing = [final for _, final in temporary_pairs if final.exists()]
            if existing:
                rendered = ", ".join(str(path) for path in existing)
                raise NormalizationWriteError(
                    f"Output already exists; use overwrite=True: {rendered}"
                )

        for temporary, final_path in temporary_pairs:
            os.replace(temporary, final_path)
            published.append(final_path)
    except Exception:
        for final_path in reversed(published):
            if final_path.exists():
                final_path.unlink()
        for final_path, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, final_path)
        raise
    else:
        for _, backup in backups:
            if backup.exists():
                backup.unlink()


def write_normalized_file(
    source_path: Path,
    source_format: SupportedFormat,
    output_directory: Path,
    *,
    overwrite: bool = False,
    registry: MappingRegistry = DEFAULT_MAPPING_REGISTRY,
) -> NormalizationWriteStats:
    """Stream one source into validated, atomically published JSONL files."""

    canonical_path = output_directory / CANONICAL_EVENTS_FILENAME
    issues_path = output_directory / NORMALIZATION_ISSUES_FILENAME
    output_directory.mkdir(parents=True, exist_ok=True)

    existing = [path for path in (canonical_path, issues_path) if path.exists()]
    if existing and not overwrite:
        rendered = ", ".join(str(path) for path in existing)
        raise NormalizationWriteError(
            f"Output already exists; use overwrite=True: {rendered}"
        )

    canonical_temporary = _temporary_path(canonical_path)
    issues_temporary = _temporary_path(issues_path)
    temporary_paths = (canonical_temporary, issues_temporary)

    input_record_count = 0
    output_event_count = 0
    event_with_issues_count = 0
    issue_count = 0
    issue_counts: Counter[str] = Counter()
    timestamp_null_count = 0

    try:
        with (
            canonical_temporary.open(
                "x", encoding="utf-8", newline="\n"
            ) as canonical_stream,
            issues_temporary.open("x", encoding="utf-8", newline="\n") as issue_stream,
        ):
            for result in iter_normalized_records(
                source_path,
                source_format,
                registry=registry,
            ):
                input_record_count += 1
                _write_json_line(canonical_stream, result.event)
                output_event_count += 1
                if result.event["timestamp"] is None:
                    timestamp_null_count += 1
                if result.issues:
                    event_with_issues_count += 1
                for issue in result.issues:
                    issue_document: dict[str, object] = {
                        "schema_version": NORMALIZATION_ISSUE_SCHEMA_VERSION,
                        "source_file": result.event["source_file"],
                        "raw_record_ref": result.event["raw_record_ref"],
                        "code": issue.code,
                        "canonical_field": issue.canonical_field,
                        "source_path": issue.source_path,
                        "message": issue.message,
                        "review_status": issue.review_status,
                    }
                    _write_json_line(issue_stream, issue_document)
                    issue_count += 1
                    issue_counts[issue.code] += 1

            canonical_stream.flush()
            os.fsync(canonical_stream.fileno())
            issue_stream.flush()
            os.fsync(issue_stream.fileno())

        dropped_record_count = input_record_count - output_event_count
        if input_record_count != output_event_count or dropped_record_count != 0:
            raise NormalizationWriteError(
                "One-to-one normalization invariant failed: "
                f"input={input_record_count}, output={output_event_count}, "
                f"dropped={dropped_record_count}"
            )

        _validate_canonical_jsonl(canonical_temporary, output_event_count)
        _validate_issue_jsonl(issues_temporary, issue_count)
        _publish_pair(
            (
                (canonical_temporary, canonical_path),
                (issues_temporary, issues_path),
            ),
            overwrite=overwrite,
        )
    finally:
        for temporary in temporary_paths:
            if temporary.exists():
                temporary.unlink()

    return NormalizationWriteStats(
        input_record_count=input_record_count,
        output_event_count=output_event_count,
        dropped_record_count=0,
        event_with_issues_count=event_with_issues_count,
        issue_count=issue_count,
        issue_counts=dict(sorted(issue_counts.items())),
        timestamp_null_count=timestamp_null_count,
        canonical_events_path=canonical_path,
        normalization_issues_path=issues_path,
    )
