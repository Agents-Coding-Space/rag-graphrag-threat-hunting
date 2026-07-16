"""Per-file structural inspection without scenario or normalization logic."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Iterable

from ..discovery import DiscoveredInput
from ..schemas.canonical_event import CANONICAL_FIELDS, SOURCE_FIELD_ALIASES
from .format_detection import FormatDetection
from .parser import ParsedRecord, iter_records


INSPECTION_SCHEMA_VERSION = "mordor-inspection/v1"


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _leaf_name(pointer: str) -> str:
    token = pointer.rsplit("/", 1)[-1]
    return token.replace("~1", "/").replace("~0", "~")


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


@dataclass
class _FieldAccumulator:
    present_count: int = 0
    null_count: int = 0
    type_counts: Counter[str] = field(default_factory=Counter)


def _collect_paths(
    value: object,
    prefix: str = "",
) -> dict[str, list[object]]:
    collected: dict[str, list[object]] = {}

    def add(path: str, item: object) -> None:
        collected.setdefault(path, []).append(item)

    def walk(item: object, current: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{current}/{_escape_pointer_token(str(key))}"
                add(child_path, child)
                if isinstance(child, (dict, list)):
                    walk(child, child_path)
        elif isinstance(item, list):
            wildcard = f"{current}/*"
            for child in item:
                if isinstance(child, dict):
                    walk(child, wildcard)
                elif isinstance(child, list):
                    add(wildcard, child)
                    walk(child, wildcard)
                else:
                    add(wildcard, child)

    walk(value, prefix)
    return collected


def _update_accumulators(
    accumulators: dict[str, _FieldAccumulator],
    values_by_path: dict[str, list[object]],
) -> None:
    for path, values in values_by_path.items():
        accumulator = accumulators.setdefault(path, _FieldAccumulator())
        accumulator.present_count += 1
        # A wildcard array path may occur more than once in one record. Count it
        # as null only when the path has no non-null value in that record, so
        # present_count = null_count + non_null_count remains true.
        if all(value is None for value in values):
            accumulator.null_count += 1
        for value_type in {_json_type(value) for value in values if value is not None}:
            accumulator.type_counts[value_type] += 1


def _field_documents(
    accumulators: dict[str, _FieldAccumulator], record_count: int
) -> list[dict[str, object]]:
    documents: list[dict[str, object]] = []
    for path in sorted(accumulators, key=str.casefold):
        accumulator = accumulators[path]
        non_null_count = accumulator.present_count - accumulator.null_count
        documents.append(
            {
                "path": path,
                "present_count": accumulator.present_count,
                "missing_count": record_count - accumulator.present_count,
                "null_count": accumulator.null_count,
                "non_null_count": non_null_count,
                "coverage": round(
                    accumulator.present_count / record_count if record_count else 0.0,
                    6,
                ),
                "observed_type_counts": dict(sorted(accumulator.type_counts.items())),
            }
        )
    return documents


def _first_top_level(record: dict[str, object], aliases: tuple[str, ...]) -> object | None:
    folded = {key.casefold(): value for key, value in record.items()}
    for alias in aliases:
        if alias.casefold() in folded:
            return folded[alias.casefold()]
    return None


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping_proposals(
    field_documents: list[dict[str, object]],
) -> dict[str, object]:
    proposals: dict[str, object] = {}
    for canonical_field in CANONICAL_FIELDS:
        name = str(canonical_field["name"])
        if name in {"raw_record_ref", "source_file"}:
            proposals[name] = {
                "status": "parser_metadata",
                "candidates": [],
                "rationale": "Generated by the parser boundary; no source field is mapped.",
            }
            continue

        aliases = {alias.casefold() for alias in SOURCE_FIELD_ALIASES.get(name, ())}
        candidates: list[dict[str, object]] = []
        for document in field_documents:
            path = str(document["path"])
            if _leaf_name(path).casefold() not in aliases:
                continue
            candidates.append(
                {
                    "source_path": path,
                    "present_count": document["present_count"],
                    "null_count": document["null_count"],
                    "coverage": document["coverage"],
                    "observed_types": sorted(
                        dict(document["observed_type_counts"]).keys()
                    ),
                    "rationale": (
                        "Source field name matches a generic alias for "
                        f"{name}; no conversion has been applied."
                    ),
                }
            )
        candidates.sort(
            key=lambda item: (-float(item["coverage"]), str(item["source_path"]).casefold())
        )
        proposals[name] = {
            "status": "candidate" if candidates else "unavailable",
            "candidates": candidates,
        }
    return proposals


def inspect_file(
    source: DiscoveredInput,
    detection: FormatDetection,
) -> dict[str, object]:
    """Inspect one complete file and return a separate JSON-ready report."""

    field_accumulators: dict[str, _FieldAccumulator] = {}
    top_level_accumulators: dict[str, _FieldAccumulator] = {}
    event_ids: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    timestamp_source_counts: Counter[str] = Counter()
    minimum_timestamp: datetime | None = None
    maximum_timestamp: datetime | None = None
    unparseable_timestamp_count = 0
    record_count = 0

    timestamp_aliases = SOURCE_FIELD_ALIASES["timestamp"]
    for parsed_record in iter_records(source.path, detection.source_format):
        record = parsed_record.data
        record_count += 1
        values_by_path = _collect_paths(record)
        _update_accumulators(field_accumulators, values_by_path)

        top_level_values = {
            f"/{_escape_pointer_token(str(key))}": [value]
            for key, value in record.items()
        }
        _update_accumulators(top_level_accumulators, top_level_values)

        event_id = _first_top_level(record, SOURCE_FIELD_ALIASES["event_id"])
        if event_id is not None:
            event_ids[str(event_id)] += 1
        provider = _first_top_level(record, SOURCE_FIELD_ALIASES["provider"])
        if provider is not None:
            providers[str(provider)] += 1

        timestamp_value = None
        timestamp_field = None
        folded = {key.casefold(): (key, value) for key, value in record.items()}
        for alias in timestamp_aliases:
            match = folded.get(alias.casefold())
            if match is not None:
                timestamp_field, timestamp_value = match
                break
        if timestamp_field is not None:
            timestamp_source_counts[str(timestamp_field)] += 1
            parsed_timestamp = _parse_timestamp(timestamp_value)
            if parsed_timestamp is None:
                unparseable_timestamp_count += 1
            else:
                minimum_timestamp = (
                    parsed_timestamp
                    if minimum_timestamp is None
                    else min(minimum_timestamp, parsed_timestamp)
                )
                maximum_timestamp = (
                    parsed_timestamp
                    if maximum_timestamp is None
                    else max(maximum_timestamp, parsed_timestamp)
                )

    fields = _field_documents(field_accumulators, record_count)
    top_level_fields = _field_documents(top_level_accumulators, record_count)
    expected = source.expected_record_count
    baseline_status = (
        "not_configured"
        if expected is None
        else "match" if expected == record_count else "mismatch"
    )
    status = "completed" if baseline_status != "mismatch" else "baseline_mismatch"

    return {
        "schema_version": INSPECTION_SCHEMA_VERSION,
        "status": status,
        "source": {
            "filename": source.path.name,
            "repository_relative_path": source.repository_relative_path,
            "size_bytes": source.path.stat().st_size,
            "sha256": _sha256(source.path),
            "encoding": detection.encoding,
        },
        "format_detection": {
            "format": detection.source_format,
            "fully_validated": detection.fully_validated,
            "validation_method": detection.validation_method,
            "validated_record_count": detection.validated_record_count,
        },
        "parsing": {
            "status": "valid",
            "record_count": record_count,
            "invalid_record_count": 0,
            "blank_line_count": detection.blank_line_count,
        },
        "record_count_check": {
            "expected": expected,
            "actual": record_count,
            "status": baseline_status,
        },
        "time_range": {
            "source_field_counts": dict(sorted(timestamp_source_counts.items())),
            "minimum_utc": _format_timestamp(minimum_timestamp),
            "maximum_utc": _format_timestamp(maximum_timestamp),
            "unparseable_count": unparseable_timestamp_count,
            "note": "Timestamps are parsed only for aggregate inspection; no canonical event is emitted.",
        },
        "observed_schema": {
            "path_notation": "RFC 6901 JSON Pointer with /* for array elements",
            "distinct_field_path_count": len(fields),
            "top_level": {
                "distinct_field_count": len(top_level_fields),
                "fields": top_level_fields,
            },
            "field_paths": fields,
        },
        "distributions": {
            "event_id": [
                {"value": value, "count": count}
                for value, count in sorted(event_ids.items(), key=lambda item: (-item[1], item[0]))
            ],
            "provider": [
                {"value": value, "count": count}
                for value, count in sorted(providers.items(), key=lambda item: (-item[1], item[0]))
            ],
        },
        "canonical_mapping_proposals": _mapping_proposals(fields),
        "warnings": [],
    }
