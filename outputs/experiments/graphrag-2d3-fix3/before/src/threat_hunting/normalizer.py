"""Normalize exactly one raw record into the canonical-event/v2 contract."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from threat_hunting.mordor.parser import SupportedFormat, iter_records
from threat_hunting.schemas.canonical_event import CANONICAL_FIELDS
from threat_hunting.schemas.canonical_mapping import (
    BASE_FIELD_SOURCE_PATHS,
    DEFAULT_MAPPING_REGISTRY,
    EVENT_OCCURRENCE_TIMESTAMP_FIELDS,
    TIMESTAMP_CONFLICT_THRESHOLD_SECONDS,
    TIMESTAMP_FIELDS,
    MappingRegistry,
    MappingRule,
)


IssueCode = Literal[
    "invalid_transformation",
    "ambiguous_mapping",
    "unsupported_context",
    "timestamp_conflict",
    "missing_expected_source",
]


@dataclass(frozen=True)
class NormalizationIssue:
    """A reviewable, non-fatal problem found while normalizing one record."""

    code: IssueCode
    canonical_field: str | None
    source_path: str | None
    message: str
    review_status: str = "needs_review"


@dataclass(frozen=True)
class NormalizationResult:
    """The single canonical event and all issues observed while producing it."""

    event: dict[str, object]
    issues: tuple[NormalizationIssue, ...]


_MISSING = object()
_PORT_FIELDS = frozenset({"source_port", "destination_port"})
_PROCESS_ID_FIELDS = frozenset({"process_id", "parent_process_id"})


def _value_at_path(record: Mapping[str, object], path: str) -> object:
    current: object = record
    for encoded_part in path.removeprefix("/").split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _issue(
    code: IssueCode,
    canonical_field: str | None,
    source_path: str | None,
    message: str,
) -> NormalizationIssue:
    return NormalizationIssue(
        code=code,
        canonical_field=canonical_field,
        source_path=source_path,
        message=message,
    )


def _transform_identifier(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _transform_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        port = int(value)
    else:
        return None
    return port if 0 <= port <= 65535 else None


def _transform_value(canonical_field: str, value: object) -> object | None:
    if canonical_field in _PORT_FIELDS:
        return _transform_port(value)
    if canonical_field in _PROCESS_ID_FIELDS or canonical_field == "event_id":
        return _transform_identifier(value)
    return value if isinstance(value, str) else None


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _rfc3339_utc(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc)
    return utc_value.isoformat().replace("+00:00", "Z")


def _timestamps_conflict(values: list[tuple[str, datetime]]) -> bool:
    for index, (_, left) in enumerate(values):
        for _, right in values[index + 1 :]:
            if (left.tzinfo is None) != (right.tzinfo is None):
                left_value = left.replace(tzinfo=None)
                right_value = right.replace(tzinfo=None)
            elif left.tzinfo is None:
                left_value = left
                right_value = right
            else:
                left_value = left.astimezone(timezone.utc)
                right_value = right.astimezone(timezone.utc)
            if abs((left_value - right_value).total_seconds()) > (
                TIMESTAMP_CONFLICT_THRESHOLD_SECONDS
            ):
                return True
    return False


def _normalize_timestamp(
    record: Mapping[str, object],
) -> tuple[str | None, list[NormalizationIssue]]:
    issues: list[NormalizationIssue] = []
    parsed_for_review: list[tuple[str, datetime]] = []
    selected: str | None = None
    occurrence_source_seen = False
    unusable_occurrence_candidates: list[tuple[str, str]] = []

    for field_name in TIMESTAMP_FIELDS:
        source_path = f"/{field_name}"
        raw_value = _value_at_path(record, source_path)
        if raw_value is _MISSING:
            continue
        parsed = _parse_datetime(raw_value)
        if parsed is not None:
            parsed_for_review.append((source_path, parsed))

        if field_name not in EVENT_OCCURRENCE_TIMESTAMP_FIELDS:
            continue
        occurrence_source_seen = True
        if parsed is None or parsed.tzinfo is None:
            reason = "not parseable" if parsed is None else "timezone-naive"
            unusable_occurrence_candidates.append((source_path, reason))
            continue
        if selected is None:
            selected = _rfc3339_utc(parsed)

    if not occurrence_source_seen:
        issues.append(
            _issue(
                "missing_expected_source",
                "timestamp",
                None,
                "No event-occurrence timestamp source is present.",
            )
        )
    elif selected is None:
        for source_path, reason in unusable_occurrence_candidates:
            issues.append(
                _issue(
                    "invalid_transformation",
                    "timestamp",
                    source_path,
                    f"Timestamp candidate is {reason}; UTC was not assumed.",
                )
            )

    if _timestamps_conflict(parsed_for_review):
        issues.append(
            _issue(
                "timestamp_conflict",
                "timestamp",
                None,
                "Timestamp candidates differ by more than the shared threshold.",
            )
        )
    return selected, issues


def _normalize_rule_group(
    record: Mapping[str, object],
    canonical_field: str,
    rules: list[MappingRule],
) -> tuple[object | None, list[NormalizationIssue]]:
    return _normalize_source_paths(
        record,
        canonical_field,
        [rule.source_path for rule in rules],
    )


def _normalize_source_paths(
    record: Mapping[str, object],
    canonical_field: str,
    source_paths: list[str] | tuple[str, ...],
) -> tuple[object | None, list[NormalizationIssue]]:
    issues: list[NormalizationIssue] = []
    candidates: list[tuple[str, object]] = []
    for source_path in source_paths:
        raw_value = _value_at_path(record, source_path)
        if raw_value is _MISSING:
            continue
        transformed = _transform_value(canonical_field, raw_value)
        if transformed is None:
            issues.append(
                _issue(
                    "invalid_transformation",
                    canonical_field,
                    source_path,
                    "Source value does not satisfy the canonical field type policy.",
                )
            )
            continue
        candidates.append((source_path, transformed))

    if not candidates and not any(
        _value_at_path(record, source_path) is not _MISSING
        for source_path in source_paths
    ):
        issues.append(
            _issue(
                "missing_expected_source",
                canonical_field,
                None,
                "No source field required by the applicable mapping rule is present.",
            )
        )
        return None, issues

    distinct_values: list[object] = []
    for _, value in candidates:
        if value not in distinct_values:
            distinct_values.append(value)
    if len(distinct_values) > 1:
        issues.append(
            _issue(
                "ambiguous_mapping",
                canonical_field,
                candidates[0][0],
                "Multiple applicable source fields contain different valid values; registry order was used.",
            )
        )
    return (candidates[0][1] if candidates else None), issues


def _validate_provenance(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def normalize_record(
    record: Mapping[str, object],
    *,
    raw_record_ref: str,
    source_file: str,
    registry: MappingRegistry = DEFAULT_MAPPING_REGISTRY,
) -> NormalizationResult:
    """Create exactly one canonical event from one input record."""

    raw_record_ref = _validate_provenance("raw_record_ref", raw_record_ref)
    source_file = _validate_provenance("source_file", source_file)
    event = {str(field["name"]): None for field in CANONICAL_FIELDS}
    issues: list[NormalizationIssue] = []

    context = registry.resolve_context(record)
    rules = registry.rules_for(context.provider, context.event_id)

    event_id = _transform_identifier(context.event_id_raw_value)
    if context.event_id_raw_value is not None and event_id is None:
        issues.append(
            _issue(
                "invalid_transformation",
                "event_id",
                context.event_id_source_path,
                "Event ID must be an integer or a non-empty string.",
            )
        )
    event["event_id"] = event_id

    if context.provider_raw_value is not None:
        if isinstance(context.provider_raw_value, str):
            event["provider"] = context.provider_raw_value
        else:
            issues.append(
                _issue(
                    "invalid_transformation",
                    "provider",
                    context.provider_source_path,
                    "Provider must be a string.",
                )
            )

    timestamp, timestamp_issues = _normalize_timestamp(record)
    event["timestamp"] = timestamp
    issues.extend(timestamp_issues)

    for canonical_field, source_paths in BASE_FIELD_SOURCE_PATHS:
        value, field_issues = _normalize_source_paths(
            record,
            canonical_field,
            source_paths,
        )
        event[canonical_field] = value
        issues.extend(field_issues)

    if not rules:
        issues.append(
            _issue(
                "unsupported_context",
                None,
                None,
                f"No mapping rules for provider={context.provider!r}, event_id={context.event_id!r}.",
            )
        )
    else:
        grouped: dict[str, list[MappingRule]] = defaultdict(list)
        for rule in rules:
            grouped[rule.canonical_field].append(rule)

        for canonical_field, field_rules in grouped.items():
            if canonical_field in {
                "event_id",
                "provider",
                "timestamp",
                "channel",
                "host",
            }:
                continue
            value, field_issues = _normalize_rule_group(
                record, canonical_field, field_rules
            )
            event[canonical_field] = value
            issues.extend(field_issues)

    event["raw_record_ref"] = raw_record_ref
    event["source_file"] = source_file
    return NormalizationResult(event=event, issues=tuple(issues))


def iter_normalized_records(
    path: Path,
    source_format: SupportedFormat,
    *,
    registry: MappingRegistry = DEFAULT_MAPPING_REGISTRY,
) -> Iterator[NormalizationResult]:
    """Yield one normalized result for each parsed source record in order."""

    for parsed in iter_records(path, source_format):
        yield normalize_record(
            parsed.data,
            raw_record_ref=parsed.raw_record_ref,
            source_file=path.name,
            registry=registry,
        )
