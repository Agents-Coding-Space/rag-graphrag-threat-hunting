"""Per-file structural inspection without scenario or normalization logic."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from itertools import combinations
from pathlib import Path

from ..discovery import DiscoveredInput
from ..schemas.canonical_event import CANONICAL_FIELDS
from ..schemas.canonical_mapping import (
    EVENT_OCCURRENCE_TIMESTAMP_FIELDS,
    SECURITY_PROVIDER,
    SECURITY_RELEVANT_CONTEXTS,
    SYSMON_10_PROCESS_ROLES,
    SYSMON_PROVIDER,
    TIMESTAMP_CONFLICT_THRESHOLD_SECONDS,
    TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS,
    TIMESTAMP_FIELDS,
    TIMESTAMP_REVIEW_ONLY_FIELDS,
    iter_mapping_rules,
    resolve_context,
)
from .format_detection import FormatDetection
from .parser import ParsedRecord, iter_records


INSPECTION_SCHEMA_VERSION = "mordor-inspection/v2"


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


@dataclass
class _ContextAccumulator:
    record_count: int = 0
    fields: dict[str, _FieldAccumulator] = field(default_factory=dict)


@dataclass(frozen=True)
class _ParsedTimestamp:
    value: datetime
    timezone_aware: bool


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


def _parse_timestamp(value: object) -> _ParsedTimestamp | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    aware = parsed.tzinfo is not None and parsed.utcoffset() is not None
    return _ParsedTimestamp(value=parsed, timezone_aware=aware)


def _format_timestamp(value: _ParsedTimestamp | None) -> str | None:
    if value is None:
        return None
    rendered = value.value
    if value.timezone_aware:
        rendered = rendered.astimezone(timezone.utc)
    return rendered.isoformat().replace("+00:00", "Z")


def _timestamp_delta(
    first: _ParsedTimestamp,
    second: _ParsedTimestamp,
) -> tuple[float, str]:
    if first.timezone_aware and second.timezone_aware:
        delta = abs(
            (
                first.value.astimezone(timezone.utc)
                - second.value.astimezone(timezone.utc)
            ).total_seconds()
        )
        return delta, "absolute_time"
    if not first.timezone_aware and not second.timezone_aware:
        return abs((first.value - second.value).total_seconds()), "naive_wall_clock"

    first_wall = first.value.replace(tzinfo=None)
    second_wall = second.value.replace(tzinfo=None)
    return (
        abs((first_wall - second_wall).total_seconds()),
        "wall_clock_only_timezone_unconfirmed",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _context_documents(
    contexts: dict[tuple[str, str], _ContextAccumulator],
) -> dict[tuple[str, str], tuple[int, dict[str, dict[str, object]]]]:
    documents = {}
    for key, context in contexts.items():
        fields = _field_documents(context.fields, context.record_count)
        documents[key] = (
            context.record_count,
            {str(document["path"]): document for document in fields},
        )
    return documents


def _mapping_proposals(
    field_documents: list[dict[str, object]],
    contexts: dict[tuple[str, str], _ContextAccumulator],
) -> dict[str, object]:
    proposals: dict[str, object] = {}
    candidates_by_field: dict[str, list[dict[str, object]]] = {
        str(field["name"]): [] for field in CANONICAL_FIELDS
    }
    context_documents = _context_documents(contexts)
    file_fields = {str(document["path"]): document for document in field_documents}

    for rule in iter_mapping_rules():
        context = context_documents.get((rule.provider, rule.event_id))
        if context is None:
            continue
        context_record_count, fields = context
        document = fields.get(rule.source_path)
        if document is None:
            continue
        observed_types = sorted(dict(document["observed_type_counts"]).keys())
        transformation = rule.expected_transformation
        if transformation == "validated_string_to_integer" and "string" not in observed_types:
            transformation = "none"
        review_status = "needs_review"
        if rule.canonical_field == "timestamp":
            primary_timestamp_path = f"/{EVENT_OCCURRENCE_TIMESTAMP_FIELDS[0]}"
            fallback_timestamp_paths = {
                f"/{field}" for field in EVENT_OCCURRENCE_TIMESTAMP_FIELDS[1:]
            }
            if rule.source_path == primary_timestamp_path:
                review_status = "recommended_primary"
            elif rule.source_path in fallback_timestamp_paths:
                review_status = "recommended_fallback"
        candidates_by_field[rule.canonical_field].append(
            {
                "source_path": rule.source_path,
                "provider": rule.provider,
                "event_id": rule.event_id,
                "present_count": document["present_count"],
                "context_record_count": context_record_count,
                "context_coverage": document["coverage"],
                "file_coverage": file_fields.get(rule.source_path, {}).get(
                    "coverage", 0.0
                ),
                "observed_types": observed_types,
                "expected_transformation": transformation,
                "rationale": rule.rationale,
                "review_status": review_status,
            }
        )

    for canonical_field in CANONICAL_FIELDS:
        name = str(canonical_field["name"])
        if name in {"raw_record_ref", "source_file"}:
            proposals[name] = {
                "status": "parser_metadata",
                "candidates": [],
                "rationale": "Generated by the parser boundary; no source field is mapped.",
            }
            continue

        candidates = candidates_by_field[name]
        candidates.sort(
            key=lambda item: (
                str(item["provider"]).casefold(),
                str(item["event_id"]),
                str(item["source_path"]).casefold(),
            )
        )
        sources_by_context: dict[tuple[str, str], set[str]] = {}
        for candidate in candidates:
            key = (str(candidate["provider"]), str(candidate["event_id"]))
            sources_by_context.setdefault(key, set()).add(str(candidate["source_path"]))
        ambiguous = name == "timestamp" or any(
            len(paths) > 1 for paths in sources_by_context.values()
        )
        status = (
            "ambiguous"
            if ambiguous and candidates
            else "candidate" if candidates else "unavailable"
        )
        proposal: dict[str, object] = {
            "status": status,
            "candidates": candidates,
        }
        if name == "timestamp":
            proposal["recommendation"] = {
                "status": "candidate",
                "primary_source_path": f"/{EVENT_OCCURRENCE_TIMESTAMP_FIELDS[0]}",
                "fallback_source_paths": [
                    f"/{field}" for field in EVENT_OCCURRENCE_TIMESTAMP_FIELDS[1:]
                ],
                "review_only_source_paths": [
                    f"/{field}" for field in TIMESTAMP_REVIEW_ONLY_FIELDS
                ],
                "excluded_occurrence_source_paths": [
                    f"/{field}" for field in TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS
                ],
                "rationale": (
                    "Use @timestamp as the cross-dataset timeline candidate and "
                    "TimeCreated or EventTime as parsed fallbacks. UtcTime remains "
                    "review-only until its timezone semantics are known, and "
                    "CreationUtcTime is not an event occurrence timestamp."
                ),
            }
        proposals[name] = proposal

    unmapped_candidates: list[dict[str, object]] = []
    sysmon_ten = context_documents.get((SYSMON_PROVIDER, "10"))
    if sysmon_ten is not None:
        context_record_count, fields = sysmon_ten
        for source_path, role in SYSMON_10_PROCESS_ROLES:
            document = fields.get(source_path)
            if document is None:
                continue
            unmapped_candidates.append(
                {
                    "source_path": source_path,
                    "provider": SYSMON_PROVIDER,
                    "event_id": "10",
                    "source_role": role,
                    "present_count": document["present_count"],
                    "context_record_count": context_record_count,
                    "context_coverage": document["coverage"],
                    "observed_types": sorted(
                        dict(document["observed_type_counts"]).keys()
                    ),
                    "expected_transformation": "none",
                    "rationale": (
                        "Sysmon Event ID 10 uses source/target process roles, "
                        "not parent/child roles represented by canonical-event/v2."
                    ),
                    "review_status": "context_specific_unmapped",
                }
            )
    proposals["context_specific_unmapped"] = {
        "status": "context_specific_unmapped" if unmapped_candidates else "unavailable",
        "candidates": unmapped_candidates,
    }
    return proposals


def _structural_context_documents(
    contexts: dict[tuple[str, str], _ContextAccumulator],
) -> list[dict[str, object]]:
    documents = []
    for label, provider, event_id in SECURITY_RELEVANT_CONTEXTS:
        context = contexts.get((provider, event_id))
        if context is not None and context.record_count:
            documents.append(
                {
                    "label": label,
                    "provider": provider,
                    "event_id": event_id,
                    "count": context.record_count,
                }
            )
    return documents


def inspect_file(
    source: DiscoveredInput,
    detection: FormatDetection,
) -> dict[str, object]:
    """Inspect one complete file and return a separate JSON-ready report."""

    field_accumulators: dict[str, _FieldAccumulator] = {}
    top_level_accumulators: dict[str, _FieldAccumulator] = {}
    context_accumulators: dict[tuple[str, str], _ContextAccumulator] = {}
    event_ids: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    timestamp_statistics: dict[str, Counter[str]] = {}
    timestamp_range_sources: Counter[str] = Counter()
    timestamp_conflicts: dict[tuple[str, str], dict[str, object]] = {}
    multiple_timestamp_candidate_count = 0
    conflicting_timestamp_record_count = 0
    mixed_timezone_range_count = 0
    minimum_timestamp: _ParsedTimestamp | None = None
    maximum_timestamp: _ParsedTimestamp | None = None
    record_count = 0

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

        resolved_context = resolve_context(record)
        event_id_text = (
            resolved_context.event_id
            if resolved_context.event_id is not None
            else "<unavailable>"
        )
        if resolved_context.event_id is not None:
            event_ids[event_id_text] += 1
        provider_text = (
            resolved_context.provider
            if resolved_context.provider is not None
            else "<unavailable>"
        )
        if resolved_context.provider is not None:
            providers[provider_text] += 1

        context = context_accumulators.setdefault(
            (provider_text, event_id_text), _ContextAccumulator()
        )
        context.record_count += 1
        _update_accumulators(context.fields, values_by_path)

        folded = {key.casefold(): (key, value) for key, value in record.items()}
        timestamps_in_record: list[tuple[str, _ParsedTimestamp]] = []
        parsed_timestamps_by_field: dict[str, tuple[str, _ParsedTimestamp]] = {}
        for field_name in TIMESTAMP_FIELDS:
            match = folded.get(field_name.casefold())
            if match is not None:
                actual_name, timestamp_value = match
                statistics = timestamp_statistics.setdefault(
                    str(actual_name), Counter()
                )
                statistics["present_count"] += 1
                parsed_timestamp = _parse_timestamp(timestamp_value)
                if parsed_timestamp is None:
                    statistics["unparseable_count"] += 1
                    continue
                statistics["parsed_count"] += 1
                if parsed_timestamp.timezone_aware:
                    statistics["timezone_aware_count"] += 1
                else:
                    statistics["timezone_naive_count"] += 1
                timestamps_in_record.append((str(actual_name), parsed_timestamp))
                parsed_timestamps_by_field[field_name] = (
                    str(actual_name),
                    parsed_timestamp,
                )

        if len(timestamps_in_record) > 1:
            multiple_timestamp_candidate_count += 1
        record_has_conflict = False
        for (first_name, first), (second_name, second) in combinations(
            timestamps_in_record, 2
        ):
            delta, basis = _timestamp_delta(first, second)
            if delta <= TIMESTAMP_CONFLICT_THRESHOLD_SECONDS:
                continue
            record_has_conflict = True
            pair = (first_name, second_name)
            conflict = timestamp_conflicts.setdefault(
                pair,
                {
                    "first_field": first_name,
                    "second_field": second_name,
                    "record_count": 0,
                    "maximum_wall_clock_delta_seconds": 0.0,
                    "comparison_basis_counts": Counter(),
                },
            )
            conflict["record_count"] = int(conflict["record_count"]) + 1
            conflict["maximum_wall_clock_delta_seconds"] = max(
                float(conflict["maximum_wall_clock_delta_seconds"]), delta
            )
            basis_counts = conflict["comparison_basis_counts"]
            assert isinstance(basis_counts, Counter)
            basis_counts[basis] += 1
        if record_has_conflict:
            conflicting_timestamp_record_count += 1

        occurrence_timestamp = next(
            (
                parsed_timestamps_by_field[field_name]
                for field_name in EVENT_OCCURRENCE_TIMESTAMP_FIELDS
                if field_name in parsed_timestamps_by_field
            ),
            None,
        )
        if occurrence_timestamp is not None:
            timestamp_field, parsed_timestamp = occurrence_timestamp
            timestamp_range_sources[timestamp_field] += 1
            if minimum_timestamp is None:
                minimum_timestamp = parsed_timestamp
                maximum_timestamp = parsed_timestamp
            elif minimum_timestamp.timezone_aware == parsed_timestamp.timezone_aware:
                assert maximum_timestamp is not None
                current = (
                    parsed_timestamp.value.astimezone(timezone.utc)
                    if parsed_timestamp.timezone_aware
                    else parsed_timestamp.value
                )
                minimum = (
                    minimum_timestamp.value.astimezone(timezone.utc)
                    if minimum_timestamp.timezone_aware
                    else minimum_timestamp.value
                )
                maximum = (
                    maximum_timestamp.value.astimezone(timezone.utc)
                    if maximum_timestamp.timezone_aware
                    else maximum_timestamp.value
                )
                minimum_timestamp = (
                    parsed_timestamp if current < minimum else minimum_timestamp
                )
                maximum_timestamp = (
                    parsed_timestamp if current > maximum else maximum_timestamp
                )
            else:
                mixed_timezone_range_count += 1

    fields = _field_documents(field_accumulators, record_count)
    top_level_fields = _field_documents(top_level_accumulators, record_count)
    mappings = _mapping_proposals(fields, context_accumulators)
    warnings: list[str] = []

    conflict_documents = []
    for pair in sorted(timestamp_conflicts):
        conflict = timestamp_conflicts[pair]
        bases = conflict.pop("comparison_basis_counts")
        assert isinstance(bases, Counter)
        conflict["comparison_basis_counts"] = dict(sorted(bases.items()))
        conflict_documents.append(conflict)
    if conflict_documents:
        warnings.append(
            "Timestamp candidates differ by more than "
            f"{TIMESTAMP_CONFLICT_THRESHOLD_SECONDS:.0f} seconds in "
            f"{conflicting_timestamp_record_count} records; timezone-naive values "
            "were compared only as wall-clock text and were not assumed to be UTC."
        )
    naive_count = sum(
        statistics["timezone_naive_count"]
        for statistics in timestamp_statistics.values()
    )
    if naive_count:
        warnings.append(
            f"Observed {naive_count} timezone-naive timestamp values. Their timezone "
            "semantics remain unresolved; no UTC timezone was assigned."
        )
    if any(field in timestamp_statistics for field in TIMESTAMP_REVIEW_ONLY_FIELDS):
        warnings.append(
            "UtcTime was observed but remains review-only until its timezone "
            "semantics are confirmed; it was not selected as an event occurrence "
            "timestamp."
        )
    if any(
        field in timestamp_statistics
        for field in TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS
    ):
        warnings.append(
            "CreationUtcTime was observed as creation metadata and was excluded "
            "from event occurrence timestamp selection."
        )
    if mixed_timezone_range_count:
        warnings.append(
            "Preferred timestamp candidates mixed timezone-aware and timezone-naive "
            "values; incomparable records were excluded from the aggregate range."
        )

    transformation_fields = []
    for field_name in ("source_port", "destination_port"):
        proposal = dict(mappings[field_name])
        if any(
            dict(candidate).get("expected_transformation")
            == "validated_string_to_integer"
            for candidate in proposal["candidates"]
        ):
            transformation_fields.append(field_name)
    if transformation_fields:
        warnings.append(
            "Canonical integer port fields require validated string-to-integer "
            "transformation for observed source strings: "
            + ", ".join(transformation_fields)
            + ". No transformation was applied during inspection."
        )

    if (
        (SYSMON_PROVIDER, "1") in context_accumulators
        and (SECURITY_PROVIDER, "4688") in context_accumulators
    ):
        warnings.append(
            "ProcessId changes semantic role by context: it is process_id in Sysmon "
            "Event ID 1 but parent_process_id in Security Event ID 4688."
        )
    if any(str(document["path"]) == "/AccountName" for document in fields):
        warnings.append(
            "AccountName is not automatically mapped to target_user because its role "
            "varies across providers and Event IDs."
        )
    context_unmapped = dict(mappings["context_specific_unmapped"])
    if context_unmapped["status"] == "context_specific_unmapped":
        warnings.append(
            "Sysmon Event ID 10 SourceImage/TargetImage and related identifiers use "
            "source/target process roles. canonical-event/v2 does not force them "
            "into process_name or parent_process_name."
        )
    ambiguous_fields = [
        field_name
        for field_name, proposal in mappings.items()
        if field_name != "context_specific_unmapped"
        and dict(proposal).get("status") == "ambiguous"
    ]
    if ambiguous_fields:
        warnings.append(
            "Multiple context-aware candidates remain reviewable for: "
            + ", ".join(ambiguous_fields)
            + "."
        )

    timestamp_field_documents = {
        name: {
            "present_count": statistics["present_count"],
            "parsed_count": statistics["parsed_count"],
            "unparseable_count": statistics["unparseable_count"],
            "timezone_aware_count": statistics["timezone_aware_count"],
            "timezone_naive_count": statistics["timezone_naive_count"],
        }
        for name, statistics in sorted(timestamp_statistics.items())
    }
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
            "recommendation": {
                "status": "candidate",
                "primary_source_field": EVENT_OCCURRENCE_TIMESTAMP_FIELDS[0],
                "fallback_source_fields": list(
                    EVENT_OCCURRENCE_TIMESTAMP_FIELDS[1:]
                ),
                "review_only_source_fields": list(TIMESTAMP_REVIEW_ONLY_FIELDS),
                "excluded_occurrence_source_fields": list(
                    TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS
                ),
                "rationale": (
                    "Use @timestamp for the current datasets, then a parseable "
                    "TimeCreated or EventTime. UtcTime requires timezone semantic "
                    "review, and CreationUtcTime is not an occurrence timestamp."
                ),
            },
            "source_fields": timestamp_field_documents,
            "range_source_field_counts": dict(sorted(timestamp_range_sources.items())),
            "multiple_candidate_record_count": multiple_timestamp_candidate_count,
            "conflicting_candidate_record_count": conflicting_timestamp_record_count,
            "conflict_threshold_seconds": TIMESTAMP_CONFLICT_THRESHOLD_SECONDS,
            "conflicts": conflict_documents,
            "minimum": _format_timestamp(minimum_timestamp),
            "maximum": _format_timestamp(maximum_timestamp),
            "minimum_utc": (
                _format_timestamp(minimum_timestamp)
                if minimum_timestamp is not None and minimum_timestamp.timezone_aware
                else None
            ),
            "maximum_utc": (
                _format_timestamp(maximum_timestamp)
                if maximum_timestamp is not None and maximum_timestamp.timezone_aware
                else None
            ),
            "timezone_status": (
                "aware"
                if minimum_timestamp is not None and minimum_timestamp.timezone_aware
                else "naive_or_unavailable"
            ),
            "note": (
                "Timestamps are parsed only for aggregate structural inspection. "
                "Timezone-naive values are not assigned UTC and no canonical event "
                "is emitted."
            ),
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
        "security_relevant_structural_contexts": _structural_context_documents(
            context_accumulators
        ),
        "canonical_mapping_proposals": mappings,
        "warnings": warnings,
    }
