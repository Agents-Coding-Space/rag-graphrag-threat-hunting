"""Fail-closed evaluator for the Sigma subset accepted by the safe loader."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, TypeAlias

from .loader import SigmaRule, condition_selection_names


DEFAULT_CANONICAL_FIELD_MAPPING: Mapping[str, str | None] = MappingProxyType(
    {
        "Image": "process_name",
        "ParentImage": "parent_process_name",
        "CommandLine": "command_line",
        "OriginalFileName": None,
    }
)


class SigmaEvaluationError(ValueError):
    """Raised when evaluation would require unsupported assumptions."""


LogsourceSignature: TypeAlias = tuple[tuple[str, str], ...]
LogsourceEventMatcher: TypeAlias = Callable[[Mapping[str, object]], bool]


WINDOWS_PROCESS_CREATION_LOGSOURCE: LogsourceSignature = (
    ("category", "process_creation"),
    ("product", "windows"),
)
_WINDOWS_PROCESS_CREATION_PROVIDERS: Mapping[str, str] = MappingProxyType(
    {
        "microsoft-windows-sysmon": "1",
        "microsoft-windows-security-auditing": "4688",
    }
)


def _normalized_event_id(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if 0 <= value <= 0xFFFFFFFF else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return value.lstrip("0") or "0"
    return None


def _is_windows_process_creation(event: Mapping[str, object]) -> bool:
    provider = event.get("provider")
    if not isinstance(provider, str):
        return False
    expected_event_id = _WINDOWS_PROCESS_CREATION_PROVIDERS.get(provider.casefold())
    return (
        expected_event_id is not None
        and _normalized_event_id(event.get("event_id")) == expected_event_id
    )


SUPPORTED_LOGSOURCE_EVENT_MATCHERS: Mapping[
    LogsourceSignature,
    LogsourceEventMatcher,
] = MappingProxyType(
    {WINDOWS_PROCESS_CREATION_LOGSOURCE: _is_windows_process_creation}
)


def _logsource_event_matcher(rule: SigmaRule) -> LogsourceEventMatcher:
    logsource = rule.logsource
    if not isinstance(logsource, Mapping) or not logsource:
        raise SigmaEvaluationError(
            f"Sigma rule {rule.rule_id!r} has an invalid logsource mapping"
        )

    items: list[tuple[str, str]] = []
    for key, value in logsource.items():
        if not isinstance(key, str) or not key.strip():
            raise SigmaEvaluationError(
                f"Sigma rule {rule.rule_id!r} has an invalid logsource key"
            )
        if not isinstance(value, str) or not value.strip():
            raise SigmaEvaluationError(
                f"Sigma rule {rule.rule_id!r} has an invalid value for "
                f"logsource key {key!r}"
            )
        items.append((key, value))

    signature = tuple(sorted(items))
    matcher = SUPPORTED_LOGSOURCE_EVENT_MATCHERS.get(signature)
    if matcher is None:
        rendered = ", ".join(f"{key}={value!r}" for key, value in signature)
        raise SigmaEvaluationError(
            f"Unsupported Sigma logsource for rule {rule.rule_id!r}: {rendered}"
        )
    return matcher


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _deterministic_id(prefix: str, identity: object) -> str:
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:20]}"


def _provenance(event: Mapping[str, object]) -> tuple[str, str]:
    values: list[str] = []
    for field in ("source_file", "raw_record_ref"):
        value = event.get(field)
        if not isinstance(value, str) or not value.strip():
            raise SigmaEvaluationError(
                f"Canonical event requires non-empty provenance field {field!r}"
            )
        values.append(value)
    return values[0], values[1]


def _field_parts(expression: str) -> tuple[str, str | None]:
    parts = expression.split("|")
    return parts[0].strip(), parts[1].strip().casefold() if len(parts) == 2 else None


def _expected_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(str(item) for item in value)
    raise SigmaEvaluationError("Validated Sigma predicate has invalid values")


def _matching_values(
    observed: object,
    expected: tuple[str, ...],
    modifier: str | None,
) -> tuple[str, ...]:
    if not isinstance(observed, str):
        return ()
    folded = observed.casefold()
    if modifier is None:
        return tuple(item for item in expected if folded == item.casefold())
    if modifier == "endswith":
        return tuple(item for item in expected if folded.endswith(item.casefold()))
    if modifier == "contains":
        return tuple(item for item in expected if item.casefold() in folded)
    raise SigmaEvaluationError(f"Unsupported Sigma modifier: {modifier!r}")


def _predicate_mapping_result(
    predicate_mapping: Mapping[str, object],
    event: Mapping[str, object],
    field_mapping: Mapping[str, str | None],
) -> tuple[bool, tuple[dict[str, object], ...]]:
    details: list[dict[str, object]] = []
    for expression, expected_value in predicate_mapping.items():
        sigma_field, modifier = _field_parts(str(expression))
        if sigma_field not in field_mapping:
            raise SigmaEvaluationError(
                f"Unsupported Sigma field without canonical mapping: {sigma_field!r}"
            )
        canonical_field = field_mapping[sigma_field]
        if canonical_field is None:
            return False, ()
        expected = _expected_values(expected_value)
        observed = event.get(canonical_field)
        matched_values = _matching_values(observed, expected, modifier)
        if not matched_values:
            return False, ()
        details.append(
            {
                "sigma_field": sigma_field,
                "canonical_field": canonical_field,
                "modifier": modifier or "equals",
                "observed_value": observed,
                "matched_values": list(matched_values),
            }
        )
    return True, tuple(details)


def _selection_result(
    selection: object,
    event: Mapping[str, object],
    field_mapping: Mapping[str, str | None],
) -> tuple[bool, tuple[dict[str, object], ...]]:
    alternatives = (selection,) if isinstance(selection, Mapping) else tuple(selection)  # type: ignore[arg-type]
    matched_details: list[dict[str, object]] = []
    matched = False
    for alternative in alternatives:
        if not isinstance(alternative, Mapping):
            raise SigmaEvaluationError("Validated Sigma selection contains a non-mapping")
        alternative_matched, details = _predicate_mapping_result(
            alternative,
            event,
            field_mapping,
        )
        if alternative_matched:
            matched = True
            matched_details.extend(details)
    return matched, tuple(matched_details)


def _rule_sigma_fields(rule: SigmaRule) -> tuple[str, ...]:
    fields: set[str] = set()
    for selection_name in condition_selection_names(rule.detection):
        selection = rule.detection[selection_name]
        alternatives = (selection,) if isinstance(selection, Mapping) else tuple(selection)  # type: ignore[arg-type]
        for alternative in alternatives:
            if not isinstance(alternative, Mapping):
                raise SigmaEvaluationError("Validated Sigma selection contains a non-mapping")
            fields.update(_field_parts(str(expression))[0] for expression in alternative)
    return tuple(sorted(fields))


@dataclass(frozen=True)
class RuleEvaluation:
    """Observation-level result for one rule."""

    rule: SigmaRule
    examined_events: int
    observation_matches: tuple[Mapping[str, object], ...]
    unmapped_fields: tuple[str, ...]


def evaluate_sigma_rule(
    rule: SigmaRule,
    events: Iterable[Mapping[str, object]],
    *,
    field_mapping: Mapping[str, str | None] = DEFAULT_CANONICAL_FIELD_MAPPING,
) -> RuleEvaluation:
    """Evaluate one rule with case-insensitive Windows string semantics."""

    logsource_matches = _logsource_event_matcher(rule)
    sigma_fields = _rule_sigma_fields(rule)
    unsupported = tuple(field for field in sigma_fields if field not in field_mapping)
    if unsupported:
        raise SigmaEvaluationError(
            "Unsupported Sigma fields without canonical mapping: "
            + ", ".join(unsupported)
        )
    unmapped = tuple(field for field in sigma_fields if field_mapping[field] is None)
    selection_names = condition_selection_names(rule.detection)
    matches: list[dict[str, object]] = []
    examined = 0
    for event in events:
        if not isinstance(event, Mapping):
            raise SigmaEvaluationError("Canonical events must be mappings")
        examined += 1
        if not logsource_matches(event):
            continue
        outcomes: list[tuple[str, tuple[dict[str, object], ...]]] = []
        for selection_name in selection_names:
            matched, details = _selection_result(
                rule.detection[selection_name],
                event,
                field_mapping,
            )
            if not matched:
                outcomes = []
                break
            outcomes.append((selection_name, details))
        if not outcomes:
            continue
        source_file, raw_record_ref = _provenance(event)
        matching_fields = [
            detail
            for _, details in outcomes
            for detail in details
        ]
        identity = {
            "rule_id": rule.rule_id,
            "source_file": source_file,
            "raw_record_ref": raw_record_ref,
        }
        matches.append(
            {
                "observation_match_id": _deterministic_id(
                    "sigma-observation-match",
                    identity,
                ),
                "status": "candidate",
                "rule_id": rule.rule_id,
                "source_file": source_file,
                "raw_record_ref": raw_record_ref,
                "provider": event.get("provider"),
                "event_id": (
                    str(event["event_id"]) if event.get("event_id") is not None else None
                ),
                "timestamp": event.get("timestamp"),
                "matched_selections": [name for name, _ in outcomes],
                "matching_fields": matching_fields,
                "evidence_ids": [],
            }
        )
    matches.sort(
        key=lambda item: (
            str(item["source_file"]),
            str(item["raw_record_ref"]),
            str(item["observation_match_id"]),
        )
    )
    return RuleEvaluation(
        rule=rule,
        examined_events=examined,
        observation_matches=tuple(matches),
        unmapped_fields=unmapped,
    )


def evaluate_sigma_rules(
    rules: Iterable[SigmaRule],
    events: Iterable[Mapping[str, object]],
    *,
    field_mapping: Mapping[str, str | None] = DEFAULT_CANONICAL_FIELD_MAPPING,
) -> tuple[RuleEvaluation, ...]:
    """Evaluate unique rules over one validated, reusable event collection."""

    ordered_rules = tuple(sorted(rules, key=lambda rule: rule.rule_id))
    ids = [rule.rule_id for rule in ordered_rules]
    if len(ids) != len(set(ids)):
        raise SigmaEvaluationError("Sigma rule IDs must be unique")
    for rule in ordered_rules:
        _logsource_event_matcher(rule)
    materialized_events = tuple(events)
    provenance: dict[tuple[str, str], Mapping[str, object]] = {}
    for event in materialized_events:
        if not isinstance(event, Mapping):
            raise SigmaEvaluationError("Canonical events must be mappings")
        reference = _provenance(event)
        existing = provenance.get(reference)
        if existing is not None:
            if dict(existing) != dict(event):
                raise SigmaEvaluationError(
                    "Conflicting canonical events share provenance: "
                    f"{reference[0]!r}, {reference[1]!r}"
                )
            raise SigmaEvaluationError(
                "Duplicate canonical event provenance: "
                f"{reference[0]!r}, {reference[1]!r}"
            )
        provenance[reference] = event
    return tuple(
        evaluate_sigma_rule(rule, materialized_events, field_mapping=field_mapping)
        for rule in ordered_rules
    )


__all__ = (
    "DEFAULT_CANONICAL_FIELD_MAPPING",
    "RuleEvaluation",
    "SUPPORTED_LOGSOURCE_EVENT_MATCHERS",
    "SigmaEvaluationError",
    "WINDOWS_PROCESS_CREATION_LOGSOURCE",
    "evaluate_sigma_rule",
    "evaluate_sigma_rules",
)
