"""Strict, scenario-independent validation for Ground Truth Core documents.

This module validates a reviewable data contract only. It does not merge
production artifacts, build ground truth, answer evaluation questions, or
promote any value to a confirmed state.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from pathlib import Path
import re
from typing import Any


SCENARIO_GROUND_TRUTH_SCHEMA_VERSION = "scenario-ground-truth/v1"

TOP_LEVEL_FIELDS = (
    "schema_version",
    "scenario",
    "input_provenance",
    "entities",
    "facts",
    "relationships",
    "evidence",
    "sigma_findings",
    "mitre_assessments",
    "summary",
    "queryable_dimensions",
    "review",
    "warnings",
)

SCENARIO_FIELDS = (
    "scenario_id",
    "scenario_name",
    "description",
    "analysis_status",
    "time_window",
)
TIME_WINDOW_FIELDS = ("start", "end")
INPUT_PROVENANCE_FIELDS = (
    "input_id",
    "input_type",
    "path",
    "schema_version",
    "sha256",
    "scenario_id",
)
ENTITY_FIELDS = (
    "entity_id",
    "entity_type",
    "name",
    "attributes",
    "status",
    "evidence_ids",
)
FACT_FIELDS = (
    "fact_id",
    "subject",
    "predicate",
    "object",
    "attributes",
    "status",
    "evidence_ids",
    "source_references",
)
RELATIONSHIP_FIELDS = (
    "relationship_id",
    "relationship_type",
    "source_entity_id",
    "target_entity_id",
    "attributes",
    "status",
    "evidence_ids",
    "source_references",
)
EVIDENCE_FIELDS = (
    "evidence_id",
    "evidence_type",
    "summary",
    "status",
    "observations",
    "source_references",
)
OBSERVATION_FIELDS = (
    "source_file",
    "raw_record_ref",
    "provider",
    "event_id",
    "timestamp",
)
SOURCE_REFERENCE_FIELDS = ("source_file", "raw_record_ref")
SIGMA_FINDING_FIELDS = (
    "finding_id",
    "rule_id",
    "rule_title",
    "rule_sha256",
    "status",
    "observation_match_ids",
    "behavior_match_ids",
    "evidence_ids",
    "source_references",
    "caveats",
)
MITRE_ASSESSMENT_FIELDS = (
    "assessment_id",
    "external_id",
    "stix_id",
    "name",
    "origin",
    "status",
    "evidence_support",
    "supporting_evidence_ids",
    "supporting_sigma_rule_ids",
    "rationale",
    "review_status",
)
SUMMARY_FIELDS = (
    "observed_behavior",
    "key_entities",
    "key_relationships",
    "limitations",
)
REVIEW_FIELDS = (
    "review_status",
    "reviewer",
    "reviewed_at",
    "decisions",
    "notes",
)

CORE_STATUSES = frozenset({"observed", "inferred", "candidate"})
SIGMA_FINDING_STATUSES = frozenset({"candidate"})
MITRE_ASSESSMENT_STATUSES = frozenset({"candidate"})
MITRE_ORIGINS = frozenset({"sigma_tag", "evidence_review"})
EVIDENCE_SUPPORT_VALUES = frozenset(
    {
        "supported_by_observed_behavior",
        "not_observed_in_reviewed_scope",
        "not_supported_by_observed_command",
        "not_assessed",
    }
)
MITRE_REVIEW_STATUSES = frozenset({"needs_review"})
SCENARIO_ANALYSIS_STATUSES = frozenset({"draft_reviewable"})
DOCUMENT_REVIEW_STATUSES = frozenset({"pending_human_review"})

FORBIDDEN_QUESTION_FIELDS = frozenset(
    {
        "evaluation_questions",
        "expected_answers",
        "question_id",
        "question_text",
        "expected_answer",
        "answer_id",
    }
)
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class GroundTruthValidationError(ValueError):
    """Raised when a Ground Truth Core document violates its contract."""


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GroundTruthValidationError(f"{path} must be a JSON object")
    return value


def _require_list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise GroundTruthValidationError(f"{path} must be a list")
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    expected_fields: tuple[str, ...],
    path: str,
) -> None:
    expected = set(expected_fields)
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise GroundTruthValidationError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _require_nonempty_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GroundTruthValidationError(f"{path} must be a non-empty string")
    return value


def _require_optional_string(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _require_nonempty_string(value, path)


def _require_sha256(value: object, path: str) -> str:
    digest = _require_nonempty_string(value, path)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise GroundTruthValidationError(
            f"{path} must contain exactly 64 hexadecimal characters"
        )
    return digest


def _require_status(value: object, allowed: frozenset[str], path: str) -> str:
    status = _require_nonempty_string(value, path)
    if status not in allowed:
        raise GroundTruthValidationError(
            f"{path} has unsupported value {status!r}; allowed: {sorted(allowed)!r}"
        )
    return status


def _require_string_list(
    value: object,
    path: str,
    *,
    unique: bool = False,
) -> list[str]:
    items = _require_list(value, path)
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = _require_nonempty_string(item, f"{path}[{index}]")
        if unique and text in seen:
            raise GroundTruthValidationError(
                f"{path} must not contain duplicate value {text!r}"
            )
        seen.add(text)
        result.append(text)
    return result


def _validate_json_value(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GroundTruthValidationError(f"{path} must contain finite JSON numbers")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GroundTruthValidationError(
                    f"{path} contains a non-string object key"
                )
            _validate_json_value(item, f"{path}.{key}")
        return
    raise GroundTruthValidationError(
        f"{path} contains a value that cannot be represented in JSON"
    )


def _is_status_like_field(field_name: str) -> bool:
    normalized = field_name.casefold().replace("-", "_")
    return "status" in normalized or "review" in normalized


def _direct_status_value_is_confirmed(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() == "confirmed"
    if isinstance(value, list):
        return any(_direct_status_value_is_confirmed(item) for item in value)
    return False


def _scan_contract_guards(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = key.casefold()
            if normalized_key in FORBIDDEN_QUESTION_FIELDS:
                raise GroundTruthValidationError(
                    f"{path}.{key} is forbidden in Ground Truth Core"
                )
            if _is_status_like_field(key) and _direct_status_value_is_confirmed(item):
                raise GroundTruthValidationError(
                    f"{path}.{key} must not contain the value 'confirmed'"
                )
            _scan_contract_guards(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_contract_guards(item, f"{path}[{index}]")


def _add_unique_identifier(
    identifier: str,
    seen: set[str],
    *,
    path: str,
    label: str,
) -> None:
    if identifier in seen:
        raise GroundTruthValidationError(f"Duplicate {label} {identifier!r} at {path}")
    seen.add(identifier)


def _require_known_ids(
    value: object,
    known_ids: set[str],
    *,
    path: str,
    label: str,
) -> None:
    for identifier in _require_string_list(value, path):
        if identifier not in known_ids:
            raise GroundTruthValidationError(
                f"{path} references unknown {label} {identifier!r}"
            )


def _validate_source_references(value: object, path: str) -> None:
    references = _require_list(value, path)
    for index, raw_reference in enumerate(references):
        reference_path = f"{path}[{index}]"
        reference = _require_object(raw_reference, reference_path)
        _require_exact_fields(reference, SOURCE_REFERENCE_FIELDS, reference_path)
        _require_nonempty_string(
            reference["source_file"], f"{reference_path}.source_file"
        )
        _require_nonempty_string(
            reference["raw_record_ref"], f"{reference_path}.raw_record_ref"
        )


def _validate_scenario(value: object) -> str:
    path = "$.scenario"
    scenario = _require_object(value, path)
    _require_exact_fields(scenario, SCENARIO_FIELDS, path)
    scenario_id = _require_nonempty_string(scenario["scenario_id"], f"{path}.scenario_id")
    _require_nonempty_string(scenario["scenario_name"], f"{path}.scenario_name")
    _require_nonempty_string(scenario["description"], f"{path}.description")
    _require_status(
        scenario["analysis_status"],
        SCENARIO_ANALYSIS_STATUSES,
        f"{path}.analysis_status",
    )
    time_window_path = f"{path}.time_window"
    time_window = _require_object(scenario["time_window"], time_window_path)
    _require_exact_fields(time_window, TIME_WINDOW_FIELDS, time_window_path)
    _require_optional_string(time_window["start"], f"{time_window_path}.start")
    _require_optional_string(time_window["end"], f"{time_window_path}.end")
    return scenario_id


def _validate_input_provenance(value: object, scenario_id: str) -> None:
    items = _require_list(value, "$.input_provenance")
    seen: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.input_provenance[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, INPUT_PROVENANCE_FIELDS, path)
        input_id = _require_nonempty_string(item["input_id"], f"{path}.input_id")
        _add_unique_identifier(input_id, seen, path=path, label="input_id")
        _require_nonempty_string(item["input_type"], f"{path}.input_type")
        _require_nonempty_string(item["path"], f"{path}.path")
        _require_nonempty_string(item["schema_version"], f"{path}.schema_version")
        _require_sha256(item["sha256"], f"{path}.sha256")
        artifact_scenario_id = item["scenario_id"]
        if artifact_scenario_id is not None:
            artifact_scenario_id = _require_nonempty_string(
                artifact_scenario_id, f"{path}.scenario_id"
            )
            if artifact_scenario_id != scenario_id:
                raise GroundTruthValidationError(
                    f"{path}.scenario_id must match $.scenario.scenario_id"
                )


def _validate_observations(value: object, path: str) -> None:
    observations = _require_list(value, path)
    for index, raw_observation in enumerate(observations):
        observation_path = f"{path}[{index}]"
        observation = _require_object(raw_observation, observation_path)
        _require_exact_fields(observation, OBSERVATION_FIELDS, observation_path)
        _require_nonempty_string(
            observation["source_file"], f"{observation_path}.source_file"
        )
        _require_nonempty_string(
            observation["raw_record_ref"], f"{observation_path}.raw_record_ref"
        )
        _require_optional_string(
            observation["provider"], f"{observation_path}.provider"
        )
        event_id = observation["event_id"]
        if event_id is not None:
            if isinstance(event_id, bool) or not isinstance(event_id, (str, int)):
                raise GroundTruthValidationError(
                    f"{observation_path}.event_id must be a string, integer, or null"
                )
            if isinstance(event_id, str):
                _require_nonempty_string(event_id, f"{observation_path}.event_id")
        _require_optional_string(
            observation["timestamp"], f"{observation_path}.timestamp"
        )


def _validate_evidence(value: object) -> set[str]:
    items = _require_list(value, "$.evidence")
    evidence_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.evidence[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, EVIDENCE_FIELDS, path)
        evidence_id = _require_nonempty_string(item["evidence_id"], f"{path}.evidence_id")
        _add_unique_identifier(
            evidence_id, evidence_ids, path=path, label="evidence_id"
        )
        _require_nonempty_string(item["evidence_type"], f"{path}.evidence_type")
        _require_nonempty_string(item["summary"], f"{path}.summary")
        _require_status(item["status"], CORE_STATUSES, f"{path}.status")
        _validate_observations(item["observations"], f"{path}.observations")
        _validate_source_references(
            item["source_references"], f"{path}.source_references"
        )
    return evidence_ids


def _validate_entities(value: object, evidence_ids: set[str]) -> set[str]:
    items = _require_list(value, "$.entities")
    entity_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.entities[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, ENTITY_FIELDS, path)
        entity_id = _require_nonempty_string(item["entity_id"], f"{path}.entity_id")
        _add_unique_identifier(entity_id, entity_ids, path=path, label="entity_id")
        _require_nonempty_string(item["entity_type"], f"{path}.entity_type")
        _require_nonempty_string(item["name"], f"{path}.name")
        _require_object(item["attributes"], f"{path}.attributes")
        _require_status(item["status"], CORE_STATUSES, f"{path}.status")
        _require_known_ids(
            item["evidence_ids"],
            evidence_ids,
            path=f"{path}.evidence_ids",
            label="evidence_id",
        )
    return entity_ids


def _validate_fact_term(value: object, path: str) -> None:
    if value is None:
        raise GroundTruthValidationError(f"{path} must not be null")
    if isinstance(value, str):
        _require_nonempty_string(value, path)


def _validate_facts(value: object, evidence_ids: set[str]) -> None:
    items = _require_list(value, "$.facts")
    fact_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.facts[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, FACT_FIELDS, path)
        fact_id = _require_nonempty_string(item["fact_id"], f"{path}.fact_id")
        _add_unique_identifier(fact_id, fact_ids, path=path, label="fact_id")
        _validate_fact_term(item["subject"], f"{path}.subject")
        _require_nonempty_string(item["predicate"], f"{path}.predicate")
        _validate_fact_term(item["object"], f"{path}.object")
        _require_object(item["attributes"], f"{path}.attributes")
        _require_status(item["status"], CORE_STATUSES, f"{path}.status")
        _require_known_ids(
            item["evidence_ids"],
            evidence_ids,
            path=f"{path}.evidence_ids",
            label="evidence_id",
        )
        _validate_source_references(
            item["source_references"], f"{path}.source_references"
        )


def _validate_relationships(
    value: object,
    entity_ids: set[str],
    evidence_ids: set[str],
) -> None:
    items = _require_list(value, "$.relationships")
    relationship_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.relationships[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, RELATIONSHIP_FIELDS, path)
        relationship_id = _require_nonempty_string(
            item["relationship_id"], f"{path}.relationship_id"
        )
        _add_unique_identifier(
            relationship_id,
            relationship_ids,
            path=path,
            label="relationship_id",
        )
        _require_nonempty_string(
            item["relationship_type"], f"{path}.relationship_type"
        )
        for field in ("source_entity_id", "target_entity_id"):
            entity_id = _require_nonempty_string(item[field], f"{path}.{field}")
            if entity_id not in entity_ids:
                raise GroundTruthValidationError(
                    f"{path}.{field} references unknown entity_id {entity_id!r}"
                )
        _require_object(item["attributes"], f"{path}.attributes")
        _require_status(item["status"], CORE_STATUSES, f"{path}.status")
        _require_known_ids(
            item["evidence_ids"],
            evidence_ids,
            path=f"{path}.evidence_ids",
            label="evidence_id",
        )
        _validate_source_references(
            item["source_references"], f"{path}.source_references"
        )


def _validate_sigma_findings(
    value: object,
    evidence_ids: set[str],
) -> set[str]:
    items = _require_list(value, "$.sigma_findings")
    finding_ids: set[str] = set()
    rule_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.sigma_findings[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, SIGMA_FINDING_FIELDS, path)
        finding_id = _require_nonempty_string(item["finding_id"], f"{path}.finding_id")
        _add_unique_identifier(
            finding_id, finding_ids, path=path, label="finding_id"
        )
        rule_id = _require_nonempty_string(item["rule_id"], f"{path}.rule_id")
        rule_ids.add(rule_id)
        _require_nonempty_string(item["rule_title"], f"{path}.rule_title")
        _require_sha256(item["rule_sha256"], f"{path}.rule_sha256")
        _require_status(
            item["status"], SIGMA_FINDING_STATUSES, f"{path}.status"
        )
        _require_string_list(
            item["observation_match_ids"], f"{path}.observation_match_ids"
        )
        _require_string_list(
            item["behavior_match_ids"], f"{path}.behavior_match_ids"
        )
        _require_known_ids(
            item["evidence_ids"],
            evidence_ids,
            path=f"{path}.evidence_ids",
            label="evidence_id",
        )
        _validate_source_references(
            item["source_references"], f"{path}.source_references"
        )
        _require_string_list(item["caveats"], f"{path}.caveats")
    return rule_ids


def _validate_mitre_assessments(
    value: object,
    evidence_ids: set[str],
    sigma_rule_ids: set[str],
) -> None:
    items = _require_list(value, "$.mitre_assessments")
    assessment_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"$.mitre_assessments[{index}]"
        item = _require_object(raw_item, path)
        _require_exact_fields(item, MITRE_ASSESSMENT_FIELDS, path)
        assessment_id = _require_nonempty_string(
            item["assessment_id"], f"{path}.assessment_id"
        )
        _add_unique_identifier(
            assessment_id,
            assessment_ids,
            path=path,
            label="assessment_id",
        )
        _require_nonempty_string(item["external_id"], f"{path}.external_id")
        _require_nonempty_string(item["stix_id"], f"{path}.stix_id")
        _require_nonempty_string(item["name"], f"{path}.name")
        _require_status(item["origin"], MITRE_ORIGINS, f"{path}.origin")
        _require_status(
            item["status"], MITRE_ASSESSMENT_STATUSES, f"{path}.status"
        )
        _require_status(
            item["evidence_support"],
            EVIDENCE_SUPPORT_VALUES,
            f"{path}.evidence_support",
        )
        _require_known_ids(
            item["supporting_evidence_ids"],
            evidence_ids,
            path=f"{path}.supporting_evidence_ids",
            label="evidence_id",
        )
        _require_known_ids(
            item["supporting_sigma_rule_ids"],
            sigma_rule_ids,
            path=f"{path}.supporting_sigma_rule_ids",
            label="Sigma rule_id",
        )
        _require_nonempty_string(item["rationale"], f"{path}.rationale")
        _require_status(
            item["review_status"],
            MITRE_REVIEW_STATUSES,
            f"{path}.review_status",
        )


def _validate_summary(value: object) -> None:
    path = "$.summary"
    summary = _require_object(value, path)
    _require_exact_fields(summary, SUMMARY_FIELDS, path)
    for field in SUMMARY_FIELDS:
        _require_string_list(summary[field], f"{path}.{field}")


def _validate_review(value: object) -> None:
    path = "$.review"
    review = _require_object(value, path)
    _require_exact_fields(review, REVIEW_FIELDS, path)
    _require_status(
        review["review_status"],
        DOCUMENT_REVIEW_STATUSES,
        f"{path}.review_status",
    )
    if review["reviewer"] is not None:
        raise GroundTruthValidationError(f"{path}.reviewer must be null in this version")
    if review["reviewed_at"] is not None:
        raise GroundTruthValidationError(f"{path}.reviewed_at must be null in this version")
    decisions = _require_list(review["decisions"], f"{path}.decisions")
    for index, decision in enumerate(decisions):
        if isinstance(decision, str):
            _require_nonempty_string(decision, f"{path}.decisions[{index}]")
    _require_string_list(review["notes"], f"{path}.notes")


def validate_ground_truth_document(document: object) -> None:
    """Validate a Ground Truth Core document without changing it."""

    root = _require_object(document, "$")
    _validate_json_value(root, "$")
    _scan_contract_guards(root, "$")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "$")

    schema_version = _require_nonempty_string(root["schema_version"], "$.schema_version")
    if schema_version != SCENARIO_GROUND_TRUTH_SCHEMA_VERSION:
        raise GroundTruthValidationError(
            f"$.schema_version must be {SCENARIO_GROUND_TRUTH_SCHEMA_VERSION!r}"
        )

    scenario_id = _validate_scenario(root["scenario"])
    _validate_input_provenance(root["input_provenance"], scenario_id)
    evidence_ids = _validate_evidence(root["evidence"])
    entity_ids = _validate_entities(root["entities"], evidence_ids)
    _validate_facts(root["facts"], evidence_ids)
    _validate_relationships(root["relationships"], entity_ids, evidence_ids)
    sigma_rule_ids = _validate_sigma_findings(root["sigma_findings"], evidence_ids)
    _validate_mitre_assessments(
        root["mitre_assessments"], evidence_ids, sigma_rule_ids
    )
    _validate_summary(root["summary"])
    _require_string_list(
        root["queryable_dimensions"], "$.queryable_dimensions", unique=True
    )
    _validate_review(root["review"])
    _require_string_list(root["warnings"], "$.warnings")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"non-standard JSON number {value!r}")


def load_ground_truth_document(path: Path) -> dict[str, Any]:
    """Load UTF-8 JSON from *path*, validate it, and include the path in errors."""

    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_number,
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise GroundTruthValidationError(
            f"Cannot read ground truth document {source_path}: {exc}"
        ) from exc

    try:
        validate_ground_truth_document(document)
    except GroundTruthValidationError as exc:
        raise GroundTruthValidationError(
            f"Invalid ground truth document {source_path}: {exc}"
        ) from exc
    return document


__all__ = (
    "SCENARIO_GROUND_TRUTH_SCHEMA_VERSION",
    "GroundTruthValidationError",
    "load_ground_truth_document",
    "validate_ground_truth_document",
)
