"""Data-driven, in-memory builder for reviewable Ground Truth Core documents.

The builder understands artifact contracts, not scenario content. Scenario-specific
facts, assessment decisions, summaries, and display names arrive through config.
File I/O and atomic output are intentionally outside this module.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from hashlib import sha256
import re
from typing import Any

from .schema import (
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthValidationError,
    validate_ground_truth_document,
)


GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION = "ground-truth-build-config/v1"
SCENARIO_EVIDENCE_SCHEMA_VERSION = "scenario-evidence/v1"
SIGMA_REVIEW_SCHEMA_VERSION = "sigma-match-review/v1"
MITRE_RESOLUTION_SCHEMA_VERSION = "mitre-resolution/v1"

BUILD_CONFIG_FIELDS = (
    "schema_version",
    "scenario",
    "entity_name_overrides",
    "facts",
    "mitre_decisions",
    "summary",
    "queryable_dimensions",
    "review_notes",
)
CONFIG_SCENARIO_FIELDS = ("scenario_id", "description")
CONFIG_FACT_FIELDS = (
    "fact_id",
    "subject",
    "predicate",
    "object",
    "attributes",
    "status",
    "evidence_ids",
    "source_references",
)
MITRE_DECISION_FIELDS = (
    "external_id",
    "evidence_support",
    "supporting_evidence_ids",
    "rationale",
)
SUMMARY_FIELDS = (
    "observed_behavior",
    "key_entities",
    "key_relationships",
    "limitations",
)
SOURCE_REFERENCE_FIELDS = ("source_file", "raw_record_ref")
INPUT_PROVENANCE_FIELDS = (
    "input_id",
    "input_type",
    "path",
    "schema_version",
    "sha256",
    "scenario_id",
)

SCENARIO_EVIDENCE_FIELDS = (
    "schema_version",
    "scenario_id",
    "scenario_name",
    "source_files",
    "analysis_status",
    "time_window",
    "observed_entities",
    "evidence",
    "relationships",
    "sigma_rules",
    "mitre_techniques",
    "review_notes",
)
SCENARIO_ENTITY_FIELDS = ("entity_id", "entity_type", "attributes")
SCENARIO_EVIDENCE_ITEM_FIELDS = (
    "evidence_id",
    "evidence_type",
    "status",
    "summary",
    "observations",
    "reason",
    "review_status",
)
SCENARIO_OBSERVATION_FIELDS = (
    "source_file",
    "raw_record_ref",
    "provider",
    "event_id",
    "timestamp",
    "canonical_fields",
    "raw_fields",
)
SCENARIO_RELATIONSHIP_FIELDS = (
    "relationship_id",
    "relationship_type",
    "source_entity_id",
    "target_entity_id",
    "status",
    "supported_by",
    "review_status",
)

CORE_STATUSES = frozenset({"observed", "inferred", "candidate"})
EVIDENCE_SUPPORT_VALUES = frozenset(
    {
        "supported_by_observed_behavior",
        "not_observed_in_reviewed_scope",
        "not_supported_by_observed_command",
        "not_assessed",
    }
)
EXPECTED_INPUT_SCHEMAS = {
    "scenario_evidence": SCENARIO_EVIDENCE_SCHEMA_VERSION,
    "sigma_review": SIGMA_REVIEW_SCHEMA_VERSION,
    "mitre_resolution": MITRE_RESOLUTION_SCHEMA_VERSION,
}
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class GroundTruthBuildError(ValueError):
    """Raised when inputs cannot be merged without guessing."""


def _object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GroundTruthBuildError(f"{path} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise GroundTruthBuildError(f"{path} contains a non-string key")
    return value


def _list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise GroundTruthBuildError(f"{path} must be a list")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: tuple[str, ...], path: str
) -> None:
    expected_set = set(expected)
    actual = set(value)
    missing = sorted(expected_set - actual)
    unexpected = sorted(actual - expected_set)
    details: list[str] = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise GroundTruthBuildError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GroundTruthBuildError(f"{path} must be a non-empty string")
    return value


def _optional_text(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path)


def _sha256_text(value: object, path: str) -> str:
    digest = _text(value, path)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise GroundTruthBuildError(f"{path} must be a SHA-256 value")
    return digest


def _strings(value: object, path: str, *, unique: bool = False) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(value, path)):
        text = _text(item, f"{path}[{index}]")
        if unique and text in seen:
            raise GroundTruthBuildError(f"{path} contains duplicate value {text!r}")
        result.append(text)
        seen.add(text)
    return result


def _status(value: object, allowed: frozenset[str], path: str) -> str:
    status = _text(value, path)
    if status not in allowed:
        raise GroundTruthBuildError(
            f"{path} has unsupported value {status!r}; allowed: {sorted(allowed)!r}"
        )
    return status


def _unique_id(identifier: str, seen: set[str], path: str, label: str) -> None:
    if identifier in seen:
        raise GroundTruthBuildError(f"Duplicate {label} {identifier!r} at {path}")
    seen.add(identifier)


def _source_reference(value: object, path: str) -> tuple[str, str]:
    reference = _object(value, path)
    _exact_fields(reference, SOURCE_REFERENCE_FIELDS, path)
    return (
        _text(reference["source_file"], f"{path}.source_file"),
        _text(reference["raw_record_ref"], f"{path}.raw_record_ref"),
    )


def _source_references(value: object, path: str) -> list[tuple[str, str]]:
    return [
        _source_reference(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path))
    ]


def _reference_documents(
    references: Sequence[tuple[str, str]],
) -> list[dict[str, str]]:
    return [
        {"source_file": source_file, "raw_record_ref": raw_record_ref}
        for source_file, raw_record_ref in sorted(set(references))
    ]


def _deterministic_id(prefix: str, *identity: str) -> str:
    digest = sha256("\x00".join(identity).encode("utf-8")).hexdigest()
    return f"{prefix}--{digest}"


def _fact_term(value: object, path: str) -> None:
    if value is None:
        raise GroundTruthBuildError(f"{path} must not be null")
    if isinstance(value, str):
        _text(value, path)


def _validate_config_fact(value: object, path: str) -> str:
    fact = _object(value, path)
    _exact_fields(fact, CONFIG_FACT_FIELDS, path)
    fact_id = _text(fact["fact_id"], f"{path}.fact_id")
    _fact_term(fact["subject"], f"{path}.subject")
    _text(fact["predicate"], f"{path}.predicate")
    _fact_term(fact["object"], f"{path}.object")
    _object(fact["attributes"], f"{path}.attributes")
    _status(fact["status"], CORE_STATUSES, f"{path}.status")
    _strings(fact["evidence_ids"], f"{path}.evidence_ids")
    _source_references(fact["source_references"], f"{path}.source_references")
    return fact_id


def validate_ground_truth_build_config(build_config: Mapping[str, object]) -> None:
    """Validate scenario decisions without consulting any artifact."""

    config = _object(build_config, "build_config")
    _exact_fields(config, BUILD_CONFIG_FIELDS, "build_config")
    if config["schema_version"] != GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION:
        raise GroundTruthBuildError(
            "build_config.schema_version must be "
            f"{GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION!r}"
        )

    scenario = _object(config["scenario"], "build_config.scenario")
    _exact_fields(scenario, CONFIG_SCENARIO_FIELDS, "build_config.scenario")
    _text(scenario["scenario_id"], "build_config.scenario.scenario_id")
    _text(scenario["description"], "build_config.scenario.description")

    overrides = _object(
        config["entity_name_overrides"], "build_config.entity_name_overrides"
    )
    for entity_id, display_name in overrides.items():
        _text(entity_id, "build_config.entity_name_overrides key")
        _text(display_name, f"build_config.entity_name_overrides.{entity_id}")

    fact_ids: set[str] = set()
    for index, raw_fact in enumerate(_list(config["facts"], "build_config.facts")):
        path = f"build_config.facts[{index}]"
        fact_id = _validate_config_fact(raw_fact, path)
        _unique_id(fact_id, fact_ids, path, "fact_id")

    decision_ids: set[str] = set()
    decisions = _list(config["mitre_decisions"], "build_config.mitre_decisions")
    for index, raw_decision in enumerate(decisions):
        path = f"build_config.mitre_decisions[{index}]"
        decision = _object(raw_decision, path)
        _exact_fields(decision, MITRE_DECISION_FIELDS, path)
        external_id = _text(decision["external_id"], f"{path}.external_id")
        _unique_id(external_id, decision_ids, path, "MITRE decision external_id")
        _status(
            decision["evidence_support"],
            EVIDENCE_SUPPORT_VALUES,
            f"{path}.evidence_support",
        )
        _strings(
            decision["supporting_evidence_ids"],
            f"{path}.supporting_evidence_ids",
            unique=True,
        )
        _text(decision["rationale"], f"{path}.rationale")

    summary = _object(config["summary"], "build_config.summary")
    _exact_fields(summary, SUMMARY_FIELDS, "build_config.summary")
    for field in SUMMARY_FIELDS:
        _strings(summary[field], f"build_config.summary.{field}")
    _strings(
        config["queryable_dimensions"],
        "build_config.queryable_dimensions",
        unique=True,
    )
    _strings(config["review_notes"], "build_config.review_notes")


def _validate_artifact_identity(
    document: Mapping[str, object],
    *,
    label: str,
    schema_version: str,
    scenario_id: str,
) -> None:
    if document.get("schema_version") != schema_version:
        raise GroundTruthBuildError(
            f"{label}.schema_version must be {schema_version!r}"
        )
    if _text(document.get("scenario_id"), f"{label}.scenario_id") != scenario_id:
        raise GroundTruthBuildError(
            f"{label}.scenario_id must match build_config.scenario.scenario_id"
        )


def _validate_input_provenance(
    input_provenance: Sequence[Mapping[str, object]],
    *,
    scenario_id: str,
    documents: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    if isinstance(input_provenance, (str, bytes)) or not isinstance(
        input_provenance, Sequence
    ):
        raise GroundTruthBuildError("input_provenance must be a sequence")

    seen_ids: set[str] = set()
    seen_types: set[str] = set()
    normalized: list[dict[str, object]] = []
    for index, raw_item in enumerate(input_provenance):
        path = f"input_provenance[{index}]"
        item = _object(raw_item, path)
        _exact_fields(item, INPUT_PROVENANCE_FIELDS, path)
        input_id = _text(item["input_id"], f"{path}.input_id")
        _unique_id(input_id, seen_ids, path, "input_id")
        input_type = _text(item["input_type"], f"{path}.input_type")
        if input_type in seen_types:
            raise GroundTruthBuildError(f"Duplicate input_type {input_type!r}")
        if input_type not in EXPECTED_INPUT_SCHEMAS:
            raise GroundTruthBuildError(f"Unsupported input_type {input_type!r}")
        seen_types.add(input_type)
        _text(item["path"], f"{path}.path")
        _sha256_text(item["sha256"], f"{path}.sha256")
        item_scenario_id = _text(item["scenario_id"], f"{path}.scenario_id")
        if item_scenario_id != scenario_id:
            raise GroundTruthBuildError(f"{path}.scenario_id does not match scenario")
        expected_schema = EXPECTED_INPUT_SCHEMAS[input_type]
        if item["schema_version"] != expected_schema:
            raise GroundTruthBuildError(
                f"{path}.schema_version must be {expected_schema!r}"
            )
        if documents[input_type].get("schema_version") != expected_schema:
            raise GroundTruthBuildError(
                f"{path}.schema_version does not match its artifact"
            )
        normalized.append(copy.deepcopy(dict(item)))

    missing_types = sorted(set(EXPECTED_INPUT_SCHEMAS) - seen_types)
    if missing_types:
        raise GroundTruthBuildError(f"Missing input types: {missing_types!r}")
    return sorted(normalized, key=lambda item: str(item["input_id"]))


def _scenario_evidence_parts(
    document: Mapping[str, object],
    *,
    name_overrides: Mapping[str, object],
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    set[str],
    set[tuple[str, str]],
]:
    _exact_fields(document, SCENARIO_EVIDENCE_FIELDS, "scenario_evidence")
    if document["analysis_status"] != "draft_reviewable":
        raise GroundTruthBuildError(
            "scenario_evidence.analysis_status must remain draft_reviewable"
        )

    raw_evidence = _list(document["evidence"], "scenario_evidence.evidence")
    evidence_ids: set[str] = set()
    evidence_references: dict[str, set[tuple[str, str]]] = {}
    output_evidence: list[dict[str, object]] = []
    all_references: set[tuple[str, str]] = set()
    for index, raw_item in enumerate(raw_evidence):
        path = f"scenario_evidence.evidence[{index}]"
        item = _object(raw_item, path)
        _exact_fields(item, SCENARIO_EVIDENCE_ITEM_FIELDS, path)
        evidence_id = _text(item["evidence_id"], f"{path}.evidence_id")
        _unique_id(evidence_id, evidence_ids, path, "evidence_id")
        _text(item["evidence_type"], f"{path}.evidence_type")
        _text(item["summary"], f"{path}.summary")
        _status(item["status"], CORE_STATUSES, f"{path}.status")
        _text(item["reason"], f"{path}.reason")
        if item["review_status"] != "needs_review":
            raise GroundTruthBuildError(f"{path}.review_status must be needs_review")

        observations: list[dict[str, object]] = []
        references: set[tuple[str, str]] = set()
        raw_observations = _list(item["observations"], f"{path}.observations")
        if not raw_observations:
            raise GroundTruthBuildError(f"{path}.observations must not be empty")
        for observation_index, raw_observation in enumerate(raw_observations):
            observation_path = f"{path}.observations[{observation_index}]"
            observation = _object(raw_observation, observation_path)
            _exact_fields(observation, SCENARIO_OBSERVATION_FIELDS, observation_path)
            reference = (
                _text(
                    observation["source_file"], f"{observation_path}.source_file"
                ),
                _text(
                    observation["raw_record_ref"],
                    f"{observation_path}.raw_record_ref",
                ),
            )
            _optional_text(observation["provider"], f"{observation_path}.provider")
            event_id = observation["event_id"]
            if event_id is not None:
                if isinstance(event_id, bool) or not isinstance(event_id, (str, int)):
                    raise GroundTruthBuildError(
                        f"{observation_path}.event_id must be a string, integer, or null"
                    )
                if isinstance(event_id, str):
                    _text(event_id, f"{observation_path}.event_id")
            _optional_text(observation["timestamp"], f"{observation_path}.timestamp")
            _object(observation["canonical_fields"], f"{observation_path}.canonical_fields")
            _object(observation["raw_fields"], f"{observation_path}.raw_fields")
            references.add(reference)
            all_references.add(reference)
            observations.append(
                {
                    "source_file": reference[0],
                    "raw_record_ref": reference[1],
                    "provider": copy.deepcopy(observation["provider"]),
                    "event_id": copy.deepcopy(event_id),
                    "timestamp": copy.deepcopy(observation["timestamp"]),
                }
            )
        observations.sort(
            key=lambda item: (
                str(item["source_file"]),
                str(item["raw_record_ref"]),
            )
        )
        evidence_references[evidence_id] = references
        output_evidence.append(
            {
                "evidence_id": evidence_id,
                "evidence_type": item["evidence_type"],
                "summary": item["summary"],
                "status": item["status"],
                "observations": observations,
                "source_references": _reference_documents(tuple(references)),
            }
        )

    raw_entities = _list(
        document["observed_entities"], "scenario_evidence.observed_entities"
    )
    entity_ids: set[str] = set()
    entities_by_id: dict[str, Mapping[str, Any]] = {}
    for index, raw_entity in enumerate(raw_entities):
        path = f"scenario_evidence.observed_entities[{index}]"
        entity = _object(raw_entity, path)
        _exact_fields(entity, SCENARIO_ENTITY_FIELDS, path)
        entity_id = _text(entity["entity_id"], f"{path}.entity_id")
        _unique_id(entity_id, entity_ids, path, "entity_id")
        _text(entity["entity_type"], f"{path}.entity_type")
        _object(entity["attributes"], f"{path}.attributes")
        entities_by_id[entity_id] = entity

    unknown_overrides = sorted(set(name_overrides) - entity_ids)
    if unknown_overrides:
        raise GroundTruthBuildError(
            f"entity_name_overrides references unknown entities: {unknown_overrides!r}"
        )

    raw_relationships = _list(
        document["relationships"], "scenario_evidence.relationships"
    )
    relationship_ids: set[str] = set()
    entity_evidence: dict[str, set[str]] = {entity_id: set() for entity_id in entity_ids}
    output_relationships: list[dict[str, object]] = []
    for index, raw_relationship in enumerate(raw_relationships):
        path = f"scenario_evidence.relationships[{index}]"
        relationship = _object(raw_relationship, path)
        _exact_fields(relationship, SCENARIO_RELATIONSHIP_FIELDS, path)
        relationship_id = _text(
            relationship["relationship_id"], f"{path}.relationship_id"
        )
        _unique_id(
            relationship_id, relationship_ids, path, "relationship_id"
        )
        relationship_type = _text(
            relationship["relationship_type"], f"{path}.relationship_type"
        )
        source_entity_id = _text(
            relationship["source_entity_id"], f"{path}.source_entity_id"
        )
        target_entity_id = _text(
            relationship["target_entity_id"], f"{path}.target_entity_id"
        )
        if source_entity_id not in entity_ids or target_entity_id not in entity_ids:
            raise GroundTruthBuildError(
                f"{path} references an entity not present in scenario evidence"
            )
        supported_by = _strings(
            relationship["supported_by"], f"{path}.supported_by", unique=True
        )
        missing_evidence = sorted(set(supported_by) - evidence_ids)
        if missing_evidence:
            raise GroundTruthBuildError(
                f"{path}.supported_by references unknown evidence: {missing_evidence!r}"
            )
        relationship_references: set[tuple[str, str]] = set()
        for evidence_id in supported_by:
            relationship_references.update(evidence_references[evidence_id])
        entity_evidence[source_entity_id].update(supported_by)
        entity_evidence[target_entity_id].update(supported_by)
        output_relationships.append(
            {
                "relationship_id": relationship_id,
                "relationship_type": relationship_type,
                "source_entity_id": source_entity_id,
                "target_entity_id": target_entity_id,
                "attributes": {},
                "status": _status(
                    relationship["status"], CORE_STATUSES, f"{path}.status"
                ),
                "evidence_ids": sorted(supported_by),
                "source_references": _reference_documents(
                    tuple(relationship_references)
                ),
            }
        )

    output_entities: list[dict[str, object]] = []
    for entity_id, entity in entities_by_id.items():
        attributes = entity["attributes"]
        display_name = name_overrides.get(entity_id)
        if display_name is None:
            for field in ("name", "process_name", "host"):
                candidate = attributes.get(field)
                if isinstance(candidate, str) and candidate.strip():
                    display_name = candidate
                    break
        if display_name is None:
            display_name = entity_id
        output_entities.append(
            {
                "entity_id": entity_id,
                "entity_type": entity["entity_type"],
                "name": copy.deepcopy(display_name),
                "attributes": copy.deepcopy(dict(attributes)),
                "status": "observed",
                "evidence_ids": sorted(entity_evidence[entity_id]),
            }
        )

    return (
        sorted(output_entities, key=lambda item: str(item["entity_id"])),
        sorted(output_evidence, key=lambda item: str(item["evidence_id"])),
        sorted(
            output_relationships,
            key=lambda item: str(item["relationship_id"]),
        ),
        evidence_ids,
        all_references,
    )


def _config_facts(
    raw_facts: object,
    *,
    evidence_ids: set[str],
    source_references: set[tuple[str, str]],
) -> list[dict[str, object]]:
    facts: list[dict[str, object]] = []
    for index, raw_fact in enumerate(_list(raw_facts, "build_config.facts")):
        path = f"build_config.facts[{index}]"
        fact = _object(raw_fact, path)
        evidence = _strings(fact["evidence_ids"], f"{path}.evidence_ids", unique=True)
        missing_evidence = sorted(set(evidence) - evidence_ids)
        if missing_evidence:
            raise GroundTruthBuildError(
                f"{path}.evidence_ids references unknown evidence: {missing_evidence!r}"
            )
        references = _source_references(
            fact["source_references"], f"{path}.source_references"
        )
        missing_references = sorted(set(references) - source_references)
        if missing_references:
            raise GroundTruthBuildError(
                f"{path}.source_references are not present in scenario evidence: "
                f"{missing_references!r}"
            )
        facts.append(
            {
                "fact_id": fact["fact_id"],
                "subject": copy.deepcopy(fact["subject"]),
                "predicate": fact["predicate"],
                "object": copy.deepcopy(fact["object"]),
                "attributes": copy.deepcopy(dict(fact["attributes"])),
                "status": fact["status"],
                "evidence_ids": sorted(evidence),
                "source_references": _reference_documents(references),
            }
        )
    return sorted(facts, key=lambda item: str(item["fact_id"]))


def _rule_caveats(rule: Mapping[str, Any], path: str) -> list[str]:
    caveats: set[str] = set()
    for item in _strings(rule.get("caveats", []), f"{path}.caveats"):
        caveats.add(item)
    for field, prefix in (
        ("unsupported_fields", "unsupported_field"),
        ("unsupported_constructs", "unsupported_construct"),
        ("known_unmapped_fields", "known_unmapped_field"),
    ):
        for item in _strings(rule.get(field, []), f"{path}.{field}"):
            caveats.add(f"{prefix}: {item}")
    return sorted(caveats)


def _sigma_findings(
    document: Mapping[str, object],
    *,
    evidence_ids: set[str],
    scenario_references: set[tuple[str, str]],
) -> tuple[list[dict[str, object]], set[str]]:
    raw_rules = _list(document.get("rules"), "sigma_review.rules")
    if document.get("rule_count") != len(raw_rules):
        raise GroundTruthBuildError("sigma_review.rule_count does not match rules")
    rules: dict[str, Mapping[str, Any]] = {}
    caveats_by_rule: dict[str, list[str]] = {}
    for index, raw_rule in enumerate(raw_rules):
        path = f"sigma_review.rules[{index}]"
        rule = _object(raw_rule, path)
        rule_id = _text(rule.get("id"), f"{path}.id")
        if rule_id in rules:
            raise GroundTruthBuildError(
                f"Duplicate or conflicting Sigma rule {rule_id!r}"
            )
        _text(rule.get("title"), f"{path}.title")
        _sha256_text(rule.get("sha256"), f"{path}.sha256")
        rules[rule_id] = rule
        caveats_by_rule[rule_id] = _rule_caveats(rule, path)

    observation_ids: set[str] = set()
    observations_by_id: dict[str, tuple[str, tuple[str, str]]] = {}
    observation_ids_by_rule: dict[str, set[str]] = {rule_id: set() for rule_id in rules}
    evidence_by_rule: dict[str, set[str]] = {rule_id: set() for rule_id in rules}
    references_by_rule: dict[str, set[tuple[str, str]]] = {
        rule_id: set() for rule_id in rules
    }
    raw_observations = _list(
        document.get("observation_matches"), "sigma_review.observation_matches"
    )
    for index, raw_match in enumerate(raw_observations):
        path = f"sigma_review.observation_matches[{index}]"
        match = _object(raw_match, path)
        match_id = _text(match.get("observation_match_id"), f"{path}.observation_match_id")
        _unique_id(match_id, observation_ids, path, "observation_match_id")
        rule_id = _text(match.get("rule_id"), f"{path}.rule_id")
        if rule_id not in rules:
            raise GroundTruthBuildError(f"{path} references unknown Sigma rule {rule_id!r}")
        if match.get("status") != "candidate":
            raise GroundTruthBuildError(f"{path}.status must be candidate")
        reference = (
            _text(match.get("source_file"), f"{path}.source_file"),
            _text(match.get("raw_record_ref"), f"{path}.raw_record_ref"),
        )
        match_evidence = _strings(match.get("evidence_ids"), f"{path}.evidence_ids")
        missing_evidence = sorted(set(match_evidence) - evidence_ids)
        if missing_evidence:
            raise GroundTruthBuildError(
                f"{path}.evidence_ids references unknown evidence: {missing_evidence!r}"
            )
        observation_ids_by_rule[rule_id].add(match_id)
        evidence_by_rule[rule_id].update(match_evidence)
        references_by_rule[rule_id].add(reference)
        observations_by_id[match_id] = (rule_id, reference)

    behavior_ids: set[str] = set()
    behavior_ids_by_rule: dict[str, set[str]] = {rule_id: set() for rule_id in rules}
    raw_behaviors = _list(
        document.get("behavior_matches"), "sigma_review.behavior_matches"
    )
    for index, raw_match in enumerate(raw_behaviors):
        path = f"sigma_review.behavior_matches[{index}]"
        match = _object(raw_match, path)
        behavior_id = _text(match.get("behavior_match_id"), f"{path}.behavior_match_id")
        _unique_id(behavior_id, behavior_ids, path, "behavior_match_id")
        rule_id = _text(match.get("rule_id"), f"{path}.rule_id")
        if rule_id not in rules:
            raise GroundTruthBuildError(f"{path} references unknown Sigma rule {rule_id!r}")
        if match.get("status") != "candidate":
            raise GroundTruthBuildError(f"{path}.status must be candidate")
        evidence_id = _text(match.get("evidence_id"), f"{path}.evidence_id")
        if evidence_id not in evidence_ids:
            raise GroundTruthBuildError(
                f"{path}.evidence_id references unknown evidence {evidence_id!r}"
            )
        linked_observations = _strings(
            match.get("observation_match_ids"),
            f"{path}.observation_match_ids",
            unique=True,
        )
        for observation_id in linked_observations:
            observation = observations_by_id.get(observation_id)
            if observation is None or observation[0] != rule_id:
                raise GroundTruthBuildError(
                    f"{path} references an unknown or different-rule observation"
                )
        behavior_references = _source_references(
            match.get("source_references"), f"{path}.source_references"
        )
        missing_references = sorted(
            set(behavior_references) - scenario_references
        )
        if missing_references:
            raise GroundTruthBuildError(
                f"{path}.source_references are not present in scenario evidence"
            )
        behavior_ids_by_rule[rule_id].add(behavior_id)
        evidence_by_rule[rule_id].add(evidence_id)
        references_by_rule[rule_id].update(behavior_references)

    findings: list[dict[str, object]] = []
    for rule_id, rule in rules.items():
        expected_observation_count = rule.get("observation_match_count")
        if expected_observation_count is not None and expected_observation_count != len(
            observation_ids_by_rule[rule_id]
        ):
            raise GroundTruthBuildError(
                f"Sigma rule {rule_id!r} observation_match_count is inconsistent"
            )
        expected_behavior_count = rule.get("behavior_match_count")
        if expected_behavior_count is not None and expected_behavior_count != len(
            behavior_ids_by_rule[rule_id]
        ):
            raise GroundTruthBuildError(
                f"Sigma rule {rule_id!r} behavior_match_count is inconsistent"
            )
        findings.append(
            {
                "finding_id": _deterministic_id("sigma-finding", rule_id),
                "rule_id": rule_id,
                "rule_title": rule["title"],
                "rule_sha256": rule["sha256"],
                "status": "candidate",
                "observation_match_ids": sorted(observation_ids_by_rule[rule_id]),
                "behavior_match_ids": sorted(behavior_ids_by_rule[rule_id]),
                "evidence_ids": sorted(evidence_by_rule[rule_id]),
                "source_references": _reference_documents(
                    tuple(references_by_rule[rule_id])
                ),
                "caveats": caveats_by_rule[rule_id],
            }
        )
    return sorted(findings, key=lambda item: str(item["rule_id"])), set(rules)


def _mitre_assessments(
    document: Mapping[str, object],
    *,
    decisions: object,
    evidence_ids: set[str],
    sigma_rule_ids: set[str],
) -> list[dict[str, object]]:
    decision_by_external_id: dict[str, Mapping[str, Any]] = {}
    for raw_decision in _list(decisions, "build_config.mitre_decisions"):
        decision = _object(raw_decision, "build_config.mitre_decisions[]")
        decision_by_external_id[str(decision["external_id"])] = decision

    raw_techniques = _list(
        document.get("resolved_techniques"), "mitre_resolution.resolved_techniques"
    )
    if document.get("resolved_technique_count") not in (None, len(raw_techniques)):
        raise GroundTruthBuildError(
            "mitre_resolution.resolved_technique_count does not match techniques"
        )
    techniques: dict[str, Mapping[str, Any]] = {}
    stix_to_external: dict[str, str] = {}
    for index, raw_technique in enumerate(raw_techniques):
        path = f"mitre_resolution.resolved_techniques[{index}]"
        technique = _object(raw_technique, path)
        external_id = _text(technique.get("external_id"), f"{path}.external_id")
        stix_id = _text(technique.get("stix_id"), f"{path}.stix_id")
        _text(technique.get("name"), f"{path}.name")
        if external_id in techniques:
            raise GroundTruthBuildError(
                f"Duplicate resolved technique external_id {external_id!r}"
            )
        if stix_id in stix_to_external:
            raise GroundTruthBuildError(f"Duplicate resolved technique STIX ID {stix_id!r}")
        techniques[external_id] = technique
        stix_to_external[stix_id] = external_id

    unknown_decisions = sorted(set(decision_by_external_id) - set(techniques))
    if unknown_decisions:
        raise GroundTruthBuildError(
            f"MITRE decisions reference unknown techniques: {unknown_decisions!r}"
        )

    supporting_rules: dict[str, set[str]] = {
        external_id: set() for external_id in techniques
    }
    raw_links = _list(
        document.get("rule_technique_candidate_links"),
        "mitre_resolution.rule_technique_candidate_links",
    )
    for index, raw_link in enumerate(raw_links):
        path = f"mitre_resolution.rule_technique_candidate_links[{index}]"
        link = _object(raw_link, path)
        rule_id = _text(link.get("rule_id"), f"{path}.rule_id")
        if rule_id not in sigma_rule_ids:
            raise GroundTruthBuildError(
                f"{path}.rule_id references unknown Sigma rule {rule_id!r}"
            )
        external_id = _text(
            link.get("normalized_external_id"), f"{path}.normalized_external_id"
        )
        technique_stix_id = _text(
            link.get("technique_stix_id"), f"{path}.technique_stix_id"
        )
        technique = techniques.get(external_id)
        if technique is None or technique["stix_id"] != technique_stix_id:
            raise GroundTruthBuildError(
                f"{path} does not reference a resolved technique exactly"
            )
        if link.get("status") != "candidate":
            raise GroundTruthBuildError(f"{path}.status must be candidate")
        if link.get("evidence_assessment") != "not_assessed":
            raise GroundTruthBuildError(
                f"{path}.evidence_assessment must be not_assessed"
            )
        supporting_rules[external_id].add(rule_id)

    assessments: list[dict[str, object]] = []
    for external_id, technique in techniques.items():
        decision = decision_by_external_id.get(external_id)
        if decision is None:
            evidence_support = "not_assessed"
            supporting_evidence: list[str] = []
            rationale = "No evidence-support decision was provided in the build config."
        else:
            evidence_support = str(decision["evidence_support"])
            supporting_evidence = _strings(
                decision["supporting_evidence_ids"],
                f"MITRE decision {external_id}.supporting_evidence_ids",
                unique=True,
            )
            missing_evidence = sorted(set(supporting_evidence) - evidence_ids)
            if missing_evidence:
                raise GroundTruthBuildError(
                    f"MITRE decision {external_id!r} references unknown evidence: "
                    f"{missing_evidence!r}"
                )
            rationale = str(decision["rationale"])
        assessments.append(
            {
                "assessment_id": _deterministic_id(
                    "mitre-assessment", external_id, "sigma_tag"
                ),
                "external_id": external_id,
                "stix_id": technique["stix_id"],
                "name": technique["name"],
                "origin": "sigma_tag",
                "status": "candidate",
                "evidence_support": evidence_support,
                "supporting_evidence_ids": sorted(supporting_evidence),
                "supporting_sigma_rule_ids": sorted(supporting_rules[external_id]),
                "rationale": rationale,
                "review_status": "needs_review",
            }
        )
    return sorted(assessments, key=lambda item: str(item["external_id"]))


def _warnings(*documents: Mapping[str, object]) -> list[str]:
    warnings: set[str] = set()
    for index, document in enumerate(documents):
        raw_warnings = document.get("warnings", [])
        for warning in _strings(raw_warnings, f"artifact[{index}].warnings"):
            warnings.add(warning)
    return sorted(warnings)


def build_ground_truth_core(
    *,
    scenario_evidence: Mapping[str, object],
    sigma_review: Mapping[str, object],
    mitre_resolution: Mapping[str, object],
    input_provenance: Sequence[Mapping[str, object]],
    build_config: Mapping[str, object],
) -> dict[str, object]:
    """Merge three reviewed artifacts using only explicit config decisions."""

    validate_ground_truth_build_config(build_config)
    config = _object(build_config, "build_config")
    config_scenario = _object(config["scenario"], "build_config.scenario")
    scenario_id = str(config_scenario["scenario_id"])

    evidence_document = _object(scenario_evidence, "scenario_evidence")
    sigma_document = _object(sigma_review, "sigma_review")
    mitre_document = _object(mitre_resolution, "mitre_resolution")
    _validate_artifact_identity(
        evidence_document,
        label="scenario_evidence",
        schema_version=SCENARIO_EVIDENCE_SCHEMA_VERSION,
        scenario_id=scenario_id,
    )
    _validate_artifact_identity(
        sigma_document,
        label="sigma_review",
        schema_version=SIGMA_REVIEW_SCHEMA_VERSION,
        scenario_id=scenario_id,
    )
    if sigma_document.get("analysis_status") != "needs_review":
        raise GroundTruthBuildError(
            "sigma_review.analysis_status must remain needs_review"
        )
    _validate_artifact_identity(
        mitre_document,
        label="mitre_resolution",
        schema_version=MITRE_RESOLUTION_SCHEMA_VERSION,
        scenario_id=scenario_id,
    )
    if mitre_document.get("analysis_status") != "needs_review":
        raise GroundTruthBuildError(
            "mitre_resolution.analysis_status must remain needs_review"
        )

    provenance = _validate_input_provenance(
        input_provenance,
        scenario_id=scenario_id,
        documents={
            "scenario_evidence": evidence_document,
            "sigma_review": sigma_document,
            "mitre_resolution": mitre_document,
        },
    )
    overrides = _object(
        config["entity_name_overrides"], "build_config.entity_name_overrides"
    )
    entities, evidence, relationships, evidence_ids, source_references = (
        _scenario_evidence_parts(
            evidence_document,
            name_overrides=overrides,
        )
    )
    facts = _config_facts(
        config["facts"],
        evidence_ids=evidence_ids,
        source_references=source_references,
    )
    sigma_findings, sigma_rule_ids = _sigma_findings(
        sigma_document,
        evidence_ids=evidence_ids,
        scenario_references=source_references,
    )
    mitre_assessments = _mitre_assessments(
        mitre_document,
        decisions=config["mitre_decisions"],
        evidence_ids=evidence_ids,
        sigma_rule_ids=sigma_rule_ids,
    )

    summary = copy.deepcopy(dict(_object(config["summary"], "build_config.summary")))
    entity_ids = {str(item["entity_id"]) for item in entities}
    relationship_ids = {str(item["relationship_id"]) for item in relationships}
    missing_summary_entities = sorted(set(summary["key_entities"]) - entity_ids)
    if missing_summary_entities:
        raise GroundTruthBuildError(
            f"summary.key_entities references unknown entities: {missing_summary_entities!r}"
        )
    missing_summary_relationships = sorted(
        set(summary["key_relationships"]) - relationship_ids
    )
    if missing_summary_relationships:
        raise GroundTruthBuildError(
            "summary.key_relationships references unknown relationships: "
            f"{missing_summary_relationships!r}"
        )

    time_window = _object(evidence_document["time_window"], "scenario_evidence.time_window")
    _exact_fields(time_window, ("start", "end"), "scenario_evidence.time_window")
    _optional_text(time_window["start"], "scenario_evidence.time_window.start")
    _optional_text(time_window["end"], "scenario_evidence.time_window.end")
    output: dict[str, object] = {
        "schema_version": SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
        "scenario": {
            "scenario_id": scenario_id,
            "scenario_name": _text(
                evidence_document["scenario_name"], "scenario_evidence.scenario_name"
            ),
            "description": config_scenario["description"],
            "analysis_status": "draft_reviewable",
            "time_window": copy.deepcopy(dict(time_window)),
        },
        "input_provenance": provenance,
        "entities": entities,
        "facts": facts,
        "relationships": relationships,
        "evidence": evidence,
        "sigma_findings": sigma_findings,
        "mitre_assessments": mitre_assessments,
        "summary": summary,
        "queryable_dimensions": sorted(
            _strings(
                config["queryable_dimensions"],
                "build_config.queryable_dimensions",
                unique=True,
            )
        ),
        "review": {
            "review_status": "pending_human_review",
            "reviewer": None,
            "reviewed_at": None,
            "decisions": [],
            "notes": copy.deepcopy(list(config["review_notes"])),
        },
        "warnings": _warnings(sigma_document, mitre_document),
    }
    try:
        validate_ground_truth_document(output)
    except GroundTruthValidationError as exc:
        raise GroundTruthBuildError(
            f"Built Ground Truth Core document failed validation: {exc}"
        ) from exc
    return output


__all__ = (
    "GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION",
    "GroundTruthBuildError",
    "build_ground_truth_core",
    "validate_ground_truth_build_config",
)
