"""Scenario-independent Sigma tag resolver for an indexed ATT&CK bundle."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from threat_hunting.mitre.loader import (
    AttackPattern,
    ExternalReference,
    MitreAttackIndex,
    MitreSourceManifest,
)


SIGMA_REVIEW_SCHEMA = "sigma-match-review/v1"
MITRE_RESOLUTION_SCHEMA = "mitre-resolution/v1"
TECHNIQUE_TAG_PATTERN = re.compile(r"^attack\.(t[0-9]{4}(?:\.[0-9]{3})?)$")


class MitreResolutionError(ValueError):
    """Raised when Sigma input or the requested resolution is ambiguous."""


def _nonempty_string(value: object, *, field: str, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise MitreResolutionError(
            f"{context} field {field!r} must be a non-empty string"
        )
    return value


def _nonnegative_integer(value: object, *, field: str, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MitreResolutionError(
            f"{context} field {field!r} must be a non-negative integer"
        )
    return value


def _sha256_string(value: object, *, field: str, context: str) -> str:
    result = _nonempty_string(value, field=field, context=context)
    if re.fullmatch(r"[0-9a-f]{64}", result) is None:
        raise MitreResolutionError(f"{context} field {field!r} is not a SHA-256")
    return result


def load_sigma_review(path: Path, *, expected_scenario_id: str) -> dict[str, Any]:
    """Read and validate the Sigma review boundary used by the resolver."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MitreResolutionError(f"Cannot read Sigma review {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MitreResolutionError(f"Sigma review {path} must contain a JSON object")
    validate_sigma_review(value, expected_scenario_id=expected_scenario_id)
    return value


def validate_sigma_review(
    review: Mapping[str, Any],
    *,
    expected_scenario_id: str,
) -> None:
    """Validate the stable Sigma metadata consumed by ATT&CK resolution."""

    context = "Sigma review"
    if review.get("schema_version") != SIGMA_REVIEW_SCHEMA:
        raise MitreResolutionError(
            f"{context} has unsupported schema_version "
            f"{review.get('schema_version')!r}; expected {SIGMA_REVIEW_SCHEMA!r}"
        )
    scenario_id = _nonempty_string(
        review.get("scenario_id"), field="scenario_id", context=context
    )
    if scenario_id != expected_scenario_id:
        raise MitreResolutionError(
            f"{context} scenario_id {scenario_id!r} does not match expected "
            f"{expected_scenario_id!r}"
        )
    _nonempty_string(
        review.get("analysis_status"), field="analysis_status", context=context
    )
    raw_rules = review.get("rules")
    if not isinstance(raw_rules, list):
        raise MitreResolutionError(f"{context} field 'rules' must be a list")
    rule_count = _nonnegative_integer(
        review.get("rule_count"), field="rule_count", context=context
    )
    if rule_count != len(raw_rules):
        raise MitreResolutionError(
            f"{context} rule_count {rule_count} does not match {len(raw_rules)} rules"
        )

    seen_rule_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule_context = f"Sigma review rules[{index}]"
        if not isinstance(raw_rule, dict):
            raise MitreResolutionError(f"{rule_context} must be an object")
        rule_id = _nonempty_string(raw_rule.get("id"), field="id", context=rule_context)
        if rule_id in seen_rule_ids:
            raise MitreResolutionError(f"Duplicate Sigma rule ID {rule_id!r}")
        seen_rule_ids.add(rule_id)
        _nonempty_string(raw_rule.get("title"), field="title", context=rule_context)
        _nonempty_string(
            raw_rule.get("source_path"), field="source_path", context=rule_context
        )
        _sha256_string(raw_rule.get("sha256"), field="sha256", context=rule_context)
        tags = raw_rule.get("tags")
        if not isinstance(tags, list):
            raise MitreResolutionError(f"{rule_context} field 'tags' must be a list")
        seen_tags: set[str] = set()
        for tag_index, tag in enumerate(tags):
            tag_value = _nonempty_string(
                tag, field=f"tags[{tag_index}]", context=rule_context
            )
            if tag_value in seen_tags:
                raise MitreResolutionError(
                    f"{rule_context} contains duplicate tag {tag_value!r}"
                )
            seen_tags.add(tag_value)


def deterministic_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize a resolution artifact with stable UTF-8 bytes."""

    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _reference_document(reference: ExternalReference) -> dict[str, Any]:
    return {
        "description": reference.description,
        "external_id": reference.external_id,
        "source_name": reference.source_name,
        "url": reference.url,
    }


def _pattern_document(pattern: AttackPattern) -> dict[str, Any]:
    return {
        "stix_id": pattern.stix_id,
        "external_id": pattern.external_id,
        "name": pattern.name,
        "description": pattern.description,
        "created": pattern.created,
        "modified": pattern.modified,
        "x_mitre_version": pattern.version,
        "x_mitre_domains": list(pattern.domains),
        "x_mitre_is_subtechnique": pattern.is_subtechnique,
        "kill_chain_phases": [
            {
                "kill_chain_name": phase.kill_chain_name,
                "phase_name": phase.phase_name,
            }
            for phase in pattern.kill_chain_phases
        ],
        "external_references": [
            _reference_document(reference)
            for reference in pattern.external_references
        ],
        "attack_external_reference": _reference_document(
            pattern.attack_external_reference
        ),
        "revoked": pattern.revoked,
        "x_mitre_deprecated": pattern.deprecated,
        "active": pattern.is_active,
        "resolution_status": "resolved",
        "evidence_assessment": "not_assessed",
    }


def _tag_occurrences(
    review: Mapping[str, Any],
) -> tuple[
    dict[str, list[dict[str, str]]],
    dict[str, list[dict[str, str]]],
    dict[str, list[dict[str, str]]],
]:
    technique: dict[str, list[dict[str, str]]] = defaultdict(list)
    non_technique_attack: dict[str, list[dict[str, str]]] = defaultdict(list)
    other: dict[str, list[dict[str, str]]] = defaultdict(list)
    for raw_rule in review["rules"]:
        provenance = {
            "rule_id": raw_rule["id"],
            "rule_title": raw_rule["title"],
            "rule_source_path": raw_rule["source_path"],
            "rule_sha256": raw_rule["sha256"],
        }
        for tag in raw_rule["tags"]:
            match = TECHNIQUE_TAG_PATTERN.fullmatch(tag)
            if match is not None:
                technique[tag].append(dict(provenance))
            elif tag.startswith("attack."):
                non_technique_attack[tag].append(dict(provenance))
            else:
                other[tag].append(dict(provenance))
    return dict(technique), dict(non_technique_attack), dict(other)


def _tag_inventory(
    occurrences: Mapping[str, Sequence[Mapping[str, str]]],
) -> list[dict[str, Any]]:
    return [
        {
            "tag": tag,
            "rule_ids": sorted(item["rule_id"] for item in provenance),
        }
        for tag, provenance in sorted(occurrences.items())
    ]


def _link_id(
    *, scenario_id: str, rule_id: str, sigma_tag: str, technique_stix_id: str
) -> str:
    identity = "\x00".join(
        (scenario_id, rule_id, sigma_tag, technique_stix_id)
    ).encode("utf-8")
    return f"mitre-link--{sha256(identity).hexdigest()}"


def build_resolution(
    *,
    sigma_review: Mapping[str, Any],
    sigma_input_path: str,
    sigma_input_sha256: str,
    attack_index: MitreAttackIndex,
    manifest: MitreSourceManifest,
    manifest_path: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Resolve exact Sigma technique tags into review-only ATT&CK candidates."""

    scenario_id = _nonempty_string(
        sigma_review.get("scenario_id"), field="scenario_id", context="Sigma review"
    )
    validate_sigma_review(sigma_review, expected_scenario_id=scenario_id)
    _sha256_string(
        sigma_input_sha256, field="sigma_input_sha256", context="resolution request"
    )
    _sha256_string(
        manifest_sha256, field="manifest_sha256", context="resolution request"
    )

    technique_tags, non_technique_tags, other_tags = _tag_occurrences(sigma_review)
    resolved_patterns: dict[str, AttackPattern] = {}
    unresolved: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    rules_by_id = {rule["id"]: rule for rule in sigma_review["rules"]}
    for sigma_tag, provenance_items in sorted(technique_tags.items()):
        match = TECHNIQUE_TAG_PATTERN.fullmatch(sigma_tag)
        if match is None:  # Defensive: classification and resolution must agree.
            raise MitreResolutionError(f"Technique tag classification drift: {sigma_tag!r}")
        external_id = match.group(1).upper()
        pattern = attack_index.active_patterns_by_external_id.get(external_id)
        if pattern is None:
            inactive = attack_index.inactive_patterns_by_external_id.get(external_id, ())
            unresolved.append(
                {
                    "sigma_tag": sigma_tag,
                    "normalized_external_id": external_id,
                    "status": "inactive" if inactive else "not_found",
                    "rule_ids": sorted(item["rule_id"] for item in provenance_items),
                    "inactive_objects": [
                        {
                            "stix_id": item.stix_id,
                            "name": item.name,
                            "revoked": item.revoked,
                            "x_mitre_deprecated": item.deprecated,
                        }
                        for item in inactive
                    ],
                }
            )
            continue

        resolved_patterns[external_id] = pattern
        for provenance in provenance_items:
            rule = rules_by_id[provenance["rule_id"]]
            links.append(
                {
                    "link_id": _link_id(
                        scenario_id=scenario_id,
                        rule_id=rule["id"],
                        sigma_tag=sigma_tag,
                        technique_stix_id=pattern.stix_id,
                    ),
                    "rule_id": rule["id"],
                    "rule_title": rule["title"],
                    "sigma_tag": sigma_tag,
                    "normalized_external_id": external_id,
                    "technique_stix_id": pattern.stix_id,
                    "status": "candidate",
                    "evidence_assessment": "not_assessed",
                    "provenance": {
                        "sigma_input_path": sigma_input_path,
                        "sigma_input_sha256": sigma_input_sha256,
                        "sigma_input_schema_version": SIGMA_REVIEW_SCHEMA,
                        "rule_source_path": rule["source_path"],
                        "rule_sha256": rule["sha256"],
                    },
                }
            )

    parent_relationships: list[dict[str, Any]] = []
    for external_id, pattern in sorted(resolved_patterns.items()):
        if not pattern.is_subtechnique:
            continue
        relationship = attack_index.parent_by_subtechnique_id.get(pattern.stix_id)
        if relationship is None:
            raise MitreResolutionError(
                f"Resolved active sub-technique {external_id} has no validated parent"
            )
        parent = attack_index.attack_patterns_by_stix_id[relationship.target_ref]
        parent_relationships.append(
            {
                "relationship_stix_id": relationship.stix_id,
                "relationship_type": "subtechnique-of",
                "subtechnique_stix_id": pattern.stix_id,
                "subtechnique_external_id": pattern.external_id,
                "subtechnique_name": pattern.name,
                "parent_stix_id": parent.stix_id,
                "parent_external_id": parent.external_id,
                "parent_name": parent.name,
                "provenance": {
                    "mitre_bundle_path": manifest.bundle_path,
                    "mitre_bundle_sha256": attack_index.source_sha256,
                },
            }
        )

    links.sort(key=lambda item: (item["rule_id"], item["normalized_external_id"]))
    resolved_documents = [
        _pattern_document(pattern)
        for _, pattern in sorted(resolved_patterns.items())
    ]
    return {
        "schema_version": MITRE_RESOLUTION_SCHEMA,
        "scenario_id": scenario_id,
        "analysis_status": "needs_review",
        "sigma_input": {
            "path": sigma_input_path,
            "sha256": sigma_input_sha256,
            "schema_version": sigma_review["schema_version"],
            "analysis_status": sigma_review["analysis_status"],
            "rule_count": sigma_review["rule_count"],
            "canonical_input": sigma_review.get("canonical_input"),
            "evidence_input": sigma_review.get("evidence_input"),
        },
        "mitre_stix_input": {
            "manifest_path": manifest_path,
            "manifest_sha256": manifest_sha256,
            "bundle_path": manifest.bundle_path,
            "bundle_sha256": attack_index.source_sha256,
            "source_name": manifest.source_name,
            "repository": manifest.repository,
            "tag": manifest.tag,
            "commit": manifest.commit,
            "source_url": manifest.url,
            "data_type": manifest.data_type,
            "stix_version": manifest.stix_version,
            "bundle_id": attack_index.bundle_id,
            "object_count": attack_index.object_count,
            "active_attack_pattern_count": attack_index.active_attack_pattern_count,
            "subtechnique_of_relationship_count": len(
                attack_index.subtechnique_relationships
            ),
            "collection": {
                "stix_id": manifest.collection.stix_id,
                "name": manifest.collection.name,
                "version": manifest.collection.version,
                "created": manifest.collection.created,
                "modified": manifest.collection.modified,
            },
        },
        "rule_count": sigma_review["rule_count"],
        "technique_tag_count": len(technique_tags),
        "technique_tag_occurrence_count": sum(
            len(items) for items in technique_tags.values()
        ),
        "resolved_technique_count": len(resolved_documents),
        "unresolved_technique_tags": unresolved,
        "non_technique_attack_tags": _tag_inventory(non_technique_tags),
        "other_rule_tags": _tag_inventory(other_tags),
        "resolved_techniques": resolved_documents,
        "rule_technique_candidate_links": links,
        "parent_subtechnique_relationships": sorted(
            parent_relationships,
            key=lambda item: item["subtechnique_external_id"],
        ),
        "warnings": [],
        "review_notes": [
            "Resolved means that an exact Sigma tag was mapped to active ATT&CK metadata; it does not confirm that the evidence demonstrates the technique.",
            "Every rule-technique link is a candidate with evidence_assessment set to not_assessed.",
            "Technique applicability and evidence confirmation belong to the later reviewed ground-truth milestone.",
        ],
    }


def assert_review_only(resolution: Mapping[str, Any]) -> None:
    """Reject any artifact that introduces a confirmed status or assessment."""

    def visit(value: object, path: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in {"status", "analysis_status", "evidence_assessment"}:
                    if isinstance(child, str) and child.casefold() == "confirmed":
                        raise MitreResolutionError(
                            f"Review-only artifact contains confirmed state at {child_path}"
                        )
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(resolution, "resolution")


def validate_resolution_document(resolution: Mapping[str, Any]) -> None:
    """Validate core output invariants after serialization and reload."""

    if resolution.get("schema_version") != MITRE_RESOLUTION_SCHEMA:
        raise MitreResolutionError("Resolution output has the wrong schema_version")
    if resolution.get("analysis_status") != "needs_review":
        raise MitreResolutionError("Resolution output must remain needs_review")
    links = resolution.get("rule_technique_candidate_links")
    if not isinstance(links, list):
        raise MitreResolutionError(
            "Resolution output field 'rule_technique_candidate_links' must be a list"
        )
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            raise MitreResolutionError(f"Resolution link {index} must be an object")
        if link.get("status") != "candidate":
            raise MitreResolutionError(f"Resolution link {index} must be candidate")
        if link.get("evidence_assessment") != "not_assessed":
            raise MitreResolutionError(
                f"Resolution link {index} must have evidence_assessment not_assessed"
            )
    assert_review_only(resolution)
