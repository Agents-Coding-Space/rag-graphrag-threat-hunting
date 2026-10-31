"""Build a deterministic, review-only artifact from Sigma observation matches."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Mapping

from threat_hunting.evidence import SCENARIO_EVIDENCE_SCHEMA_VERSION

from .evaluator import DEFAULT_CANONICAL_FIELD_MAPPING, RuleEvaluation


SIGMA_MATCH_REVIEW_SCHEMA_VERSION = "sigma-match-review/v1"
SIGMA_MATCH_ANALYSIS_STATUS = "needs_review"


class SigmaReviewError(ValueError):
    """Raised when evidence cannot safely support behavior-level grouping."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _deterministic_id(prefix: str, identity: object) -> str:
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:20]}"


def _nonempty_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SigmaReviewError(f"{field} must be a non-empty string")
    return value


def _evidence_index(
    evidence_document: Mapping[str, object],
) -> dict[tuple[str, str], str]:
    if evidence_document.get("schema_version") != SCENARIO_EVIDENCE_SCHEMA_VERSION:
        raise SigmaReviewError(
            f"Evidence must use {SCENARIO_EVIDENCE_SCHEMA_VERSION}"
        )
    evidence_items = evidence_document.get("evidence")
    if not isinstance(evidence_items, list):
        raise SigmaReviewError("Evidence document field 'evidence' must be a list")
    index: dict[tuple[str, str], str] = {}
    for item in evidence_items:
        if not isinstance(item, Mapping):
            raise SigmaReviewError("Evidence items must be mappings")
        evidence_id = _nonempty_text(item.get("evidence_id"), "evidence_id")
        observations = item.get("observations")
        if not isinstance(observations, list) or not observations:
            raise SigmaReviewError("Evidence observations must be a non-empty list")
        for observation in observations:
            if not isinstance(observation, Mapping):
                raise SigmaReviewError("Evidence observations must be mappings")
            reference = (
                _nonempty_text(observation.get("source_file"), "source_file"),
                _nonempty_text(observation.get("raw_record_ref"), "raw_record_ref"),
            )
            existing = index.get(reference)
            if existing is not None and existing != evidence_id:
                raise SigmaReviewError(
                    "Evidence provenance maps to multiple evidence IDs: "
                    f"{reference[0]!r}, {reference[1]!r}"
                )
            index[reference] = evidence_id
    return index


def build_sigma_match_review(
    *,
    scenario_id: str,
    canonical_input: Mapping[str, object],
    evidence_input: Mapping[str, object],
    evidence_document: Mapping[str, object],
    evaluations: Iterable[RuleEvaluation],
    field_mapping: Mapping[str, str | None] = DEFAULT_CANONICAL_FIELD_MAPPING,
    review_notes: Iterable[str] = (),
) -> dict[str, object]:
    """Link observation matches to existing evidence groups, never recorrelation."""

    _nonempty_text(scenario_id, "scenario_id")
    if evidence_document.get("scenario_id") != scenario_id:
        raise SigmaReviewError("Evidence scenario_id does not match requested scenario")
    materialized = tuple(sorted(evaluations, key=lambda item: item.rule.rule_id))
    if not materialized:
        raise SigmaReviewError("At least one Sigma rule evaluation is required")
    examined_counts = {evaluation.examined_events for evaluation in materialized}
    if len(examined_counts) != 1:
        raise SigmaReviewError("All rule evaluations must examine the same event count")
    evidence_index = _evidence_index(evidence_document)

    observation_matches: list[dict[str, object]] = []
    behavior_groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    rule_artifacts: list[dict[str, object]] = []
    for evaluation in materialized:
        rule_matches: list[dict[str, object]] = []
        for source_match in evaluation.observation_matches:
            match = copy.deepcopy(dict(source_match))
            reference = (
                _nonempty_text(match.get("source_file"), "source_file"),
                _nonempty_text(match.get("raw_record_ref"), "raw_record_ref"),
            )
            evidence_id = evidence_index.get(reference)
            match["evidence_ids"] = [evidence_id] if evidence_id is not None else []
            rule_matches.append(match)
            observation_matches.append(match)
            if evidence_id is not None:
                behavior_groups.setdefault(
                    (evaluation.rule.rule_id, evidence_id),
                    [],
                ).append(match)

        rule_metadata = evaluation.rule.to_dict()
        rule_metadata.update(
            {
                "analysis_status": "candidate",
                "unsupported_fields": [],
                "unsupported_constructs": [],
                "known_unmapped_fields": list(evaluation.unmapped_fields),
                "observation_match_count": len(rule_matches),
                "behavior_match_count": len(
                    {
                        evidence_id
                        for rule_id, evidence_id in behavior_groups
                        if rule_id == evaluation.rule.rule_id
                    }
                ),
            }
        )
        rule_artifacts.append(rule_metadata)

    observation_matches.sort(
        key=lambda item: (
            str(item["rule_id"]),
            str(item["source_file"]),
            str(item["raw_record_ref"]),
        )
    )
    behavior_matches: list[dict[str, object]] = []
    for (rule_id, evidence_id), matches in sorted(behavior_groups.items()):
        ordered = sorted(matches, key=lambda item: str(item["observation_match_id"]))
        behavior_matches.append(
            {
                "behavior_match_id": _deterministic_id(
                    "sigma-behavior-match",
                    {"rule_id": rule_id, "evidence_id": evidence_id},
                ),
                "status": "candidate",
                "rule_id": rule_id,
                "evidence_id": evidence_id,
                "observation_match_ids": [
                    item["observation_match_id"] for item in ordered
                ],
                "source_references": [
                    {
                        "source_file": item["source_file"],
                        "raw_record_ref": item["raw_record_ref"],
                    }
                    for item in ordered
                ],
                "review_status": "needs_review",
            }
        )

    matched_references = {
        (str(item["source_file"]), str(item["raw_record_ref"]))
        for item in observation_matches
    }
    examined_events = next(iter(examined_counts))
    notes = tuple(review_notes)
    if any(not isinstance(note, str) or not note.strip() for note in notes):
        raise SigmaReviewError("review_notes must contain non-empty strings")
    unmapped_fields = sorted(
        {field for evaluation in materialized for field in evaluation.unmapped_fields}
    )
    return {
        "schema_version": SIGMA_MATCH_REVIEW_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "analysis_status": SIGMA_MATCH_ANALYSIS_STATUS,
        "canonical_input": copy.deepcopy(dict(canonical_input)),
        "evidence_input": copy.deepcopy(dict(evidence_input)),
        "rule_count": len(rule_artifacts),
        "rules": rule_artifacts,
        "canonical_field_mappings": dict(field_mapping),
        "unsupported_fields": [],
        "unsupported_constructs": [],
        "known_unmapped_fields": unmapped_fields,
        "examined_events": examined_events,
        "matched_events": len(matched_references),
        "unmatched_events": examined_events - len(matched_references),
        "observation_matches": observation_matches,
        "behavior_matches": behavior_matches,
        "warnings": [],
        "review_notes": list(notes),
    }


def serialize_sigma_match_review(document: Mapping[str, object]) -> bytes:
    """Serialize deterministic, human-reviewable UTF-8 JSON."""

    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


__all__ = (
    "SIGMA_MATCH_ANALYSIS_STATUS",
    "SIGMA_MATCH_REVIEW_SCHEMA_VERSION",
    "SigmaReviewError",
    "build_sigma_match_review",
    "serialize_sigma_match_review",
)
