"""Read approved labels and audit returned evidence outside the runtime gate.

The answer-unit rubric is an AI-authored, conservative support screen, not a
human-approved semantic evaluator. It never repairs a context, calls retrieval,
or supplies labels, expected answers, or expected evidence to gate inputs.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import unicodedata

from ..ground_truth.review_artifacts import (
    REFERENCE_ANSWERS_SCHEMA_V2,
    REVIEW_MANIFEST_SCHEMA_V2,
    validate_reference_answers_document,
    validate_review_bundle,
    validate_review_manifest_document,
)
from ..ground_truth.schema import (
    SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION,
    validate_ground_truth_document,
)


class TwoStageReviewError(ValueError):
    """An evaluation source or rubric cannot safely be interpreted."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _nonstandard(value: str) -> None:
    raise ValueError(f"non-standard JSON number {value!r}")


def load_approved_evaluation_bundle(
    review_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load actual UTF-8 bytes, validate v2 approval and dependency hashes.

    Approval must describe one human event in all three artifacts. V1 and v2
    pending documents are valid elsewhere, but are not approved labels for this
    evaluation. No version/status is rewritten, and no artifact is written.
    """
    names = ("scenario_ground_truth.json", "reference_answers.json", "review_manifest.json")
    versions = (
        SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION,
        REFERENCE_ANSWERS_SCHEMA_V2,
        REVIEW_MANIFEST_SCHEMA_V2,
    )
    validators = (
        validate_ground_truth_document,
        validate_reference_answers_document,
        validate_review_manifest_document,
    )
    documents: list[dict[str, Any]] = []
    digests: list[str] = []
    for name, version, validator in zip(names, versions, validators, strict=True):
        source = Path(review_dir) / name
        try:
            payload = source.read_bytes()
            document = json.loads(
                payload.decode("utf-8-sig"), object_pairs_hook=_pairs,
                parse_constant=_nonstandard,
            )
            validator(document)
            if document["schema_version"] != version:
                raise ValueError(f"evaluation requires approved {version!r}")
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            raise TwoStageReviewError(f"Cannot load {source}: {exc}") from exc
        documents.append(document)
        digests.append(hashlib.sha256(payload).hexdigest())
    gt, answers, manifest = documents
    try:
        validate_review_bundle(
            gt, answers, manifest,
            ground_truth_sha256=digests[0], reference_answers_sha256=digests[1],
        )
        if gt["review"]["review_status"] != "confirmed":
            raise ValueError("ground-truth human approval is required")
    except (ValueError, TypeError, KeyError) as exc:
        files = ", ".join(str(Path(review_dir) / name) for name in names)
        raise TwoStageReviewError(f"Invalid approved evaluation bundle ({files}): {exc}") from exc
    return gt, answers, manifest


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _normal(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _pointer(value: object, pointer: str) -> object:
    cursor = value
    try:
        for part in pointer.lstrip("/").split("/") if pointer else []:
            key = part.replace("~1", "/").replace("~0", "~")
            cursor = cursor[int(key)] if isinstance(cursor, list) else cursor[key]  # type: ignore[index]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return cursor


def _records(context: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    retrieval = _mapping(context.get("retrieval"))
    chunks = [
        ("chunk", _mapping(hit.get("chunk")))
        for hit in _items(retrieval.get("hits")) if isinstance(hit, Mapping)
    ]
    traversal = _mapping(context.get("traversal"))
    return chunks + [
        (kind, item)
        for kind, collection in (("node", "nodes"), ("edge", "edges"))
        for item in _items(traversal.get(collection)) if isinstance(item, Mapping)
    ]


def _document(kind: str, item: Mapping[str, Any]) -> dict[str, Any]:
    """Project only documented returned evidence fields, never opaque labels."""
    attrs = _mapping(item.get("metadata" if kind == "chunk" else "attributes"))
    allowed = (
        "subject", "predicate", "object", "attributes", "evidence_type", "summary",
        "observations", "external_id", "origin", "evidence_support", "rationale",
        "review_status", "analysis_status", "description", "time_window",
    )
    result = {key: attrs[key] for key in allowed if key in attrs}
    result["status"] = item.get("status")
    result["source_references"] = item.get("source_references", [])
    return result


def _text(kind: str, item: Mapping[str, Any]) -> str:
    # Labels and answers nested in metadata/attributes cannot satisfy evidence.
    fields = ("title", "content") if kind == "chunk" else ("label",)
    return " ".join(item[field] for field in fields if isinstance(item.get(field), str))


def _source(item: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(item.get("source"))


def _expected(unit: Mapping[str, Any]) -> dict[str, Any]:
    prefix = unit["source_ground_truth_pointer"]
    result: dict[str, Any] = {}
    for field in _items(unit.get("required_ground_truth_fields")):
        if not isinstance(field, Mapping) or not isinstance(field.get("pointer"), str):
            raise TwoStageReviewError("answer unit requires explicit ground-truth fields")
        pointer = field["pointer"]
        if pointer != prefix and not pointer.startswith(prefix + "/"):
            raise TwoStageReviewError(f"answer-unit field {pointer!r} escapes its source object")
        result[pointer[len(prefix):]] = field.get("value")
    return result


def _relationship(
    records: list[tuple[str, Mapping[str, Any]]], prefix: str,
    expected: Mapping[str, Any],
) -> tuple[bool | None, str]:
    source_id, target_id = expected.get("/source_entity_id"), expected.get("/target_entity_id")
    relationship_type, status = expected.get("/relationship_type"), expected.get("/status")
    if not all(isinstance(value, str) for value in (source_id, target_id, relationship_type, status)):
        raise TwoStageReviewError("relationship unit requires directed entity IDs, type and status")
    entities = {
        item.get("node_id"): _source(item).get("object_id")
        for kind, item in records if kind == "node" and item.get("node_type") == "entity"
    }
    returned_entities = set(entities.values())
    for kind, item in records:
        same_source = _source(item).get("json_pointer") == prefix
        if kind == "edge" and same_source:
            if (item.get("edge_type") == relationship_type and item.get("directed") is True
                    and item.get("status") == status
                    and entities.get(item.get("source_node_id")) == source_id
                    and entities.get(item.get("target_node_id")) == target_id):
                return True, "directed_edge_and_both_returned_entity_endpoints"
        if kind == "chunk" and same_source and item.get("chunk_type") == "relationship":
            pattern = (
                r"Source:\s*.+?\(" + re.escape(source_id) + r"\)\.\s*Type:\s*"
                + re.escape(relationship_type) + r"\.\s*Target:\s*.+?\("
                + re.escape(target_id) + r"\)\."
            )
            if item.get("status") == status and re.search(pattern, str(item.get("content", ""))):
                return True, "relationship_chunk_explicit_source_type_target_roles"
        # A returned fact is an alternative representation of the same relation.
        if _source(item).get("object_type") == "fact":
            doc = _document(kind, item)
            if (relationship_type == "process_spawn" and doc.get("subject") == source_id
                    and doc.get("predicate") == "spawned_process" and doc.get("object") == target_id
                    and doc.get("status") == status and source_id in returned_entities
                    and target_id in returned_entities):
                return True, "directed_fact_and_both_returned_entity_endpoints"
    return False, "directed_relationship_with_resolved_endpoints_not_returned"


def _observations(
    matching: list[tuple[str, Mapping[str, Any]]], expected: Mapping[str, Any],
) -> tuple[bool | None, str]:
    observations = expected.get("/observations")
    refs = expected.get("/source_references")
    for kind, item in matching:
        doc = _document(kind, item)
        actual = _items(doc.get("observations"))
        if (isinstance(observations, list) and isinstance(refs, list)
                and ("/summary" not in expected or doc.get("summary") == expected["/summary"])
                and all(obs in actual for obs in observations)
                and all(ref in _items(doc.get("source_references")) for ref in refs)):
            return True, "observation_provider_event_timestamp_raw_reference_associations_returned"
    return False, "associated_original_observations_and_raw_references_not_returned"


def _command(
    matching: list[tuple[str, Mapping[str, Any]]], expected: Mapping[str, Any],
    expected_refs: list[Any],
) -> tuple[bool | None, str]:
    commands = [value for path, value in expected.items() if path.endswith("/original_fields/CommandLine")]
    if not commands or not all(isinstance(value, str) for value in commands):
        raise TwoStageReviewError("launch-command unit requires original CommandLine values")
    for kind, item in matching:
        observations = _pointer(_document(kind, item), "/attributes/source_observations")
        for obs in _items(observations):
            if (isinstance(obs, Mapping) and obs.get("source_file") and obs.get("raw_record_ref")
                    and (not expected_refs or {"source_file": obs["source_file"],
                                             "raw_record_ref": obs["raw_record_ref"]} in expected_refs)
                    and _mapping(obs.get("original_fields")).get("CommandLine") in commands):
                return True, "original_command_line_with_its_raw_reference_returned"
    return False, "original_command_line_field_not_returned_summary_or_reference_is_insufficient"


def _unit_result(
    records: list[tuple[str, Mapping[str, Any]]], unit: Mapping[str, Any],
    expected_refs: list[Any],
) -> tuple[bool | None, str]:
    prefix = unit.get("source_ground_truth_pointer")
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise TwoStageReviewError("answer unit requires an absolute JSON pointer")
    expected = _expected(unit)
    if not expected:
        raise TwoStageReviewError("answer unit must contain required ground-truth fields")
    matching = [(kind, item) for kind, item in records if _source(item).get("json_pointer") == prefix]
    if "/source_entity_id" in expected:
        return _relationship(records, prefix, expected)
    if any(path.endswith("/original_fields/CommandLine") for path in expected):
        return _command(matching, expected, expected_refs)
    if "/observations" in expected:
        return _observations(matching, expected)
    prose_unknown = False
    for kind, item in matching:
        doc, text = _document(kind, item), _normal(_text(kind, item))
        supported = True
        candidate_prose_unknown = False
        candidate_structured_failure = False
        for relative, wanted in expected.items():
            actual = _pointer(doc, relative) if relative else None
            if actual == wanted:
                continue
            # A conflicting structured value cannot be overruled by finding the
            # expected word somewhere else in the same chunk's prose.
            if actual is None and isinstance(wanted, str) and _normal(wanted) in text:
                continue
            supported = False
            if relative in ("", "/rationale", "/description"):
                candidate_prose_unknown = True
            else:
                candidate_structured_failure = True
        if supported:
            return True, "source_associated_required_fields_or_explicit_text_returned"
        prose_unknown |= candidate_prose_unknown and not candidate_structured_failure
    # Equivalents are supplied by the external rubric, never selected by a case
    # identifier or scenario-specific evaluator keyword.
    if prefix.startswith("/summary/limitations/"):
        alternatives = unit.get("acceptable_semantic_equivalents", [])
        wanted = expected.get("")
        texts = [
            _normal(_text(kind, item)) for kind, item in records
            if _source(item).get("object_type") == "limitation"
        ]
        if any(_normal(candidate) in text for candidate in [wanted, *_items(alternatives)]
               if isinstance(candidate, str) for text in texts):
            return True, "limitation_text_or_rubric_declared_semantic_equivalent_returned"
        if unit.get("known_absent_from_frozen_consumers") is True:
            return False, "full_consumer_audit_established_required_information_is_absent"
        return None, "no_exact_limitation_support_semantic_sufficiency_not_established"
    if prose_unknown:
        return None, "required_prose_not_exactly_supported_semantic_equivalence_unassessed"
    return False, "required_source_associated_structured_fields_not_returned"


def audit_returned_context(
    context: Mapping[str, Any], case_descriptor: Mapping[str, Any],
    answer_units: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare an actual context to external labels without modifying either.

    ``True`` means every required unit passed this conservative AI rubric.
    ``False`` means a requested positive assertion is unsupported by the approved
    category, or required structured information is known missing. ``None`` means
    outside scope or semantic sufficiency remains unassessed. Expected pointers
    and IDs never count as returned content and are never dereferenced.
    """
    if not all(isinstance(value, Mapping) for value in (context, case_descriptor, answer_units)):
        raise TwoStageReviewError("context, case descriptor and answer units must be objects")
    records = _records(context)
    ids = {
        value for _, item in records for value in _items(item.get("evidence_ids"))
        if isinstance(value, str)
    }
    expected_ids = set(
        value for value in _items(case_descriptor.get("expected_evidence_ids"))
        if isinstance(value, str)
    )
    required = case_descriptor.get("minimal_answer_unit_ids", [])
    if not isinstance(required, list) or any(not isinstance(uid, str) for uid in required):
        raise TwoStageReviewError("minimal_answer_unit_ids must be a list of unit IDs")
    if len(required) != len(set(required)):
        raise TwoStageReviewError("minimal_answer_unit_ids must be unique")
    satisfied: list[str] = []
    missing: list[str] = []
    diagnostics: list[dict[str, Any]] = []
    outcomes: list[bool | None] = []
    for uid in required:
        if uid not in answer_units or not isinstance(answer_units[uid], Mapping):
            raise TwoStageReviewError(f"Unknown answer unit {uid!r}")
        unit = answer_units[uid]
        expected_ids.update(value for value in _items(unit.get("expected_evidence_ids")) if isinstance(value, str))
        passed, reason = _unit_result(
            records, unit, _items(case_descriptor.get("raw_reference_requirements")),
        )
        outcomes.append(passed)
        if passed is True:
            satisfied.append(uid)
        else:
            missing.append(uid)
            diagnostics.append({
                "answer_unit_id": uid, "source_ground_truth_pointer": unit["source_ground_truth_pointer"],
                "support_status": "known_missing" if passed is False else "unassessed",
                "reason": reason,
            })
    category = case_descriptor.get("category")
    if category == "unrelated":
        enough, basis = None, "outside_scope_answerability_not_applicable"
    elif category == "insufficient_evidence":
        enough, basis = False, "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
    elif category in ("relevant_direct", "relevant_paraphrase"):
        enough = False if False in outcomes else None if None in outcomes or not outcomes else True
        basis = (
            "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
            if enough is True else "known_required_information_missing_from_actual_returned_context"
            if enough is False else "semantic_context_sufficiency_unassessed_conservative_screen_incomplete"
        )
    else:
        raise TwoStageReviewError(f"Unsupported reviewed category {category!r}")
    return {
        "context_sufficient": enough, "context_sufficiency_basis": basis,
        "missing_evidence_diagnostics": diagnostics,
        "expected_evidence_ids": sorted(expected_ids), "returned_evidence_ids": sorted(ids),
        "satisfied_answer_units": satisfied, "missing_answer_units": missing,
    }


__all__ = ("TwoStageReviewError", "load_approved_evaluation_bundle", "audit_returned_context")
