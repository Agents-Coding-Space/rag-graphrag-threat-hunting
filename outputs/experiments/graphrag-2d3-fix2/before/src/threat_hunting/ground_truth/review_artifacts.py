"""Explicit contracts for the MSHTA technical-review package.

Approval concerns the reviewed artifacts only. It neither changes evidence
labels nor supplies retrieval, gate, or security-decision inputs. Version 1
preserves the original pending-only contracts; version 2 records a human
approval separately from the original AI technical-review provenance.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import date
import math
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any

from .approval import validate_human_review
from .schema import validate_ground_truth_document


REFERENCE_ANSWERS_SCHEMA_V1 = "mshta-reference-answers/v1"
REFERENCE_ANSWERS_SCHEMA_V2 = "mshta-reference-answers/v2"
REVIEW_MANIFEST_SCHEMA_V1 = "mshta-technical-review/v1"
REVIEW_MANIFEST_SCHEMA_V2 = "mshta-technical-review/v2"
ANSWERS_PENDING_STATUS = "ai_review_completed_pending_human_approval"
ANSWERS_APPROVED_STATUS = "human_approved"

_ANSWER_FIELDS = (
    "schema_version", "scenario_id", "purpose", "review", "scope_policy",
    "sources", "cases", "metadata",
)
_ANSWER_REVIEW_FIELDS = (
    "human_approved_at", "human_reviewer", "notes", "review_date",
    "review_status", "review_type", "reviewer", "reviewer_type",
)
_CASE_FIELDS = (
    "answer_constraints", "case_id", "category", "expected_decision",
    "ground_truth_pointers", "language", "original_query", "query",
    "raw_record_references", "raw_reference_role", "reference_answer",
    "reference_answer_language", "source_case_pointer", "target_kind",
)
_SCOPE_FIELDS = (
    "abstain_meaning", "insufficient_evidence", "relevant_direct",
    "relevant_paraphrase", "retrieval_target_meaning",
    "scope_reference_for_unrelated", "unrelated",
)
_METADATA_FIELDS = (
    "case_count", "category_counts", "changed_labels", "changed_queries",
    "dataset_use", "decision_counts",
)
_MANIFEST_FIELDS = (
    "artifacts", "baseline_ground_truth_valid", "baseline_inputs",
    "canonical_records_examined", "category_and_decision_changes", "consumer_note",
    "human_review_status", "input_hashes_unchanged", "json_readback_passed",
    "mitre_label_promotions", "original_sources", "query_wording_corrections",
    "raw_records_examined", "reference_answers", "resolved_baseline_cases",
    "resolved_baseline_relevance_pointers", "review_date", "reviewed_entities",
    "reviewed_evidence", "reviewed_relationships", "reviewer", "reviewer_type",
    "scenario_id", "schema_version", "status",
)
_APPROVAL_MANIFEST_FIELDS = (
    "human_reviewer", "human_approved_at", "approval_provenance",
)
_APPROVAL_ARTIFACTS = (
    "scenario_ground_truth.json", "reference_answers.json", "review_manifest.json",
)
_CATEGORY_DECISIONS = {
    "relevant_direct": ("proceed", "answer_support"),
    "relevant_paraphrase": ("proceed", "answer_support"),
    "insufficient_evidence": ("abstain", "abstention_support"),
    "unrelated": ("abstain", "no_relevant_chunk"),
}
_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
_POINTER_ESCAPE = re.compile(r"~(?![01])")


class ReviewArtifactValidationError(ValueError):
    """Raised when review metadata or package consistency is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewArtifactValidationError(message)


def _object(value: object, path: str, fields: tuple[str, ...] | None = None) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{path} must be an object")
    assert isinstance(value, Mapping)
    _require(all(isinstance(key, str) for key in value), f"{path} keys must be strings")
    if fields is not None:
        _require(set(value) == set(fields), f"{path} fields must be {sorted(fields)!r}")
    return value


def _text(value: object, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be a non-empty string")
    assert isinstance(value, str)
    return value


def _integer(value: object, path: str) -> int:
    _require(type(value) is int and value >= 0, f"{path} must be a nonnegative integer")
    assert isinstance(value, int)
    return value


def _hash(value: object, path: str) -> str:
    digest = _text(value, path)
    _require(_HASH.fullmatch(digest) is not None, f"{path} must be a SHA-256 digest")
    return digest


def _relative_path(value: object, path: str) -> str:
    result = _text(value, path)
    posix, windows = PurePosixPath(result), PureWindowsPath(result)
    _require(
        not posix.is_absolute() and not windows.drive and not windows.root
        and ".." not in posix.parts and ".." not in windows.parts,
        f"{path} must be a repository-relative path",
    )
    return result


def _strings(value: object, path: str, *, unique: bool = False) -> list[str]:
    _require(isinstance(value, list), f"{path} must be a list")
    assert isinstance(value, list)
    result = [_text(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if unique:
        _require(len(result) == len(set(result)), f"{path} must not contain duplicates")
    return result


def _date(value: object, path: str) -> None:
    text = _text(value, path)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise ReviewArtifactValidationError(f"{path} must be an ISO date") from exc
    _require(parsed.isoformat() == text, f"{path} must use YYYY-MM-DD")


def _json(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ReviewArtifactValidationError(f"{path} must be valid UTF-8") from exc
        return
    if isinstance(value, float):
        _require(math.isfinite(value), f"{path} must be finite JSON")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in _object(value, path).items():
            _json(key, path)
            _json(item, f"{path}.{key}")
        return
    raise ReviewArtifactValidationError(f"{path} must contain native JSON values")


def _human_review(status: object, reviewer: object, approved_at: object, *, path: str,
                  pending: str = "pending_human_review", approved: str = "confirmed") -> None:
    try:
        validate_human_review(
            status, reviewer, approved_at, path=path,
            pending_status=pending, approved_status=approved,
        )
    except ValueError as exc:
        raise ReviewArtifactValidationError(str(exc)) from exc


def _hash_map(value: object, path: str) -> Mapping[str, Any]:
    result = _object(value, path)
    _require(bool(result), f"{path} must not be empty")
    for key, digest in result.items():
        _relative_path(key, f"{path} key")
        _hash(digest, f"{path}.{key}")
    return result


def _source(value: object, path: str) -> Mapping[str, Any]:
    source = _object(value, path, ("path", "sha256"))
    _relative_path(source["path"], f"{path}.path")
    _hash(source["sha256"], f"{path}.sha256")
    return source


def _pointer(value: object, path: str) -> str:
    pointer = _text(value, path)
    _require(pointer.startswith("/") and _POINTER_ESCAPE.search(pointer) is None,
             f"{path} must be a JSON pointer")
    return pointer


def _validate_reference_answers(document: object) -> Mapping[str, Any]:
    root = _object(document, "answers", _ANSWER_FIELDS)
    _json(root, "answers")
    version = root["schema_version"]
    _require(version in (REFERENCE_ANSWERS_SCHEMA_V1, REFERENCE_ANSWERS_SCHEMA_V2),
             "answers.schema_version is unsupported")
    _text(root["scenario_id"], "answers.scenario_id")
    _require(root["purpose"] == "evaluation_reference_only_not_retrieval_or_runtime_gate_input",
             "answers.purpose must retain the evaluation-only boundary")
    review = _object(root["review"], "answers.review", _ANSWER_REVIEW_FIELDS)
    _text(review["reviewer"], "answers.review.reviewer")
    _require(review["reviewer_type"] == "ai_assistant", "answers.review.reviewer_type is unsupported")
    _require(review["review_type"] == "evidence_and_reference_answer_audit", "answers.review.review_type is unsupported")
    _date(review["review_date"], "answers.review.review_date")
    _strings(review["notes"], "answers.review.notes")
    if version == REFERENCE_ANSWERS_SCHEMA_V1:
        _require(review["review_status"] == ANSWERS_PENDING_STATUS, "answers v1 must remain pending human approval")
    _human_review(review["review_status"], review["human_reviewer"], review["human_approved_at"],
                  path="answers.review", pending=ANSWERS_PENDING_STATUS, approved=ANSWERS_APPROVED_STATUS)
    scope = _object(root["scope_policy"], "answers.scope_policy", _SCOPE_FIELDS)
    for key, value in scope.items():
        _text(value, f"answers.scope_policy.{key}")
    sources = _object(root["sources"], "answers.sources", ("dataset", "ground_truth", "raw_log"))
    for key, source in sources.items():
        _source(source, f"answers.sources.{key}")
    cases = root["cases"]
    _require(isinstance(cases, list) and bool(cases), "answers.cases must be a non-empty list")
    seen: set[str] = set()
    for index, item in enumerate(cases):
        path = f"answers.cases[{index}]"
        case = _object(item, path, _CASE_FIELDS)
        identifier = _text(case["case_id"], f"{path}.case_id")
        _require(identifier not in seen, f"{path}.case_id is duplicated")
        seen.add(identifier)
        category = _text(case["category"], f"{path}.category")
        _require(category in _CATEGORY_DECISIONS, f"{path}.category is unsupported")
        _require((case["expected_decision"], case["target_kind"]) == _CATEGORY_DECISIONS[category],
                 f"{path} category, decision and target_kind disagree")
        _require(case["language"] in ("en", "vi"), f"{path}.language is unsupported")
        _require(case["reference_answer_language"] == "vi", f"{path}.reference_answer_language is unsupported")
        for key in ("query", "original_query", "reference_answer"):
            _text(case[key], f"{path}.{key}")
        _require(case["source_case_pointer"] == f"/cases/{index}", f"{path}.source_case_pointer disagrees with its position")
        pointers = _strings(case["ground_truth_pointers"], f"{path}.ground_truth_pointers", unique=True)
        for pointer in pointers:
            _pointer(pointer, f"{path}.ground_truth_pointers")
        _require(bool(pointers) == (category != "unrelated"), f"{path}.ground_truth_pointers disagree with category")
        _strings(case["answer_constraints"], f"{path}.answer_constraints")
        references = case["raw_record_references"]
        _require(isinstance(references, list), f"{path}.raw_record_references must be a list")
        reference_ids: set[tuple[str, str]] = set()
        for ref_index, ref in enumerate(references):
            ref_path = f"{path}.raw_record_references[{ref_index}]"
            reference = _object(ref, ref_path, ("source_file", "raw_record_ref"))
            pair = tuple(_text(reference[key], f"{ref_path}.{key}") for key in ("source_file", "raw_record_ref"))
            _require(pair not in reference_ids, f"{ref_path} duplicates a raw reference")
            reference_ids.add(pair)
        role = "supports_stated_observed_fields" if references else "not_required_for_artifact_status_or_scope_answer"
        _require(case["raw_reference_role"] == role, f"{path}.raw_reference_role disagrees with references")
    metadata = _object(root["metadata"], "answers.metadata", _METADATA_FIELDS)
    _require(_integer(metadata["case_count"], "answers.metadata.case_count") == len(cases), "answers.metadata.case_count disagrees with cases")
    for name, field, vocabulary in (
        ("category_counts", "category", tuple(_CATEGORY_DECISIONS)),
        ("decision_counts", "expected_decision", ("abstain", "proceed")),
    ):
        counts = _object(metadata[name], f"answers.metadata.{name}")
        _require(set(counts).issubset(vocabulary), f"answers.metadata.{name} contains unsupported keys")
        for key, value in counts.items():
            _integer(value, f"answers.metadata.{name}.{key}")
        _require(dict(counts) == dict(Counter(case[field] for case in cases)), f"answers.metadata.{name} disagrees with cases")
    _require(_integer(metadata["changed_labels"], "answers.metadata.changed_labels") == 0, "answers.metadata.changed_labels must remain zero")
    changed = sum(case["query"] != case["original_query"] for case in cases)
    _require(_integer(metadata["changed_queries"], "answers.metadata.changed_queries") == changed, "answers.metadata.changed_queries disagrees with cases")
    _require(metadata["dataset_use"] == "calibration_not_final_benchmark", "answers.metadata.dataset_use is unsupported")
    return root


def validate_reference_answers_document(document: object) -> None:
    """Validate original pending v1 or explicitly versioned v2 review answers."""
    _validate_reference_answers(document)


def _validate_review_manifest(document: object) -> Mapping[str, Any]:
    root = _object(document, "manifest")
    _json(root, "manifest")
    version = root.get("schema_version")
    _require(version in (REVIEW_MANIFEST_SCHEMA_V1, REVIEW_MANIFEST_SCHEMA_V2), "manifest.schema_version is unsupported")
    fields = _MANIFEST_FIELDS + (_APPROVAL_MANIFEST_FIELDS if version == REVIEW_MANIFEST_SCHEMA_V2 else ())
    _object(root, "manifest", fields)
    for key in ("reviewer", "scenario_id", "consumer_note"):
        _text(root[key], f"manifest.{key}")
    _require(root["reviewer_type"] == "ai_assistant", "manifest.reviewer_type is unsupported")
    _require(root["status"] == "technical_review_completed_with_corrections", "manifest.status must describe the original technical review")
    _date(root["review_date"], "manifest.review_date")
    for key in ("baseline_ground_truth_valid", "input_hashes_unchanged", "json_readback_passed"):
        _require(root[key] is True, f"manifest.{key} must be true")
    for key in (
        "canonical_records_examined", "category_and_decision_changes", "mitre_label_promotions",
        "query_wording_corrections", "raw_records_examined", "reference_answers",
        "resolved_baseline_cases", "resolved_baseline_relevance_pointers", "reviewed_entities",
        "reviewed_evidence", "reviewed_relationships",
    ):
        _integer(root[key], f"manifest.{key}")
    _require(root["canonical_records_examined"] == root["raw_records_examined"], "manifest record counts disagree")
    _require(root["reference_answers"] == root["resolved_baseline_cases"], "manifest case counts disagree")
    _require(root["category_and_decision_changes"] == root["mitre_label_promotions"] == 0,
             "manifest must not record label changes or promotions")
    for key in ("artifacts", "baseline_inputs", "original_sources"):
        _hash_map(root[key], f"manifest.{key}")
    _require({"scenario_ground_truth.json", "reference_answers.json"}.issubset(root["artifacts"]),
             "manifest.artifacts must include ground truth and reference answers")
    if version == REVIEW_MANIFEST_SCHEMA_V1:
        _require(root["human_review_status"] == "pending_human_review", "manifest v1 must remain pending human review")
    else:
        _human_review(root["human_review_status"], root["human_reviewer"], root["human_approved_at"], path="manifest")
        provenance = _object(root["approval_provenance"], "manifest.approval_provenance",
                             ("previous_artifacts", "basis", "timestamp_basis"))
        previous = _object(provenance["previous_artifacts"], "manifest.approval_provenance.previous_artifacts", _APPROVAL_ARTIFACTS)
        for key, digest in previous.items():
            _hash(digest, f"manifest.approval_provenance.previous_artifacts.{key}")
        for key in ("basis", "timestamp_basis"):
            _text(provenance[key], f"manifest.approval_provenance.{key}")
    return root


def validate_review_manifest_document(document: object) -> None:
    """Validate the technical-review manifest without reading or rebuilding files."""
    _validate_review_manifest(document)


def _resolve_pointer(document: object, pointer: str) -> None:
    value = document
    try:
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                _require(token.isdigit() and (token == "0" or not token.startswith("0")), f"Invalid array index in {pointer!r}")
                value = value[int(token)]
            else:
                value = _object(value, pointer)[token]
    except (KeyError, IndexError, ValueError) as exc:
        raise ReviewArtifactValidationError(f"Ground-truth pointer does not resolve: {pointer!r}") from exc


def validate_review_bundle(
    ground_truth: object, reference_answers: object, manifest: object, *,
    ground_truth_sha256: str, reference_answers_sha256: str,
) -> None:
    """Check one approval event, current artifact hashes, and pinned provenance.

    Actual file digests are supplied by the caller. This function performs no
    file access and never changes its inputs or any evidence/security labels.
    """
    try:
        validate_ground_truth_document(ground_truth)
    except ValueError as exc:
        raise ReviewArtifactValidationError(f"Invalid ground truth: {exc}") from exc
    gt = _object(ground_truth, "ground_truth")
    answers = _validate_reference_answers(reference_answers)
    review_manifest = _validate_review_manifest(manifest)
    _hash(ground_truth_sha256, "ground_truth_sha256")
    _hash(reference_answers_sha256, "reference_answers_sha256")
    scenario = gt["scenario"]["scenario_id"]
    _require(answers["scenario_id"] == review_manifest["scenario_id"] == scenario, "Bundle scenario IDs disagree")
    gt_review, answer_review = gt["review"], answers["review"]
    expected = (gt_review["review_status"], gt_review["reviewer"], gt_review["reviewed_at"])
    answer_status = "confirmed" if answer_review["review_status"] == ANSWERS_APPROVED_STATUS else "pending_human_review"
    answer_event = (answer_status, answer_review["human_reviewer"], answer_review["human_approved_at"])
    manifest_event = (
        review_manifest["human_review_status"], review_manifest.get("human_reviewer"),
        review_manifest.get("human_approved_at"),
    )
    _require(expected == answer_event == manifest_event, "Bundle human review status, reviewer or approval time disagree")
    _require(answer_review["reviewer"] == review_manifest["reviewer"]
             and answer_review["reviewer_type"] == review_manifest["reviewer_type"]
             and answer_review["review_date"] == review_manifest["review_date"], "Bundle technical-review provenance disagrees")
    sources, artifact_hashes = answers["sources"], review_manifest["artifacts"]
    _require(sources["ground_truth"]["sha256"] == artifact_hashes["scenario_ground_truth.json"] == ground_truth_sha256,
             "Bundle ground-truth SHA-256 disagrees")
    _require(artifact_hashes["reference_answers.json"] == reference_answers_sha256,
             "Bundle reference-answers SHA-256 disagrees")
    _require(PurePosixPath(sources["ground_truth"]["path"]).name == "scenario_ground_truth.json",
             "Bundle ground-truth source filename disagrees")
    originals = review_manifest["original_sources"]
    for entry in gt["input_provenance"]:
        _require(originals.get(entry["path"]) == entry["sha256"],
                 f"Bundle input provenance changed or missing: {entry['path']}")
    raw_source, dataset_source = sources["raw_log"], sources["dataset"]
    _require(originals.get(raw_source["path"]) == raw_source["sha256"], "Bundle raw-source provenance disagrees")
    _require(artifact_hashes.get(PurePosixPath(dataset_source["path"]).name) == dataset_source["sha256"],
             "Bundle dataset provenance disagrees")
    for manifest_key, collection in (
        ("reviewed_entities", "entities"), ("reviewed_evidence", "evidence"),
        ("reviewed_relationships", "relationships"),
    ):
        _require(review_manifest[manifest_key] == len(gt[collection]), f"Bundle {manifest_key} disagrees")
    _require(review_manifest["reference_answers"] == len(answers["cases"]), "Bundle reference answer count disagrees")
    _require(review_manifest["query_wording_corrections"] == answers["metadata"]["changed_queries"], "Bundle query correction count disagrees")
    raw_references = {
        (ref["source_file"], ref["raw_record_ref"])
        for item in gt["evidence"] for ref in item["source_references"]
    }
    raw_filename = PurePosixPath(raw_source["path"]).name
    for case in answers["cases"]:
        for pointer in case["ground_truth_pointers"]:
            _resolve_pointer(gt, pointer)
        for ref in case["raw_record_references"]:
            _require(ref["source_file"] == raw_filename
                     and (ref["source_file"], ref["raw_record_ref"]) in raw_references,
                     f"Bundle answer raw reference is unsupported: {case['case_id']}")


__all__ = (
    "REFERENCE_ANSWERS_SCHEMA_V1", "REFERENCE_ANSWERS_SCHEMA_V2",
    "REVIEW_MANIFEST_SCHEMA_V1", "REVIEW_MANIFEST_SCHEMA_V2",
    "ReviewArtifactValidationError", "validate_reference_answers_document",
    "validate_review_manifest_document", "validate_review_bundle",
)
