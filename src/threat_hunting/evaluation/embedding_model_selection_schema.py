"""Strict, detached contracts for policy-based embedding model recommendations.

Paths in the supplied comparison report remain provenance labels. Validation
does not open files, run retrieval or models, or change production decisions.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
import re
from typing import Any
import unicodedata

from .embedding_retrieval_comparison_schema import (
    EmbeddingRetrievalComparisonError,
    validate_embedding_retrieval_comparison_report,
)


EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION = "embedding-model-selection-policy/v1"
EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION = "embedding-model-selection/v1"
_POLICY_FIELDS = (
    "schema_version", "policy_id", "primary_cutoff", "validation_cutoff",
    "priority_language", "secondary_languages", "primary_metric",
    "required_overall_metrics", "min_priority_language_delta",
    "max_overall_regression", "max_secondary_language_regression",
    "max_slice_regression", "require_positive_validation_delta", "tie_break_policy", "review",
)
_SELECTION_FIELDS = (
    "schema_version", "evaluation_id", "policy_id", "baseline_candidate_id",
    "candidate_assessments", "decision", "recommended_candidate_id",
    "reason_codes", "warnings", "review", "metadata",
)
_REVIEW_FIELDS = ("review_status", "reviewer", "reviewed_at")
_METRIC_FIELDS = {
    "ndcg": "mean_ndcg_at_k", "mrr": "mrr_at_k",
    "recall": "macro_recall_at_k", "hit_rate": "hit_rate_at_k",
}
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_FORBIDDEN_FIELDS = frozenset({
    "question", "questions", "questiontext", "query", "queries", "querytext",
    "expectedanswer", "expectedanswers", "generatedanswer", "generatedanswers",
    "referenceanswer", "referenceanswers", "goldanswer", "goldanswers",
    "answer", "answers", "modeloutput", "modeloutputs", "llmoutput",
    "llmoutputs", "llmresponse", "llmresponses",
})


class EmbeddingModelSelectionError(ValueError):
    """Raised when a policy, comparison report, or recommendation is invalid."""


def _field_path(path: str, key: str) -> str:
    return f"{path}.{key}" if key.isidentifier() else f"{path}[{json.dumps(key)}]"


def _guard_identifier(value: str) -> str:
    return "".join(
        character for character in unicodedata.normalize("NFKC", value).casefold()
        if character.isalnum()
    )


def _snapshot(value: object, path: str, active: set[int]) -> Any:
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        if unicodedata.normalize("NFKC", value).strip().casefold() == "confirmed":
            raise EmbeddingModelSelectionError(f"{path} must not contain confirmed")
        return str(value)
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise EmbeddingModelSelectionError(f"{path} must contain finite JSON numbers")
        return value
    if not isinstance(value, (Mapping, list)):
        raise EmbeddingModelSelectionError(f"{path} must contain only native JSON values")
    if id(value) in active:
        raise EmbeddingModelSelectionError(f"{path} contains a cyclic JSON value")
    active.add(id(value))
    try:
        if isinstance(value, Mapping):
            detached: dict[str, Any] = {}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise EmbeddingModelSelectionError(f"{path} must have string object keys")
                where = _field_path(path, key)
                _snapshot(key, where, active)
                if _guard_identifier(key) in _FORBIDDEN_FIELDS:
                    raise EmbeddingModelSelectionError(f"{where} is forbidden in selection data")
                detached[str(key)] = _snapshot(child, where, active)
            return detached
        return [_snapshot(child, f"{path}[{index}]", active) for index, child in enumerate(value)]
    finally:
        active.remove(id(value))


def canonical_json(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes, refusing nonfinite values."""
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingModelSelectionError(f"$ cannot serialize selection JSON: {exc}") from exc


def snapshot_selection_json(value: object, path: str = "$") -> Any:
    """Snapshot finite JSON without mutation, with recursive content guards."""
    try:
        detached = _snapshot(value, path, set())
        canonical_json(detached)
        return detached
    except EmbeddingModelSelectionError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingModelSelectionError(f"{path} cannot snapshot JSON: {exc}") from exc


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EmbeddingModelSelectionError(f"{path} must be a JSON object")
    return value


def _exact_fields(
    value: dict[str, Any], required: tuple[str, ...], path: str,
) -> None:
    missing = sorted(set(required) - set(value))
    unexpected = sorted(set(value) - set(required))
    if missing or unexpected:
        raise EmbeddingModelSelectionError(
            f"{path} fields must match the contract: missing {missing!r}; unexpected {unexpected!r}"
        )


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise EmbeddingModelSelectionError(f"{path} must be a normalized non-empty identifier")
    return value


def _positive_integer(value: object, path: str) -> int:
    if type(value) is not int or value < 1:
        raise EmbeddingModelSelectionError(f"{path} must be a positive integer, not a boolean")
    return value


def _number(value: object, path: str, minimum: int, maximum: int) -> int | float:
    if type(value) not in (int, float):
        raise EmbeddingModelSelectionError(f"{path} must be numeric, not a boolean")
    try:
        valid = math.isfinite(value) and minimum <= value <= maximum
    except OverflowError:
        valid = False
    if not valid:
        raise EmbeddingModelSelectionError(f"{path} must be finite in [{minimum}, {maximum}]")
    return value


def _sorted_identifiers(value: object, path: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise EmbeddingModelSelectionError(f"{path} must be a non-empty list")
    identifiers = [_identifier(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if identifiers != sorted(set(identifiers)):
        raise EmbeddingModelSelectionError(f"{path} must be unique and stably sorted")
    return identifiers


def _validate_policy(root: dict[str, Any]) -> None:
    _exact_fields(root, _POLICY_FIELDS, "$.policy")
    if root["schema_version"] != EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION:
        raise EmbeddingModelSelectionError("$.policy.schema_version does not match the policy contract")
    _identifier(root["policy_id"], "$.policy.policy_id")
    for field in ("primary_cutoff", "validation_cutoff"):
        _positive_integer(root[field], f"$.policy.{field}")
    priority = _identifier(root["priority_language"], "$.policy.priority_language")
    languages = _sorted_identifiers(root["secondary_languages"], "$.policy.secondary_languages")
    if priority in languages:
        raise EmbeddingModelSelectionError("$.policy.secondary_languages must not contain priority_language")
    if root["primary_metric"] not in _METRIC_FIELDS or not isinstance(root["primary_metric"], str):
        raise EmbeddingModelSelectionError("$.policy.primary_metric must be ndcg, mrr, recall, or hit_rate")
    metrics = _sorted_identifiers(root["required_overall_metrics"], "$.policy.required_overall_metrics")
    if any(metric not in _METRIC_FIELDS for metric in metrics):
        raise EmbeddingModelSelectionError("$.policy.required_overall_metrics contains an unsupported metric")
    for field in (
        "min_priority_language_delta", "max_overall_regression",
        "max_secondary_language_regression", "max_slice_regression",
    ):
        _number(root[field], f"$.policy.{field}", 0, 1)
    if type(root["require_positive_validation_delta"]) is not bool:
        raise EmbeddingModelSelectionError("$.policy.require_positive_validation_delta must be boolean")
    if not isinstance(root["tie_break_policy"], str) or root["tie_break_policy"] not in ("candidate_id", "human_review"):
        raise EmbeddingModelSelectionError("$.policy.tie_break_policy must be candidate_id or human_review")
    review = _object(root["review"], "$.policy.review")
    _exact_fields(review, _REVIEW_FIELDS, "$.policy.review")
    if review["review_status"] != "pending_human_review":
        raise EmbeddingModelSelectionError("$.policy.review.review_status must be pending_human_review")
    if review["reviewer"] is not None or review["reviewed_at"] is not None:
        raise EmbeddingModelSelectionError("$.policy.review.reviewer and reviewed_at must be null")


def _metric(
    row: dict[str, Any], metric: str, cutoff: int, path: str,
) -> None:
    at_cutoff = next((item for item in row["metrics"] if item["cutoff"] == cutoff), None)
    if at_cutoff is None or _METRIC_FIELDS[metric] not in at_cutoff:
        raise EmbeddingModelSelectionError(f"{path} is missing metric {metric!r} at cutoff {cutoff}")
    _number(at_cutoff[_METRIC_FIELDS[metric]], f"{path}.{metric}@{cutoff}", 0, 1)


def _validate_policy_context(report: dict[str, Any], policy: dict[str, Any]) -> None:
    for field in ("primary_cutoff", "validation_cutoff"):
        if policy[field] not in report["cutoffs"]:
            raise EmbeddingModelSelectionError(f"$.policy.{field} must exist in comparison_report.cutoffs")
    rows = {
        (row["candidate_id"], row["group_by"], canonical_json(row["key"])): row
        for row in report["aggregates"]
    }
    primary = policy["primary_metric"]
    languages = sorted({policy["priority_language"], *policy["secondary_languages"]})
    metrics = sorted({primary, *policy["required_overall_metrics"]})
    for descriptor in report["candidates"]:
        candidate_id = descriptor["candidate_id"]
        overall = rows.get((candidate_id, "candidate", canonical_json({})))
        if overall is None:
            raise EmbeddingModelSelectionError(f"$.comparison_report is missing overall breakdown for {candidate_id!r}")
        for metric in metrics:
            _metric(overall, metric, policy["primary_cutoff"], "$.comparison_report.aggregates")
        _metric(overall, primary, policy["validation_cutoff"], "$.comparison_report.aggregates")
        for language in languages:
            row = rows.get((candidate_id, "language", canonical_json({"language": language})))
            if row is None:
                raise EmbeddingModelSelectionError(f"$.comparison_report is missing language breakdown {language!r}")
            _metric(row, primary, policy["primary_cutoff"], "$.comparison_report.aggregates")
        for row in report["aggregates"]:
            if row["candidate_id"] == candidate_id and row["group_by"] == "category_language" and row["relevance_case_count"] > 0:
                _metric(row, primary, policy["primary_cutoff"], "$.comparison_report.aggregates")


def validated_inputs(
    comparison_report: object, policy: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return detached, context-validated report and policy for evaluator replay."""
    try:
        report = _object(snapshot_selection_json(comparison_report, "$.comparison_report"), "$.comparison_report")
        checked_policy = _object(snapshot_selection_json(policy, "$.policy"), "$.policy")
        validate_embedding_retrieval_comparison_report(report)
        _validate_policy(checked_policy)
        _validate_policy_context(report, checked_policy)
        return report, checked_policy
    except EmbeddingModelSelectionError:
        raise
    except (EmbeddingRetrievalComparisonError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingModelSelectionError(f"$ cannot validate selection inputs: {exc}") from exc


def validate_embedding_model_selection_policy(
    policy: object, *, comparison_report: object | None = None,
) -> None:
    """Validate policy syntax and, when supplied, required report breakdowns."""
    if comparison_report is not None:
        validated_inputs(comparison_report, policy)
        return
    try:
        checked_policy = _object(snapshot_selection_json(policy, "$.policy"), "$.policy")
        _validate_policy(checked_policy)
    except EmbeddingModelSelectionError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingModelSelectionError(f"$.policy cannot validate: {exc}") from exc


def validate_embedding_model_selection(
    selection: object, *, comparison_report: object, policy: object,
) -> None:
    """Replay the complete recommendation and reject any structural tampering.

    Required context binds candidate IDs, every delta, conditions, ordering,
    reason codes, decision, counts, review status, and the deterministic ID.
    """
    try:
        checked = _object(snapshot_selection_json(selection), "$")
        _exact_fields(checked, _SELECTION_FIELDS, "$")
        report, checked_policy = validated_inputs(comparison_report, policy)
        # This helper does not call public validation, avoiding replay recursion.
        from .embedding_model_selection import _complete_selection

        expected = _complete_selection(report, checked_policy)
        if canonical_json(checked) != canonical_json(expected):
            raise EmbeddingModelSelectionError("$ must match the complete deterministic selection replay")
    except EmbeddingModelSelectionError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingModelSelectionError(f"$ cannot validate selection: {exc}") from exc


__all__ = (
    "EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION",
    "EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION",
    "EmbeddingModelSelectionError",
    "validate_embedding_model_selection_policy",
    "validate_embedding_model_selection",
)
