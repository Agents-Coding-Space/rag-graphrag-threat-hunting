"""Evaluate context eligibility with two stages and an explicit caller policy.

Only validated returned-context signals supply observations. Zero count minima
and null score thresholds disable their respective conditions; no policy or
threshold is selected here. A proceed decision does not establish answer truth
or a security conclusion. Retrieval scores are not probabilities.
"""

from __future__ import annotations

from collections.abc import Mapping
import math
from typing import Any, cast

from .gate_signals import _validated_gate_signals
from .relevance import (
    _boolean, _integer, _json_bytes, _object, _require, _snapshot, _text,
)


GRAPHRAG_TWO_STAGE_GATE_POLICY_SCHEMA_VERSION = "graphrag-two-stage-gate-policy/v1"
GRAPHRAG_TWO_STAGE_GATE_DECISION_SCHEMA_VERSION = "graphrag-two-stage-gate-decision/v1"

_POLICY_FIELDS = (
    "schema_version", "policy_id", "topical_relevance", "evidence_answerability",
)
_TOPICAL_COUNT_CHECKS = (
    ("min_retrieval_hit_count", "retrieval_hit_count", "insufficient_retrieval_hits"),
    ("min_lexical_hit_count", "lexical_hit_count", "insufficient_lexical_hits"),
    ("min_vector_hit_count", "vector_hit_count", "insufficient_vector_hits"),
    (
        "min_joint_lexical_vector_hit_count", "joint_lexical_vector_hit_count",
        "insufficient_joint_lexical_vector_hits",
    ),
)
_TOPICAL_SCORE_CHECKS = (
    (
        "min_returned_top_rrf_score", "returned_top_rrf_score",
        "returned_top_rrf_score_missing", "returned_top_rrf_score_below_threshold",
    ),
    (
        "min_returned_top_bm25_score", "returned_top_bm25_score",
        "returned_top_bm25_score_missing", "returned_top_bm25_score_below_threshold",
    ),
    (
        "min_returned_top_cosine_score", "returned_top_cosine_score",
        "returned_top_cosine_score_missing", "returned_top_cosine_score_below_threshold",
    ),
)
_TOPICAL_POLICY_FIELDS = (
    *(check[0] for check in _TOPICAL_COUNT_CHECKS),
    "min_query_token_coverage",
    *(check[0] for check in _TOPICAL_SCORE_CHECKS),
)
_ANSWERABILITY_HIT_CHECKS = (
    (
        "min_hits_with_evidence_ids", "hits_with_evidence_ids",
        "insufficient_hits_with_evidence_ids",
    ),
    (
        "min_hits_with_source_references", "hits_with_source_references",
        "insufficient_hits_with_source_references",
    ),
    (
        "min_unique_source_reference_count", "unique_source_reference_count",
        "insufficient_unique_source_references",
    ),
    ("min_mapped_hit_count", "mapped_hit_count", "insufficient_mapped_hits"),
    ("min_seed_node_count", "seed_node_count", "insufficient_seed_nodes"),
)
_ANSWERABILITY_TRAVERSAL_CHECKS = (
    ("min_traversal_node_count", "traversal_node_count", "insufficient_traversal_nodes"),
    ("min_traversal_edge_count", "traversal_edge_count", "insufficient_traversal_edges"),
    ("min_traversal_path_count", "traversal_path_count", "insufficient_traversal_paths"),
    (
        "min_traversed_evidence_node_count", "traversed_evidence_node_count",
        "insufficient_traversed_evidence_nodes",
    ),
    ("min_support_edge_count", "support_edge_count", "insufficient_support_edges"),
)
_ANSWERABILITY_POLICY_FIELDS = (
    *(check[0] for check in _ANSWERABILITY_HIT_CHECKS),
    "require_traversal",
    *(check[0] for check in _ANSWERABILITY_TRAVERSAL_CHECKS),
    "max_traversed_limitation_node_count",
)


class GraphRAGTwoStageGateError(ValueError):
    """Raised when signals or policy cannot safely produce a gate decision."""


def _threshold(
    value: object, path: str, *, minimum: int | float, maximum: int | float | None = None,
) -> int | float:
    """Validate one enabled finite threshold without coercing booleans."""
    _require(type(value) in (int, float), f"{path} must be numeric, excluding bool")
    number = cast(int | float, value)
    try:
        finite = math.isfinite(number)
    except OverflowError:
        finite = False
    _require(finite, f"{path} must be finite")
    _require(number >= minimum, f"{path} must be >= {minimum}")
    _require(maximum is None or number <= maximum, f"{path} exceeds its valid range")
    return number


def _validated_policy(policy: object) -> dict[str, Any]:
    """Detach a complete strict policy; every condition must be supplied."""
    configured = _object(_snapshot(policy, "policy", set()), "policy", _POLICY_FIELDS)
    _require(
        configured["schema_version"] == GRAPHRAG_TWO_STAGE_GATE_POLICY_SCHEMA_VERSION,
        "policy.schema_version is unsupported",
    )
    _text(configured["policy_id"], "policy.policy_id")
    topical = _object(
        configured["topical_relevance"], "policy.topical_relevance", _TOPICAL_POLICY_FIELDS,
    )
    answerability = _object(
        configured["evidence_answerability"], "policy.evidence_answerability",
        _ANSWERABILITY_POLICY_FIELDS,
    )
    for setting, _, _ in _TOPICAL_COUNT_CHECKS:
        _integer(topical[setting], f"policy.topical_relevance.{setting}")
    _threshold(
        topical["min_query_token_coverage"], "policy.topical_relevance.min_query_token_coverage",
        minimum=0, maximum=1,
    )
    for setting, _, _, _ in _TOPICAL_SCORE_CHECKS:
        if topical[setting] is not None:
            cosine = setting == "min_returned_top_cosine_score"
            _threshold(
                topical[setting], f"policy.topical_relevance.{setting}",
                minimum=-1 if cosine else 0, maximum=1 if cosine else None,
            )
    for setting, _, _ in (*_ANSWERABILITY_HIT_CHECKS, *_ANSWERABILITY_TRAVERSAL_CHECKS):
        _integer(answerability[setting], f"policy.evidence_answerability.{setting}")
    _boolean(answerability["require_traversal"], "policy.evidence_answerability.require_traversal")
    maximum = answerability["max_traversed_limitation_node_count"]
    if maximum is not None:
        _integer(maximum, "policy.evidence_answerability.max_traversed_limitation_node_count")
    _json_bytes(configured)
    return {
        "schema_version": configured["schema_version"],
        "policy_id": configured["policy_id"],
        "topical_relevance": {field: topical[field] for field in _TOPICAL_POLICY_FIELDS},
        "evidence_answerability": {
            field: answerability[field] for field in _ANSWERABILITY_POLICY_FIELDS
        },
    }


def _minimum_reasons(
    signals: Mapping[str, Any], policy: Mapping[str, Any],
    checks: tuple[tuple[str, str, str], ...],
) -> list[str]:
    return [
        reason for setting, observed, reason in checks
        if policy[setting] > 0 and signals[observed] < policy[setting]
    ]


def _topical_reasons(
    signals: Mapping[str, Any], policy: Mapping[str, Any],
) -> list[str]:
    """Check every topical condition in the fixed policy field order."""
    reasons = _minimum_reasons(signals, policy, _TOPICAL_COUNT_CHECKS)
    if signals["query_token_coverage"] < policy["min_query_token_coverage"]:
        reasons.append("query_token_coverage_below_threshold")
    for setting, observed, missing, below in _TOPICAL_SCORE_CHECKS:
        minimum = policy[setting]
        if minimum is not None:
            if signals[observed] is None:
                reasons.append(missing)
            elif signals[observed] < minimum:
                reasons.append(below)
    return reasons


def _answerability_reasons(
    signals: Mapping[str, Any], policy: Mapping[str, Any],
) -> list[str]:
    """Check answerability only after topical eligibility has passed."""
    reasons = _minimum_reasons(signals, policy, _ANSWERABILITY_HIT_CHECKS)
    if policy["require_traversal"] and not signals["traversal_performed"]:
        reasons.append("traversal_required")
    reasons.extend(_minimum_reasons(signals, policy, _ANSWERABILITY_TRAVERSAL_CHECKS))
    maximum = policy["max_traversed_limitation_node_count"]
    if maximum is not None and signals["traversed_limitation_node_count"] > maximum:
        reasons.append("traversed_limitation_node_count_above_maximum")
    return reasons


def assess_graphrag_two_stage_gate(
    signals: Mapping[str, object], *, policy: Mapping[str, object],
) -> dict[str, object]:
    """Return a detached finite decision from strict signals and a full policy.

    Both input contracts are validated before evaluating conditions. All topical
    conditions run first. A failed topical stage leaves answerability conditions
    unevaluated, while retaining their input signals with empty reason codes.
    Otherwise every answerability condition runs. Equality passes each minimum
    or maximum, and enabled missing scores have distinct fixed failure reasons.

    Conditions and reasons follow policy field order, independent of mapping
    insertion order. Technical failures raise GraphRAGTwoStageGateError;
    KeyboardInterrupt and SystemExit propagate. No artifact is accessed or
    authenticated, and no security conclusion is made.
    """
    try:
        configured = _validated_policy(policy)
        root = _validated_gate_signals(signals)
        topical_signals = root["topical_relevance"]
        answerability_signals = root["evidence_answerability"]
        topical_reasons = _topical_reasons(topical_signals, configured["topical_relevance"])
        answerability_reasons = (
            [] if topical_reasons
            else _answerability_reasons(answerability_signals, configured["evidence_answerability"])
        )
        if topical_reasons:
            abstention_stage = "topical_relevance"
            answerability_status = "not_evaluated"
        elif answerability_reasons:
            abstention_stage = "evidence_answerability"
            answerability_status = "failed"
        else:
            abstention_stage = None
            answerability_status = "passed"
        result = {
            "schema_version": GRAPHRAG_TWO_STAGE_GATE_DECISION_SCHEMA_VERSION,
            "corpus_id": root["corpus_id"],
            "graph_id": root["graph_id"],
            "scenario_id": root["scenario_id"],
            "query": root["query"],
            "policy_id": configured["policy_id"],
            "decision": "abstain" if abstention_stage is not None else "proceed",
            "abstention_stage": abstention_stage,
            "reason_codes": [*topical_reasons, *answerability_reasons],
            "stage_results": {
                "topical_relevance": {
                    "status": "failed" if topical_reasons else "passed",
                    "reason_codes": topical_reasons,
                    "signals": topical_signals,
                },
                "evidence_answerability": {
                    "status": answerability_status,
                    "reason_codes": answerability_reasons,
                    "signals": answerability_signals,
                },
            },
            "warnings": root["warnings"],
            "metadata": {
                "signal_schema_version": root["schema_version"],
                "policy_schema_version": configured["schema_version"],
                "policy": configured,
                "score_interpretations": root["metadata"]["score_interpretations"],
                "decision_interpretation": "context_eligibility_only",
                "security_conclusion_made": False,
                "source_ground_truth": root["source_ground_truth"],
            },
        }
        _json_bytes(result)
        return result
    except Exception as exc:
        raise GraphRAGTwoStageGateError(f"Invalid GraphRAG two-stage gate input: {exc}") from exc


__all__ = (
    "GRAPHRAG_TWO_STAGE_GATE_POLICY_SCHEMA_VERSION",
    "GRAPHRAG_TWO_STAGE_GATE_DECISION_SCHEMA_VERSION",
    "GraphRAGTwoStageGateError",
    "assess_graphrag_two_stage_gate",
)
