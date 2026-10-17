"""In-memory policy evaluation, confusion matrices and deterministic selection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..graphrag.relevance import assess_graphrag_relevance
from .calibration_config import (
    _canonical, _json_document, validate_relevance_policy,
    validate_selection_constraints,
)
from .relevance_dataset import validate_relevance_calibration_dataset


CATEGORIES = ("relevant_direct", "relevant_paraphrase", "insufficient_evidence", "unrelated")
LANGUAGES = ("en", "vi")
DECISIONS = ("proceed", "abstain")
METRIC_CONVENTIONS = {
    "positive_class": "proceed", "zero_denominator": 0.0,
    "score_interpretation": "bm25_cosine_rrf_not_probabilities",
    "dataset_use": "calibration_not_final_benchmark",
}
NO_ELIGIBLE_WARNING = "No candidate policy satisfies the configured selection constraints."


class RelevanceCalibrationError(ValueError):
    """Raised when calibration inputs cannot be evaluated without corruption."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RelevanceCalibrationError(message)


def _normalize_policies(value: object) -> list[dict[str, Any]]:
    policies = _json_document(value)
    _require(isinstance(policies, list) and bool(policies), "candidate_policies must be a nonempty list")
    ids: dict[str, bytes] = {}
    unique: dict[bytes, dict[str, Any]] = {}
    for policy in policies:
        validate_relevance_policy(policy)
        if policy["min_cosine_score"] is not None:
            policy["min_cosine_score"] = float(policy["min_cosine_score"])
            if policy["min_cosine_score"] == 0:
                policy["min_cosine_score"] = 0.0
        body = _canonical({key: item for key, item in policy.items() if key != "policy_id"})
        identifier = policy["policy_id"]
        _require(identifier not in ids or ids[identifier] == body, "conflicting duplicate policy_id")
        ids[identifier] = body
        if body not in unique or identifier < unique[body]["policy_id"]:
            unique[body] = policy
    return sorted(unique.values(), key=_canonical)


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Only evaluation labels/outcomes enter metrics; retrieval scores do not."""
    matrix = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for record in records:
        expected, actual = record["expected_decision"], record["actual_decision"]
        _require(expected in DECISIONS and actual in DECISIONS, "invalid expected or actual decision")
        field = "tp" if expected == actual == "proceed" else (
            "tn" if expected == actual == "abstain" else ("fp" if actual == "proceed" else "fn")
        )
        matrix[field] += 1
    tp, tn, fp, fn = (matrix[name] for name in ("tp", "tn", "fp", "fn"))
    total = len(records)

    def ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    recall, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    return {
        "case_count": total, "confusion_matrix": matrix,
        "metrics": {
            "accuracy": ratio(tp + tn, total), "precision": ratio(tp, tp + fp),
            "recall": recall, "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "specificity": specificity, "balanced_accuracy": (recall + specificity) / 2,
            "proceed_rate": ratio(tp + fp, total), "abstain_rate": ratio(tn + fn, total),
        },
    }


def _candidate_result(policy: dict[str, Any], records: list[dict[str, Any]], constraints: dict[str, Any]) -> dict[str, Any]:
    summary = _summary(records)
    breakdown = {
        name: {group: _summary([record for record in records if record[name] == group]) for group in groups}
        for name, groups in (("category", CATEGORIES), ("language", LANGUAGES), ("expected_decision", DECISIONS))
    }
    reasons = []
    for category, constraint in (
        ("unrelated", "max_false_proceed_unrelated"),
        ("insufficient_evidence", "max_false_proceed_insufficient_evidence"),
    ):
        if breakdown["category"][category]["confusion_matrix"]["fp"] > constraints[constraint]:
            reasons.append("false_proceed_" + category + "_above_limit")
    for metric in ("recall", "f1"):
        if summary["metrics"][metric] < constraints["min_" + metric]:
            reasons.append(metric + "_below_minimum")
    return {
        "policy": policy, "eligible": not reasons, "ineligibility_reasons": sorted(reasons),
        "confusion_matrix": summary["confusion_matrix"], "metrics": summary["metrics"],
        "breakdown": breakdown,
        "false_positive_case_ids": sorted(record["case_id"] for record in records if record["expected_decision"] == "abstain" and record["actual_decision"] == "proceed"),
        "false_negative_case_ids": sorted(record["case_id"] for record in records if record["expected_decision"] == "proceed" and record["actual_decision"] == "abstain"),
    }


def _select(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    eligible = [result for result in results if result["eligible"]]
    if not eligible:
        return None
    return min(eligible, key=lambda result: (
        -result["metrics"]["f1"], -result["metrics"]["recall"],
        -result["metrics"]["specificity"], -result["metrics"]["balanced_accuracy"],
        result["policy"]["policy_id"],
    ))


def calibrate_relevance_policies(
    dataset: Mapping[str, object], contexts_by_case_id: Mapping[str, object],
    *, candidate_policies: object, selection_constraints: Mapping[str, object],
) -> dict[str, Any]:
    """Assess each reused context with every unique policy, then select deterministically.

    This function constructs no context and performs no IO or embedding. Case
    identity, exact query text, scenario and shared artifact provenance must agree
    before evaluation. Every per-policy outcome is retained even if selection
    fails; configured constraints are never relaxed to force a selected policy.
    """
    try:
        source = _json_document(dataset)
        validate_relevance_calibration_dataset(source)
        contexts = _json_document(contexts_by_case_id)
        _require(isinstance(contexts, dict), "contexts_by_case_id must be an object")
        cases = sorted(source["cases"], key=lambda item: item["case_id"])
        _require(set(contexts) == {case["case_id"] for case in cases}, "context case IDs must match dataset exactly")
        policies = _normalize_policies(candidate_policies)
        constraints = _json_document(selection_constraints)
        validate_selection_constraints(constraints)
        provenance = None
        for case in cases:
            context = contexts[case["case_id"]]
            _require(isinstance(context, dict), "context must be an object")
            _require(context.get("scenario_id") == source["scenario_id"], "context scenario_id differs from dataset")
            _require(isinstance(context.get("query"), dict) and context["query"].get("text") == case["query"], "context query text differs from dataset case")
            linked = {name: context.get(name) for name in ("corpus_id", "graph_id", "source_ground_truth")}
            serialized = _canonical(linked)
            _require(provenance is None or provenance == serialized, "contexts refer to different artifacts or Ground Truth")
            provenance = serialized
        candidate_results, outcomes_by_case = [], {case["case_id"]: [] for case in cases}
        observed = {}
        for policy in policies:
            records = []
            for case in cases:
                identifier = case["case_id"]
                decision = assess_graphrag_relevance(contexts[identifier], policy=policy)
                _require(decision["decision"] in DECISIONS, "gate returned an unsupported decision")
                invariant = {"signals": decision["signals"], "warnings": decision["warnings"]}
                _require(identifier not in observed or _canonical(observed[identifier]) == _canonical(invariant), "gate signals or warnings differ by policy")
                observed[identifier] = invariant
                outcome = {"policy_id": policy["policy_id"], "actual_decision": decision["decision"], "reason_codes": decision["reason_codes"]}
                outcomes_by_case[identifier].append(outcome)
                records.append({**case, "actual_decision": decision["decision"]})
            candidate_results.append(_candidate_result(policy, records, constraints))
        selected = _select(candidate_results)
        selected_id = selected["policy"]["policy_id"] if selected is not None else None
        case_results = []
        for case in cases:
            identifier = case["case_id"]
            outcomes = outcomes_by_case[identifier]
            chosen = next((outcome for outcome in outcomes if outcome["policy_id"] == selected_id), None)
            case_results.append({
                "case_id": identifier, "category": case["category"], "language": case["language"],
                "expected_decision": case["expected_decision"],
                "actual_decision": chosen["actual_decision"] if chosen is not None else None,
                "reason_codes": chosen["reason_codes"] if chosen is not None else [],
                **observed[identifier], "policy_results": outcomes,
            })
        warnings = {warning for item in observed.values() for warning in item["warnings"]}
        if selected is None:
            warnings.add(NO_ELIGIBLE_WARNING)
        result = {
            "candidate_count": len(policies), "case_count": len(cases),
            "selection_status": "selected" if selected is not None else "no_eligible_policy",
            "selection_constraints": constraints, "candidate_results": candidate_results,
            "selected_policy": selected["policy"] if selected is not None else None,
            "selected_policy_metrics": selected["metrics"] if selected is not None else None,
            "cases": case_results, "warnings": sorted(warnings), "metric_conventions": METRIC_CONVENTIONS,
        }
        return _json_document(result)
    except RelevanceCalibrationError:
        raise
    except Exception as exc:
        raise RelevanceCalibrationError(f"Invalid relevance calibration: {exc}") from exc


__all__ = ("RelevanceCalibrationError", "calibrate_relevance_policies")
