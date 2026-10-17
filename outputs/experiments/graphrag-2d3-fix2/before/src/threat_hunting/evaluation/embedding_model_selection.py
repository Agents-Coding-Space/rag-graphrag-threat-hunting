"""Deterministic in-memory policy recommendations from validated reports.

Published relevance aggregates, rather than cross-model cosine scores, drive
every decision. Recommendations always require human review and never promote
a production model. The caller owns report loading and any later action.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math
from typing import Any

from .embedding_model_selection_schema import (
    EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION,
    EmbeddingModelSelectionError,
    canonical_json,
    validated_inputs,
    validate_embedding_model_selection,
)


_METRIC_FIELDS = {
    "ndcg": "mean_ndcg_at_k",
    "mrr": "mrr_at_k",
    "recall": "macro_recall_at_k",
    "hit_rate": "hit_rate_at_k",
}
_WARNINGS = sorted([
    "Results are based only on the supplied comparison report.",
    "This is not a general benchmark for the entire system.",
    "Raw cosine scores cannot be compared directly between embedding models.",
    "A recommendation does not automatically change the production embedding model.",
    "Slices with no relevance-support cases have undefined relevance metrics and are excluded from quality conditions.",
])


def _scope(group_by: str, key: dict[str, str]) -> dict[str, Any]:
    return {"group_by": group_by, "key": deepcopy(key)}


def _number(value: object, path: str) -> int | float:
    if type(value) not in (int, float):
        raise EmbeddingModelSelectionError(f"{path} requires a numeric relevance metric")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise EmbeddingModelSelectionError(f"{path} requires a finite relevance metric in [0, 1]")
    return value


def _metric(row: dict[str, Any], metric: str, cutoff: int) -> int | float:
    field = _METRIC_FIELDS[metric]
    for values in row["metrics"]:
        if values["cutoff"] == cutoff:
            if field not in values:
                break
            return _number(values[field], f"$.aggregates.{row['candidate_id']}.{row['group_by']}.{field}@{cutoff}")
    raise EmbeddingModelSelectionError(f"$.aggregates is missing {metric!r} at cutoff {cutoff}")


def _indexes(report: dict[str, Any]) -> tuple[dict[tuple[Any, ...], Any], dict[tuple[Any, ...], Any]]:
    aggregates = {
        (row["candidate_id"], row["group_by"], canonical_json(row["key"])): row
        for row in report["aggregates"]
    }
    comparisons = {
        (comparison["candidate_id"], delta["group_by"], canonical_json(delta["key"])): delta
        for comparison in report["comparisons"] for delta in comparison["deltas"]
    }
    return aggregates, comparisons


def _delta(
    aggregates: dict[tuple[Any, ...], Any], comparisons: dict[tuple[Any, ...], Any],
    baseline: str, candidate: str, group_by: str, key: dict[str, str],
    metric: str, cutoff: int,
) -> dict[str, Any]:
    group = (group_by, canonical_json(key))
    try:
        base = _metric(aggregates[(baseline, *group)], metric, cutoff)
        other = _metric(aggregates[(candidate, *group)], metric, cutoff)
        published = comparisons[(candidate, *group)]
    except KeyError as exc:
        raise EmbeddingModelSelectionError(
            f"$.aggregates/comparisons is missing required breakdown {group_by!r} {key!r}"
        ) from exc
    difference = round(other - base, 12)
    field = _METRIC_FIELDS[metric]
    reported = next((row[field] for row in published["metrics"] if row["cutoff"] == cutoff and field in row), None)
    if type(reported) not in (int, float) or not math.isfinite(reported) or reported != difference:
        raise EmbeddingModelSelectionError(
            f"$.comparisons delta differs from recomputed {metric!r} at {cutoff} for {key!r}"
        )
    return {"metric": metric, "cutoff": cutoff, "baseline": base, "candidate": other, "delta": difference}


def _condition(
    identifier: str, row: dict[str, Any], required: int | float,
    scope: dict[str, Any], *, positive: bool = False,
) -> dict[str, Any]:
    observed = row["delta"]
    return {
        "condition_id": identifier,
        "passed": observed > required if positive else observed >= required,
        "observed_value": observed, "required_value": required,
        "scope": deepcopy(scope), "metric": row["metric"], "cutoff": row["cutoff"],
    }


def _condition_key(condition: dict[str, Any]) -> tuple[Any, ...]:
    return (condition["condition_id"], canonical_json(condition["scope"]), condition["metric"], condition["cutoff"])


def _worst_regression(rows: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    negative = [(row, scope) for row, scope in rows if row["delta"] < 0]
    if not negative:
        return {"magnitude": 0.0, "delta": 0.0, "scope": None, "metric": None, "cutoff": None}
    row, scope = min(negative, key=lambda item: (
        item[0]["delta"], canonical_json(item[1]), item[0]["metric"], item[0]["cutoff"],
    ))
    return {
        "magnitude": -row["delta"], "delta": row["delta"],
        "scope": deepcopy(scope), "metric": row["metric"], "cutoff": row["cutoff"],
    }


def _assessment(
    baseline: str, candidate: str, policy: dict[str, Any],
    slices: list[dict[str, str]], aggregates: dict[tuple[Any, ...], Any],
    comparisons: dict[tuple[Any, ...], Any],
) -> dict[str, Any]:
    primary, validation = policy["primary_cutoff"], policy["validation_cutoff"]
    metric = policy["primary_metric"]
    required_metrics = policy["required_overall_metrics"]
    overall = [_delta(aggregates, comparisons, baseline, candidate, "candidate", {}, name, primary)
               for name in sorted(set(required_metrics) | {metric})]
    language = policy["priority_language"]
    priority = {"language": language, **_delta(
        aggregates, comparisons, baseline, candidate, "language", {"language": language}, metric, primary,
    )}
    secondary = [{"language": name, **_delta(
        aggregates, comparisons, baseline, candidate, "language", {"language": name}, metric, primary,
    )} for name in policy["secondary_languages"]]
    slice_deltas = [{**key, **_delta(
        aggregates, comparisons, baseline, candidate, "category_language", key, metric, primary,
    )} for key in slices]
    validation_delta = _delta(aggregates, comparisons, baseline, candidate, "candidate", {}, metric, validation)
    overall_scope = _scope("candidate", {})
    conditions = [_condition("overall_metric_regression", row, -policy["max_overall_regression"], overall_scope)
                  for row in overall if row["metric"] in required_metrics]
    conditions.append(_condition(
        "priority_language_gain", priority, policy["min_priority_language_delta"],
        _scope("language", {"language": language}),
    ))
    conditions.extend(_condition(
        "secondary_language_regression", row, -policy["max_secondary_language_regression"],
        _scope("language", {"language": row["language"]}),
    ) for row in secondary)
    conditions.extend(_condition(
        "slice_regression", row, -policy["max_slice_regression"],
        _scope("category_language", {"category": row["category"], "language": row["language"]}),
    ) for row in slice_deltas)
    if policy["require_positive_validation_delta"]:
        conditions.append(_condition("positive_validation_delta", validation_delta, 0, overall_scope, positive=True))
    reasons_by_condition = {
        "overall_metric_regression": "overall_metric_regression",
        "priority_language_gain": "priority_language_gain_below_minimum",
        "secondary_language_regression": "secondary_language_regression",
        "slice_regression": "slice_regression",
        "positive_validation_delta": "validation_delta_not_positive",
    }
    eligible = all(condition["passed"] for condition in conditions)
    reasons = {reasons_by_condition[condition["condition_id"]] for condition in conditions if not condition["passed"]}
    if eligible:
        reasons.add("eligible_candidate")
    worst_rows = [(row, overall_scope) for row in overall] + [(validation_delta, overall_scope)]
    worst_rows.append((priority, _scope("language", {"language": language})))
    worst_rows.extend((row, _scope("language", {"language": row["language"]})) for row in secondary)
    worst_rows.extend((row, _scope("category_language", {"category": row["category"], "language": row["language"]})) for row in slice_deltas)
    return {
        "candidate_id": candidate, "eligible": eligible, "overall_deltas": overall,
        "priority_language_delta": priority, "secondary_language_deltas": secondary,
        "slice_deltas": slice_deltas, "validation_delta": validation_delta,
        "worst_regression": _worst_regression(worst_rows),
        "conditions": sorted(conditions, key=_condition_key), "reason_codes": sorted(reasons),
    }


def _quality_rank(assessment: dict[str, Any], metric: str) -> tuple[float, float, float]:
    overall = next(row for row in assessment["overall_deltas"] if row["metric"] == metric)
    return (-assessment["priority_language_delta"]["delta"], -overall["delta"], -assessment["validation_delta"]["delta"])


def _complete_selection(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Build a selection from checked snapshots; also used for validator replay."""
    baseline = report["baseline_candidate_id"]
    aggregates, comparisons = _indexes(report)
    slices = sorted([
        deepcopy(row["key"]) for row in report["aggregates"]
        if row["candidate_id"] == baseline and row["group_by"] == "category_language"
        and row["relevance_case_count"] > 0
    ], key=lambda key: (key["category"], key["language"]))
    if not slices:
        raise EmbeddingModelSelectionError("$.aggregates requires relevance-support category/language slices")
    assessments = [_assessment(baseline, descriptor["candidate_id"], policy, slices, aggregates, comparisons)
                   for descriptor in report["candidates"] if descriptor["candidate_id"] != baseline]
    assessments.sort(key=lambda assessment: assessment["candidate_id"])
    eligible = sorted((row for row in assessments if row["eligible"]), key=lambda row: (
        *_quality_rank(row, policy["primary_metric"]), row["candidate_id"],
    ))
    reasons = {"human_review_required", "provisional_only_single_scenario"}
    reasons.update(code for row in assessments for code in row["reason_codes"])
    recommended = None
    if not eligible:
        decision = "retain_baseline"
        reasons.add("no_eligible_candidate")
    else:
        if len(eligible) > 1:
            reasons.add("multiple_eligible_candidates")
        tied = len(eligible) > 1 and _quality_rank(eligible[0], policy["primary_metric"]) == _quality_rank(eligible[1], policy["primary_metric"])
        if tied and policy["tie_break_policy"] == "human_review":
            decision = "needs_human_review"
        else:
            decision = "provisional_recommendation"
            recommended = eligible[0]["candidate_id"]
    metrics = sorted(set(policy["required_overall_metrics"]) | {policy["primary_metric"]})
    languages = sorted({policy["priority_language"], *policy["secondary_languages"], *(key["language"] for key in slices)})
    output = {
        "schema_version": EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION,
        "policy_id": policy["policy_id"], "baseline_candidate_id": baseline,
        "candidate_assessments": assessments, "decision": decision,
        "recommended_candidate_id": recommended, "reason_codes": sorted(reasons),
        "warnings": list(_WARNINGS),
        "review": {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None},
        "metadata": {
            "candidate_count": len(report["candidates"]), "eligible_candidate_count": len(eligible),
            "evaluated_cutoffs": sorted({policy["primary_cutoff"], policy["validation_cutoff"]}),
            "evaluated_metrics": metrics, "evaluated_languages": languages,
            "evaluated_slice_count": len(slices), "selection_method": "policy_based_deterministic_selection",
        },
    }
    identity = {"comparison_report": report, "policy": policy, "selection": output}
    output["evaluation_id"] = "embedding-model-selection-" + sha256(canonical_json(identity)).hexdigest()
    return json.loads(canonical_json(output))


def evaluate_embedding_model_candidates(comparison_report: object, *, policy: object) -> dict[str, Any]:
    """Recommend according to a strict policy without I/O or production action.

    Required breakdowns must exist and have finite relevance metrics. Published
    deltas use the comparison contract's 12-place precision and exact checks.
    ``tie_break_policy`` must explicitly choose ``candidate_id`` or
    ``human_review`` for equal quality ranks. There is no default. Inputs are
    detached before evaluation.
    """
    try:
        report, checked_policy = validated_inputs(comparison_report, policy)
        output = _complete_selection(report, checked_policy)
        validate_embedding_model_selection(output, comparison_report=report, policy=checked_policy)
        return output
    except EmbeddingModelSelectionError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError) as exc:
        raise EmbeddingModelSelectionError(f"$ cannot evaluate embedding model candidates: {exc}") from exc


__all__ = ("evaluate_embedding_model_candidates",)
