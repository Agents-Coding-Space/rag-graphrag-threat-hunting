"""Deterministic diagnostics and independent replay of compact policy outcomes.

This module consumes validated calibration data only. It never constructs a
context, runs the gate, accesses files, or creates an embedding backend.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import math
import re
from statistics import median
from typing import Any

from .calibration_config import _canonical, _json_document
from .calibration_schema import SIGNAL_COUNTS, validate_calibration_report
from .diagnostics_schema import (
    GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION,
    RelevanceDiagnosticsError, validate_relevance_diagnostics,
)
from .relevance_calibration import DECISIONS, _summary
from .relevance_dataset import validate_relevance_calibration_dataset


PRECISION = 6
COUNT_CONDITIONS = (
    ("min_hits", "retrieval_hit_count", "insufficient_hits"),
    ("min_mapped_hits", "mapped_hit_count", "insufficient_mapped_hits"),
    ("min_seed_nodes", "seed_node_count", "insufficient_seeds"),
    ("min_traversal_nodes", "traversal_node_count", "insufficient_traversal_nodes"),
)
BOOLEAN_CONDITIONS = (
    ("require_traversal", "traversal_performed", "traversal_required"),
    ("require_lexical_support", "lexical_hit_count", "missing_lexical_support"),
    ("require_joint_lexical_vector_support", "joint_lexical_vector_hit_count", "missing_joint_lexical_vector_support"),
)
VISIBLE_SIGNALS = (
    "retrieval_hit_count", "mapped_hit_count", "seed_node_count",
    "traversal_node_count", "traversal_performed", "lexical_support",
    "joint_lexical_vector_support", "top_cosine_score",
)
LIMITATIONS = (
    "Historical per-policy signal snapshots were not retained; diagnostics cannot independently prove historical signal invariance.",
    "Stored decisions and ordered reason codes are independently replayed from each canonical case snapshot and its policies.",
    "BM25, cosine and RRF scores are not probabilities.",
    "Diagnostics describe this calibration dataset and current lower-bound conjunction policy family; no production policy is selected.",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RelevanceDiagnosticsError(message)


def _replay(signals: dict[str, Any], policy: dict[str, Any]) -> tuple[str, list[str]]:
    """Replay the existing gate's conjunction using signals, not a context."""
    reasons = [reason for setting, observed, reason in COUNT_CONDITIONS
               if signals[observed] < policy[setting]]
    reasons.extend(reason for setting, observed, reason in BOOLEAN_CONDITIONS
                   if policy[setting] and not signals[observed])
    threshold, score = policy["min_cosine_score"], signals["top_cosine_score"]
    if threshold is not None and (score is None or score < threshold):
        reasons.append("vector_score_below_threshold")
    return ("abstain" if reasons else "proceed"), sorted(reasons)


def _expanded(signals: dict[str, Any]) -> dict[str, Any]:
    return {**signals, "lexical_support": signals["lexical_hit_count"] > 0,
            "joint_lexical_vector_support": signals["joint_lexical_vector_hit_count"] > 0}


def _profile(case: dict[str, Any]) -> dict[str, Any]:
    expanded = _expanded(case["signals"])
    score = expanded["top_cosine_score"]
    if score is not None:
        # The gate compares numeric values: integer/float and signed-zero
        # representations must not split otherwise identical profiles.
        expanded["top_cosine_score"] = float(score) if score != 0 else 0.0
    return {name: expanded[name] for name in VISIBLE_SIGNALS}


def _round(value: float | int) -> float:
    _require(math.isfinite(value), "$ statistics must be finite")
    result = round(float(value), PRECISION)
    return 0.0 if result == 0 else result


def _definitions() -> dict[str, dict[str, Any]]:
    result = {}
    for name in sorted((*SIGNAL_COUNTS, "top_cosine_score", "traversal_performed",
                        "lexical_support", "joint_lexical_vector_support")):
        kind = "boolean" if name in ("traversal_performed", "lexical_support", "joint_lexical_vector_support") else "numeric"
        if name == "top_cosine_score":
            semantics = "Maximum returned vector cosine; null fails an enabled cosine minimum and passes a disabled minimum."
        elif name in ("lexical_support", "joint_lexical_vector_support"):
            semantics = "Positive corresponding hit count; the policy tests presence, not magnitude."
        elif name == "traversal_performed":
            semantics = "False fails an enabled traversal requirement."
        elif name in VISIBLE_SIGNALS:
            semantics = "Nonnegative count compared against an inclusive policy lower bound."
        else:
            semantics = "Descriptive gate signal; not an independent policy threshold dimension."
        result[name] = {"kind": kind, "policy_visible": name in VISIBLE_SIGNALS, "semantics": semantics}
    return result


def _statistics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    snapshots = [_expanded(case["signals"]) for case in cases]
    result = {}
    for name, definition in _definitions().items():
        values = [snapshot[name] for snapshot in snapshots]
        if definition["kind"] == "boolean":
            true = sum(values)
            result[name] = {"count": len(values), "true_count": true,
                            "false_count": len(values) - true,
                            "true_rate": _round(true / len(values)) if values else 0.0}
        else:
            present = [value for value in values if value is not None]
            result[name] = {
                "count": len(present), "null_count": len(values) - len(present),
                "minimum": _round(min(present)) if present else None,
                "maximum": _round(max(present)) if present else None,
                "mean": _round(sum(present) / len(present)) if present else None,
                "median": _round(median(present)) if present else None,
            }
    return result


def _range(values: list[Any]) -> dict[str, Any]:
    present = [value for value in values if value is not None]
    return {"count": len(present), "null_count": len(values) - len(present),
            "minimum": _round(min(present)) if present else None,
            "maximum": _round(max(present)) if present else None}


def _overlap(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for name, definition in _definitions().items():
        if definition["kind"] != "numeric":
            continue
        groups = {decision: [_expanded(case["signals"])[name] for case in cases
                             if case["expected_decision"] == decision]
                  for decision in ("proceed", "abstain")}
        left = [value for value in groups["proceed"] if value is not None]
        right = [value for value in groups["abstain"] if value is not None]
        overlaps = bool(left and right and max(min(left), min(right)) <= min(max(left), max(right)))
        result.append({"signal": name, "proceed_range": _range(groups["proceed"]),
                       "abstain_range": _range(groups["abstain"]), "overlap": overlaps})
    return result


def _boolean_overlap(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for name, definition in _definitions().items():
        if definition["kind"] != "boolean":
            continue
        groups = {decision: [_expanded(case["signals"])[name] for case in cases
                             if case["expected_decision"] == decision]
                  for decision in DECISIONS}
        ranges = {}
        for decision, values in groups.items():
            ranges[decision] = {"count": len(values), "true_count": sum(values),
                                "false_count": len(values) - sum(values),
                                "minimum": min(values) if values else None,
                                "maximum": max(values) if values else None}
        shared = sorted(set(groups["proceed"]) & set(groups["abstain"]))
        result.append({"signal": name, "proceed_range": ranges["proceed"],
                       "abstain_range": ranges["abstain"],
                       "shared_values": shared, "overlap": bool(shared)})
    return result


def _collisions(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[bytes, list[dict[str, Any]]] = {}
    for case in cases:
        groups.setdefault(_canonical(_profile(case)), []).append(case)
    result = []
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda case: case["case_id"])
        if len({case["expected_decision"] for case in group}) < 2:
            continue
        result.append({"profile": _profile(group[0]),
                       "case_ids": [case["case_id"] for case in group],
                       "proceed_case_ids": [case["case_id"] for case in group if case["expected_decision"] == "proceed"],
                       "abstain_case_ids": [case["case_id"] for case in group if case["expected_decision"] == "abstain"]})
    return result


def _dominance(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Null cosine is bottom: every enabled minimum rejects it, including -1."""
    conflicts = []
    for proceed in cases:
        if proceed["expected_decision"] != "proceed":
            continue
        left = _profile(proceed)
        for abstain in cases:
            if abstain["expected_decision"] != "abstain":
                continue
            right = _profile(abstain)
            stronger, dominates = [], True
            for name in VISIBLE_SIGNALS:
                p, a = left[name], right[name]
                if p is not None and (a is None or a < p):
                    dominates = False
                    break
                if (p is None and a is not None) or (p is not None and a > p):
                    stronger.append(name)
            if dominates and stronger:
                conflicts.append({
                    "proceed_case_id": proceed["case_id"], "abstain_case_id": abstain["case_id"],
                    "proceed_category": proceed["category"], "abstain_category": abstain["category"],
                    "proceed_language": proceed["language"], "abstain_language": abstain["language"],
                    "proceed_signals": left, "abstain_signals": right,
                    "strictly_stronger_signals": sorted(stronger),
                })
    conflicts.sort(key=lambda item: (item["proceed_case_id"], item["abstain_case_id"]))
    summaries = {}
    for field in ("category", "language"):
        counts = Counter((item["proceed_" + field], item["abstain_" + field]) for item in conflicts)
        summaries["by_" + field] = [
            {"proceed_" + field: left, "abstain_" + field: right, "count": count}
            for (left, right), count in sorted(counts.items())]
    return {"compared_signals": list(VISIBLE_SIGNALS), "conflicts": conflicts, **summaries}


def _policy_analysis(cases: list[dict[str, Any]], policies: list[dict[str, Any]],
                     constraints: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    categories = sorted({case["category"] for case in cases})
    limits = {name: name.removeprefix("max_false_proceed_") for name in constraints
              if name.startswith("max_false_proceed_")}
    constraints_count = {name: {"passed": 0, "failed": 0} for name in sorted(constraints)
                         if name != "tie_break_order"}
    results, objectives = [], []
    for policy in policies:
        records = [{**case, "actual_decision": _replay(case["signals"], policy)[0]} for case in cases]
        summary = _summary(records)
        false_proceeds = {category: sum(record["category"] == category and record["expected_decision"] == "abstain"
                                         and record["actual_decision"] == "proceed" for record in records)
                          for category in categories}
        failed = []
        for name, counts in constraints_count.items():
            passes = (false_proceeds.get(limits[name], 0) <= constraints[name]) if name in limits else (
                summary["metrics"][name.removeprefix("min_")] >= constraints[name])
            counts["passed" if passes else "failed"] += 1
            if not passes:
                failed.append(name)
        result = {
            "policy_id": policy["policy_id"], "eligible": not failed,
            "failed_constraints": sorted(failed), "confusion_matrix": summary["confusion_matrix"],
            "metrics": {name: _round(value) for name, value in summary["metrics"].items()},
            "false_proceeds_by_category": false_proceeds,
            "false_positive_case_ids": sorted(record["case_id"] for record in records
                                              if record["expected_decision"] == "abstain" and record["actual_decision"] == "proceed"),
            "false_negative_case_ids": sorted(record["case_id"] for record in records
                                              if record["expected_decision"] == "proceed" and record["actual_decision"] == "abstain"),
        }
        results.append(result)
        objective = {"false_proceed_" + category: false_proceeds.get(category, 0)
                     for category in sorted(set(limits.values()))}
        objective.update({metric: summary["metrics"][metric]
                          for metric in ("recall", "f1", "specificity", "balanced_accuracy")})
        objectives.append((policy["policy_id"], objective))
    eligible = sum(result["eligible"] for result in results)
    summary = {
        "selection_status": "selected" if eligible else "no_eligible_policy",
        "eligible_policy_count": eligible, "constraint_counts": constraints_count,
        "highest_metrics": {metric: max(result["metrics"][metric] for result in results)
                            for metric in ("f1", "recall", "accuracy", "specificity", "balanced_accuracy")},
        "distinct_confusion_matrix_count": len({_canonical(result["confusion_matrix"]) for result in results}),
        "candidate_results": results,
    }
    # Group using full precision, then compare every distinct objective vector.
    groups: dict[bytes, list[tuple[str, dict[str, Any]]]] = {}
    for item in objectives:
        groups.setdefault(_canonical(item[1]), []).append(item)
    unique = [sorted(group) for _, group in sorted(groups.items())]
    frontier = []
    for group in unique:
        identifier, current = group[0]
        dominated = False
        for other_group in unique:
            other = other_group[0][1]
            comparisons = [(other[name] <= value if name.startswith("false_proceed_") else other[name] >= value)
                           for name, value in current.items()]
            if all(comparisons) and any(other[name] != value for name, value in current.items()):
                dominated = True
                break
        if not dominated:
            frontier.append({"representative_policy_id": identifier,
                             "equivalent_policy_ids": [item[0] for item in group],
                             "metrics": {name: value if name.startswith("false_proceed_") else _round(value)
                                         for name, value in current.items()}})
    frontier.sort(key=lambda item: tuple(-item["metrics"][metric] for metric in
                                        ("f1", "recall", "specificity", "balanced_accuracy"))
                  + tuple(item["metrics"][name] for name in sorted(item["metrics"]) if name.startswith("false_proceed_"))
                  + (item["representative_policy_id"],))
    return summary, frontier


def _findings(cases: list[dict[str, Any]], analysis: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []

    def add(code: str, explanation: str, *, case_ids: list[str] | None = None,
            statistics: Any = None, policy_ids: list[str] | None = None) -> None:
        findings.append({"code": code, "severity": "technical_limitation",
                         "evidence": {"case_ids": sorted(set(case_ids or [])),
                                      "policy_ids": sorted(set(policy_ids or [])), "statistics": statistics},
                         "explanation": explanation, "status": "needs_review"})

    constant_counts = {name: cases[0]["signals"][name] for name in SIGNAL_COUNTS
                       if len({case["signals"][name] for case in cases}) == 1}
    if constant_counts:
        add("count_signals_have_low_variance", "Constant count signals cannot separate the observed labels on their own.",
            case_ids=[case["case_id"] for case in cases], statistics={"constant_signals": constant_counts})
    overlaps = [item["signal"] for item in analysis["numeric_ranges"] if item["overlap"]]
    if overlaps:
        add("numeric_ranges_overlap", "Expected proceed and abstain numeric ranges overlap; scores are not probabilities.",
            statistics={"signals": overlaps})
    if analysis["collisions"]:
        add("cross_label_signal_profile_collision", "Identical policy-visible profiles carry different expected decisions.",
            case_ids=[identifier for item in analysis["collisions"] for identifier in item["case_ids"]],
            statistics={"profile_count": len(analysis["collisions"])})
    conflicts = analysis["dominance"]["conflicts"]
    if conflicts:
        add("abstain_case_dominates_proceed_case", "An abstain profile dominates a proceed profile; an accepting lower-bound conjunction also accepts that abstain profile.",
            case_ids=[identifier for item in conflicts for identifier in (item["proceed_case_id"], item["abstain_case_id"])],
            statistics={"conflict_count": len(conflicts)})
    # Compare language support inside each expected label, avoiding a pooled
    # language claim caused solely by a different label mix.
    gaps = []
    for decision in sorted({case["expected_decision"] for case in cases}):
        subgroup = [case for case in cases if case["expected_decision"] == decision]
        languages = sorted({case["language"] for case in subgroup})
        supports = {language: _statistics([case for case in subgroup if case["language"] == language])
                    for language in languages}
        for name, statistic in (("lexical_support", "true_rate"), ("joint_lexical_vector_support", "true_rate"),
                                ("top_cosine_score", "mean")):
            values = {language: supports[language][name][statistic] for language in languages}
            finite = [value for value in values.values() if value is not None]
            if len(finite) >= 2 and max(finite) > min(finite):
                gaps.append({"expected_decision": decision, "signal": name, "statistic": statistic, "by_language": values})
    if gaps:
        add("language_support_gap", "Observed lexical or vector support differs by language within the same expected label; this descriptive difference does not establish its cause.",
            statistics={"gaps": gaps})
    if analysis["collisions"] or conflicts:
        add("current_policy_family_not_separable", "Cross-label equal or dominated profiles prevent perfect label separation by the current monotonic conjunction family; this does not prove that all selection constraints are universally infeasible.",
            statistics={"collision_count": len(analysis["collisions"]), "dominance_conflict_count": len(conflicts),
                        "observed_eligible_policy_count": analysis["policy_failures"]["eligible_policy_count"]})
    return sorted(findings, key=lambda finding: finding["code"])


def _derive_diagnostics(cases: list[dict[str, Any]], policies: list[dict[str, Any]],
                        constraints: dict[str, Any]) -> dict[str, Any]:
    distributions, statistics = {}, {}
    for field in ("expected_decision", "category", "language"):
        groups = sorted(DECISIONS if field == "expected_decision" else {case[field] for case in cases})
        distributions[field] = {group: sum(case[field] == group for case in cases) for group in groups}
        statistics["by_" + field] = {group: _statistics([case for case in cases if case[field] == group]) for group in groups}
    failures, frontier = _policy_analysis(cases, policies, constraints)
    analysis = {"distributions": distributions, "signal_definitions": _definitions(),
                "statistics": statistics, "numeric_ranges": _overlap(cases),
                "boolean_overlap": _boolean_overlap(cases),
                "collisions": _collisions(cases), "dominance": _dominance(cases),
                "policy_failures": failures, "trade_off_frontier": frontier}
    analysis["findings"] = _findings(cases, analysis)
    return analysis


def _metadata(cases: list[dict[str, Any]], policies: list[dict[str, Any]], analysis: dict[str, Any]) -> dict[str, int]:
    return {"case_count": len(cases), "policy_count": len(policies),
            "replayed_outcome_count": len(cases) * len(policies),
            "collision_count": len(analysis["collisions"]),
            "dominance_conflict_count": len(analysis["dominance"]["conflicts"]),
            "frontier_count": len(analysis["trade_off_frontier"]),
            "finding_count": len(analysis["findings"]), "numeric_precision": PRECISION}


def _warnings(cases: list[dict[str, Any]]) -> list[str]:
    return sorted(set(LIMITATIONS) | {warning for case in cases for warning in case["warnings"]})


def analyze_relevance_separability(
    calibration_dataset: object, calibration_report: object, *,
    dataset_path: str, dataset_sha256: str, report_path: str, report_sha256: str,
) -> dict[str, Any]:
    """Audit every stored outcome, then derive detached diagnostics in memory."""
    try:
        for name, value in (("dataset_path", dataset_path), ("report_path", report_path)):
            _require(isinstance(value, str) and bool(value.strip()), f"$.{name} must be nonempty text")
        for name, value in (("dataset_sha256", dataset_sha256), ("report_sha256", report_sha256)):
            _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                     f"$.{name} must be a lowercase full SHA-256")
        dataset, report = _json_document(calibration_dataset), _json_document(calibration_report)
        validate_relevance_calibration_dataset(dataset)
        validate_calibration_report(report)
        provenance = report["provenance"]["dataset"]
        _require(dataset["scenario_id"] == provenance["scenario_id"], "$.scenario_id dataset/report mismatch")
        _require(dataset["dataset_id"] == provenance["dataset_id"], "$.dataset_id dataset/report mismatch")
        _require(dataset_sha256 == provenance["sha256"], "$.provenance.dataset.sha256 mismatch")
        expected = {case["case_id"]: case for case in dataset["cases"]}
        observed = report["calibration"]["cases"]
        _require(set(expected) == {case["case_id"] for case in observed}, "$.calibration.cases missing or extra case IDs")
        policies = sorted((item["policy"] for item in report["calibration"]["candidate_results"]), key=lambda item: item["policy_id"])
        by_policy = {policy["policy_id"]: policy for policy in policies}
        cases = []
        for case in observed:
            where = f"$.calibration.cases[{case['case_id']}]"
            for name in ("category", "language", "expected_decision"):
                _require(case[name] == expected[case["case_id"]][name], f"{where}.{name} dataset/report mismatch")
            seen = set()
            for outcome in case["policy_results"]:
                identifier = outcome["policy_id"]
                _require(identifier in by_policy and identifier not in seen, f"{where}.policy_results unknown or duplicate policy")
                seen.add(identifier)
                decision, reasons = _replay(case["signals"], by_policy[identifier])
                _require(outcome["actual_decision"] == decision, f"{where}.policy_results[{identifier}].actual_decision replay mismatch")
                _require(outcome["reason_codes"] == reasons, f"{where}.policy_results[{identifier}].reason_codes replay mismatch; expected canonical sorted reasons")
            _require(seen == set(by_policy), f"{where}.policy_results missing policies")
            cases.append({name: case[name] for name in ("case_id", "category", "language", "expected_decision", "signals", "warnings")})
        cases.sort(key=lambda item: item["case_id"])
        constraints = report["calibration"]["selection_constraints"]
        analysis = _derive_diagnostics(cases, policies, constraints)
        _require(analysis["policy_failures"]["selection_status"] == report["calibration"]["selection_status"], "$.calibration.selection_status replay mismatch")
        result = {
            "schema_version": GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION,
            "scenario_id": dataset["scenario_id"],
            "provenance": {
                "dataset": {"path": str(dataset_path), "sha256": dataset_sha256,
                            "schema_version": dataset["schema_version"], "dataset_id": dataset["dataset_id"]},
                "calibration_report": {"path": str(report_path), "sha256": report_sha256,
                                       "schema_version": report["schema_version"], "calibration_id": report["calibration_id"]},
            },
            "audit": {"signal_snapshot_scope": "per_case",
                      "signal_snapshot_source": "calibration_report.case.signals",
                      "historical_invariance_assurance": "validated_by_upstream_calibration_engine",
                      "diagnostic_verification": "policy_outcome_replay_from_canonical_case_signals",
                      "replayed_outcome_count": len(cases) * len(policies)},
            "cases": cases, "policies": policies, "selection_constraints": constraints,
            "analysis": analysis, "warnings": _warnings(cases),
            "metadata": _metadata(cases, policies, analysis),
            "review": {"status": "pending_human_review", "reviewer": None, "reviewed_at": None},
        }
        result["analysis_id"] = "relevance-diagnostics-" + sha256(_canonical(result)).hexdigest()
        validate_relevance_diagnostics(result)
        return result
    except RelevanceDiagnosticsError:
        raise
    except Exception as exc:
        raise RelevanceDiagnosticsError(f"Invalid relevance diagnostics input at $: {exc}") from exc


__all__ = ("analyze_relevance_separability",)
