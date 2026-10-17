"""Pure, label-isolated calibration and replay for the two-stage context gate.

Dataset answerability, external adjudication of the returned context, and the
gate's own answerability prediction are separate observations. Expected labels,
answers and evidence never supply gate input. This module performs no retrieval,
model calls, file reads or artifact writes; callers supply already observed
signals and explicitly identify every case's split and usage history.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
import json
import re
from typing import Any

from threat_hunting.graphrag import (
    assess_graphrag_two_stage_gate,
    validate_graphrag_gate_signals,
)
from threat_hunting.graphrag.two_stage_gate import _validated_policy


SPLIT_SCHEMA_VERSION = "two-stage-gate-evaluation-split/v1"
FREEZE_SCHEMA_VERSION = "two-stage-gate-evaluation-freeze/v1"
SELECTION_RULE = (
    "Minimize false proceed on unrelated plus insufficient_evidence; then "
    "maximize retained context-sufficient positives; then minimize enabled "
    "conditions; then policy_id. All-abstain candidates cannot be selected."
)
_PARTITIONS = ("calibration", "heldout")
_RECORD_FIELDS = {
    "case_id", "signals", "expected_decision", "category", "topical_relevant",
    "context_sufficient", "dataset_answerable", "context_sufficiency_basis",
    "expected_evidence_ids", "returned_evidence_ids", "missing_evidence_diagnostics",
}


class TwoStageCalibrationError(ValueError):
    """An evaluation contract, split, or replay binding is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TwoStageCalibrationError(message)


def _text(value: object, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be nonempty text")
    return value  # type: ignore[return-value]


def _digest(value: object, path: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{path} must be a lowercase SHA-256 digest")
    return value  # type: ignore[return-value]


def _snapshot(value: Any) -> Any:
    """Detach JSON data, rejecting non-finite numbers and non-JSON containers."""
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise TwoStageCalibrationError(f"Evaluation data must be finite JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash detached JSON with stable object ordering; array order is meaningful."""
    snapshot = _snapshot(value)
    payload = json.dumps(snapshot, ensure_ascii=False, allow_nan=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return sha256(payload).hexdigest()


def ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    """Expose the denominator, using null for an undefined fraction."""
    _require(type(numerator) is int and numerator >= 0, "numerator must be a nonnegative integer")
    _require(type(denominator) is int and denominator >= 0,
             "denominator must be a nonnegative integer")
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def build_split_manifest(
    cases: Sequence[Mapping[str, object]], *, dataset_id: str, dataset_sha256: str,
    assignments: Mapping[str, str], usage_history: Mapping[str, Sequence[str]],
    split_rationale: str = "Explicit group-disjoint split",
) -> dict[str, Any]:
    """Describe a split without retaining questions, expected answers or labels.

    Every group must have an explicit history (an empty list means unused).
    Previously used groups cannot enter held-out. Grouping must be adjudicated
    by the caller from meaning/evidence, rather than inferred from case IDs.
    """
    _text(dataset_id, "dataset_id")
    _digest(dataset_sha256, "dataset_sha256")
    _text(split_rationale, "split_rationale")
    _require(isinstance(assignments, Mapping), "assignments must be an object")
    _require(isinstance(usage_history, Mapping), "usage_history must be an object")
    _require(isinstance(cases, (list, tuple)), "cases must be a list of descriptors")
    descriptors = []
    ids: set[str] = set()
    group_partitions: dict[str, str] = {}
    for case in cases:
        _require(isinstance(case, Mapping), "each case descriptor must be an object")
        case_id = _text(case.get("case_id"), "case.case_id")
        group_id = _text(case.get("group_id"), f"case {case_id}.group_id")
        label_source = _text(case.get("label_source"), f"case {case_id}.label_source")
        _require(case_id not in ids, f"Duplicate case_id {case_id}")
        ids.add(case_id)
        partition = assignments.get(case_id)
        _require(partition in _PARTITIONS, f"Missing or unsupported split for {case_id}")
        _require(group_id not in group_partitions or group_partitions[group_id] == partition,
                 f"Group {group_id} overlaps calibration and heldout")
        group_partitions[group_id] = partition  # type: ignore[assignment]
        descriptor = {"case_id": case_id, "group_id": group_id, "label_source": label_source}
        if "grouping_rationale" in case:
            descriptor["grouping_rationale"] = _text(
                case["grouping_rationale"], f"case {case_id}.grouping_rationale")
        descriptors.append(descriptor)
    _require(set(assignments) == ids, "assignments must contain exactly the declared case IDs")
    _require(set(usage_history) == set(group_partitions),
             "usage_history must explicitly cover exactly the declared groups")
    history: dict[str, list[str]] = {}
    for group_id, partition in sorted(group_partitions.items()):
        entries = usage_history[group_id]
        _require(isinstance(entries, (list, tuple)), f"usage_history.{group_id} must be a list")
        history[group_id] = [_text(item, f"usage_history.{group_id}") for item in entries]
        _require(partition != "heldout" or not entries,
                 f"Previously used group {group_id} cannot be independent heldout")
    return {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "dataset_id": dataset_id, "dataset_sha256": dataset_sha256,
        "split_rationale": split_rationale,
        "cases": sorted(descriptors, key=lambda item: item["case_id"]),
        "assignments": {case_id: assignments[case_id] for case_id in sorted(ids)},
        "usage_history": history,
    }


def validate_split_manifest(document: object) -> None:
    """Validate a persisted split with the same group and usage protections."""
    _require(isinstance(document, dict), "split_manifest must be a JSON object")
    root: dict[str, Any] = document  # type: ignore[assignment]
    _require(set(root) == {"schema_version", "dataset_id", "dataset_sha256", "split_rationale",
                           "cases", "assignments", "usage_history"}, "Unexpected split manifest fields")
    _require(root["schema_version"] == SPLIT_SCHEMA_VERSION, "Unsupported split schema")
    rebuilt = build_split_manifest(
        root["cases"], dataset_id=root["dataset_id"], dataset_sha256=root["dataset_sha256"],
        assignments=root["assignments"], usage_history=root["usage_history"],
        split_rationale=root["split_rationale"],
    )
    _require(canonical_sha256(rebuilt) == canonical_sha256(root),
             "Split manifest must have deterministic descriptors and no undeclared fields")


def _binding_hashes(
    policy: Mapping[str, object], *, retrieval_config: object, split_manifest: dict[str, Any],
    evaluation_code_sha256: str, criteria: object, calibration_signals: Mapping[str, object],
) -> dict[str, str]:
    validate_split_manifest(split_manifest)
    configured = _validated_policy(policy)
    _digest(evaluation_code_sha256, "evaluation_code_sha256")
    expected_ids = {case_id for case_id, partition in split_manifest["assignments"].items()
                    if partition == "calibration"}
    _require(isinstance(calibration_signals, Mapping) and set(calibration_signals) == expected_ids,
             "calibration_signals must contain exactly the calibration case IDs")
    for signals in calibration_signals.values():
        validate_graphrag_gate_signals(signals)
    return {
        "policy_sha256": canonical_sha256(configured),
        "retrieval_configuration_sha256": canonical_sha256(retrieval_config),
        "split_manifest_sha256": canonical_sha256(split_manifest),
        "evaluation_code_sha256": evaluation_code_sha256,
        "criteria_sha256": canonical_sha256(criteria),
        "calibration_signals_sha256": canonical_sha256(calibration_signals),
    }


def freeze_policy(
    policy: Mapping[str, object], *, retrieval_config: object, split_manifest: dict[str, Any],
    evaluation_code_sha256: str, criteria: object, calibration_signals: Mapping[str, object],
) -> dict[str, Any]:
    """Bind every pre-evaluation component; the lock hash is not a signature."""
    bindings = _binding_hashes(
        policy, retrieval_config=retrieval_config, split_manifest=split_manifest,
        evaluation_code_sha256=evaluation_code_sha256, criteria=criteria,
        calibration_signals=calibration_signals,
    )
    body = {"schema_version": FREEZE_SCHEMA_VERSION, "bindings": bindings}
    return {**body, "lock_sha256": canonical_sha256(body)}


def validate_freeze(
    freeze: object, policy: Mapping[str, object], *, retrieval_config: object,
    split_manifest: dict[str, Any], evaluation_code_sha256: str, criteria: object,
    calibration_signals: Mapping[str, object],
) -> None:
    """Fail closed if any current replay input differs from the frozen input."""
    expected = freeze_policy(
        policy, retrieval_config=retrieval_config, split_manifest=split_manifest,
        evaluation_code_sha256=evaluation_code_sha256, criteria=criteria,
        calibration_signals=calibration_signals,
    )
    _require(freeze == expected, "Frozen policy/configuration/split/code/criteria/signals integrity mismatch")


def _matrix(pairs: Sequence[tuple[bool, bool]]) -> dict[str, int]:
    return {
        "tp": sum(expected and actual for expected, actual in pairs),
        "tn": sum(not expected and not actual for expected, actual in pairs),
        "fp": sum(not expected and actual for expected, actual in pairs),
        "fn": sum(expected and not actual for expected, actual in pairs),
    }


def _matrix_metrics(matrix: Mapping[str, int]) -> dict[str, dict[str, int | float | None]]:
    tp, tn, fp, fn = (matrix[key] for key in ("tp", "tn", "fp", "fn"))
    return {
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp), "f1": ratio(2 * tp, 2 * tp + fp + fn),
    }


def _layer_summary(cases: Sequence[dict[str, Any]], stage: str, label: str) -> dict[str, Any]:
    pairs = [(case[label], case["gate_decision"]["stage_results"][stage]["status"] == "passed")
             for case in cases if case[label] is not None and
             case["gate_decision"]["stage_results"][stage]["status"] != "not_evaluated"]
    matrix = _matrix(pairs)
    not_evaluated = [case for case in cases if
                     case["gate_decision"]["stage_results"][stage]["status"] == "not_evaluated"]
    return {
        "case_count": len(cases),
        "known_label_count": sum(case[label] is not None for case in cases),
        "unknown_label_count": sum(case[label] is None for case in cases),
        "evaluated_known_label_count": len(pairs),
        "not_evaluated_count": len(not_evaluated),
        "known_label_not_evaluated_count": sum(case[label] is not None for case in not_evaluated),
        "confusion_matrix": matrix, "metrics": _matrix_metrics(matrix),
    }


def summarize_cases(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Report dataset labels and context eligibility separately, with denominators."""
    matrix = _matrix([(case["expected_decision"] == "proceed", case["actual_decision"] == "proceed")
                      for case in cases])
    proceed_count = sum(case["actual_decision"] == "proceed" for case in cases)
    category_rates = {}
    for category in ("unrelated", "insufficient_evidence"):
        members = [case for case in cases if case["category"] == category]
        category_rates[category] = ratio(
            sum(case["actual_decision"] == "proceed" for case in members), len(members))
    sufficient = [case for case in cases if case["expected_decision"] == "proceed"
                  and case["context_sufficient"] is True]
    context_pairs = []
    for case in cases:
        topical, sufficient_context = case["topical_relevant"], case["context_sufficient"]
        if topical is False or sufficient_context is False:
            context_pairs.append((False, case["actual_decision"] == "proceed"))
        elif topical is True and sufficient_context is True:
            context_pairs.append((True, case["actual_decision"] == "proceed"))
    context_matrix = _matrix(context_pairs)
    return {
        "case_count": len(cases), "positive_class": "proceed", "negative_class": "abstain",
        "dataset_label_confusion_matrix": matrix, "dataset_label_metrics": _matrix_metrics(matrix),
        "coverage": ratio(proceed_count, len(cases)),
        "selective_error": ratio(matrix["fp"], proceed_count),
        "selective_error_basis": "dataset_expected_decision",
        "context_eligibility_known_label_count": len(context_pairs),
        "context_eligibility_unknown_label_count": len(cases) - len(context_pairs),
        "context_eligibility_confusion_matrix": context_matrix,
        "context_eligibility_metrics": _matrix_metrics(context_matrix),
        "context_selective_error": ratio(context_matrix["fp"], context_matrix["tp"] + context_matrix["fp"]),
        "false_proceed_by_category": category_rates,
        "false_abstain_context_sufficient": ratio(
            sum(case["actual_decision"] == "abstain" for case in sufficient), len(sufficient)),
        "retained_context_sufficient_positives": sum(
            case["actual_decision"] == "proceed" for case in sufficient),
        "dataset_answerable_context_failure_count": sum(
            case["dataset_answerable"] is True and case["context_sufficient"] is False for case in cases),
        "unknown_context_sufficiency_count": sum(case["context_sufficient"] is None for case in cases),
        "layers": {
            "topical_relevance": _layer_summary(cases, "topical_relevance", "topical_relevant"),
            "evidence_answerability": _layer_summary(cases, "evidence_answerability", "context_sufficient"),
        },
        "all_abstain": proceed_count == 0,
    }


def evaluate_policy(
    records: Sequence[Mapping[str, Any]], *, policy: Mapping[str, object],
    split_manifest: dict[str, Any], partition: str = "calibration", freeze: object = None,
    labels_approved: bool = False, retrieval_config: object = None,
    evaluation_code_sha256: str | None = None, criteria: object = None,
    calibration_signals: Mapping[str, object] | None = None,
    replay: bool = False,
) -> dict[str, Any]:
    """Evaluate one partition, sending only strict returned-context signals to gate.

    Membership is checked for the whole input before any record labels are read.
    A held-out invocation requires explicit approved labels and all lock bindings.
    A dataset-label false abstain is not automatically a gate error: the returned
    context may be inadequate or its adequacy may remain unknown.
    """
    validate_split_manifest(split_manifest)
    _require(type(replay) is bool, "replay must be an explicit boolean")
    _require(not replay or freeze is not None, "Replay requires a frozen evaluation lock")
    _require(partition in _PARTITIONS, "Unsupported evaluation partition")
    expected_ids = {case_id for case_id, value in split_manifest["assignments"].items()
                    if value == partition}
    _require(isinstance(records, (list, tuple)) and all(isinstance(record, Mapping) for record in records),
             "records must be a list of evaluation objects")
    record_ids = [_text(record.get("case_id"), "record.case_id") for record in records]
    _require(len(record_ids) == len(set(record_ids)), "Duplicate evaluation case IDs")
    _require(set(record_ids) == expected_ids,
             f"Input records must contain exactly {partition} case IDs; heldout labels are forbidden in calibration")
    if partition == "heldout":
        _require(labels_approved is True, "Heldout labels require explicit human approval")
        _require(freeze is not None and retrieval_config is not None and evaluation_code_sha256 is not None
                 and criteria is not None and calibration_signals is not None,
                 "Heldout evaluation requires every frozen replay binding")
    if freeze is not None:
        _require(evaluation_code_sha256 is not None and calibration_signals is not None,
                 "Replay requires evaluation code and calibration signals")
        validate_freeze(
            freeze, policy, retrieval_config=retrieval_config, split_manifest=split_manifest,
            evaluation_code_sha256=evaluation_code_sha256, criteria=criteria,
            calibration_signals=calibration_signals,
        )
    configured = _validated_policy(policy)
    results = []
    for original in sorted(records, key=lambda record: record["case_id"]):
        _require(set(original) <= _RECORD_FIELDS, "Unexpected evaluation record fields")
        record = _snapshot(original)
        _require(record.get("expected_decision") in ("proceed", "abstain"), "Invalid expected_decision")
        _text(record.get("category"), "record.category")
        if record["category"] in ("unrelated", "insufficient_evidence"):
            _require(record["expected_decision"] == "abstain", "Negative category contradicts expected_decision")
        for label in ("topical_relevant", "context_sufficient", "dataset_answerable"):
            _require(record.get(label) is None or type(record[label]) is bool,
                     f"record.{label} must be bool or null")
            record.setdefault(label, None)
        if record["context_sufficient"] is not None:
            _text(record.get("context_sufficiency_basis"), "record.context_sufficiency_basis")
        validate_graphrag_gate_signals(record.get("signals"))
        decision = assess_graphrag_two_stage_gate(record["signals"], policy=configured)
        expected_evidence = record.get("expected_evidence_ids", [])
        returned_evidence = record.get("returned_evidence_ids", [])
        for name, values in (("expected_evidence_ids", expected_evidence),
                             ("returned_evidence_ids", returned_evidence)):
            _require(isinstance(values, list)
                     and all(isinstance(item, str) and item.strip() for item in values)
                     and len(values) == len(set(values)),
                     f"record.{name} must be distinct nonempty strings")
        results.append({
            "case_id": record["case_id"], "category": record["category"],
            "expected_decision": record["expected_decision"],
            "actual_decision": decision["decision"],
            "topical_relevant": record["topical_relevant"],
            "dataset_answerable": record["dataset_answerable"],
            "context_sufficient": record["context_sufficient"],
            "context_sufficiency_basis": record.get("context_sufficiency_basis"),
            "missing_expected_evidence_ids": sorted(set(expected_evidence) - set(returned_evidence)),
            "missing_evidence_diagnostics": record.get("missing_evidence_diagnostics", []),
            "signals": record["signals"], "gate_decision": decision,
        })
    return {"partition": partition, "policy": _snapshot(configured),
            "evaluation_kind": "replay" if replay else partition,
            "split_manifest_sha256": canonical_sha256(split_manifest),
            "cases": results, "summary": summarize_cases(results)}


def policy_complexity(policy: Mapping[str, object]) -> int:
    """Count enabled conditions under the existing complete policy contract."""
    configured = _validated_policy(policy)
    count = 0
    for stage in ("topical_relevance", "evidence_answerability"):
        for name, value in configured[stage].items():
            if name == "require_traversal":
                count += value is True
            elif name == "max_traversed_limitation_node_count" or "score" in name:
                count += value is not None
            else:
                count += value > 0
    return count


def select_policy(
    candidates: Sequence[Mapping[str, object]], records: Sequence[Mapping[str, Any]], *,
    split_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate an explicit small candidate list; never search held-out labels."""
    validate_split_manifest(split_manifest)
    reports: dict[str, dict[str, Any]] = {}
    for policy in candidates:
        configured = _validated_policy(policy)
        policy_id = configured["policy_id"]
        if policy_id in reports:
            _require(reports[policy_id]["policy"] == configured, "Conflicting duplicate policy_id")
            continue
        report = evaluate_policy(records, policy=configured, split_manifest=split_manifest)
        summary = report["summary"]
        false_proceed = sum(rate["numerator"] for rate in summary["false_proceed_by_category"].values())
        report["complexity"] = policy_complexity(configured)
        report["selection_rank"] = [false_proceed, -summary["retained_context_sufficient_positives"],
                                    report["complexity"], policy_id]
        reports[policy_id] = report
    ordered = sorted(reports.values(), key=lambda report: report["selection_rank"])
    selectable = [report for report in ordered if not report["summary"]["all_abstain"]]
    chosen = selectable[0] if selectable else None
    return {"selection_rule": SELECTION_RULE, "candidate_results": ordered,
            "selection_status": "selected_calibration_candidate" if chosen else "no_nontrivial_candidate",
            "selected_policy": chosen["policy"] if chosen else None,
            "selected_result": chosen,
            "independent_validation_performed": False,
            "policy_qualified": False}


__all__ = (
    "SPLIT_SCHEMA_VERSION", "FREEZE_SCHEMA_VERSION", "SELECTION_RULE", "TwoStageCalibrationError",
    "canonical_sha256", "ratio", "build_split_manifest", "validate_split_manifest", "freeze_policy",
    "validate_freeze", "summarize_cases", "evaluate_policy", "policy_complexity", "select_policy",
)
