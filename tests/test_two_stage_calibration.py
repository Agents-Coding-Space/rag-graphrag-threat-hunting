"""Synthetic contracts for split isolation, context metrics and frozen replay."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
from pathlib import Path

import pytest

from threat_hunting.evaluation import two_stage_calibration as engine


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/graphrag/two_stage_gate/expected_two_stage_gate_decisions.json"


def base_inputs():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return fixture["base_signals"], fixture["base_policy"]


def record(case_id="positive", *, expected="proceed", category="relevant_direct",
           topical=True, context=True, dataset_answerable=True):
    signals, _ = base_inputs()
    return {
        "case_id": case_id, "signals": signals, "expected_decision": expected,
        "category": category, "topical_relevant": topical, "context_sufficient": context,
        "context_sufficiency_basis": "Independent synthetic context adjudication",
        "dataset_answerable": dataset_answerable,
        "expected_evidence_ids": ["expected-one", "expected-two"],
        "returned_evidence_ids": ["expected-one"],
        "missing_evidence_diagnostics": ["Only one synthetic requirement returned"],
    }


def manifest(records, *, heldout=(), groups=None, history=None):
    heldout = set(heldout)
    groups = groups or {item["case_id"]: "group-" + item["case_id"] for item in records}
    descriptors = [{"case_id": item["case_id"], "group_id": groups[item["case_id"]],
                    "label_source": "independently-authored-synthetic-labels",
                    "grouping_rationale": "Distinct synthetic evidence question"} for item in records]
    return engine.build_split_manifest(
        descriptors, dataset_id="synthetic", dataset_sha256="a" * 64,
        assignments={item["case_id"]: "heldout" if item["case_id"] in heldout else "calibration"
                     for item in records},
        usage_history=history or {group_id: [] for group_id in groups.values()},
        split_rationale="Synthetic split fixed before policy comparison",
    )


def run(records, *, policy=None, split=None, **kwargs):
    return engine.evaluate_policy(records, policy=policy or base_inputs()[1],
                                  split_manifest=split or manifest(records), **kwargs)


def disabled_policy(name="disabled"):
    _, policy = base_inputs()
    policy["policy_id"] = name
    for stage in ("topical_relevance", "evidence_answerability"):
        for field in policy[stage]:
            if field == "require_traversal":
                policy[stage][field] = False
            elif "score" in field or field == "max_traversed_limitation_node_count":
                policy[stage][field] = None
            else:
                policy[stage][field] = 0
    return policy


def freeze_inputs(records, split):
    return {
        "retrieval_config": {"model": "existing-local-model", "top_k": 5,
                             "fusion": "fixed", "traversal": {"max_depth": 2}},
        "split_manifest": split, "evaluation_code_sha256": "b" * 64,
        "criteria": {"priorities": engine.SELECTION_RULE},
        "calibration_signals": {item["case_id"]: item["signals"] for item in records
                                if split["assignments"][item["case_id"]] == "calibration"},
    }


def test_manifest_persists_only_descriptors_and_is_deterministic():
    records = [record("b"), record("a")]
    before = deepcopy(records)
    first = manifest(records)
    second = manifest(list(reversed(records)))
    assert first == second
    assert engine.validate_split_manifest(first) is None
    assert records == before
    serialized = json.dumps(first)
    assert "expected_decision" not in serialized and "signals" not in serialized
    assert "expected-one" not in serialized


def test_group_overlap_rejected_even_when_case_ids_differ():
    records = [record("a"), record("b")]
    with pytest.raises(engine.TwoStageCalibrationError, match="overlaps"):
        manifest(records, heldout=["b"], groups={"a": "same-meaning", "b": "same-meaning"})


@pytest.mark.parametrize("use", ["model-selection", "threshold-calibration", "error-analysis"])
def test_previously_used_groups_cannot_be_declared_independent_heldout(use):
    records = [record("a")]
    with pytest.raises(engine.TwoStageCalibrationError, match="Previously used"):
        manifest(records, heldout=["a"], history={"group-a": [use]})


@pytest.mark.parametrize("operation", ["missing_history", "extra_assignment", "unknown_partition",
                                       "duplicate_case", "invalid_digest", "unknown_field"])
def test_manifest_explicit_membership_and_schema_validation(operation):
    value = manifest([record("a")])
    if operation == "missing_history":
        value["usage_history"] = {}
    elif operation == "extra_assignment":
        value["assignments"]["extra"] = "calibration"
    elif operation == "unknown_partition":
        value["assignments"]["a"] = "development"
    elif operation == "duplicate_case":
        value["cases"].append(deepcopy(value["cases"][0]))
    elif operation == "invalid_digest":
        value["dataset_sha256"] = "not-a-digest"
    else:
        value["cases"][0]["expected_answer"] = "must not survive"
    with pytest.raises(engine.TwoStageCalibrationError):
        engine.validate_split_manifest(value)


class LabelAccessTrap(Mapping):
    """Fail if the engine reads held-out labels before rejecting membership."""
    def __init__(self, case_id):
        self.case_id = case_id

    def __getitem__(self, key):
        if key != "case_id":
            raise AssertionError("Held-out labels were accessed")
        return self.case_id

    def __iter__(self):
        return iter(["case_id", "expected_decision"])

    def __len__(self):
        return 2


def test_calibration_rejects_heldout_membership_before_reading_any_labels():
    a, b = record("a"), record("b")
    split = manifest([a, b], heldout=["b"])
    with pytest.raises(engine.TwoStageCalibrationError, match="heldout labels are forbidden"):
        run([a, LabelAccessTrap("b")], split=split)


def test_only_signals_enter_actual_gate_and_external_evidence_never_fills_context(monkeypatch):
    item = record()
    before = deepcopy(item)
    calls = []
    actual = engine.assess_graphrag_two_stage_gate
    def observing(signals, *, policy):
        calls.append(deepcopy(signals))
        return actual(signals, policy=policy)
    monkeypatch.setattr(engine, "assess_graphrag_two_stage_gate", observing)
    report = run([item])
    assert calls == [item["signals"]]
    assert "expected-one" not in json.dumps(calls)
    assert "expected_decision" not in json.dumps(calls)
    assert report["cases"][0]["missing_expected_evidence_ids"] == ["expected-two"]
    assert item == before
    report["cases"][0]["signals"]["topical_relevance"]["retrieval_hit_count"] = 999
    assert item == before


@pytest.mark.parametrize("field,value", [("expected_answer", "private answer"),
                                         ("expected_summary", "private summary")])
def test_expected_answer_fields_are_refused_in_evaluation_records(field, value):
    item = record()
    item[field] = value
    with pytest.raises(engine.TwoStageCalibrationError, match="Unexpected evaluation record fields"):
        run([item])


def test_strict_signals_refuse_benchmark_metadata():
    item = record()
    item["signals"]["expected_decision"] = "proceed"
    with pytest.raises(ValueError):
        run([item])


def test_metrics_define_proceed_positive_and_preserve_context_failure_separation():
    positive, negative = record("tp"), record("fp", expected="abstain", category="unrelated",
                                                 topical=False, context=False, dataset_answerable=False)
    failure = record("fn", context=False)
    true_negative = record("tn", expected="abstain", category="insufficient_evidence", context=False,
                           dataset_answerable=False)
    failure["signals"]["topical_relevance"]["returned_top_cosine_score"] = -1
    true_negative["signals"]["topical_relevance"]["returned_top_cosine_score"] = -1
    report = run([positive, negative, failure, true_negative])
    summary = report["summary"]
    assert summary["dataset_label_confusion_matrix"] == {"tp": 1, "tn": 1, "fp": 1, "fn": 1}
    assert summary["coverage"] == {"numerator": 2, "denominator": 4, "value": 0.5}
    assert summary["selective_error"] == {"numerator": 1, "denominator": 2, "value": 0.5}
    assert summary["false_proceed_by_category"]["unrelated"] == engine.ratio(1, 1)
    assert summary["false_proceed_by_category"]["insufficient_evidence"] == engine.ratio(0, 1)
    assert summary["false_abstain_context_sufficient"] == engine.ratio(0, 1)
    assert summary["dataset_answerable_context_failure_count"] == 1
    assert summary["layers"]["evidence_answerability"]["not_evaluated_count"] == 2
    assert summary["layers"]["evidence_answerability"]["evaluated_known_label_count"] == 2


def test_unknown_layer_labels_are_not_derived_from_abstain_or_expected_evidence():
    item = record(expected="abstain", category="unlabeled-negative", topical=None, context=None,
                  dataset_answerable=None)
    result = run([item])
    for layer in result["summary"]["layers"].values():
        assert layer["known_label_count"] == 0 and layer["unknown_label_count"] == 1
        assert layer["evaluated_known_label_count"] == 0
        assert layer["confusion_matrix"] == {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        assert all(metric["value"] is None for metric in layer["metrics"].values())
    assert result["summary"]["unknown_context_sufficiency_count"] == 1
    assert result["summary"]["false_abstain_context_sufficient"] == engine.ratio(0, 0)


def test_proceed_with_dataset_answer_but_insufficient_returned_context_is_context_error():
    item = record(context=False)
    report = run([item], policy=disabled_policy())
    summary = report["summary"]
    assert summary["dataset_label_confusion_matrix"] == {"tp": 1, "tn": 0, "fp": 0, "fn": 0}
    assert summary["selective_error"] == engine.ratio(0, 1)
    assert summary["selective_error_basis"] == "dataset_expected_decision"
    assert summary["context_eligibility_confusion_matrix"] == {"tp": 0, "tn": 0, "fp": 1, "fn": 0}
    assert summary["context_selective_error"] == engine.ratio(1, 1)


def test_unknown_context_eligibility_is_excluded_from_known_context_denominators():
    known_negative = record("negative", expected="abstain", category="unrelated", topical=False,
                            context=None, dataset_answerable=False)
    unknown = record("unknown", topical=None, context=True)
    report = run([known_negative, unknown], policy=disabled_policy())
    assert report["summary"]["context_eligibility_known_label_count"] == 1
    assert report["summary"]["context_eligibility_unknown_label_count"] == 1
    assert report["summary"]["context_selective_error"] == engine.ratio(1, 1)


@pytest.mark.parametrize("numerator,denominator,expected", [(0, 0, None), (0, 4, 0), (3, 4, 0.75)])
def test_ratio_keeps_zero_denominators_as_null(numerator, denominator, expected):
    assert engine.ratio(numerator, denominator) == {
        "numerator": numerator, "denominator": denominator, "value": expected}


def test_empty_metrics_are_na_instead_of_perfect_or_zero():
    summary = engine.summarize_cases([])
    assert summary["coverage"] == engine.ratio(0, 0)
    assert summary["selective_error"] == engine.ratio(0, 0)
    assert all(value["value"] is None for value in summary["dataset_label_metrics"].values())
    assert summary["all_abstain"] is True


@pytest.mark.parametrize("field,value", [("topical_relevant", "true"), ("context_sufficient", 1),
                                         ("dataset_answerable", 0), ("context_sufficiency_basis", ""),
                                         ("expected_evidence_ids", ["repeat", "repeat"])])
def test_invalid_external_labels_and_evidence_fail_closed(field, value):
    item = record()
    item[field] = value
    with pytest.raises(engine.TwoStageCalibrationError):
        run([item])


def test_policy_ranking_prioritizes_false_proceed_then_context_retention_then_complexity():
    positive, negative = record("p"), record("n", expected="abstain", category="unrelated",
                                           topical=False, context=False, dataset_answerable=False)
    negative["signals"]["topical_relevance"]["returned_top_cosine_score"] = 0
    loose = disabled_policy("loose")
    selective = disabled_policy("selective")
    selective["topical_relevance"]["min_returned_top_cosine_score"] = 0.1
    complex_policy = deepcopy(selective)
    complex_policy["policy_id"] = "complex"
    complex_policy["evidence_answerability"]["min_seed_node_count"] = 1
    result = engine.select_policy([loose, complex_policy, selective], [positive, negative],
                                  split_manifest=manifest([positive, negative]))
    assert result["selected_policy"]["policy_id"] == "selective"
    assert result["policy_qualified"] is False
    assert result["independent_validation_performed"] is False
    assert [entry["policy"]["policy_id"] for entry in result["candidate_results"]] == [
        "selective", "complex", "loose"]


def test_retained_context_sufficient_positive_breaks_false_proceed_tie():
    one, two = record("one"), record("two")
    two["signals"]["topical_relevance"]["returned_top_cosine_score"] = 0.2
    retains_both, retains_one = disabled_policy("both"), disabled_policy("one")
    retains_both["topical_relevance"]["min_returned_top_cosine_score"] = 0.1
    retains_one["topical_relevance"]["min_returned_top_cosine_score"] = 0.5
    result = engine.select_policy([retains_one, retains_both], [one, two], split_manifest=manifest([one, two]))
    assert result["selected_policy"]["policy_id"] == "both"


def test_all_abstain_can_never_be_a_success_even_with_zero_false_proceed():
    item = record()
    policy = disabled_policy("reject-all")
    policy["topical_relevance"]["min_retrieval_hit_count"] = 100
    result = engine.select_policy([policy], [item], split_manifest=manifest([item]))
    assert result["selected_policy"] is None
    assert result["selection_status"] == "no_nontrivial_candidate"
    assert result["candidate_results"][0]["summary"]["all_abstain"] is True


def test_candidate_order_and_duplicate_identical_policy_do_not_change_selection():
    item = record()
    first, second = disabled_policy("a"), disabled_policy("b")
    split = manifest([item])
    assert engine.select_policy([first, second], [item], split_manifest=split) == engine.select_policy(
        [second, first, first], [item], split_manifest=split)
    second["policy_id"] = "a"
    second["topical_relevance"]["min_retrieval_hit_count"] = 1
    with pytest.raises(engine.TwoStageCalibrationError, match="Conflicting"):
        engine.select_policy([first, second], [item], split_manifest=split)


def test_policy_complexity_counts_all_twenty_conditions_under_contract():
    policy = disabled_policy()
    assert engine.policy_complexity(policy) == 0
    for stage in ("topical_relevance", "evidence_answerability"):
        for field in policy[stage]:
            if field == "require_traversal":
                policy[stage][field] = True
            elif field == "max_traversed_limitation_node_count":
                policy[stage][field] = 0
            else:
                policy[stage][field] = 1
    assert engine.policy_complexity(policy) == 20


def test_freeze_replay_integrity_and_canonical_object_order():
    item = record()
    policy = base_inputs()[1]
    split = manifest([item])
    bindings = freeze_inputs([item], split)
    before = deepcopy((policy, bindings))
    frozen = engine.freeze_policy(policy, **bindings)
    assert engine.validate_freeze(frozen, policy, **bindings) is None
    first = run([item], split=split, policy=policy)
    replay_bindings = {key: value for key, value in bindings.items() if key != "split_manifest"}
    replay = run([item], split=split, policy=policy, freeze=frozen, replay=True, **replay_bindings)
    assert replay["evaluation_kind"] == "replay"
    assert first["cases"] == replay["cases"] and first["summary"] == replay["summary"]
    assert (policy, bindings) == before
    assert engine.canonical_sha256({"a": 1, "b": 2}) == engine.canonical_sha256({"b": 2, "a": 1})


@pytest.mark.parametrize("component", ["policy", "retrieval_config", "split_manifest",
                                       "evaluation_code_sha256", "criteria", "calibration_signals",
                                       "lock_sha256"])
def test_every_frozen_component_is_bound(component):
    item = record()
    policy = base_inputs()[1]
    bindings = freeze_inputs([item], manifest([item]))
    frozen = engine.freeze_policy(policy, **bindings)
    if component == "policy":
        policy["topical_relevance"]["min_retrieval_hit_count"] += 1
    elif component == "retrieval_config":
        bindings[component]["top_k"] += 1
    elif component == "split_manifest":
        bindings[component]["split_rationale"] += " changed"
    elif component == "evaluation_code_sha256":
        bindings[component] = "c" * 64
    elif component == "criteria":
        bindings[component]["extra-rule"] = True
    elif component == "calibration_signals":
        bindings[component]["positive"]["topical_relevance"]["returned_top_cosine_score"] = -1
    else:
        frozen["lock_sha256"] = "0" * 64
    with pytest.raises(engine.TwoStageCalibrationError, match="integrity mismatch"):
        engine.validate_freeze(frozen, policy, **bindings)


def test_heldout_requires_approval_and_complete_frozen_bindings_then_distinguishes_replay():
    a, b = record("a"), record("b")
    split = manifest([a, b], heldout=["b"])
    policy = base_inputs()[1]
    with pytest.raises(engine.TwoStageCalibrationError, match="human approval"):
        run([b], split=split, partition="heldout")
    with pytest.raises(engine.TwoStageCalibrationError, match="every frozen"):
        run([b], split=split, partition="heldout", labels_approved=True)
    bindings = freeze_inputs([a, b], split)
    frozen = engine.freeze_policy(policy, **bindings)
    replay_bindings = {key: value for key, value in bindings.items() if key != "split_manifest"}
    result = run([b], split=split, partition="heldout", labels_approved=True,
                 freeze=frozen, **replay_bindings)
    assert result["evaluation_kind"] == "heldout"
    replay = run([b], split=split, partition="heldout", labels_approved=True,
                 freeze=frozen, replay=True, **replay_bindings)
    assert replay["evaluation_kind"] == "replay"
    assert result["cases"] == replay["cases"]


def test_replay_without_lock_and_freeze_with_heldout_signals_fail_closed():
    item = record()
    with pytest.raises(engine.TwoStageCalibrationError, match="frozen evaluation lock"):
        run([item], replay=True)
    a, b = record("a"), record("b")
    split = manifest([a, b], heldout=["b"])
    bindings = freeze_inputs([a, b], split)
    bindings["calibration_signals"]["b"] = b["signals"]
    with pytest.raises(engine.TwoStageCalibrationError, match="exactly the calibration"):
        engine.freeze_policy(base_inputs()[1], **bindings)


def test_nonfinite_json_is_refused_by_hashing():
    with pytest.raises(engine.TwoStageCalibrationError, match="finite JSON"):
        engine.canonical_sha256({"invalid": float("nan")})
