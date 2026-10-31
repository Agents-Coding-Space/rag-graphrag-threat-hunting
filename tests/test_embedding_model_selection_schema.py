"""Selection contracts reject forged policy, context, and nested recommendations."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.evaluation import (
    EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION,
    EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION,
    EmbeddingModelSelectionError,
    validate_embedding_model_selection,
    validate_embedding_model_selection_policy,
)
from threat_hunting.evaluation.embedding_model_selection_schema import (
    canonical_json,
    snapshot_selection_json,
    validated_inputs,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures/evaluation/embedding_model_selection"
_POLICY_FIELDS = (
    "schema_version", "policy_id", "primary_cutoff", "validation_cutoff",
    "priority_language", "secondary_languages", "primary_metric",
    "required_overall_metrics", "min_priority_language_delta",
    "max_overall_regression", "max_secondary_language_regression",
    "max_slice_regression", "require_positive_validation_delta", "tie_break_policy", "review",
)
_THRESHOLD_FIELDS = (
    "min_priority_language_delta", "max_overall_regression",
    "max_secondary_language_regression", "max_slice_regression",
)


def _inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    wrapper = json.loads((FIXTURE_ROOT / "input_comparison.json").read_text(encoding="utf-8"))
    return wrapper["comparison_report"], wrapper["policy"]


def _selection() -> dict[str, Any]:
    return json.loads((FIXTURE_ROOT / "expected_selection.json").read_text(encoding="utf-8"))


def _at(value: Any, path: tuple) -> Any:
    for key in path:
        value = value[key]
    return value


def _set(value: Any, path: tuple, replacement: object) -> None:
    _at(value, path[:-1])[path[-1]] = replacement


def _validate(selection: object) -> None:
    report, policy = _inputs()
    validate_embedding_model_selection(selection, comparison_report=report, policy=policy)


def test_schema_exports_and_reviewed_synthetic_fixtures() -> None:
    report, policy = _inputs()
    selection = _selection()
    assert EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION == "embedding-model-selection-policy/v1"
    assert EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION == "embedding-model-selection/v1"
    assert issubclass(EmbeddingModelSelectionError, ValueError)
    assert validate_embedding_model_selection_policy(policy) is None
    assert validate_embedding_model_selection_policy(policy, comparison_report=report) is None
    assert validate_embedding_model_selection(selection, comparison_report=report, policy=policy) is None
    assert selection["metadata"]["candidate_count"] == 4
    assert selection["metadata"]["eligible_candidate_count"] == 1
    assert selection["metadata"]["evaluated_slice_count"] == 6


@pytest.mark.parametrize("field", _POLICY_FIELDS)
def test_missing_required_policy_field(field: str) -> None:
    _, policy = _inputs()
    del policy[field]
    with pytest.raises(EmbeddingModelSelectionError, match="contract"):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("path", [(), ("review",)])
def test_extra_policy_fields_are_rejected(path: tuple) -> None:
    _, policy = _inputs()
    _at(policy, path)["unexpected_field"] = None
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("field", ["policy_id", "priority_language"])
@pytest.mark.parametrize("value", [
    "", " ", "UPPER", " vi", "vi ", "vi/en", "vi--en", "vi..en",
    "vi_-en", "vỉ", "ｖｉ", None, 1, True, [], {},
])
def test_policy_identifiers_must_already_be_normalized(field: str, value: object) -> None:
    _, policy = _inputs()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("value", ["en", "pt-br", "language_2", "version.2"])
def test_policy_language_identifiers_are_generic(value: str) -> None:
    _, policy = _inputs()
    policy["priority_language"] = value
    policy["secondary_languages"] = ["zz"]
    assert validate_embedding_model_selection_policy(policy) is None


@pytest.mark.parametrize("field", ["primary_cutoff", "validation_cutoff"])
@pytest.mark.parametrize("value", [0, -1, True, False, 1.0, "3", None, [], {}])
def test_cutoffs_are_positive_integer_values(field: str, value: object) -> None:
    _, policy = _inputs()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("field", _THRESHOLD_FIELDS)
@pytest.mark.parametrize("value", [
    -0.0001, 1.0001, True, False, "0.25", None, [], {},
    float("nan"), float("inf"), float("-inf"), 10 ** 1000,
])
def test_thresholds_are_finite_non_boolean_magnitudes(field: str, value: object) -> None:
    _, policy = _inputs()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("field", _THRESHOLD_FIELDS)
@pytest.mark.parametrize("value", [0, 1, 0.0, 1.0])
def test_threshold_contract_accepts_both_boundaries(field: str, value: int | float) -> None:
    _, policy = _inputs()
    policy[field] = value
    assert validate_embedding_model_selection_policy(policy) is None


@pytest.mark.parametrize("field,value", [
    ("schema_version", "other/v1"),
    ("primary_metric", "cosine"), ("primary_metric", "NDCG"),
    ("primary_metric", True), ("primary_metric", []), ("primary_metric", {}),
    ("secondary_languages", []), ("secondary_languages", None),
    ("secondary_languages", "en"), ("secondary_languages", ["en", "en"]),
    ("secondary_languages", ["zz", "en"]), ("secondary_languages", ["vi"]),
    ("secondary_languages", ["EN"]), ("secondary_languages", [True]),
    ("required_overall_metrics", []), ("required_overall_metrics", None),
    ("required_overall_metrics", ["mrr", "mrr"]),
    ("required_overall_metrics", ["recall", "ndcg"]),
    ("required_overall_metrics", ["cosine"]), ("required_overall_metrics", ["MRR"]),
    ("require_positive_validation_delta", 1), ("require_positive_validation_delta", 0),
    ("require_positive_validation_delta", "true"),
    ("require_positive_validation_delta", None),
    ("tie_break_policy", "random"), ("tie_break_policy", True),
    ("tie_break_policy", None), ("tie_break_policy", {}),
])
def test_malformed_policy_choices_and_sorted_lists(field: str, value: object) -> None:
    _, policy = _inputs()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("tie_break", ["candidate_id", "human_review"])
def test_tie_break_policy_is_required_and_strict(tie_break: str) -> None:
    _, policy = _inputs()
    policy["tie_break_policy"] = tie_break
    assert validate_embedding_model_selection_policy(policy) is None


@pytest.mark.parametrize("field,value", [
    ("review_status", "reviewed"), ("review_status", "PENDING_HUMAN_REVIEW"),
    ("review_status", None), ("reviewer", "a-reviewer"),
    ("reviewer", False), ("reviewed_at", "2026-01-01"), ("reviewed_at", 0),
])
def test_policy_review_always_remains_pending(field: str, value: object) -> None:
    _, policy = _inputs()
    policy["review"][field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy)


@pytest.mark.parametrize("field", ["primary_cutoff", "validation_cutoff"])
def test_syntax_valid_cutoff_missing_from_report_fails_closed(field: str) -> None:
    report, policy = _inputs()
    policy[field] = 7
    assert validate_embedding_model_selection_policy(policy) is None
    with pytest.raises(EmbeddingModelSelectionError, match="cutoff|cutoffs"):
        validate_embedding_model_selection_policy(policy, comparison_report=report)


@pytest.mark.parametrize("field,value", [
    ("priority_language", "zz"), ("secondary_languages", ["zz"]),
])
def test_syntax_valid_language_missing_from_report_fails_closed(field: str, value: object) -> None:
    report, policy = _inputs()
    policy[field] = value
    assert validate_embedding_model_selection_policy(policy) is None
    with pytest.raises(EmbeddingModelSelectionError, match="language"):
        validate_embedding_model_selection_policy(policy, comparison_report=report)


@pytest.mark.parametrize("operation", ["cutoff", "aggregate", "metric", "delta", "null"])
def test_invalid_comparison_breakdowns_are_never_hidden_by_review(operation: str) -> None:
    report, policy = _inputs()
    if operation == "cutoff":
        report["cutoffs"].remove(policy["primary_cutoff"])
    elif operation == "aggregate":
        del report["aggregates"][0]
    elif operation == "metric":
        del report["aggregates"][0]["metrics"][0]["mrr_at_k"]
    elif operation == "delta":
        report["comparisons"][0]["deltas"][0]["metrics"][1]["mrr_at_k"] = 0.123
    else:
        report["aggregates"][0]["metrics"][1]["mrr_at_k"] = None
    before = deepcopy(report)
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection_policy(policy, comparison_report=report)
    assert report == before


@pytest.mark.parametrize("path", [
    (), ("review",), ("metadata",), ("candidate_assessments", 0),
    ("candidate_assessments", 0, "overall_deltas", 0),
    ("candidate_assessments", 0, "priority_language_delta"),
    ("candidate_assessments", 0, "secondary_language_deltas", 0),
    ("candidate_assessments", 0, "slice_deltas", 0),
    ("candidate_assessments", 0, "validation_delta"),
    ("candidate_assessments", 0, "worst_regression"),
    ("candidate_assessments", 0, "conditions", 0),
    ("candidate_assessments", 0, "conditions", 0, "scope"),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_all_output_objects_have_strict_fields(path: tuple, operation: str) -> None:
    selection = _selection()
    target = _at(selection, path)
    if operation == "missing":
        del target[next(iter(target))]
    else:
        target["unexpected_field"] = None
    before = deepcopy(selection)
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)
    assert selection == before


@pytest.mark.parametrize("path,value", [
    (("schema_version",), "other/v1"), (("evaluation_id",), "forged-id"),
    (("policy_id",), "other-policy"), (("baseline_candidate_id",), "unknown"),
    (("decision",), "retain_baseline"), (("decision",), "confirmed"),
    (("recommended_candidate_id",), None), (("recommended_candidate_id",), "baseline"),
    (("recommended_candidate_id",), "unknown"),
    (("candidate_assessments", 0, "candidate_id"), "unknown"),
    (("candidate_assessments", 0, "eligible"), False),
    (("candidate_assessments", 0, "eligible"), 1),
    (("candidate_assessments", 0, "overall_deltas", 0, "metric"), "cosine"),
    (("candidate_assessments", 0, "overall_deltas", 0, "cutoff"), 7),
    (("candidate_assessments", 0, "overall_deltas", 0, "baseline"), 0.123),
    (("candidate_assessments", 0, "overall_deltas", 0, "candidate"), 0.123),
    (("candidate_assessments", 0, "overall_deltas", 0, "delta"), 0.123),
    (("candidate_assessments", 0, "priority_language_delta", "language"), "zz"),
    (("candidate_assessments", 0, "priority_language_delta", "delta"), -0.5),
    (("candidate_assessments", 0, "secondary_language_deltas", 0, "delta"), 0.5),
    (("candidate_assessments", 0, "slice_deltas", 0, "category"), "other"),
    (("candidate_assessments", 0, "slice_deltas", 0, "language"), "zz"),
    (("candidate_assessments", 0, "slice_deltas", 0, "delta"), -0.9),
    (("candidate_assessments", 0, "validation_delta", "delta"), -0.9),
    (("candidate_assessments", 0, "worst_regression", "magnitude"), 0.5),
    (("candidate_assessments", 0, "conditions", 0, "passed"), False),
    (("candidate_assessments", 0, "conditions", 0, "passed"), 1),
    (("candidate_assessments", 0, "conditions", 0, "observed_value"), 0.123),
    (("candidate_assessments", 0, "conditions", 0, "required_value"), 0.123),
    (("candidate_assessments", 0, "conditions", 0, "scope", "group_by"), "cosine"),
    (("candidate_assessments", 0, "conditions", 0, "scope", "key"), {"unknown": "en"}),
    (("candidate_assessments", 0, "reason_codes"), []),
    (("reason_codes",), []), (("warnings",), []),
    (("review", "review_status"), "reviewed"), (("review", "reviewer"), "reviewer"),
    (("review", "reviewed_at"), "2026-01-01"),
    (("metadata", "candidate_count"), 3), (("metadata", "eligible_candidate_count"), 0),
    (("metadata", "evaluated_slice_count"), 8),
    (("metadata", "evaluated_cutoffs"), [3]),
    (("metadata", "evaluated_metrics"), ["mrr"]),
    (("metadata", "evaluated_languages"), ["vi"]),
    (("metadata", "selection_method"), "probability"),
])
def test_every_decision_condition_metric_and_count_is_replayed(path: tuple, value: object) -> None:
    selection = _selection()
    assert canonical_json(_at(selection, path)) != canonical_json(value)
    _set(selection, path, value)
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)


@pytest.mark.parametrize("value", [True, False, -1.01, 1.01, None, "0.0", float("nan"), float("inf"), float("-inf")])
def test_output_delta_must_be_finite_and_have_the_exact_numeric_type(value: object) -> None:
    selection = _selection()
    selection["candidate_assessments"][0]["priority_language_delta"]["delta"] = value
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)


@pytest.mark.parametrize("field", ["candidate_count", "eligible_candidate_count", "evaluated_slice_count"])
def test_boolean_cannot_impersonate_an_integer_count(field: str) -> None:
    selection = _selection()
    selection["metadata"][field] = True
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)


@pytest.mark.parametrize("path", [
    ("candidate_assessments",), ("candidate_assessments", 0, "overall_deltas"),
    ("candidate_assessments", 0, "slice_deltas"),
    ("candidate_assessments", 0, "conditions"), ("reason_codes",), ("warnings",),
    ("metadata", "evaluated_cutoffs"), ("metadata", "evaluated_metrics"),
    ("metadata", "evaluated_languages"),
])
def test_output_list_order_is_part_of_the_contract(path: tuple) -> None:
    selection = _selection()
    target = _at(selection, path)
    assert len(target) > 1
    target.reverse()
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)


@pytest.mark.parametrize("field", ["candidate_assessments", "reason_codes"])
def test_duplicate_candidates_and_reason_codes_are_rejected(field: str) -> None:
    selection = _selection()
    selection[field].append(deepcopy(selection[field][0]))
    with pytest.raises(EmbeddingModelSelectionError):
        _validate(selection)


@pytest.mark.parametrize("field", [
    "question", "questions", "question_text", "query", "queries", "query_text",
    "expected_answer", "expected_answers", "generated_answer", "generated_answers",
    "reference_answer", "gold_answer", "answer", "answers", "model_output",
    "llm_output", "llm_response", "EXPECTED-ANSWER", "Expected Answer",
    "ModelOutput", "ｇｅｎｅｒａｔｅｄ＿ａｎｓｗｅｒ",
])
@pytest.mark.parametrize("target", ["selection", "policy", "report"])
def test_recursive_forbidden_fields_with_normalized_aliases(field: str, target: str) -> None:
    report, policy = _inputs()
    selection = _selection()
    if target == "selection":
        selection["metadata"]["unexpected"] = [{"nested": {field: "injected"}}]
        with pytest.raises(EmbeddingModelSelectionError, match="forbidden"):
            validate_embedding_model_selection(selection, comparison_report=report, policy=policy)
    elif target == "policy":
        policy["review"]["unexpected"] = [{field: "injected"}]
        with pytest.raises(EmbeddingModelSelectionError, match="forbidden"):
            validate_embedding_model_selection_policy(policy)
    else:
        report["metadata"]["unexpected"] = [{field: "injected"}]
        with pytest.raises(EmbeddingModelSelectionError, match="forbidden"):
            validated_inputs(report, policy)


@pytest.mark.parametrize("value", ["confirmed", "CONFIRMED", " ConFiRmEd ", "ＣＯＮＦＩＲＭＥＤ"])
@pytest.mark.parametrize("target", ["selection", "policy", "report"])
def test_recursive_confirmed_guard(value: str, target: str) -> None:
    report, policy = _inputs()
    selection = _selection()
    document = {"selection": selection, "policy": policy, "report": report}[target]
    document["review"]["unexpected"] = [{"state": value}]
    with pytest.raises(EmbeddingModelSelectionError, match="confirmed"):
        if target == "selection":
            validate_embedding_model_selection(selection, comparison_report=report, policy=policy)
        elif target == "policy":
            validate_embedding_model_selection_policy(policy)
        else:
            validated_inputs(report, policy)


@pytest.mark.parametrize("value", [b"bytes", {"set"}, (1,), Decimal("0.25"), object()])
def test_snapshot_rejects_non_json_native_values(value: object) -> None:
    with pytest.raises(EmbeddingModelSelectionError):
        snapshot_selection_json({"nested": [value]})


def test_snapshot_rejects_cycles_non_string_keys_and_invalid_utf8() -> None:
    cyclic: list = []
    cyclic.append(cyclic)
    for value in (cyclic, {1: "value"}, {"field": "\ud800"}, {"\ud800": "value"}):
        with pytest.raises(EmbeddingModelSelectionError):
            snapshot_selection_json(value)


def test_validated_inputs_are_fully_detached_and_do_not_mutate_sources() -> None:
    report, policy = _inputs()
    before_report, before_policy = deepcopy(report), deepcopy(policy)
    checked_report, checked_policy = validated_inputs(report, policy)
    assert report == before_report and policy == before_policy
    assert checked_report == report and checked_policy == policy
    checked_report["candidates"][0]["embedding"]["model_id"] = "changed"
    checked_policy["secondary_languages"].append("zz")
    assert report == before_report and policy == before_policy


def test_valid_and_invalid_output_validation_does_not_mutate_inputs() -> None:
    report, policy = _inputs()
    selection = _selection()
    before = deepcopy((report, policy, selection))
    validate_embedding_model_selection(selection, comparison_report=report, policy=policy)
    assert (report, policy, selection) == before
    selection["metadata"]["eligible_candidate_count"] = 99
    before_invalid = deepcopy((report, policy, selection))
    with pytest.raises(EmbeddingModelSelectionError):
        validate_embedding_model_selection(selection, comparison_report=report, policy=policy)
    assert (report, policy, selection) == before_invalid


def test_output_is_bound_to_the_complete_policy_not_only_quality_outcome() -> None:
    report, policy = _inputs()
    policy["tie_break_policy"] = "human_review"
    with pytest.raises(EmbeddingModelSelectionError, match="replay"):
        validate_embedding_model_selection(_selection(), comparison_report=report, policy=policy)


def test_output_is_bound_to_comparison_provenance_even_with_identical_metrics() -> None:
    from threat_hunting.evaluation.embedding_retrieval_comparison import _complete_report

    report, policy = _inputs()
    report["dataset_provenance"]["sha256"] = "0" * 64
    changed_report = _complete_report(report)
    with pytest.raises(EmbeddingModelSelectionError, match="replay"):
        validate_embedding_model_selection(_selection(), comparison_report=changed_report, policy=policy)


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", ["policy_snapshot", "report_validator", "selection_replay"])
def test_control_flow_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, exception: type[BaseException], operation: str,
) -> None:
    import threat_hunting.evaluation.embedding_model_selection as engine
    import threat_hunting.evaluation.embedding_model_selection_schema as schema

    report, policy = _inputs()

    def interrupt(*args: object, **kwargs: object) -> None:
        raise exception("must propagate")

    if operation == "policy_snapshot":
        monkeypatch.setattr(schema, "_snapshot", interrupt)
        call = lambda: validate_embedding_model_selection_policy(policy)
    elif operation == "report_validator":
        monkeypatch.setattr(schema, "validate_embedding_retrieval_comparison_report", interrupt)
        call = lambda: validated_inputs(report, policy)
    else:
        monkeypatch.setattr(engine, "_complete_selection", interrupt)
        call = lambda: validate_embedding_model_selection(_selection(), comparison_report=report, policy=policy)
    with pytest.raises(exception):
        call()


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_mapping_snapshot_does_not_swallow_control_flow_exceptions(exception: type[BaseException]) -> None:
    class InterruptingMapping(Mapping):
        def __iter__(self):
            raise exception("must propagate")

        def __len__(self) -> int:
            return 1

        def __getitem__(self, key: object) -> object:
            raise exception("must propagate")

    with pytest.raises(exception):
        snapshot_selection_json(InterruptingMapping())
