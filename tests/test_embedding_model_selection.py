"""Policy selection over synthetic reports, with no models or external effects."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
import importlib
import json
import math
import os
from pathlib import Path
import random
import socket
import time
from typing import Any
import uuid

import pytest

from threat_hunting.evaluation import (
    EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION,
    EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION,
    EmbeddingModelSelectionError,
    evaluate_embedding_model_candidates,
    validate_embedding_model_selection,
    validate_embedding_model_selection_policy,
)
from threat_hunting.evaluation import embedding_model_selection as engine
from threat_hunting.evaluation import embedding_model_selection_schema as selection_schema
from threat_hunting.evaluation import embedding_retrieval_comparison as comparison


FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures/evaluation/embedding_model_selection"
INPUT_PATH = FIXTURE_DIRECTORY / "input_comparison.json"
EXPECTED_PATH = FIXTURE_DIRECTORY / "expected_selection.json"
ELIGIBLE = "candidate-eligible"
REGRESSION = "candidate-regression"
PRIORITY_MISS = "candidate-priority-miss"
METRIC_FIELDS = {
    "hit_rate": "hit_rate_at_k", "mrr": "mrr_at_k",
    "ndcg": "mean_ndcg_at_k", "recall": "macro_recall_at_k",
}


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    wrapper = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    return wrapper["comparison_report"], wrapper["policy"]


def _bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _assessment(selection: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    return next(row for row in selection["candidate_assessments"] if row["candidate_id"] == candidate_id)


def _relaxed_policy(policy: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    result = deepcopy(policy)
    result.update(
        max_overall_regression=1, max_secondary_language_regression=1,
        max_slice_regression=1, require_positive_validation_delta=False,
    )
    result.update(overrides)
    return result


def _rebuild(report: dict[str, Any]) -> dict[str, Any]:
    """The existing comparison core produces a valid report for ranking variants."""
    return comparison._complete_report(deepcopy(report))


def _copy_rankings(report: dict[str, Any], source_id: str, destination_id: str) -> dict[str, Any]:
    result = deepcopy(report)
    for case in result["cases"]:
        source = next(row for row in case["rankings"] if row["candidate_id"] == source_id)
        target = next(row for row in case["rankings"] if row["candidate_id"] == destination_id)
        target["hits"] = deepcopy(source["hits"])
    return _rebuild(result)


def test_complete_fixture_and_independent_rank_metric_oracle() -> None:
    report, policy = _fixture()
    before = deepcopy((report, policy))
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    assert selection == expected
    assert validate_embedding_model_selection(selection, comparison_report=report, policy=policy) is None
    assert (report, policy) == before
    assert selection["schema_version"] == EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION
    assert policy["schema_version"] == EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION
    assert selection["decision"] == "provisional_recommendation"
    assert selection["recommended_candidate_id"] == ELIGIBLE
    assert selection["metadata"]["candidate_count"] == 4
    assert selection["metadata"]["eligible_candidate_count"] == 1
    assert selection["metadata"]["evaluated_slice_count"] == 6
    assert selection["metadata"]["evaluated_cutoffs"] == [3, 10]
    assert selection["metadata"]["evaluated_metrics"] == sorted(METRIC_FIELDS)
    assert selection["metadata"]["evaluated_languages"] == ["en", "vi"]
    # All support cases have one relevant chunk. A rank-2 result gives MRR 1/2
    # and NDCG 1/log2(3); each language has equal weight in the fixture.
    rank_two_ndcg = round(1 / math.log2(3), 12)
    mixed_ndcg = round((1 + 1 / math.log2(3)) / 2, 12)
    expected_overall = {
        ELIGIBLE: {"hit_rate": 0.0, "mrr": 0.25, "ndcg": round(mixed_ndcg - rank_two_ndcg, 12), "recall": 0.0},
        PRIORITY_MISS: {"hit_rate": 0.0, "mrr": 0.25, "ndcg": round(mixed_ndcg - rank_two_ndcg, 12), "recall": 0.0},
        REGRESSION: {"hit_rate": -0.5, "mrr": 0.0, "ndcg": round(0.5 - rank_two_ndcg, 12), "recall": -0.5},
    }
    for candidate_id, deltas in expected_overall.items():
        assessment = _assessment(selection, candidate_id)
        assert {row["metric"]: row["delta"] for row in assessment["overall_deltas"]} == deltas
        assert len(assessment["slice_deltas"]) == 6
        assert {row["category"] for row in assessment["slice_deltas"]} == {
            "relevant_direct", "relevant_paraphrase", "insufficient_evidence",
        }
    assert _assessment(selection, ELIGIBLE)["priority_language_delta"]["delta"] == 0.5
    assert _assessment(selection, REGRESSION)["priority_language_delta"]["delta"] == 0.5
    assert _assessment(selection, PRIORITY_MISS)["priority_language_delta"]["delta"] == 0.0


def test_fixture_is_generic_and_has_every_required_category_language() -> None:
    report, policy = _fixture()
    text = INPUT_PATH.read_text(encoding="utf-8").casefold()
    assert all(token not in text for token in ("mshta", "powershell", "all-minilm", "multilingual-e5"))
    assert len(report["candidates"]) == 4 and len(report["cases"]) == 8
    assert {(case["category"], case["language"]) for case in report["cases"]} == {
        (category, language) for category in (
            "relevant_direct", "relevant_paraphrase", "insufficient_evidence", "unrelated",
        ) for language in ("en", "vi")
    }
    assert validate_embedding_model_selection_policy(policy, comparison_report=report) is None


def test_priority_gain_does_not_override_quality_regressions() -> None:
    report, policy = _fixture()
    assessment = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    assert assessment["priority_language_delta"]["delta"] == 0.5
    assert not assessment["eligible"]
    assert {
        "overall_metric_regression", "secondary_language_regression",
        "slice_regression", "validation_delta_not_positive",
    }.issubset(assessment["reason_codes"])
    assert assessment["worst_regression"]["magnitude"] == 0.5
    assert assessment["worst_regression"]["delta"] == -0.5


def test_overall_improvement_does_not_override_priority_minimum() -> None:
    report, policy = _fixture()
    assessment = _assessment(evaluate_embedding_model_candidates(report, policy=policy), PRIORITY_MISS)
    assert next(row["delta"] for row in assessment["overall_deltas"] if row["metric"] == "mrr") == 0.25
    assert assessment["priority_language_delta"]["delta"] == 0
    assert not assessment["eligible"]
    assert assessment["reason_codes"] == ["priority_language_gain_below_minimum"]


def test_no_eligible_candidate_retains_baseline_only_for_this_report() -> None:
    report, policy = _fixture()
    policy["min_priority_language_delta"] = 1
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["decision"] == "retain_baseline"
    assert selection["recommended_candidate_id"] is None
    assert selection["metadata"]["eligible_candidate_count"] == 0
    assert all(not row["eligible"] for row in selection["candidate_assessments"])
    assert "no_eligible_candidate" in selection["reason_codes"]


def test_multiple_eligible_candidates_use_priority_gain_before_overall_gain() -> None:
    report, policy = _fixture()
    policy["min_priority_language_delta"] = 0
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["recommended_candidate_id"] == ELIGIBLE
    assert selection["metadata"]["eligible_candidate_count"] == 2
    assert "multiple_eligible_candidates" in selection["reason_codes"]
    assert _assessment(selection, PRIORITY_MISS)["eligible"]


@pytest.mark.parametrize("tie_policy,decision,recommended", [
    ("candidate_id", "provisional_recommendation", ELIGIBLE),
    ("human_review", "needs_human_review", None),
])
def test_equal_quality_tie_has_explicit_deterministic_or_review_behavior(tie_policy, decision, recommended) -> None:
    report, policy = _fixture()
    report = _copy_rankings(report, ELIGIBLE, PRIORITY_MISS)
    policy["tie_break_policy"] = tie_policy
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["decision"] == decision
    assert selection["recommended_candidate_id"] == recommended
    assert selection["metadata"]["eligible_candidate_count"] == 2
    assert selection["review"] == {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None}


def test_missing_tie_policy_fails_closed_without_default_or_input_mutation() -> None:
    report, policy = _fixture()
    del policy["tie_break_policy"]
    before = deepcopy((report, policy))
    with pytest.raises(EmbeddingModelSelectionError, match="tie_break_policy"):
        evaluate_embedding_model_candidates(report, policy=policy)
    assert (report, policy) == before


def test_overall_gain_breaks_equal_priority_gain_before_candidate_identifier() -> None:
    report, policy = _fixture()
    report = _copy_rankings(report, ELIGIBLE, PRIORITY_MISS)
    for case in report["cases"]:
        if case["language"] != "en" or case["target_kind"] == "no_relevant_chunk":
            continue
        ranking = next(row for row in case["rankings"] if row["candidate_id"] == PRIORITY_MISS)
        ranking["hits"] = [hit for hit in ranking["hits"] if hit["is_relevant"]]
    report = _rebuild(report)
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["recommended_candidate_id"] == PRIORITY_MISS
    assert _assessment(selection, PRIORITY_MISS)["priority_language_delta"]["delta"] == 0.5


def test_validation_gain_breaks_equal_primary_gains_before_candidate_identifier() -> None:
    report, policy = _fixture()
    report = _copy_rankings(report, ELIGIBLE, PRIORITY_MISS)
    case = next(case for case in report["cases"]
                if case["language"] == "en" and case["target_kind"] != "no_relevant_chunk")
    relevant = case["relevant_chunk_ids"][0]
    distractors = [row["chunk_id"] for row in report["corpus_catalog"] if row["chunk_id"] != relevant][:3]
    assert len(distractors) == 3
    for ranking in case["rankings"]:
        if ranking["candidate_id"] == ELIGIBLE:
            ranking["hits"] = []
        elif ranking["candidate_id"] == PRIORITY_MISS:
            ranking["hits"] = [{"chunk_id": chunk, "score": 0.9 - index * 0.1}
                               for index, chunk in enumerate([*distractors, relevant])]
    report = _rebuild(report)
    policy = _relaxed_policy(policy)
    policy["tie_break_policy"] = "human_review"
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    first, second = (_assessment(selection, candidate) for candidate in (ELIGIBLE, PRIORITY_MISS))
    assert first["priority_language_delta"]["delta"] == second["priority_language_delta"]["delta"]
    assert next(row["delta"] for row in first["overall_deltas"] if row["metric"] == "mrr") == next(
        row["delta"] for row in second["overall_deltas"] if row["metric"] == "mrr"
    )
    assert first["validation_delta"]["delta"] < second["validation_delta"]["delta"]
    assert selection["decision"] == "provisional_recommendation"
    assert selection["recommended_candidate_id"] == PRIORITY_MISS


def test_positive_validation_delta_is_strict_and_can_be_disabled() -> None:
    report, policy = _fixture()
    policy = _relaxed_policy(policy, require_positive_validation_delta=True)
    strict = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    assert strict["validation_delta"]["delta"] == 0
    assert not strict["eligible"]
    assert strict["reason_codes"] == ["validation_delta_not_positive"]
    policy["require_positive_validation_delta"] = False
    relaxed = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    assert relaxed["eligible"]
    assert all(condition["condition_id"] != "positive_validation_delta" for condition in relaxed["conditions"])


@pytest.mark.parametrize("boundary,eligible", [(0.5, True), (0.49, False)])
def test_slice_regression_boundary_is_inclusive(boundary, eligible) -> None:
    report, policy = _fixture()
    policy = _relaxed_policy(policy, max_slice_regression=boundary)
    assessment = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    conditions = [row for row in assessment["conditions"] if row["condition_id"] == "slice_regression"]
    assert len(conditions) == 6
    assert [row["observed_value"] for row in conditions].count(-0.5) == 3
    assert assessment["eligible"] is eligible
    assert ("slice_regression" in assessment["reason_codes"]) is not eligible


@pytest.mark.parametrize("field,reason", [
    ("max_overall_regression", "overall_metric_regression"),
    ("max_secondary_language_regression", "secondary_language_regression"),
])
@pytest.mark.parametrize("boundary,eligible", [(0.5, True), (0.49, False)])
def test_other_regression_boundaries_are_inclusive(field, reason, boundary, eligible) -> None:
    report, policy = _fixture()
    policy = _relaxed_policy(policy, **{field: boundary})
    assessment = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    assert assessment["eligible"] is eligible
    assert (reason in assessment["reason_codes"]) is not eligible


@pytest.mark.parametrize("minimum,eligible", [(0.5, True), (0.500000000001, False)])
def test_priority_language_gain_boundary_is_inclusive(minimum, eligible) -> None:
    report, policy = _fixture()
    policy["min_priority_language_delta"] = minimum
    assert _assessment(evaluate_embedding_model_candidates(report, policy=policy), ELIGIBLE)["eligible"] is eligible


def test_worst_regression_reports_its_actual_scope_and_stable_tie_choice() -> None:
    report, policy = _fixture()
    regression = _assessment(evaluate_embedding_model_candidates(report, policy=policy), REGRESSION)
    assert regression["worst_regression"] == {
        "magnitude": 0.5, "delta": -0.5, "scope": {"group_by": "candidate", "key": {}},
        "metric": "hit_rate", "cutoff": 3,
    }


@pytest.mark.parametrize("metric", ["ndcg", "mrr", "recall", "hit_rate"])
@pytest.mark.parametrize("primary_cutoff,validation_cutoff", [(1, 3), (3, 5), (5, 10), (10, 1), (3, 3)])
def test_supported_metrics_and_existing_cutoffs_are_policy_driven(metric, primary_cutoff, validation_cutoff) -> None:
    report, policy = _fixture()
    policy = _relaxed_policy(policy, primary_metric=metric, primary_cutoff=primary_cutoff,
                             validation_cutoff=validation_cutoff, min_priority_language_delta=0)
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["metadata"]["evaluated_cutoffs"] == sorted({primary_cutoff, validation_cutoff})
    for assessment in selection["candidate_assessments"]:
        assert assessment["priority_language_delta"]["metric"] == metric
        assert assessment["priority_language_delta"]["cutoff"] == primary_cutoff
        assert assessment["validation_delta"]["metric"] == metric
        assert assessment["validation_delta"]["cutoff"] == validation_cutoff


@pytest.mark.parametrize("mutation", ["metric", "cutoff", "language", "slice", "comparison_delta"])
def test_missing_metrics_or_breakdowns_and_forged_deltas_fail_closed(mutation) -> None:
    report, policy = _fixture()
    if mutation == "metric":
        del report["aggregates"][0]["metrics"][1]["mrr_at_k"]
    elif mutation == "cutoff":
        report["cutoffs"].remove(3)
    elif mutation == "language":
        report["aggregates"] = [row for row in report["aggregates"] if row["group_by"] != "language"]
    elif mutation == "slice":
        report["aggregates"] = [row for row in report["aggregates"] if row["group_by"] != "category_language"]
    else:
        report["comparisons"][0]["deltas"][0]["metrics"][1]["mrr_at_k"] = 0.125
    before = deepcopy(report)
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)
    assert report == before


def test_report_validation_precedes_selection_and_never_trusts_pareto_summary() -> None:
    report, policy = _fixture()
    report["comparisons"][0]["pareto"]["result"] = "baseline_pareto_dominates"
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)


def test_input_immutability_detached_output_and_json_serialization() -> None:
    report, policy = _fixture()
    report_bytes, policy_bytes = _bytes(report), _bytes(policy)
    first = evaluate_embedding_model_candidates(report, policy=policy)
    second = evaluate_embedding_model_candidates(report, policy=policy)
    assert _bytes(first) == _bytes(second)
    assert _bytes(report) == report_bytes and _bytes(policy) == policy_bytes
    first["review"]["reviewer"] = "detached"
    first["candidate_assessments"][0]["conditions"][0]["scope"]["key"]["detached"] = True
    first["metadata"]["evaluated_languages"].append("detached")
    first["warnings"].append("detached")
    assert _bytes(second) == _bytes(evaluate_embedding_model_candidates(report, policy=policy))
    assert _bytes(report) == report_bytes and _bytes(policy) == policy_bytes


def test_dictionary_order_has_no_effect_on_selection_bytes() -> None:
    report, policy = _fixture()
    reordered_report = dict(reversed(list(report.items())))
    reordered_policy = dict(reversed(list(policy.items())))
    assert _bytes(evaluate_embedding_model_candidates(report, policy=policy)) == _bytes(
        evaluate_embedding_model_candidates(reordered_report, policy=reordered_policy)
    )


def test_raw_cosine_changes_do_not_change_policy_quality_assessments() -> None:
    report, policy = _fixture()
    before = evaluate_embedding_model_candidates(report, policy=policy)
    modified = deepcopy(report)
    for case in modified["cases"]:
        for ranking in case["rankings"]:
            for position, hit in enumerate(ranking["hits"]):
                hit["score"] = 0.2 - position * 0.01
    modified = _rebuild(modified)
    after = evaluate_embedding_model_candidates(modified, policy=policy)
    assert before["candidate_assessments"] == after["candidate_assessments"]
    assert before["decision"] == after["decision"]
    assert before["recommended_candidate_id"] == after["recommended_candidate_id"]


@pytest.mark.parametrize("field", [
    "min_priority_language_delta", "max_overall_regression",
    "max_secondary_language_regression", "max_slice_regression",
])
@pytest.mark.parametrize("value", [True, False, None, "0.1", -0.01, 1.01, math.nan, math.inf, -math.inf])
def test_malformed_numeric_policy_values_fail_closed(field, value) -> None:
    report, policy = _fixture()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)


@pytest.mark.parametrize("field,value", [
    ("primary_cutoff", True), ("primary_cutoff", 0), ("primary_cutoff", 2),
    ("validation_cutoff", False), ("validation_cutoff", -1), ("validation_cutoff", 7),
    ("primary_metric", "cosine"), ("primary_metric", "NDCG"),
    ("required_overall_metrics", []), ("required_overall_metrics", ["mrr", "mrr"]),
    ("required_overall_metrics", ["cosine"]), ("secondary_languages", []),
    ("secondary_languages", ["en", "en"]), ("secondary_languages", ["vi"]),
    ("secondary_languages", ["fr"]), ("priority_language", ""),
    ("priority_language", "VI"), ("priority_language", "fr"),
    ("require_positive_validation_delta", 1), ("tie_break_policy", "random"),
])
def test_other_malformed_or_unsupported_policy_values_fail_closed(field, value) -> None:
    report, policy = _fixture()
    policy[field] = value
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)


@pytest.mark.parametrize("field", ["question", "expected_answer", "generated_answer", "model_output", "ExPeCtEd-AnSwEr"])
@pytest.mark.parametrize("target", ["policy", "report"])
def test_recursive_forbidden_fields_fail_closed(field, target) -> None:
    report, policy = _fixture()
    document = policy if target == "policy" else report
    document["review"]["nested"] = {field: "synthetic text"}
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)


@pytest.mark.parametrize("value", ["confirmed", "CONFIRMED", "ConFiRmEd", " confirmed "])
@pytest.mark.parametrize("target", ["policy", "report"])
def test_recursive_confirmed_guard_and_review_status_fail_closed(value, target) -> None:
    report, policy = _fixture()
    document = policy if target == "policy" else report
    document["review"]["review_status"] = value
    with pytest.raises(EmbeddingModelSelectionError):
        evaluate_embedding_model_candidates(report, policy=policy)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_interrupts_from_comparison_validator_are_not_swallowed(monkeypatch, error) -> None:
    report, policy = _fixture()
    def interrupted(_report):
        raise error("synthetic interruption")
    monkeypatch.setattr(selection_schema, "validate_embedding_retrieval_comparison_report", interrupted)
    with pytest.raises(error, match="synthetic interruption"):
        evaluate_embedding_model_candidates(report, policy=policy)


def test_evaluator_does_not_call_file_network_clock_random_or_uuid(monkeypatch) -> None:
    report, policy = _fixture()
    expected = evaluate_embedding_model_candidates(report, policy=policy)
    imported = builtins.__import__
    def forbidden(*args, **kwargs):
        raise AssertionError("external side effect is forbidden")
    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in {"sentence_transformers", "torch", "transformers", "huggingface_hub", "openai"} or any(
            token in name.casefold() for token in (
                "embedding_backend", "vector_search", "vector_retriever",
                "graph_traversal", "knowledge_graph", "graphrag",
            )
        ):
            forbidden()
        return imported(name, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "__import__", guarded_import)
        patch.setattr(builtins, "open", forbidden)
        patch.setattr(os, "open", forbidden)
        for name in ("open", "read_text", "read_bytes", "write_text", "write_bytes"):
            patch.setattr(Path, name, forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(socket, "create_connection", forbidden)
        for name in ("time", "monotonic", "perf_counter"):
            patch.setattr(time, name, forbidden)
        for name in ("random", "randint", "getrandbits"):
            patch.setattr(random, name, forbidden)
        for name in ("uuid1", "uuid4"):
            patch.setattr(uuid, name, forbidden)
        actual = evaluate_embedding_model_candidates(report, policy=policy)
        validate_embedding_model_selection(actual, comparison_report=report, policy=policy)
    assert actual == expected


def test_new_modules_do_not_import_execution_backends_or_external_apis() -> None:
    forbidden = {
        "os", "pathlib", "io", "socket", "time", "datetime", "random", "uuid",
        "requests", "http", "urllib", "sentence_transformers", "torch",
        "transformers", "huggingface_hub", "openai", "neo4j",
    }
    for module in (engine, importlib.import_module("threat_hunting.evaluation.embedding_model_selection_schema")):
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        assert all(name.split(".")[0] not in forbidden for name in imports)
        assert all(not any(token in name.casefold() for token in (
            "embedding_backend", "vector_retriev", "knowledge_graph", "graph_traversal", "graphrag", "llm",
        )) for name in imports)


def test_review_warnings_and_reason_codes_are_stable_and_provisional() -> None:
    report, policy = _fixture()
    selection = evaluate_embedding_model_candidates(report, policy=policy)
    assert selection["review"] == {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    assert selection["reason_codes"] == sorted(set(selection["reason_codes"]))
    assert {"human_review_required", "provisional_only_single_scenario"}.issubset(selection["reason_codes"])
    assert len(selection["warnings"]) >= 4
    warning_text = " ".join(selection["warnings"]).casefold()
    assert "cosine" in warning_text and "production" in warning_text
    assert all(token not in warning_text for token in ("mshta", "powershell", "all-minilm", "multilingual-e5"))
    for assessment in selection["candidate_assessments"]:
        assert assessment["reason_codes"] == sorted(set(assessment["reason_codes"]))
        assert assessment["eligible"] == all(condition["passed"] for condition in assessment["conditions"])
        for condition in assessment["conditions"]:
            assert set(condition) == {
                "condition_id", "passed", "observed_value", "required_value", "scope", "metric", "cutoff",
            }
