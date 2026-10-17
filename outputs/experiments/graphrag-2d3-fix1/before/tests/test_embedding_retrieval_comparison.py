"""Synthetic comparison math, input integrity and in-memory determinism."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import socket
import time
from typing import Any
import uuid

import pytest

from threat_hunting.evaluation import (
    EmbeddingRetrievalComparisonError,
    compare_embedding_retrieval_rankings,
    serialize_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_comparison_report,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = ROOT / "tests/fixtures/evaluation/embedding_retrieval_comparison"
INPUT_PATH = FIXTURE_DIRECTORY / "input_comparison.json"
EXPECTED_PATH = FIXTURE_DIRECTORY / "expected_comparison.json"
CUTOFFS = (1, 3, 5, 10)


def _bytes(document: object) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _input() -> dict[str, Any]:
    return json.loads(INPUT_PATH.read_text(encoding="utf-8"))


def _arguments(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_dataset_path": source["source_dataset_path"],
        "source_dataset_bytes": _bytes(source["calibration_dataset"]),
        "source_judgments_path": source["source_judgments_path"],
        "source_judgments_bytes": _bytes(source["retrieval_judgments"]),
        "source_corpus_path": source["source_corpus_path"],
        "source_corpus_bytes": _bytes(source["retrieval_corpus"]),
        "baseline_candidate_id": source["baseline_candidate_id"],
    }


def _compare(source: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    source = _input() if source is None else source
    arguments = _arguments(source)
    arguments.update(overrides)
    return compare_embedding_retrieval_rankings(
        source["calibration_dataset"], source["retrieval_judgments"],
        source["retrieval_corpus"], source["candidate_runs"], **arguments,
    )


def _case(report: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(case for case in report["cases"] if case["case_id"] == case_id)


def _ranking(case: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    return next(row for row in case["rankings"] if row["candidate_id"] == candidate_id)


def _run(source: dict[str, Any], candidate_id: str = "baseline") -> dict[str, Any]:
    return next(run for run in source["candidate_runs"] if run["candidate_id"] == candidate_id)


def _input_ranking(source: dict[str, Any], case_id: str, candidate_id: str = "baseline") -> dict[str, Any]:
    return next(row for row in _run(source, candidate_id)["rankings"] if row["case_id"] == case_id)


def _bind_source_hashes(source: dict[str, Any]) -> None:
    judgments = source["retrieval_judgments"]
    judgments["source_dataset"]["sha256"] = sha256(_bytes(source["calibration_dataset"])).hexdigest()
    judgments["source_corpus"]["sha256"] = sha256(_bytes(source["retrieval_corpus"])).hexdigest()


def _drop_cases(source: dict[str, Any], case_ids: set[str]) -> None:
    dataset, judgments = source["calibration_dataset"], source["retrieval_judgments"]
    for document in (dataset, judgments):
        document["cases"] = [case for case in document["cases"] if case["case_id"] not in case_ids]
        document["metadata"]["case_count"] = len(document["cases"])
    for run in source["candidate_runs"]:
        run["rankings"] = [case for case in run["rankings"] if case["case_id"] not in case_ids]
    for field, case_field in (("category_counts", "category"), ("language_counts", "language"), ("decision_counts", "expected_decision")):
        dataset["metadata"][field] = {name: sum(case[case_field] == name for case in dataset["cases"]) for name in dataset["metadata"][field]}
    for field in ("category_counts", "language_counts"):
        judgments["metadata"][field] = deepcopy(dataset["metadata"][field])
    judgments["metadata"]["target_kind_counts"] = {kind: sum(case["target_kind"] == kind for case in judgments["cases"]) for kind in judgments["metadata"]["target_kind_counts"]}
    judgments["metadata"]["total_relevant_pointer_count"] = sum(len(case["relevant_source_pointers"]) for case in judgments["cases"])
    judgments["metadata"]["cases_with_multiple_relevant_chunks"] = sum(len(case["relevant_source_pointers"]) > 1 for case in judgments["cases"])
    _bind_source_hashes(source)


def _aggregate(report: dict[str, Any], candidate_id: str, group_by: str, key: dict) -> dict[str, Any]:
    return next(group for group in report["aggregates"] if group["candidate_id"] == candidate_id and group["group_by"] == group_by and group["key"] == key)


def _oracle_metrics(relevant: set[str], ranked_ids: list[str], cutoff: int, *, rounded: bool = True) -> dict[str, Any]:
    """Binary-gain definition independent of production metric helpers."""
    gains = [chunk_id in relevant for chunk_id in ranked_ids[:cutoff]]
    total_hits = sum(gains)
    first_hit = next((position for position, gain in enumerate(gains, 1) if gain), None)
    dcg = sum(1 / math.log2(position + 1) for position, gain in enumerate(gains, 1) if gain)
    ideal = sum(1 / math.log2(position + 1) for position in range(1, min(len(relevant), cutoff) + 1))
    result = {
        "cutoff": cutoff,
        "returned_hit_count": len(gains),
        "relevant_retrieved_at_k": total_hits,
        "hit_at_k": int(bool(total_hits)),
        "recall_at_k": total_hits / len(relevant),
        "reciprocal_rank_at_k": 1 / first_hit if first_hit else 0.0,
        "ndcg_at_k": dcg / ideal,
    }
    if rounded:
        for field in ("recall_at_k", "reciprocal_rank_at_k", "ndcg_at_k"):
            result[field] = round(result[field], 12)
    return result


def test_complete_expected_fixture_and_repeat_serialization() -> None:
    source = _input()
    before_bytes = INPUT_PATH.read_bytes()
    before = deepcopy(source)
    report = _compare(source)
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    assert report == expected
    assert validate_embedding_retrieval_comparison_report(report) is None
    assert source == before
    assert INPUT_PATH.read_bytes() == before_bytes
    assert serialize_embedding_retrieval_comparison_report(report) == serialize_embedding_retrieval_comparison_report(_compare(source))
    assert "mshta" not in before_bytes.decode("utf-8").casefold()


def test_vietnamese_fixture_contains_preserved_unicode() -> None:
    source = _input()
    cases = [case for case in source["calibration_dataset"]["cases"] if case["language"] == "vi"]
    assert len(cases) == 4
    for case in cases:
        assert any(ord(character) > 127 for character in case["query"])
        assert any(ord(character) > 127 for character in case["rationale"])
        assert "c?u" not in case["query"].casefold()
    report = _compare(source)
    assert report["dataset_provenance"]["sha256"] == sha256(_bytes(source["calibration_dataset"])).hexdigest()


def test_every_case_metric_matches_independent_binary_gain_oracle() -> None:
    report = _compare()
    for case in report["cases"]:
        for ranking in case["rankings"]:
            assert [metric["cutoff"] for metric in ranking["metrics"]] == list(CUTOFFS)
            ranked_ids = [hit["chunk_id"] for hit in ranking["hits"]]
            relevant = set(case["relevant_chunk_ids"])
            if case["target_kind"] == "no_relevant_chunk":
                for metric in ranking["metrics"]:
                    assert metric["returned_hit_count"] == min(len(ranked_ids), metric["cutoff"])
                    assert all(metric[field] is None for field in ("relevant_retrieved_at_k", "hit_at_k", "recall_at_k", "reciprocal_rank_at_k", "ndcg_at_k"))
            else:
                assert case["relevant_total"] == len(relevant) > 0
                assert ranking["metrics"] == [_oracle_metrics(relevant, ranked_ids, cutoff) for cutoff in CUTOFFS]


def test_hand_calculated_multi_relevant_rank_two_and_four() -> None:
    ranking = _ranking(_case(_compare(), "comparison-direct-en"), "baseline")
    metric1, metric3, metric5, metric10 = ranking["metrics"]
    assert metric1["recall_at_k"] == metric1["ndcg_at_k"] == 0
    assert metric3["relevant_retrieved_at_k"] == 1
    assert metric3["recall_at_k"] == metric3["reciprocal_rank_at_k"] == 0.5
    ideal_two = 1 + 1 / math.log2(3)
    assert metric3["ndcg_at_k"] == round((1 / math.log2(3)) / ideal_two, 12)
    assert metric5["recall_at_k"] == 1
    assert metric5["reciprocal_rank_at_k"] == 0.5
    assert metric5["ndcg_at_k"] == round((1 / math.log2(3) + 1 / math.log2(5)) / ideal_two, 12)
    assert metric10["ndcg_at_k"] == metric5["ndcg_at_k"]


def test_ideal_dcg_uses_all_relevant_chunks_when_ranking_is_short() -> None:
    source = _input()
    case = _input_ranking(source, "comparison-direct-en", "candidate")
    case["hits"] = case["hits"][:1]
    report = _compare(source)
    result = _ranking(_case(report, "comparison-direct-en"), "candidate")
    assert result["returned_hit_count"] == 1
    assert result["metrics"][0]["ndcg_at_k"] == 1
    assert result["metrics"][1]["recall_at_k"] == 0.5
    assert result["metrics"][1]["ndcg_at_k"] == round(1 / (1 + 1 / math.log2(3)), 12)
    assert result["metrics"][3]["returned_hit_count"] == 1


def test_empty_support_and_relevant_at_rank_six() -> None:
    report = _compare()
    empty = _ranking(_case(report, "comparison-insufficient-en"), "baseline")
    assert empty["hits"] == [] and empty["returned_hit_count"] == 0
    assert empty["top_cosine_score"] is None
    assert all(metric["hit_at_k"] == 0 and metric["recall_at_k"] == metric["reciprocal_rank_at_k"] == metric["ndcg_at_k"] == 0 for metric in empty["metrics"])
    late = _ranking(_case(report, "comparison-insufficient-vi"), "baseline")
    assert late["metrics"][2]["hit_at_k"] == 0
    assert late["metrics"][3]["reciprocal_rank_at_k"] == round(1 / 6, 12)
    assert late["metrics"][3]["ndcg_at_k"] == round(1 / math.log2(7), 12)


def test_no_relevant_groups_have_null_metrics_and_separate_score_denominator() -> None:
    report = _compare()
    for candidate_id in ("baseline", "candidate"):
        group = _aggregate(report, candidate_id, "target_kind", {"target_kind": "no_relevant_chunk"})
        assert group["case_count"] == group["no_relevant_case_count"] == 2
        assert group["relevance_case_count"] == 0
        assert group["top_score_case_count"] == 1
        nonempty = _ranking(_case(report, "comparison-unrelated-en"), candidate_id)
        assert group["top_cosine_score_summary"] == {"min": nonempty["top_cosine_score"], "max": nonempty["top_cosine_score"], "mean": nonempty["top_cosine_score"]}
        assert all(all(metric[field] is None for field in ("hit_rate_at_k", "macro_recall_at_k", "mrr_at_k", "mean_ndcg_at_k")) for metric in group["metrics"])
        overall = _aggregate(report, candidate_id, "candidate", {})
        assert overall["case_count"] == 8 and overall["relevance_case_count"] == 6
        support = [case for case in report["cases"] if case["target_kind"] != "no_relevant_chunk"]
        first_cutoff = [_ranking(case, candidate_id)["metrics"][0] for case in support]
        assert overall["metrics"][0]["hit_rate_at_k"] == round(sum(metric["hit_at_k"] for metric in first_cutoff) / 6, 12)


def test_all_group_metrics_and_published_deltas_match_independent_raw_oracle() -> None:
    report = _compare()
    correspondence = {
        "hit_rate_at_k": "hit_at_k", "macro_recall_at_k": "recall_at_k",
        "mrr_at_k": "reciprocal_rank_at_k", "mean_ndcg_at_k": "ndcg_at_k",
    }
    for group in report["aggregates"]:
        members = [case for case in report["cases"] if all(case[key] == value for key, value in group["key"].items())]
        eligible = [case for case in members if case["target_kind"] != "no_relevant_chunk"]
        assert group["case_count"] == len(members)
        assert group["relevance_case_count"] == len(eligible)
        for metric in group["metrics"]:
            oracle_rows = [_oracle_metrics(set(case["relevant_chunk_ids"]), [hit["chunk_id"] for hit in _ranking(case, group["candidate_id"])["hits"]], metric["cutoff"], rounded=False) for case in eligible]
            for aggregate_field, case_field in correspondence.items():
                expected = round(sum(row[case_field] for row in oracle_rows) / len(oracle_rows), 12) if oracle_rows else None
                assert metric[aggregate_field] == expected
    for delta in report["comparisons"][0]["deltas"]:
        baseline = _aggregate(report, "baseline", delta["group_by"], delta["key"])
        candidate = _aggregate(report, "candidate", delta["group_by"], delta["key"])
        for observed, before, after in zip(delta["metrics"], baseline["metrics"], candidate["metrics"], strict=True):
            for field in correspondence:
                expected = round(after[field] - before[field], 12) if before[field] is not None else None
                assert observed[field] == expected


def test_aggregates_round_once_after_raw_case_metrics() -> None:
    source = _input()
    by_pointer = {chunk["source"]["json_pointer"]: chunk["chunk_id"] for chunk in source["retrieval_corpus"]["chunks"]}
    all_ids = sorted(by_pointer.values())
    for judgment in source["retrieval_judgments"]["cases"]:
        relevant = sorted(by_pointer[pointer] for pointer in judgment["relevant_source_pointers"])
        if not relevant:
            continue
        others = [chunk_id for chunk_id in all_ids if chunk_id not in relevant]
        ordering = relevant + others if len(relevant) == 2 else [others[0], *relevant, *others[1:]]
        _input_ranking(source, judgment["case_id"], "candidate")["hits"] = [{"chunk_id": chunk_id, "score": round(0.9 - index * 0.05, 8)} for index, chunk_id in enumerate(ordering)]
    group = _aggregate(_compare(source), "candidate", "candidate", {})
    ndcg = next(row["mean_ndcg_at_k"] for row in group["metrics"] if row["cutoff"] == 3)
    raw_answer = round((2 + 4 / math.log2(3)) / 6, 12)
    prematurely_rounded = round((2 + 4 * round(1 / math.log2(3), 12)) / 6, 12)
    assert raw_answer == 0.753953169048
    assert prematurely_rounded == 0.753953169047
    assert ndcg == raw_answer != prematurely_rounded


def test_zero_size_no_relevant_groups_are_retained_with_null_metrics() -> None:
    source = _input()
    _drop_cases(source, {"comparison-unrelated-en", "comparison-unrelated-vi"})
    report = _compare(source)
    assert len(report["cases"]) == 6 and len(report["aggregates"]) == 36
    group = _aggregate(report, "baseline", "target_kind", {"target_kind": "no_relevant_chunk"})
    assert group["case_count"] == group["relevance_case_count"] == group["no_relevant_case_count"] == group["top_score_case_count"] == 0
    assert group["top_cosine_score_summary"] == {"min": None, "max": None, "mean": None}
    assert all(row["mean_ndcg_at_k"] is None for row in group["metrics"])


def test_missing_required_pareto_dimension_fails_after_valid_source_rebinding() -> None:
    source = _input()
    _drop_cases(source, {"comparison-insufficient-vi"})
    with pytest.raises(EmbeddingRetrievalComparisonError, match="missing required Pareto support group"):
        _compare(source)


def test_main_fixture_is_candidate_pareto_dominant_without_score_comparison() -> None:
    report = _compare()
    comparison = report["comparisons"][0]
    assert comparison["baseline_candidate_id"] == "baseline"
    assert comparison["candidate_id"] == "candidate"
    assert comparison["pareto"]["result"] == "candidate_pareto_dominates"
    assert len(comparison["pareto"]["groups"]) == 6
    assert all(group["delta"] >= 0 for group in comparison["pareto"]["groups"])
    assert any(group["delta"] > 0 for group in comparison["pareto"]["groups"])
    source = _input()
    for ranking in _run(source, "candidate")["rankings"]:
        for index, hit in enumerate(ranking["hits"]):
            hit["score"] = round(0.1 - index * 0.01, 6)
    # Much lower cosine scores do not change rank metrics or Pareto dimensions.
    lower_scores = _compare(source)
    assert lower_scores["comparisons"] == report["comparisons"]


@pytest.mark.parametrize("result", ["mixed", "tie", "baseline_pareto_dominates"])
def test_pareto_results_from_independent_ranking_mutations(result: str) -> None:
    source = _input()
    baseline, candidate = _run(source), _run(source, "candidate")
    if result == "tie":
        candidate["rankings"] = deepcopy(baseline["rankings"])
    elif result == "baseline_pareto_dominates":
        baseline["rankings"], candidate["rankings"] = candidate["rankings"], baseline["rankings"]
    else:
        _input_ranking(source, "comparison-direct-vi", "candidate")["hits"] = []
    assert _compare(source)["comparisons"][0]["pareto"]["result"] == result


def test_success_and_failure_leave_all_inputs_detached() -> None:
    source = _input()
    before = deepcopy(source)
    report = _compare(source)
    report["cases"][0]["rankings"][0]["hits"].clear()
    report["candidates"][0]["embedding"]["model_id"] = "detached"
    assert source == before
    source["candidate_runs"][0]["rankings"][0]["hits"].append({"chunk_id": "missing", "score": -0.9})
    invalid_before = deepcopy(source)
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)
    assert source == invalid_before


def test_ordering_is_deterministic_across_candidate_and_case_source_order() -> None:
    source = _input()
    first = _compare(source)
    source["candidate_runs"].reverse()
    for run in source["candidate_runs"]:
        run["rankings"].reverse()
    second = _compare(source)
    assert serialize_embedding_retrieval_comparison_report(first) == serialize_embedding_retrieval_comparison_report(second)


def test_three_candidates_produce_two_explicit_baseline_comparisons() -> None:
    source = _input()
    third = deepcopy(_run(source, "candidate"))
    third.update(candidate_id="third-candidate", index_id="third-index", index_sha256="c" * 64)
    source["candidate_runs"].append(third)
    report = _compare(source)
    assert report["metadata"]["candidate_count"] == 3
    assert report["metadata"]["ranking_count"] == 24
    assert len(report["aggregates"]) == 54
    assert [comparison["candidate_id"] for comparison in report["comparisons"]] == ["candidate", "third-candidate"]
    assert all(comparison["baseline_candidate_id"] == "baseline" for comparison in report["comparisons"])
    source["candidate_runs"].reverse()
    assert serialize_embedding_retrieval_comparison_report(report) == serialize_embedding_retrieval_comparison_report(_compare(source))


@pytest.mark.parametrize("score", [True, "0.5", None, float("nan"), float("inf"), float("-inf"), 1.01, -1.01])
def test_scores_fail_closed(score: object) -> None:
    source = _input()
    _input_ranking(source, "comparison-direct-en")["hits"][0]["score"] = score
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


def test_cosine_endpoints_are_preserved_without_probability_conversion() -> None:
    for score in (-1.0, 1.0):
        source = _input()
        ranking = _input_ranking(source, "comparison-direct-en")
        ranking["hits"] = [{"chunk_id": ranking["hits"][0]["chunk_id"], "score": score}]
        result = _ranking(_case(_compare(source), "comparison-direct-en"), "baseline")
        assert result["top_cosine_score"] == score
        assert result["hits"][0]["score"] == score


@pytest.mark.parametrize("cutoffs", [(1, 1, 5, 10), (3, 1, 5, 10), (True, 3, 5, 10), (0, 3, 5, 10), (-1, 3, 5, 10), (1.0, 3, 5, 10), (), "1,3,5,10"])
def test_invalid_cutoffs_fail_closed(cutoffs: object) -> None:
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(cutoffs=cutoffs)


@pytest.mark.parametrize("mutation", [
    "duplicate_candidate", "duplicate_index", "missing_case", "extra_case",
    "duplicate_case", "unknown_case", "unknown_chunk", "duplicate_chunk",
    "ascending_score", "wrong_tie_order", "exceeds_limit", "declared_metrics",
])
def test_run_integrity_matrix(mutation: str) -> None:
    source = _input()
    run = _run(source)
    ranking = _input_ranking(source, "comparison-direct-en")
    if mutation == "duplicate_candidate":
        source["candidate_runs"][1]["candidate_id"] = run["candidate_id"]
    elif mutation == "duplicate_index":
        source["candidate_runs"][1]["index_id"] = run["index_id"]
    elif mutation == "missing_case":
        run["rankings"].pop()
    elif mutation in {"extra_case", "duplicate_case"}:
        extra = deepcopy(run["rankings"][0])
        if mutation == "extra_case":
            extra["case_id"] = "extra-case"
        run["rankings"].append(extra)
    elif mutation == "unknown_case":
        ranking["case_id"] = "unknown-case"
    elif mutation == "unknown_chunk":
        ranking["hits"][0]["chunk_id"] = "unknown-chunk"
    elif mutation == "duplicate_chunk":
        ranking["hits"][1]["chunk_id"] = ranking["hits"][0]["chunk_id"]
    elif mutation == "ascending_score":
        ranking["hits"][0]["score"] = -0.9
    elif mutation == "wrong_tie_order":
        tied = _input_ranking(source, "comparison-direct-en", "candidate")
        tied["hits"][0], tied["hits"][1] = tied["hits"][1], tied["hits"][0]
    elif mutation == "exceeds_limit":
        run["ranking_limit"] = 1
    else:
        ranking["metrics"] = {"recall_at_k": 1}
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


@pytest.mark.parametrize("field,value", [("candidate_id", ""), ("index_id", ""), ("index_sha256", "bad"), ("ranking_limit", True), ("ranking_limit", 0)])
def test_invalid_candidate_descriptor(field: str, value: object) -> None:
    source = _input()
    _run(source)[field] = value
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


@pytest.mark.parametrize("field,value", [("provider", ""), ("model_id", ""), ("model_revision", ""), ("dimension", True), ("dimension", 0), ("distance_metric", "euclidean"), ("normalization", "unit")])
def test_invalid_embedding_descriptor(field: str, value: object) -> None:
    source = _input()
    _run(source)["embedding"][field] = value
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


@pytest.mark.parametrize("name", ["expected_answer", "generated_answer", "llm_output", "threshold"])
def test_forbidden_candidate_fields(name: str) -> None:
    source = _input()
    _run(source)[name] = "forbidden"
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


@pytest.mark.parametrize("document_key", ["calibration_dataset", "retrieval_judgments", "retrieval_corpus"])
def test_invalid_source_documents_are_wrapped_domain_errors(document_key: str) -> None:
    source = _input()
    source[document_key]["schema_version"] = "wrong-schema"
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


@pytest.mark.parametrize("source_name", ["dataset", "judgments", "corpus"])
def test_byte_provenance_and_path_mismatches(source_name: str) -> None:
    arguments = _arguments(_input())
    altered_bytes = arguments[f"source_{source_name}_bytes"] + b"\n"
    wrong_path = "fixtures/wrong-source.json"
    if source_name == "judgments":
        altered = _input()["retrieval_judgments"]
        altered["judgment_set_id"] = "different-set"
        altered_bytes = _bytes(altered)
        # Judgments have no self-pinned path/hash; caller labels and actual
        # bytes become report provenance, while parsed content must still match.
        wrong_path = "../unsafe-source.json"
    for override in (
        {f"source_{source_name}_bytes": altered_bytes},
        {f"source_{source_name}_path": wrong_path},
        {f"source_{source_name}_bytes": None},
    ):
        with pytest.raises(EmbeddingRetrievalComparisonError):
            _compare(**override)


def test_judgments_original_whitespace_bytes_determine_provenance_hash() -> None:
    source = _input()
    payload = (json.dumps(source["retrieval_judgments"], ensure_ascii=False, indent=3) + "\n").encode("utf-8")
    report = _compare(source, source_judgments_bytes=payload)
    assert report["judgments_provenance"]["sha256"] == sha256(payload).hexdigest()
    assert report["judgments_provenance"]["sha256"] != sha256(_bytes(source["retrieval_judgments"])).hexdigest()
    assert report["cases"] == _compare(source)["cases"]


@pytest.mark.parametrize("source_name,document_key", [("dataset", "calibration_dataset"), ("corpus", "retrieval_corpus")])
def test_source_bytes_parsed_document_must_match_even_with_valid_hash(source_name: str, document_key: str) -> None:
    source = _input()
    altered = deepcopy(source[document_key])
    if source_name == "dataset":
        altered["cases"][0]["query"] += " Changed text."
    else:
        altered["chunks"][0]["content"] += " Changed content."
    payload = _bytes(altered)
    source["retrieval_judgments"][f"source_{source_name}"]["sha256"] = sha256(payload).hexdigest()
    with pytest.raises(EmbeddingRetrievalComparisonError, match="do not match"):
        _compare(source, **{f"source_{source_name}_bytes": payload})


def test_ambiguous_source_pointer_fails_after_valid_corpus_hash_rebinding() -> None:
    source = _input()
    duplicate = deepcopy(next(chunk for chunk in source["retrieval_corpus"]["chunks"] if chunk["source"]["json_pointer"] == "/evidence/0"))
    duplicate["chunk_id"] = "chunk-comparison-07-ambiguous"
    source["retrieval_corpus"]["chunks"].append(duplicate)
    source["retrieval_corpus"]["metadata"]["chunk_count"] = len(source["retrieval_corpus"]["chunks"])
    _bind_source_hashes(source)
    with pytest.raises(EmbeddingRetrievalComparisonError, match="ambiguous"):
        _compare(source)


@pytest.mark.parametrize("count", [True, None, "6", 6.0, -1, 7])
def test_declared_corpus_chunk_count_is_verified(count: object) -> None:
    source = _input()
    source["retrieval_corpus"]["metadata"]["chunk_count"] = count
    _bind_source_hashes(source)
    with pytest.raises(EmbeddingRetrievalComparisonError, match="metadata.chunk_count"):
        _compare(source)


def test_corpus_without_optional_count_uses_actual_chunk_count() -> None:
    source = _input()
    del source["retrieval_corpus"]["metadata"]["chunk_count"]
    _bind_source_hashes(source)
    assert _compare(source)["metadata"]["corpus_chunk_count"] == 6


@pytest.mark.parametrize("mutation", ["scenario", "pointer", "category_target_kind", "judgment_metadata"])
def test_resolved_judgment_integrity_is_preserved(mutation: str) -> None:
    source = _input()
    judgments = source["retrieval_judgments"]
    if mutation == "scenario":
        source["retrieval_corpus"]["scenario_id"] = "other-scenario"
    elif mutation == "pointer":
        judgments["cases"][0]["relevant_source_pointers"] = ["/facts"]
    elif mutation == "category_target_kind":
        judgments["cases"][0]["target_kind"] = "abstention_support"
    else:
        judgments["metadata"]["total_relevant_pointer_count"] += 1
    with pytest.raises(EmbeddingRetrievalComparisonError):
        _compare(source)


def test_engine_has_no_io_network_models_retrieval_clock_random_or_uuid(monkeypatch) -> None:
    source = _input()
    arguments = _arguments(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("Pure metric engine called an external or nondeterministic operation")

    for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
        monkeypatch.setattr(Path, name, forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    for name in ("time", "monotonic", "perf_counter"):
        monkeypatch.setattr(time, name, forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(uuid, "uuid4", forbidden)
    report = compare_embedding_retrieval_rankings(
        source["calibration_dataset"], source["retrieval_judgments"],
        source["retrieval_corpus"], source["candidate_runs"], **arguments,
    )
    assert len(report["cases"]) == 8
    assert serialize_embedding_retrieval_comparison_report(report)


def test_core_modules_import_no_models_or_search_implementations() -> None:
    for filename in ("embedding_retrieval_comparison.py", "embedding_retrieval_comparison_schema.py"):
        tree = ast.parse((ROOT / "src/threat_hunting/evaluation" / filename).read_text(encoding="utf-8"))
        modules = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        modules += [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        assert not any(any(token in module.casefold() for token in ("sentence_transformers", "torch", "transformers", "embedding_backend", "vector_search", "lexical", "hybrid", "graphrag", "datetime", "random", "uuid")) for module in modules)
