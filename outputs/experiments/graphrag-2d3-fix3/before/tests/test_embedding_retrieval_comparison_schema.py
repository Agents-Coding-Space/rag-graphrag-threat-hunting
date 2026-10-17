"""Strict report replay rejects forged metrics, groups and comparison claims."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.evaluation import (
    EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION,
    EmbeddingRetrievalComparisonError,
    serialize_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_comparison_report,
)


EXPECTED_PATH = Path(__file__).parent / "fixtures/evaluation/embedding_retrieval_comparison/expected_comparison.json"


def _report() -> dict[str, Any]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


def _at(value: Any, path: tuple) -> Any:
    for key in path:
        value = value[key]
    return value


def _set(value: Any, path: tuple, replacement: object) -> None:
    _at(value, path[:-1])[path[-1]] = replacement


def test_schema_export_and_expected_report_are_valid() -> None:
    report = _report()
    assert EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION == "embedding-retrieval-comparison/v1"
    assert report["schema_version"] == EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION
    assert validate_embedding_retrieval_comparison_report(report) is None
    assert report["metadata"]["candidate_count"] == 2
    assert report["metadata"]["case_count"] == 8
    assert report["metadata"]["ranking_count"] == 16
    assert len(report["aggregates"]) == 36
    assert len(report["comparisons"]) == 1


@pytest.mark.parametrize("path", [
    (), ("dataset_provenance",), ("judgments_provenance",), ("corpus_provenance",),
    ("candidates", 0), ("candidates", 0, "embedding"), ("corpus_catalog", 0),
    ("cases", 0), ("cases", 0, "rankings", 0),
    ("cases", 0, "rankings", 0, "hits", 0),
    ("cases", 0, "rankings", 0, "metrics", 0),
    ("aggregates", 0), ("aggregates", 0, "top_cosine_score_summary"),
    ("aggregates", 0, "metrics", 0), ("comparisons", 0),
    ("comparisons", 0, "deltas", 0), ("comparisons", 0, "deltas", 0, "metrics", 0),
    ("comparisons", 0, "pareto"), ("comparisons", 0, "pareto", "groups", 0),
    ("metric_policy",), ("metadata",), ("metadata", "category_counts"), ("review",),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_strict_fields_in_every_report_object(path: tuple, operation: str) -> None:
    report = _report()
    target = _at(report, path)
    if operation == "missing":
        del target[next(iter(target))]
    else:
        target["unexpected_field"] = None
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), "wrong-schema"),
    (("evaluation_id",), "forged-id"),
    (("scenario_id",), "other-scenario"),
    (("baseline_candidate_id",), "missing-candidate"),
    (("dataset_provenance", "sha256"), "not-a-digest"),
    (("judgments_provenance", "scenario_id"), "other-scenario"),
    (("corpus_provenance", "schema_version"), "wrong-schema"),
    (("review", "review_status"), "reviewed"),
    (("review", "reviewer"), "reviewer"),
    (("review", "reviewed_at"), "2026-01-01"),
    (("metric_policy", "precision_decimal_places"), 6),
    (("metadata", "case_count"), 99),
    (("metadata", "ranking_count"), 1),
    (("metadata", "total_returned_hit_count"), 0),
    (("metadata", "total_relevant_pointer_count"), 0),
    (("cases", 0, "relevant_total"), 99),
    (("cases", 0, "relevant_pointer_count"), 99),
    (("cases", 0, "rankings", 0, "returned_hit_count"), 99),
    (("cases", 0, "rankings", 0, "top_cosine_score"), -0.9),
    (("cases", 0, "rankings", 0, "hits", 0, "rank"), 99),
    (("cases", 0, "rankings", 0, "hits", 0, "is_relevant"), True),
    (("cases", 0, "rankings", 0, "hits", 0, "source_json_pointer"), "/facts"),
    (("cases", 0, "rankings", 0, "hits", 0, "chunk_type"), "limitation"),
    (("cases", 0, "rankings", 0, "metrics", 0, "recall_at_k"), 0.123),
    (("cases", 0, "rankings", 0, "metrics", 0, "ndcg_at_k"), 0.123),
    (("aggregates", 0, "metrics", 0, "macro_recall_at_k"), 0.123),
    (("aggregates", 0, "metrics", 0, "mrr_at_k"), 0.123),
    (("comparisons", 0, "deltas", 0, "metrics", 0, "mean_ndcg_at_k"), 0.123),
    (("comparisons", 0, "pareto", "groups", 0, "delta"), -0.123),
    (("comparisons", 0, "pareto", "result"), "baseline_pareto_dominates"),
])
def test_counts_metrics_hit_provenance_and_comparisons_are_recomputed(path: tuple, value: object) -> None:
    report = _report()
    assert _at(report, path) != value
    _set(report, path, value)
    before = deepcopy(report)
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)
    assert report == before


def test_no_relevant_metrics_cannot_be_fabricated_or_added_to_denominators() -> None:
    for field in ("relevant_retrieved_at_k", "hit_at_k", "recall_at_k", "reciprocal_rank_at_k", "ndcg_at_k"):
        report = _report()
        case = next(case for case in report["cases"] if case["target_kind"] == "no_relevant_chunk")
        case["rankings"][0]["metrics"][0][field] = 0
        with pytest.raises(EmbeddingRetrievalComparisonError):
            validate_embedding_retrieval_comparison_report(report)
    report = _report()
    unrelated = next(group for group in report["aggregates"] if group["group_by"] == "category" and group["key"] == {"category": "unrelated"})
    unrelated["relevance_case_count"] = unrelated["case_count"]
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


@pytest.mark.parametrize("path", [
    ("candidates",), ("corpus_catalog",), ("cases",),
    ("cases", 0, "rankings"), ("cases", 0, "rankings", 0, "hits"),
    ("cases", 0, "rankings", 0, "metrics"), ("aggregates",),
    ("comparisons", 0, "deltas"), ("comparisons", 0, "pareto", "groups"),
])
def test_deterministic_list_order_is_enforced(path: tuple) -> None:
    report = _report()
    _at(report, path).reverse()
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


@pytest.mark.parametrize("field", ["expected_answer", "answer", "generated_answer", "llm_output", "model_output", "threshold"])
def test_recursive_forbidden_fields_rejected(field: str) -> None:
    report = _report()
    report["metadata"]["unexpected"] = [{"nested": {field: "injected"}}]
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


@pytest.mark.parametrize("value", ["confirmed", "CONFIRMED", " ConFiRmEd "])
def test_recursive_confirmed_guard(value: str) -> None:
    report = _report()
    report["warnings"].append(value)
    with pytest.raises(EmbeddingRetrievalComparisonError, match="confirmed"):
        validate_embedding_retrieval_comparison_report(report)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_numbers_rejected_in_deep_metadata(value: float) -> None:
    report = _report()
    report["metadata"]["unexpected"] = [{"number": value}]
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


def test_boolean_integer_equalities_cannot_hide_type_tampering() -> None:
    report = _report()
    metric = report["cases"][0]["rankings"][0]["metrics"][0]
    metric["hit_at_k"] = bool(metric["hit_at_k"])
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)


def test_cycles_and_invalid_unicode_raise_domain_errors() -> None:
    report = _report()
    report["metadata"]["cycle"] = report
    with pytest.raises(EmbeddingRetrievalComparisonError):
        validate_embedding_retrieval_comparison_report(report)
    report = _report()
    report["warnings"].append("\ud800")
    with pytest.raises(EmbeddingRetrievalComparisonError):
        serialize_embedding_retrieval_comparison_report(report)


def test_validating_and_serializing_are_immutable_canonical_utf8_operations() -> None:
    report = _report()
    before = deepcopy(report)
    assert validate_embedding_retrieval_comparison_report(report) is None
    first = serialize_embedding_retrieval_comparison_report(report)
    second = serialize_embedding_retrieval_comparison_report(report)
    assert type(first) is bytes and first == second
    assert json.loads(first.decode("utf-8")) == report
    assert first == json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert report == before
