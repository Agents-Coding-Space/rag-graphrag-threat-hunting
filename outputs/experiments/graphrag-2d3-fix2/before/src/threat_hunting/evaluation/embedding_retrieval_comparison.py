"""Compare caller-supplied cosine rankings without retrieval or model execution.

Paths are provenance labels, never opened. Exact UTF-8 source bytes bind the
three input documents. Index hashes/descriptors are caller declarations: this
engine neither opens indexes nor certifies how their rankings were produced.
All six support category/language groups are required for the fixed Pareto
comparison; missing dimensions fail closed rather than imply a smaller test.

Metrics use binary gains and the full relevant set for ideal DCG. Calculated
relevance metrics and means are rounded once to 12 decimal places; aggregates
use raw per-case metrics. Input cosine scores and their extrema are preserved.
Deltas and Pareto compare published aggregate values so a displayed tie cannot
conceal a dominance decision.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .embedding_retrieval_comparison_schema import (
    EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION,
    EmbeddingRetrievalComparisonError,
    snapshot_json,
    validate_candidate_runs,
    validate_cutoffs,
    validate_embedding_retrieval_comparison_report,
)
from .retrieval_judgments import resolve_retrieval_judgments


_CATEGORY_TARGETS = {
    "relevant_direct": "answer_support",
    "relevant_paraphrase": "answer_support",
    "insufficient_evidence": "abstention_support",
    "unrelated": "no_relevant_chunk",
}
_LANGUAGES = ("en", "vi")
_TARGET_KINDS = ("answer_support", "abstention_support", "no_relevant_chunk")
_AGGREGATE_METRICS = (
    "hit_rate_at_k", "macro_recall_at_k", "mrr_at_k", "mean_ndcg_at_k",
)
_METRIC_POLICY = {
    "precision_decimal_places": 12,
    "rounding": "python_round_half_even",
    "aggregation": "unrounded_per_case_math_fsum",
    "pareto": "published_group_ndcg_at_5",
    "no_relevant_relevance_metrics": "null_excluded",
    "ndcg": "binary_gain_log2_ideal_min_cutoff_relevant_total",
}
_WARNINGS = [
    "Cosine scores are not probabilities; no acceptance threshold is defined.",
    "No-relevant cases measure returned hits and top scores only. Rankings do not establish answer correctness or select a production model.",
]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 12)


def _case_metrics(
    relevant_ids: set[str], hits: list[dict[str, Any]], cutoff: int,
) -> dict[str, Any]:
    selected = hits[:cutoff]
    result: dict[str, Any] = {"cutoff": cutoff, "returned_hit_count": len(selected)}
    if not relevant_ids:
        result.update(dict.fromkeys((
            "relevant_retrieved_at_k", "hit_at_k", "recall_at_k",
            "reciprocal_rank_at_k", "ndcg_at_k",
        )))
        return result
    ranks = [rank for rank, hit in enumerate(selected, 1) if hit["chunk_id"] in relevant_ids]
    ideal = math.fsum(1 / math.log2(rank + 1) for rank in range(1, min(cutoff, len(relevant_ids)) + 1))
    result.update({
        "relevant_retrieved_at_k": len(ranks),
        "hit_at_k": int(bool(ranks)),
        "recall_at_k": len(ranks) / len(relevant_ids),
        "reciprocal_rank_at_k": 1 / ranks[0] if ranks else 0.0,
        "ndcg_at_k": math.fsum(1 / math.log2(rank + 1) for rank in ranks) / ideal,
    })
    return result


def _group_specs() -> list[tuple[str, dict[str, str]]]:
    groups = [("candidate", {})]
    groups.extend(("target_kind", {"target_kind": kind}) for kind in _TARGET_KINDS)
    groups.extend(("category", {"category": category}) for category in _CATEGORY_TARGETS)
    groups.extend(("language", {"language": language}) for language in _LANGUAGES)
    groups.extend(("category_language", {"category": category, "language": language})
                  for category in _CATEGORY_TARGETS for language in _LANGUAGES)
    return sorted(groups, key=lambda group: (group[0], _canonical(group[1])))


def _group_metrics(
    candidate_id: str, group_by: str, key: dict[str, str],
    cases: list[dict[str, Any]], raw_metrics: dict[tuple[str, str, int], dict[str, Any]],
    cutoffs: list[int],
) -> dict[str, Any]:
    selected = [case for case in cases if all(case[field] == value for field, value in key.items())]
    support = [case for case in selected if case["target_kind"] != "no_relevant_chunk"]
    unrelated = [case for case in selected if case["target_kind"] == "no_relevant_chunk"]
    scores = [ranking["top_cosine_score"] for case in unrelated for ranking in case["rankings"]
              if ranking["candidate_id"] == candidate_id and ranking["top_cosine_score"] is not None]
    metrics = []
    for cutoff in cutoffs:
        rows = [raw_metrics[(case["case_id"], candidate_id, cutoff)] for case in support]
        values = ("hit_at_k", "recall_at_k", "reciprocal_rank_at_k", "ndcg_at_k")
        metrics.append({
            "cutoff": cutoff,
            **{name: _round(math.fsum(row[field] for row in rows) / len(rows)) if rows else None
               for name, field in zip(_AGGREGATE_METRICS, values, strict=True)},
        })
    return {
        "candidate_id": candidate_id, "group_by": group_by, "key": deepcopy(key),
        "case_count": len(selected), "relevance_case_count": len(support),
        "no_relevant_case_count": len(unrelated), "top_score_case_count": len(scores),
        "top_cosine_score_summary": {
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
            "mean": _round(math.fsum(scores) / len(scores)) if scores else None,
        },
        "metrics": metrics,
    }


def _comparison(
    baseline: str, candidate: str, aggregates: list[dict[str, Any]],
) -> dict[str, Any]:
    by_group = {(row["candidate_id"], row["group_by"], _canonical(row["key"])): row
                for row in aggregates}
    deltas = []
    for group_by, key in _group_specs():
        baseline_row = by_group[(baseline, group_by, _canonical(key))]
        candidate_row = by_group[(candidate, group_by, _canonical(key))]
        metrics = []
        for base, other in zip(baseline_row["metrics"], candidate_row["metrics"], strict=True):
            metrics.append({
                "cutoff": base["cutoff"],
                **{name: _round(other[name] - base[name]) if base[name] is not None else None
                   for name in _AGGREGATE_METRICS},
            })
        deltas.append({"group_by": group_by, "key": deepcopy(key), "metrics": metrics})
    dimensions = []
    for category in sorted(set(_CATEGORY_TARGETS) - {"unrelated"}):
        for language in _LANGUAGES:
            key = {"category": category, "language": language}
            base = by_group[(baseline, "category_language", _canonical(key))]
            other = by_group[(candidate, "category_language", _canonical(key))]
            if not base["relevance_case_count"] or not other["relevance_case_count"]:
                raise EmbeddingRetrievalComparisonError(
                    f"$.cases missing required Pareto support group {category!r} + {language!r}"
                )
            bvalue = next(row["mean_ndcg_at_k"] for row in base["metrics"] if row["cutoff"] == 5)
            cvalue = next(row["mean_ndcg_at_k"] for row in other["metrics"] if row["cutoff"] == 5)
            dimensions.append({
                **key, "baseline": bvalue, "candidate": cvalue,
                "delta": _round(cvalue - bvalue),
            })
    differences = [row["candidate"] - row["baseline"] for row in dimensions]
    if all(value == 0 for value in differences):
        result = "tie"
    elif all(value >= 0 for value in differences):
        result = "candidate_pareto_dominates"
    elif all(value <= 0 for value in differences):
        result = "baseline_pareto_dominates"
    else:
        result = "mixed"
    return {
        "baseline_candidate_id": baseline, "candidate_id": candidate, "deltas": deltas,
        "pareto": {"metric": "mean_ndcg_at_k", "cutoff": 5, "groups": dimensions, "result": result},
    }


def _complete_report(seed: dict[str, Any]) -> dict[str, Any]:
    """Rebuild all derived values from a structurally validated report seed.

    Also used by the schema validator. It never trusts stored ranks, relevance,
    per-case metrics, aggregates, comparisons, counts, or evaluation IDs.
    """
    report = {field: deepcopy(seed[field]) for field in (
        "scenario_id", "dataset_provenance", "judgments_provenance", "corpus_provenance",
        "cutoffs", "baseline_candidate_id", "candidates", "corpus_catalog",
    )}
    report["schema_version"] = EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION
    catalog = {chunk["chunk_id"]: chunk for chunk in report["corpus_catalog"]}
    cases = []
    raw_metrics = {}
    for original in sorted(seed["cases"], key=lambda case: case["case_id"]):
        case = {field: deepcopy(original[field]) for field in (
            "case_id", "category", "language", "target_kind", "relevant_chunk_ids", "relevant_source_pointers",
        )}
        relevant_ids = set(case["relevant_chunk_ids"])
        case["relevant_total"] = len(relevant_ids)
        case["relevant_pointer_count"] = len(case["relevant_source_pointers"])
        rankings = []
        for original_ranking in sorted(original["rankings"], key=lambda ranking: ranking["candidate_id"]):
            candidate = original_ranking["candidate_id"]
            hits = [{
                "rank": rank, "chunk_id": hit["chunk_id"],
                "chunk_type": catalog[hit["chunk_id"]]["chunk_type"],
                "source_json_pointer": catalog[hit["chunk_id"]]["source_json_pointer"],
                "score": hit["score"], "is_relevant": hit["chunk_id"] in relevant_ids,
            } for rank, hit in enumerate(original_ranking["hits"], 1)]
            metrics = []
            for cutoff in report["cutoffs"]:
                raw = _case_metrics(relevant_ids, hits, cutoff)
                raw_metrics[(case["case_id"], candidate, cutoff)] = raw
                metrics.append({key: _round(value) if type(value) is float else value for key, value in raw.items()})
            rankings.append({
                "candidate_id": candidate, "hits": hits, "returned_hit_count": len(hits),
                "top_cosine_score": hits[0]["score"] if hits else None, "metrics": metrics,
            })
        case["rankings"] = rankings
        cases.append(case)
    report["cases"] = cases
    report["aggregates"] = [
        _group_metrics(candidate["candidate_id"], group_by, key, cases, raw_metrics, report["cutoffs"])
        for candidate in report["candidates"] for group_by, key in _group_specs()
    ]
    report["comparisons"] = [
        _comparison(report["baseline_candidate_id"], candidate["candidate_id"], report["aggregates"])
        for candidate in report["candidates"] if candidate["candidate_id"] != report["baseline_candidate_id"]
    ]
    report["metric_policy"] = deepcopy(_METRIC_POLICY)
    report["warnings"] = list(_WARNINGS)
    report["review"] = {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    report["metadata"] = {
        "candidate_count": len(report["candidates"]), "case_count": len(cases),
        "corpus_chunk_count": len(catalog),
        "total_relevant_pointer_count": sum(case["relevant_pointer_count"] for case in cases),
        "ranking_count": sum(len(case["rankings"]) for case in cases),
        "total_returned_hit_count": sum(ranking["returned_hit_count"] for case in cases for ranking in case["rankings"]),
        "target_kind_counts": {kind: sum(case["target_kind"] == kind for case in cases) for kind in sorted(_TARGET_KINDS)},
        "category_counts": {category: sum(case["category"] == category for case in cases) for category in sorted(_CATEGORY_TARGETS)},
        "language_counts": {language: sum(case["language"] == language for case in cases) for language in _LANGUAGES},
    }
    report["evaluation_id"] = "embedding-retrieval-comparison-" + sha256(_canonical(report)).hexdigest()
    # Sort every object key as well as collection members. This keeps callers'
    # ordinary JSON serialization deterministic, alongside the public serializer.
    return json.loads(_canonical(report))


def _judgments_provenance(
    document: dict[str, Any], source_path: str | Path, source_bytes: bytes,
) -> dict[str, Any]:
    label = source_path.as_posix() if isinstance(source_path, Path) else source_path
    if (not isinstance(label, str) or not label.strip() or "\\" in label
            or PurePosixPath(label).is_absolute() or PureWindowsPath(label).drive
            or any(part in ("", ".", "..") for part in label.split("/"))):
        raise EmbeddingRetrievalComparisonError("$.source_judgments_path must be a safe relative POSIX path")
    if type(source_bytes) is not bytes:
        raise EmbeddingRetrievalComparisonError("$.source_judgments_bytes must be bytes")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise EmbeddingRetrievalComparisonError(f"$.source_judgments_bytes duplicate JSON key {key!r}")
            result[key] = value
        return result

    parsed = snapshot_json(json.loads(source_bytes.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs))
    if _canonical(parsed) != _canonical(document):
        raise EmbeddingRetrievalComparisonError("$.source_judgments_bytes do not match input judgments document")
    return {
        "path": label, "schema_version": document["schema_version"],
        "sha256": sha256(source_bytes).hexdigest(),
        "judgment_set_id": document["judgment_set_id"], "scenario_id": document["scenario_id"],
    }


def compare_embedding_retrieval_rankings(
    calibration_dataset: object, retrieval_judgments: object,
    retrieval_corpus: object, candidate_runs: object, *,
    source_dataset_path: str | Path, source_dataset_bytes: bytes,
    source_judgments_path: str | Path, source_judgments_bytes: bytes,
    source_corpus_path: str | Path, source_corpus_bytes: bytes,
    baseline_candidate_id: str, cutoffs: tuple[int, ...] = (1, 3, 5, 10),
) -> dict[str, Any]:
    """Return a detached, byte-reproducible report over pre-existing rankings.

    Raw judgments bytes and their logical path are required in addition to
    dataset/corpus bytes so provenance never substitutes a reserialized hash
    for an original-file hash. All validation errors use the domain error.
    The report remains pending human review and makes no model selection.
    """
    try:
        checked_cutoffs = validate_cutoffs(cutoffs)
        dataset = snapshot_json(calibration_dataset, "$.calibration_dataset")
        judgments = snapshot_json(retrieval_judgments, "$.retrieval_judgments")
        corpus = snapshot_json(retrieval_corpus, "$.retrieval_corpus")
        resolved = resolve_retrieval_judgments(
            judgments, dataset, corpus, source_dataset_path=source_dataset_path,
            source_dataset_bytes=source_dataset_bytes, source_corpus_path=source_corpus_path,
            source_corpus_bytes=source_corpus_bytes,
        )
        # The corpus builder defines this count, while the generic corpus
        # schema permits arbitrary metadata. Verify the known declaration when
        # supplied, without imposing a new required field on generic corpora.
        if "chunk_count" in corpus["metadata"]:
            count = corpus["metadata"]["chunk_count"]
            if type(count) is not int or count != len(corpus["chunks"]):
                raise EmbeddingRetrievalComparisonError(
                    "$.retrieval_corpus.metadata.chunk_count must equal the actual integer chunk count"
                )
        provenance = _judgments_provenance(judgments, source_judgments_path, source_judgments_bytes)
        runs = validate_candidate_runs(candidate_runs, {case["case_id"] for case in resolved},
                                       {chunk["chunk_id"] for chunk in corpus["chunks"]})
        if not isinstance(baseline_candidate_id, str) or baseline_candidate_id not in {run["candidate_id"] for run in runs}:
            raise EmbeddingRetrievalComparisonError("$.baseline_candidate_id must identify a supplied candidate")
        ranking_lookup = {run["candidate_id"]: {ranking["case_id"]: ranking["hits"] for ranking in run["rankings"]}
                          for run in runs}
        seed = {
            "scenario_id": corpus["scenario_id"],
            "dataset_provenance": deepcopy(judgments["source_dataset"]),
            "judgments_provenance": provenance, "corpus_provenance": deepcopy(judgments["source_corpus"]),
            "cutoffs": checked_cutoffs, "baseline_candidate_id": baseline_candidate_id,
            "candidates": [{key: deepcopy(value) for key, value in run.items() if key != "rankings"} for run in runs],
            "corpus_catalog": sorted([{
                "chunk_id": chunk["chunk_id"], "chunk_type": chunk["chunk_type"],
                "source_json_pointer": chunk["source"]["json_pointer"],
            } for chunk in corpus["chunks"]], key=lambda chunk: chunk["chunk_id"]),
            "cases": [{
                "case_id": case["case_id"], "category": case["category"], "language": case["language"],
                "target_kind": case["target_kind"], "relevant_chunk_ids": case["resolved_chunk_ids"],
                "relevant_source_pointers": case["relevant_source_pointers"],
                "rankings": [{"candidate_id": run["candidate_id"], "hits": ranking_lookup[run["candidate_id"]][case["case_id"]]}
                             for run in runs],
            } for case in resolved],
        }
        report = _complete_report(seed)
        validate_embedding_retrieval_comparison_report(report)
        return report
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError, IndexError) as exc:
        raise EmbeddingRetrievalComparisonError(f"$ cannot compare embedding retrieval rankings: {exc}") from exc


__all__ = ("compare_embedding_retrieval_rankings",)
