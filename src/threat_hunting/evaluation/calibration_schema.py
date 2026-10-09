"""Strict, compact calibration reports with reproducible metrics and provenance."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any

from .calibration_config import (
    _canonical, _integer, _json_document, _load_json, _object,
    _text, generate_policy_candidates, validate_execution_settings,
    validate_relevance_policy, validate_selection_constraints,
)
from .relevance_calibration import (
    CATEGORIES, DECISIONS, LANGUAGES, METRIC_CONVENTIONS, NO_ELIGIBLE_WARNING,
    _candidate_result, _select,
)


CALIBRATION_REPORT_SCHEMA_VERSION = "graphrag-relevance-calibration/v1"
REASONS = {
    "insufficient_hits", "insufficient_mapped_hits", "insufficient_seeds",
    "insufficient_traversal_nodes", "traversal_required", "missing_lexical_support",
    "missing_joint_lexical_vector_support", "vector_score_below_threshold",
}
SIGNAL_COUNTS = (
    "retrieval_hit_count", "lexical_hit_count", "vector_hit_count",
    "joint_lexical_vector_hit_count", "hit_mapping_count", "mapped_hit_count",
    "seed_node_count", "traversal_node_count", "traversal_edge_count", "traversal_path_count",
)
ARTIFACT_FIELDS = {
    "dataset": ("dataset_id", "scenario_id"), "config": ("calibration_id",),
    "corpus": ("corpus_id", "scenario_id"),
    "vector_index": ("index_id", "corpus_id", "scenario_id"),
    "graph": ("graph_id", "scenario_id"), "ground_truth": ("scenario_id",),
}
ARTIFACT_SCHEMAS = {
    "dataset": "graphrag-relevance-calibration-dataset/v1",
    "config": "graphrag-relevance-calibration-config/v1",
    "corpus": "retrieval-corpus/v1", "vector_index": "vector-index/v1",
    "graph": "knowledge-graph/v1", "ground_truth": "scenario-ground-truth/v1",
}


class CalibrationReportValidationError(ValueError):
    """A report is malformed, inconsistent or contains unsupported review states."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CalibrationReportValidationError(message)


def _strings(value: object, path: str, *, vocabulary: set[str] | None = None) -> None:
    _require(isinstance(value, list), f"{path} must be a list")
    for item in value:
        _text(item, path)
    _require(len(value) == len(set(value)), f"{path} contains duplicates")
    _require(vocabulary is None or set(value) <= vocabulary, f"{path} contains unsupported values")


def _signals(value: object) -> None:
    root = _object(value, (*SIGNAL_COUNTS, "top_cosine_score", "traversal_performed"), "$.signals")
    for field in SIGNAL_COUNTS:
        _integer(root[field], f"$.signals.{field}")
    _require(type(root["traversal_performed"]) is bool, "$.signals.traversal_performed must be bool")
    score = root["top_cosine_score"]
    _require(score is None or (type(score) in (float, int) and -1 <= score <= 1), "$.signals.top_cosine_score out of range")
    hits = root["retrieval_hit_count"]
    _require(all(root[name] <= hits for name in ("lexical_hit_count", "vector_hit_count", "mapped_hit_count")), "$.signals hit counts inconsistent")
    _require(root["joint_lexical_vector_hit_count"] <= min(root["lexical_hit_count"], root["vector_hit_count"]), "$.signals joint hit count inconsistent")
    _require(root["mapped_hit_count"] <= root["hit_mapping_count"], "$.signals mapping counts inconsistent")
    _require((root["vector_hit_count"] == 0) == (score is None), "$.signals cosine presence inconsistent")
    if not root["traversal_performed"]:
        _require(all(root[name] == 0 for name in ("traversal_node_count", "traversal_edge_count", "traversal_path_count")), "$.signals nonempty unperformed traversal")


def _validate_result(root: dict[str, Any]) -> None:
    _object(root, (
        "candidate_count", "case_count", "selection_status", "selection_constraints",
        "candidate_results", "selected_policy", "selected_policy_metrics", "cases",
        "warnings", "metric_conventions",
    ), "$.calibration")
    _integer(root["candidate_count"], "$.calibration.candidate_count", 1)
    _integer(root["case_count"], "$.calibration.case_count", 1)
    validate_selection_constraints(root["selection_constraints"])
    _require(root["metric_conventions"] == METRIC_CONVENTIONS, "$.calibration.metric_conventions mismatch")
    _strings(root["warnings"], "$.calibration.warnings")
    candidates, cases = root["candidate_results"], root["cases"]
    _require(isinstance(candidates, list) and len(candidates) == root["candidate_count"], "$.calibration candidate_count mismatch")
    _require(isinstance(cases, list) and len(cases) == root["case_count"], "$.calibration case_count mismatch")
    policies, bodies = {}, set()
    for candidate in candidates:
        _require(isinstance(candidate, dict) and "policy" in candidate, "candidate must include policy")
        policy = candidate["policy"]
        validate_relevance_policy(policy)
        identifier = policy["policy_id"]
        body = _canonical({key: value for key, value in policy.items() if key != "policy_id"})
        _require(identifier not in policies and body not in bodies, "duplicate policy ID or body")
        policies[identifier] = policy
        bodies.add(body)
    _require(candidates == sorted(candidates, key=lambda item: _canonical(item["policy"])), "candidates must be canonically sorted")
    identifiers = set()
    records_by_policy: dict[str, list[dict[str, Any]]] = {identifier: [] for identifier in policies}
    all_warnings = set()
    for case in cases:
        _object(case, ("case_id", "category", "language", "expected_decision", "actual_decision", "reason_codes", "signals", "warnings", "policy_results"), "$.calibration.cases[]")
        _text(case["case_id"], "$.case_id")
        _require(case["case_id"] not in identifiers, "duplicate case_id")
        identifiers.add(case["case_id"])
        _require(case["category"] in CATEGORIES and case["language"] in LANGUAGES, "unsupported category or language")
        expected = "proceed" if case["category"] in CATEGORIES[:2] else "abstain"
        _require(case["expected_decision"] == expected, "category/expected_decision mismatch")
        _signals(case["signals"])
        _strings(case["warnings"], "$.case.warnings")
        all_warnings.update(case["warnings"])
        _strings(case["reason_codes"], "$.case.reason_codes", vocabulary=REASONS)
        outcomes = case["policy_results"]
        _require(isinstance(outcomes, list) and len(outcomes) == len(policies), "per-case policy results mismatch")
        seen = set()
        for outcome in outcomes:
            _object(outcome, ("policy_id", "actual_decision", "reason_codes"), "$.policy_results[]")
            identifier = outcome["policy_id"]
            _require(isinstance(identifier, str) and identifier in policies and identifier not in seen, "unknown/duplicate outcome policy_id")
            seen.add(identifier)
            _require(outcome["actual_decision"] in DECISIONS, "unsupported actual_decision")
            _strings(outcome["reason_codes"], "$.outcome.reason_codes", vocabulary=REASONS)
            _require((outcome["actual_decision"] == "proceed") == (not outcome["reason_codes"]), "decision/reason_codes mismatch")
            records_by_policy[identifier].append({**case, "actual_decision": outcome["actual_decision"]})
    _require(cases == sorted(cases, key=lambda item: item["case_id"]), "cases must be sorted by case_id")
    for candidate in candidates:
        identifier = candidate["policy"]["policy_id"]
        expected = _candidate_result(policies[identifier], records_by_policy[identifier], root["selection_constraints"])
        _require(_canonical(candidate) == _canonical(expected), f"candidate metrics/breakdown/eligibility mismatch: {identifier}")
    selected = _select(candidates)
    _require(root["selection_status"] == ("selected" if selected else "no_eligible_policy"), "selection_status inconsistent")
    _require(_canonical(root["selected_policy"]) == _canonical(selected["policy"] if selected else None), "selected_policy inconsistent with deterministic selection")
    _require(_canonical(root["selected_policy_metrics"]) == _canonical(selected["metrics"] if selected else None), "selected_policy_metrics mismatch")
    for case in cases:
        chosen = next((item for item in case["policy_results"] if selected and item["policy_id"] == selected["policy"]["policy_id"]), None)
        _require(case["actual_decision"] == (chosen["actual_decision"] if chosen else None), "selected case decision mismatch")
        _require(case["reason_codes"] == (chosen["reason_codes"] if chosen else []), "selected case reasons mismatch")
    if selected is None:
        all_warnings.add(NO_ELIGIBLE_WARNING)
    _require(root["warnings"] == sorted(all_warnings), "calibration warnings mismatch")


def validate_calibration_report(document: object) -> None:
    """Validate structure and recalculate metrics from stored compact outcomes.

    Read-back never re-embeds queries or re-runs the relevance gate.
    """
    try:
        root = _object(_json_document(document), ("schema_version", "calibration_id", "provenance", "candidate_search_space", "calibration", "execution", "review"), "$")
        _require(root["schema_version"] == CALIBRATION_REPORT_SCHEMA_VERSION, "$.schema_version mismatch")
        _text(root["calibration_id"], "$.calibration_id")
        provenance = _object(root["provenance"], (*ARTIFACT_FIELDS, "embedding"), "$.provenance")
        for name, fields in ARTIFACT_FIELDS.items():
            artifact = _object(provenance[name], ("path", "sha256", "schema_version", *fields), f"$.provenance.{name}")
            for field in ("path", *fields):
                _text(artifact[field], f"$.provenance.{name}.{field}")
            _require(isinstance(artifact["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is not None, "provenance SHA-256 must be lowercase full hash")
            _require(artifact["schema_version"] == ARTIFACT_SCHEMAS[name], "provenance schema_version mismatch")
        _require(provenance["config"]["calibration_id"] == root["calibration_id"], "config/calibration ID mismatch")
        _require(len({provenance[name]["scenario_id"] for name in ARTIFACT_FIELDS if "scenario_id" in ARTIFACT_FIELDS[name]}) == 1, "artifact scenario mismatch")
        _require(provenance["vector_index"]["corpus_id"] == provenance["corpus"]["corpus_id"], "index/corpus ID mismatch")
        embedding = _object(provenance["embedding"], ("provider", "model_id", "model_revision", "dimension", "distance_metric", "normalization", "document_prefix", "query_prefix"), "$.provenance.embedding")
        _require(embedding["provider"] == "sentence-transformers", "unsupported embedding provider")
        _text(embedding["model_id"], "$.embedding.model_id")
        _require(isinstance(embedding["model_revision"], str) and re.fullmatch(r"[0-9a-fA-F]{40}", embedding["model_revision"]) is not None, "embedding revision must be full commit SHA")
        _integer(embedding["dimension"], "$.embedding.dimension", 1)
        _require(embedding["distance_metric"] == "cosine" and embedding["normalization"] == "l2", "embedding metric/normalization mismatch")
        _require(all(isinstance(embedding[field], str) for field in ("document_prefix", "query_prefix")), "embedding prefixes must be strings")
        _validate_result(root["calibration"])
        candidates = generate_policy_candidates(root["candidate_search_space"], max_candidate_policies=root["calibration"]["candidate_count"])
        _require(candidates == [item["policy"] for item in root["calibration"]["candidate_results"]], "search space/candidate policies mismatch")
        execution = _object(root["execution"], ("graphrag_context_count", "embedding_backend_count", "retrieval", "traversal", "embedding_runtime"), "$.execution")
        _integer(execution["graphrag_context_count"], "$.execution.graphrag_context_count", 1)
        _integer(execution["embedding_backend_count"], "$.execution.embedding_backend_count", 0, 1)
        _require(execution["graphrag_context_count"] == root["calibration"]["case_count"], "context/case count mismatch")
        validate_execution_settings(execution["retrieval"], execution["traversal"], execution["embedding_runtime"])
        _require(root["review"] == {"status": "pending_human_review", "reviewer": None, "reviewed_at": None}, "review must remain pending_human_review")
    except CalibrationReportValidationError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        raise CalibrationReportValidationError(f"Invalid calibration report at $: {exc}") from exc


def build_calibration_report(
    result: Mapping[str, object], *, calibration_id: str,
    provenance: Mapping[str, object], candidate_search_space: Mapping[str, object],
    execution: Mapping[str, object],
) -> dict[str, Any]:
    try:
        report = _json_document({
            "schema_version": CALIBRATION_REPORT_SCHEMA_VERSION,
            "calibration_id": calibration_id, "provenance": provenance,
            "candidate_search_space": candidate_search_space, "calibration": result,
            "execution": execution,
            "review": {"status": "pending_human_review", "reviewer": None, "reviewed_at": None},
        })
        validate_calibration_report(report)
        return report
    except CalibrationReportValidationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise CalibrationReportValidationError(f"Cannot build calibration report at $: {exc}") from exc


def load_calibration_report(path: Path) -> dict[str, Any]:
    try:
        document = _load_json(path)
        validate_calibration_report(document)
        return document
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise CalibrationReportValidationError(f"Cannot load calibration report {path} at $: {exc}") from exc


__all__ = (
    "CALIBRATION_REPORT_SCHEMA_VERSION", "CalibrationReportValidationError",
    "build_calibration_report", "validate_calibration_report", "load_calibration_report",
)
