"""Source-version compatibility without changing gate or report semantics.

Existing synthetic v1 fixtures remain unchanged. Only the source provenance
envelope is varied here; approval metadata is never supplied as evidence.
"""

from copy import deepcopy
import json

import pytest

from test_graphrag_relevance import _context, _policy
from test_graphrag_two_stage_gate import _case
from test_relevance_calibration_schema import report_document
from threat_hunting.evaluation import (
    CalibrationReportValidationError,
    build_calibration_report,
    validate_calibration_report,
)
from threat_hunting.graphrag import (
    GraphRAGGateSignalError,
    GraphRAGRelevanceError,
    GraphRAGTwoStageGateError,
    assess_graphrag_relevance,
    assess_graphrag_two_stage_gate,
    extract_graphrag_gate_signals,
    validate_graphrag_gate_signals,
)


SUPPORTED_VERSIONS = ("scenario-ground-truth/v1", "scenario-ground-truth/v2")
UNSUPPORTED_VERSIONS = (
    "scenario-ground-truth/v0", "scenario-ground-truth/v3",
    "scenario-ground-truth/v999", "scenario-ground-truth/v2 ", "other/v2",
)


def _with_source_version(context: dict, version: str) -> dict:
    result = deepcopy(context)
    for document in (result, result["seed_mapping"]):
        document["source_ground_truth"]["schema_version"] = version
    return result


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_actual_source_version_is_preserved_by_public_context_consumers(version):
    context = _with_source_version(_context(), version)
    before = deepcopy(context)
    provenance = context["source_ground_truth"]
    relevance = assess_graphrag_relevance(context, policy=_policy())
    signals = extract_graphrag_gate_signals(context)
    validate_graphrag_gate_signals(signals)
    _, policy, _ = _case()
    decision = assess_graphrag_two_stage_gate(signals, policy=policy)

    assert context == before
    assert relevance["decision"] == "proceed"
    assert relevance["metadata"]["source_ground_truth"] == provenance
    assert signals["source_ground_truth"] == provenance
    assert decision["metadata"]["source_ground_truth"] == provenance
    assert decision["metadata"]["security_conclusion_made"] is False
    assert "confirmed" not in signals["evidence_answerability"]["status_counts"]
    assert not any(name in json.dumps((signals, decision)) for name in (
        "human_reviewer", "human_approved_at", "reviewed_at",
    ))


def test_source_version_changes_no_observed_signal_or_gate_decision():
    contexts = [_with_source_version(_context(), version) for version in SUPPORTED_VERSIONS]
    signals = [extract_graphrag_gate_signals(context) for context in contexts]
    assert signals[0]["topical_relevance"] == signals[1]["topical_relevance"]
    assert signals[0]["evidence_answerability"] == signals[1]["evidence_answerability"]
    _, policy, _ = _case()
    decisions = [assess_graphrag_two_stage_gate(signal, policy=policy) for signal in signals]
    for decision in decisions:
        decision["metadata"].pop("source_ground_truth")
    assert decisions[0] == decisions[1]


@pytest.mark.parametrize("version", UNSUPPORTED_VERSIONS)
def test_unknown_source_versions_are_rejected_without_downgrade(version):
    context = _with_source_version(_context(), version)
    with pytest.raises(GraphRAGRelevanceError, match="schema_version is unsupported"):
        assess_graphrag_relevance(context, policy=_policy())
    with pytest.raises(GraphRAGGateSignalError, match="schema_version is unsupported"):
        extract_graphrag_gate_signals(context)
    signals, policy, _ = _case()
    signals["source_ground_truth"]["schema_version"] = version
    with pytest.raises(GraphRAGTwoStageGateError, match="schema_version is unsupported"):
        assess_graphrag_two_stage_gate(signals, policy=policy)


@pytest.mark.parametrize("field,value", [
    ("schema_version", "scenario-ground-truth/v1"),
    ("path", "different_ground_truth.json"),
    ("sha256", "b" * 64),
    ("scenario_id", "different-scenario"),
])
def test_v2_context_requires_linked_seed_provenance_to_match(field, value):
    context = _with_source_version(_context(), "scenario-ground-truth/v2")
    context["seed_mapping"]["source_ground_truth"][field] = value
    with pytest.raises(GraphRAGRelevanceError, match="mismatch"):
        assess_graphrag_relevance(context, policy=_policy())
    with pytest.raises(GraphRAGGateSignalError, match="mismatch"):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("location", [
    ("retrieval", "hits", 0, "chunk", "metadata"),
    ("traversal", "nodes", 0, "attributes"),
])
def test_v2_does_not_allow_approval_as_evidence_status(location):
    context = _with_source_version(_context(), "scenario-ground-truth/v2")
    target = context
    for key in location:
        target = target[key]
    target["review_status"] = "confirmed"
    with pytest.raises(GraphRAGGateSignalError, match="confirmed"):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("field,value", [
    ("review_status", "confirmed"), ("reviewer", "Synthetic Reviewer"),
    ("reviewed_at", "2026-10-16T10:00:00+07:00"),
])
def test_v2_gate_provenance_does_not_accept_approval_fields(field, value):
    signals, policy, _ = _case()
    signals["source_ground_truth"]["schema_version"] = "scenario-ground-truth/v2"
    signals["source_ground_truth"][field] = value
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(signals, policy=policy)


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_legacy_report_contract_preserves_supported_actual_source_version(version):
    report = report_document()
    original = deepcopy(report)
    report["provenance"]["ground_truth"]["schema_version"] = version
    validate_calibration_report(report)
    rebuilt = build_calibration_report(
        report["calibration"], calibration_id=report["calibration_id"],
        provenance=report["provenance"],
        candidate_search_space=report["candidate_search_space"],
        execution=report["execution"],
    )
    assert rebuilt == report
    assert rebuilt["schema_version"] == "graphrag-relevance-calibration/v1"
    assert rebuilt["provenance"]["ground_truth"]["schema_version"] == version
    assert rebuilt["calibration"] == original["calibration"]
    assert rebuilt["review"] == original["review"]


@pytest.mark.parametrize("version", UNSUPPORTED_VERSIONS)
def test_legacy_report_rejects_unknown_ground_truth_source_versions(version):
    report = report_document()
    report["provenance"]["ground_truth"]["schema_version"] = version
    with pytest.raises(CalibrationReportValidationError, match="provenance schema_version"):
        validate_calibration_report(report)


@pytest.mark.parametrize("location,value", [
    (("ground_truth", "sha256"), "not-a-digest"),
    (("ground_truth", "scenario_id"), "different-scenario"),
    (("graph", "scenario_id"), "different-scenario"),
    (("vector_index", "corpus_id"), "different-corpus"),
    (("corpus", "schema_version"), "retrieval-corpus/v2"),
    (("graph", "schema_version"), "knowledge-graph/v2"),
])
def test_v2_report_keeps_current_binding_and_downstream_version_guards(location, value):
    report = report_document()
    report["provenance"]["ground_truth"]["schema_version"] = "scenario-ground-truth/v2"
    role, field = location
    report["provenance"][role][field] = value
    with pytest.raises(CalibrationReportValidationError):
        validate_calibration_report(report)


def test_v2_source_does_not_approve_report_or_promote_decisions():
    report = report_document()
    report["provenance"]["ground_truth"]["schema_version"] = "scenario-ground-truth/v2"
    report["review"]["status"] = "confirmed"
    with pytest.raises(CalibrationReportValidationError, match="confirmed"):
        validate_calibration_report(report)
