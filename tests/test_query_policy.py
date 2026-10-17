"""Synthetic development checks for the explicit FIX3 combination policy."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.orchestrator import build_graphrag_context
from threat_hunting.graphrag.query_context import enrich_query_context
from threat_hunting.graphrag.query_gate import assess_query_aware_gate
from threat_hunting.graphrag.query_policy import (
    CombinedQueryGateError, assess_combined_query_gate, validate_combined_policy,
)
from threat_hunting.graphrag.query_requirements import analyze_query_requirements
from threat_hunting.graphrag.query_support import assess_evidence_support


ROOT = Path(__file__).resolve().parents[1]
POLICY = {
    "schema_version": "query-evidence-eligibility-policy/v1",
    "policy_id": "synthetic-source-bound-test",
    "parser_mode": "supported_with_mandatory_requirements",
    "source_mode": "exact_runtime_source_payloads",
    "scope_mode": "block_mismatch_or_ambiguous_allow_authenticated_bound_unspecified",
    "mandatory_support_mode": "all_supported_with_resolved_nonempty_traces",
    "evidence_mode": "kind_specific_identity_or_source_metadata",
    "completeness_mode": "block_required_identity_set_gap_or_relevant_cuts",
    "contradiction_mode": "block_conflicting_bound_values",
    "legacy_mode": "diagnostic_only",
    "ranking_mode": "diagnostic_only_no_supplement_scores",
    "retrieval_quality": {
        "min_ranked_hits": 1, "require_finite_ranked_scores": True,
        "require_exact_source_bound_ranked_payloads": True,
    },
    "max_chain_depth": 8,
}
LEGACY_POLICY = {
    "schema_version": "graphrag-two-stage-gate-policy/v1",
    "policy_id": "synthetic-strict-legacy",
    "topical_relevance": {
        "min_retrieval_hit_count": 1, "min_lexical_hit_count": 0,
        "min_vector_hit_count": 0, "min_joint_lexical_vector_hit_count": 0,
        "min_query_token_coverage": 1.0,
        "min_returned_top_rrf_score": None, "min_returned_top_bm25_score": None,
        "min_returned_top_cosine_score": None,
    },
    "evidence_answerability": {
        "min_hits_with_evidence_ids": 0, "min_hits_with_source_references": 0,
        "min_unique_source_reference_count": 0, "min_mapped_hit_count": 1,
        "min_seed_node_count": 1, "require_traversal": True,
        "min_traversal_node_count": 0, "min_traversal_edge_count": 0,
        "min_traversal_path_count": 0, "min_traversed_evidence_node_count": 0,
        "min_support_edge_count": 0, "max_traversed_limitation_node_count": None,
    },
}


def _read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture
def sources():
    corpus_path = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
    return (
        json.loads(corpus_path.read_text(encoding="utf-8")),
        _read("tests/fixtures/retrieval/vector_builder/expected_vector_index.json"),
        _read("tests/fixtures/graph/builder/expected_knowledge_graph.json"),
        sha256(corpus_path.read_bytes()).hexdigest(),
    )


def _inputs(sources, query="List all review limitations.", *, enabled=True):
    corpus, index, graph, digest = sources
    initial = build_graphrag_context(
        corpus, index, graph, query, corpus_sha256=digest,
        embed_query=lambda texts: [[1.0, 0.0, 0.0] for _ in texts],
        top_k=1, chunk_types=["entity"], max_depth=0,
    )
    req = analyze_query_requirements(query, scope_metadata={"platforms": ["windows"], "mechanisms": ["process_creation"]})
    final = enrich_query_context(initial, corpus, graph, req, enabled=enabled)
    return final, req


def _assess(sources, final, req, policy=None):
    corpus, _, graph, _ = sources
    return assess_combined_query_gate(final, req, corpus=corpus, graph=graph,
                                      policy=policy or POLICY, legacy_policy=LEGACY_POLICY)


def test_legacy_abstain_is_diagnostic_when_actual_source_limitation_support_exists(sources):
    final, req = _inputs(sources)
    old = assess_query_aware_gate(final, req, policy=LEGACY_POLICY)
    result = _assess(sources, final, req)
    assert old["legacy_decision"]["decision"] == old["final_decision"] == "abstain"
    assert result["legacy_decision"] == old["legacy_decision"]
    assert result["support_assessment"] == assess_evidence_support(req, final)
    assert result["support_assessment"]["schema_version"] == "query-evidence-support/v1"
    assert result["verification_guards"]["schema_version"] == "query-evidence-support/v2"
    assert result["final_decision"] == "proceed"
    assert result["reason_codes"] == []
    assert result["scope_assessment"]["status"] == "unspecified"
    assert all(item["anchored"] for item in result["evidence_anchors"])
    assert result["security_conclusion_made"] is False


def test_absent_returned_evidence_cannot_be_supplied_from_full_source(sources):
    final, req = _inputs(sources, enabled=False)
    result = _assess(sources, final, req)
    assert any(item["chunk_type"] == "limitation" for item in sources[0]["chunks"])
    assert result["support_assessment"]["status"] == "missing"
    assert result["final_decision"] == "abstain"
    assert "required_evidence_missing" in result["reason_codes"]
    assert result["authentication"]["hidden_source_content_used_as_positive_evidence"] is False


def test_scope_mismatch_is_hard_even_if_metadata_is_supported(sources):
    final, req = _inputs(sources, "List all Linux review limitations.")
    result = _assess(sources, final, req)
    assert result["scope_assessment"]["status"] == "mismatch"
    assert result["final_decision"] == "abstain"
    assert "requested_scope_mismatch" in result["reason_codes"]


@pytest.mark.parametrize("query", [
    "Compare Windows process creation with Linux cron.",
    "Explain a nebula's chemical composition.",
])
def test_unresolved_or_unsupported_semantics_remain_abstentions(sources, query):
    final, req = _inputs(sources, query)
    result = _assess(sources, final, req)
    assert req["analysis_status"] in {"ambiguous", "unsupported"}
    assert result["final_decision"] == "abstain"
    assert any(reason.startswith("query_requirements_") for reason in result["reason_codes"])


@pytest.mark.parametrize("field", list(POLICY))
def test_no_policy_field_has_a_hidden_default(field):
    changed = deepcopy(POLICY)
    del changed[field]
    with pytest.raises(CombinedQueryGateError, match="all configured fields"):
        validate_combined_policy(changed)


@pytest.mark.parametrize("field", [
    "parser_mode", "source_mode", "scope_mode", "mandatory_support_mode", "evidence_mode",
    "completeness_mode", "contradiction_mode", "legacy_mode", "ranking_mode",
])
def test_policy_modes_cannot_silently_disable_hard_checks(field):
    changed = deepcopy(POLICY)
    changed[field] = "ignore"
    with pytest.raises(CombinedQueryGateError, match=field):
        validate_combined_policy(changed)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, None])
def test_ranked_presence_requires_positive_explicit_integer(value):
    changed = deepcopy(POLICY)
    changed["retrieval_quality"]["min_ranked_hits"] = value
    with pytest.raises(CombinedQueryGateError, match="positive integer"):
        validate_combined_policy(changed)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, 65, None])
def test_chain_limit_is_explicit_and_bounded(value):
    changed = deepcopy(POLICY)
    changed["max_chain_depth"] = value
    with pytest.raises(CombinedQueryGateError, match="max_chain_depth"):
        validate_combined_policy(changed)


def test_ranked_quality_floor_is_separate_from_support(sources):
    final, req = _inputs(sources)
    policy = deepcopy(POLICY)
    policy["retrieval_quality"]["min_ranked_hits"] = 2
    result = _assess(sources, final, req, policy)
    assert result["support_assessment"]["status"] == "supported"
    assert result["final_decision"] == "abstain"
    assert "source_bound_ranked_hit_count_below_minimum" in result["reason_codes"]


def test_changed_supplement_is_rejected_despite_matching_id_and_source_pointer(sources):
    final, req = _inputs(sources)
    final["supplementary_items"][0]["payload"]["content"] += " Fabricated extra statement."
    start = len(final["final_items"]) - len(final["supplementary_items"])
    final["final_items"][start:] = deepcopy(final["supplementary_items"])
    final["budget"]["final_serialized_bytes"] = len(json.dumps(final["final_items"], ensure_ascii=False,
        sort_keys=True, separators=(",", ":")).encode("utf-8"))
    with pytest.raises(CombinedQueryGateError):
        _assess(sources, final, req)


@pytest.mark.parametrize("target", ["requirements", "context", "policy"])
def test_evaluation_annotations_are_not_runtime_policy_inputs(sources, target):
    final, req = _inputs(sources)
    policy = deepcopy(POLICY)
    changed = {"requirements": req, "context": final, "policy": policy}[target]
    changed["expected_decision"] = "proceed"
    with pytest.raises(CombinedQueryGateError):
        _assess(sources, final, req, policy)


@pytest.mark.parametrize("mutation,reason", [
    ("empty", "mandatory_support_trace_empty"),
    ("wrong_quote", "mandatory_support_trace_quote_mismatch"),
    ("wrong_pointer", "mandatory_support_trace_pointer_mismatch"),
    ("not_returned", "mandatory_support_trace_not_returned"),
])
def test_supported_status_alone_cannot_bypass_resolved_actual_evidence(sources, monkeypatch, mutation, reason):
    import threat_hunting.graphrag.query_policy as module

    final, req = _inputs(sources)
    original = module.assess_evidence_support

    def forged(*args, **kwargs):
        result = original(*args, **kwargs)
        trace = result["requirements"][0]["traces"][0]
        if mutation == "empty":
            result["requirements"][0]["traces"] = []
        elif mutation == "wrong_quote":
            trace["quote"] = "A different statement."
        elif mutation == "wrong_pointer":
            trace["context_pointer"] = "/hidden_source/0"
        else:
            trace["item_id"] = "unreturned-evidence"
        return result

    monkeypatch.setattr(module, "assess_evidence_support", forged)
    result = _assess(sources, final, req)
    assert result["support_assessment"]["status"] == "supported"
    assert result["final_decision"] == "abstain"
    assert reason in result["reason_codes"]


@pytest.mark.parametrize("field,status,reason", [
    ("completeness", "incomplete", "required_completeness_incomplete"),
    ("completeness", "unknown", "required_completeness_unknown"),
    ("contradiction", "detected", "bound_evidence_contradiction_detected"),
    ("contradiction", "unknown", "bound_evidence_contradiction_unknown"),
])
def test_independent_hard_guards_block_even_when_original_checker_supported(sources, monkeypatch, field, status, reason):
    import threat_hunting.graphrag.query_support_v2 as module

    final, req = _inputs(sources)
    original = module.assess_evidence_support_v2

    def guarded(*args, **kwargs):
        result = original(*args, **kwargs)
        result["requirements"][0][field] = {"status": status, "reason_codes": ["synthetic_guard_observation"]}
        return result

    monkeypatch.setattr(module, "assess_evidence_support_v2", guarded)
    result = _assess(sources, final, req)
    assert result["support_assessment"]["status"] == "supported"
    assert result["final_decision"] == "abstain"
    assert reason in result["reason_codes"]


def test_v2_inventory_upgrade_does_not_change_v1_checker_result(sources):
    from threat_hunting.graphrag.query_context_v2 import upgrade_evidence_context

    final, req = _inputs(sources)
    corpus, _, graph, _ = sources
    upgraded = upgrade_evidence_context(final, corpus, graph)
    assert upgraded["final_items"] == final["final_items"]
    a, b = _assess(sources, final, req), _assess(sources, upgraded, req)
    assert a == b
    assert a["support_assessment"] == assess_evidence_support(req, final)


def test_right_limitation_count_with_wrong_source_identity_is_rejected(sources):
    from threat_hunting.graphrag.query_context_v2 import upgrade_evidence_context

    final, req = _inputs(sources)
    corpus, _, graph, _ = sources
    upgraded = upgrade_evidence_context(final, corpus, graph)
    count = upgraded["source_inventory"]["limitation_count"]
    upgraded["source_inventory"]["limitation_sources"][0]["json_pointer"] = "/summary/limitations/unrelated"
    assert len(upgraded["source_inventory"]["limitation_sources"]) == count
    with pytest.raises(CombinedQueryGateError, match="inventory"):
        _assess(sources, upgraded, req)


def test_incomplete_selection_for_unrelated_requirement_remains_diagnostic(sources):
    final, req = _inputs(sources)
    final["selection"]["cut_items"].append({
        "kind": "chunk", "item_id": "unreturned-extra-candidate",
        "requirement_ids": ["unrelated-optional-request"],
        "reason_codes": ["supplementary_item_budget_exhausted"],
    })
    final["incomplete_context"] = True
    result = _assess(sources, final, req)
    assert result["verification_guards"]["status"] == "supported"
    assert result["final_decision"] == "proceed"
    assert result["signals"]["final_evidence_context"]["incomplete_context"] is True
    assert result["signals"]["final_evidence_context"]["relevant_cut_count"] == 0


def test_supplement_has_no_invented_rank_or_probability(sources):
    from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals

    final, req = _inputs(sources)
    result = _assess(sources, final, req)
    for item in final["supplementary_items"]:
        assert not {"rank", "score", "cosine", "bm25", "rrf"}.intersection(item)
    diagnostics = result["signals"]["final_evidence_context"]
    assert diagnostics["ranking_scores_are_probabilities"] is False
    assert diagnostics["supplementary_scores_invented"] is False
    assert result["signals"]["ranked_retrieval"] == extract_graphrag_gate_signals(final["initial_context"])


def test_v2_parser_and_policy_use_versioned_support_without_rewriting_legacy(sources):
    from threat_hunting.graphrag.query_requirements_v2 import analyze_query_requirements_v2

    final, old_req = _inputs(sources)
    req = analyze_query_requirements_v2(old_req["query"], scope_metadata={"platforms": ["windows"], "mechanisms": ["process_creation"]})
    result = _assess(sources, final, req)
    assert result["support_assessment"]["schema_version"] == "query-evidence-support/v2"
    assert result["query_requirements"]["schema_version"] == "query-requirements/v2"
    assert result["final_decision"] == "proceed"


def test_runtime_has_no_io_and_returns_detached_values(sources, monkeypatch):
    import builtins
    import socket

    final, req = _inputs(sources)
    expected = _assess(sources, final, req)
    inputs_before = deepcopy((sources, final, req, POLICY, LEGACY_POLICY))

    def forbidden(*args, **kwargs):
        raise AssertionError("Runtime policy attempted external IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = _assess(sources, final, req)
    assert result == expected
    result["configuration"]["policy_id"] = "caller mutation"
    result["support_assessment"]["requirements"].clear()
    assert (sources, final, req, POLICY, LEGACY_POLICY) == inputs_before


def test_finite_json_and_schema_allowlist_reject_malformed_input(sources):
    final, req = _inputs(sources)
    changed = deepcopy(POLICY)
    changed["schema_version"] = "query-evidence-eligibility-policy/v99"
    with pytest.raises(CombinedQueryGateError):
        _assess(sources, final, req, changed)
    final["initial_context"]["retrieval"]["hits"][0]["score"] = float("nan")
    with pytest.raises(CombinedQueryGateError, match="finite JSON"):
        _assess(sources, final, req)
