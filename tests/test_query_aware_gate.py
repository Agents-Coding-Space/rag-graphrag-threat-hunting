"""Development integration tests for query-aware experimental eligibility.

Real orchestration, parsing, enrichment, support and gate use tiny synthetic
artifacts and fixed fake query vectors. No benchmark labels or real logs enter
the runtime APIs and no model is loaded.
"""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.orchestrator import build_graphrag_context
from threat_hunting.graphrag.query_context import QueryContextError, enrich_query_context
from threat_hunting.graphrag.query_gate import (
    QueryAwareGateError, assess_query_aware_gate, extract_query_evidence_signals,
)
from threat_hunting.graphrag.query_requirements import analyze_query_requirements
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
INDEX = ROOT / "tests/fixtures/retrieval/vector_builder/expected_vector_index.json"
GRAPH = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
LEGACY_CONTEXT = ROOT / "tests/fixtures/graphrag/orchestrator/expected_graphrag_context.json"
LEGACY_SIGNALS = ROOT / "tests/fixtures/graphrag/gate_signals/expected_gate_signals.json"
LEGACY_INIT = ROOT / "src/threat_hunting/graphrag/__init__.py"
SCOPE = {"platforms": ["windows"], "mechanisms": ["process_creation"]}

# A deliberate test-only quality policy makes support/scope changes observable.
# It is not a calibrated policy and never replaces the fixed experiment policy.
PERMISSIVE_POLICY = {
    "schema_version": "graphrag-two-stage-gate-policy/v1",
    "policy_id": "synthetic-query-aware-integration",
    "topical_relevance": {
        "min_retrieval_hit_count": 1, "min_lexical_hit_count": 0,
        "min_vector_hit_count": 0, "min_joint_lexical_vector_hit_count": 0,
        "min_query_token_coverage": 0.0,
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


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def artifacts():
    return _read(CORPUS), _read(INDEX), _read(GRAPH), sha256(CORPUS.read_bytes()).hexdigest()


def _run(artifacts, query="List all review limitations.", *, enabled=True, policy=None):
    corpus, index, graph, digest = artifacts
    initial = build_graphrag_context(
        corpus, index, graph, query, corpus_sha256=digest,
        embed_query=lambda texts: [[1.0, 0.0, 0.0] for _ in texts],
        top_k=1, chunk_types=["entity"], max_depth=0,
    )
    requirements = analyze_query_requirements(query, scope_metadata=SCOPE)
    final = enrich_query_context(initial, corpus, graph, requirements, enabled=enabled)
    result = assess_query_aware_gate(final, requirements, policy=policy or PERMISSIVE_POLICY)
    return initial, requirements, final, result


def test_gate_only_missing_limitations_and_combined_enrichment_supports(artifacts):
    old, req_c, final_c, c = _run(artifacts, enabled=False)
    same_old, req_d, final_d, d = _run(artifacts, enabled=True)
    assert old == same_old and req_c == req_d
    assert c["legacy_decision"]["decision"] == d["legacy_decision"]["decision"] == "proceed"
    assert c["support_assessment"]["status"] == "missing"
    assert c["final_decision"] == "abstain"
    assert c["abstention_stage"] == "evidence_answerability"
    assert "required_evidence_missing" in c["reason_codes"]
    assert not final_c["supplementary_items"]
    assert final_d["supplementary_items"]
    assert final_d["source_inventory"]["limitation_count"] == 1
    assert d["support_assessment"]["status"] == "supported"
    assert d["final_decision"] == "proceed"
    assert d["reason_codes"] == [] and d["abstention_stage"] is None
    assert d["security_conclusion_made"] is False
    returned = {record["item_id"] for record in final_d["final_items"]}
    for requirement in d["support_assessment"]["requirements"]:
        assert requirement["traces"]
        assert all(trace["item_id"] in returned for trace in requirement["traces"])


def test_supported_requirements_cannot_bypass_explicit_legacy_topical_failure(artifacts):
    policy = deepcopy(PERMISSIVE_POLICY)
    policy["topical_relevance"]["min_query_token_coverage"] = 1.0
    initial, requirements, final, result = _run(artifacts, policy=policy)
    assert result["support_assessment"]["status"] == "supported"
    assert result["legacy_decision"]["decision"] == "abstain"
    assert result["legacy_decision"]["abstention_stage"] == "topical_relevance"
    assert result["final_decision"] == "abstain"
    assert result["abstention_stage"] == "topical_relevance"
    assert result["reason_codes"] == ["legacy_quality_gate_abstained"]
    assert result["configuration"]["legacy_quality_mode"] == "require_legacy_proceed"
    assert result["legacy_decision"] == assess_graphrag_two_stage_gate(
        extract_graphrag_gate_signals(initial), policy=policy,
    )


def test_explicit_linux_cron_scope_mismatch_blocks_topical_stage(artifacts):
    _, requirements, _, result = _run(artifacts, "Describe the Linux cron scheduling configuration.")
    assert requirements["scope"]["status"] == "mismatch"
    assert result["legacy_decision"]["decision"] == "proceed"
    assert result["final_decision"] == "abstain"
    assert result["abstention_stage"] == "topical_relevance"
    assert result["reason_codes"][0] == "requested_scope_mismatch"
    assert result["scope_assessment"] == requirements["scope"]


@pytest.mark.parametrize("query", [
    "Explain quantum chromodynamics.",
    "Compare Windows process creation with Linux cron.",
    "Do not discuss Linux cron; list all Windows review limitations.",
])
def test_unknown_negation_and_comparison_do_not_become_clear_scope_mismatch(artifacts, query):
    _, requirements, _, result = _run(artifacts, query)
    assert requirements["analysis_status"] in {"unsupported", "ambiguous"}
    assert requirements["scope"]["status"] != "mismatch"
    assert result["final_decision"] == "abstain"
    assert result["abstention_stage"] == "query_requirements"
    assert "requested_scope_mismatch" not in result["reason_codes"]
    assert any(code in result["reason_codes"] for code in (
        "query_requirements_unsupported", "query_requirements_ambiguous",
    ))


def test_ranked_signals_stay_exact_and_supplementary_counts_are_separate(artifacts):
    initial, _, before, _ = _run(artifacts, enabled=False)
    _, _, enriched, _ = _run(artifacts, enabled=True)
    old = extract_graphrag_gate_signals(initial)
    c, d = extract_query_evidence_signals(before), extract_query_evidence_signals(enriched)
    assert c["ranked_retrieval"] == d["ranked_retrieval"] == old
    assert c["final_evidence_context"]["supplementary_item_count"] == 0
    assert d["final_evidence_context"]["supplementary_item_count"] > 0
    assert d["final_evidence_context"]["final_item_count"] > c["final_evidence_context"]["final_item_count"]
    assert d["final_evidence_context"]["unranked_items_have_no_retrieval_scores_or_paths"] is True
    assert d["ranked_retrieval"]["topical_relevance"]["retrieval_hit_count"] == 1
    assert d["ranked_retrieval"]["evidence_answerability"] == old["evidence_answerability"]


def test_mismatched_query_rejected_before_support_can_change_result(artifacts):
    _, requirements, final, _ = _run(artifacts)
    changed = deepcopy(requirements)
    changed["query"] = "A different query about review limitations."
    with pytest.raises(QueryAwareGateError, match="query differs"):
        assess_query_aware_gate(final, changed, policy=PERMISSIVE_POLICY)


@pytest.mark.parametrize("mutation", ["changed_payload", "invalid_byte_count", "negative_budget", "invented_supplement_score"])
def test_modified_context_or_budget_is_rejected(artifacts, mutation):
    _, requirements, final, _ = _run(artifacts)
    if mutation == "changed_payload":
        final["final_items"][0]["payload"]["content"] += " fabricated replacement"
    elif mutation == "invalid_byte_count":
        final["budget"]["final_serialized_bytes"] += 1
    elif mutation == "negative_budget":
        final["budget"]["max_supplementary_items"] = -1
    else:
        # The same changed record must be mirrored in both collections so this
        # specifically tests forbidden ranking fields rather than list mismatch.
        final["supplementary_items"][0]["score"] = 0.99
        base_length = len(final["final_items"]) - len(final["supplementary_items"])
        final["final_items"][base_length] = deepcopy(final["supplementary_items"][0])
    with pytest.raises(QueryAwareGateError):
        assess_query_aware_gate(final, requirements, policy=PERMISSIVE_POLICY)


def test_runtime_uses_no_files_network_or_benchmark_annotations(artifacts, monkeypatch):
    import builtins
    import socket

    initial, requirements, final, expected = _run(artifacts)

    def forbidden(*args, **kwargs):
        raise AssertionError("runtime attempted external IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    corpus, _, graph, _ = artifacts
    repeated = enrich_query_context(initial, corpus, graph, requirements)
    assert assess_query_aware_gate(repeated, requirements, policy=PERMISSIVE_POLICY) == expected
    changed = deepcopy(requirements)
    changed["expected_decision"] = "proceed"
    with pytest.raises(QueryAwareGateError):
        assess_query_aware_gate(final, changed, policy=PERMISSIVE_POLICY)
    changed = deepcopy(final)
    changed["reference_answer"] = "Evaluation-only sentinel must not enter runtime."
    with pytest.raises(QueryAwareGateError):
        assess_query_aware_gate(changed, requirements, policy=PERMISSIVE_POLICY)


def test_legacy_golden_signals_and_init_bytes_remain_unchanged(artifacts):
    files = (LEGACY_CONTEXT, LEGACY_SIGNALS, LEGACY_INIT)
    before = {path: path.read_bytes() for path in files}
    golden_context = json.loads(before[LEGACY_CONTEXT])
    golden_signals = json.loads(before[LEGACY_SIGNALS])
    # The legacy signal fixture intentionally uses a transformed context in its
    # own suite; it is preserved here, not paired with a different input.
    original_signals = extract_graphrag_gate_signals(golden_context)
    assert original_signals["schema_version"] == golden_signals["schema_version"] == "graphrag-gate-signals/v1"
    _run(artifacts)
    assert extract_graphrag_gate_signals(golden_context) == original_signals
    assert {path: path.read_bytes() for path in files} == before
    assert not hasattr(__import__("threat_hunting.graphrag", fromlist=["enrich_query_context"]), "enrich_query_context")


def test_result_is_detached_from_requirements_policy_and_returned_evidence(artifacts):
    initial, requirements, final, result = _run(artifacts)
    before = deepcopy((initial, requirements, final, PERMISSIVE_POLICY))
    result["query_requirements"]["reason_codes"].append("caller mutation")
    result["legacy_decision"]["reason_codes"].append("caller mutation")
    result["signals"]["final_evidence_context"]["returned_evidence_ids"].append("caller mutation")
    assert (initial, requirements, final, PERMISSIVE_POLICY) == before
