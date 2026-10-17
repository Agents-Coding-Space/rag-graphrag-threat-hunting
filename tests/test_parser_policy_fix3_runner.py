"""Research-runner boundaries, using synthetic evidence and no benchmark labels."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).resolve().parents[1] / "scripts/evaluate_parser_policy_fix3.py"
    spec = importlib.util.spec_from_file_location("fix3_research_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_context_measurement_uses_utf8_payloads_and_separates_unranked_items():
    module = _module()
    items = [{"kind": "chunk", "payload": {"content": "Giới hạn bằng chứng"}}]
    context = {"final_items": items, "supplementary_items": deepcopy(items), "incomplete_context": True}
    measured = module.context_metrics(context)
    assert measured == {
        "serialized_final_items_utf8_bytes": len(json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        "supplementary_item_count": 1, "final_item_count": 1, "incomplete_context": True,
    }
    assert measured["serialized_final_items_utf8_bytes"] > len(module.encoded(items).decode("utf-8"))
    assert not {"cosine", "rrf", "bm25", "probability"}.intersection(measured)


@pytest.mark.parametrize("parser_status,scope,support_status,legacy_decision,expected,reason", [
    ("supported", "unspecified", "supported", "proceed", "proceed", None),
    ("supported", "in_scope", "supported", "abstain", "abstain", "legacy_quality_gate_abstained"),
    ("ambiguous", "in_scope", "supported", "proceed", "abstain", "query_requirements_ambiguous"),
    ("unsupported", "in_scope", "supported", "proceed", "abstain", "query_requirements_unsupported"),
    ("supported", "mismatch", "supported", "proceed", "abstain", "requested_scope_mismatch"),
    ("supported", "ambiguous", "supported", "proceed", "abstain", "query_scope_ambiguous"),
    ("supported", "in_scope", "missing", "proceed", "abstain", "required_evidence_missing"),
    ("supported", "in_scope", "unknown", "proceed", "abstain", "required_evidence_unknown"),
])
def test_E1_adapter_retains_AND_quality_and_unresolved_requirement_blockers(
    monkeypatch, parser_status, scope, support_status, legacy_decision, expected, reason,
):
    module = _module()
    initial = {"query": {"text": "Synthetic query"}}
    context = {"initial_context": initial}
    requirements = {"analysis_status": parser_status, "scope": {"status": scope}}
    policy = {"synthetic": True}
    legacy = {"decision": legacy_decision, "abstention_stage": "topical_relevance" if legacy_decision == "abstain" else None}
    support = {"status": support_status}
    calls = []

    def evidence(req, ctx, *, max_chain_depth):
        calls.append((req, ctx, max_chain_depth))
        return deepcopy(support)

    monkeypatch.setattr(module, "extract_graphrag_gate_signals", lambda value: {"ranked_only": value is initial})
    monkeypatch.setattr(module, "assess_graphrag_two_stage_gate", lambda signals, *, policy: deepcopy(legacy))
    monkeypatch.setattr(module, "assess_evidence_support_v2", evidence)
    result = module.and_legacy_v2(context, requirements, policy, max_chain_depth=8)
    assert calls == [(requirements, context, 8)]
    assert result["final_decision"] == expected
    assert result["legacy_decision"] == legacy
    assert result["support_assessment"] == support
    assert result["security_conclusion_made"] is False
    assert (reason in result["reason_codes"]) if reason else not result["reason_codes"]


def test_runner_refuses_to_overwrite_a_completed_experiment_before_reading_sources(tmp_path, monkeypatch):
    module = _module()
    completed = tmp_path / "ablation_results.json"
    completed.write_bytes(b'{"preserved": true}\n')
    monkeypatch.setattr(module, "OUT", tmp_path)

    def forbidden():
        raise AssertionError("Read sources before enforcing completed-run protection")

    monkeypatch.setattr(module, "load_inputs", forbidden)
    with pytest.raises(AssertionError, match="overwrite completed"):
        module.main()
    assert completed.read_bytes() == b'{"preserved": true}\n'


def test_only_external_adapter_joins_rubric_to_returned_evidence():
    module = _module()
    helper = module.old_helpers()
    context = {"final_items": []}
    projection = helper.evaluation_context_projection(context)
    assert projection["retrieval"]["hits"] == []
    assert projection["metadata"]["evaluation_only_projection"] is True
    assert projection["metadata"]["not_a_ranked_retrieval_result"] is True
    assert context == {"final_items": []}
