"""Comparison adapters, stop rules and denominator checks; no real providers."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from threat_hunting.evaluation import experimental_comparison as comparison
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate
from threat_hunting.llm.client import LLMProviderError
from threat_hunting.llm.config import LLMConfig
from threat_hunting.llm.guardrail import context_catalog

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def source_context():
    return json.loads((ROOT / "tests/fixtures/graphrag/orchestrator/expected_graphrag_context.json").read_text(encoding="utf-8"))


def corpus_for(context):
    return {"corpus_id": context["corpus_id"], "scenario_id": context["scenario_id"],
            "source_ground_truth": context["source_ground_truth"]}


def policy():
    doc = json.loads((ROOT / "configs/gate/two_stage_production_policy.json").read_text(encoding="utf-8"))
    return {key: doc[key] for key in ("schema_version", "policy_id", "topical_relevance", "evidence_answerability")}


def test_retrieval_only_rag_never_receives_graph_aliases(source_context):
    original = deepcopy(source_context)
    rag = comparison.rag_context(source_context["retrieval"], corpus_for(source_context), "no-graph")
    assert rag["traversal"] is None
    assert rag["seed_mapping"]["hit_mappings"] == []
    assert rag["retrieval"] == source_context["retrieval"]
    assert source_context == original
    supplied = comparison.supplied_context(rag)
    assert supplied["traversal"] == {}
    retrieval_aliases = context_catalog({"retrieval": source_context["retrieval"]})
    assert context_catalog(supplied) == retrieval_aliases
    graph_only = next(n["node_id"] for n in source_context["traversal"]["nodes"])
    assert graph_only not in context_catalog(supplied)


def test_unchanged_graph_dependent_gate_rejects_rag(source_context):
    rag = comparison.rag_context(source_context["retrieval"], corpus_for(source_context), "no-graph")
    signals = extract_graphrag_gate_signals(rag)
    result = assess_graphrag_two_stage_gate(signals, policy=policy())
    assert result["decision"] == "abstain"
    assert signals["evidence_answerability"]["traversal_performed"] is False
    assert signals["evidence_answerability"]["seed_node_count"] == 0


def test_rejected_values_retained_before_sanitization(source_context):
    rag = comparison.supplied_context(comparison.rag_context(source_context["retrieval"], corpus_for(source_context), "no-graph"))
    raw = {"verdict": "SUSPICIOUS", "executive_summary": "", "technical_analysis": "",
           "evidence_refs": ["unretrieved-graph-reference"], "sigma_matches": ["unverified-rule"]}
    before = deepcopy(raw)
    checked = comparison.validate_generated(raw, rag)
    assert checked["status"] == "validation_failed"
    assert checked["raw_report_before_sanitize"] == before == raw
    assert checked["sanitized_report"]["evidence_refs"] == []
    assert checked["sanitized_report"]["sigma_matches"] == []
    assert checked["human_review_required"] is True


def test_gate_metrics_exclude_permissible_overreach_from_mandatory_denominator():
    cases = [{"case_id": "A", "category": "answerable"}, {"case_id": "O", "category": "out_of_scope"}, {"case_id": "L", "category": "overreach"}]
    rows = [{"case_id": c["case_id"], "branch": b, "gate_decision": "proceed" if c["case_id"] != "A" else "abstain",
             "outcome": "fallback"} for c in cases for b in comparison.BRANCHES]
    metrics = comparison.gate_metrics(rows, cases)
    for item in metrics.values():
        assert item["mandatory_gate_accuracy"] == {"numerator": 0, "denominator": 2}
        assert item["false_proceed"]["numerator"] == item["false_abstain"]["numerator"] == 1
        assert item["false_proceed"]["denominator"] == item["false_abstain"]["denominator"] == 1
        assert item["accepted_draft_coverage"] == {"numerator": 0, "denominator": 3}
        assert item["overreach_permissible_either"] == {"proceed": 1}


@pytest.fixture
def prepared_run(monkeypatch, tmp_path, source_context):
    """Small synthetic benchmark has no copied raw logs or remote dependencies."""
    monkeypatch.setattr(comparison, "ROOT", tmp_path)
    monkeypatch.setattr(comparison, "_code_manifest", lambda: {})
    sid = source_context["scenario_id"]
    source_files = {}
    for name in ("gt_path", "corpus_path", "graph_path", "index_path"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        source_files[name] = path
    monkeypatch.setattr(comparison, "_runtime_sources", lambda: {sid: source_files})
    monkeypatch.setattr(comparison, "load_retrieval_corpus", lambda _: corpus_for(source_context))
    monkeypatch.setattr(comparison, "load_knowledge_graph", lambda _: {})
    monkeypatch.setattr(comparison, "load_vector_index", lambda _: {"embedding": {
        "model_id": "synthetic", "model_revision": "a" * 40, "dimension": 3}})
    monkeypatch.setattr(comparison, "assess_query_scope", lambda *args, **kwargs: {"decision": "proceed"})
    monkeypatch.setattr(comparison, "retrieve_hybrid", lambda *args, **kwargs: deepcopy(source_context["retrieval"]))
    monkeypatch.setattr(comparison, "build_graphrag_context", lambda *args, **kwargs: deepcopy(source_context))
    # This synthetic run isolates stop/budget logic rather than production gate thresholds.
    monkeypatch.setattr(comparison, "assess_graphrag_two_stage_gate", lambda *args, **kwargs: {"decision": "proceed"})
    monkeypatch.setattr(LLMConfig, "from_env", classmethod(lambda cls: cls(model_name="synthetic", api_key="test-secret", max_retries=9)))
    benchmark = {"cases": [{"case_id": f"C{i:02d}", "scenario_id": sid, "category": "answerable",
                 "request": {"query": source_context["query"]["text"]}} for i in range(15)]}
    (tmp_path / "cases.json").write_text(json.dumps(benchmark), encoding="utf-8")
    (tmp_path / "policy.json").write_text(json.dumps(policy()), encoding="utf-8")
    (tmp_path / "runtime.json").write_text("{}", encoding="utf-8")
    config = {"branches": list(comparison.BRANCHES), "maximum_llm_requests": 30, "expected_case_count": 15,
              "benchmark": "cases.json", "gate_policy": "policy.json", "runtime_artifacts": "runtime.json",
              "retrieval": {"top_k": 5, "candidate_k": 20}, "graph_expansion": {},
              "maximum_context_utf8_bytes": 262144, "maximum_messages_utf8_bytes": 294912,
              "interpretation": "synthetic test only"}
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    embedding = lambda **kwargs: SimpleNamespace(load=lambda: None, embed_documents=lambda _: [])
    return config_path, tmp_path / "output", embedding


def test_offline_never_constructs_provider_and_preserves_input(prepared_run):
    config, output, embedding = prepared_run
    before = comparison.sha256(config.parent / "cases.json")
    def forbidden(**kwargs):
        raise AssertionError("offline provider must not be constructed")
    result = comparison.run_comparison(config, output, embedding_factory=embedding, client_factory=forbidden)
    assert result["llm_http_attempts"] == 0
    assert result["maximum_llm_requests"] == 0
    assert result["harness_request_ceiling"] == 30
    assert len(result["rows"]) == 30
    assert {r["outcome"] for r in result["rows"]} == {"dry_run_no_generation"}
    assert before == comparison.sha256(config.parent / "cases.json")
    assert "test-secret" not in (output / "manifest.json").read_text(encoding="utf-8")
    assert result["runtime_artifacts_unchanged"] is True
    with pytest.raises(FileExistsError):
        comparison.run_comparison(config, output, embedding_factory=embedding, client_factory=forbidden)


@pytest.mark.parametrize("status", [401, 403, 429, 503])
def test_authentication_or_rate_limit_stops_all_later_requests(prepared_run, status):
    config, output, embedding = prepared_run
    class Provider:
        calls = 0
        def __init__(self, *, config):
            assert config.max_retries == 1
            self.last_attempt_count = 0
        def generate(self, messages):
            type(self).calls += 1
            self.last_attempt_count += 1
            raise LLMProviderError(status)
    result = comparison.run_comparison(config, output, live=True, max_requests=30,
                                       embedding_factory=embedding, client_factory=Provider)
    assert Provider.calls == result["llm_http_attempts"] == 1
    assert result["stopped_reason"] == f"provider_http_{status}"
    assert sum(r["outcome"] == "not_run" for r in result["rows"]) == 29
    assert result["rows"][0]["outcome"] == ("rate_limited" if status == 429 else "provider_error")


def test_live_request_budget_no_fallback(prepared_run):
    config, output, embedding = prepared_run
    class Provider:
        def __init__(self, *, config):
            self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            return '{"verdict":"INSUFFICIENT_EVIDENCE","executive_summary":"","technical_analysis":""}'
    result = comparison.run_comparison(config, output, live=True, max_requests=2,
                                       embedding_factory=embedding, client_factory=Provider)
    assert result["llm_http_attempts"] == 2
    assert result["maximum_llm_requests"] == 2
    assert result["harness_request_ceiling"] == 30
    assert sum(r["outcome"] == "accepted_draft" for r in result["rows"]) == 2
    assert sum(r["outcome"] == "not_run_request_limit" for r in result["rows"]) == 28
    assert not any(r["fallback_used"] for r in result["rows"])


def test_safe_configuration_omits_credentials():
    config = LLMConfig(model_name="test", api_key="hidden", base_url="https://user:password@example.test:443/v1?key=hidden#hidden")
    public = comparison._safe_config(config)
    assert public["base_url"] == "https://example.test:443/v1"
    assert "hidden" not in json.dumps(public)
    assert "password" not in json.dumps(public)


def test_budget_abstention_keeps_original_policy_decision(prepared_run):
    config_path, output, embedding = prepared_run
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["maximum_context_utf8_bytes"] = 1
    config_path.write_text(json.dumps(config), encoding="utf-8")
    result = comparison.run_comparison(config_path, output, embedding_factory=embedding)
    first = result["rows"][0]
    assert first["gate_decision"] == first["policy_gate_decision"] == "proceed"
    assert first["eligibility_decision"] == "abstain"
    assert first["abstention_stage"] == "context_budget"
    assert result["eligible_branch_count"] == 0
    assert result["llm_http_attempts"] == 0
    eligibility = json.loads((output / f"{first['case_id']}_{first['branch']}" / "eligibility.json").read_text(encoding="utf-8"))
    assert eligibility["budget_exceeded"] is True
    assert eligibility["policy_decision"] == "proceed"


def test_provider_protocol_failure_is_not_model_validation_failure(prepared_run):
    config, output, embedding = prepared_run
    class Provider:
        def __init__(self, *, config):
            self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            raise comparison.LLMClientError("Incomplete SSE completion")
    result = comparison.run_comparison(config, output, live=True, max_requests=1,
                                       embedding_factory=embedding, client_factory=Provider)
    assert result["llm_http_attempts"] == 1
    assert result["rows"][0]["outcome"] == "provider_error"
    assert result["rows"][0]["provider_error"]["kind"] == "protocol_error"
    assert not any(row["outcome"] == "accepted_draft" for row in result["rows"])


def test_source_contract_refuses_order_biased_live_cap_before_any_work(prepared_run):
    config_path, output, embedding = prepared_run
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["gate_contract"] = "source-evidence-contract/v1"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="case-pair subset"):
        comparison.run_comparison(config_path, output, live=True, max_requests=12, embedding_factory=embedding)
    assert not output.exists()


def test_predeclared_pilot_runs_both_selected_branches_only(prepared_run, monkeypatch):
    from threat_hunting.evaluation import evidence_contract
    config_path, output, embedding = prepared_run
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["gate_contract"] = "source-evidence-contract/v1"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    calls = []
    def source_gate(query, context, legacy):
        calls.append(deepcopy(context))
        return {"decision": "proceed", "reason_codes": [], "abstention_stage": None}, {"units": []}
    monkeypatch.setattr(evidence_contract, "assess_source_evidence_gate", source_gate)
    class Provider:
        def __init__(self, *, config): self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            return '{"verdict":"INSUFFICIENT_EVIDENCE","executive_summary":"","technical_analysis":""}'
    result = comparison.run_comparison(config_path, output, live=True, max_requests=4,
        case_ids=("C01", "C00"), embedding_factory=embedding, client_factory=Provider)
    assert result["planned_branch_count"] == result["llm_http_attempts"] == 4
    assert result["maximum_llm_requests"] == 4
    assert result["harness_request_ceiling"] == 30
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["limits"]["maximum_llm_requests"] == 4
    assert manifest["limits"]["configured_request_budget"] == 4
    assert manifest["limits"]["harness_request_ceiling"] == 30
    assert {r["case_id"] for r in result["rows"]} == {"C01", "C00"}
    assert all(r["outcome"] == "accepted_draft" for r in result["rows"])
    assert len(calls) == 4
    assert sum(c["traversal"] == {} for c in calls) == 2
    assert (output / "C01_rag" / "legacy_gate.json").is_file()
    assert (output / "C01_rag" / "evidence_contract.json").is_file()


@pytest.mark.parametrize("live,cap,expected,prefix", [(True, 4, 4, "Live execution:"), (False, 4, 0, "Offline dry-run:")])
def test_reporting_metadata_names_effective_cap_and_actual_mode(live, cap, expected, prefix):
    metadata = comparison.run_reporting_metadata(live=live, max_requests=cap, harness_ceiling=30,
        interpretation="Offline corrective regression with unchanged protocol.")
    assert metadata["maximum_llm_requests"] == expected
    assert metadata["harness_request_ceiling"] == 30
    assert metadata["configured_request_budget"] == cap
    assert metadata["warning"].startswith(prefix)
    assert metadata["warning"].endswith("corrective regression with unchanged protocol.")
    if live:
        assert "Offline" not in metadata["warning"]


def test_interval_applies_only_between_attempts_and_abstain_does_not_add_wait(prepared_run, monkeypatch):
    config, output, embedding = prepared_run
    clock = {"now": 0.0, "scope_calls": 0}
    sleeps, starts = [], []
    def scope(*args, **kwargs):
        clock["scope_calls"] += 1
        if clock["scope_calls"] == 2:
            clock["now"] += 10
            return {"decision": "abstain"}
        return {"decision": "proceed"}
    monkeypatch.setattr(comparison, "assess_query_scope", scope)
    def sleep(seconds):
        sleeps.append(seconds)
        clock["now"] += seconds
    class Provider:
        def __init__(self, **kwargs): self.last_attempt_count = 0
        def generate(self, messages):
            starts.append(clock["now"])
            self.last_attempt_count = 1
            clock["now"] += 2
            return '{"verdict":"INSUFFICIENT_EVIDENCE","executive_summary":"","technical_analysis":""}'
    result = comparison.run_comparison(config, output, live=True, max_requests=2,
        embedding_factory=embedding, client_factory=Provider, request_interval_seconds=60,
        clock=lambda: clock["now"], sleep=sleep)
    assert starts == [0, 62]
    assert sum(sleeps) == 50
    assert result["rows"][1]["outcome"] == "abstain"
    assert result["llm_http_attempts"] == 2


def test_explicit_branch_keys_never_generate_the_successful_sibling(prepared_run):
    config, output, embedding = prepared_run
    class Provider:
        def __init__(self, **kwargs): self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            return '{"verdict":"INSUFFICIENT_EVIDENCE","executive_summary":"","technical_analysis":""}'
    result = comparison.run_comparison(config, output, live=True, max_requests=2,
        branch_keys=(("C00", "graphrag"), ("C01", "rag")), embedding_factory=embedding, client_factory=Provider)
    assert result["planned_branch_count"] == result["llm_http_attempts"] == 2
    assert {(r["case_id"], r["branch"]) for r in result["rows"]} == {("C00", "graphrag"), ("C01", "rag")}
    assert not (output / "C00_rag").exists() and not (output / "C01_graphrag").exists()
