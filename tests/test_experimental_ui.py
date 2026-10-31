"""Offline adapter safety, labeled states, shared generation, and HTTP isolation."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.llm.client import LLMClientError, LLMConnectionError, LLMProviderError, LLMTimeoutError
from threat_hunting.llm.config import LLMConfig
from threat_hunting.server import experimental as demo


@pytest.fixture
def session(monkeypatch, tmp_path):
    from historical_fixtures import require_frozen
    pilot = demo.read(demo.PILOT / "manifest.json")
    require_frozen(pilot, demo.ROOT, "rag-graphrag-pilot-source-contract-02 dashboard fixture")
    pin = pilot["model"]
    config = LLMConfig(**{k: pin[k] for k in ("provider", "model_name", "base_url", "temperature", "max_tokens", "timeout_seconds")}, api_key="synthetic-secret")
    monkeypatch.setattr(LLMConfig, "from_env", classmethod(lambda cls: config))
    # Output confinement uses ROOT only; real pinned paths/config stay untouched.
    monkeypatch.setattr(demo, "ROOT", tmp_path)
    (tmp_path / "configs/gate").mkdir(parents=True)
    (tmp_path / "configs/gate/two_stage_production_policy.json").write_bytes((pipeline.ROOT / "configs/gate/two_stage_production_policy.json").read_bytes())
    (tmp_path / "configs/runtime_artifacts.json").write_bytes((pipeline.ROOT / "configs/runtime_artifacts.json").read_bytes())
    monkeypatch.setattr(demo.ExperimentalSession, "presets", lambda self: [])
    return demo.ExperimentalSession(tmp_path / "outputs/demo/test-session", backend=SimpleNamespace(embed_documents=lambda _: []))


def request(query="Hãy viết thực đơn ăn chay cho ba ngày và tính lượng calo mỗi ngày."):
    return demo.ExperimentalRequest(query=query, scenario_id="regsvr32-c2", branch="rag")


def forbid_client(**kwargs):
    raise AssertionError("Offline/abstain must not construct LLM client")


def test_scope_abstain_never_constructs_provider_or_retrieves(session, monkeypatch):
    session.client_factory = forbid_client
    monkeypatch.setattr(pipeline, "load_vector_index", lambda _: pytest.fail("Scope abstain must precede retrieval"))
    response = session.run(request())
    assert response["outcome"] == "abstain"
    assert response["result"]["abstention_stage"] == "query_scope"
    assert response["context"] is None and response["report"] is None
    assert session.attempts == response["result"]["llm_http_attempts"] == 0
    assert response["provenance"]["benchmark_result"] is False


def mock_prepared(monkeypatch, *, gate="proceed", budget=False):
    monkeypatch.setattr(pipeline, "assess_query_scope", lambda *a, **kw: {"decision": "proceed"})
    def prepare(*args):
        emit = args[-1]
        emit("context", {"synthetic": True})
        emit("gate", {"decision": gate, "reason_codes": ["synthetic_fixture_only"]})
        emit("eligibility", {"decision": "abstain" if budget else gate, "budget_exceeded": budget})
        return {"row": {"gate_decision": gate, "eligibility_decision": gate}, "budget_exceeded": budget,
                "gate": {"decision": gate}, "context": {}, "messages": []}
    monkeypatch.setattr(pipeline, "prepare_branch", prepare)


@pytest.mark.parametrize("gate,budget,expected", [("proceed", False, "dry_run_no_generation"), ("abstain", False, "abstain"), ("proceed", True, "abstain")])
def test_offline_gate_and_budget_never_call_llm(session, monkeypatch, gate, budget, expected):
    mock_prepared(monkeypatch, gate=gate, budget=budget)
    session.client_factory = forbid_client
    response = session.run(request("Synthetic request"))
    assert response["outcome"] == expected
    assert response["report"] is None
    assert response["result"]["llm_http_attempts"] == session.attempts == 0
    if budget:
        assert response["gate"]["decision"] == "proceed"
        assert response["result"]["eligibility_decision"] == "abstain"


@pytest.mark.parametrize("outcome", demo.FIXTURE_IDS)
def test_labeled_fixtures_never_claim_live_generation_or_return_rejection_as_answer(session, outcome):
    payload = demo.synthetic_fixture(outcome, session.metadata())
    assert payload["provenance"]["mode"] == "synthetic_fixture"
    assert payload["provenance"]["llm_requests"] == 0
    assert payload["result"]["fallback_used"] is False
    assert bool(payload["report"]) == (outcome == "accepted_draft")
    assert payload["human_review_required"] is True
    if outcome == "validation_failed":
        assert payload["diagnostic"] and payload["report"] is None


@pytest.mark.parametrize("error,expected,stop", [
    (LLMProviderError(429), "rate_limited", "provider_http_429"),
    (LLMProviderError(401), "provider_error", "provider_http_401"),
    (LLMProviderError(403), "provider_error", "provider_http_403"),
    (LLMProviderError(503), "provider_error", None),
    (LLMClientError("Synthetic protocol error"), "provider_error", None),
    (LLMConnectionError("Synthetic connection error"), "provider_error", None),
    (LLMTimeoutError("Synthetic timeout"), "provider_error", None),
])
def test_session_uses_shared_generation_classification_and_stop_latch(session, monkeypatch, error, expected, stop):
    mock_prepared(monkeypatch)
    calls = []
    class Provider:
        def __init__(self, *, config):
            assert config.max_retries == 1
            self.last_attempt_count = 0
        def generate(self, messages):
            calls.append(messages)
            self.last_attempt_count = 1
            raise error
    session.live, session.max_requests, session.client_factory = True, 2, Provider
    response = session.run(request("Synthetic request"))
    assert response["outcome"] == expected
    assert session.stopped == stop
    assert response["report"] is None
    assert session.attempts == len(calls) == 1
    if stop:
        later = session.run(request("Synthetic request"))
        assert later["outcome"] == "not_run_after_stop"
        assert later["result"]["llm_http_attempts"] == 0
        assert len(calls) == 1


def test_cap_prevents_second_generation(session, monkeypatch):
    mock_prepared(monkeypatch)
    class Provider:
        def __init__(self, **kw): self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            return '{"verdict":"INSUFFICIENT_EVIDENCE","executive_summary":"","technical_analysis":""}'
    session.live, session.max_requests, session.client_factory = True, 1, Provider
    first = session.run(request("Synthetic request"))
    second = session.run(request("Synthetic request"))
    assert first["outcome"] == "accepted_draft" and first["report"]
    assert second["outcome"] == "not_run_request_limit" and second["report"] is None
    assert session.attempts == 1


@pytest.mark.parametrize("content", ['not JSON', '{"verdict":"invented_verdict"}', '{"verdict":"SUSPICIOUS","evidence_refs":["invented-reference"]}'])
def test_json_schema_and_guardrail_failure_are_rejected(session, monkeypatch, content):
    mock_prepared(monkeypatch)
    class Provider:
        def __init__(self, **kw): self.last_attempt_count = 0
        def generate(self, messages):
            self.last_attempt_count = 1
            return content
    session.live, session.max_requests, session.client_factory = True, 1, Provider
    result = session.run(request("Synthetic request"))
    assert result["outcome"] == "validation_failed"
    assert result["report"] is None and result["diagnostic"]
    assert result["result"]["llm_http_attempts"] == 1


def test_http_isolation_unknown_inputs_and_fixture_states(session, monkeypatch):
    # Static directory is real; output ROOT remains synthetic.
    monkeypatch.setattr(demo, "ROOT", pipeline.ROOT)
    with TestClient(demo.create_app(session)) as client:
        assert client.get('/experimental.html').status_code == 200
        assert client.get('/experimental-api/config').json()['mode'] == 'experimental_offline_demo'
        assert client.post('/api/hunt', json={}).status_code in (404, 405)
        assert client.get('/api/hunt/stream').status_code == 404
        assert client.get('/.env').status_code == 404
        assert client.post('/experimental-api/hunt', json={**request().model_dump(), 'enforce_gate': False}).status_code == 422
        assert client.post('/experimental-api/hunt', json={**request().model_dump(), 'branch': 'unknown'}).status_code == 422
        assert client.get('/experimental-api/fixture?outcome=unknown').status_code == 404
        for outcome in demo.FIXTURE_IDS:
            assert client.get('/experimental-api/fixture', params={'outcome': outcome}).json()['outcome'] == outcome


def test_response_hides_rejected_report_even_with_sanitized_content(session):
    artifacts = {'validation': {'status': 'validation_failed', 'sanitized_report': {'direct_answer': 'REJECTED'}, 'issues': []}}
    row = {'outcome': 'validation_failed'}
    result = demo.response_payload(request(), row, artifacts, session.metadata(), {'mode': 'synthetic_fixture'})
    assert result['report'] is None
    assert result['diagnostic']['sanitized_report']['direct_answer'] == 'REJECTED'
