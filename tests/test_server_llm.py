"""Exercise backend LLM synthesis using synthetic context and no provider calls."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient


FALLBACK_ENGINE = "Rule-Guided Forensic Synthesizer (Offline Fallback)"
MODEL_ENGINE = "fixture-model (http://fixture.invalid/v1)"


@pytest.fixture
def synthetic_backend(monkeypatch, tmp_path):
    server = importlib.import_module("threat_hunting.server.app")
    scenario_id = "synthetic-connectivity"
    monkeypatch.setattr(server, "SCENARIO_REGISTRY", {
        scenario_id: {
            "corpus_path": tmp_path / "unused-corpus.json",
            "graph_path": tmp_path / "unused-graph.json",
            "index_path": tmp_path / "unused-index.json",
        },
    })
    monkeypatch.setattr(server, "GATE_POLICY_PATH", tmp_path / "absent-policy.json")
    for loader_name in ("load_retrieval_corpus", "load_knowledge_graph", "load_vector_index"):
        monkeypatch.setattr(server, loader_name, Mock(return_value={}))
    monkeypatch.setattr(server, "digest", Mock(return_value="0" * 64))
    embedding_backend = Mock()
    monkeypatch.setattr(server, "get_embedding_backend", Mock(return_value=embedding_backend))
    context = {
        "retrieval": {
            "hits": [{
                "chunk": {
                    "chunk_id": "synthetic-note",
                    "chunk_type": "note",
                    "content": "Synthetic connectivity test only; no security log data.",
                    "source": {"json_pointer": "/synthetic/note"},
                },
                "score": 1.0,
            }],
        },
        "traversal": {"nodes": [], "edges": []},
    }
    monkeypatch.setattr(server, "build_graphrag_context", Mock(return_value=context))
    client = TestClient(server.app)
    request = {
        "query": "Summarize the evidence.",
        "scenario_id": scenario_id,
        "enforce_gate": True,
        "use_llm": True,
    }
    yield server, client, request
    embedding_backend.embed_documents.assert_not_called()
    client.close()


@pytest.fixture
def valid_report():
    return {
        "schema_version": "threat-hunting-report/v1",
        "verdict": "BENIGN",
        "direct_answer": "This is a synthetic connectivity note.",
        "executive_summary": "Synthetic connectivity check.",
        "technical_analysis": "The supplied note contains no security log data.",
        "attack_chain": [],
        "mitre_mappings": [],
        "sigma_matches": [],
        "containment_recommendations": [],
        "unverified_claims": [],
        "evidence_refs": ["/synthetic/note"],
    }


def install_client(monkeypatch, server, *, report=None, error=None):
    llm_client = Mock()
    llm_client.config = SimpleNamespace(
        model_name="fixture-model", base_url="http://fixture.invalid/v1",
    )
    llm_client.generate_json = Mock(return_value=report, side_effect=error)
    constructor = Mock(return_value=llm_client)
    monkeypatch.setattr(server, "LLMClient", constructor)
    return llm_client


def post_hunt(client, request, expected_status="proceed"):
    response = client.post("/api/hunt", json=request)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == expected_status
    return body["report"]


def test_backend_identifies_successful_llm_report(synthetic_backend, valid_report, monkeypatch):
    server, client, request = synthetic_backend
    llm_client = install_client(monkeypatch, server, report=valid_report)

    report = post_hunt(client, request)

    llm_client.generate_json.assert_called_once()
    assert report["ai_engine"] == MODEL_ENGINE
    assert report["verdict"] == "BENIGN"
    assert report["evidence_refs"] == ["/synthetic/note"]


def test_answerable_network_question_allows_a_short_report(synthetic_backend, valid_report, monkeypatch):
    """Mocked model output verifies the accepted path, not model compliance."""
    server, client, request = synthetic_backend
    context = {"retrieval": {"hits": [{"chunk": {"chunk_id": "fixture-network", "chunk_type": "fact",
        "content": "kestrel.exe connected to 192.0.2.7:8444; HTTP completion is unverified.",
        "source": {"json_pointer": "/facts/0", "object_id": "fixture-network-fact"},
        "metadata": {"source_observations": [{"source_file": "fixture.json", "raw_record_ref": "jsonl:line:1",
            "canonical_fields": {"event_id": "3", "process_name": "kestrel.exe", "destination_ip": "192.0.2.7", "destination_port": 8444}}]}}, "score": 1.0}]},
        "traversal": {"nodes": [], "edges": []}}
    server.build_graphrag_context.return_value = context
    request["query"] = "What network endpoint did kestrel.exe connect to?"
    valid_report.update(direct_answer="192.0.2.7:8444 (/facts/0)", executive_summary="", technical_analysis="",
        evidence_refs=["/facts/0"], attack_chain=[], mitre_mappings=[], containment_recommendations=[])
    llm = install_client(monkeypatch, server, report=valid_report)
    body = client.post("/api/hunt", json=request).json()
    assert body["status"] == "proceed"
    assert body["validation"]["status"] == "passed"
    assert body["report"]["direct_answer"] == valid_report["direct_answer"]
    assert body["report"]["attack_chain"] == body["report"]["mitre_mappings"] == []
    llm.generate_json.assert_called_once()


def test_backend_identifies_provider_failure_fallback(synthetic_backend, monkeypatch):
    server, client, request = synthetic_backend
    llm_client = install_client(monkeypatch, server, error=RuntimeError("Synthetic provider failure"))

    report = post_hunt(client, request, "validation_failed")

    llm_client.generate_json.assert_called_once()
    assert report["ai_engine"] == FALLBACK_ENGINE
    assert report["verdict"] is None


def test_backend_handles_client_initialization_failure(synthetic_backend, monkeypatch):
    server, client, request = synthetic_backend
    constructor = Mock(side_effect=RuntimeError("Synthetic initialization failure"))
    monkeypatch.setattr(server, "LLMClient", constructor)

    report = post_hunt(client, request, "validation_failed")

    constructor.assert_called_once_with()
    assert report["ai_engine"] == FALLBACK_ENGINE
    assert report["verdict"] is None


def test_backend_keeps_report_schema_validation(synthetic_backend, valid_report, monkeypatch):
    server, client, request = synthetic_backend
    valid_report["verdict"] = "INVALID_VERDICT"
    install_client(monkeypatch, server, report=valid_report)

    report = post_hunt(client, request, "validation_failed")

    assert report["ai_engine"] == FALLBACK_ENGINE
    assert report["verdict"] is None


def test_backend_keeps_citation_guardrail(synthetic_backend, valid_report, monkeypatch):
    server, client, request = synthetic_backend
    valid_report["evidence_refs"] = ["unsupported-synthetic-reference"]
    install_client(monkeypatch, server, report=valid_report)

    report = post_hunt(client, request, "validation_failed")

    assert report["ai_engine"] == MODEL_ENGINE
    assert report["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any("unsupported-synthetic-reference" in warning for warning in report["unverified_claims"])
    assert report["evidence_refs"] == []


def test_backend_rate_limit_is_operational_failure(synthetic_backend, monkeypatch):
    from threat_hunting.llm import LLMProviderError
    server, client, request = synthetic_backend
    llm = install_client(monkeypatch, server, error=LLMProviderError(429, retry_after_seconds=60))
    llm.last_attempt_count = 1
    body = client.post("/api/hunt", json=request).json()
    assert body["status"] == "provider_error"
    assert body["provider_error"] == {"kind": "rate_limited", "http_status": 429, "retry_after_seconds": 60, "automatic_retry": False}
    assert body["report"]["verdict"] is None
    assert body["execution"]["source"] == "offline_fallback"
    assert body["execution"]["fallback_used"] is True
    assert body["execution"]["llm_called"] is True
    assert body["execution"]["llm_http_attempts"] == 1
    assert body["validation"]["status"] == "not_run"
    llm.generate_json.assert_called_once()


@pytest.mark.parametrize("error_name,kind", [("LLMConnectionError", "connection_error"), ("LLMTimeoutError", "timeout")])
def test_backend_transport_error_is_not_evidence_insufficiency(synthetic_backend, monkeypatch, error_name, kind):
    import threat_hunting.llm as llm_module
    server, client, request = synthetic_backend
    llm = install_client(monkeypatch, server, error=getattr(llm_module, error_name)("synthetic"))
    llm.last_attempt_count = 1
    body = client.post("/api/hunt", json=request).json()
    assert body["status"] == "provider_error"
    assert body["provider_error"]["kind"] == kind
    assert body["report"]["verdict"] is None
    assert body["execution"]["source"] == "offline_fallback"


@pytest.mark.parametrize("query", [
    "How do I prune a lemon tree?", "Write a poem about mshta.exe.", "How can I cook rice?",
    "Hãy viết thực đơn ăn chay cho ba ngày và tính lượng calo mỗi ngày.",
])
def test_backend_scope_stops_before_embedding_and_llm(synthetic_backend, monkeypatch, query):
    server, client, request = synthetic_backend
    llm_constructor = Mock()
    monkeypatch.setattr(server, "LLMClient", llm_constructor)
    request["query"] = query
    body = client.post("/api/hunt", json=request).json()
    assert body["status"] == "abstained"
    assert body["scope_decision"]["decision"] == "abstain"
    assert body["execution"]["llm_called"] is False
    assert body["execution"]["llm_http_attempts"] == 0
    llm_constructor.assert_not_called()
    server.get_embedding_backend.assert_not_called()
