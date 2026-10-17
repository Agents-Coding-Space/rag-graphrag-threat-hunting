"""Unit tests for FastAPI Threat Hunting SOC endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threat_hunting.server.app import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "threat-hunting-graphrag-backend"


def test_list_scenarios_endpoint(client):
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 3
    scen_ids = {s["scenario_id"] for s in data}
    assert "mshta-powershell" in scen_ids
    assert "purplesharp-ad" in scen_ids
    assert "regsvr32-c2" in scen_ids


def test_get_graph_endpoint(client):
    resp = client.get("/api/graph?scenario_id=mshta-powershell")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "mshta-powershell"
    assert data["node_count"] > 0
    assert data["edge_count"] > 0
    assert len(data["elements"]) > 0

    first_elem = data["elements"][0]
    assert "data" in first_elem
    assert "id" in first_elem["data"]


def test_get_evidence_endpoint(client):
    resp = client.get("/api/evidence?scenario_id=mshta-powershell")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "mshta-powershell"
    assert data["evidence_count"] > 0
    assert len(data["evidence_items"]) > 0
    assert "observations" in data["evidence_items"][0]


def test_hunt_endpoint_proceed(client):
    payload = {
        "query": "Which process chain led to powershell.exe in the reviewed evidence?",
        "scenario_id": "mshta-powershell",
        "enforce_gate": True,
        "use_llm": False,
    }
    resp = client.post("/api/hunt", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "proceed"
    assert data["scenario_id"] == "mshta-powershell"
    assert len(data["retrieval_hits"]) > 0
    assert data["subgraph"] is not None
    assert data["subgraph"]["node_count"] > 0


def test_hunt_endpoint_abstained(client):
    payload = {
        "query": "Thời tiết ngày mai ở Hà Nội thế nào?",
        "scenario_id": "mshta-powershell",
        "enforce_gate": True,
        "use_llm": False,
    }
    resp = client.post("/api/hunt", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "abstained"
    assert "reason" in data
    assert data["subgraph"] is None
