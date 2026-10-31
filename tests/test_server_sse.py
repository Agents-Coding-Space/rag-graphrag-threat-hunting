"""Unit tests for FastAPI SSE Streaming endpoint."""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from threat_hunting.server.app import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def parse_sse_events(text: str) -> list[tuple[str, dict]]:
    events = []
    blocks = text.strip().split("\n\n")
    for block in blocks:
        lines = block.strip().split("\n")
        event_type = "message"
        data_str = ""
        for line in lines:
            if line.startswith("event: "):
                event_type = line[len("event: "):].strip()
            elif line.startswith("data: "):
                data_str = line[len("data: "):].strip()
        if data_str:
            try:
                events.append((event_type, json.loads(data_str)))
            except Exception:
                pass
    return events


def test_sse_stream_proceed(client):
    url = "/api/hunt/stream?query=Which process chain led to powershell.exe in the reviewed evidence?&scenario_id=mshta-powershell&enforce_gate=true"
    resp = client.get(url)
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    events = parse_sse_events(resp.text)
    event_types = [e[0] for e in events]
    assert "gate" in event_types
    assert "subgraph" in event_types
    assert "token" in event_types
    assert "done" in event_types

    gate_evt = next(e[1] for e in events if e[0] == "gate")
    assert gate_evt["decision"] == "proceed"


def test_sse_stream_abstained(client):
    url = "/api/hunt/stream?query=Thời tiết hôm nay thế nào?&scenario_id=mshta-powershell&enforce_gate=true"
    resp = client.get(url)
    assert resp.status_code == 200

    events = parse_sse_events(resp.text)
    event_types = [e[0] for e in events]
    assert "gate" in event_types
    assert "error" in event_types
    assert "subgraph" not in event_types
