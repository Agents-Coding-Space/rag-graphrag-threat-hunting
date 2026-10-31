"""Replay data and route safety checks; no model or provider is constructed."""
from __future__ import annotations

import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer

import pytest

from scripts.serve_ui_replay import CASES, CASE_IDS, ROOT, ReplayHandler, digest, load_replay


@pytest.mark.parametrize("case_id", CASES)
def test_replay_preserves_original_response(case_id: str) -> None:
    source = CASES[case_id]
    before = digest(source)
    payload = load_replay(case_id)
    response = payload["response"]
    marker = response.pop("replay")
    assert response == json.loads(source.read_text(encoding="utf-8"))
    assert marker["sha256"] == before == digest(source)
    assert marker["mode"] == "saved_response"


@pytest.mark.parametrize("case_id", ("provider_error", "rate_limited"))
def test_synthetic_provider_fixture_is_not_success(case_id: str) -> None:
    response = load_replay(case_id)["response"]
    assert response["replay"]["mode"] == "synthetic_fixture"
    assert response["status"] == "provider_error"
    assert response["report"]["verdict"] is None
    assert not response["execution"]["generation_succeeded"]
    assert response["execution"]["llm_http_attempts"] == 0
    assert response["execution"]["fallback_used"]
    assert not response["provider_error"]["automatic_retry"]


def test_loading_and_unknown_case() -> None:
    assert load_replay("loading")["response"] is None
    with pytest.raises(KeyError):
        load_replay("../../.env")


def test_service_rejects_all_production_routes() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler)
    server.loaded_sha256 = "test"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        for method, route, expected in (("POST", "/api/hunt", 405), ("GET", "/api/hunt/stream", 404), ("GET", "/.env", 404), ("GET", "/assets/../../.env", 404), ("GET", "/qa-api/replay?case=MS01", 200)):
            conn.request(method, route)
            response = conn.getresponse()
            assert response.status == expected
            response.read()
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
