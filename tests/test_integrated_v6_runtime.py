"""Actual integrated profile, existing dashboard, local E5 and no LLM client."""
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.server.experimental import ExperimentalSession, create_app

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "outputs/integrated/20261030_v6"
CONFIG = ROOT / "configs/evaluation/integrated_scenarios_v6.json"
PIN = BASE / "runtime_pin_v6.json"


def test_integrated_dashboard_and_harness_share_new_context_and_messages():
    """v6 is a superseded frozen checkpoint; skip once its code pin no longer matches."""
    from historical_fixtures import require_frozen
    require_frozen(pipeline._read(PIN), ROOT, "integrated v6 checkpoint")
    def forbidden(**kwargs):
        pytest.fail("Offline dashboard constructed provider client")
    session = ExperimentalSession(ROOT / "outputs/demo" / ("integrated-v6-qa-" + uuid4().hex),
        config_path=CONFIG, pin_path=PIN, client_factory=forbidden)
    checks = []
    with TestClient(create_app(session)) as client:
        assert client.get("/").status_code == 200
        config = client.get("/experimental-api/config").json()
        assert config["profile_id"] == "integrated-three-scenarios-cti-v6"
        assert config["generation_contract"] == "source-meaning/v2"
        assert config["mode"] == "experimental_offline_demo" and config["maximum_llm_requests"] == 0
        assert len(config["presets"]) == 12
        for preset in config["presets"]:
            assert set(preset) == {"case_id", "scenario_id", "query"}
            for branch in pipeline.BRANCHES:
                response = client.get("/experimental-api/saved", params={"case_id": preset["case_id"], "branch": branch}).json()
                assert response["result"]["llm_http_attempts"] == 0
                assert response["provenance"]["mode"] == "saved_offline_preflight"
                assert response["report"] is None
                checks.append({"case_id": preset["case_id"], "branch": branch, "saved_status": response["outcome"]})
        historical = client.get("/experimental-api/config", params={"profile": "historical-replay"}).json()
        assert historical["mode"] == "historical_replay_only" and historical["generation_disabled"]
        assert client.post("/experimental-api/hunt?profile=historical-replay", json={
            "scenario_id": "purplesharp-ad", "query": "test", "branch": "rag"}).status_code == 409
        assert client.get("/.env").status_code == 404
        assert client.post("/api/hunt", json={}).status_code in {404, 405}
        # Real shared retrieval/prompt path for all three scenarios, no saved-answer shortcut.
        for case_id in ("AUTH-CTI", "PS-CTI", "NET-CTI"):
            preset = next(p for p in config["presets"] if p["case_id"] == case_id)
            response = client.post("/experimental-api/hunt", json={"scenario_id": preset["scenario_id"],
                "query": preset["query"], "branch": "graphrag"}).json()
            assert response["outcome"] == "dry_run_no_generation", response["result"]
            saved = pipeline._read(ROOT / session.pin["offline_preflight_path"] / f"{case_id}_graphrag/result.json")
            assert response["result"]["context_sha256"] == saved["context_sha256"]
            assert response["result"]["messages_sha256"] == saved["messages_sha256"]
            units = response["evidence_contract"]["units"]
            assert any(u.get("evidence_layer") == "cti_context" for u in units)
            checks.append({"case_id": case_id, "real_shared_offline_query": True,
                "messages_context_match_harness": True, "cti_context_returned": True})
    assert session.attempts == 0
    pipeline._write(session.output / "qa.json", {"checks": checks, "llm_attempts": 0,
        "frontend_unchanged": True, "browser_visual_qa": "not_run; existing build served",
        "scope": "actual integrated HTTP adapter, 24 saved branches, 3 shared offline queries"})
    pipeline._write(BASE / "dashboard_qa_final.json", {"report": str((session.output / "qa.json").relative_to(ROOT)),
        "saved_branches_checked": 24, "shared_queries_checked": 3, "llm_attempts": 0, "all_checks_passed": True})


def test_full_new_pin_blocks_unlisted_runtime_mismatch(monkeypatch):
    current = pipeline._code_manifest()
    corrupted = deepcopy(current)
    corrupted["src/threat_hunting/llm/guardrail.py"] = "0" * 64
    monkeypatch.setattr(pipeline, "_code_manifest", lambda: corrupted)
    output = ROOT / "outputs/demo" / ("must-not-create-v6-" + uuid4().hex)
    with pytest.raises(ValueError, match="runtime code pin mismatch"):
        ExperimentalSession(output, config_path=CONFIG, pin_path=PIN)
    assert not output.exists()
