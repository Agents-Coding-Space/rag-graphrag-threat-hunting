"""Actual frozen direct profile, local dashboard only; no live LLM calls."""
from pathlib import Path
from uuid import uuid4
from fastapi.testclient import TestClient
import pytest

from threat_hunting.evaluation import experimental_comparison as p
from threat_hunting.evaluation.final_experiment import validate_preflight
from threat_hunting.server.experimental import ExperimentalSession, create_app

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "outputs/final/20261031_direct_v7"
CONFIG = ROOT / "configs/evaluation/integrated_final_direct_v7.json"
PIN = BASE / "runtime_pin.json"


def test_frozen_direct_profile_and_shared_offline_dashboard():
    config, pin, results, model = validate_preflight(CONFIG, PIN, BASE / "preflight")
    assert model.base_url == "https://openrouter.ai/api/v1" and model.model_name == "google/gemma-4-31b-it"
    assert model.max_retries == 1 and len(results["rows"]) == 24
    assert sum(r["eligibility_decision"] == "proceed" for r in results["rows"]) == 16
    def forbidden(**kwargs): pytest.fail("Offline profile constructed LLM client")
    session = ExperimentalSession(ROOT / "outputs/demo" / ("final-direct-offline-qa-" + uuid4().hex),
        config_path=CONFIG, pin_path=PIN, client_factory=forbidden)
    with TestClient(create_app(session)) as client:
        assert client.get("/").status_code == 200
        meta = client.get("/experimental-api/config").json()
        assert meta["profile_id"] == "integrated-final-direct-v7" and meta["maximum_llm_requests"] == 0
        for preset in meta["presets"]:
            assert set(preset) == {"case_id", "scenario_id", "query"}
            for branch in p.BRANCHES:
                response = client.get("/experimental-api/saved", params={"case_id":preset["case_id"],"branch":branch})
                assert response.status_code == 200
                assert response.json()["provenance"]["llm_requests_this_replay"] == 0
        preset = next(x for x in meta["presets"] if x["case_id"] == "AUTH-CTI")
        response = client.post("/experimental-api/hunt", json={"scenario_id":preset["scenario_id"],"query":preset["query"],"branch":"rag"}).json()
        expected = next(r for r in results["rows"] if (r["case_id"],r["branch"]) == ("AUTH-CTI","rag"))
        assert response["outcome"] == "dry_run_no_generation"
        assert response["result"]["messages_sha256"] == expected["messages_sha256"]
        assert response["result"]["context_sha256"] == expected["context_sha256"]
    assert session.attempts == 0


def test_final_dashboard_live_cannot_bypass_task_ledger():
    output = ROOT / "outputs/demo" / ("must-not-start-final-live-" + uuid4().hex)
    with pytest.raises(ValueError, match="offline/replay dashboard only"):
        ExperimentalSession(output, config_path=CONFIG, pin_path=PIN, live=True, max_requests=16)
    assert not output.exists()
