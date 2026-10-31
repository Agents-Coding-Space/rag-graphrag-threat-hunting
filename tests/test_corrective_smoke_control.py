"""Offline stop-control checks; no SQLite or network access."""
from scripts.smoke_live_llm_fixes import provider_ready, stopped_by_response


def test_no_probe_until_provider_has_recorded_recovery():
    assert not provider_ready({"rows": []})
    assert not provider_ready({"rows": [{"errorCode": 429, "testStatus": "unavailable"}]})
    assert not provider_ready({"rows": [{"errorCode": 429, "testStatus": "active"}]})
    assert provider_ready({"rows": [{"errorCode": None, "testStatus": "active"}]})


def test_http200_fallback_still_stops_on_provider429():
    assert stopped_by_response(200, {"status": "provider_error", "provider_error": {"kind": "rate_limited", "http_status": 429}})
    assert stopped_by_response(401, {})
    assert not stopped_by_response(200, {"status": "abstained", "execution": {"llm_called": False}})
