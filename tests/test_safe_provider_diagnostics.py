"""Mock error bodies: diagnostics are useful without request/credential dumps."""
import io
import json
from unittest.mock import patch

import pytest

from threat_hunting.llm.client import LLMClient, LLMProviderError
from threat_hunting.llm.config import LLMConfig
from threat_hunting.llm.error_diagnostics import extract_diagnostic, MAX_ERROR_BYTES
from threat_hunting.evaluation import experimental_comparison as pipeline
import urllib.error

KEY = "sk-or-v1-unit-test-secret-keep-private"
MESSAGES = [{"role": "user", "content": "Confidential investigation phrase that must never enter provider diagnostics."}]


def make_error(status=402, body=None, headers=None):
    return urllib.error.HTTPError("http://mock/v1/chat/completions", status, "upstream",
        headers or {"X-Request-ID": "request-123", "Retry-After": "120"},
        io.BytesIO(json.dumps(body or {"error": {"code": status, "message": "Request requires more credits, or fewer max_tokens. You requested up to 2048 tokens, but can only afford 700.",
            "metadata": {"available_credits": 0.05, "requested_cost": "0.07", "max_tokens": 2048}}}).encode()))


def test_client_keeps_allowlisted_message_id_and_budget_but_exception_stays_generic():
    client = LLMClient(LLMConfig(model_name="fixture", api_key=KEY, base_url="http://mock/v1", max_retries=1))
    error = make_error()
    with patch("urllib.request.urlopen", side_effect=error) as http:
        with pytest.raises(LLMProviderError) as caught:
            client.generate(MESSAGES)
    diagnostic = caught.value.diagnostic
    assert http.call_count == client.last_attempt_count == 1 and error.fp.closed
    assert diagnostic["http_status"] == 402
    assert "requires more credits" in diagnostic["message"]
    assert diagnostic["request_id"] == "request-123"
    assert diagnostic["budget_metadata"] == {"available_credits":0.05,"requested_cost":0.07,"max_tokens":2048,
                                             "requested_max_tokens":2048,"affordable_tokens":700}
    assert "credits" not in str(caught.value)


def test_unknown_fields_request_echoes_and_credentials_never_escape():
    body = {"error": {"code": 402, "message": "Not enough credits. Request headers: Authorization: Bearer " + KEY + " Prompt: " + MESSAGES[0]["content"],
        "metadata": {"request_id":"safe-id", "api_key":KEY, "headers":{"Authorization":KEY}, "prompt":MESSAGES,
                     "balance":0.5, "max_tokens":"do not keep text", "raw":"untrusted dump"}}, "user_id":"private-user"}
    diagnostic = extract_diagnostic(402, json.dumps(body).encode(), {"Authorization":KEY}, api_key=KEY,messages=MESSAGES)
    text = json.dumps(diagnostic)
    assert KEY not in text and "Authorization" not in text and MESSAGES[0]["content"] not in text
    assert "private-user" not in text and "untrusted dump" not in text
    assert diagnostic["message"].startswith("Not enough credits.")
    assert diagnostic["budget_metadata"] == {"balance":0.5}
    assert diagnostic["request_id"] == "safe-id"


def test_unlabeled_prompt_echo_is_removed_and_secret_in_request_id_is_dropped():
    body = {"error":{"message":"Error: " + MESSAGES[0]["content"], "request_id":KEY}}
    diagnostic = extract_diagnostic(402,json.dumps(body).encode(),{"x-request-id":KEY},api_key=KEY,messages=MESSAGES)
    assert MESSAGES[0]["content"] not in json.dumps(diagnostic)
    assert diagnostic["request_id"] is None and KEY not in json.dumps(diagnostic)


def test_nonjson_and_oversized_bodies_are_bounded_without_raw_dump():
    plain = extract_diagnostic(503,b"Service unavailable",{},api_key=KEY,messages=MESSAGES)
    assert plain["message"] == "Service unavailable" and plain["body_format"] == "non_json"
    client = LLMClient(LLMConfig(model_name="fixture", api_key=KEY, base_url="http://mock/v1", max_retries=1))
    error = urllib.error.HTTPError("http://mock/v1",402,"error",{},io.BytesIO(b"<html>"+b"x"*(MAX_ERROR_BYTES*2)))
    with patch("urllib.request.urlopen",side_effect=error):
        with pytest.raises(LLMProviderError) as caught: client.generate(MESSAGES)
    assert caught.value.diagnostic["body_truncated"] is True
    assert len(json.dumps(caught.value.diagnostic)) < 1800
    assert "<html>" not in caught.value.diagnostic["message"]


def test_shared_generator_persists_safe_diagnostic_and_stops_402(tmp_path):
    model = LLMConfig(model_name="fixture", api_key=KEY, base_url="http://mock/v1", max_retries=1)
    def emit(name,value):
        (tmp_path/(name+".json")).write_text(json.dumps(value),encoding="utf-8")
    with patch("urllib.request.urlopen",side_effect=make_error()) as http:
        row, stopped = pipeline.generate_branch(MESSAGES,{},model,LLMClient,emit)
    assert stopped == "provider_http_402" and row["llm_http_attempts"] == http.call_count == 1
    assert row["outcome"] == "provider_error"
    diagnostic = json.loads((tmp_path/"provider_diagnostic.json").read_text("utf-8"))
    assert diagnostic == row["provider_error"]["diagnostic"]
    assert KEY not in (tmp_path/"provider_diagnostic.json").read_text("utf-8")
