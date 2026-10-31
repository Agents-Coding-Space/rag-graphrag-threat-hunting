"""Unit tests for HTTP/model parsing in the OpenAI-compatible LLM client."""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from threat_hunting.llm.client import (
    LLMClient,
    LLMClientError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMProviderError,
    extract_json_text,
)
from threat_hunting.llm.config import LLMConfig


MESSAGES = [{"role": "user", "content": "Reply with a harmless greeting."}]


class MockHTTPResponse(io.BytesIO):
    """Give urlopen a response with real header values and context handling."""

    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        super().__init__(body)
        self.headers = {"Content-Type": content_type}
        self.status = 200

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)


def json_response(body: object) -> MockHTTPResponse:
    return MockHTTPResponse(json.dumps(body, ensure_ascii=False).encode("utf-8"))


def completion(content: object = "Hello") -> dict[str, object]:
    return {
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ]
    }


def sse_event(data: object) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def delta_event(content: str) -> str:
    return sse_event({"choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]})


def finish_event(reason: str = "stop") -> str:
    return sse_event({"choices": [{"index": 0, "delta": {}, "finish_reason": reason}]})


def sse_response(body: str) -> MockHTTPResponse:
    return MockHTTPResponse(body.encode("utf-8"), "text/event-stream; charset=utf-8")


@pytest.fixture
def client() -> LLMClient:
    return LLMClient(LLMConfig(base_url="http://mock-llm/v1", model_name="test-model", max_retries=1))


@pytest.fixture
def clean_config_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Config imports .env at module import. Remove every input from_env reads so
    # assertions cannot depend on a developer's private configuration.
    for name in (
        "LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY",
        "LLM_TEMPERATURE", "LLM_MAX_TOKENS", "LLM_TIMEOUT_SECONDS",
        "LLM_MAX_RETRIES", "LLM_RETRY_DELAY", "OLLAMA_HOST", "OLLAMA_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_llm_config_defaults_and_env(clean_config_env, monkeypatch):
    cfg = LLMConfig()
    assert cfg.provider == "generic_openai"
    assert cfg.model_name == ""
    assert cfg.temperature == 0.0

    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_API_KEY", "unit-test-credential")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_BASE_URL", "http://mock-llm/v1/")
    monkeypatch.setenv("LLM_TEMPERATURE", "0.2")

    cfg_env = LLMConfig.from_env()
    assert cfg_env.provider == "openai"
    assert cfg_env.api_key == "unit-test-credential"
    assert cfg_env.model_name == "test-model"
    assert cfg_env.base_url == "http://mock-llm/v1"
    assert cfg_env.temperature == 0.2


def test_llm_config_requires_model(clean_config_env):
    with pytest.raises(ValueError, match="LLM_MODEL"):
        LLMConfig.from_env()


def test_llm_config_requires_api_key(clean_config_env, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-test-credential")
    with pytest.raises(ValueError, match="LLM_API_KEY"):
        LLMConfig.from_env()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('{"key": "value"}', '{"key": "value"}'),
        ('```json\n{"key": "value"}\n```', '{"key": "value"}'),
        ('```\n{"key": "value"}\n```', '{"key": "value"}'),
        (' \n```json\n{"key": "value"}\n```\n ', '{"key": "value"}'),
    ],
)
def test_extract_json_text(raw, expected):
    assert extract_json_text(raw) == expected


def test_extract_json_text_preserves_trailing_text():
    raw = '```json\n{"key": "value"}\n```\nUnexpected suffix'
    assert extract_json_text(raw) == raw


def test_llm_client_generate_success_requests_non_streaming(client):
    response = MockHTTPResponse(
        json.dumps(completion("Xin chào")).encode("utf-8"),
        "application/json; charset=utf-8",
    )
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        assert client.generate(MESSAGES) == "Xin chào"

    request = urlopen.call_args.args[0]
    payload = json.loads(request.data)
    assert request.full_url == "http://mock-llm/v1/chat/completions"
    assert request.method == "POST"
    assert payload["stream"] is False
    assert payload["model"] == "test-model"
    assert payload["messages"] == MESSAGES
    assert request.get_header("Accept") == "application/json"
    assert request.get_header("Content-type") == "application/json"
    assert urlopen.call_count == 1


def test_llm_client_retry_mechanism():
    cfg = LLMConfig(base_url="http://mock-llm/v1", model_name="test-model", max_retries=3, retry_delay_seconds=0)
    client = LLMClient(cfg)
    error = urllib.error.HTTPError(
        "http://mock-llm/v1", 500, "Internal Server Error", {}, io.BytesIO(b'{"error":"busy"}')
    )
    with patch("urllib.request.urlopen", side_effect=[error, json_response(completion("Recovered"))]) as urlopen:
        assert client.generate(MESSAGES) == "Recovered"
        assert urlopen.call_count == 2


@pytest.mark.parametrize("content", [
    '{"greeting": "Hello", "safe": true}',
    '```json\n{"greeting": "Hello", "safe": true}\n```',
])
def test_llm_client_generate_json(client, content):
    with patch("urllib.request.urlopen", return_value=json_response(completion(content))):
        assert client.generate_json(MESSAGES) == {"greeting": "Hello", "safe": True}


@pytest.mark.parametrize(
    "content",
    [
        '{"safe": true} {"extra": true}',
        '```json\n{"safe": true}\n```\nUnexpected suffix',
        'Not JSON at all',
        '[{"safe": true}]',
        'null',
    ],
)
def test_llm_client_rejects_invalid_model_content_json(client, content):
    with patch("urllib.request.urlopen", return_value=json_response(completion(content))):
        with pytest.raises(LLMClientError, match="model content JSON"):
            client.generate_json(MESSAGES)


@pytest.mark.parametrize(
    "body",
    [
        b'{"choices":',
        json.dumps(completion()).encode("utf-8") + b'\n{"extra":true}',
        b'{"choices":[{"message":{"content":"\xff"}}]}',
    ],
)
def test_llm_client_rejects_invalid_http_response_json(client, body):
    with patch("urllib.request.urlopen", return_value=MockHTTPResponse(body)):
        with pytest.raises(LLMClientError, match="HTTP response|UTF-8"):
            client.generate(MESSAGES)


@pytest.mark.parametrize(
    "body",
    [
        [],
        None,
        {},
        {"choices": []},
        {"choices": "wrong type"},
        {"choices": [None]},
        {"choices": [{"delta": {"content": "stream in a JSON envelope"}}]},
        completion(None),
        completion([{"type": "text", "text": "unsupported content array"}]),
    ],
)
def test_llm_client_rejects_invalid_json_envelopes(client, body):
    with patch("urllib.request.urlopen", return_value=json_response(body)):
        with pytest.raises(LLMClientError):
            client.generate(MESSAGES)


def test_llm_client_rejects_unknown_content_type(client):
    with patch("urllib.request.urlopen", return_value=MockHTTPResponse(b"<html>Error</html>", "text/html")):
        with pytest.raises(LLMClientError):
            client.generate(MESSAGES)


def test_llm_client_sse_assembles_comments_role_content_and_usage(client):
    body = (
        ": router heartbeat\n\n"
        + sse_event({"choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})
        + delta_event("Xin ")
        + delta_event("chào")
        + finish_event()
        + sse_event({"choices": [], "usage": {"completion_tokens": 2}})
        + "data: [DONE]\n\n"
    ).replace("\n", "\r\n")
    with patch("urllib.request.urlopen", return_value=sse_response(body)):
        assert client.generate(MESSAGES) == "Xin chào"


def test_llm_client_sse_supports_multiline_data_events(client):
    body = (
        'event: message\ndata: {"choices": [\n'
        'data: {"index": 0, "delta": {"content": "Hello"}, "finish_reason": null}]}\n\n'
        + finish_event()
        + "data: [DONE]\n\n"
    )
    with patch("urllib.request.urlopen", return_value=sse_response(body)):
        assert client.generate(MESSAGES) == "Hello"


def test_llm_client_sse_preserves_unicode_line_separators(client):
    content = "Xin\u2028chào\u0085router"
    body = delta_event(content) + finish_event() + "data: [DONE]\n\n"
    with patch("urllib.request.urlopen", return_value=sse_response(body)):
        assert client.generate(MESSAGES) == content


@pytest.mark.parametrize(
    "body",
    [
        delta_event("Hello") + "data: {bad-json}\n\n" + finish_event() + "data: [DONE]\n\n",
        delta_event("Hello") + sse_event({"error": {"message": "provider failure"}}) + "data: [DONE]\n\n",
        delta_event("Hello") + finish_event(),  # Missing terminal [DONE].
        delta_event("Hello") + "data: [DONE]\n\n",  # Missing finish_reason.
        delta_event("Hello") + finish_event("length") + "data: [DONE]\n\n",
        delta_event("Hello") + finish_event() + "data: [DONE]\n\n" + delta_event("Extra"),
        delta_event("Hello") + finish_event() + "data: [DONE]\n\ndata: [DONE]\n\n",
        sse_event({"choices": [{"index": 0, "delta": {"content": 123}, "finish_reason": None}]}) + finish_event() + "data: [DONE]\n\n",
        sse_event({"choices": "invalid"}) + "data: [DONE]\n\n",
        "data: [DONE]\n\n",
        # A mislabeled response with unframed JSON must not be accepted as SSE.
        json.dumps(completion()) + "\n[DONE]\n",
        delta_event("Hello") + finish_event() + "data: [DONE]\n",  # Unterminated event.
        delta_event("Hello") + 'event: error\ndata: {"message":"provider failure"}\n\n',
    ],
)
def test_llm_client_rejects_invalid_or_incomplete_sse(client, body):
    with patch("urllib.request.urlopen", return_value=sse_response(body)):
        with pytest.raises(LLMClientError):
            client.generate(MESSAGES)


def test_llm_client_generate_json_from_complete_sse(client):
    body = delta_event('{"safe":') + delta_event('true}') + finish_event() + "data: [DONE]\n\n"
    with patch("urllib.request.urlopen", return_value=sse_response(body)):
        assert client.generate_json(MESSAGES) == {"safe": True}


def test_llm_client_http_error_does_not_expose_response_body(client, caplog):
    private_marker = "PRIVATE_PROVIDER_RESPONSE_MARKER"
    error = urllib.error.HTTPError(
        "http://mock-llm/v1", 400, "Bad Request", {}, io.BytesIO(private_marker.encode("utf-8"))
    )
    with patch("urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMClientError, match="HTTP 400") as caught:
            client.generate(MESSAGES)
    assert private_marker not in str(caught.value)
    assert private_marker not in caplog.text


def test_llm_client_provider_error_in_http_200_does_not_expose_body(client, caplog):
    private_marker = "PRIVATE_PROVIDER_RESPONSE_MARKER"
    response = json_response({"error": {"message": private_marker, "code": "provider_error"}})
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(LLMClientError) as caught:
            client.generate(MESSAGES)
    assert private_marker not in str(caught.value)
    assert private_marker not in caplog.text


def test_llm_client_model_json_error_does_not_expose_raw_content(client, caplog):
    private_marker = "PRIVATE_MODEL_CONTENT_MARKER"
    with patch("urllib.request.urlopen", return_value=json_response(completion(private_marker))):
        with pytest.raises(LLMClientError, match="model content JSON") as caught:
            client.generate_json(MESSAGES)
    assert private_marker not in str(caught.value)
    assert private_marker not in caplog.text


def test_llm_client_connection_error(client):
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        with pytest.raises(LLMConnectionError):
            client.generate(MESSAGES)


def test_llm_client_timeout_error(client):
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError(TimeoutError("timed out"))):
        with pytest.raises(LLMTimeoutError):
            client.generate(MESSAGES)


@pytest.mark.parametrize("status,kind", [(429, "rate_limited"), (401, "authentication_error"), (403, "authentication_error")])
def test_permanent_provider_error_is_typed_and_never_retried(status, kind, caplog):
    client = LLMClient(LLMConfig(base_url="http://mock-llm/v1", model_name="test-model", max_retries=4, retry_delay_seconds=0))
    error = urllib.error.HTTPError("http://mock-llm/v1", status, "private-marker", {"Retry-After": "45"}, io.BytesIO(b"private-marker"))
    with patch("urllib.request.urlopen", side_effect=error) as urlopen:
        with pytest.raises(LLMProviderError) as caught:
            client.generate(MESSAGES)
    assert caught.value.kind == kind
    assert caught.value.status_code == status
    assert caught.value.retry_after_seconds == 45
    assert urlopen.call_count == client.last_attempt_count == 1
    assert "private-marker" not in str(caught.value) + caplog.text


@pytest.mark.parametrize("transport", ["json", "sse", "sse-error"])
def test_rate_limit_envelope_is_typed_without_retry(client, transport):
    payload = {"error": {"code": 429, "message": "private-marker"}}
    response = json_response(payload) if transport == "json" else sse_response(
        ("event: error\n" if transport == "sse-error" else "") + sse_event(payload))
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        with pytest.raises(LLMProviderError) as caught:
            client.generate(MESSAGES)
    assert caught.value.kind == "rate_limited"
    assert client.last_attempt_count == urlopen.call_count == 1
    assert "private-marker" not in str(caught.value)
