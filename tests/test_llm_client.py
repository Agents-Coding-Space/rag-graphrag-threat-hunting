"""Unit tests for LLMClient and LLMConfig."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from threat_hunting.llm.client import (
    LLMClient,
    LLMClientError,
    LLMConnectionError,
    LLMTimeoutError,
    extract_json_text,
)
from threat_hunting.llm.config import LLMConfig


def test_llm_config_defaults_and_env(monkeypatch):
    cfg = LLMConfig()
    assert cfg.provider == "ollama"
    assert cfg.model_name == "llama3.1:8b"
    assert cfg.temperature == 0.0

    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_TEMPERATURE", "0.2")

    cfg_env = LLMConfig.from_env()
    assert cfg_env.provider == "openai"
    assert cfg_env.api_key == "sk-test-key"
    assert cfg_env.model_name == "gpt-4o"
    assert cfg_env.temperature == 0.2


def test_extract_json_text():
    plain = '{"key": "value"}'
    assert extract_json_text(plain) == plain

    fenced = '```json\n{"key": "value"}\n```'
    assert extract_json_text(fenced) == '{"key": "value"}'

    fenced_no_tag = '```\n{"key": "value"}\n```'
    assert extract_json_text(fenced_no_tag) == '{"key": "value"}'


def test_llm_client_generate_success():
    cfg = LLMConfig(base_url="http://mock-llm/v1", model_name="test-model")
    client = LLMClient(cfg)

    mock_response_body = json.dumps({
        "choices": [{"message": {"role": "assistant", "content": "Observed mshta execution"}}]
    }).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_response_body
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        result = client.generate([{"role": "user", "content": "Analyze log"}])
        assert result == "Observed mshta execution"
        assert mock_urlopen.call_count == 1


def test_llm_client_retry_mechanism():
    cfg = LLMConfig(base_url="http://mock-llm/v1", model_name="test-model", max_retries=3, retry_delay_seconds=0.01)
    client = LLMClient(cfg)

    err = urllib.error.HTTPError("http://mock-llm/v1", 500, "Internal Server Error", {}, io.BytesIO(b'{"error": "busy"}'))
    
    mock_response_body = json.dumps({
        "choices": [{"message": {"role": "assistant", "content": "Succeeded on retry"}}]
    }).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_response_body
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", side_effect=[err, mock_resp]) as mock_urlopen:
        result = client.generate([{"role": "user", "content": "Analyze"}])
        assert result == "Succeeded on retry"
        assert mock_urlopen.call_count == 2


def test_llm_client_generate_json():
    cfg = LLMConfig(base_url="http://mock-llm/v1", model_name="test-model")
    client = LLMClient(cfg)

    mock_response_body = json.dumps({
        "choices": [{"message": {"role": "assistant", "content": '```json\n{"verdict": "MALICIOUS", "technique": "T1218.005"}\n```'}}]
    }).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_response_body
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        data = client.generate_json([{"role": "user", "content": "Analyze"}])
        assert data["verdict"] == "MALICIOUS"
        assert data["technique"] == "T1218.005"


def test_llm_client_connection_error():
    cfg = LLMConfig(base_url="http://mock-llm/v1", max_retries=2, retry_delay_seconds=0.01)
    client = LLMClient(cfg)

    err = urllib.error.URLError("Connection refused")
    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(LLMConnectionError):
            client.generate([{"role": "user", "content": "ping"}])


def test_llm_client_timeout_error():
    cfg = LLMConfig(base_url="http://mock-llm/v1", max_retries=1)
    client = LLMClient(cfg)

    err = urllib.error.URLError(TimeoutError("timed out"))
    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(LLMTimeoutError):
            client.generate([{"role": "user", "content": "ping"}])
