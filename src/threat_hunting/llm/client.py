"""Unified LLM client supporting Ollama and OpenAI-compatible endpoints."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Mapping
import urllib.error
import urllib.request

from .config import LLMConfig


logger = logging.getLogger(__name__)


class LLMClientError(RuntimeError):
    """Base error for LLM client communication."""


class LLMConnectionError(LLMClientError):
    """Raised when connection to LLM provider fails."""


class LLMTimeoutError(LLMClientError):
    """Raised when request to LLM provider times out."""


_JSON_CODE_BLOCK_PATTERN = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL | re.MULTILINE)


def extract_json_text(raw_text: str) -> str:
    """Extract JSON string from raw text, stripping markdown code blocks if present."""
    text = raw_text.strip()
    match = _JSON_CODE_BLOCK_PATTERN.match(text)
    if match:
        return match.group(1).strip()
    return text


class LLMClient:
    """Unified client for interacting with LLM providers."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()

    def generate(self, messages: list[dict[str, str]]) -> str:
        """Send chat messages and return assistant response text, parsing both JSON and SSE streams."""
        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "claude-cli/0.2.29 (external, cli)",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        last_error: Exception | None = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    resp_text = resp.read().decode("utf-8", errors="replace")

                    # Handle SSE Streaming response from some OpenAI proxies (like 9router)
                    if resp_text.strip().startswith("data:"):
                        content_parts = []
                        for line in resp_text.splitlines():
                            line = line.strip()
                            if line.startswith("data:") and not line.endswith("[DONE]"):
                                json_part = line[5:].strip()
                                if json_part:
                                    try:
                                        chunk = json.loads(json_part)
                                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                                        part = delta.get("content", "")
                                        if part:
                                            content_parts.append(part)
                                    except Exception:
                                        pass
                        if content_parts:
                            return "".join(content_parts)

                    # Standard JSON response
                    resp_json = json.loads(resp_text)
                    choices = resp_json.get("choices", [])
                    if not choices:
                        raise LLMClientError(f"Empty choices returned from LLM endpoint: {resp_json}")
                    content = choices[0].get("message", {}).get("content", "")
                    return str(content)
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                last_error = LLMClientError(f"HTTP {exc.code} from LLM provider: {err_body}")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, TimeoutError):
                    last_error = LLMTimeoutError(f"Timeout after {self.config.timeout_seconds}s connecting to {endpoint}")
                else:
                    last_error = LLMConnectionError(f"Failed to connect to LLM provider at {endpoint}: {exc.reason}")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)
            except Exception as exc:
                last_error = LLMClientError(f"Unexpected error communicating with LLM provider: {exc}")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)

            if attempt < self.config.max_retries:
                time.sleep(self.config.retry_delay_seconds * (2 ** (attempt - 1)))

        raise last_error or LLMClientError("Failed to generate response after retries")

    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Generate response and parse as JSON object."""
        raw_output = self.generate(messages)
        cleaned = extract_json_text(raw_output)
        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected JSON object, got {type(parsed).__name__}")
            return parsed
        except Exception as exc:
            raise LLMClientError(f"Failed to parse LLM response as JSON: {exc}\nRaw: {raw_output[:500]}") from exc
