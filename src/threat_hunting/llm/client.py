"""Unified LLM client supporting Ollama and OpenAI-compatible endpoints."""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterator
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


class LLMProviderError(LLMClientError):
    """Safe operational metadata, without provider bodies or credential headers."""
    def __init__(self, status_code: int | None, *, retry_after_seconds: float | None = None,
                 diagnostic: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self.kind = "rate_limited" if status_code == 429 else "authentication_error" if status_code in (401, 403) else "provider_error"
        self.retry_after_seconds = retry_after_seconds
        self.diagnostic = diagnostic
        super().__init__(f"LLM provider {self.kind}" + (f" (HTTP {status_code})" if status_code else ""))


def retry_after_delay(value: str) -> float | None:
    """Allowlisted Retry-After metadata only; never retain provider headers/body."""
    if re.fullmatch(r"\d{1,6}(?:\.\d+)?", value):
        return float(value)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, TypeError, OverflowError):
        return None


_JSON_CODE_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json_text(raw_text: str) -> str:
    """Extract JSON string from raw text, stripping markdown code blocks if present."""
    text = raw_text.strip()
    match = _JSON_CODE_BLOCK_PATTERN.fullmatch(text)
    if match:
        return match.group(1).strip()
    return text


def _parse_json(text: str, layer: str) -> Any:
    """Parse the entire document and report its layer without logging its contents."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMClientError(
            f"Invalid {layer}: {exc.msg} at line {exc.lineno}, "
            f"column {exc.colno} (char {exc.pos})"
        ) from exc


def _completion_choice(payload: Any, *, allow_usage: bool = False) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        raise LLMClientError("Invalid LLM response: expected a JSON object")
    if "error" in payload:
        error = payload["error"]
        code = error.get("status", error.get("code")) if isinstance(error, dict) else None
        status = int(code) if str(code).isdigit() and 400 <= int(code) <= 599 else None
        if code in ("rate_limit_exceeded", "rate_limited", "insufficient_quota"):
            status = 429
        raise LLMProviderError(status)
    choices = payload.get("choices")
    if allow_usage and choices == [] and isinstance(payload.get("usage"), dict):
        return None
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise LLMClientError("Invalid LLM response: expected exactly one completion choice")
    return choices[0]


def _sse_events(text: str) -> Iterator[tuple[str, str]]:
    """Read SSE event boundaries, including comments and multiline data fields."""
    data_lines: list[str] = []
    event = "message"
    # SSE uses CR/LF, not Unicode line separators that may occur in JSON strings.
    lines = re.split(r"\r\n|\r|\n", text)
    if lines[-1] == "":
        lines.pop()  # A final newline terminates a line; it is not another blank line.
    for line in lines:
        if not line:
            if data_lines:
                yield event, "\n".join(data_lines)
            data_lines = []
            event = "message"
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
        elif field == "event":
            event = value
        elif field not in ("id", "retry"):
            raise LLMClientError("Malformed SSE response: unexpected field or unframed data")
    if data_lines:
        raise LLMClientError("Incomplete SSE response: unterminated event")


def _parse_sse_content(text: str) -> str:
    """Assemble one complete OpenAI chat stream; never return partial content."""
    parts: list[str] = []
    finished = False
    done = False
    for event, data in _sse_events(text):
        if done:
            raise LLMClientError("Invalid SSE response: data after [DONE]")
        if event == "error":
            payload = _parse_json(data, "SSE error JSON")
            _completion_choice(payload if isinstance(payload, dict) and "error" in payload else {"error": payload})
            raise LLMProviderError(None)
        if data == "[DONE]":
            done = True
            continue
        choice = _completion_choice(_parse_json(data, "SSE event JSON"), allow_usage=True)
        if choice is None:
            continue
        if finished:
            raise LLMClientError("Invalid SSE response: choice after completion finished")
        if choice.get("index", 0) != 0:
            raise LLMClientError("Invalid SSE response: unexpected completion index")
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            raise LLMClientError("Invalid SSE response: expected a delta object")
        content = delta.get("content")
        if content is not None:
            if not isinstance(content, str):
                raise LLMClientError("Invalid SSE response: delta content must be text")
            parts.append(content)
        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            if finish_reason != "stop":
                raise LLMClientError("Incomplete SSE completion: finish_reason is not stop")
            finished = True
    if not done or not finished:
        raise LLMClientError("Incomplete SSE response: missing finish_reason=stop or [DONE]")
    content = "".join(parts)
    if not content.strip():
        raise LLMClientError("Empty assistant content in SSE response")
    return content


def _parse_http_content(body: bytes, content_type: str) -> str:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LLMClientError("Invalid UTF-8 in LLM HTTP response") from exc
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "text/event-stream":
        return _parse_sse_content(text)
    if media_type and media_type != "application/json" and not media_type.endswith("+json"):
        raise LLMClientError("Unsupported Content-Type in LLM HTTP response; expected JSON or SSE")
    # A missing Content-Type still requires one complete JSON document.
    choice = _completion_choice(_parse_json(text, "HTTP response JSON"))
    assert choice is not None
    if choice.get("finish_reason") not in (None, "stop"):
        raise LLMClientError("Incomplete LLM completion: finish_reason is not stop")
    message = choice.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise LLMClientError("Invalid LLM response: expected assistant message content as text")
    if not message["content"].strip():
        raise LLMClientError("Empty assistant content in LLM response")
    return message["content"]


class LLMClient:
    """Unified client for interacting with LLM providers."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()
        self.last_attempt_count = 0

    def generate(self, messages: list[dict[str, str]]) -> str:
        """Send chat messages and return assistant response text, parsing both JSON and SSE streams."""
        self.last_attempt_count = 0
        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "claude-cli/0.2.29 (external, cli)",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        last_error: Exception | None = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
                self.last_attempt_count += 1
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    return _parse_http_content(resp.read(), resp.headers.get("Content-Type", ""))
            except urllib.error.HTTPError as exc:
                from .error_diagnostics import read_http_diagnostic
                retry_after = (exc.headers or {}).get("Retry-After", "")
                retry_after_seconds = retry_after_delay(retry_after)
                try:
                    diagnostic = read_http_diagnostic(exc, api_key=self.config.api_key, messages=messages)
                finally:
                    exc.close()
                last_error = LLMProviderError(exc.code, retry_after_seconds=retry_after_seconds, diagnostic=diagnostic)
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)
                if exc.code < 500:
                    # Authentication/rate limits/permanent requests must not trigger automatic retries.
                    raise last_error from None
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, TimeoutError):
                    last_error = LLMTimeoutError(f"Timeout after {self.config.timeout_seconds}s connecting to {endpoint}")
                else:
                    last_error = LLMConnectionError(f"Failed to connect to LLM provider at {endpoint}")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)
            except TimeoutError:
                last_error = LLMTimeoutError(f"Timeout after {self.config.timeout_seconds}s connecting to {endpoint}")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)
            except LLMClientError:
                # Protocol/parse errors are deterministic; preserve the layer and cause.
                raise
            except Exception as exc:
                last_error = LLMClientError(f"Unexpected error communicating with LLM provider ({type(exc).__name__})")
                logger.warning("Attempt %d/%d failed: %s", attempt, self.config.max_retries, last_error)

            if attempt < self.config.max_retries:
                time.sleep(self.config.retry_delay_seconds * (2 ** (attempt - 1)))

        raise last_error or LLMClientError("Failed to generate response after retries")

    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Generate response and parse as JSON object."""
        raw_output = self.generate(messages)
        cleaned = extract_json_text(raw_output)
        parsed = _parse_json(cleaned, "model content JSON")
        if not isinstance(parsed, dict):
            raise LLMClientError(f"Invalid model content JSON: expected object, got {type(parsed).__name__}")
        return parsed
