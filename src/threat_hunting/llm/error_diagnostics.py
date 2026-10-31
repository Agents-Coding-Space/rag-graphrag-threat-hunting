"""Bounded, allowlisted provider diagnostics, never raw request/error dumps."""
from __future__ import annotations

import json
import math
import re
from typing import Any

MAX_ERROR_BYTES = 65536
MAX_MESSAGE_CHARS = 1200
ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
SECRET = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}|\bBearer\s+[^\s,;\"'}]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
REQUEST_ECHO = re.compile(r"(?i)(?:request\s+headers?|authorization|prompt|messages|request\s+body|api[_ -]?key|password|access[_ -]?token|secret)\s*[=:]|request\s+headers?\b")
BUDGET_FIELDS = frozenset({"credits", "credits_required", "required_credits", "available_credits", "remaining_credits",
    "credit_limit", "remaining_limit", "limit", "limit_remaining", "balance", "remaining_balance", "remaining",
    "requested_cost", "estimated_cost", "cost", "max_tokens", "requested_tokens", "requested_max_tokens",
    "available_tokens", "affordable_tokens", "tokens_required", "tokens_available", "prompt_tokens",
    "completion_tokens", "total_tokens", "token_limit", "remaining_tokens"})


def safe_message(value: Any, *, api_key: str, messages: list[dict[str, str]]) -> str | None:
    if not isinstance(value, str):
        return None
    text = value[:8192]
    if api_key:
        text = text.replace(api_key, "[REDACTED_SECRET]")
    text = SECRET.sub("[REDACTED_SECRET]", text)
    echo = REQUEST_ECHO.search(text)
    if echo:
        text = text[:echo.start()] + "[REDACTED_REQUEST_ECHO]"
    # Error messages can echo unlabeled request text; omit any long common span.
    for message in messages:
        content = message.get("content", "")
        if not isinstance(content, str) or not content:
            continue
        if content in text:
            text = text.replace(content, "[REDACTED_PROMPT]")
        words = text.split()
        if any(len(part) >= 16 and part in content for part in words):
            return "[Provider message contained request content; omitted]"
        if any(len(part := " ".join(words[i:i+4])) >= 24 and part in content for i in range(max(0, len(words)-3))):
            return "[Provider message contained request content; omitted]"
    return " ".join(text.split())[:MAX_MESSAGE_CHARS] or None


def safe_id(value: Any, *, api_key: str) -> str | None:
    text = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not ID_PATTERN.fullmatch(text) or SECRET.search(text) or (api_key and api_key in text):
        return None
    return text


def numeric(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,18}(?:\.\d{1,12})?", value):
        return float(value) if "." in value else int(value)
    return None


def extract_diagnostic(status: int, body: bytes, response_headers: Any, *,
                       api_key: str, messages: list[dict[str, str]], truncated: bool = False) -> dict[str, Any]:
    """Keep error message/code/request IDs and numeric budgets only.

    Unknown fields, raw body, user/account IDs and header maps are discarded.
    No request headers are accepted as an argument to this API.
    """
    text = body.decode("utf-8", errors="replace")
    try:
        document = json.loads(text)
        body_format = "json"
    except (ValueError, TypeError):
        document, body_format = {}, "non_json"
    root = document if isinstance(document, dict) else {}
    error = root.get("error", {})
    error = error if isinstance(error, dict) else {"message": error} if isinstance(error, str) else {}
    raw_message = error.get("message", root.get("message"))
    if raw_message is None and body_format == "non_json" and not text.lstrip().startswith(("<", "{", "[")):
        raw_message = text
    message = safe_message(raw_message, api_key=api_key, messages=messages)
    request_ids = []
    for header in ("x-request-id", "request-id", "x-openrouter-request-id"):
        candidate = next((value for name, value in response_headers.items() if str(name).casefold() == header), None) if response_headers else None
        value = safe_id(candidate, api_key=api_key)
        if value and value not in request_ids:
            request_ids.append(value)
    budgets = {}
    def visit(value: Any, depth: int = 0) -> None:
        if depth > 5 or not isinstance(value, dict):
            return
        for key, item in value.items():
            if key in {"request_id", "requestId"}:
                identifier = safe_id(item, api_key=api_key)
                if identifier and identifier not in request_ids:
                    request_ids.append(identifier)
            if key in BUDGET_FIELDS:
                number = numeric(item)
                if number is not None:
                    budgets[key] = number
            # Never descend into request echoes, raw provider dumps or unknown structures.
            if key in {"error", "metadata", "budget", "credits", "usage", "limits"}:
                visit(item, depth + 1)
    visit(root)
    # These counts are explicit provider-message claims, not inferred balances.
    if isinstance(raw_message, str):
        for key, pattern in (("requested_max_tokens", r"requested(?: up to)?\s+(\d+)\s+tokens"),
                             ("affordable_tokens", r"(?:only )?afford\s+(\d+)")):
            match = re.search(pattern, raw_message, re.I)
            if match:
                budgets.setdefault(key, int(match[1]))
    result = {"schema_version": "safe-provider-diagnostic/v1", "http_status": status,
        "message": message or "Provider returned an HTTP error; no safe textual message extracted.",
        "request_id": request_ids[0] if request_ids else None, "request_ids": request_ids,
        "error_code": safe_id(error.get("code", root.get("code")), api_key=api_key),
        "error_type": safe_id(error.get("type"), api_key=api_key), "budget_metadata": budgets,
        "budget_metadata_basis": "allowlisted numeric provider fields or explicitly reported token counts",
        "body_format": body_format, "body_truncated": truncated,
        "request_headers_saved": False, "prompt_saved": False, "raw_error_body_saved": False}
    return result


def read_http_diagnostic(error: Any, *, api_key: str, messages: list[dict[str, str]]) -> dict[str, Any]:
    try:
        body = error.read(MAX_ERROR_BYTES + 1)
        return extract_diagnostic(error.code, body[:MAX_ERROR_BYTES], error.headers,
            api_key=api_key, messages=messages, truncated=len(body) > MAX_ERROR_BYTES)
    except Exception:
        return {"schema_version": "safe-provider-diagnostic/v1", "http_status": error.code,
                "message": "Error body could not be read safely.", "request_id": None,
                "budget_metadata": {}, "request_headers_saved": False,
                "prompt_saved": False, "raw_error_body_saved": False}
