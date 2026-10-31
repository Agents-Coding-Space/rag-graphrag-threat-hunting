"""Human approval metadata rules; never evidence or a security conclusion."""

from __future__ import annotations

from datetime import datetime
import re


_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def validate_human_review(
    status: object,
    reviewer: object,
    reviewed_at: object,
    *,
    path: str,
    pending_status: str = "pending_human_review",
    approved_status: str = "confirmed",
) -> None:
    """Require null pending metadata or a named, timezone-aware approval.

    The timestamp is an ISO 8601 calendar datetime with seconds and an explicit
    UTC offset (or Z). This validates supplied metadata; it never invents a time
    or authorizes a transition.
    """

    if status == pending_status:
        if reviewer is not None or reviewed_at is not None:
            raise ValueError(f"{path}: pending review requires null reviewer and reviewed_at")
        return
    if status != approved_status:
        raise ValueError(f"{path}: unsupported human review status {status!r}")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError(f"{path}.reviewer must be a non-empty string for approval")
    if not isinstance(reviewed_at, str) or _TIMESTAMP.fullmatch(reviewed_at) is None:
        raise ValueError(f"{path}.reviewed_at must be a valid ISO 8601 timestamp with timezone")
    # datetime normalizes some out-of-range offsets, so reject them explicitly.
    if reviewed_at[-1] != "Z":
        hours, minutes = map(int, reviewed_at[-5:].split(":"))
        if hours > 23 or minutes > 59:
            raise ValueError(f"{path}.reviewed_at has an invalid timezone offset")
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timezone is required")
    except ValueError as exc:
        raise ValueError(f"{path}.reviewed_at must be a valid timestamp with timezone: {exc}") from exc
