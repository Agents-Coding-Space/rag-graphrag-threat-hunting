"""Atomic file replacement that survives transient Windows file locks.

On Windows an ``os.replace`` can fail with ``PermissionError`` (``WinError 5``) or
``WinError 32`` while another process still holds a handle to either the temporary file or the
target — most often an antivirus scanner that opened the file microseconds earlier. The write
itself already succeeded, so losing the rename loses a completed checkpoint for no reason.

This helper retries only those transient lock errors, for a bounded time, and re-raises
anything else immediately so a real permission problem is never masked.

Callers that already wrote their payload to a temporary file should use
``replace_with_retry(temporary, target)`` instead of ``os.replace`` directly.
"""
from __future__ import annotations

import os
from pathlib import Path
import time

# Windows codes raised when a handle is briefly held. On other platforms these constants do not
# exist, hence the getattr fallbacks; the retry is a no-op there because the error never occurs.
# 5  = ERROR_ACCESS_DENIED   (os.replace on a file a scanner briefly holds)
# 32 = ERROR_SHARING_VIOLATION
# 33 = ERROR_LOCK_VIOLATION
# 13 = EACCES from the isolated errno field
_TRANSIENT_CODES = frozenset({5, 32, 33, 13})

DEFAULT_ATTEMPTS = 6
DEFAULT_DELAY_SECONDS = 0.05


def replace_with_retry(source: str | Path, target: str | Path, *,
                       attempts: int = DEFAULT_ATTEMPTS,
                       delay: float = DEFAULT_DELAY_SECONDS) -> None:
    """``os.replace`` with a bounded retry on transient Windows lock errors."""
    last: OSError | None = None
    for attempt in range(max(1, attempts)):
        try:
            os.replace(source, target)
            return
        except (PermissionError, OSError) as exc:
            winerror = getattr(exc, "winerror", None)
            code = winerror if winerror is not None else getattr(exc, "errno", None)
            if code not in _TRANSIENT_CODES:
                raise
            last = exc
            time.sleep(delay * (attempt + 1))
    if last is not None:
        raise last
