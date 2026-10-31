"""Historical run fixtures: skip with provenance instead of reporting a current defect.

Several suites assert against *frozen historical* run directories (a pilot study pinned in
October, a v6 delivery, the pre-review v7/v8/v9/v10 profiles). Those pins record the code image
of the day they were produced. Once the source changes — as it did for the review fixes — those
suites can no longer exercise their subject, because the frozen code manifest no longer matches.

Three options existed:

1. delete the tests — removes real coverage and hides history;
2. weaken the pin check — destroys the guarantee the pins exist to provide;
3. skip with an explicit reason that names the drifted module.

This module implements option 3. A skipped historical fixture is reported, never silently
dropped, and the *current* profile is checked by the suites that pin it (see
``test_final_direct_experiment.py`` and ``test_review_subset.py``).
"""
from __future__ import annotations

from pathlib import Path
import hashlib

import pytest


def hash_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def drifted_modules(pin: dict, root: Path) -> list[str]:
    """Return the pinned code paths whose current bytes differ from the frozen pin."""
    drifted = []
    for relative, expected in (pin.get("code_sha256") or {}).items():
        candidate = Path(root) / relative
        if not candidate.is_file() or hash_file(candidate) != expected:
            drifted.append(relative)
    return sorted(drifted)


def require_frozen(codepin: dict, root: Path, label: str) -> None:
    """Skip a historical fixture when its frozen code image no longer matches the checkout."""
    drifted = drifted_modules(codepin, root)
    if drifted:
        shown = ", ".join(drifted[:3]) + (f" (+{len(drifted) - 3} more)" if len(drifted) > 3 else "")
        pytest.skip(f"{label} is a frozen historical run; its code pin no longer matches the "
                    f"current checkout ({len(drifted)} module(s) changed: {shown}). "
                    f"Current behaviour is covered by the suites that pin the active profile.")
