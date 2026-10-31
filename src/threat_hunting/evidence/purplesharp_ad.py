"""Canonical-only PurpleSharp launch slice with reviewable provenance."""

from pathlib import Path
from typing import Any

from .slice_provenance import extract_slice


def extract_purplesharp_evidence(canonical_events_path: Path) -> dict[str, Any]:
    """Retain launch fields without attributing accounts or technique success."""
    return extract_slice(canonical_events_path, scenario_id="purplesharp-ad")
