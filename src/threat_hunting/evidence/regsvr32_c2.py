"""Canonical-only Regsvr32 launch/network slice with reviewable provenance."""

from pathlib import Path
from typing import Any

from .slice_provenance import extract_slice


def extract_regsvr32_evidence(canonical_events_path: Path) -> dict[str, Any]:
    """Retain launch/endpoint fields without inferring transfer completion."""
    return extract_slice(canonical_events_path, scenario_id="regsvr32-c2")
