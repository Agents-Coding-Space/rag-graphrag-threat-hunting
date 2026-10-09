"""Strict diagnostic reports whose derived analysis is independently recalculated."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from .calibration_config import (
    _canonical, _json_document, _load_json, validate_relevance_policy,
    validate_selection_constraints,
)
from .calibration_schema import CALIBRATION_REPORT_SCHEMA_VERSION, _signals
from .relevance_dataset import RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION


GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION = "graphrag-relevance-diagnostics/v1"
_ROOT_FIELDS = (
    "schema_version", "analysis_id", "scenario_id", "provenance", "audit",
    "cases", "policies", "selection_constraints", "analysis", "warnings",
    "metadata", "review",
)
_CASE_FIELDS = (
    "case_id", "category", "language", "expected_decision", "signals", "warnings",
)
_AUDIT_ASSURANCES = {
    "signal_snapshot_scope": "per_case",
    "signal_snapshot_source": "calibration_report.case.signals",
    "historical_invariance_assurance": "validated_by_upstream_calibration_engine",
    "diagnostic_verification": "policy_outcome_replay_from_canonical_case_signals",
}


class RelevanceDiagnosticsError(ValueError):
    """Diagnostic inputs, replay outcomes or derived reports violate the contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RelevanceDiagnosticsError(message)


def _object(value: object, fields: tuple[str, ...], path: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{path} must be an object")
    _require(set(value) == set(fields), f"{path} has missing or unknown fields")
    return value


def _text(value: object, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be nonempty text")
    return value


def _strings(value: object, path: str) -> None:
    _require(isinstance(value, list), f"{path} must be a list")
    for index, item in enumerate(value):
        _text(item, f"{path}[{index}]")
    _require(value == sorted(set(value)), f"{path} must be unique and canonically sorted")


def _same(actual: object, expected: object, path: str) -> None:
    """Reject a changed derived value while retaining its first complete JSON path."""
    if _canonical(actual) == _canonical(expected):
        return
    if isinstance(actual, dict) and isinstance(expected, dict):
        _require(set(actual) == set(expected), f"{path} has missing or unknown fields")
        for key in sorted(expected):
            _same(actual[key], expected[key], f"{path}.{key}")
    elif isinstance(actual, list) and isinstance(expected, list):
        _require(len(actual) == len(expected), f"{path} count does not match derived data")
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            _same(left, right, f"{path}[{index}]")
    raise RelevanceDiagnosticsError(f"{path} does not match independently derived data")


def _validate_provenance(root: dict[str, Any]) -> None:
    provenance = _object(root["provenance"], ("dataset", "calibration_report"), "$.provenance")
    specifications = (
        ("dataset", "dataset_id", RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION),
        ("calibration_report", "calibration_id", CALIBRATION_REPORT_SCHEMA_VERSION),
    )
    for name, identifier, version in specifications:
        path = f"$.provenance.{name}"
        artifact = _object(provenance[name], ("path", "sha256", "schema_version", identifier), path)
        _text(artifact["path"], f"{path}.path")
        _text(artifact[identifier], f"{path}.{identifier}")
        _require(artifact["schema_version"] == version, f"{path}.schema_version mismatch")
        _require(
            isinstance(artifact["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is not None,
            f"{path}.sha256 must be a lowercase full SHA-256",
        )


def _validate_cases(value: object) -> list[dict[str, Any]]:
    _require(isinstance(value, list) and bool(value), "$.cases must be a nonempty list")
    identifiers = set()
    for index, item in enumerate(value):
        path = f"$.cases[{index}]"
        case = _object(item, _CASE_FIELDS, path)
        identifier = _text(case["case_id"], f"{path}.case_id")
        _require(identifier not in identifiers, f"{path}.case_id contains a duplicate ID")
        identifiers.add(identifier)
        for field in ("category", "language"):
            _text(case[field], f"{path}.{field}")
        _require(case["expected_decision"] in ("proceed", "abstain"), f"{path}.expected_decision unsupported")
        try:
            _signals(case["signals"])
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            raise RelevanceDiagnosticsError(f"{path}.signals invalid: {exc}") from exc
        _strings(case["warnings"], f"{path}.warnings")
    _require(value == sorted(value, key=lambda case: case["case_id"]), "$.cases must be sorted by case_id")
    return value


def _validate_policies(value: object) -> list[dict[str, Any]]:
    _require(isinstance(value, list) and bool(value), "$.policies must be a nonempty list")
    identifiers, bodies = set(), set()
    for index, policy in enumerate(value):
        path = f"$.policies[{index}]"
        try:
            validate_relevance_policy(policy)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            raise RelevanceDiagnosticsError(f"{path} invalid: {exc}") from exc
        identifier = policy["policy_id"]
        body = _canonical({key: item for key, item in policy.items() if key != "policy_id"})
        _require(identifier not in identifiers, f"{path}.policy_id contains a duplicate ID")
        _require(body not in bodies, f"{path} contains a duplicate policy body")
        identifiers.add(identifier)
        bodies.add(body)
    _require(value == sorted(value, key=lambda policy: policy["policy_id"]), "$.policies must be sorted by policy_id")
    return value


def validate_relevance_diagnostics(document: object) -> None:
    """Validate detached finite JSON, then recalculate every derived section.

    This validates one canonical signal snapshot per case. It does not claim to
    inspect historical per-policy snapshots, which the calibration report does
    not store. No filesystem access, gate execution, model or network is used.
    """
    try:
        root = _object(_json_document(document), _ROOT_FIELDS, "$")
        _require(root["schema_version"] == GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION, "$.schema_version mismatch")
        _text(root["analysis_id"], "$.analysis_id")
        _text(root["scenario_id"], "$.scenario_id")
        _validate_provenance(root)
        cases = _validate_cases(root["cases"])
        policies = _validate_policies(root["policies"])
        validate_selection_constraints(root["selection_constraints"])
        _same(root["audit"], {
            **_AUDIT_ASSURANCES,
            "replayed_outcome_count": len(cases) * len(policies),
        }, "$.audit")

        # Local imports keep the public exception available without an import cycle.
        from .relevance_diagnostics import _derive_diagnostics, _metadata, _warnings

        analysis = _derive_diagnostics(cases, policies, root["selection_constraints"])
        _same(root["analysis"], analysis, "$.analysis")
        _same(root["metadata"], _metadata(cases, policies, analysis), "$.metadata")
        _same(root["warnings"], _warnings(cases), "$.warnings")
        _same(root["review"], {
            "status": "pending_human_review", "reviewer": None, "reviewed_at": None,
        }, "$.review")
        body = {key: item for key, item in root.items() if key != "analysis_id"}
        expected_id = "relevance-diagnostics-" + sha256(_canonical(body)).hexdigest()
        _require(root["analysis_id"] == expected_id, "$.analysis_id does not match deterministic report content")
    except RelevanceDiagnosticsError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        raise RelevanceDiagnosticsError(f"Invalid relevance diagnostics at $: {exc}") from exc


def load_relevance_diagnostics(path: Path) -> dict[str, Any]:
    """Load strict UTF-8 JSON with filename and JSON-path validation errors."""
    source = Path(path)
    try:
        document = _load_json(source)
        validate_relevance_diagnostics(document)
        return document
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        raise RelevanceDiagnosticsError(f"Cannot load relevance diagnostics {source} at $: {exc}") from exc


__all__ = (
    "GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION", "RelevanceDiagnosticsError",
    "validate_relevance_diagnostics", "load_relevance_diagnostics",
)
