"""F05: float tolerance is a property of the comparison, never of a stored artifact."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting.retrieval.reproducibility import (  # noqa: E402
    TOLERANCE_POLICY, assert_equivalent, compare_documents)


def _context(score: float, hit_id: str = "chunk-a") -> dict:
    return {"retrieval": {"hits": [{"score": score, "chunk": {"chunk_id": hit_id}}]},
            "gate": {"decision": "proceed", "reason_codes": []}}


def test_policy_is_versioned_and_declared():
    assert TOLERANCE_POLICY["policy_id"] == "reproducibility-tolerance/v1"
    assert TOLERANCE_POLICY["absolute"] == 1e-6
    assert TOLERANCE_POLICY["relative"] == 1e-6


def test_identical_documents_are_equivalent_with_no_differences():
    report = compare_documents(_context(0.87362147), _context(0.87362147))
    assert report["equivalent"] is True
    assert report["exact_differences"] == [] and report["tolerated_differences"] == []


def test_the_observed_float_drift_is_tolerated_and_reported():
    """This is the exact pair recorded by the review."""
    report = compare_documents(_context(0.87362147), _context(0.87362149))
    assert report["equivalent"] is True
    assert len(report["tolerated_differences"]) == 1
    assert report["tolerated_differences"][0]["pointer"].endswith("/score")


def test_a_drift_larger_than_the_tolerance_is_a_real_difference():
    report = compare_documents(_context(0.87362147), _context(0.88000000))
    assert report["equivalent"] is False
    assert report["exact_differences"]


def test_reordered_hits_are_never_tolerated():
    left = {"retrieval": {"hits": [{"score": 0.9, "chunk": {"chunk_id": "a"}},
                                  {"score": 0.8, "chunk": {"chunk_id": "b"}}]}}
    right = {"retrieval": {"hits": [{"score": 0.8, "chunk": {"chunk_id": "b"}},
                                   {"score": 0.9, "chunk": {"chunk_id": "a"}}]}}
    report = compare_documents(left, right)
    assert report["equivalent"] is False
    assert any(d["pointer"].endswith("/chunk_id") for d in report["exact_differences"])


def test_a_changed_gate_decision_is_never_tolerated():
    report = compare_documents(_context(0.9), {**_context(0.9), "gate": {"decision": "abstain", "reason_codes": []}})
    assert report["equivalent"] is False


def test_a_changed_reason_code_is_never_tolerated():
    left = {**_context(0.9), "gate": {"decision": "abstain", "reason_codes": ["a"]}}
    right = {**_context(0.9), "gate": {"decision": "abstain", "reason_codes": ["b"]}}
    assert compare_documents(left, right)["equivalent"] is False


def test_a_missing_or_extra_key_is_a_real_difference():
    left, right = _context(0.9), _context(0.9)
    right["extra"] = 1
    report = compare_documents(left, right)
    assert report["equivalent"] is False
    assert any(d.get("kind") == "key_set" for d in report["exact_differences"])


def test_string_change_is_never_tolerated():
    left = _context(0.9, "chunk-a")
    right = _context(0.9, "chunk-b")
    assert compare_documents(left, right)["equivalent"] is False


def test_assert_equivalent_names_the_pointer_on_structural_drift():
    with pytest.raises(ValueError, match="differs beyond the declared tolerance"):
        assert_equivalent(_context(0.9, "a"), _context(0.9, "b"))


def test_assert_equivalent_returns_tolerated_report_for_float_drift():
    report = assert_equivalent(_context(0.87362147), _context(0.87362149))
    assert report["equivalent"] is True and report["tolerated_differences"]
