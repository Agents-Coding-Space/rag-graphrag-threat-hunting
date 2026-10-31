"""Explicit, metadata-only human approval transition for a reviewed bundle.

This module performs no I/O and supplies neither a reviewer nor a timestamp.
Calling it requires an independently authorized human approval. It does not
build consumers, change evidence labels, or grant runtime context eligibility.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

from .approval import validate_human_review
from .review_artifacts import validate_review_bundle
from .schema import SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION


def serialize_review_document(document: dict[str, Any]) -> bytes:
    """Serialize review JSON deterministically, preserving object/list order."""

    return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(serialize_review_document(document)).hexdigest()


def approve_review_bundle(
    ground_truth: dict[str, Any],
    reference_answers: dict[str, Any],
    manifest: dict[str, Any],
    *,
    reviewer: str,
    reviewed_at: str,
    basis: str,
    timestamp_basis: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return v2 copies recording one pending -> approved human review event.

    Existing source and technical-review provenance, notes, case content and
    labels stay unchanged. Only approval metadata, versions and direct hashes
    of the two newly serialized artifacts change. The manifest retains all
    three previous artifact hashes. Reapproval requires a separately designed
    review cycle rather than silently replacing this approval event.
    """

    validate_human_review("confirmed", reviewer, reviewed_at, path="approval")
    for name, text in (("basis", basis), ("timestamp_basis", timestamp_basis)):
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"approval.{name} must be a non-empty string")
    validate_review_bundle(
        ground_truth, reference_answers, manifest,
        ground_truth_sha256=_digest(ground_truth),
        reference_answers_sha256=_digest(reference_answers),
    )
    if ground_truth["review"]["review_status"] != "pending_human_review":
        raise ValueError("Only a pending human review can be approved; reapproval is unsupported")

    previous = {
        "scenario_ground_truth.json": _digest(ground_truth),
        "reference_answers.json": _digest(reference_answers),
        "review_manifest.json": _digest(manifest),
    }
    approved_gt, approved_answers, approved_manifest = deepcopy(
        (ground_truth, reference_answers, manifest)
    )
    approved_gt["schema_version"] = SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION
    approved_gt["review"].update(
        review_status="confirmed", reviewer=reviewer, reviewed_at=reviewed_at
    )
    approved_answers["schema_version"] = "mshta-reference-answers/v2"
    approved_answers["review"].update(
        review_status="human_approved", human_reviewer=reviewer, human_approved_at=reviewed_at
    )
    approved_answers["sources"]["ground_truth"]["sha256"] = _digest(approved_gt)
    approved_manifest.update(
        schema_version="mshta-technical-review/v2",
        human_review_status="confirmed",
        human_reviewer=reviewer,
        human_approved_at=reviewed_at,
        approval_provenance={
            "previous_artifacts": previous, "basis": basis, "timestamp_basis": timestamp_basis,
        },
    )
    approved_manifest["artifacts"].update({
        "scenario_ground_truth.json": _digest(approved_gt),
        "reference_answers.json": _digest(approved_answers),
    })
    validate_review_bundle(
        approved_gt, approved_answers, approved_manifest,
        ground_truth_sha256=_digest(approved_gt),
        reference_answers_sha256=_digest(approved_answers),
    )
    return approved_gt, approved_answers, approved_manifest
