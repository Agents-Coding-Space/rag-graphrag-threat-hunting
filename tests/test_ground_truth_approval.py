"""Human approval is document metadata, never a promotion of evidence labels."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth.approval import validate_human_review
from threat_hunting.ground_truth.approval_update import (
    approve_review_bundle,
    serialize_review_document,
)
from threat_hunting.ground_truth.review_artifacts import (
    ReviewArtifactValidationError,
    validate_reference_answers_document,
    validate_review_bundle,
    validate_review_manifest_document,
)
from threat_hunting.ground_truth.schema import (
    SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION,
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthValidationError,
    load_ground_truth_document,
    validate_ground_truth_document,
)


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "ground_truth"
    / "scenario_ground_truth_minimal.json"
)
REVIEWER = "Nguyen Hong Phong"
# This fixed synthetic timestamp is fixture data, not a claim about human approval.
APPROVED_AT = "2026-10-15T10:21:32+07:00"
SHA256 = "a" * 64


def _digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(serialize_review_document(document)).hexdigest()


def _set_path(document: dict[str, Any], path: tuple[str | int, ...], value: object) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


@pytest.fixture
def ground_truth_v1() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _ground_truth_v2(document: dict[str, Any], *, approved: bool) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result["schema_version"] = SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION
    if approved:
        result["review"].update(
            review_status="confirmed", reviewer=REVIEWER, reviewed_at=APPROVED_AT
        )
    return result


def test_v1_pending_contract_remains_unchanged(ground_truth_v1: dict[str, Any]) -> None:
    before = copy.deepcopy(ground_truth_v1)
    assert SCENARIO_GROUND_TRUTH_SCHEMA_VERSION == "scenario-ground-truth/v1"
    assert SCENARIO_GROUND_TRUTH_APPROVAL_SCHEMA_VERSION == "scenario-ground-truth/v2"
    assert ground_truth_v1["review"] == {
        "review_status": "pending_human_review",
        "reviewer": None,
        "reviewed_at": None,
        "decisions": [],
        "notes": [],
    }
    validate_ground_truth_document(ground_truth_v1)
    assert ground_truth_v1 == before


@pytest.mark.parametrize("approved", [False, True], ids=["pending", "confirmed"])
def test_v2_accepts_both_document_review_states(
    ground_truth_v1: dict[str, Any], approved: bool, tmp_path: Path
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=approved)
    before = copy.deepcopy(document)
    validate_ground_truth_document(document)
    path = tmp_path / "ground_truth_v2.json"
    path.write_bytes(serialize_review_document(document))
    assert load_ground_truth_document(path) == before
    assert document == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("review_status", "confirmed"),
        ("reviewer", REVIEWER),
        ("reviewed_at", APPROVED_AT),
    ],
)
def test_v1_does_not_acquire_v2_approval_semantics(
    ground_truth_v1: dict[str, Any], field: str, value: str
) -> None:
    ground_truth_v1["review"][field] = value
    with pytest.raises(GroundTruthValidationError):
        validate_ground_truth_document(ground_truth_v1)


@pytest.mark.parametrize("reviewer", [None, "", " ", "\t\n", 15, False, [], {}])
def test_confirmed_requires_a_nonblank_string_reviewer(
    ground_truth_v1: dict[str, Any], reviewer: object
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    document["review"]["reviewer"] = reviewer
    with pytest.raises(GroundTruthValidationError, match="reviewer"):
        validate_ground_truth_document(document)


@pytest.mark.parametrize(
    "reviewed_at",
    [
        None,
        "",
        " ",
        123,
        False,
        "not-a-time",
        "2026-02-30T10:21:32+07:00",
        "2026-10-15T25:21:32+07:00",
        "2026-10-15",
        "2026-10-15T10:21:32",
        "2026-10-15T10:21:32+25:00",
    ],
)
def test_confirmed_requires_a_valid_timezone_aware_timestamp(
    ground_truth_v1: dict[str, Any], reviewed_at: object
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    document["review"]["reviewed_at"] = reviewed_at
    with pytest.raises(GroundTruthValidationError, match="reviewed_at"):
        validate_ground_truth_document(document)


@pytest.mark.parametrize("reviewed_at", [APPROVED_AT, "2026-10-15T03:21:32Z"])
def test_confirmed_accepts_explicit_offset_or_utc(
    ground_truth_v1: dict[str, Any], reviewed_at: str
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    document["review"]["reviewed_at"] = reviewed_at
    validate_ground_truth_document(document)


@pytest.mark.parametrize("field", ["review_status", "reviewer", "reviewed_at"])
@pytest.mark.parametrize("approved", [False, True])
def test_v2_review_metadata_fields_cannot_be_omitted(
    ground_truth_v1: dict[str, Any], field: str, approved: bool
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=approved)
    del document["review"][field]
    with pytest.raises(GroundTruthValidationError, match="missing"):
        validate_ground_truth_document(document)


@pytest.mark.parametrize(
    ("reviewer", "reviewed_at"),
    [(REVIEWER, None), (None, APPROVED_AT), (REVIEWER, APPROVED_AT), ("", None)],
)
def test_pending_rejects_any_approval_metadata(
    ground_truth_v1: dict[str, Any], reviewer: object, reviewed_at: object
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=False)
    document["review"].update(reviewer=reviewer, reviewed_at=reviewed_at)
    with pytest.raises(GroundTruthValidationError):
        validate_ground_truth_document(document)


@pytest.mark.parametrize("status", ["approved", "human_approved", "confirmed ", "CONFIRMED"])
def test_ground_truth_approval_vocabulary_is_exact(
    ground_truth_v1: dict[str, Any], status: str
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    document["review"]["review_status"] = status
    with pytest.raises(GroundTruthValidationError):
        validate_ground_truth_document(document)


@pytest.mark.parametrize(
    "path",
    [
        ("scenario", "analysis_status"),
        ("entities", 0, "status"),
        ("facts", 0, "status"),
        ("relationships", 0, "status"),
        ("evidence", 0, "status"),
        ("sigma_findings", 0, "status"),
        ("mitre_assessments", 0, "status"),
        ("mitre_assessments", 0, "review_status"),
    ],
)
def test_human_confirmation_does_not_allow_confirmed_security_labels(
    ground_truth_v1: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    _set_path(document, path, "confirmed")
    with pytest.raises(GroundTruthValidationError, match="confirmed"):
        validate_ground_truth_document(document)


@pytest.mark.parametrize("field", ["custom_status", "human_review", "review_status"])
def test_confirmation_exception_is_confined_to_exact_document_review_path(
    ground_truth_v1: dict[str, Any], field: str
) -> None:
    document = _ground_truth_v2(ground_truth_v1, approved=True)
    document["entities"][0]["attributes"][field] = "confirmed"
    with pytest.raises(GroundTruthValidationError, match="confirmed"):
        validate_ground_truth_document(document)


def test_shared_review_validator_supports_artifact_specific_vocabulary() -> None:
    validate_human_review(
        "ai_review_completed_pending_human_approval",
        None,
        None,
        path="$.review",
        pending_status="ai_review_completed_pending_human_approval",
        approved_status="human_approved",
    )
    validate_human_review(
        "human_approved",
        REVIEWER,
        APPROVED_AT,
        path="$.review",
        pending_status="ai_review_completed_pending_human_approval",
        approved_status="human_approved",
    )
    with pytest.raises(ValueError):
        validate_human_review(
            "confirmed",
            REVIEWER,
            APPROVED_AT,
            path="$.review",
            pending_status="ai_review_completed_pending_human_approval",
            approved_status="human_approved",
        )


def _reference_answers(ground_truth: dict[str, Any]) -> dict[str, Any]:
    """A four-case synthetic reference set, one case per documented category."""
    cases = []
    for index, category in enumerate(
        ["relevant_direct", "relevant_paraphrase", "insufficient_evidence", "unrelated"]
    ):
        supported = index < 2
        unrelated = category == "unrelated"
        cases.append(
            {
                "answer_constraints": [
                    "Keep observed/candidate labels; human review was pending in the draft.",
                    "Do not invent facts or turn missing telemetry into an absence claim.",
                ],
                "case_id": f"synthetic-case-{index}",
                "category": category,
                "expected_decision": "proceed" if supported else "abstain",
                "ground_truth_pointers": [] if unrelated else ["/evidence/0"],
                "language": "vi" if index % 2 else "en",
                "original_query": f"Synthetic question {index}: bằng chứng nào?",
                "query": f"Synthetic question {index}: bằng chứng nào?",
                "raw_record_references": []
                if unrelated
                else [
                    {
                        "source_file": "synthetic_events.jsonl",
                        "raw_record_ref": "fixture:record:1",
                    }
                ],
                "raw_reference_role": "not_required_for_artifact_status_or_scope_answer"
                if unrelated
                else "supports_stated_observed_fields",
                "reference_answer": f"Synthetic reference answer {index}: giữ nguyên Unicode.",
                "reference_answer_language": "vi",
                "source_case_pointer": f"/cases/{index}",
                "target_kind": "answer_support"
                if supported
                else "no_relevant_chunk"
                if unrelated
                else "abstention_support",
            }
        )
    return {
        "cases": cases,
        "metadata": {
            "case_count": 4,
            "category_counts": {
                "insufficient_evidence": 1,
                "relevant_direct": 1,
                "relevant_paraphrase": 1,
                "unrelated": 1,
            },
            "changed_labels": 0,
            "changed_queries": 0,
            "dataset_use": "calibration_not_final_benchmark",
            "decision_counts": {"abstain": 2, "proceed": 2},
        },
        "purpose": "evaluation_reference_only_not_retrieval_or_runtime_gate_input",
        "review": {
            "human_approved_at": None,
            "human_reviewer": None,
            "notes": ["Synthetic technical review; no production evidence."],
            "review_date": "2026-10-14",
            "review_status": "ai_review_completed_pending_human_approval",
            "review_type": "evidence_and_reference_answer_audit",
            "reviewer": "Codex",
            "reviewer_type": "ai_assistant",
        },
        "scenario_id": ground_truth["scenario"]["scenario_id"],
        "schema_version": "mshta-reference-answers/v1",
        "scope_policy": {
            "abstain_meaning": "Insufficient evidence or outside scope.",
            "insufficient_evidence": "Same topic, unsupported requested fact.",
            "relevant_direct": "Direct evidence question.",
            "relevant_paraphrase": "Evidence question rephrased.",
            "retrieval_target_meaning": "Context eligibility is not a security conclusion.",
            "scope_reference_for_unrelated": "Scope explanation is not relevant evidence.",
            "unrelated": "Outside the synthetic scenario.",
        },
        "sources": {
            "dataset": {"path": "fixtures/reviewed_cases.json", "sha256": SHA256},
            "ground_truth": {
                "path": "fixtures/scenario_ground_truth.json",
                "sha256": _digest(ground_truth),
            },
            "raw_log": {"path": "fixtures/synthetic_events.jsonl", "sha256": "1" * 64},
        },
    }


def _manifest(
    ground_truth: dict[str, Any], answers: dict[str, Any]
) -> dict[str, Any]:
    return {
        "artifacts": {
            "scenario_ground_truth.json": _digest(ground_truth),
            "reference_answers.json": _digest(answers),
            "reference_answers.md": "c" * 64,
            "reviewed_cases.json": SHA256,
        },
        "baseline_ground_truth_valid": True,
        "baseline_inputs": {"fixtures/baseline_ground_truth.json": "d" * 64},
        "canonical_records_examined": 1,
        "category_and_decision_changes": 0,
        "consumer_note": "Consumers still pin the earlier fixture provenance.",
        "human_review_status": "pending_human_review",
        "input_hashes_unchanged": True,
        "json_readback_passed": True,
        "mitre_label_promotions": 0,
        "original_sources": {"fixtures/synthetic_events.jsonl": "1" * 64},
        "query_wording_corrections": 0,
        "raw_records_examined": 1,
        "reference_answers": 4,
        "resolved_baseline_cases": 4,
        "resolved_baseline_relevance_pointers": 3,
        "review_date": "2026-10-14",
        "reviewed_entities": len(ground_truth["entities"]),
        "reviewed_evidence": len(ground_truth["evidence"]),
        "reviewed_relationships": len(ground_truth["relationships"]),
        "reviewer": "Codex",
        "reviewer_type": "ai_assistant",
        "scenario_id": ground_truth["scenario"]["scenario_id"],
        "schema_version": "mshta-technical-review/v1",
        "status": "technical_review_completed_with_corrections",
    }


@pytest.fixture
def pending_bundle(ground_truth_v1: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    answers = _reference_answers(ground_truth_v1)
    return ground_truth_v1, answers, _manifest(ground_truth_v1, answers)


def _validate_bundle(bundle: tuple[dict[str, Any], ...]) -> None:
    ground_truth, answers, manifest = bundle
    validate_review_bundle(
        ground_truth,
        answers,
        manifest,
        ground_truth_sha256=_digest(ground_truth),
        reference_answers_sha256=_digest(answers),
    )


def _approve(bundle: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    return approve_review_bundle(
        *bundle,
        reviewer=REVIEWER,
        reviewed_at=APPROVED_AT,
        basis="Explicit human approval in the synthetic test conversation.",
        timestamp_basis="Fixed test fixture timestamp; no real approval asserted.",
    )


@pytest.fixture
def approved_bundle(pending_bundle: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    return _approve(pending_bundle)


def test_legacy_reference_answers_and_manifest_are_validated_explicitly(
    pending_bundle: tuple[dict[str, Any], ...],
) -> None:
    before = copy.deepcopy(pending_bundle)
    ground_truth, answers, manifest = pending_bundle
    validate_reference_answers_document(answers)
    validate_review_manifest_document(manifest)
    _validate_bundle(pending_bundle)
    assert ground_truth["schema_version"] == "scenario-ground-truth/v1"
    assert answers["schema_version"] == "mshta-reference-answers/v1"
    assert manifest["schema_version"] == "mshta-technical-review/v1"
    assert pending_bundle == before


def test_all_approved_artifacts_record_one_event(
    approved_bundle: tuple[dict[str, Any], ...],
) -> None:
    ground_truth, answers, manifest = approved_bundle
    _validate_bundle(approved_bundle)
    assert ground_truth["schema_version"] == "scenario-ground-truth/v2"
    assert answers["schema_version"] == "mshta-reference-answers/v2"
    assert manifest["schema_version"] == "mshta-technical-review/v2"
    assert ground_truth["review"]["review_status"] == "confirmed"
    assert answers["review"]["review_status"] == "human_approved"
    assert manifest["human_review_status"] == "confirmed"
    assert ground_truth["review"]["reviewer"] == answers["review"]["human_reviewer"]
    assert answers["review"]["human_reviewer"] == manifest["human_reviewer"] == REVIEWER
    assert ground_truth["review"]["reviewed_at"] == answers["review"]["human_approved_at"]
    assert answers["review"]["human_approved_at"] == manifest["human_approved_at"] == APPROVED_AT
    assert answers["review"]["reviewer"] == manifest["reviewer"] == "Codex"
    assert answers["sources"]["ground_truth"]["sha256"] == _digest(ground_truth)
    assert manifest["artifacts"]["scenario_ground_truth.json"] == _digest(ground_truth)
    assert manifest["artifacts"]["reference_answers.json"] == _digest(answers)


def _refresh_links(bundle: tuple[dict[str, Any], ...]) -> None:
    ground_truth, answers, manifest = bundle
    answers["sources"]["ground_truth"]["sha256"] = _digest(ground_truth)
    manifest["artifacts"]["scenario_ground_truth.json"] = _digest(ground_truth)
    manifest["artifacts"]["reference_answers.json"] = _digest(answers)


def test_v2_pending_bundle_is_valid_and_can_transition_to_approval(
    approved_bundle: tuple[dict[str, Any], ...],
) -> None:
    ground_truth, answers, manifest = approved_bundle
    ground_truth["review"].update(
        review_status="pending_human_review", reviewer=None, reviewed_at=None
    )
    answers["review"].update(
        review_status="ai_review_completed_pending_human_approval",
        human_reviewer=None,
        human_approved_at=None,
    )
    manifest.update(
        human_review_status="pending_human_review",
        human_reviewer=None,
        human_approved_at=None,
    )
    _refresh_links(approved_bundle)
    _validate_bundle(approved_bundle)
    _validate_bundle(_approve(approved_bundle))


@pytest.mark.parametrize("artifact_index", [1, 2], ids=["answers", "manifest"])
def test_v1_review_artifacts_cannot_claim_human_approval(
    approved_bundle: tuple[dict[str, Any], ...], artifact_index: int
) -> None:
    artifact = approved_bundle[artifact_index]
    artifact["schema_version"] = (
        "mshta-reference-answers/v1" if artifact_index == 1 else "mshta-technical-review/v1"
    )
    validator = validate_reference_answers_document if artifact_index == 1 else validate_review_manifest_document
    with pytest.raises(ReviewArtifactValidationError):
        validator(artifact)


@pytest.mark.parametrize("artifact_index", [1, 2], ids=["answers", "manifest"])
@pytest.mark.parametrize(
    ("reviewer", "approved_at"),
    [
        (None, APPROVED_AT),
        ("", APPROVED_AT),
        (" \t", APPROVED_AT),
        (REVIEWER, None),
        (REVIEWER, ""),
        (REVIEWER, "invalid-time"),
        (REVIEWER, "2026-10-15T10:21:32"),
        (REVIEWER, "2026-13-15T10:21:32+07:00"),
    ],
)
def test_review_artifacts_require_valid_human_approval_metadata(
    approved_bundle: tuple[dict[str, Any], ...],
    artifact_index: int,
    reviewer: object,
    approved_at: object,
) -> None:
    artifact = approved_bundle[artifact_index]
    review = artifact["review"] if artifact_index == 1 else artifact
    review.update(human_reviewer=reviewer, human_approved_at=approved_at)
    validator = validate_reference_answers_document if artifact_index == 1 else validate_review_manifest_document
    with pytest.raises(ReviewArtifactValidationError):
        validator(artifact)


@pytest.mark.parametrize("artifact_index", [1, 2], ids=["answers", "manifest"])
@pytest.mark.parametrize("field", ["human_reviewer", "human_approved_at", "status"])
def test_review_artifacts_require_explicit_approval_fields(
    approved_bundle: tuple[dict[str, Any], ...], artifact_index: int, field: str
) -> None:
    artifact = approved_bundle[artifact_index]
    review = artifact["review"] if artifact_index == 1 else artifact
    if field == "status":
        field = "review_status" if artifact_index == 1 else "human_review_status"
    del review[field]
    validator = validate_reference_answers_document if artifact_index == 1 else validate_review_manifest_document
    with pytest.raises(ReviewArtifactValidationError):
        validator(artifact)


@pytest.mark.parametrize("artifact_index", [1, 2], ids=["answers", "manifest"])
@pytest.mark.parametrize("field", ["human_reviewer", "human_approved_at"])
def test_pending_review_artifacts_reject_approval_identity_or_time(
    approved_bundle: tuple[dict[str, Any], ...], artifact_index: int, field: str
) -> None:
    artifact = approved_bundle[artifact_index]
    review = artifact["review"] if artifact_index == 1 else artifact
    status_field = "review_status" if artifact_index == 1 else "human_review_status"
    review[status_field] = "ai_review_completed_pending_human_approval" if artifact_index == 1 else "pending_human_review"
    review["human_reviewer"] = REVIEWER if field == "human_reviewer" else None
    review["human_approved_at"] = APPROVED_AT if field == "human_approved_at" else None
    validator = validate_reference_answers_document if artifact_index == 1 else validate_review_manifest_document
    with pytest.raises(ReviewArtifactValidationError):
        validator(artifact)


@pytest.mark.parametrize(
    ("artifact_index", "status"),
    [(1, "confirmed"), (1, "approved"), (2, "human_approved"), (2, "approved")],
)
def test_review_artifacts_use_their_explicit_status_vocabulary(
    approved_bundle: tuple[dict[str, Any], ...], artifact_index: int, status: str
) -> None:
    artifact = approved_bundle[artifact_index]
    review = artifact["review"] if artifact_index == 1 else artifact
    review["review_status" if artifact_index == 1 else "human_review_status"] = status
    validator = validate_reference_answers_document if artifact_index == 1 else validate_review_manifest_document
    with pytest.raises(ReviewArtifactValidationError):
        validator(artifact)


@pytest.mark.parametrize("field", ["basis", "timestamp_basis", "previous_artifacts"])
def test_manifest_requires_explicit_approval_provenance(
    approved_bundle: tuple[dict[str, Any], ...], field: str
) -> None:
    manifest = approved_bundle[2]
    del manifest["approval_provenance"][field]
    with pytest.raises(ReviewArtifactValidationError):
        validate_review_manifest_document(manifest)


@pytest.mark.parametrize("artifact_index", [1, 2], ids=["answers", "manifest"])
@pytest.mark.parametrize(
    "field",
    ["status", "reviewer", "timestamp"],
)
def test_bundle_rejects_individually_valid_but_different_human_events(
    approved_bundle: tuple[dict[str, Any], ...], artifact_index: int, field: str
) -> None:
    ground_truth, answers, manifest = approved_bundle
    if artifact_index == 1:
        target = answers["review"]
        fields = {"status": "review_status", "reviewer": "human_reviewer", "timestamp": "human_approved_at"}
    else:
        target = manifest
        fields = {"status": "human_review_status", "reviewer": "human_reviewer", "timestamp": "human_approved_at"}
    if field == "status":
        target[fields[field]] = (
            "ai_review_completed_pending_human_approval" if artifact_index == 1 else "pending_human_review"
        )
        target[fields["reviewer"]] = None
        target[fields["timestamp"]] = None
    else:
        target[fields[field]] = "Another Reviewer" if field == "reviewer" else "2026-10-15T10:21:33+07:00"
    validate_reference_answers_document(answers)
    validate_review_manifest_document(manifest)
    # Refresh hashes so an approval mismatch cannot be hidden by a stale-hash failure.
    manifest["artifacts"]["reference_answers.json"] = _digest(answers)
    with pytest.raises(ReviewArtifactValidationError):
        _validate_bundle((ground_truth, answers, manifest))


@pytest.mark.parametrize(
    "path",
    [
        (1, "sources", "ground_truth", "sha256"),
        (2, "artifacts", "scenario_ground_truth.json"),
        (2, "artifacts", "reference_answers.json"),
    ],
)
def test_bundle_rejects_stale_approval_dependency_hashes(
    approved_bundle: tuple[dict[str, Any], ...], path: tuple[int | str, ...]
) -> None:
    _set_path(approved_bundle[path[0]], path[1:], "f" * 64)
    with pytest.raises(ReviewArtifactValidationError):
        _validate_bundle(approved_bundle)


def test_approval_upgrade_preserves_all_nonapproval_content(
    pending_bundle: tuple[dict[str, Any], ...],
) -> None:
    original = copy.deepcopy(pending_bundle)
    upgraded = _approve(pending_bundle)
    assert pending_bundle == original, "The transition must not mutate its input documents."
    before_gt, before_answers, before_manifest = copy.deepcopy(original)
    after_gt, after_answers, after_manifest = copy.deepcopy(upgraded)
    for document in (before_gt, after_gt):
        del document["schema_version"]
        for field in ("review_status", "reviewer", "reviewed_at"):
            del document["review"][field]
    for document in (before_answers, after_answers):
        del document["schema_version"]
        for field in ("review_status", "human_reviewer", "human_approved_at"):
            del document["review"][field]
        del document["sources"]["ground_truth"]["sha256"]
    for document in (before_manifest, after_manifest):
        del document["schema_version"]
        for field in ("human_review_status", "human_reviewer", "human_approved_at", "approval_provenance"):
            document.pop(field, None)
        for name in ("scenario_ground_truth.json", "reference_answers.json"):
            del document["artifacts"][name]
    assert after_gt == before_gt
    assert after_answers == before_answers
    assert after_manifest == before_manifest
    assert upgraded[1]["cases"] == original[1]["cases"]
    assert upgraded[0]["input_provenance"] == original[0]["input_provenance"]
    assert upgraded[2]["original_sources"] == original[2]["original_sources"]
    assert upgraded[2]["baseline_inputs"] == original[2]["baseline_inputs"]
    assert upgraded[2]["approval_provenance"]["previous_artifacts"] == {
        "scenario_ground_truth.json": _digest(original[0]),
        "reference_answers.json": _digest(original[1]),
        "review_manifest.json": _digest(original[2]),
    }


def test_approval_serialization_is_deterministic_utf8_and_valid_json(
    approved_bundle: tuple[dict[str, Any], ...],
) -> None:
    for document in approved_bundle:
        encoded = serialize_review_document(document)
        assert encoded == serialize_review_document(copy.deepcopy(document))
        assert encoded.endswith(b"\n")
        assert json.loads(encoded.decode("utf-8")) == document
    assert "bằng chứng".encode("utf-8") in serialize_review_document(approved_bundle[1])


def test_transition_rejects_reapproval(
    approved_bundle: tuple[dict[str, Any], ...],
) -> None:
    before = copy.deepcopy(approved_bundle)
    with pytest.raises(ValueError):
        _approve(approved_bundle)
    assert approved_bundle == before


def test_transition_rejects_mismatched_pending_baseline(
    pending_bundle: tuple[dict[str, Any], ...],
) -> None:
    pending_bundle[1]["sources"]["ground_truth"]["sha256"] = "f" * 64
    before = copy.deepcopy(pending_bundle)
    with pytest.raises(ValueError):
        _approve(pending_bundle)
    assert pending_bundle == before


def test_document_approval_does_not_enter_gate_signals_or_make_a_security_conclusion(
    pending_bundle: tuple[dict[str, Any], ...],
) -> None:
    from threat_hunting.graphrag import (
        GraphRAGGateSignalError,
        GraphRAGTwoStageGateError,
        assess_graphrag_two_stage_gate,
        validate_graphrag_gate_signals,
    )

    fixture_path = (
        Path(__file__).parent
        / "fixtures/graphrag/two_stage_gate/expected_two_stage_gate_decisions.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    signals, policy = fixture["base_signals"], fixture["base_policy"]
    before = assess_graphrag_two_stage_gate(signals, policy=policy)
    approved = _approve(pending_bundle)
    injected_signals = copy.deepcopy(signals)
    injected_signals["human_review_status"] = approved[0]["review"]["review_status"]
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(injected_signals)
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(injected_signals, policy=policy)
    after = assess_graphrag_two_stage_gate(signals, policy=policy)
    assert after == before
    assert after["decision"] == "proceed"
    assert after["metadata"]["decision_interpretation"] == "context_eligibility_only"
    assert after["metadata"]["security_conclusion_made"] is False
    assert "confirmed" not in json.dumps(after).casefold()
