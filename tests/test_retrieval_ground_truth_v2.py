"""Retrieval compatibility and evidence preservation for approved GT v2 sources."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth import validate_ground_truth_document
from threat_hunting.retrieval import (
    RetrievalCorpusBuildError,
    RetrievalCorpusValidationError,
    build_retrieval_corpus,
    retrieve_lexical,
    validate_retrieval_corpus,
)


FIXTURES = Path(__file__).parent / "fixtures"
GROUND_TRUTH_PATH = FIXTURES / "ground_truth/builder/expected_ground_truth.json"
GOLDEN_CORPUS_PATH = FIXTURES / "retrieval/builder/expected_retrieval_corpus.json"
SOURCE_PATH = "logical/reviewed_ground_truth.json"
REVIEWER = "Synthetic Human Reviewer"
REVIEWED_AT = "2024-01-02T10:20:30+07:00"
EXCLUDED_REVIEW_NOTE = "BENCHMARK_REFERENCE_ANSWER_AND_CASE_ID_ARE_NOT_EVIDENCE"


def _json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _source(approved: bool = True) -> dict[str, Any]:
    source = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    source["schema_version"] = "scenario-ground-truth/v2"
    source["review"].update(
        review_status="confirmed" if approved else "pending_human_review",
        reviewer=REVIEWER if approved else None,
        reviewed_at=REVIEWED_AT if approved else None,
    )
    source["review"]["notes"].append(EXCLUDED_REVIEW_NOTE)
    source["facts"][0]["attributes"]["source_observations"] = [
        {
            "source_file": "synthetic_events.jsonl",
            "raw_record_ref": "fixture:record:1",
            "original_fields": {
                "CommandLine": '"worker-beta.bin" --needleproof "Dữ liệu gốc"',
                "ParentCommandLine": '"launcher-alpha.bin" --synthetic',
                "ParentImage": "launcher-alpha.bin",
                "Image": "worker-beta.bin",
                "ProcessId": "17",
                "ParentProcessId": "9",
                "ProcessGuid": "synthetic-child-guid",
                "ParentProcessGuid": "synthetic-parent-guid",
                "TimeCreated": "2024-01-01T00:00:00Z",
            },
        }
    ]
    source["summary"]["limitations"] = [
        f"Scopebound{index}: only synthetic launch telemetry; no completion result."
        for index in range(7)
    ]
    return source


def _build(source: dict[str, Any]) -> dict[str, Any]:
    return build_retrieval_corpus(
        source,
        source_ground_truth_path=SOURCE_PATH,
        source_ground_truth_sha256=sha256(_json_text(source).encode("utf-8")).hexdigest(),
    )


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_keys(item) for item in value))
    return set()


def test_v1_matches_untouched_complete_golden_output() -> None:
    source_bytes = GROUND_TRUTH_PATH.read_bytes()
    golden_bytes = GOLDEN_CORPUS_PATH.read_bytes()
    corpus = build_retrieval_corpus(
        json.loads(source_bytes),
        source_ground_truth_path=GROUND_TRUTH_PATH.relative_to(
            Path(__file__).parents[1]
        ).as_posix(),
        source_ground_truth_sha256=sha256(source_bytes).hexdigest(),
    )

    assert corpus == json.loads(golden_bytes)
    assert GROUND_TRUTH_PATH.read_bytes() == source_bytes
    assert GOLDEN_CORPUS_PATH.read_bytes() == golden_bytes


@pytest.mark.parametrize("approved", (False, True))
def test_v2_uses_validated_actual_source_version_and_provenance(approved: bool) -> None:
    source = _source(approved)
    validate_ground_truth_document(source)
    corpus = _build(source)

    validate_retrieval_corpus(corpus)
    assert corpus["schema_version"] == "retrieval-corpus/v1"
    assert corpus["source_ground_truth"] == {
        "path": SOURCE_PATH,
        "schema_version": source["schema_version"],
        "sha256": sha256(_json_text(source).encode("utf-8")).hexdigest(),
        "scenario_id": source["scenario"]["scenario_id"],
    }


@pytest.mark.parametrize("approved", (False, True))
def test_v2_source_review_does_not_leak_or_promote_generated_artifact(approved: bool) -> None:
    corpus = _build(_source(approved))
    serialized = _json_text(corpus)

    assert "source_review_status" not in _keys(corpus)
    assert REVIEWER not in serialized
    assert REVIEWED_AT not in serialized
    assert EXCLUDED_REVIEW_NOTE not in serialized
    assert '"confirmed"' not in serialized
    assert corpus["review"]["review_status"] == "pending_human_review"
    assert corpus["review"]["reviewer"] is None
    assert corpus["review"]["reviewed_at"] is None


def test_v2_approval_changes_provenance_binding_only() -> None:
    pending = _build(_source(False))
    approved = _build(_source(True))

    assert approved["source_ground_truth"]["sha256"] != pending["source_ground_truth"]["sha256"]
    assert approved["corpus_id"] != pending["corpus_id"]
    pending["source_ground_truth"]["sha256"] = approved["source_ground_truth"]["sha256"]
    pending["corpus_id"] = approved["corpus_id"]
    assert approved == pending


def test_v2_preserves_original_source_values_in_runtime_retrieval_text() -> None:
    source = _source()
    result = retrieve_lexical(
        _build(source), "needleproof", top_k=1, chunk_types=["fact"]
    )

    assert len(result["hits"]) == 1
    chunk = result["hits"][0]["chunk"]
    attributes = json.loads(chunk["content"].split("Attributes: ", 1)[1][:-1])
    assert attributes == source["facts"][0]["attributes"]
    assert attributes["source_observations"][0]["original_fields"]["CommandLine"] == (
        '"worker-beta.bin" --needleproof "Dữ liệu gốc"'
    )
    assert chunk["source_references"] == source["facts"][0]["source_references"]
    assert chunk["entity_ids"] == sorted(
        [source["facts"][0]["subject"], source["facts"][0]["object"]]
    )


def test_v2_preserves_every_limitation_and_can_return_each_at_runtime() -> None:
    source = _source()
    corpus = _build(source)
    chunks = [item for item in corpus["chunks"] if item["chunk_type"] == "limitation"]

    assert [item["content"] for item in chunks] == source["summary"]["limitations"]
    for index, limitation in enumerate(source["summary"]["limitations"]):
        result = retrieve_lexical(
            corpus, f"Scopebound{index}", top_k=1, chunk_types=["limitation"]
        )
        assert result["hits"][0]["chunk"]["content"] == limitation


def test_v2_preserves_source_security_statuses_and_determinism_without_mutation() -> None:
    source = _source()
    before = deepcopy(source)
    first = _build(source)
    second = _build(source)

    assert first == second
    assert _json_text(first) == _json_text(second)
    assert source == before
    assert len({chunk["chunk_id"] for chunk in first["chunks"]}) == len(first["chunks"])
    for collection, identifier in (
        ("entities", "entity_id"),
        ("facts", "fact_id"),
        ("relationships", "relationship_id"),
        ("evidence", "evidence_id"),
        ("sigma_findings", "finding_id"),
        ("mitre_assessments", "assessment_id"),
    ):
        for item in source[collection]:
            chunk = next(
                chunk for chunk in first["chunks"]
                if chunk["source"]["object_id"] == item[identifier]
            )
            assert chunk["status"] == item["status"]


@pytest.mark.parametrize("version", ("scenario-ground-truth/v0", "scenario-ground-truth/v3", "other/v2", "scenario-ground-truth/v2 "))
def test_builder_rejects_unsupported_actual_source_version(version: str) -> None:
    source = _source(False)
    source["schema_version"] = version

    with pytest.raises(RetrievalCorpusBuildError, match="schema_version"):
        _build(source)


@pytest.mark.parametrize("version", ("scenario-ground-truth/v0", "scenario-ground-truth/v3", "other/v2", "scenario-ground-truth/v2 "))
def test_corpus_rejects_unsupported_source_provenance_version(version: str) -> None:
    corpus = _build(_source())
    corpus["source_ground_truth"]["schema_version"] = version

    with pytest.raises(RetrievalCorpusValidationError, match="schema_version"):
        validate_retrieval_corpus(corpus)


@pytest.mark.parametrize("field", ("questions", "expected_answer", "question_id"))
def test_v2_builder_rejects_benchmark_fields_in_evidence_attributes(field: str) -> None:
    source = _source()
    source["facts"][0]["attributes"][field] = "benchmark-only sentinel"

    with pytest.raises(RetrievalCorpusBuildError, match="forbidden"):
        _build(source)


def test_v2_keeps_existing_confirmed_security_status_guard() -> None:
    source = _source()
    source["facts"][0]["status"] = "confirmed"

    with pytest.raises(RetrievalCorpusBuildError, match="confirmed"):
        _build(source)

    corpus = _build(_source())
    corpus["chunks"][0]["metadata"]["source_review_status"] = "confirmed"
    with pytest.raises(RetrievalCorpusValidationError, match="confirmed"):
        validate_retrieval_corpus(corpus)
