from __future__ import annotations

from copy import deepcopy
import json
import math
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.retrieval import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)
from threat_hunting.retrieval import schema as retrieval_schema


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "retrieval_corpus_minimal.json"
)
EXPECTED_CHUNK_TYPES = {
    "scenario_summary": 1,
    "entity": 2,
    "fact": 1,
    "relationship": 1,
    "evidence": 1,
    "sigma_finding": 1,
    "mitre_assessment": 1,
    "limitation": 1,
}
REFERENCE_LIST_FIELDS = (
    "entity_ids",
    "fact_ids",
    "relationship_ids",
    "evidence_ids",
    "sigma_rule_ids",
    "mitre_external_ids",
    "queryable_dimensions",
)
FORBIDDEN_CONTRACT_FIELDS = {
    "questions",
    "evaluation_questions",
    "expected_answers",
    "question_id",
    "question_text",
    "expected_answer",
    "embedding",
    "embedding_model",
    "vector",
    "llm_response",
}


def _document() -> dict[str, Any]:
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _chunk(document: dict[str, Any], chunk_type: str) -> dict[str, Any]:
    return next(item for item in document["chunks"] if item["chunk_type"] == chunk_type)


def _write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _walk_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(key)
            keys.update(_walk_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.update(_walk_keys(nested))
    return keys


def test_schema_version_export_is_stable() -> None:
    assert RETRIEVAL_CORPUS_SCHEMA_VERSION == "retrieval-corpus/v1"


def test_minimal_fixture_is_valid() -> None:
    validate_retrieval_corpus(_document())


def test_fixture_contains_nine_chunks_across_all_required_types() -> None:
    document = _document()
    counts = {
        chunk_type: sum(
            item["chunk_type"] == chunk_type for item in document["chunks"]
        )
        for chunk_type in EXPECTED_CHUNK_TYPES
    }

    assert len(document["chunks"]) == 9
    assert counts == EXPECTED_CHUNK_TYPES


def test_loader_reads_valid_utf8_without_normalizing_content(tmp_path: Path) -> None:
    document = _document()
    document["metadata"]["unicode_label"] = "Dữ liệu tổng quát"
    document["chunks"][0]["content"] += " Nội dung giữ nguyên Unicode."
    path = tmp_path / "corpus_unicode.json"
    _write(path, document)

    loaded = load_retrieval_corpus(path)

    assert loaded == document
    assert loaded["metadata"]["unicode_label"] == "Dữ liệu tổng quát"


def test_loader_rejects_duplicate_json_keys_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":"retrieval-corpus/v1",'
        '"schema_version":"retrieval-corpus/v1"}\n',
        encoding="utf-8",
    )

    with pytest.raises(RetrievalCorpusValidationError) as exc_info:
        load_retrieval_corpus(path)

    assert "duplicate JSON object key" in str(exc_info.value)
    assert str(path) in str(exc_info.value)


def test_loader_rejects_malformed_json_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"schema_version": ', encoding="utf-8")

    with pytest.raises(RetrievalCorpusValidationError) as exc_info:
        load_retrieval_corpus(path)

    assert str(path) in str(exc_info.value)


def test_loader_rejects_non_object_top_level_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "array.json"
    path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(RetrievalCorpusValidationError) as exc_info:
        load_retrieval_corpus(path)

    assert "must be a JSON object" in str(exc_info.value)
    assert str(path) in str(exc_info.value)


def test_wrong_schema_version_is_rejected() -> None:
    document = _document()
    document["schema_version"] = "retrieval-corpus/v999"

    with pytest.raises(RetrievalCorpusValidationError, match="schema_version"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_top_level_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["warnings"]
    else:
        document["extra"] = []

    with pytest.raises(RetrievalCorpusValidationError, match=mode):
        validate_retrieval_corpus(document)


def test_duplicate_chunk_id_is_rejected() -> None:
    document = _document()
    document["chunks"][1]["chunk_id"] = document["chunks"][0]["chunk_id"]

    with pytest.raises(RetrievalCorpusValidationError, match="Duplicate chunk_id"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("location", ("source_ground_truth", "chunk"))
def test_scenario_id_mismatch_is_rejected(location: str) -> None:
    document = _document()
    if location == "source_ground_truth":
        document["source_ground_truth"]["scenario_id"] = "scenario-other"
    else:
        document["chunks"][0]["scenario_id"] = "scenario-other"

    with pytest.raises(RetrievalCorpusValidationError, match="scenario_id"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize(
    "digest",
    (
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "",
    ),
)
def test_source_ground_truth_sha256_must_be_exact_hex(digest: str) -> None:
    document = _document()
    document["source_ground_truth"]["sha256"] = digest

    with pytest.raises(RetrievalCorpusValidationError, match="sha256"):
        validate_retrieval_corpus(document)


def test_source_ground_truth_schema_version_is_fixed() -> None:
    document = _document()
    document["source_ground_truth"]["schema_version"] = "other/v1"

    with pytest.raises(RetrievalCorpusValidationError, match="scenario-ground-truth/v1"):
        validate_retrieval_corpus(document)


def test_unsupported_chunk_type_is_rejected() -> None:
    document = _document()
    document["chunks"][0]["chunk_type"] = "scenario_specific_behavior"

    with pytest.raises(RetrievalCorpusValidationError, match="unsupported value"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("status", ("observed", "inferred", "candidate", "reviewable"))
def test_complete_conservative_status_vocabulary_is_accepted(status: str) -> None:
    document = _document()
    document["chunks"][0]["status"] = status

    validate_retrieval_corpus(document)


def test_unsupported_status_is_rejected() -> None:
    document = _document()
    document["chunks"][0]["status"] = "approved"

    with pytest.raises(RetrievalCorpusValidationError, match="unsupported value"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("value", ("confirmed", "CONFIRMED", "ConFiRmEd"))
def test_confirmed_is_rejected_case_insensitively(value: str) -> None:
    document = _document()
    document["chunks"][0]["status"] = value

    with pytest.raises(RetrievalCorpusValidationError, match="confirmed"):
        validate_retrieval_corpus(document)


def test_nested_status_like_confirmed_is_rejected() -> None:
    document = _document()
    document["chunks"][0]["metadata"]["nested"] = {
        "assessment_status": "CoNfIrMeD"
    }

    with pytest.raises(RetrievalCorpusValidationError, match="confirmed"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("content", ("", "   "))
def test_empty_chunk_content_is_rejected(content: str) -> None:
    document = _document()
    document["chunks"][0]["content"] = content

    with pytest.raises(RetrievalCorpusValidationError, match="content"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize(
    "content",
    (
        "Which entity participated?",
        "Question: identify the entity",
        "Expected answer: entity alpha",
    ),
)
def test_question_or_expected_answer_shaped_content_is_rejected(content: str) -> None:
    document = _document()
    document["chunks"][0]["content"] = content

    with pytest.raises(RetrievalCorpusValidationError, match="not a question"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("pointer", ("", "entities/0"))
def test_source_json_pointer_must_be_nonempty_and_absolute(pointer: str) -> None:
    document = _document()
    document["chunks"][1]["source"]["json_pointer"] = pointer

    with pytest.raises(RetrievalCorpusValidationError, match="json_pointer"):
        validate_retrieval_corpus(document)


def test_chunk_type_source_object_type_mapping_is_enforced() -> None:
    document = _document()
    _chunk(document, "entity")["source"]["object_type"] = "fact"

    with pytest.raises(RetrievalCorpusValidationError, match="object_type"):
        validate_retrieval_corpus(document)


def test_fixture_exercises_every_chunk_source_mapping() -> None:
    document = _document()

    assert {
        item["chunk_type"]: item["source"]["object_type"]
        for item in document["chunks"]
    } == retrieval_schema.CHUNK_SOURCE_OBJECT_TYPES


@pytest.mark.parametrize("field", REFERENCE_LIST_FIELDS)
def test_duplicate_chunk_reference_list_value_is_rejected(field: str) -> None:
    document = _document()
    chunk = document["chunks"][0]
    if not chunk[field]:
        chunk[field] = ["synthetic-value"]
    chunk[field].append(chunk[field][0])

    with pytest.raises(RetrievalCorpusValidationError, match="duplicate value"):
        validate_retrieval_corpus(document)


def test_duplicate_source_reference_pair_is_rejected() -> None:
    document = _document()
    references = document["chunks"][0]["source_references"]
    references.append(deepcopy(references[0]))

    with pytest.raises(RetrievalCorpusValidationError, match="duplicate source reference"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("field", ("source_file", "raw_record_ref"))
def test_source_reference_requires_nonempty_fields(field: str) -> None:
    document = _document()
    document["chunks"][0]["source_references"][0][field] = ""

    with pytest.raises(RetrievalCorpusValidationError, match=field):
        validate_retrieval_corpus(document)


def test_chunk_dimension_must_be_declared_by_corpus() -> None:
    document = _document()
    document["chunks"][0]["queryable_dimensions"].append("undeclared")

    with pytest.raises(RetrievalCorpusValidationError, match="not declared"):
        validate_retrieval_corpus(document)


def test_duplicate_corpus_dimension_is_rejected() -> None:
    document = _document()
    document["queryable_dimensions"].append(document["queryable_dimensions"][0])

    with pytest.raises(RetrievalCorpusValidationError, match="duplicate value"):
        validate_retrieval_corpus(document)


def test_empty_corpus_dimensions_are_rejected() -> None:
    document = _document()
    document["queryable_dimensions"] = []

    with pytest.raises(RetrievalCorpusValidationError, match="must not be empty"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("field,value", (("reviewer", "analyst"), ("reviewed_at", "2026-01-01T00:00:00Z")))
def test_review_identity_and_time_must_remain_null(field: str, value: str) -> None:
    document = _document()
    document["review"][field] = value

    with pytest.raises(RetrievalCorpusValidationError, match=field):
        validate_retrieval_corpus(document)


def test_document_review_status_must_remain_pending() -> None:
    document = _document()
    document["review"]["review_status"] = "approved"

    with pytest.raises(RetrievalCorpusValidationError, match="review_status"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("field", sorted(FORBIDDEN_CONTRACT_FIELDS))
def test_question_answer_embedding_vector_and_llm_fields_are_rejected_recursively(
    field: str,
) -> None:
    document = _document()
    document["chunks"][0]["metadata"]["nested"] = {field: "forbidden"}

    with pytest.raises(RetrievalCorpusValidationError, match="forbidden"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("value", (math.nan, math.inf, -math.inf))
def test_nonfinite_numbers_are_rejected(value: float) -> None:
    document = _document()
    document["metadata"]["score"] = value

    with pytest.raises(RetrievalCorpusValidationError, match="finite JSON numbers"):
        validate_retrieval_corpus(document)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_loader_rejects_nonstandard_json_numbers(
    tmp_path: Path, constant: str
) -> None:
    text = FIXTURE_PATH.read_text(encoding="utf-8")
    text = text.replace('"fixture": true', f'"fixture": {constant}', 1)
    path = tmp_path / "nonstandard_number.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(RetrievalCorpusValidationError, match="non-standard JSON number"):
        load_retrieval_corpus(path)


def test_validator_rejects_values_not_representable_in_json() -> None:
    document = _document()
    document["metadata"]["tuple"] = ("not", "json")

    with pytest.raises(RetrievalCorpusValidationError, match="cannot be represented"):
        validate_retrieval_corpus(document)


def test_validator_rejects_non_string_metadata_keys() -> None:
    document = _document()
    document["metadata"][1] = "invalid"

    with pytest.raises(RetrievalCorpusValidationError, match="non-string object key"):
        validate_retrieval_corpus(document)


def test_validator_does_not_mutate_input() -> None:
    document = _document()
    before = deepcopy(document)

    validate_retrieval_corpus(document)

    assert document == before


def test_fixture_is_entirely_synthetic_and_scenario_independent() -> None:
    text = FIXTURE_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "cmd.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:",
    ):
        assert forbidden not in text
    assert "synthetic" in text


def test_fixture_has_no_question_expected_answer_or_confirmed_values() -> None:
    document = _document()
    keys = {key.casefold() for key in _walk_keys(document)}
    serialized = json.dumps(document, ensure_ascii=False).casefold()

    assert FORBIDDEN_CONTRACT_FIELDS.isdisjoint(keys)
    assert '"confirmed"' not in serialized


def test_v1_contract_has_no_embedding_vector_or_llm_payload_fields() -> None:
    declared_fields = set(retrieval_schema.TOP_LEVEL_FIELDS)
    declared_fields.update(retrieval_schema.CHUNK_FIELDS)
    declared_fields.update(retrieval_schema.CHUNK_SOURCE_FIELDS)

    assert {
        "embedding",
        "embedding_model",
        "vector",
        "llm_response",
    }.isdisjoint(declared_fields)


def test_source_artifact_type_is_fixed_to_ground_truth() -> None:
    document = _document()
    document["chunks"][0]["source"]["artifact_type"] = "raw_event"

    with pytest.raises(RetrievalCorpusValidationError, match="artifact_type"):
        validate_retrieval_corpus(document)


def test_aggregate_chunk_object_id_must_be_null() -> None:
    document = _document()
    _chunk(document, "scenario_summary")["source"]["object_id"] = "scenario-id"

    with pytest.raises(RetrievalCorpusValidationError, match="object_id"):
        validate_retrieval_corpus(document)


def test_object_chunk_object_id_must_be_nonempty() -> None:
    document = _document()
    _chunk(document, "entity")["source"]["object_id"] = None

    with pytest.raises(RetrievalCorpusValidationError, match="object_id"):
        validate_retrieval_corpus(document)


def test_chunk_field_set_is_strict() -> None:
    document = _document()
    document["chunks"][0]["extra"] = "not allowed"

    with pytest.raises(RetrievalCorpusValidationError, match="unexpected"):
        validate_retrieval_corpus(document)


def test_metadata_remains_a_json_extension_container() -> None:
    document = _document()
    document["metadata"]["extension"] = {
        "labels": ["alpha", "beta"],
        "score": 1.25,
        "enabled": True,
        "optional": None,
    }

    validate_retrieval_corpus(document)
