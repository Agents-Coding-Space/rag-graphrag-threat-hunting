from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth import (
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


@pytest.fixture
def valid_document() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _set_path(document: dict[str, Any], path: tuple[str | int, ...], value: object) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def test_minimal_fixture_is_valid() -> None:
    document = load_ground_truth_document(FIXTURE_PATH)
    assert document["schema_version"] == SCENARIO_GROUND_TRUTH_SCHEMA_VERSION
    assert len(document["entities"]) == 2
    assert len(document["evidence"]) == 1
    assert len(document["facts"]) == 1
    assert len(document["relationships"]) == 1
    assert len(document["sigma_findings"]) == 1
    assert len(document["mitre_assessments"]) == 1


def test_wrong_schema_version_is_rejected(valid_document: dict[str, Any]) -> None:
    valid_document["schema_version"] = "scenario-ground-truth/v999"
    with pytest.raises(GroundTruthValidationError, match="schema_version"):
        validate_ground_truth_document(valid_document)


def test_missing_top_level_field_is_rejected(valid_document: dict[str, Any]) -> None:
    del valid_document["facts"]
    with pytest.raises(GroundTruthValidationError, match="missing"):
        validate_ground_truth_document(valid_document)


def test_unknown_top_level_field_is_rejected(valid_document: dict[str, Any]) -> None:
    valid_document["extra"] = []
    with pytest.raises(GroundTruthValidationError, match="unexpected"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize("field", ("evaluation_questions", "expected_answers"))
def test_question_or_answer_collection_is_rejected(
    valid_document: dict[str, Any], field: str
) -> None:
    valid_document[field] = []
    with pytest.raises(GroundTruthValidationError, match="forbidden"):
        validate_ground_truth_document(valid_document)


def test_question_fields_are_rejected_recursively(valid_document: dict[str, Any]) -> None:
    valid_document["entities"][0]["attributes"]["question_id"] = "fixture-question"
    with pytest.raises(GroundTruthValidationError, match="forbidden"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize(
    ("collection", "id_field"),
    (
        ("input_provenance", "input_id"),
        ("entities", "entity_id"),
        ("facts", "fact_id"),
        ("relationships", "relationship_id"),
        ("evidence", "evidence_id"),
        ("sigma_findings", "finding_id"),
        ("mitre_assessments", "assessment_id"),
    ),
)
def test_duplicate_collection_ids_are_rejected(
    valid_document: dict[str, Any], collection: str, id_field: str
) -> None:
    valid_document[collection].append(copy.deepcopy(valid_document[collection][0]))
    with pytest.raises(GroundTruthValidationError, match=f"Duplicate {id_field}"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize("field", ("source_entity_id", "target_entity_id"))
def test_relationship_must_reference_existing_entities(
    valid_document: dict[str, Any], field: str
) -> None:
    valid_document["relationships"][0][field] = "entity-missing"
    with pytest.raises(GroundTruthValidationError, match="unknown entity_id"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize(
    "path",
    (
        ("entities", 0, "evidence_ids"),
        ("facts", 0, "evidence_ids"),
        ("relationships", 0, "evidence_ids"),
        ("sigma_findings", 0, "evidence_ids"),
        ("mitre_assessments", 0, "supporting_evidence_ids"),
    ),
)
def test_evidence_references_must_exist(
    valid_document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    _set_path(valid_document, path, ["evidence-missing"])
    with pytest.raises(GroundTruthValidationError, match="unknown evidence_id"):
        validate_ground_truth_document(valid_document)


def test_sigma_rule_reference_must_exist(valid_document: dict[str, Any]) -> None:
    valid_document["mitre_assessments"][0]["supporting_sigma_rule_ids"] = [
        "rule-missing"
    ]
    with pytest.raises(GroundTruthValidationError, match="unknown Sigma rule_id"):
        validate_ground_truth_document(valid_document)


def test_provenance_scenario_id_must_match(valid_document: dict[str, Any]) -> None:
    valid_document["input_provenance"][0]["scenario_id"] = "scenario-other"
    with pytest.raises(GroundTruthValidationError, match="must match"):
        validate_ground_truth_document(valid_document)


def test_null_provenance_scenario_id_is_allowed(valid_document: dict[str, Any]) -> None:
    valid_document["input_provenance"][0]["scenario_id"] = None
    validate_ground_truth_document(valid_document)


@pytest.mark.parametrize(
    "path",
    (
        ("scenario", "analysis_status"),
        ("entities", 0, "status"),
        ("facts", 0, "status"),
        ("relationships", 0, "status"),
        ("evidence", 0, "status"),
        ("sigma_findings", 0, "status"),
        ("mitre_assessments", 0, "status"),
        ("mitre_assessments", 0, "origin"),
        ("mitre_assessments", 0, "evidence_support"),
        ("mitre_assessments", 0, "review_status"),
        ("review", "review_status"),
    ),
)
def test_invalid_status_vocabulary_is_rejected(
    valid_document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    _set_path(valid_document, path, "unsupported-value")
    with pytest.raises(GroundTruthValidationError, match="unsupported value"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize(
    "path",
    (
        ("scenario", "analysis_status"),
        ("entities", 0, "status"),
        ("mitre_assessments", 0, "review_status"),
    ),
)
def test_confirmed_is_rejected_case_insensitively(
    valid_document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    _set_path(valid_document, path, "CoNfIrMeD")
    with pytest.raises(GroundTruthValidationError, match="confirmed"):
        validate_ground_truth_document(valid_document)


def test_confirmed_is_rejected_in_nested_status_like_field(
    valid_document: dict[str, Any],
) -> None:
    valid_document["entities"][0]["attributes"]["custom_status"] = "CONFIRMED"
    with pytest.raises(GroundTruthValidationError, match="confirmed"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize(
    "path",
    (
        ("input_provenance", 0, "sha256"),
        ("sigma_findings", 0, "rule_sha256"),
    ),
)
def test_invalid_sha256_is_rejected(
    valid_document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    _set_path(valid_document, path, "not-a-sha256")
    with pytest.raises(GroundTruthValidationError, match="64 hexadecimal"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize("field", ("source_file", "raw_record_ref"))
def test_source_reference_requires_both_fields(
    valid_document: dict[str, Any], field: str
) -> None:
    del valid_document["facts"][0]["source_references"][0][field]
    with pytest.raises(GroundTruthValidationError, match="fields do not match"):
        validate_ground_truth_document(valid_document)


@pytest.mark.parametrize("field", ("source_file", "raw_record_ref"))
def test_observation_requires_nonempty_provenance(
    valid_document: dict[str, Any], field: str
) -> None:
    valid_document["evidence"][0]["observations"][0][field] = ""
    with pytest.raises(GroundTruthValidationError, match=field):
        validate_ground_truth_document(valid_document)


def test_duplicate_queryable_dimension_is_rejected(
    valid_document: dict[str, Any],
) -> None:
    valid_document["queryable_dimensions"].append(
        valid_document["queryable_dimensions"][0]
    )
    with pytest.raises(GroundTruthValidationError, match="duplicate value"):
        validate_ground_truth_document(valid_document)


def test_nested_objects_reject_fields_outside_the_contract(
    valid_document: dict[str, Any],
) -> None:
    valid_document["evidence"][0]["unexpected"] = "not allowed"
    with pytest.raises(GroundTruthValidationError, match="unexpected"):
        validate_ground_truth_document(valid_document)


def test_entity_type_is_open_but_must_be_nonempty(
    valid_document: dict[str, Any],
) -> None:
    valid_document["entities"][0]["entity_type"] = "future_entity_type"
    validate_ground_truth_document(valid_document)
    valid_document["entities"][0]["entity_type"] = " "
    with pytest.raises(GroundTruthValidationError, match="entity_type"):
        validate_ground_truth_document(valid_document)


def test_queryable_dimensions_are_open_vocabulary(
    valid_document: dict[str, Any],
) -> None:
    valid_document["queryable_dimensions"].append("future_dimension")
    validate_ground_truth_document(valid_document)


def test_validator_does_not_mutate_input(valid_document: dict[str, Any]) -> None:
    before = copy.deepcopy(valid_document)
    validate_ground_truth_document(valid_document)
    assert valid_document == before


def test_validation_result_and_error_are_deterministic(
    valid_document: dict[str, Any],
) -> None:
    assert validate_ground_truth_document(valid_document) is None
    assert validate_ground_truth_document(valid_document) is None

    valid_document["relationships"][0]["target_entity_id"] = "entity-missing"
    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(GroundTruthValidationError) as error:
            validate_ground_truth_document(valid_document)
        messages.append(str(error.value))
    assert messages[0] == messages[1]


def test_load_error_contains_filename(tmp_path: Path) -> None:
    path = tmp_path / "invalid_ground_truth.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(GroundTruthValidationError, match=path.name):
        load_ground_truth_document(path)


def test_load_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate_keys.json"
    path.write_text('{"schema_version": "a", "schema_version": "b"}', encoding="utf-8")
    with pytest.raises(GroundTruthValidationError, match="duplicate JSON object key"):
        load_ground_truth_document(path)
