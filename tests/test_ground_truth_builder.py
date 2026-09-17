from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth import (
    GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION,
    GroundTruthBuildError,
    build_ground_truth_core,
    validate_ground_truth_build_config,
    validate_ground_truth_document,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "ground_truth" / "builder"
ARTIFACTS = {
    "scenario_evidence": (
        "scenario-evidence-input",
        "scenario_evidence.json",
        "scenario-evidence/v1",
    ),
    "sigma_review": (
        "sigma-review-input",
        "sigma_match_review.json",
        "sigma-match-review/v1",
    ),
    "mitre_resolution": (
        "mitre-resolution-input",
        "mitre_resolution.json",
        "mitre-resolution/v1",
    ),
}
FORBIDDEN_CORE_FIELDS = {
    "evaluation_questions",
    "expected_answers",
    "question_id",
    "question_text",
    "expected_answer",
    "answer_id",
}


def _json(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _inputs() -> dict[str, Any]:
    documents: dict[str, dict[str, Any]] = {}
    provenance: list[dict[str, Any]] = []
    for input_type, (input_id, filename, schema_version) in ARTIFACTS.items():
        path = FIXTURE_ROOT / filename
        documents[input_type] = _json(filename)
        provenance.append(
            {
                "input_id": input_id,
                "input_type": input_type,
                "path": filename,
                "schema_version": schema_version,
                "sha256": sha256(path.read_bytes()).hexdigest(),
                "scenario_id": "scenario-synthetic-builder",
            }
        )
    return {
        **documents,
        "input_provenance": provenance,
        "build_config": _json("build_config.json"),
    }


def _build(inputs: dict[str, Any] | None = None) -> dict[str, object]:
    return build_ground_truth_core(**(inputs or _inputs()))


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def test_build_matches_complete_expected_fixture() -> None:
    assert _build() == _json("expected_ground_truth.json")


def test_built_document_passes_gt1_validation() -> None:
    validate_ground_truth_document(_build())


def test_fixture_exercises_required_aggregation_counts() -> None:
    result = _build()

    assert len(result["entities"]) == 3
    assert len(result["evidence"]) == 2
    assert len(result["relationships"]) == 2
    assert len(result["sigma_findings"]) == 2
    assert sum(
        len(item["observation_match_ids"])
        for item in result["sigma_findings"]
    ) == 4
    assert sum(
        len(item["behavior_match_ids"])
        for item in result["sigma_findings"]
    ) == 2
    assert len(result["mitre_assessments"]) == 2


def test_builder_never_emits_confirmed() -> None:
    assert all(
        not (isinstance(value, str) and value.casefold() == "confirmed")
        for value in _walk(_build())
    )


def test_builder_never_emits_question_or_expected_answer_fields() -> None:
    keys = {value for value in _walk(_build()) if isinstance(value, str)}
    assert keys.isdisjoint(FORBIDDEN_CORE_FIELDS)


def test_entity_evidence_is_only_from_incident_relationships() -> None:
    entities = {item["entity_id"]: item for item in _build()["entities"]}

    assert entities["entity-synthetic-alpha"]["evidence_ids"] == [
        "evidence-synthetic-1"
    ]
    assert entities["entity-synthetic-beta"]["evidence_ids"] == [
        "evidence-synthetic-1",
        "evidence-synthetic-2",
    ]
    assert entities["entity-synthetic-gamma"]["evidence_ids"] == [
        "evidence-synthetic-2"
    ]


def test_entity_names_use_config_then_source_attribute_fallbacks() -> None:
    entities = {item["entity_id"]: item for item in _build()["entities"]}

    assert entities["entity-synthetic-alpha"]["name"] == "Alpha display override"
    assert entities["entity-synthetic-beta"]["name"] == "worker-beta.bin"
    assert entities["entity-synthetic-gamma"]["name"] == "host-gamma"


def test_sigma_findings_aggregate_observation_and_behavior_matches_per_rule() -> None:
    findings = {item["rule_id"]: item for item in _build()["sigma_findings"]}

    assert findings["rule-synthetic-alpha"]["observation_match_ids"] == [
        "observation-match-synthetic-1",
        "observation-match-synthetic-2",
    ]
    assert findings["rule-synthetic-alpha"]["behavior_match_ids"] == [
        "behavior-match-synthetic-1"
    ]
    assert findings["rule-synthetic-beta"]["caveats"] == [
        "known_unmapped_field: SyntheticField"
    ]


def test_missing_mitre_decision_defaults_to_not_assessed_without_evidence() -> None:
    assessments = {
        item["external_id"]: item for item in _build()["mitre_assessments"]
    }

    assert assessments["SYN-1001"]["evidence_support"] == (
        "supported_by_observed_behavior"
    )
    assert assessments["SYN-1002"]["evidence_support"] == "not_assessed"
    assert assessments["SYN-1002"]["supporting_evidence_ids"] == []


def test_deterministic_ids_and_repeated_builds() -> None:
    first = _build()
    second = _build()

    assert first == second
    assert all(
        item["finding_id"].startswith("sigma-finding--")
        for item in first["sigma_findings"]
    )
    assert all(
        item["assessment_id"].startswith("mitre-assessment--")
        for item in first["mitre_assessments"]
    )


def test_builder_does_not_mutate_any_input() -> None:
    inputs = _inputs()
    before = deepcopy(inputs)

    _build(inputs)

    assert inputs == before


def test_list_order_in_artifacts_does_not_change_output() -> None:
    inputs = _inputs()
    evidence = inputs["scenario_evidence"]
    for field in ("observed_entities", "evidence", "relationships"):
        evidence[field].reverse()
    for item in evidence["evidence"]:
        item["observations"].reverse()
    sigma = inputs["sigma_review"]
    for field in ("rules", "observation_matches", "behavior_matches"):
        sigma[field].reverse()
    for item in sigma["behavior_matches"]:
        item["source_references"].reverse()
    mitre = inputs["mitre_resolution"]
    mitre["resolved_techniques"].reverse()
    mitre["rule_technique_candidate_links"].reverse()
    inputs["input_provenance"].reverse()
    inputs["build_config"]["facts"].reverse()
    inputs["build_config"]["queryable_dimensions"].reverse()

    assert _build(inputs) == _build()


def test_output_lists_have_stable_primary_order() -> None:
    result = _build()

    for field, identifier in (
        ("input_provenance", "input_id"),
        ("entities", "entity_id"),
        ("facts", "fact_id"),
        ("relationships", "relationship_id"),
        ("evidence", "evidence_id"),
        ("sigma_findings", "rule_id"),
        ("mitre_assessments", "external_id"),
    ):
        values = [item[identifier] for item in result[field]]
        assert values == sorted(values)
    assert result["queryable_dimensions"] == sorted(result["queryable_dimensions"])


@pytest.mark.parametrize(
    ("artifact", "bad_version"),
    (
        ("scenario_evidence", "scenario-evidence/v0"),
        ("sigma_review", "sigma-match-review/v0"),
        ("mitre_resolution", "mitre-resolution/v0"),
    ),
)
def test_rejects_wrong_artifact_schema_version(
    artifact: str, bad_version: str
) -> None:
    inputs = _inputs()
    inputs[artifact]["schema_version"] = bad_version

    with pytest.raises(GroundTruthBuildError, match="schema_version"):
        _build(inputs)


@pytest.mark.parametrize(
    "artifact", ("scenario_evidence", "sigma_review", "mitre_resolution")
)
def test_rejects_artifact_scenario_mismatch(artifact: str) -> None:
    inputs = _inputs()
    inputs[artifact]["scenario_id"] = "scenario-other"

    with pytest.raises(GroundTruthBuildError, match="scenario_id"):
        _build(inputs)


@pytest.mark.parametrize(
    ("artifact", "bad_status"),
    (
        ("scenario_evidence", "needs_review"),
        ("sigma_review", "draft_reviewable"),
        ("mitre_resolution", "draft_reviewable"),
    ),
)
def test_rejects_non_review_artifact_status(artifact: str, bad_status: str) -> None:
    inputs = _inputs()
    inputs[artifact]["analysis_status"] = bad_status

    with pytest.raises(GroundTruthBuildError, match="analysis_status"):
        _build(inputs)


def test_rejects_missing_input_type() -> None:
    inputs = _inputs()
    inputs["input_provenance"].pop()

    with pytest.raises(GroundTruthBuildError, match="Missing input types"):
        _build(inputs)


def test_rejects_duplicate_input_id() -> None:
    inputs = _inputs()
    inputs["input_provenance"][1]["input_id"] = inputs["input_provenance"][0][
        "input_id"
    ]

    with pytest.raises(GroundTruthBuildError, match="Duplicate input_id"):
        _build(inputs)


def test_rejects_invalid_input_hash() -> None:
    inputs = _inputs()
    inputs["input_provenance"][0]["sha256"] = "not-a-hash"

    with pytest.raises(GroundTruthBuildError, match="SHA-256"):
        _build(inputs)


def test_rejects_duplicate_entity() -> None:
    inputs = _inputs()
    entities = inputs["scenario_evidence"]["observed_entities"]
    entities.append(deepcopy(entities[0]))

    with pytest.raises(GroundTruthBuildError, match="Duplicate entity_id"):
        _build(inputs)


def test_rejects_relationship_with_unknown_entity() -> None:
    inputs = _inputs()
    inputs["scenario_evidence"]["relationships"][0][
        "target_entity_id"
    ] = "entity-missing"

    with pytest.raises(GroundTruthBuildError, match="entity not present"):
        _build(inputs)


def test_rejects_relationship_with_unknown_evidence() -> None:
    inputs = _inputs()
    inputs["scenario_evidence"]["relationships"][0]["supported_by"] = [
        "evidence-missing"
    ]

    with pytest.raises(GroundTruthBuildError, match="unknown evidence"):
        _build(inputs)


def test_rejects_config_fact_with_unknown_evidence() -> None:
    inputs = _inputs()
    inputs["build_config"]["facts"][0]["evidence_ids"] = ["evidence-missing"]

    with pytest.raises(GroundTruthBuildError, match="unknown evidence"):
        _build(inputs)


def test_rejects_config_fact_with_unknown_source_reference() -> None:
    inputs = _inputs()
    inputs["build_config"]["facts"][0]["source_references"][0][
        "raw_record_ref"
    ] = "fixture:record:missing"

    with pytest.raises(GroundTruthBuildError, match="not present in scenario evidence"):
        _build(inputs)


def test_rejects_sigma_match_with_unknown_evidence() -> None:
    inputs = _inputs()
    inputs["sigma_review"]["observation_matches"][0]["evidence_ids"] = [
        "evidence-missing"
    ]

    with pytest.raises(GroundTruthBuildError, match="unknown evidence"):
        _build(inputs)


def test_preserves_ungrouped_sigma_source_reference_without_inventing_evidence() -> None:
    inputs = _inputs()
    match = inputs["sigma_review"]["observation_matches"][0]
    match["raw_record_ref"] = "fixture:record:outside-evidence"
    match["evidence_ids"] = []
    behavior = inputs["sigma_review"]["behavior_matches"][0]
    behavior["observation_match_ids"].remove(match["observation_match_id"])
    behavior["source_references"] = [
        item
        for item in behavior["source_references"]
        if item["raw_record_ref"] != "fixture:record:4"
    ]

    finding = next(
        item for item in _build(inputs)["sigma_findings"]
        if item["rule_id"] == "rule-synthetic-beta"
    )

    assert {
        item["raw_record_ref"] for item in finding["source_references"]
    } == {"fixture:record:3", "fixture:record:outside-evidence"}


def test_rejects_duplicate_sigma_rule() -> None:
    inputs = _inputs()
    rules = inputs["sigma_review"]["rules"]
    rules.append(deepcopy(rules[0]))
    inputs["sigma_review"]["rule_count"] = 3

    with pytest.raises(GroundTruthBuildError, match="Duplicate or conflicting"):
        _build(inputs)


def test_rejects_behavior_match_linked_to_different_rule_observation() -> None:
    inputs = _inputs()
    inputs["sigma_review"]["behavior_matches"][0]["observation_match_ids"] = [
        "observation-match-synthetic-1"
    ]

    with pytest.raises(GroundTruthBuildError, match="different-rule observation"):
        _build(inputs)


def test_rejects_mitre_decision_for_unknown_technique() -> None:
    inputs = _inputs()
    inputs["build_config"]["mitre_decisions"][0]["external_id"] = "SYN-MISSING"

    with pytest.raises(GroundTruthBuildError, match="unknown techniques"):
        _build(inputs)


def test_rejects_mitre_decision_with_unknown_evidence() -> None:
    inputs = _inputs()
    inputs["build_config"]["mitre_decisions"][0][
        "supporting_evidence_ids"
    ] = ["evidence-missing"]

    with pytest.raises(GroundTruthBuildError, match="unknown evidence"):
        _build(inputs)


def test_rejects_mitre_link_with_unknown_sigma_rule() -> None:
    inputs = _inputs()
    inputs["mitre_resolution"]["rule_technique_candidate_links"][0][
        "rule_id"
    ] = "rule-missing"

    with pytest.raises(GroundTruthBuildError, match="unknown Sigma rule"):
        _build(inputs)


def test_rejects_mitre_link_with_mismatched_resolved_technique() -> None:
    inputs = _inputs()
    inputs["mitre_resolution"]["rule_technique_candidate_links"][0][
        "technique_stix_id"
    ] = "attack-pattern--wrong"

    with pytest.raises(GroundTruthBuildError, match="resolved technique exactly"):
        _build(inputs)


def test_config_validator_rejects_duplicate_queryable_dimension() -> None:
    config = _json("build_config.json")
    config["queryable_dimensions"].append(config["queryable_dimensions"][0])

    with pytest.raises(GroundTruthBuildError, match="duplicate value"):
        validate_ground_truth_build_config(config)


def test_config_validator_rejects_unknown_field() -> None:
    config = _json("build_config.json")
    config["unexpected"] = True

    with pytest.raises(GroundTruthBuildError, match="unexpected"):
        validate_ground_truth_build_config(config)


def test_config_schema_version_is_exported_and_enforced() -> None:
    config = _json("build_config.json")
    assert GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION == "ground-truth-build-config/v1"
    config["schema_version"] = "ground-truth-build-config/v0"

    with pytest.raises(GroundTruthBuildError, match="schema_version"):
        validate_ground_truth_build_config(config)


def test_nested_confirmed_status_is_rejected_by_final_gt1_validation() -> None:
    inputs = _inputs()
    inputs["build_config"]["facts"][0]["attributes"]["review_status"] = "CONFIRMED"

    with pytest.raises(GroundTruthBuildError, match="confirmed"):
        _build(inputs)


def test_output_does_not_copy_uncontracted_observation_payloads() -> None:
    serialized = json.dumps(_build(), sort_keys=True)

    assert "canonical_fields" not in serialized
    assert "raw_fields" not in serialized


def test_builder_source_has_no_scenario_or_question_hardcoding() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "threat_hunting"
        / "ground_truth"
        / "builder.py"
    ).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "question_id",
        "question_text",
        "expected_answer",
    ):
        assert forbidden not in source


def test_all_builder_fixtures_are_synthetic_and_have_no_question_contract() -> None:
    for path in FIXTURE_ROOT.glob("*.json"):
        text = path.read_text(encoding="utf-8").casefold()
        assert "mshta" not in text
        assert "powershell" not in text
        assert "confirmed" not in text
        document = json.loads(text)
        keys = {value for value in _walk(document) if isinstance(value, str)}
        assert keys.isdisjoint(FORBIDDEN_CORE_FIELDS)
