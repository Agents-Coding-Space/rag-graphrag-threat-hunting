from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
from pathlib import Path
from typing import Any

from threat_hunting.ground_truth import (
    GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION,
    validate_ground_truth_build_config,
)


ROOT = Path(__file__).parents[1]
CONFIG_PATH = ROOT / "configs" / "ground_truth" / "mshta_powershell.json"
SCENARIO_ID = "mshta-powershell"
SOURCE_FILE = "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
ENTITY_IDS = {
    "process-7c96a17eb66f2831da61",
    "process-9c691740bde5d3dbdc4e",
    "process-9f7ceeecb4cd61358ab7",
}
FACT_CONTRACT = {
    "fact-cmd-spawns-mshta": {
        "subject": "process-7c96a17eb66f2831da61",
        "object": "process-9c691740bde5d3dbdc4e",
        "relationship_id": "relationship-9e41d0cc407e7878b2d8",
        "evidence_id": "evidence-b07a5ff4763e629715e6",
        "raw_record_refs": {"jsonl:line:4", "jsonl:line:275"},
    },
    "fact-mshta-spawns-powershell": {
        "subject": "process-9c691740bde5d3dbdc4e",
        "object": "process-9f7ceeecb4cd61358ab7",
        "relationship_id": "relationship-1641029b76ea1ac3df6e",
        "evidence_id": "evidence-b31714b888d1489a380c",
        "raw_record_refs": {"jsonl:line:30", "jsonl:line:398"},
    },
}
MITRE_DECISION_CONTRACT = {
    "T1059.007": {
        "evidence_support": "not_supported_by_observed_command",
        "supporting_evidence_ids": ["evidence-b07a5ff4763e629715e6"],
    },
    "T1140": {
        "evidence_support": "not_assessed",
        "supporting_evidence_ids": [],
    },
    "T1218.005": {
        "evidence_support": "supported_by_observed_behavior",
        "supporting_evidence_ids": [
            "evidence-b07a5ff4763e629715e6",
            "evidence-b31714b888d1489a380c",
        ],
    },
}
FORBIDDEN_QUESTION_FIELDS = {
    "evaluation_questions",
    "expected_answers",
    "question_id",
    "question_text",
    "expected_answer",
    "answer_id",
}


def _load_config() -> dict[str, Any]:
    document = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield key
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_config_loads_as_utf8_and_passes_build_config_validation() -> None:
    config = _load_config()

    validate_ground_truth_build_config(config)
    assert config["schema_version"] == GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION
    assert config["schema_version"] == "ground-truth-build-config/v1"


def test_scenario_uses_production_id_and_states_reviewable_scope() -> None:
    config = _load_config()
    scenario = config["scenario"]
    description = scenario["description"].casefold()

    assert scenario["scenario_id"] == SCENARIO_ID
    assert config["entity_name_overrides"] == {}
    for expected in ("cmd.exe", "mshta.exe", "powershell.exe", "get-service sysmon"):
        assert expected in description
    assert config["review_notes"] == [
        "A generated Ground Truth Core document remains draft_reviewable.",
        "All MITRE assessments remain candidate.",
        "Human review is incomplete.",
        "No final determination has been made.",
    ]


def test_exactly_two_facts_match_production_relationships_and_evidence() -> None:
    facts = _load_config()["facts"]
    assert len(facts) == 2
    assert {fact["fact_id"] for fact in facts} == set(FACT_CONTRACT)

    for fact in facts:
        expected = FACT_CONTRACT[fact["fact_id"]]
        assert fact["subject"] == expected["subject"]
        assert fact["object"] == expected["object"]
        assert fact["predicate"] == "spawned_process"
        assert fact["status"] == "observed"
        assert fact["attributes"] == {
            "relationship_id": expected["relationship_id"]
        }
        assert fact["evidence_ids"] == [expected["evidence_id"]]
        assert {
            reference["raw_record_ref"] for reference in fact["source_references"]
        } == expected["raw_record_refs"]
        assert {
            reference["source_file"] for reference in fact["source_references"]
        } == {SOURCE_FILE}


def test_all_fact_ids_reference_known_production_ids() -> None:
    facts = _load_config()["facts"]
    known_evidence = {
        contract["evidence_id"] for contract in FACT_CONTRACT.values()
    }
    known_relationships = {
        contract["relationship_id"] for contract in FACT_CONTRACT.values()
    }

    assert {fact["subject"] for fact in facts}.issubset(ENTITY_IDS)
    assert {fact["object"] for fact in facts}.issubset(ENTITY_IDS)
    assert {
        evidence_id for fact in facts for evidence_id in fact["evidence_ids"]
    } == known_evidence
    assert {
        fact["attributes"]["relationship_id"] for fact in facts
    } == known_relationships


def test_three_mitre_decisions_have_reviewed_evidence_semantics() -> None:
    decisions = {
        decision["external_id"]: decision
        for decision in _load_config()["mitre_decisions"]
    }

    assert set(decisions) == set(MITRE_DECISION_CONTRACT)
    for external_id, expected in MITRE_DECISION_CONTRACT.items():
        assert decisions[external_id]["evidence_support"] == expected[
            "evidence_support"
        ]
        assert decisions[external_id]["supporting_evidence_ids"] == expected[
            "supporting_evidence_ids"
        ]

    assert "vbscript:execute" in decisions["T1059.007"]["rationale"].casefold()
    assert "javascript is not observed" in decisions["T1059.007"][
        "rationale"
    ].casefold()
    assert "sigma tag" in decisions["T1059.007"]["rationale"].casefold()
    assert "mshta.exe is directly observed" in decisions["T1218.005"][
        "rationale"
    ].casefold()
    assert "launch of powershell" in decisions["T1218.005"][
        "rationale"
    ].casefold()
    assert "candidate technique" in decisions["T1218.005"][
        "rationale"
    ].casefold()


def test_t1140_remains_not_assessed_without_supporting_evidence() -> None:
    decision = next(
        item
        for item in _load_config()["mitre_decisions"]
        if item["external_id"] == "T1140"
    )
    rationale = decision["rationale"].casefold()

    assert decision["evidence_support"] == "not_assessed"
    assert decision["supporting_evidence_ids"] == []
    assert "resolver only resolved a sigma tag" in rationale
    assert "two reviewed evidence groups are insufficient" in rationale
    assert "negative scan" in rationale
    assert "not_observed_in_reviewed_scope" in rationale


def test_summary_references_production_entities_and_relationships() -> None:
    summary = _load_config()["summary"]

    assert len(summary["observed_behavior"]) == 3
    assert "inline vbscript:execute" in summary["observed_behavior"][0].casefold()
    assert "mshta.exe launched powershell" in summary["observed_behavior"][1].casefold()
    assert "get-service sysmon" in summary["observed_behavior"][2].casefold()
    assert set(summary["key_entities"]) == ENTITY_IDS
    assert set(summary["key_relationships"]) == {
        contract["relationship_id"] for contract in FACT_CONTRACT.values()
    }
    limitations = " ".join(summary["limitations"]).casefold()
    for expected in (
        "two reviewed behavior and evidence groups",
        "two sysmon observations",
        "timestamp_conflict",
        "negative scan",
        "human review",
    ):
        assert expected in limitations


def test_queryable_dimensions_are_open_unique_and_deterministic() -> None:
    dimensions = _load_config()["queryable_dimensions"]

    assert dimensions == sorted(dimensions)
    assert len(dimensions) == len(set(dimensions))
    assert dimensions == [
        "command_line",
        "entity",
        "evidence",
        "mitre_technique",
        "process",
        "process_spawn",
        "provenance",
        "sigma_rule",
    ]


def test_recursive_contract_guards_and_fact_scope() -> None:
    config = _load_config()
    values = list(_walk(config))
    keys = {value for value in values if isinstance(value, str)}
    serialized = _canonical_json(config).casefold()

    assert keys.isdisjoint(FORBIDDEN_QUESTION_FIELDS)
    assert "confirmed" not in serialized
    facts = _canonical_json(config["facts"]).casefold()
    for unsupported_fact in (
        "download",
        "c2",
        "credential theft",
        "destructive",
        "deobfuscat",
    ):
        assert unsupported_fact not in facts


def test_canonical_json_is_deterministic_after_parse_round_trip() -> None:
    first = _load_config()
    second = _load_config()
    first_serialized = _canonical_json(first)

    assert first_serialized == _canonical_json(second)
    assert first_serialized == _canonical_json(json.loads(first_serialized))
