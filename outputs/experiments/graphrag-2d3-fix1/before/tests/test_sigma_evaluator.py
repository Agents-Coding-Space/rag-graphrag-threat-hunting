from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest

from threat_hunting.evidence import extract_mshta_powershell_evidence
from threat_hunting.sigma import (
    DEFAULT_CANONICAL_FIELD_MAPPING,
    SigmaEvaluationError,
    SigmaRule,
    build_sigma_match_review,
    evaluate_sigma_rule,
    evaluate_sigma_rules,
    load_sigma_rule,
    load_sigma_rules,
    serialize_sigma_match_review,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
CANONICAL_FIXTURE = FIXTURE_ROOT / "evidence" / "mshta_powershell_canonical.jsonl"
EXECUTION_RULE = FIXTURE_ROOT / "sigma" / "mshta_execution.yml"
CHILD_RULE = FIXTURE_ROOT / "sigma" / "mshta_child.yml"


def _events() -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in CANONICAL_FIXTURE.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _metadata(path: str, schema_version: str, sha256: str) -> dict[str, object]:
    return {"path": path, "schema_version": schema_version, "sha256": sha256}


def _rule_with_logsource(logsource: dict[str, object]) -> SigmaRule:
    return replace(
        load_sigma_rule(EXECUTION_RULE),
        logsource=MappingProxyType(logsource),
    )


def _review(
    events: list[dict[str, object]],
    *,
    evidence_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    rules = load_sigma_rules((EXECUTION_RULE, CHILD_RULE))
    evaluations = evaluate_sigma_rules(rules, events)
    evidence = extract_mshta_powershell_evidence(evidence_events or events)
    return build_sigma_match_review(
        scenario_id="mshta-powershell",
        canonical_input=_metadata("canonical.jsonl", "canonical-event/v2", "a" * 64),
        evidence_input=_metadata(
            "scenario_evidence.json",
            "scenario-evidence/v1",
            "b" * 64,
        ),
        evidence_document=evidence,
        evaluations=evaluations,
        review_notes=("Review only.",),
    )


def test_evaluator_maps_fields_and_matches_exactly_four_fixture_observations() -> None:
    rules = load_sigma_rules((EXECUTION_RULE, CHILD_RULE))
    evaluations = evaluate_sigma_rules(rules, _events())
    by_id = {evaluation.rule.rule_id: evaluation for evaluation in evaluations}

    execution = by_id["11111111-1111-4111-8111-111111111111"]
    child = by_id["22222222-2222-4222-8222-222222222222"]
    assert [item["raw_record_ref"] for item in execution.observation_matches] == [
        "jsonl:line:275",
        "jsonl:line:4",
    ]
    assert [item["raw_record_ref"] for item in child.observation_matches] == [
        "jsonl:line:30",
        "jsonl:line:398",
    ]
    assert sum(len(item.observation_matches) for item in evaluations) == 4
    assert all(item.examined_events == 4 for item in evaluations)
    assert all(item.unmapped_fields == ("OriginalFileName",) for item in evaluations)

    execution_fields = {
        (detail["sigma_field"], detail["canonical_field"], detail["modifier"])
        for match in execution.observation_matches
        for detail in match["matching_fields"]
    }
    assert execution_fields == {
        ("Image", "process_name", "endswith"),
        ("CommandLine", "command_line", "contains"),
    }
    assert DEFAULT_CANONICAL_FIELD_MAPPING["OriginalFileName"] is None


def test_evaluator_supports_case_insensitive_windows_paths_contains_lists_and_or() -> None:
    events = _events()
    event = copy.deepcopy(events[0])
    event["process_name"] = "C:\\WINDOWS\\SYSTEM32\\MSHTA.EXE"
    event["command_line"] = "MSHTA.EXE VBSCRIPT:Execute('payload')"
    rule = load_sigma_rule(EXECUTION_RULE)
    result = evaluate_sigma_rule(rule, (event,))

    assert len(result.observation_matches) == 1
    details = result.observation_matches[0]["matching_fields"]
    assert {item["modifier"] for item in details} == {"endswith", "contains"}
    assert all(item["sigma_field"] != "OriginalFileName" for item in details)


def test_evaluator_accepts_windows_process_creation_regardless_of_key_order() -> None:
    category_first = load_sigma_rule(EXECUTION_RULE)
    product_first = _rule_with_logsource(
        {"product": "windows", "category": "process_creation"}
    )

    assert len(evaluate_sigma_rule(category_first, _events()).observation_matches) == 2
    assert len(evaluate_sigma_rule(product_first, _events()).observation_matches) == 2


@pytest.mark.parametrize(
    "logsource",
    (
        {"product": "linux", "category": "process_creation"},
        {"product": "windows", "category": "network_connection"},
        {
            "product": "windows",
            "category": "process_creation",
            "service": "sysmon",
        },
        {"category": "process_creation"},
        {"product": "windows"},
    ),
)
def test_evaluator_rejects_unsupported_or_incomplete_logsource(
    logsource: dict[str, object],
) -> None:
    with pytest.raises(SigmaEvaluationError, match="Unsupported Sigma logsource"):
        evaluate_sigma_rule(_rule_with_logsource(logsource), _events())


@pytest.mark.parametrize(
    "logsource",
    (
        {"product": 1, "category": "process_creation"},
        {"product": "windows", "category": []},
        {"product": "windows", "category": ""},
    ),
)
def test_evaluator_rejects_invalid_logsource_values(
    logsource: dict[str, object],
) -> None:
    with pytest.raises(SigmaEvaluationError, match="invalid value"):
        evaluate_sigma_rule(_rule_with_logsource(logsource), _events())


def test_process_fields_do_not_make_sysmon_network_event_process_creation() -> None:
    event = copy.deepcopy(_events()[2])
    event["event_id"] = "3"

    result = evaluate_sigma_rule(load_sigma_rule(EXECUTION_RULE), (event,))

    assert result.examined_events == 1
    assert result.observation_matches == ()


@pytest.mark.parametrize("missing_field", ("provider", "event_id"))
def test_event_missing_provider_or_event_id_does_not_match(
    missing_field: str,
) -> None:
    event = copy.deepcopy(_events()[0])
    event.pop(missing_field)

    result = evaluate_sigma_rule(load_sigma_rule(EXECUTION_RULE), (event,))

    assert result.examined_events == 1
    assert result.observation_matches == ()


def test_logsource_provider_matching_is_case_insensitive() -> None:
    event = copy.deepcopy(_events()[0])
    event["provider"] = "mIcRoSoFt-WiNdOwS-sEcUrItY-aUdItInG"

    result = evaluate_sigma_rule(load_sigma_rule(EXECUTION_RULE), (event,))

    assert len(result.observation_matches) == 1


def test_logsource_event_id_accepts_canonical_string_and_integer() -> None:
    string_event = copy.deepcopy(_events()[0])
    integer_event = copy.deepcopy(_events()[0])
    integer_event["event_id"] = 4688
    integer_event["raw_record_ref"] = "fixture:integer-event-id"

    result = evaluate_sigma_rule(
        load_sigma_rule(EXECUTION_RULE),
        (string_event, integer_event),
    )

    assert result.examined_events == 2
    assert len(result.observation_matches) == 2


@pytest.mark.parametrize(
    "unsafe_event_id",
    (True, 4688.0, -1, 0x100000000, "4688.0"),
)
def test_logsource_event_id_rejects_unsafe_coercions(unsafe_event_id: object) -> None:
    event = copy.deepcopy(_events()[0])
    event["event_id"] = unsafe_event_id

    result = evaluate_sigma_rule(load_sigma_rule(EXECUTION_RULE), (event,))

    assert result.examined_events == 1
    assert result.observation_matches == ()


def test_missing_original_file_name_does_not_fail_satisfied_image_alternative() -> None:
    event = _events()[0]
    assert "original_file_name" not in event
    result = evaluate_sigma_rule(load_sigma_rule(EXECUTION_RULE), (event,))
    assert len(result.observation_matches) == 1
    assert result.unmapped_fields == ("OriginalFileName",)


def test_evaluator_fails_closed_for_field_without_mapping(tmp_path: Path) -> None:
    path = tmp_path / "unknown-field.yml"
    path.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8")
        .replace("Image|endswith", "UnsupportedProcessField|endswith")
        .replace("OriginalFileName: 'mshta.exe'", "Image: 'mshta.exe'"),
        encoding="utf-8",
    )
    rule = load_sigma_rule(path)
    with pytest.raises(SigmaEvaluationError, match="without canonical mapping"):
        evaluate_sigma_rule(rule, _events())


def test_review_uses_evidence_groups_for_two_behaviors_and_keeps_provenance() -> None:
    review = _review(_events())
    assert review["schema_version"] == "sigma-match-review/v1"
    assert review["analysis_status"] == "needs_review"
    assert review["examined_events"] == 4
    assert review["matched_events"] == 4
    assert review["unmatched_events"] == 0
    assert len(review["observation_matches"]) == 4
    assert len(review["behavior_matches"]) == 2
    assert review["unsupported_fields"] == []
    assert review["unsupported_constructs"] == []
    assert review["known_unmapped_fields"] == ["OriginalFileName"]

    assert {
        (item["rule_id"], item["evidence_id"], len(item["observation_match_ids"]))
        for item in review["behavior_matches"]
    } == {
        (
            "11111111-1111-4111-8111-111111111111",
            "evidence-b07a5ff4763e629715e6",
            2,
        ),
        (
            "22222222-2222-4222-8222-222222222222",
            "evidence-b31714b888d1489a380c",
            2,
        ),
    }
    assert all(
        item["source_file"] and item["raw_record_ref"]
        for item in review["observation_matches"]
    )
    assert all(item["evidence_ids"] for item in review["observation_matches"])


def test_observation_outside_evidence_is_retained_but_not_grouped() -> None:
    evidence_events = _events()
    events = copy.deepcopy(evidence_events)
    outside = copy.deepcopy(events[0])
    outside["raw_record_ref"] = "fixture:outside-evidence"
    events.append(outside)

    review = _review(events, evidence_events=evidence_events)
    outside_match = next(
        item
        for item in review["observation_matches"]
        if item["raw_record_ref"] == "fixture:outside-evidence"
    )
    assert outside_match["evidence_ids"] == []
    grouped_ids = {
        match_id
        for behavior in review["behavior_matches"]
        for match_id in behavior["observation_match_ids"]
    }
    assert outside_match["observation_match_id"] not in grouped_ids
    assert len(review["behavior_matches"]) == 2


def test_review_ids_serialization_and_statuses_are_deterministic() -> None:
    events = _events()
    first = _review(events)
    second = _review(copy.deepcopy(events))
    assert first == second
    assert serialize_sigma_match_review(first) == serialize_sigma_match_review(second)
    assert len(
        {item["observation_match_id"] for item in first["observation_matches"]}
    ) == 4
    assert len({item["behavior_match_id"] for item in first["behavior_matches"]}) == 2
    assert first["analysis_status"] == "needs_review"
    assert all(item["status"] == "candidate" for item in first["observation_matches"])
    assert all(
        item["status"] == "candidate" and item["review_status"] == "needs_review"
        for item in first["behavior_matches"]
    )
    assert all(rule["analysis_status"] == "candidate" for rule in first["rules"])


def test_evaluation_and_review_do_not_mutate_inputs() -> None:
    events = _events()
    original_events = copy.deepcopy(events)
    evidence = extract_mshta_powershell_evidence(events)
    original_evidence = copy.deepcopy(evidence)
    rules = load_sigma_rules((EXECUTION_RULE, CHILD_RULE))
    evaluations = evaluate_sigma_rules(rules, events)
    build_sigma_match_review(
        scenario_id="mshta-powershell",
        canonical_input={},
        evidence_input={},
        evidence_document=evidence,
        evaluations=evaluations,
    )
    assert events == original_events
    assert evidence == original_evidence
