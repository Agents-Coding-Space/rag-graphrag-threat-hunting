from __future__ import annotations

import copy
import json
import random
from datetime import datetime
from pathlib import Path

import pytest
import threat_hunting.evidence as evidence_package

from threat_hunting.evidence import (
    ProcessCreationGroup,
    build_mshta_powershell_evidence_document,
    build_process_creation_evidence,
    build_process_entities,
    build_process_spawn_relationships,
    classify_process_creation,
    equivalent_process_id,
    extract_mshta_powershell_evidence,
    group_process_creations,
    normalize_process_name,
    same_process_creation,
)
from threat_hunting.schemas.canonical_event import CANONICAL_FIELDS


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "evidence"
    / "mshta_powershell_canonical.jsonl"
)


def _load_events() -> list[dict[str, object]]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def test_fixture_has_four_complete_ordered_canonical_events() -> None:
    events = _load_events()
    expected_fields = tuple(str(field["name"]) for field in CANONICAL_FIELDS)
    assert len(events) == 4
    assert [event["raw_record_ref"] for event in events] == [
        "jsonl:line:4",
        "jsonl:line:30",
        "jsonl:line:275",
        "jsonl:line:398",
    ]
    assert all(tuple(event) == expected_fields for event in events)
    assert {event["host"] for event in events} == {"WORKSTATION5"}


def test_process_id_equivalence_handles_hex_decimal_and_invalid_values() -> None:
    assert equivalent_process_id("0x2ae4", "10980")
    assert equivalent_process_id("0x1700", "5888")
    assert equivalent_process_id("0x2564", "9572")
    for invalid in (None, "", "not-a-pid", object(), True, -1):
        assert not equivalent_process_id(invalid, "10980")
        assert not equivalent_process_id("10980", invalid)


def test_public_process_creation_pipeline_has_one_correlation_semantics() -> None:
    events = _load_events()
    assert [classify_process_creation(event) for event in events] == [
        "cmd_to_mshta",
        "mshta_to_powershell",
        "cmd_to_mshta",
        "mshta_to_powershell",
    ]
    assert same_process_creation(events[0], events[2])
    assert same_process_creation(events[1], events[3])

    security_duplicate = copy.deepcopy(events[0])
    security_duplicate["raw_record_ref"] = "fixture:security:duplicate-view"
    assert not same_process_creation(events[0], security_duplicate)
    security_groups = group_process_creations((events[0], security_duplicate))
    assert len(security_groups) == 2
    assert all(len(group.observations) == 1 for group in security_groups)
    assert all(group.correlation_status is None for group in security_groups)

    groups = group_process_creations(events)
    assert len(groups) == 2
    assert all(group.correlation_status == "inferred" for group in groups)
    assert all(
        [
            (observation["provider"], observation["event_id"])
            for observation in group.observations
        ]
        == [
            ("Microsoft-Windows-Security-Auditing", "4688"),
            ("Microsoft-Windows-Sysmon", "1"),
        ]
        for group in groups
    )

    evidence = [build_process_creation_evidence(group) for group in groups]
    assert all(item["status"] == "observed" for item in evidence)
    document = build_mshta_powershell_evidence_document(groups)
    assert all(
        relationship["status"] == "observed"
        for relationship in document["relationships"]
    )
    statuses = [document["analysis_status"]]
    statuses.extend(item["status"] for item in document["evidence"])
    statuses.extend(item["status"] for item in document["relationships"])
    assert "confirmed" not in statuses


def test_legacy_correlation_api_is_not_public() -> None:
    legacy_name = "correlate_process_creation_events"
    assert not hasattr(evidence_package, legacy_name)
    assert legacy_name not in evidence_package.__all__


def test_classifier_recognizes_all_four_fixture_process_creations() -> None:
    events = _load_events()
    assert [classify_process_creation(event) for event in events] == [
        "cmd_to_mshta",
        "mshta_to_powershell",
        "cmd_to_mshta",
        "mshta_to_powershell",
    ]
    assert {event["event_id"] for event in events[:2]} == {"4688"}
    assert {event["event_id"] for event in events[2:]} == {"1"}


def test_classifier_handles_full_paths_and_process_name_case() -> None:
    event = {
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": "4688",
        "parent_process_name": "C:\\WINDOWS\\System32\\CMD.EXE",
        "process_name": "c:\\windows\\SYSTEM32\\MsHtA.ExE",
    }
    assert normalize_process_name(event["parent_process_name"]) == "cmd.exe"
    assert normalize_process_name(event["process_name"]) == "mshta.exe"
    assert classify_process_creation(event) == "cmd_to_mshta"


@pytest.mark.parametrize(
    "value",
    (
        "mshta.exe",
        "MSHTA.EXE",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\tools.exe\\mshta.exe",
        "C:/Windows/System32/MSHTA.EXE",
        "\\server\\share\\mshta.exe",
        '"C:\\Windows\\System32\\mshta.exe"',
    ),
)
def test_normalize_process_name_accepts_supported_windows_paths(value: str) -> None:
    original = value
    assert normalize_process_name(value) == "mshta.exe"
    assert value == original


@pytest.mark.parametrize(
    "value",
    (
        "C:\\Windows\\System32\\mshta.exe\\",
        "C:/Windows/System32/mshta.exe/",
        "mshta.exe vbscript:Execute('payload')",
        "not-mshta.exe",
        "",
        "   ",
        None,
        True,
        [],
        {},
        "C:\\Windows\\System32",
        "C:\\Windows\\System32\\",
        "C:\\",
        ".",
        "mshta",
    ),
)
def test_normalize_process_name_rejects_invalid_values(value: object) -> None:
    assert normalize_process_name(value) is None


@pytest.mark.parametrize(
    "value",
    (
        '"C:\\Windows\\System32\\mshta.exe',
        'C:\\Windows\\System32\\mshta.exe"',
        '"C:\\Windows\\System32\\mshta.exe" vbscript:Execute("payload")',
        '"C:\\Windows\\System32\\mshta.exe\\"',
    ),
)
def test_normalize_process_name_rejects_invalid_quoting(value: str) -> None:
    assert normalize_process_name(value) is None


def test_classifier_rejects_wrong_event_id_or_provider() -> None:
    valid = _load_events()[0]
    invalid_contexts = (
        {"event_id": "1"},
        {"event_id": "4625"},
        {"provider": "Microsoft-Windows-Sysmon"},
        {"provider": "Security"},
    )
    for changes in invalid_contexts:
        event = copy.deepcopy(valid)
        event.update(changes)
        assert classify_process_creation(event) is None


def test_classifier_rejects_missing_or_invalid_process_names() -> None:
    valid = _load_events()[0]
    for field in ("process_name", "parent_process_name"):
        missing = copy.deepcopy(valid)
        missing.pop(field)
        assert classify_process_creation(missing) is None
        for invalid in (None, "", "   ", True, [], {}, object()):
            event = copy.deepcopy(valid)
            event[field] = invalid
            assert classify_process_creation(event) is None
            assert normalize_process_name(invalid) is None

    for invalid_event in (None, "", True, [], object()):
        assert classify_process_creation(invalid_event) is None  # type: ignore[arg-type]


def test_classifier_requires_exact_process_names_without_arguments() -> None:
    valid = _load_events()[0]
    invalid_names = (
        {"process_name": "not-mshta.exe"},
        {"process_name": "mshta.exe -Embedding"},
        {"process_name": "notepad.exe /argument/mshta.exe"},
        {"parent_process_name": "cmd.exe /c"},
    )
    for changes in invalid_names:
        event = copy.deepcopy(valid)
        event.update(changes)
        assert classify_process_creation(event) is None


def test_classifier_does_not_search_command_line_substrings() -> None:
    event = copy.deepcopy(_load_events()[0])
    event["process_name"] = "C:\\Windows\\System32\\notepad.exe"
    event["command_line"] = "notepad.exe mentions mshta.exe and powershell.exe"
    assert classify_process_creation(event) is None


def test_classifier_does_not_mutate_input() -> None:
    event = copy.deepcopy(_load_events()[1])
    original = copy.deepcopy(event)
    assert classify_process_creation(event) == "mshta_to_powershell"
    assert event == original


def test_classifier_is_independent_of_raw_record_references() -> None:
    events = _load_events()
    expected = [classify_process_creation(event) for event in events]
    for index, event in enumerate(events):
        event["raw_record_ref"] = f"fixture:any:{index}"
    assert [classify_process_creation(event) for event in events] == expected


def test_same_process_creation_matches_fixture_pairs_in_either_order() -> None:
    events = _load_events()
    for left_index, right_index in ((0, 2), (1, 3)):
        left = events[left_index]
        right = events[right_index]
        assert equivalent_process_id(left["process_id"], right["process_id"])
        assert equivalent_process_id(
            left["parent_process_id"], right["parent_process_id"]
        )
        assert same_process_creation(left, right)
        assert same_process_creation(right, left)


def test_same_process_creation_rejects_different_or_unclassified_kinds() -> None:
    events = _load_events()
    assert not same_process_creation(events[0], events[3])

    unclassified = copy.deepcopy(events[2])
    unclassified["process_name"] = "C:\\Windows\\System32\\notepad.exe"
    assert not same_process_creation(events[0], unclassified)


def test_same_process_creation_requires_opposite_telemetry_providers() -> None:
    events = _load_events()
    security_copy = copy.deepcopy(events[0])
    sysmon_copy = copy.deepcopy(events[2])
    assert not same_process_creation(events[0], security_copy)
    assert not same_process_creation(events[2], sysmon_copy)


def test_same_process_creation_requires_matching_nonempty_hosts() -> None:
    security, sysmon = _load_events()[0::2]
    different = copy.deepcopy(sysmon)
    different["host"] = "WORKSTATION6"
    assert not same_process_creation(security, different)

    for invalid in (None, "", "   ", True, [], {}):
        missing = copy.deepcopy(sysmon)
        missing["host"] = invalid
        assert not same_process_creation(security, missing)

    case_variant = copy.deepcopy(sysmon)
    case_variant["host"] = "workstation5"
    assert same_process_creation(security, case_variant)


def test_same_process_creation_requires_equivalent_process_ids() -> None:
    security, sysmon = _load_events()[0::2]
    for invalid in ("10981", None, "", "not-a-pid", True):
        changed = copy.deepcopy(sysmon)
        changed["process_id"] = invalid
        assert not same_process_creation(security, changed)


def test_same_process_creation_requires_equivalent_parent_process_ids() -> None:
    security, sysmon = _load_events()[0::2]
    for invalid in ("5889", None, "", "not-a-pid", True):
        changed = copy.deepcopy(sysmon)
        changed["parent_process_id"] = invalid
        assert not same_process_creation(security, changed)


def test_same_process_creation_applies_inclusive_timestamp_tolerance() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    security["timestamp"] = "2020-01-01T00:00:00Z"
    sysmon["timestamp"] = "2020-01-01T00:00:01+00:00"
    assert same_process_creation(security, sysmon)

    sysmon["timestamp"] = "2020-01-01T00:00:01.000001Z"
    assert not same_process_creation(security, sysmon)

    sysmon["timestamp"] = security["timestamp"]
    assert same_process_creation(security, sysmon, tolerance_seconds=0)


def test_same_process_creation_validates_timestamp_awareness_and_values() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    security["timestamp"] = "2020-01-01T07:00:00+07:00"
    sysmon["timestamp"] = "2020-01-01T00:00:00Z"
    assert same_process_creation(security, sysmon)

    security["timestamp"] = "2020-01-01T00:00:00"
    sysmon["timestamp"] = "2020-01-01T00:00:01"
    assert same_process_creation(security, sysmon)

    sysmon["timestamp"] = "2020-01-01T00:00:01Z"
    assert not same_process_creation(security, sysmon)

    for invalid in (None, "", "not-a-timestamp", True, [], {}):
        changed = copy.deepcopy(sysmon)
        changed["timestamp"] = invalid
        assert not same_process_creation(security, changed)

    missing = copy.deepcopy(sysmon)
    missing.pop("timestamp")
    assert not same_process_creation(security, missing)


def test_same_process_creation_rejects_invalid_tolerance() -> None:
    security, sysmon = _load_events()[0::2]
    invalid_values = (
        True,
        False,
        -0.1,
        float("nan"),
        float("inf"),
        -float("inf"),
        "1",
        None,
    )
    for invalid in invalid_values:
        with pytest.raises(
            ValueError,
            match="tolerance_seconds must be a finite, non-negative number",
        ):
            same_process_creation(
                security,
                sysmon,
                tolerance_seconds=invalid,  # type: ignore[arg-type]
            )


def test_same_process_creation_does_not_mutate_inputs() -> None:
    left, right = copy.deepcopy(_load_events()[0::2])
    original_left = copy.deepcopy(left)
    original_right = copy.deepcopy(right)
    assert same_process_creation(left, right)
    assert left == original_left
    assert right == original_right


def test_group_process_creations_builds_two_inferred_fixture_groups() -> None:
    groups = group_process_creations(_load_events())
    assert len(groups) == 2
    assert {group.kind for group in groups} == {
        "cmd_to_mshta",
        "mshta_to_powershell",
    }
    assert all(len(group.observations) == 2 for group in groups)
    assert all(group.correlation_status == "inferred" for group in groups)

    observations = [
        observation
        for group in groups
        for observation in group.observations
    ]
    references = [observation["raw_record_ref"] for observation in observations]
    assert set(references) == {
        "jsonl:line:4",
        "jsonl:line:30",
        "jsonl:line:275",
        "jsonl:line:398",
    }
    assert len(references) == len(set(references))
    assert all(
        [observation["event_id"] for observation in group.observations]
        == ["4688", "1"]
        for group in groups
    )


def test_group_process_creations_is_independent_of_input_order() -> None:
    events = _load_events()
    expected = group_process_creations(events)
    shuffled = list(events)
    random.Random(20260818).shuffle(shuffled)
    assert group_process_creations(reversed(events)) == expected
    assert group_process_creations(shuffled) == expected


def test_group_process_creations_consumes_generator_once() -> None:
    events = _load_events()
    yielded: list[str] = []

    def event_stream():
        for event in events:
            yielded.append(str(event["raw_record_ref"]))
            yield event

    groups = group_process_creations(event_stream())
    assert len(groups) == 2
    assert yielded == [str(event["raw_record_ref"]) for event in events]


def test_group_process_creations_ignores_unclassified_events() -> None:
    ignored = copy.deepcopy(_load_events()[0])
    ignored["process_name"] = "C:\\Windows\\System32\\notepad.exe"
    ignored["raw_record_ref"] = "fixture:ignored"
    assert group_process_creations((ignored,)) == ()

    expected = group_process_creations(_load_events())
    assert group_process_creations((*_load_events(), ignored)) == expected


def test_group_process_creations_retains_unpaired_singleton() -> None:
    event = _load_events()[0]
    groups = group_process_creations((event,))
    assert len(groups) == 1
    assert groups[0].kind == "cmd_to_mshta"
    assert groups[0].correlation_status is None
    assert groups[0].observations == (event,)

    for missing_field in ("source_file", "raw_record_ref"):
        missing = copy.deepcopy(event)
        missing.pop(missing_field)
        with pytest.raises(ValueError, match=missing_field):
            group_process_creations((missing,))


def test_group_process_creations_keeps_host_or_pid_mismatches_as_singletons() -> None:
    security, sysmon = _load_events()[0::2]
    changed_fields = (
        ("host", "WORKSTATION6"),
        ("process_id", "10981"),
        ("parent_process_id", "5889"),
    )
    for field, value in changed_fields:
        changed = copy.deepcopy(sysmon)
        changed[field] = value
        groups = group_process_creations((security, changed))
        assert len(groups) == 2
        assert all(len(group.observations) == 1 for group in groups)
        assert all(group.correlation_status is None for group in groups)
        assert {
            group.observations[0]["raw_record_ref"] for group in groups
        } == {"jsonl:line:4", "jsonl:line:275"}


def test_group_process_creations_does_not_guess_ambiguous_pairing() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    competing_sysmon = copy.deepcopy(sysmon)
    competing_sysmon["raw_record_ref"] = "fixture:ambiguous:sysmon"
    groups = group_process_creations((security, sysmon, competing_sysmon))
    assert len(groups) == 3
    assert all(len(group.observations) == 1 for group in groups)
    assert all(group.correlation_status is None for group in groups)


def test_group_process_creations_deduplicates_identical_provenance() -> None:
    security, sysmon = _load_events()[0::2]
    duplicate = copy.deepcopy(sysmon)
    groups = group_process_creations((security, sysmon, duplicate))
    assert len(groups) == 1
    assert len(groups[0].observations) == 2
    assert [
        observation["raw_record_ref"] for observation in groups[0].observations
    ] == ["jsonl:line:4", "jsonl:line:275"]


def test_group_process_creations_rejects_conflicting_duplicate_provenance() -> None:
    event = _load_events()[0]
    conflicting = copy.deepcopy(event)
    conflicting["command_line"] = "different content"
    with pytest.raises(ValueError, match="conflicting.*share provenance"):
        group_process_creations((event, conflicting))


def test_group_process_creations_does_not_mutate_inputs() -> None:
    events = _load_events()
    original = copy.deepcopy(events)
    group_process_creations(events)
    assert events == original


def test_group_process_creations_empty_input_returns_empty_tuple() -> None:
    assert group_process_creations(()) == ()


def test_group_process_creations_rejects_invalid_tolerance() -> None:
    for invalid in (True, -1, float("nan"), float("inf"), "1", None):
        with pytest.raises(
            ValueError,
            match="tolerance_seconds must be a finite, non-negative number",
        ):
            group_process_creations(
                (),
                tolerance_seconds=invalid,  # type: ignore[arg-type]
            )


def test_custom_tolerance_survives_grouping_and_evidence_building() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    security["timestamp"] = "2020-01-01T00:00:00Z"
    sysmon["timestamp"] = "2020-01-01T00:00:01.500000Z"
    events = (security, sysmon)

    assert same_process_creation(
        security,
        sysmon,
        tolerance_seconds=2.0,
    )
    groups = group_process_creations(events, tolerance_seconds=2.0)
    assert len(groups) == 1
    group = groups[0]
    assert len(group.observations) == 2
    assert group.correlation_status == "inferred"
    assert group.correlation_tolerance_seconds == 2.0

    evidence = build_process_creation_evidence(group)
    assert evidence["status"] == "observed"
    assert evidence["status"] != "confirmed"
    assert len(evidence["observations"]) == 2

    document = build_mshta_powershell_evidence_document((group,))
    assert len(document["evidence"]) == 1
    assert len(document["evidence"][0]["observations"]) == 2
    assert document["evidence"][0]["status"] == "observed"
    assert "correlation_tolerance_seconds" not in json.dumps(document)

    extracted = extract_mshta_powershell_evidence(
        events,
        correlation_tolerance_seconds=2.0,
    )
    assert len(extracted["evidence"]) == 1
    assert len(extracted["evidence"][0]["observations"]) == 2
    statuses = [extracted["analysis_status"]]
    statuses.extend(item["status"] for item in extracted["evidence"])
    statuses.extend(item["status"] for item in extracted["relationships"])
    assert "confirmed" not in statuses


def test_default_tolerance_keeps_distant_pair_as_singletons() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    security["timestamp"] = "2020-01-01T00:00:00Z"
    sysmon["timestamp"] = "2020-01-01T00:00:01.500000Z"

    groups = group_process_creations((security, sysmon))
    assert len(groups) == 2
    assert all(len(group.observations) == 1 for group in groups)
    assert all(group.correlation_status is None for group in groups)
    assert all(group.correlation_tolerance_seconds == 1.0 for group in groups)

    custom_singleton = group_process_creations(
        (security,),
        tolerance_seconds=2.0,
    )
    assert len(custom_singleton) == 1
    assert custom_singleton[0].correlation_tolerance_seconds == 2.0


def test_default_tolerance_still_pairs_fixture_millisecond_deltas() -> None:
    events = _load_events()
    fixture_pairs = ((events[0], events[2]), (events[1], events[3]))
    expected_deltas = (0.001, 0.027)
    actual_deltas = tuple(
        abs(
            (
                datetime.fromisoformat(str(right["timestamp"]).replace("Z", "+00:00"))
                - datetime.fromisoformat(
                    str(left["timestamp"]).replace("Z", "+00:00")
                )
            ).total_seconds()
        )
        for left, right in fixture_pairs
    )
    assert actual_deltas == expected_deltas
    assert all(same_process_creation(left, right) for left, right in fixture_pairs)

    groups = group_process_creations(events)
    assert len(groups) == 2
    assert all(len(group.observations) == 2 for group in groups)
    assert all(group.correlation_tolerance_seconds == 1.0 for group in groups)


def test_process_creation_group_rejects_invalid_tolerance_when_consumed() -> None:
    event = _load_events()[0]
    invalid_values = (
        True,
        -1,
        float("nan"),
        float("inf"),
        -float("inf"),
        "2.0",
        None,
        object(),
    )
    for invalid in invalid_values:
        group = ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(event,),
            correlation_status=None,
            correlation_tolerance_seconds=invalid,  # type: ignore[arg-type]
        )
        with pytest.raises(
            ValueError,
            match="tolerance_seconds must be a finite, non-negative number",
        ):
            build_process_creation_evidence(group)


def test_build_evidence_has_expected_semantics_and_deterministic_ids() -> None:
    groups = {group.kind: group for group in group_process_creations(_load_events())}
    cmd_evidence = build_process_creation_evidence(groups["cmd_to_mshta"])
    powershell_evidence = build_process_creation_evidence(
        groups["mshta_to_powershell"]
    )

    assert tuple(cmd_evidence) == (
        "evidence_id",
        "evidence_type",
        "status",
        "summary",
        "observations",
        "reason",
        "review_status",
    )
    assert cmd_evidence["summary"] == "cmd.exe spawned mshta.exe"
    assert powershell_evidence["summary"] == "mshta.exe spawned powershell.exe"
    assert cmd_evidence["evidence_id"] != powershell_evidence["evidence_id"]
    assert cmd_evidence["evidence_id"] == build_process_creation_evidence(
        groups["cmd_to_mshta"]
    )["evidence_id"]
    for evidence in (cmd_evidence, powershell_evidence):
        assert evidence["evidence_type"] == "process_creation"
        assert evidence["status"] == "observed"
        assert evidence["status"] != "confirmed"
        assert evidence["review_status"] == "needs_review"
        assert "inferred" in str(evidence["reason"]).casefold()


def test_build_evidence_retains_paired_observations_and_allowed_fields() -> None:
    allowed_fields = {
        "host",
        "user",
        "process_name",
        "process_id",
        "parent_process_name",
        "parent_process_id",
        "command_line",
        "process_guid",
        "parent_process_guid",
    }
    groups = group_process_creations(_load_events())
    expected_references = {
        "cmd_to_mshta": ["jsonl:line:4", "jsonl:line:275"],
        "mshta_to_powershell": ["jsonl:line:30", "jsonl:line:398"],
    }
    for group in groups:
        evidence = build_process_creation_evidence(group)
        observations = evidence["observations"]
        assert isinstance(observations, list)
        assert len(observations) == 2
        assert [item["raw_record_ref"] for item in observations] == (
            expected_references[group.kind]
        )
        assert [item["event_id"] for item in observations] == ["4688", "1"]
        for item in observations:
            canonical_fields = item["canonical_fields"]
            assert set(canonical_fields) <= allowed_fields
            assert all(value is not None for value in canonical_fields.values())
            assert canonical_fields["command_line"]
            assert item["raw_fields"] == {}


def test_build_evidence_deep_copies_provided_raw_fields() -> None:
    event = copy.deepcopy(_load_events()[0])
    event["raw_fields"] = {
        "NewProcessName": "C:\\Windows\\System32\\mshta.exe",
        "nested": {"values": [1, 2]},
    }
    group = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(event,),
        correlation_status=None,
    )
    evidence = build_process_creation_evidence(group)
    raw_fields = evidence["observations"][0]["raw_fields"]
    assert raw_fields == event["raw_fields"]

    event["raw_fields"]["nested"]["values"].append(3)
    assert raw_fields["nested"]["values"] == [1, 2]
    raw_fields["nested"]["values"].append(4)
    assert event["raw_fields"]["nested"]["values"] == [1, 2, 3]


def test_build_evidence_supports_observed_singleton() -> None:
    group = group_process_creations((_load_events()[0],))[0]
    evidence = build_process_creation_evidence(group)
    assert evidence["status"] == "observed"
    assert evidence["review_status"] == "needs_review"
    assert len(evidence["observations"]) == 1
    assert evidence["observations"][0]["raw_record_ref"] == "jsonl:line:4"
    assert "inferred" not in str(evidence["reason"]).casefold()


def test_build_evidence_rejects_empty_or_oversized_groups() -> None:
    event = _load_events()[0]
    invalid_groups = (
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(),
            correlation_status=None,
        ),
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(event, event, event),
            correlation_status="inferred",
        ),
    )
    for group in invalid_groups:
        with pytest.raises(ValueError, match="one or two observations"):
            build_process_creation_evidence(group)


def test_build_evidence_rejects_kind_mismatch() -> None:
    event = _load_events()[0]
    mismatched = ProcessCreationGroup(
        kind="mshta_to_powershell",
        observations=(event,),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="group kind"):
        build_process_creation_evidence(mismatched)

    unsupported = ProcessCreationGroup(
        kind="unsupported",  # type: ignore[arg-type]
        observations=(event,),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="unsupported.*kind"):
        build_process_creation_evidence(unsupported)


def test_build_evidence_rejects_invalid_paired_observations() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    wrong_host = copy.deepcopy(sysmon)
    wrong_host["host"] = "WORKSTATION6"
    not_correlated = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(security, wrong_host),
        correlation_status="inferred",
    )
    with pytest.raises(ValueError, match="do not describe the same"):
        build_process_creation_evidence(not_correlated)

    same_provider = copy.deepcopy(security)
    same_provider["raw_record_ref"] = "fixture:security:duplicate-view"
    invalid_context = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(security, same_provider),
        correlation_status="inferred",
    )
    with pytest.raises(ValueError, match="Security 4688 first and Sysmon 1 second"):
        build_process_creation_evidence(invalid_context)

    reversed_pair = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(sysmon, security),
        correlation_status="inferred",
    )
    with pytest.raises(ValueError, match="Security 4688 first and Sysmon 1 second"):
        build_process_creation_evidence(reversed_pair)


def test_build_evidence_rejects_invalid_correlation_status() -> None:
    security, sysmon = _load_events()[0::2]
    singleton = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(security,),
        correlation_status="inferred",
    )
    paired = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(security, sysmon),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="singleton.*must be None"):
        build_process_creation_evidence(singleton)
    with pytest.raises(ValueError, match="paired.*must be inferred"):
        build_process_creation_evidence(paired)


def test_build_evidence_rejects_missing_provenance_or_invalid_raw_fields() -> None:
    event = _load_events()[0]
    for field in ("source_file", "raw_record_ref"):
        missing = copy.deepcopy(event)
        missing.pop(field)
        group = ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(missing,),
            correlation_status=None,
        )
        with pytest.raises(ValueError, match=field):
            build_process_creation_evidence(group)

    invalid_raw_fields = copy.deepcopy(event)
    invalid_raw_fields["raw_fields"] = ["not", "an", "object"]
    group = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(invalid_raw_fields,),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="raw_fields must be a mapping"):
        build_process_creation_evidence(group)


def test_build_evidence_is_json_serializable_and_does_not_mutate_group() -> None:
    group = group_process_creations(_load_events())[0]
    original = copy.deepcopy(group)
    evidence = build_process_creation_evidence(group)
    parsed = json.loads(json.dumps(evidence, ensure_ascii=False))
    assert parsed == evidence
    assert group == original

    evidence["observations"][0]["canonical_fields"]["process_name"] = "changed.exe"
    assert group.observations[0]["process_name"] != "changed.exe"


def test_build_process_entities_creates_three_deduplicated_fixture_processes() -> None:
    entities = build_process_entities(group_process_creations(_load_events()))
    assert len(entities) == 3
    assert {entity["entity_type"] for entity in entities} == {"process"}

    by_name = {
        entity["attributes"]["process_name"]: entity
        for entity in entities
    }
    assert set(by_name) == {"cmd.exe", "mshta.exe", "powershell.exe"}
    assert sum(
        entity["attributes"]["process_name"] == "mshta.exe"
        for entity in entities
    ) == 1
    assert {
        name: entity["attributes"]["process_id"]
        for name, entity in by_name.items()
    } == {
        "cmd.exe": "5888",
        "mshta.exe": "10980",
        "powershell.exe": "9572",
    }
    assert all(
        entity["attributes"]["process_guid"] is not None
        for entity in entities
    )


def test_build_process_entities_reuses_mshta_between_fixture_groups() -> None:
    groups = {group.kind: group for group in group_process_creations(_load_events())}
    first_entities = build_process_entities((groups["cmd_to_mshta"],))
    second_entities = build_process_entities((groups["mshta_to_powershell"],))
    first_mshta_id = next(
        entity["entity_id"]
        for entity in first_entities
        if entity["attributes"]["process_name"] == "mshta.exe"
    )
    second_mshta_id = next(
        entity["entity_id"]
        for entity in second_entities
        if entity["attributes"]["process_name"] == "mshta.exe"
    )
    assert first_mshta_id == second_mshta_id


def test_build_process_entities_is_deterministic_and_order_independent() -> None:
    groups = group_process_creations(_load_events())
    expected = build_process_entities(groups)
    assert build_process_entities(groups) == expected
    assert build_process_entities(reversed(groups)) == expected
    assert [entity["entity_id"] for entity in expected] == [
        "process-7c96a17eb66f2831da61",
        "process-9c691740bde5d3dbdc4e",
        "process-9f7ceeecb4cd61358ab7",
    ]


def test_build_process_entities_consumes_generator_once() -> None:
    groups = group_process_creations(_load_events())
    yielded: list[str] = []

    def group_stream():
        for group in groups:
            yielded.append(group.kind)
            yield group

    assert len(build_process_entities(group_stream())) == 3
    assert yielded == [group.kind for group in groups]


def test_build_process_entities_different_host_creates_distinct_entities() -> None:
    first = _load_events()[2]
    second = copy.deepcopy(first)
    second["host"] = "WORKSTATION6"
    second["raw_record_ref"] = "fixture:different-host"
    entities = build_process_entities(group_process_creations((first, second)))
    mshta_entities = [
        entity
        for entity in entities
        if entity["attributes"]["process_name"] == "mshta.exe"
    ]
    assert len(mshta_entities) == 2
    assert len({entity["entity_id"] for entity in mshta_entities}) == 2
    assert {
        entity["attributes"]["host"] for entity in mshta_entities
    } == {"WORKSTATION5", "WORKSTATION6"}


def test_build_process_entities_same_pid_at_distant_times_is_distinct_without_guid() -> None:
    first = _load_events()[0]
    second = copy.deepcopy(first)
    second["timestamp"] = "2020-10-22T03:57:59.856000Z"
    second["raw_record_ref"] = "fixture:distant-process"
    entities = build_process_entities(group_process_creations((first, second)))
    mshta_entities = [
        entity
        for entity in entities
        if entity["attributes"]["process_name"] == "mshta.exe"
    ]
    assert len(mshta_entities) == 2
    assert len({entity["entity_id"] for entity in mshta_entities}) == 2
    assert all(
        entity["attributes"]["process_guid"] is None
        for entity in mshta_entities
    )


def test_build_process_entities_treats_guid_case_insensitively() -> None:
    first = _load_events()[2]
    second = copy.deepcopy(first)
    second["raw_record_ref"] = "fixture:uppercase-guids"
    second["process_guid"] = str(second["process_guid"]).upper()
    second["parent_process_guid"] = str(second["parent_process_guid"]).upper()
    entities = build_process_entities(group_process_creations((first, second)))
    assert len(entities) == 2
    assert {
        entity["attributes"]["process_guid"] for entity in entities
    } == {
        "{39e4a257-2d59-5f91-6813-000000000700}",
        "{39e4a257-2d77-5f91-6b13-000000000700}",
    }


def test_build_process_entities_rejects_conflicting_endpoint_guids() -> None:
    security, sysmon = copy.deepcopy(_load_events()[0::2])
    security["process_guid"] = "{00000000-0000-0000-0000-000000000001}"
    group = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(security, sysmon),
        correlation_status="inferred",
    )
    with pytest.raises(ValueError, match="conflicting process GUIDs"):
        build_process_entities((group,))


def test_build_process_entities_rejects_missing_identity() -> None:
    event = copy.deepcopy(_load_events()[0])
    event["process_id"] = None
    event["process_guid"] = None
    group = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(event,),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="target.*identity"):
        build_process_entities((group,))


def test_build_process_entities_is_json_serializable_and_does_not_mutate_input() -> None:
    groups = group_process_creations(_load_events())
    original = copy.deepcopy(groups)
    entities = build_process_entities(groups)
    assert json.loads(json.dumps(entities, ensure_ascii=False)) == list(entities)
    assert groups == original

    entities[0]["attributes"]["process_name"] = "changed.exe"
    assert groups == original
    assert all(
        observation.get("process_name") != "changed.exe"
        and observation.get("parent_process_name") != "changed.exe"
        for group in groups
        for observation in group.observations
    )


def test_build_process_entities_empty_input_returns_empty_tuple() -> None:
    assert build_process_entities(()) == ()


def test_build_process_spawn_relationships_has_fixture_semantics_and_references() -> None:
    groups = group_process_creations(_load_events())
    relationships = build_process_spawn_relationships(groups)
    assert len(relationships) == 2

    expected_support = {
        (
            "process-7c96a17eb66f2831da61",
            "process-9c691740bde5d3dbdc4e",
        ): "evidence-b07a5ff4763e629715e6",
        (
            "process-9c691740bde5d3dbdc4e",
            "process-9f7ceeecb4cd61358ab7",
        ): "evidence-b31714b888d1489a380c",
    }
    actual_support = {
        (relationship["source_entity_id"], relationship["target_entity_id"]):
        relationship["supported_by"][0]
        for relationship in relationships
    }
    assert actual_support == expected_support
    assert all(
        relationship["relationship_type"] == "process_spawn"
        and relationship["status"] == "observed"
        and relationship["status"] not in {"inferred", "confirmed"}
        and relationship["review_status"] == "needs_review"
        for relationship in relationships
    )

    entity_ids = {
        entity["entity_id"] for entity in build_process_entities(groups)
    }
    evidence_ids = {
        build_process_creation_evidence(group)["evidence_id"]
        for group in groups
    }
    assert all(
        relationship["source_entity_id"] in entity_ids
        and relationship["target_entity_id"] in entity_ids
        and set(relationship["supported_by"]) <= evidence_ids
        for relationship in relationships
    )
    mshta_id = "process-9c691740bde5d3dbdc4e"
    assert any(
        relationship["target_entity_id"] == mshta_id
        for relationship in relationships
    )
    assert any(
        relationship["source_entity_id"] == mshta_id
        for relationship in relationships
    )


def test_build_process_spawn_relationships_is_deterministic_and_order_independent() -> None:
    groups = group_process_creations(_load_events())
    expected = build_process_spawn_relationships(groups)
    assert build_process_spawn_relationships(groups) == expected
    assert build_process_spawn_relationships(reversed(groups)) == expected
    assert [relationship["relationship_id"] for relationship in expected] == [
        "relationship-1641029b76ea1ac3df6e",
        "relationship-9e41d0cc407e7878b2d8",
    ]


def test_build_process_spawn_relationships_consumes_generator_once() -> None:
    groups = group_process_creations(_load_events())
    yielded: list[str] = []

    def group_stream():
        for group in groups:
            yielded.append(group.kind)
            yield group

    assert len(build_process_spawn_relationships(group_stream())) == 2
    assert yielded == [group.kind for group in groups]


def test_build_process_spawn_relationships_merges_duplicate_support() -> None:
    first = copy.deepcopy(_load_events()[2])
    second = copy.deepcopy(first)
    second["raw_record_ref"] = "fixture:duplicate-relationship"
    groups = (
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(first,),
            correlation_status=None,
        ),
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(second,),
            correlation_status=None,
        ),
    )
    relationships = build_process_spawn_relationships(groups)
    expected_support = sorted(
        build_process_creation_evidence(group)["evidence_id"]
        for group in groups
    )
    assert len(relationships) == 1
    assert relationships[0]["supported_by"] == expected_support
    assert len(relationships[0]["supported_by"]) == 2
    assert build_process_spawn_relationships(reversed(groups)) == relationships


def test_build_process_spawn_relationships_rejects_unresolvable_endpoint() -> None:
    event = copy.deepcopy(_load_events()[0])
    event["process_id"] = None
    event["process_guid"] = None
    group = ProcessCreationGroup(
        kind="cmd_to_mshta",
        observations=(event,),
        correlation_status=None,
    )
    with pytest.raises(ValueError, match="target.*identity"):
        build_process_spawn_relationships((group,))


def test_build_process_spawn_relationships_is_json_serializable_and_immutable() -> None:
    groups = group_process_creations(_load_events())
    original = copy.deepcopy(groups)
    relationships = build_process_spawn_relationships(groups)
    assert json.loads(json.dumps(relationships, ensure_ascii=False)) == list(
        relationships
    )
    assert groups == original

    relationships[0]["supported_by"].append("evidence-changed")
    assert groups == original


def test_build_process_spawn_relationships_empty_input_returns_empty_tuple() -> None:
    assert build_process_spawn_relationships(()) == ()


def test_build_document_has_complete_fixture_schema_and_review_notes() -> None:
    document = build_mshta_powershell_evidence_document(
        group_process_creations(_load_events())
    )
    assert tuple(document) == (
        "schema_version",
        "scenario_id",
        "scenario_name",
        "source_files",
        "analysis_status",
        "time_window",
        "observed_entities",
        "evidence",
        "relationships",
        "sigma_rules",
        "mitre_techniques",
        "review_notes",
    )
    assert document["schema_version"] == "scenario-evidence/v1"
    assert document["scenario_id"] == "mshta-powershell"
    assert document["scenario_name"] == "MSHTA spawning PowerShell"
    assert document["analysis_status"] == "draft_reviewable"
    assert len(document["observed_entities"]) == 3
    assert len(document["evidence"]) == 2
    assert len(document["relationships"]) == 2
    assert {
        observation["raw_record_ref"]
        for evidence in document["evidence"]
        for observation in evidence["observations"]
    } == {
        "jsonl:line:4",
        "jsonl:line:30",
        "jsonl:line:275",
        "jsonl:line:398",
    }
    assert sum(
        len(evidence["observations"]) for evidence in document["evidence"]
    ) == 4
    assert document["source_files"] == [
        "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    ]
    assert document["time_window"] == {
        "start": "2020-10-22T02:57:59.856000Z",
        "end": "2020-10-22T02:58:00.489000Z",
    }
    assert document["sigma_rules"] == []
    assert document["mitre_techniques"] == []
    notes = " ".join(document["review_notes"]).casefold()
    assert "draft_reviewable" in notes
    assert "human review" in notes
    assert "inferred" in notes
    assert "sigma" in notes
    assert "mitre" in notes
    assert "not a confirmed attack" in notes
    statuses = [document["analysis_status"]]
    statuses.extend(item["status"] for item in document["evidence"])
    statuses.extend(item["status"] for item in document["relationships"])
    assert "confirmed" not in statuses


def test_build_document_has_valid_referential_integrity_and_unique_ids() -> None:
    document = build_mshta_powershell_evidence_document(
        group_process_creations(_load_events())
    )
    entity_ids = {
        entity["entity_id"] for entity in document["observed_entities"]
    }
    evidence_ids = {
        evidence["evidence_id"] for evidence in document["evidence"]
    }
    relationship_ids = [
        relationship["relationship_id"]
        for relationship in document["relationships"]
    ]
    assert len(entity_ids) == len(document["observed_entities"])
    assert len(evidence_ids) == len(document["evidence"])
    assert len(set(relationship_ids)) == len(relationship_ids)
    assert all(
        relationship["source_entity_id"] in entity_ids
        and relationship["target_entity_id"] in entity_ids
        and set(relationship["supported_by"]) <= evidence_ids
        for relationship in document["relationships"]
    )


def test_build_document_is_deterministic_and_group_order_independent() -> None:
    groups = group_process_creations(_load_events())
    expected = build_mshta_powershell_evidence_document(groups)
    assert build_mshta_powershell_evidence_document(groups) == expected
    assert build_mshta_powershell_evidence_document(reversed(groups)) == expected


def test_build_document_consumes_generator_once() -> None:
    groups = group_process_creations(_load_events())
    yielded: list[str] = []

    def group_stream():
        for group in groups:
            yielded.append(group.kind)
            yield group

    document = build_mshta_powershell_evidence_document(group_stream())
    assert len(document["relationships"]) == 2
    assert yielded == [group.kind for group in groups]


def test_build_document_accepts_empty_groups() -> None:
    document = build_mshta_powershell_evidence_document(())
    assert document["source_files"] == []
    assert document["time_window"] == {"start": None, "end": None}
    assert document["observed_entities"] == []
    assert document["evidence"] == []
    assert document["relationships"] == []
    assert document["sigma_rules"] == []
    assert document["mitre_techniques"] == []


def test_build_document_accepts_singleton_group() -> None:
    group = group_process_creations((_load_events()[0],))[0]
    document = build_mshta_powershell_evidence_document((group,))
    assert len(document["observed_entities"]) == 2
    assert len(document["evidence"]) == 1
    assert len(document["relationships"]) == 1
    assert document["time_window"] == {
        "start": "2020-10-22T02:57:59.856000Z",
        "end": "2020-10-22T02:57:59.856000Z",
    }


def test_build_document_sorts_multiple_observed_source_files() -> None:
    groups = list(copy.deepcopy(group_process_creations(_load_events())))
    for observation in groups[1].observations:
        observation["source_file"] = "a-secondary-source.json"
    document = build_mshta_powershell_evidence_document(groups)
    assert document["source_files"] == [
        "a-secondary-source.json",
        "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json",
    ]


def test_build_document_compares_aware_timestamps_by_actual_time() -> None:
    first = copy.deepcopy(_load_events()[2])
    second = copy.deepcopy(_load_events()[3])
    first["timestamp"] = "2020-10-22T09:00:00+07:00"
    second["timestamp"] = "2020-10-22T02:30:00Z"
    groups = (
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(first,),
            correlation_status=None,
        ),
        ProcessCreationGroup(
            kind="mshta_to_powershell",
            observations=(second,),
            correlation_status=None,
        ),
    )
    document = build_mshta_powershell_evidence_document(groups)
    assert document["time_window"] == {
        "start": "2020-10-22T09:00:00+07:00",
        "end": "2020-10-22T02:30:00Z",
    }


def test_build_document_rejects_missing_or_invalid_timestamp() -> None:
    for invalid in (None, "", "not-a-timestamp"):
        event = copy.deepcopy(_load_events()[2])
        event["timestamp"] = invalid
        group = ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(event,),
            correlation_status=None,
        )
        with pytest.raises(ValueError, match="valid canonical timestamp"):
            build_mshta_powershell_evidence_document((group,))


def test_build_document_rejects_mixed_timestamp_awareness() -> None:
    first = copy.deepcopy(_load_events()[2])
    second = copy.deepcopy(_load_events()[3])
    second["timestamp"] = "2020-10-22T02:58:00.489000"
    groups = (
        ProcessCreationGroup(
            kind="cmd_to_mshta",
            observations=(first,),
            correlation_status=None,
        ),
        ProcessCreationGroup(
            kind="mshta_to_powershell",
            observations=(second,),
            correlation_status=None,
        ),
    )
    with pytest.raises(ValueError, match="cannot mix naive and aware"):
        build_mshta_powershell_evidence_document(groups)


def test_build_document_is_json_serializable_and_does_not_mutate_input() -> None:
    groups = group_process_creations(_load_events())
    original = copy.deepcopy(groups)
    document = build_mshta_powershell_evidence_document(groups)
    assert json.loads(json.dumps(document, ensure_ascii=False)) == document
    assert groups == original

    document["observed_entities"][0]["attributes"]["process_name"] = "changed.exe"
    document["evidence"][0]["observations"][0]["raw_fields"]["changed"] = True
    assert groups == original


def test_extract_mshta_powershell_evidence_builds_expected_fixture_document() -> None:
    events = _load_events()
    original = copy.deepcopy(events)
    document = extract_mshta_powershell_evidence(events)

    assert document["schema_version"] == "scenario-evidence/v1"
    assert document["scenario_id"] == "mshta-powershell"
    assert document["analysis_status"] == "draft_reviewable"
    assert document["source_files"] == [
        "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    ]
    assert document["time_window"] == {
        "start": "2020-10-22T02:57:59.856000Z",
        "end": "2020-10-22T02:58:00.489000Z",
    }
    assert len(document["observed_entities"]) == 3
    assert len(document["evidence"]) == 2
    assert len(document["relationships"]) == 2
    observations = [
        observation
        for evidence in document["evidence"]
        for observation in evidence["observations"]
    ]
    assert len(observations) == 4
    assert {item["raw_record_ref"] for item in observations} == {
        "jsonl:line:4",
        "jsonl:line:30",
        "jsonl:line:275",
        "jsonl:line:398",
    }
    assert document["sigma_rules"] == []
    assert document["mitre_techniques"] == []
    assert all(
        item["status"] != "confirmed"
        for collection in (document["evidence"], document["relationships"])
        for item in collection
    )
    assert json.loads(json.dumps(document, ensure_ascii=False)) == document
    assert events == original


def test_extract_matches_manual_flow_for_list_and_tuple_inputs() -> None:
    events = _load_events()
    expected = build_mshta_powershell_evidence_document(
        group_process_creations(events)
    )
    assert extract_mshta_powershell_evidence(events) == expected
    assert extract_mshta_powershell_evidence(tuple(events)) == expected


def test_extract_consumes_one_pass_generator_once() -> None:
    events = _load_events()
    yielded: list[str] = []

    def event_stream():
        for event in events:
            yielded.append(str(event["raw_record_ref"]))
            yield event

    document = extract_mshta_powershell_evidence(event_stream())
    assert len(document["evidence"]) == 2
    assert yielded == [str(event["raw_record_ref"]) for event in events]


def test_extract_is_deterministic_and_input_order_independent() -> None:
    events = _load_events()
    expected = extract_mshta_powershell_evidence(events)
    assert extract_mshta_powershell_evidence(events) == expected
    assert extract_mshta_powershell_evidence(reversed(events)) == expected


def test_extract_ignores_unrelated_event_without_mutating_it() -> None:
    events = _load_events()
    unrelated = copy.deepcopy(events[0])
    unrelated["process_name"] = "C:\\Windows\\System32\\notepad.exe"
    unrelated["raw_record_ref"] = "fixture:unrelated"
    original_events = copy.deepcopy(events)
    original_unrelated = copy.deepcopy(unrelated)

    assert extract_mshta_powershell_evidence(
        (*events, unrelated)
    ) == extract_mshta_powershell_evidence(events)
    assert events == original_events
    assert unrelated == original_unrelated


def test_extract_deduplicates_identical_provenance() -> None:
    events = _load_events()
    duplicate = copy.deepcopy(events[2])
    document = extract_mshta_powershell_evidence((*events, duplicate))
    expected = extract_mshta_powershell_evidence(events)
    assert document == expected
    assert sum(
        len(evidence["observations"]) for evidence in document["evidence"]
    ) == 4


def test_extract_rejects_conflicting_duplicate_provenance() -> None:
    events = _load_events()
    conflicting = copy.deepcopy(events[2])
    conflicting["command_line"] = "different content"
    with pytest.raises(ValueError, match="conflicting.*share provenance"):
        extract_mshta_powershell_evidence((*events, conflicting))


def test_extract_rejects_relevant_event_without_provenance() -> None:
    for field in ("source_file", "raw_record_ref"):
        event = copy.deepcopy(_load_events()[0])
        event.pop(field)
        with pytest.raises(ValueError, match=field):
            extract_mshta_powershell_evidence((event,))


def test_extract_rejects_invalid_correlation_tolerance() -> None:
    for invalid in (True, -1, float("nan"), float("inf"), "1", None):
        with pytest.raises(
            ValueError,
            match="tolerance_seconds must be a finite, non-negative number",
        ):
            extract_mshta_powershell_evidence(
                (),
                correlation_tolerance_seconds=invalid,  # type: ignore[arg-type]
            )


def test_extract_empty_input_returns_valid_empty_document() -> None:
    document = extract_mshta_powershell_evidence(())
    assert document["schema_version"] == "scenario-evidence/v1"
    assert document["scenario_id"] == "mshta-powershell"
    assert document["analysis_status"] == "draft_reviewable"
    assert document["source_files"] == []
    assert document["time_window"] == {"start": None, "end": None}
    assert document["observed_entities"] == []
    assert document["evidence"] == []
    assert document["relationships"] == []
    assert document["sigma_rules"] == []
    assert document["mitre_techniques"] == []
    assert json.loads(json.dumps(document, ensure_ascii=False)) == document
