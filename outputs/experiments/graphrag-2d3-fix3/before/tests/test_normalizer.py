from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from threat_hunting.mordor.parser import MordorParseError, ParsedRecord
from threat_hunting.normalizer import iter_normalized_records, normalize_record
from threat_hunting.schemas.canonical_event import CANONICAL_FIELDS
from threat_hunting.schemas.canonical_mapping import (
    SECURITY_PROVIDER,
    SYSMON_PROVIDER,
)


FIXTURES = Path(__file__).parent / "fixtures" / "mordor"


def _record(provider: str, event_id: int | str, **fields: object) -> dict[str, object]:
    return {
        "SourceName": provider,
        "EventID": event_id,
        "@timestamp": "2020-01-02T03:04:05Z",
        **fields,
    }


def _normalize(record: dict[str, object], ref: str = "jsonl:line:1"):
    return normalize_record(
        record,
        raw_record_ref=ref,
        source_file="fixture.json",
    )


def test_output_has_complete_ordered_schema_and_is_json_serializable() -> None:
    result = _normalize(_record(SYSMON_PROVIDER, 1, ProcessId=123))
    expected = tuple(str(field["name"]) for field in CANONICAL_FIELDS)
    assert tuple(result.event) == expected
    assert result.event["event_id"] == "1"
    assert json.loads(json.dumps(result.event)) == result.event


def test_sysmon_one_process_fields_and_hexadecimal_are_preserved() -> None:
    result = _normalize(
        _record(
            SYSMON_PROVIDER,
            1,
            ProcessId="0x4d2",
            ProcessGuid="{PROCESS-GUID}",
            ParentProcessId=99,
            ParentProcessGuid="{PARENT-GUID}",
        )
    )
    assert result.event["process_id"] == "0x4d2"
    assert result.event["parent_process_id"] == "99"
    assert result.event["process_guid"] == "{PROCESS-GUID}"
    assert result.event["parent_process_guid"] == "{PARENT-GUID}"


def test_security_4688_process_ids_and_subject_role() -> None:
    result = _normalize(
        _record(
            SECURITY_PROVIDER,
            "4688",
            NewProcessId="0x100",
            ProcessId="0x44",
            SubjectUserName="actor",
            TargetUserName="must-not-map",
        )
    )
    assert result.event["process_id"] == "0x100"
    assert result.event["parent_process_id"] == "0x44"
    assert result.event["subject_user"] == "actor"
    assert result.event["target_user"] is None


@pytest.mark.parametrize(
    ("event_id", "expected_subject", "expected_target"),
    [
        ("4625", "actor", "victim"),
        ("4769", None, "victim"),
        ("4776", None, "victim"),
    ],
)
def test_security_authentication_user_roles(
    event_id: str,
    expected_subject: str | None,
    expected_target: str,
) -> None:
    result = _normalize(
        _record(
            SECURITY_PROVIDER,
            event_id,
            SubjectUserName="actor",
            TargetUserName="victim",
            AccountName="broad-alias-must-not-win",
        )
    )
    assert result.event["subject_user"] == expected_subject
    assert result.event["target_user"] == expected_target


def test_security_4769_source_ip_and_optional_subject_role() -> None:
    source_ip = "::ffff:172.18.39.5"
    result = _normalize(
        _record(
            SECURITY_PROVIDER,
            "4769",
            IpAddress=source_ip,
            TargetUserName="pgustavo@THESHIRE.LOCAL",
            AccountName="must-not-map",
        )
    )
    assert result.event["source_ip"] == source_ip
    assert result.event["target_user"] == "pgustavo@THESHIRE.LOCAL"
    assert result.event["subject_user"] is None
    assert result.event["user"] is None
    assert not any(
        issue.code == "missing_expected_source"
        and issue.canonical_field == "subject_user"
        for issue in result.issues
    )

    missing_ip = _normalize(
        _record(
            SECURITY_PROVIDER,
            "4769",
            TargetUserName="pgustavo@THESHIRE.LOCAL",
        )
    )
    assert missing_ip.event["source_ip"] is None


def test_security_4625_process_path_without_unapproved_process_id() -> None:
    process_path = "C:\\Users\\pgustavo\\Downloads\\PurpleSharp.exe"
    result = _normalize(
        _record(
            SECURITY_PROVIDER,
            "4625",
            ProcessName=process_path,
            ProcessId="0x1d60",
            TargetUserName="lrodriguez",
        )
    )
    assert result.event["process_name"] == process_path
    assert result.event["process_id"] is None
    assert result.event["target_user"] == "lrodriguez"


def test_account_name_does_not_become_target_user() -> None:
    result = _normalize(
        _record(SECURITY_PROVIDER, "4776", AccountName="not-a-target")
    )
    assert result.event["target_user"] is None
    assert any(
        issue.code == "missing_expected_source"
        and issue.canonical_field == "target_user"
        for issue in result.issues
    )


@pytest.mark.parametrize("event_id", ["12", "13", "14"])
def test_target_object_maps_only_in_registry_contexts(event_id: str) -> None:
    registry_result = _normalize(
        _record(SYSMON_PROVIDER, event_id, TargetObject="HKLM\\Software\\Example")
    )
    network_result = _normalize(
        _record(SYSMON_PROVIDER, "3", TargetObject="not-a-registry-key")
    )
    assert registry_result.event["registry_key"] == "HKLM\\Software\\Example"
    assert network_result.event["registry_key"] is None


def test_sysmon_ten_does_not_create_parent_child_relationship() -> None:
    result = _normalize(
        _record(
            SYSMON_PROVIDER,
            "10",
            SourceImage="source.exe",
            SourceProcessId="11",
            TargetImage="target.exe",
            TargetProcessId="22",
        )
    )
    assert result.event["process_name"] is None
    assert result.event["process_id"] is None
    assert result.event["parent_process_name"] is None
    assert result.event["parent_process_id"] is None


def test_network_contexts_and_valid_ports() -> None:
    sysmon = _normalize(
        _record(
            SYSMON_PROVIDER,
            "3",
            SourceIp="10.0.0.1",
            SourcePort="443",
            DestinationIp="10.0.0.2",
            DestinationPort=65535,
        )
    )
    security = _normalize(
        _record(
            SECURITY_PROVIDER,
            "5156",
            SourceAddress="192.0.2.1",
            SourcePort="0",
            DestAddress="198.51.100.1",
            DestPort="8443",
        )
    )
    assert (sysmon.event["source_port"], sysmon.event["destination_port"]) == (
        443,
        65535,
    )
    assert security.event["source_ip"] == "192.0.2.1"
    assert security.event["destination_ip"] == "198.51.100.1"
    assert security.event["source_port"] == 0
    assert security.event["destination_port"] == 8443


@pytest.mark.parametrize("invalid_port", [True, 1.5, "12.5", "65536", -1])
def test_invalid_port_is_null_with_issue(invalid_port: object) -> None:
    result = _normalize(
        _record(SYSMON_PROVIDER, "3", DestinationPort=invalid_port)
    )
    assert result.event["destination_port"] is None
    assert any(
        issue.code == "invalid_transformation"
        and issue.canonical_field == "destination_port"
        for issue in result.issues
    )


def test_sysmon_dns_context() -> None:
    result = _normalize(
        _record(SYSMON_PROVIDER, "22", QueryName="example.test")
    )
    assert result.event["dns_query"] == "example.test"


def test_timestamp_primary_and_fallback_order() -> None:
    primary = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            **{
                "@timestamp": "2020-01-02T10:04:05+07:00",
                "TimeCreated": "2020-01-02T03:04:05Z",
            },
        )
    )
    fallback = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            **{
                "@timestamp": "invalid",
                "TimeCreated": "2020-01-02T04:05:06+01:00",
                "EventTime": "2020-01-02T03:04:05Z",
            },
        )
    )
    final_fallback = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            **{
                "@timestamp": "invalid-primary",
                "TimeCreated": "invalid-secondary",
                "EventTime": "2020-01-02T05:06:07+02:00",
            },
        )
    )
    assert primary.event["timestamp"] == "2020-01-02T03:04:05Z"
    assert fallback.event["timestamp"] == "2020-01-02T03:05:06Z"
    assert final_fallback.event["timestamp"] == "2020-01-02T03:06:07Z"


def test_naive_timestamp_is_not_assigned_utc_and_can_fall_back() -> None:
    result = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            **{
                "@timestamp": "2020-01-02T03:04:05",
                "TimeCreated": "2020-01-02T03:04:06+00:00",
            },
        )
    )
    assert result.event["timestamp"] == "2020-01-02T03:04:06Z"
    assert not any(
        issue.code == "invalid_transformation" for issue in result.issues
    )


def test_unselected_naive_event_time_does_not_emit_invalid_transformation() -> None:
    primary = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            **{
                "@timestamp": "2020-01-02T03:04:05Z",
                "EventTime": "2020-01-01 22:04:05",
            },
        )
    )
    fallback = _normalize(
        {
            "SourceName": SYSMON_PROVIDER,
            "EventID": "1",
            "TimeCreated": "2020-01-02T03:04:05Z",
            "EventTime": "2020-01-01 22:04:05",
        }
    )
    for result in (primary, fallback):
        assert result.event["timestamp"] == "2020-01-02T03:04:05Z"
        assert not any(
            issue.code == "invalid_transformation" for issue in result.issues
        )
        assert any(issue.code == "timestamp_conflict" for issue in result.issues)


def test_only_naive_event_time_is_null_with_invalid_transformation() -> None:
    result = _normalize(
        {
            "SourceName": SYSMON_PROVIDER,
            "EventID": "1",
            "EventTime": "2020-01-02 03:04:05",
        }
    )
    assert result.event["timestamp"] is None
    assert any(
        issue.code == "invalid_transformation"
        and issue.source_path == "/EventTime"
        for issue in result.issues
    )


def test_invalid_timestamp_is_null_with_issue() -> None:
    result = _normalize(
        _record(SYSMON_PROVIDER, "1", **{"@timestamp": "not-a-time"})
    )
    assert result.event["timestamp"] is None
    assert any(
        issue.code == "invalid_transformation"
        and issue.canonical_field == "timestamp"
        for issue in result.issues
    )


def test_review_only_and_excluded_timestamps_are_not_selected() -> None:
    record = {
        "SourceName": SYSMON_PROVIDER,
        "EventID": "1",
        "UtcTime": "2020-01-02T03:04:05Z",
        "CreationUtcTime": "2020-01-02T03:04:06Z",
    }
    result = _normalize(record)
    assert result.event["timestamp"] is None
    assert any(
        issue.code == "missing_expected_source"
        and issue.canonical_field == "timestamp"
        for issue in result.issues
    )


def test_timestamp_conflict_is_non_fatal() -> None:
    result = _normalize(
        _record(
            SYSMON_PROVIDER,
            "1",
            TimeCreated="2020-01-02T04:05:06Z",
        )
    )
    assert result.event["timestamp"] == "2020-01-02T03:04:05Z"
    assert any(issue.code == "timestamp_conflict" for issue in result.issues)


def test_unknown_context_still_returns_one_event() -> None:
    result = _normalize(
        {
            "SourceName": "Unknown-Provider",
            "EventID": "0x10",
            "TargetObject": "not-mapped",
        }
    )
    assert result.event["provider"] == "Unknown-Provider"
    assert result.event["event_id"] == "0x10"
    assert result.event["registry_key"] is None
    assert any(issue.code == "unsupported_context" for issue in result.issues)


def test_unknown_context_normalizes_explicit_base_fields() -> None:
    result = _normalize(
        {
            "SourceName": "Unknown-Provider",
            "EventID": "999",
            "@timestamp": "2020-01-02T03:04:05Z",
            "Channel": "Unknown/Operational",
            "Hostname": "unknown-host",
            "Image": "must-not-map.exe",
            "User": "must-not-map",
            "SourceIp": "192.0.2.10",
            "TargetObject": "must-not-map",
            "QueryName": "must-not-map.example",
        }
    )
    assert result.event["event_id"] == "999"
    assert result.event["provider"] == "Unknown-Provider"
    assert result.event["timestamp"] == "2020-01-02T03:04:05Z"
    assert result.event["channel"] == "Unknown/Operational"
    assert result.event["host"] == "unknown-host"
    for field in (
        "process_name",
        "user",
        "source_ip",
        "registry_key",
        "dns_query",
    ):
        assert result.event[field] is None
    assert any(issue.code == "unsupported_context" for issue in result.issues)


def test_unknown_context_checks_timestamp_conflict_with_review_only_value() -> None:
    result = _normalize(
        {
            "SourceName": "Unknown-Provider",
            "EventID": "999",
            "@timestamp": "2020-01-02T03:04:05Z",
            "UtcTime": "2020-01-02 07:04:05",
            "Channel": "Unknown/Operational",
            "Hostname": "unknown-host",
        }
    )
    assert result.event["timestamp"] == "2020-01-02T03:04:05Z"
    assert any(issue.code == "timestamp_conflict" for issue in result.issues)
    assert not any(
        issue.code == "invalid_transformation" and issue.canonical_field == "timestamp"
        for issue in result.issues
    )


def test_unknown_context_with_only_naive_timestamp_still_yields_event() -> None:
    result = _normalize(
        {
            "SourceName": "Unknown-Provider",
            "EventID": "999",
            "EventTime": "2020-01-02 03:04:05",
            "Channel": "Unknown/Operational",
            "Hostname": "unknown-host",
        }
    )
    assert result.event["timestamp"] is None
    assert result.event["raw_record_ref"] == "jsonl:line:1"
    assert any(
        issue.code == "invalid_transformation"
        and issue.canonical_field == "timestamp"
        and issue.source_path == "/EventTime"
        for issue in result.issues
    )
    assert any(issue.code == "unsupported_context" for issue in result.issues)


def test_identical_records_are_independent_and_input_is_not_mutated() -> None:
    record = _record(SYSMON_PROVIDER, "22", QueryName="example.test")
    before = copy.deepcopy(record)
    first = _normalize(record, "jsonl:line:1")
    second = _normalize(record, "jsonl:line:2")
    assert record == before
    assert first is not second
    assert first.event is not second.event
    assert first.event["raw_record_ref"] == "jsonl:line:1"
    assert second.event["raw_record_ref"] == "jsonl:line:2"
    assert first.event["source_file"] == "fixture.json"


def test_ambiguous_mapping_is_reported_deterministically() -> None:
    result = _normalize(
        _record(SYSMON_PROVIDER, "1", Hostname="host-a", Computer="host-b")
    )
    assert result.event["host"] == "host-a"
    assert any(
        issue.code == "ambiguous_mapping" and issue.canonical_field == "host"
        for issue in result.issues
    )


def test_iter_normalized_jsonl_preserves_order_physical_refs_and_fixture() -> None:
    path = FIXTURES / "sample.jsonl"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    results = list(iter_normalized_records(path, "jsonl"))
    after = hashlib.sha256(path.read_bytes()).hexdigest()

    assert [result.event["event_id"] for result in results] == ["1", "2"]
    assert [result.event["raw_record_ref"] for result in results] == [
        "jsonl:line:1",
        "jsonl:line:3",
    ]
    assert all(result.event["source_file"] == path.name for result in results)
    assert before == after


def test_iter_normalized_json_array_preserves_zero_based_refs() -> None:
    path = FIXTURES / "sample-array.json"
    results = list(iter_normalized_records(path, "json_array"))

    assert [result.event["event_id"] for result in results] == ["1", "2"]
    assert [result.event["raw_record_ref"] for result in results] == [
        "json-array:index:0",
        "json-array:index:1",
    ]
    assert all(result.event["source_file"] == path.name for result in results)


def test_iter_normalized_json_object_yields_exactly_one_root_result() -> None:
    path = FIXTURES / "sample-object.json"
    results = list(iter_normalized_records(path, "json_object"))

    assert len(results) == 1
    assert results[0].event["raw_record_ref"] == "json-object:root"
    assert results[0].event["source_file"] == path.name


def test_iter_normalized_does_not_deduplicate_identical_records(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.jsonl"
    record = _record(SYSMON_PROVIDER, "22", QueryName="example.test")
    path.write_text(
        json.dumps(record) + "\n" + json.dumps(record) + "\n",
        encoding="utf-8",
    )

    results = list(iter_normalized_records(path, "jsonl"))

    assert len(results) == 2
    assert results[0].event["dns_query"] == results[1].event["dns_query"]
    assert [result.event["raw_record_ref"] for result in results] == [
        "jsonl:line:1",
        "jsonl:line:2",
    ]


def test_iter_normalized_yields_issues_and_unknown_context(tmp_path: Path) -> None:
    path = tmp_path / "issues.jsonl"
    records = [
        _record(SYSMON_PROVIDER, "3", DestinationPort="65536"),
        {"SourceName": "Unknown-Provider", "EventID": "999"},
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    results = list(iter_normalized_records(path, "jsonl"))

    assert len(results) == len(records)
    assert any(issue.code == "invalid_transformation" for issue in results[0].issues)
    assert results[1].event["event_id"] == "999"
    assert results[1].event["raw_record_ref"] == "jsonl:line:2"
    assert results[1].event["source_file"] == path.name
    assert any(issue.code == "unsupported_context" for issue in results[1].issues)


def test_iter_normalized_is_lazy_and_propagates_later_parse_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "lazy.jsonl"
    path.write_text(
        json.dumps(_record(SYSMON_PROVIDER, "1", Image="first.exe"))
        + "\n{malformed later line}\n",
        encoding="utf-8",
    )

    iterator = iter_normalized_records(path, "jsonl")
    first = next(iterator)
    assert first.event["process_name"] == "first.exe"
    assert first.event["raw_record_ref"] == "jsonl:line:1"
    with pytest.raises(MordorParseError, match="line 2"):
        next(iterator)


def test_iter_normalized_does_not_mutate_parsed_record(monkeypatch) -> None:
    record = _record(SYSMON_PROVIDER, "1", Image="process.exe")
    before = copy.deepcopy(record)

    def fake_iter_records(path: Path, source_format: str):
        assert path.name == "fixture.jsonl"
        assert source_format == "jsonl"
        yield ParsedRecord(record, "jsonl:line:1")

    monkeypatch.setattr("threat_hunting.normalizer.iter_records", fake_iter_records)
    results = list(iter_normalized_records(Path("fixture.jsonl"), "jsonl"))

    assert len(results) == 1
    assert record == before


@pytest.mark.parametrize(
    ("raw_record_ref", "source_file", "expected_name"),
    [
        ("", "fixture.json", "raw_record_ref"),
        ("   ", "fixture.json", "raw_record_ref"),
        ("jsonl:line:1", "", "source_file"),
        ("jsonl:line:1", "   ", "source_file"),
        (None, "fixture.json", "raw_record_ref"),
        ("jsonl:line:1", None, "source_file"),
    ],
)
def test_empty_provenance_is_rejected(
    raw_record_ref: object,
    source_file: object,
    expected_name: str,
) -> None:
    with pytest.raises(ValueError, match=expected_name):
        normalize_record(
            {},
            raw_record_ref=raw_record_ref,  # type: ignore[arg-type]
            source_file=source_file,  # type: ignore[arg-type]
        )
