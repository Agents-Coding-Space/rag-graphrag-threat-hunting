"""Synthetic fixtures: no production data or benchmark answers in these tests."""
import json
from pathlib import Path

import pytest

from threat_hunting.evidence.authentication import (
    assess_logons, correlate_failures, detect_spraying, survey_authentication,
)
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.mordor.parser import iter_records
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.normalizer import normalize_record
from threat_hunting.sigma.security_offline import evaluate_security_rule


def raw_event(eid=4625, account="fixture-user", **fields):
    return {"EventID": eid, "SourceName": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
            "Hostname": "fixture-endpoint.example", "@timestamp": "2020-01-01T00:00:01.000Z",
            "TargetUserName": account, "TargetDomainName": "EXAMPLE", "WorkstationName": "fixture-endpoint",
            "Status": "0xc000006d", "SubStatus": "0xc000006a", **fields}


def survey_fixture(tmp_path, rows, fmt="jsonl"):
    raw = tmp_path / ("fixture.jsonl" if fmt == "jsonl" else "fixture.json")
    canonical = tmp_path / "canonical.jsonl"
    raw.write_text("\n".join(json.dumps(r) for r in rows) if fmt == "jsonl" else json.dumps(rows), encoding="utf-8")
    events = [normalize_record(p.data, raw_record_ref=p.raw_record_ref, source_file=raw.name).event
              for p in iter_records(raw, detect_format(raw).source_format)]
    canonical.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    hashes = [digest(raw), digest(canonical)]
    result = survey_authentication(raw, canonical, expected_raw_sha256=hashes[0], expected_canonical_sha256=hashes[1])
    assert hashes == [digest(raw), digest(canonical)]
    return result, raw, canonical


@pytest.mark.parametrize("fmt,first_ref", [("jsonl", "jsonl:line:1"), ("json_array", "json-array:index:0")])
def test_full_survey_formats_missing_nested_and_stable_refs(tmp_path, fmt, first_ref):
    rows = [raw_event(), raw_event(4776, WorkstationName=None, Workstation="fixture-endpoint", Status="0xc000006a", SubStatus=None, TargetDomainName=None),
            raw_event(4624, TargetUserName=None, nested={"TargetUserName": "not-an-alias"})]
    survey, raw, canonical = survey_fixture(tmp_path, rows, fmt)
    assert survey["raw_records_read"] == survey["raw_canonical_equal_records"] == 3
    assert survey["dropped_records"] == 0
    assert survey["observations"][0]["raw_record_ref"] == first_ref
    assert survey["observations"][2]["target_account"] is None
    assert survey["authentication_profiles"]["4624"]["count"] == 1
    again = survey_authentication(raw, canonical, expected_raw_sha256=digest(raw), expected_canonical_sha256=digest(canonical))
    assert survey == again


def test_hash_and_shifted_canonical_fail_closed(tmp_path):
    _, raw, canonical = survey_fixture(tmp_path, [raw_event()])
    with pytest.raises(ValueError, match="provenance mismatch"):
        survey_authentication(raw, canonical, expected_raw_sha256="0" * 64, expected_canonical_sha256=digest(canonical))
    row = json.loads(canonical.read_text())
    row["raw_record_ref"] = "jsonl:line:99"
    canonical.write_text(json.dumps(row))
    with pytest.raises(ValueError, match="Raw/canonical mismatch"):
        survey_authentication(raw, canonical, expected_raw_sha256=digest(raw), expected_canonical_sha256=digest(canonical))


def observation(oid, eid="4625", account="fixture-user", workstation="fixture-endpoint", timestamp="2020-01-01T00:00:01Z", domain="EXAMPLE", **kwargs):
    return {"observation_id": oid, "event_id": eid, "target_account": account, "source_workstation": workstation,
            "source_file": "fixture.jsonl", "target_domain": domain, "source_ip": None, "host": "fixture-host",
            "timestamp": timestamp, "outcome": "failure", "raw_record_ref": oid,
            "original_fields": {"Status": "0xc000006a", "ProcessName": "fixture.exe", "ProcessId": "7"}, **kwargs}


def test_unique_cross_provider_pair_keeps_both_refs():
    rows = [observation("endpoint"), observation("dc", "4776", domain=None, timestamp="2020-01-01T00:00:01.2Z")]
    result = correlate_failures(rows)
    assert result["paired_attempts"] == result["countable_attempts"] == 1
    assert result["attempts"][0]["raw_record_refs"] == ["endpoint", "dc"]
    assert result["attempts"][0]["status"] == "inferred"
    assert result["attempts"][0]["limitations"]


@pytest.mark.parametrize("changes", [{"workstation": "another"}, {"domain": "ANOTHER"}, {"timestamp": "2020-01-01T00:00:03Z"}, {"workstation": None}, {"source_ip": "192.0.2.2"}])
def test_pairing_rejects_conflicts_and_missing_context(changes):
    left = observation("left", source_ip="192.0.2.1")
    right = observation("right", "4776", **changes)
    assert correlate_failures([left, right])["paired_attempts"] == 0


def test_many_to_one_is_ambiguous_not_three_attempts():
    rows = [observation("a"), observation("b"), observation("dc", "4776")]
    result = correlate_failures(rows)
    assert len(result["ambiguous_observations"]) == 3
    assert result["countable_attempts"] == 0
    assert detect_spraying(result["attempts"], min_accounts=2) == []


def test_distinct_accounts_source_scope_and_exact_sliding_boundary():
    rows = [observation(str(i), account=f"fixture-{i}", timestamp=f"2020-01-01T00:00:0{i}Z") for i in range(5)]
    attempts = correlate_failures(rows)["attempts"]
    findings = detect_spraying(attempts)
    assert len(findings) == 1 and len(findings[0]["distinct_accounts"]) == 5
    assert findings[0]["status"] == "candidate"
    assert detect_spraying(attempts, window_seconds=3) == []
    attempts[-1]["timestamp"] = "2020-01-01T00:01:00Z"
    assert len(detect_spraying(attempts)) == 1
    attempts[-1]["timestamp"] = "2020-01-01T00:01:00.001Z"
    assert detect_spraying(attempts) == []
    attempts[-1]["timestamp"] = "2020-01-01T00:00:04Z"
    attempts[-1]["source_context"]["value"] = "other-source"
    assert detect_spraying(attempts) == []


def test_repeated_single_account_or_unknown_source_never_spraying():
    assert detect_spraying(correlate_failures([observation(str(i)) for i in range(20)])["attempts"]) == []
    assert detect_spraying(correlate_failures([observation(str(i), account=str(i), workstation=None) for i in range(8)])["attempts"]) == []


def test_same_name_success_is_not_causal_and_privileges_are_context():
    failure = observation("failure")
    success = observation("success", "4624", timestamp="2020-01-01T00:00:02Z", outcome="success",
                          original_fields={"TargetLogonId": "0x123", "LogonType": "3"})
    privilege = observation("priv", "4672", timestamp="2020-01-01T00:00:02Z", outcome="context_only",
                            original_fields={"SubjectLogonId": "0x123", "SubjectUserName": "fixture-user"})
    result = assess_logons([failure, success, privilege], correlate_failures([failure])["attempts"])
    assert result["same_name_temporal_candidates"][0]["direction"] == "after_failure"
    assert result["abnormal_login_verdict"] == "not_established_without_baseline"
    assert result["privileged_logon_context_links"][0]["status"] == "inferred"


def test_security_sigma_evaluates_reduction_and_rejects_unknown_fields(tmp_path):
    import yaml
    rule = {"title": "Fixture", "logsource": {"product": "windows", "service": "security"},
            "detection": {"selection": {"EventID": 4769, "TicketEncryptionType": "0x17"},
                          "reduction": {"ServiceName|endswith": "$"}, "condition": "selection and not reduction"}}
    path = tmp_path / "fixture.yml"
    path.write_text(yaml.safe_dump(rule))
    obs = [observation("one", "4769", original_fields={"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "fixture-service"}),
           observation("two", "4769", original_fields={"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "fixture-machine$"})]
    result = evaluate_security_rule(path, obs)
    assert [m["raw_record_ref"] for m in result["matches"]] == ["one"]
    rule["detection"]["selection"]["UnknownField"] = "x"
    path.write_text(yaml.safe_dump(rule))
    with pytest.raises(ValueError, match="Unsupported field"):
        evaluate_security_rule(path, obs)


def test_yaml_tags_not_executed(tmp_path):
    import yaml
    path = tmp_path / "unsafe.yml"
    path.write_text("!!python/object/apply:os.system ['echo unsafe']")
    with pytest.raises(yaml.YAMLError):
        evaluate_security_rule(path, [])
