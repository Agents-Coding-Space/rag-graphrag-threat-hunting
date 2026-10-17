"""Read-only streaming audit of the MSHTA ground-truth evidence anchors."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from hashlib import sha256
from itertools import zip_longest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FILENAME = "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
EXPECTED_HASH = "25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32"
GT_PATH = ROOT / "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json"
EVIDENCE_PATH = ROOT / "outputs/evidence/mshta-powershell/scenario_evidence.json"
MANIFEST_PATH = ROOT / "outputs/canonical/mordor-selected-v2/manifest.json"
OUTPUT = Path(__file__).with_name("raw_audit.json")
FIELDS = (
    "SourceName", "EventID", "TimeCreated", "@timestamp", "UtcTime", "Hostname",
    "Image", "NewProcessName", "ProcessId", "NewProcessId", "ProcessGuid",
    "ParentImage", "ParentProcessName", "ParentProcessId", "ParentProcessGuid",
    "CommandLine", "ParentCommandLine", "User", "SubjectUserName", "SubjectDomainName",
    "OriginalFileName", "Application", "SourceAddress", "DestAddress", "DestPort",
    "TargetFilename", "Channel",
)


def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def events(path: Path):
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            yield line_number, json.loads(line)


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def pid(value: str) -> int:
    return int(value, 16 if value.lower().startswith("0x") else 10)


def main() -> None:
    matches = sorted((ROOT / "data/raw").rglob(FILENAME))
    if len(matches) != 1:
        raise ValueError(f"Expected one exact raw filename {FILENAME}, found {len(matches)}")
    raw_path = matches[0]
    before = digest(raw_path)
    gt = read(GT_PATH)
    evidence = read(EVIDENCE_PATH)
    manifest = read(MANIFEST_PATH)
    entry = next(item for item in manifest["files"] if item["input"] == FILENAME)
    canonical_path = MANIFEST_PATH.parent / entry["canonical_events"]
    counts: Counter = Counter()
    provider_counts: Counter = Counter()
    anchor_numbers = {4, 30, 36, 275, 398, 422}
    anchors: dict[int, dict] = {}
    canonical_anchors: dict[int, dict] = {}
    network_records = []
    deletion_records = []
    log_clear_records = []
    command_records = []
    script_fields = []
    invariant_errors = []
    min_timestamp = max_timestamp = None
    total = 0
    for raw_item, canonical_item in zip_longest(events(raw_path), events(canonical_path)):
        if raw_item is None or canonical_item is None:
            invariant_errors.append("raw_canonical_count_mismatch")
            continue
        number, raw = raw_item
        _, canonical = canonical_item
        total += 1
        event_id = str(raw.get("EventID"))
        counts[event_id] += 1
        provider_counts[raw.get("SourceName")] += 1
        expected = {
            "event_id": event_id, "provider": raw.get("SourceName"),
            "host": raw.get("Hostname"), "source_file": FILENAME,
            "raw_record_ref": f"jsonl:line:{number}",
        }
        for field, value in expected.items():
            if canonical[field] != value:
                invariant_errors.append({"line": number, "field": field, "expected": value,
                                         "actual": canonical[field]})
        if parsed(canonical["timestamp"]) != parsed(raw["TimeCreated"]):
            invariant_errors.append({"line": number, "field": "timestamp"})
        timestamp = canonical["timestamp"]
        min_timestamp = min(min_timestamp, timestamp) if min_timestamp else timestamp
        max_timestamp = max(max_timestamp, timestamp) if max_timestamp else timestamp
        compact = {"raw_record_ref": f"jsonl:line:{number}",
                   "original_fields": {key: raw[key] for key in FIELDS if key in raw}}
        if number in anchor_numbers:
            anchors[number] = compact
            canonical_anchors[number] = canonical
        if event_id in ("5156", "5158", "3", "22"):
            network_records.append(compact)
        if event_id == "23":
            deletion_records.append(compact)
        if event_id in ("1102", "104"):
            log_clear_records.append(compact)
        if "CommandLine" in raw:
            command_records.append(compact)
        if any(key in raw for key in ("ScriptBlockText", "ScriptBlockId", "HostApplication", "Payload")):
            script_fields.append(f"jsonl:line:{number}")

    anchor_mapping_errors = []
    for number, compact in anchors.items():
        raw = compact["original_fields"]
        canonical = canonical_anchors[number]
        mapping = {
            "command_line": "CommandLine", "host": "Hostname", "provider": "SourceName",
            "process_name": "NewProcessName" if raw["EventID"] == 4688 else "Image",
            "process_id": "NewProcessId" if raw["EventID"] == 4688 else "ProcessId",
            "parent_process_name": "ParentProcessName" if raw["EventID"] == 4688 else "ParentImage",
            "parent_process_id": "ProcessId" if raw["EventID"] == 4688 else "ParentProcessId",
        }
        if raw["EventID"] == 1:
            mapping.update(process_guid="ProcessGuid", parent_process_guid="ParentProcessGuid", user="User")
        for canonical_field, raw_field in mapping.items():
            if canonical[canonical_field] != raw[raw_field]:
                anchor_mapping_errors.append({"raw_record_ref": compact["raw_record_ref"],
                                              "canonical_field": canonical_field, "raw_field": raw_field})
    observation_errors = []
    for item in evidence["evidence"]:
        for observation in item["observations"]:
            number = int(observation["raw_record_ref"].split(":")[-1])
            canonical = canonical_anchors[number]
            for field in ("provider", "event_id", "timestamp", "source_file", "raw_record_ref"):
                if observation[field] != canonical[field]:
                    observation_errors.append({"raw_record_ref": observation["raw_record_ref"], "field": field})
            for field, value in observation["canonical_fields"].items():
                if value != canonical[field]:
                    observation_errors.append({"raw_record_ref": observation["raw_record_ref"], "field": field})
    gt_observation_errors = []
    for item in gt["evidence"]:
        for observation in item["observations"]:
            canonical = canonical_anchors[int(observation["raw_record_ref"].split(":")[-1])]
            for field in ("provider", "event_id", "timestamp", "source_file", "raw_record_ref"):
                if observation[field] != canonical[field]:
                    gt_observation_errors.append({"raw_record_ref": observation["raw_record_ref"], "field": field})

    pairs = []
    for security_number, sysmon_number in ((4, 275), (30, 398), (36, 422)):
        s = anchors[security_number]["original_fields"]
        y = anchors[sysmon_number]["original_fields"]
        pairs.append({
            "security_ref": f"jsonl:line:{security_number}", "sysmon_ref": f"jsonl:line:{sysmon_number}",
            "matching_host": s["Hostname"] == y["Hostname"],
            "matching_process_path": s["NewProcessName"].casefold() == y["Image"].casefold(),
            "matching_process_id": pid(s["NewProcessId"]) == pid(y["ProcessId"]),
            "matching_parent_path": s["ParentProcessName"].casefold() == y["ParentImage"].casefold(),
            "matching_parent_id": pid(s["ProcessId"]) == pid(y["ParentProcessId"]),
            "matching_command_line": s["CommandLine"] == y["CommandLine"],
            "timecreated_delta_seconds": abs((parsed(s["TimeCreated"]) - parsed(y["TimeCreated"])).total_seconds()),
            "correlation_status": "inferred", "in_ground_truth_scope": security_number != 36,
        })

    entity_checks = []
    known_entities = {item["entity_id"]: item for item in gt["entities"]}
    for entity in gt["entities"]:
        values = entity["attributes"]
        matches = []
        for n in (275, 398, 422):
            raw = anchors[n]["original_fields"]
            for role, guid_key, pid_key, path_key in (("process", "ProcessGuid", "ProcessId", "Image"),
                                                      ("parent", "ParentProcessGuid", "ParentProcessId", "ParentImage")):
                if values.get("process_guid") == raw.get(guid_key):
                    matches.append({"raw_record_ref": f"jsonl:line:{n}", "role": role,
                                    "host_matches": values["host"] == raw["Hostname"],
                                    "pid_matches": pid(values["process_id"]) == pid(raw[pid_key]),
                                    "basename_matches": values["process_name"].casefold() == raw[path_key].split("\\")[-1].casefold()})
        entity_checks.append({"entity_id": entity["entity_id"], "anchor_matches": matches})
    relationship_checks = []
    for relationship in gt["relationships"]:
        source = known_entities[relationship["source_entity_id"]]["attributes"]
        target = known_entities[relationship["target_entity_id"]]["attributes"]
        linked = [n for n in (275, 398) if anchors[n]["original_fields"]["ProcessGuid"] == target["process_guid"]
                  and anchors[n]["original_fields"]["ParentProcessGuid"] == source["process_guid"]]
        relationship_checks.append({"relationship_id": relationship["relationship_id"],
                                    "matching_sysmon_refs": [f"jsonl:line:{n}" for n in linked]})
    facts_checks = [{"fact_id": fact["fact_id"], "consistent_relationship": any(
        relationship["relationship_id"] == fact["attributes"]["relationship_id"]
        and relationship["source_entity_id"] == fact["subject"]
        and relationship["target_entity_id"] == fact["object"]
        and relationship["source_references"] == fact["source_references"]
        and relationship["evidence_ids"] == fact["evidence_ids"]
        for relationship in gt["relationships"])} for fact in gt["facts"]]
    provenance = [{"path": item["path"], "expected_sha256": item["sha256"],
                   "actual_sha256": digest(ROOT / item["path"])} for item in gt["input_provenance"]]
    after = digest(raw_path)
    result = {
        "schema_version": "mshta-ground-truth-raw-audit/v1", "analysis_status": "reviewable_audit",
        "source_file": raw_path.relative_to(ROOT).as_posix(), "encoding": "UTF-8 (strict decoded)",
        "format": "jsonl", "complete_scan_records": total, "baseline_records": 1127,
        "raw_sha256_before": before, "raw_sha256_after": after, "baseline_sha256": EXPECTED_HASH,
        "raw_unchanged": before == after, "baseline_sha256_matches": before == EXPECTED_HASH,
        "canonical_sha256_matches_manifest": digest(canonical_path) == entry["canonical_events_sha256"],
        "event_id_counts": dict(sorted(counts.items(), key=lambda item: int(item[0]))),
        "provider_counts": dict(sorted(provider_counts.items())),
        "canonical_timecreated_range": {"start": min_timestamp, "end": max_timestamp},
        "raw_canonical_invariant_errors": invariant_errors,
        "anchor_source_to_canonical_errors": anchor_mapping_errors,
        "intermediate_observation_errors": observation_errors, "ground_truth_observation_errors": gt_observation_errors,
        "input_provenance_checks": provenance, "entity_checks": entity_checks,
        "relationship_checks": relationship_checks, "fact_checks": facts_checks,
        "dedup_pairs": pairs, "original_anchors": [anchors[n] for n in sorted(anchors)],
        "command_line_records": command_records, "script_content_fields_records": script_fields,
        "network_records": network_records, "file_deletion_records": deletion_records,
        "eventlog_clear_records": log_clear_records,
        "findings": [
            {"id": "payload_execution_overstatement", "severity": "wording_correction",
             "claim": "PowerShell ran Get-Service sysmon.",
             "supported_statement": "PowerShell was launched with -noexit -command Get-Service sysmon.",
             "source_references": ["jsonl:line:30", "jsonl:line:398"],
             "reason": "Only process creation command-line telemetry is present. No PowerShell script/action/output events or command result prove completion."},
            {"id": "scope_is_two_behavior_groups", "severity": "scope_limit",
             "reason": "The three ground-truth entities describe cmd, mshta and powershell in two evidence groups; they are not the full process inventory. A conhost child is observed at lines36/422 outside this reviewed slice."},
            {"id": "timestamp_source_conflict", "severity": "review_limit",
             "reason": "Ground truth correctly preserves canonical TimeCreated timestamps; Sysmon UtcTime strings are about four hours later and timezone-naive. True UTC/timezone provenance is unresolved."},
            {"id": "commandline_not_embedded_in_core", "severity": "artifact_limit",
             "reason": "Ground Truth Core declares command_line queryability but contains no literal command lines; they are available through linked intermediate evidence and raw references. Intermediate raw_fields are empty."},
            {"id": "negative_claim_limits", "severity": "evidence_limit",
             "reason": "No Sysmon3/22 or PowerShell scriptblock telemetry is present. The Security5156 network event belongs to WindowsAzureGuestAgent, not the reviewed chain. No download/C2/destructive-payload conclusion is supported for the reviewed command; absence of such behavior cannot be proven universally."},
            {"id": "background_deletion_and_log_clear", "severity": "scope_limit",
             "reason": "Full raw data contains Eventlog1102/104 clear events and Sysmon23 temporary file deletion by PowerShell. Do not infer destructive payload or map extra techniques from these without separate review; do not claim no deletion anywhere in the file."},
        ],
        "human_review_status": gt["review"]["review_status"], "confirmed_labels_assigned": False,
    }
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    readback = read(OUTPUT)
    if readback != result:
        raise ValueError("Audit JSON readback mismatch")
    print(json.dumps({"output": OUTPUT.relative_to(ROOT).as_posix(), "records": total,
                      "raw_unchanged": before == after, "baseline_sha256_matches": before == EXPECTED_HASH,
                      "invariant_errors": len(invariant_errors), "observation_errors": len(observation_errors) + len(gt_observation_errors),
                      "facts_consistent": all(item["consistent_relationship"] for item in facts_checks)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
