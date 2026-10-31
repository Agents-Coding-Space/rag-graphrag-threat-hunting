"""Shared provenance for the limited PurpleSharp and Regsvr32 review slices."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
CANONICAL_FIELDS = (
    "host", "process_name", "process_id", "process_guid", "parent_process_name",
    "parent_process_id", "parent_process_guid", "command_line", "parent_command_line",
    "source_ip", "source_port", "destination_ip", "destination_port", "user",
    "subject_user", "target_user", "timestamp", "event_id", "provider", "channel",
)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def source_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def same_process(left: dict[str, Any], right: dict[str, Any] | None, *, max_seconds: float = 1.0) -> bool:
    if right is None or not left.get("host") or str(left["host"]).casefold() != str(right.get("host")).casefold():
        return False
    if left.get("process_guid") and right.get("process_guid"):
        return str(left["process_guid"]).casefold() == str(right["process_guid"]).casefold()
    def pid(value: object) -> object:
        try:
            text = str(value)
            return int(text, 16 if text.lower().startswith("0x") else 10)
        except ValueError:
            return value
    if left.get("process_id") is None or pid(left.get("process_id")) != pid(right.get("process_id")):
        return False
    try:
        difference = abs((datetime.fromisoformat(left["timestamp"].replace("Z", "+00:00"))
                          - datetime.fromisoformat(right["timestamp"].replace("Z", "+00:00"))).total_seconds())
    except (KeyError, TypeError, ValueError):
        return False
    return difference <= max_seconds


def source_observations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"source_file": event["source_file"], "raw_record_ref": event["raw_record_ref"],
             "field_origin": "canonical-event/v2",
             "canonical_fields": {key: event.get(key) for key in CANONICAL_FIELDS}}
            for event in events]


def unresolved_assessments(items: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    """Preserve hypothesis IDs without fabricating STIX resolution or rule support."""
    return [{
        "assessment_id": "mitre-assessment-" + technique_id.lower().replace(".", "-"),
        "external_id": technique_id, "stix_id": None,
        "name": technique_id + " (ATT&CK object unresolved)",
        "origin": "evidence_review", "status": "candidate", "evidence_support": "not_assessed",
        "supporting_evidence_ids": [evidence_id], "supporting_sigma_rule_ids": [],
        "rationale": reason + " ATT&CK source unavailable/unverified; no resolved STIX mapping or successful technique execution is asserted.",
        "review_status": "needs_review",
    } for technique_id, evidence_id, reason in items]


def finish_document(document: dict[str, Any], path: Path, events: list[dict[str, Any]], *, count: int) -> dict[str, Any]:
    """Record canonical provenance and the limits of missing raw/knowledge inputs."""
    from threat_hunting.ground_truth.schema import validate_ground_truth_document

    document["schema_version"] = "scenario-ground-truth/v3"
    document["input_provenance"][0]["path"] = source_path(path)
    document["input_provenance"][0]["sha256"] = digest(path)
    timestamps = sorted(event["timestamp"] for event in events if event.get("timestamp"))
    document["scenario"]["time_window"] = {"start": timestamps[0] if timestamps else None, "end": timestamps[-1] if timestamps else None}
    limits = [
        "Only the selected launch/network slice is reviewed; full-file absence claims are unsupported.",
        "Process creation proves launch arguments, not successful technique completion, cracking, output or service state.",
        "Raw source is unavailable/unverified in this checkout; canonical observations were hash-pinned, not substituted for a fresh raw audit.",
        "Source timestamp conflicts remain unresolved; canonical timestamps are preserved without timezone correction.",
        "Selected Sigma sources are unavailable/unverified; no rule evaluation or Sigma match is asserted.",
        "enterprise-attack.json is unavailable/unverified; STIX IDs are null and assessments remain candidate/not_assessed.",
    ]
    document["summary"]["limitations"].extend(limits)
    document["review"]["notes"].extend([
        f"Read all {count} canonical records; retained {len(events)} observations; {count-len(events)} records deliberately outside this slice. Canonical input was not modified.",
        "Technical correction only; human review remains pending and no security labels were promoted.",
    ])
    document["warnings"] = ["raw_source_unavailable_or_unverified", "selected_sigma_sources_unavailable_or_unverified", "attack_stix_source_unavailable_or_unverified"]
    validate_ground_truth_document(document)
    return document


def extract_slice(path: Path, *, scenario_id: str) -> dict[str, Any]:
    """Stream every canonical record and retain only the existing launch/network core."""
    path = Path(path)
    purple = scenario_id == "purplesharp-ad"
    binary = "purplesharp.exe" if purple else "regsvr32.exe"
    before_hash = digest(path)
    processes, networks = [], []
    count = 0
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Cannot parse {path.name}, canonical line {line_number}") from exc
            count += 1
            if not isinstance(event, dict):
                raise ValueError(f"Invalid canonical object in {path.name}, line {line_number}")
            name = str(event.get("process_name") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            if name != binary:
                continue
            if str(event.get("event_id")) in ("1", "4688"):
                processes.append(event)
            elif str(event.get("event_id")) == "3":
                networks.append(event)
    if digest(path) != before_hash:
        raise ValueError(f"Input changed while reading {path.name}")
    launches = [event for event in processes if str(event["event_id"]) == "1"]
    if not launches:
        raise ValueError(f"Missing Sysmon process-creation evidence for {binary} in {path.name}")
    launch = launches[0]
    command = launch.get("command_line")
    selected = [event for event in processes if str(event["event_id"]) == "4688"
                and same_process(event, launch) and event.get("command_line") == command][:1] + [launch]
    network = next((event for event in networks if same_process(event, launch, max_seconds=60.0)), None)
    if not purple and (network is None or network.get("destination_ip") is None or network.get("destination_port") is None):
        raise ValueError(f"Missing correlated regsvr32 destination evidence in {path.name}")
    for event in selected + ([network] if not purple else []):
        if not event.get("source_file") or not event.get("raw_record_ref"):
            raise ValueError(f"Missing source_file/raw_record_ref in {path.name}")
    host = launch.get("host")
    parent = str(launch.get("parent_process_name") or "").replace("\\", "/").rsplit("/", 1)[-1]
    if not parent:
        raise ValueError(f"Missing parent process in {path.name} at {launch['raw_record_ref']}")
    child = str(launch["process_name"]).replace("\\", "/").rsplit("/", 1)[-1]
    parent_id = "process-cmd-parent" if purple else "process-powershell-parent"
    child_id = "process-purplesharp" if purple else "process-regsvr32"
    evidence_id = "evidence-purplesharp-execution" if purple else "evidence-regsvr32-process-creation"
    fact_id = "fact-cmd-spawns-purplesharp" if purple else "fact-powershell-spawns-regsvr32"
    relationship_id = "relationship-cmd-spawns-purplesharp" if purple else "relationship-powershell-spawns-regsvr32"

    def refs(events: list[dict[str, Any]]) -> list[dict[str, str]]:
        return [{key: event[key] for key in ("source_file", "raw_record_ref")} for event in events]

    def evidence(identifier: str, kind: str, summary: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {"evidence_id": identifier, "evidence_type": kind, "summary": summary, "status": "observed",
                "observations": [{key: event.get(key) for key in ("source_file", "raw_record_ref", "provider", "event_id", "timestamp")} for event in events],
                "source_references": refs(events)}

    entities = [
        {"entity_id": parent_id, "entity_type": "process", "name": parent, "attributes": {"host": host, "process_name": parent}, "status": "observed", "evidence_ids": [evidence_id]},
        {"entity_id": child_id, "entity_type": "process", "name": child, "attributes": {"host": host, "process_name": child, "command_line": command, "source_observations": source_observations(selected)}, "status": "observed", "evidence_ids": [evidence_id]},
    ]
    facts = [{"fact_id": fact_id, "subject": parent_id, "predicate": "spawned_process", "object": child_id,
              "attributes": {"relationship_id": relationship_id, "command_line": command, "source_observations": source_observations(selected)},
              "status": "observed", "evidence_ids": [evidence_id], "source_references": refs(selected)}]
    relationships = [{"relationship_id": relationship_id, "relationship_type": "process_spawn", "source_entity_id": parent_id, "target_entity_id": child_id,
                      "attributes": {}, "status": "observed", "evidence_ids": [evidence_id], "source_references": refs(selected)}]
    evidences = [evidence(evidence_id, "process_creation", f"{parent} spawned {child}; launch arguments do not prove payload completion.", selected)]
    observed = [f"{parent} spawned {child} with command line {command!r} on {host}."]
    limits = []
    if purple:
        assessments = unresolved_assessments([
            (tech, evidence_id, f"Literal {tech} is a launch parameter, not proof of observed technique execution.")
            for tech in sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", command or "")))])
        limits.append("Authentication and Kerberos groups are outside this launch slice; accounts are not attributed to launch evidence.")
    else:
        net_id = "evidence-regsvr32-c2-network"
        ip, port = network["destination_ip"], network["destination_port"]
        entities[1]["evidence_ids"].append(net_id)
        entities.append({"entity_id": "endpoint-c2-server", "entity_type": "network_endpoint", "name": f"{ip}:{port}",
                         "attributes": {"ip": ip, "port": port, "role": "observed_destination", "source_observations": source_observations([network])}, "status": "observed", "evidence_ids": [net_id]})
        evidences.append(evidence(net_id, "network_connection", f"regsvr32.exe connected to {ip}:{port}; transferred content, completed HTTP exchange and C2 purpose remain unverified.", [network]))
        facts.append({"fact_id": "fact-regsvr32-network-connection", "subject": child_id, "predicate": "connected_to", "object": "endpoint-c2-server",
                      "attributes": {"source_observations": source_observations([network])}, "status": "observed", "evidence_ids": [net_id], "source_references": refs([network])})
        selected = selected + [network]
        observed.append(f"The correlated {child} process connected to observed endpoint {ip}:{port}.")
        limits.append("The /i HTTP URL is a launch target. A connection does not prove response contents, download/scriptlet completion, exfiltration or bytes transferred.")
        assessments = unresolved_assessments([
            ("T1218.010", evidence_id, "Regsvr32 launch with remote scriptlet arguments is an existing mapping hypothesis."),
            ("T1071.001", net_id, "An observed endpoint and HTTP launch target do not establish C2 protocol semantics."),
            ("T1059.001", evidence_id, "A PowerShell parent is observed; script contents/results are not established by this slice."),
        ])
    document = {
        "schema_version": "scenario-ground-truth/v3",
        "scenario": {"scenario_id": scenario_id, "scenario_name": "PurpleSharp launch review slice" if purple else "Regsvr32 process and network review slice",
                     "description": "Correction of the existing canonical slice; knowledge provenance remains unavailable/unverified.", "analysis_status": "draft_reviewable", "time_window": {"start": None, "end": None}},
        "input_provenance": [{"input_id": "canonical-events-" + scenario_id, "input_type": "canonical_events", "path": source_path(path), "schema_version": "canonical-event/v2", "sha256": before_hash, "scenario_id": scenario_id}],
        "entities": entities, "facts": facts, "relationships": relationships, "evidence": evidences, "sigma_findings": [], "mitre_assessments": assessments,
        "summary": {"observed_behavior": observed, "key_entities": [entity["entity_id"] for entity in entities], "key_relationships": [relationship_id], "limitations": limits},
        "queryable_dimensions": ["command_line", "entity", "evidence", "process", "process_spawn", "provenance"],
        "review": {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None, "decisions": [], "notes": []}, "warnings": [],
    }
    return finish_document(document, path, selected, count=count)
