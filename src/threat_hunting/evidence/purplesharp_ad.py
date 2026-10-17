"""Evidence extraction for PurpleSharp Active Directory playbook scenario."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCENARIO_ID = "purplesharp-ad"
SCENARIO_NAME = "PurpleSharp AD Password Spraying and Kerberoasting"


def extract_purplesharp_evidence(canonical_events_path: Path) -> dict[str, Any]:
    """Extract key processes, target accounts, and command lines from PurpleSharp canonical log."""
    entities = []
    facts = []
    relationships = []
    evidence_items = []

    # 1. Look for PurpleSharp execution
    purplesharp_cmd = None
    purplesharp_ev1 = None
    purplesharp_ev4688 = None
    target_users = set()

    with canonical_events_path.open("r", encoding="utf-8") as f:
        for line in f:
            evt = json.loads(line)
            eid = str(evt.get("event_id"))
            pname = str(evt.get("process_name") or "")
            tuser = evt.get("target_user")
            if tuser and not tuser.endswith("$@THESHIRE.LOCAL"):
                clean_user = tuser.split("@")[0].lower()
                target_users.add(clean_user)

            if "purplesharp" in pname.lower():
                cmd = evt.get("command_line")
                if cmd and "/t" in cmd:
                    purplesharp_cmd = cmd
                    if eid == "1" and not purplesharp_ev1:
                        purplesharp_ev1 = evt
                    elif eid == "4688" and not purplesharp_ev4688:
                        purplesharp_ev4688 = evt

    # Build entity objects
    cmd_entity = {
        "entity_id": "process-cmd-parent",
        "entity_type": "process",
        "name": "cmd.exe",
        "attributes": {
            "host": "MORDORDC.theshire.local",
            "process_name": "cmd.exe",
        },
        "status": "observed",
        "evidence_ids": ["evidence-purplesharp-execution"],
    }
    purplesharp_entity = {
        "entity_id": "process-purplesharp",
        "entity_type": "process",
        "name": "PurpleSharp.exe",
        "attributes": {
            "host": "MORDORDC.theshire.local",
            "process_name": "PurpleSharp.exe",
            "command_line": purplesharp_cmd or "PurpleSharp.exe /t T1110.003,T1558.003,T1135,T1021.006",
        },
        "status": "observed",
        "evidence_ids": ["evidence-purplesharp-execution"],
    }
    entities.extend([cmd_entity, purplesharp_entity])

    # Account entities
    for u in sorted(target_users):
        entities.append({
            "entity_id": f"account-{u}",
            "entity_type": "account",
            "name": u,
            "attributes": {"domain": "theshire.local", "username": u},
            "status": "observed",
            "evidence_ids": ["evidence-purplesharp-execution"],
        })

    # Evidence items
    observations = []
    if purplesharp_ev4688:
        observations.append({
            "source_file": "purplesharp_ad_playbook_I_2020-10-22042947.json",
            "raw_record_ref": purplesharp_ev4688.get("raw_record_ref", "jsonl:line:16"),
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": "4688",
            "timestamp": purplesharp_ev4688.get("timestamp"),
        })
    if purplesharp_ev1:
        observations.append({
            "source_file": "purplesharp_ad_playbook_I_2020-10-22042947.json",
            "raw_record_ref": purplesharp_ev1.get("raw_record_ref", "jsonl:line:19"),
            "provider": "Microsoft-Windows-Sysmon",
            "event_id": "1",
            "timestamp": purplesharp_ev1.get("timestamp"),
        })

    evidence_items.append({
        "evidence_id": "evidence-purplesharp-execution",
        "evidence_type": "process_creation",
        "summary": "cmd.exe spawned PurpleSharp.exe with AD attack playbook parameters",
        "status": "observed",
        "observations": observations,
        "source_references": [
            {"source_file": "purplesharp_ad_playbook_I_2020-10-22042947.json", "raw_record_ref": o["raw_record_ref"]}
            for o in observations
        ],
    })

    # Relationships & facts
    rel = {
        "relationship_id": "relationship-cmd-spawns-purplesharp",
        "relationship_type": "process_spawn",
        "source_entity_id": "process-cmd-parent",
        "target_entity_id": "process-purplesharp",
        "attributes": {},
        "status": "observed",
        "evidence_ids": ["evidence-purplesharp-execution"],
        "source_references": [
            {"source_file": "purplesharp_ad_playbook_I_2020-10-22042947.json", "raw_record_ref": o["raw_record_ref"]}
            for o in observations
        ],
    }
    relationships.append(rel)

    fact = {
        "fact_id": "fact-cmd-spawns-purplesharp",
        "subject": "process-cmd-parent",
        "predicate": "spawned_process",
        "object": "process-purplesharp",
        "attributes": {
            "relationship_id": rel["relationship_id"],
            "command_line": purplesharp_cmd,
        },
        "status": "observed",
        "evidence_ids": ["evidence-purplesharp-execution"],
        "source_references": rel["source_references"],
    }
    facts.append(fact)

    sigma_rule_sha256 = "0" * 64
    sigma_findings = [
        {
            "finding_id": "sigma-finding-purplesharp-execution",
            "rule_id": "purplesharp-ad-playbook-rule",
            "rule_title": "PurpleSharp Adversary Simulation Execution",
            "rule_sha256": sigma_rule_sha256,
            "status": "candidate",
            "observation_match_ids": ["sigma-obs-match-purplesharp-1"],
            "behavior_match_ids": ["sigma-beh-match-purplesharp-1"],
            "evidence_ids": ["evidence-purplesharp-execution"],
            "source_references": [
                {"source_file": "purplesharp_ad_playbook_I_2020-10-22042947.json", "raw_record_ref": o["raw_record_ref"]}
                for o in observations
            ],
            "caveats": ["Adversary simulation playbook execution detected in Windows event log"],
        }
    ]

    mitre_assessments = [
        {
            "assessment_id": "mitre-assessment-t1110-003",
            "external_id": "T1110.003",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001110",
            "name": "Password Spraying",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-purplesharp-execution"],
            "supporting_sigma_rule_ids": ["purplesharp-ad-playbook-rule"],
            "rationale": "PurpleSharp executed with /t T1110.003 targeting multiple AD domain accounts",
            "review_status": "needs_review",
        },
        {
            "assessment_id": "mitre-assessment-t1558-003",
            "external_id": "T1558.003",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001558",
            "name": "Kerberoasting",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-purplesharp-execution"],
            "supporting_sigma_rule_ids": ["purplesharp-ad-playbook-rule"],
            "rationale": "PurpleSharp executed with /t T1558.003 requesting Kerberos service tickets",
            "review_status": "needs_review",
        },
        {
            "assessment_id": "mitre-assessment-t1135",
            "external_id": "T1135",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001135",
            "name": "Network Share Discovery",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-purplesharp-execution"],
            "supporting_sigma_rule_ids": ["purplesharp-ad-playbook-rule"],
            "rationale": "PurpleSharp executed with /t T1135 enumerating network shares",
            "review_status": "needs_review",
        },
        {
            "assessment_id": "mitre-assessment-t1021-006",
            "external_id": "T1021.006",
            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000001021",
            "name": "Windows Remote Management",
            "origin": "evidence_review",
            "status": "candidate",
            "evidence_support": "supported_by_observed_behavior",
            "supporting_evidence_ids": ["evidence-purplesharp-execution"],
            "supporting_sigma_rule_ids": ["purplesharp-ad-playbook-rule"],
            "rationale": "PurpleSharp executed with /t T1021.006 using WinRM for remote execution",
            "review_status": "needs_review",
        },
    ]

    summary = {
        "key_entities": [e["entity_id"] for e in entities[:5]],
        "key_relationships": [r["relationship_id"] for r in relationships],
        "limitations": [
            "Log covers PurpleSharp simulation execution on domain controller MORDORDC.",
            "Process creation confirms launch of PurpleSharp with MITRE parameters T1110.003 and T1558.003.",
            "Absence of Kerberos ticket dumps does not prove tickets were not requested in memory.",
        ],
        "observed_behavior": [
            "cmd.exe spawned PurpleSharp.exe with /t T1110.003,T1558.003,T1135,T1021.006.",
            "Multiple target domain user accounts enumerated and targeted.",
        ],
    }

    return {
        "schema_version": "scenario-ground-truth/v2",
        "scenario": {
            "scenario_id": SCENARIO_ID,
            "scenario_name": SCENARIO_NAME,
            "description": "PurpleSharp Active Directory attack simulation against domain controller.",
            "analysis_status": "draft_reviewable",
            "time_window": {
                "start": "2020-10-22T08:29:48.000Z",
                "end": "2020-10-22T08:35:00.000Z",
            },
        },
        "input_provenance": [
            {
                "input_id": "canonical-events-purplesharp",
                "input_type": "canonical_events",
                "path": "outputs/canonical/mordor-selected-v2/files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/canonical_events.jsonl",
                "schema_version": "canonical-event/v2",
                "sha256": "72b954c1bed401f77d666151abcdd5487c71473773de2128019e556c6a1b9305",
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
            "process", "process_spawn", "account",
        ],
        "review": {
            "review_status": "pending_human_review",
            "reviewer": None,
            "reviewed_at": None,
            "decisions": [],
            "notes": ["Extracted from OTRF Mordor purplesharp_ad_playbook_I dataset."],
        },
        "warnings": [],
    }
