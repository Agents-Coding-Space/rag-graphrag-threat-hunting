"""Adapters into the existing Ground Truth Core, with CTI explicitly separate."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .authentication import stable_id
from .process_network import basename, refs
from .slice_provenance import digest
from threat_hunting.ground_truth.schema import validate_ground_truth_document
from threat_hunting.retrieval.schema import validate_retrieval_corpus
from threat_hunting.graph.schema import validate_knowledge_graph


def reference(row: dict) -> dict:
    return {key: row[key] for key in ("source_file", "raw_record_ref")}


def source_observation(row: dict) -> dict:
    """Canonical first, original fields retained. No inferred authentication IP."""
    # One compact field projection; full raw/canonical records remain hash-pinned
    # in the upstream survey. Avoid copying encoded commands twice per object.
    keep = {"EventID","SourceName","Hostname","@timestamp","TimeCreated","EventTime","UtcTime","Status","SubStatus","TargetUserName","TargetDomainName",
            "WorkstationName","Workstation","LogonType","ServiceName","TicketOptions","TicketEncryptionType","OriginalFileName"}
    return {"source_file": row["source_file"], "raw_record_ref": row["raw_record_ref"],
            "field_projection": "canonical non-null scalars plus unmapped authentication/source clock fields; originals remain upstream",
            "canonical_fields": {k:deepcopy(v) for k,v in row["canonical_fields"].items() if v is not None},
            "original_fields": {k:deepcopy(v) for k,v in row.get("original_fields", {}).items() if k in keep},
            "evidence_layer": "observed_telemetry"}


def core_document(sid: str, name: str, provenance: list[dict]) -> dict:
    return {"schema_version": "scenario-ground-truth/v3", "scenario": {"scenario_id": sid, "scenario_name": name,
            "description": "Integrated research draft: observed telemetry, inferred correlations, candidate assessments and separate CTI context.",
            "analysis_status": "draft_reviewable", "time_window": {"start": None, "end": None}},
            "input_provenance": provenance, "entities": [], "facts": [], "relationships": [], "evidence": [],
            "sigma_findings": [], "mitre_assessments": [],
            "summary": {"observed_behavior": [], "key_entities": [], "key_relationships": [], "limitations": []},
            "queryable_dimensions": ["entity", "evidence", "fact", "relationship", "provenance", "limitation", "sigma_rule", "mitre_technique", "cti_context", "authentication", "network", "process"],
            "review": {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None, "decisions": [],
                       "notes": ["Research drafts are runnable without human approval. Approval is separate from evidence status."]}, "warnings": []}


def evidence(doc: dict, eid: str, kind: str, text: str, rows: list[dict]) -> None:
    doc["evidence"].append({"evidence_id": eid, "evidence_type": kind, "summary": text, "status": "observed",
        "observations": [{**reference(r), **{key: r["canonical_fields"].get(key) for key in ("provider", "event_id", "timestamp")}} for r in rows],
        "source_references": refs(rows)})


def entity(doc: dict, eid: str, kind: str, name: str, attributes: dict, evidence_ids: list[str], status: str = "observed") -> None:
    if any(e["entity_id"] == eid for e in doc["entities"]):
        return
    doc["entities"].append({"entity_id": eid, "entity_type": kind, "name": name, "attributes": attributes,
                            "status": status, "evidence_ids": evidence_ids})


def fact(doc: dict, fid: str, subject: str, predicate: str, target: Any, rows: list[dict], eids: list[str], *,
         status: str = "observed", attributes: dict | None = None) -> None:
    doc["facts"].append({"fact_id": fid, "subject": subject, "predicate": predicate, "object": target,
                         "attributes": {"source_observations": [source_observation(r) for r in rows], **(attributes or {})},
                         "status": status, "evidence_ids": eids, "source_references": refs(rows)})


def relationship(doc: dict, rid: str, source: str, target: str, kind: str, rows: list[dict], eids: list[str], *, status="inferred", attributes=None) -> None:
    doc["relationships"].append({"relationship_id": rid, "relationship_type": kind, "source_entity_id": source,
        "target_entity_id": target, "status": status, "attributes": attributes or {}, "source_references": refs(rows), "evidence_ids": eids})


def assessment(doc: dict, technique: dict, evidence_ids: list[str], sigma_ids: list[str], rationale: str, support: str = "supported_by_observed_behavior") -> None:
    doc["mitre_assessments"].append({"assessment_id": "assessment-" + technique["external_id"].replace(".", "-"),
        **{k: technique[k] for k in ("external_id", "stix_id", "name")}, "origin": "evidence_review", "status": "candidate",
        "evidence_support": support, "supporting_evidence_ids": evidence_ids, "supporting_sigma_rule_ids": sigma_ids,
        "rationale": rationale, "review_status": "needs_review"})


def authentication_adapter(survey: dict, correlation: dict, spraying: dict, logons: dict, rc4: dict, draft: dict,
                           techniques: list[dict], provenance: list[dict]) -> dict:
    """Consume only the final purplesharp_v2 evidence; no launch-slice answers."""
    doc = core_document("purplesharp-ad", "3.3.1 Kịch bản brute force và đăng nhập bất thường", provenance)
    doc["scenario"]["time_window"] = survey["time_window"]
    rows = [{**o, "canonical_fields": o["canonical_fields"]} for o in survey["observations"]]
    scope_id = "authentication-capture-scope"
    entity(doc, scope_id, "event_group", "Authentication capture scope", {"scope": "Selected authentication observations; membership is not causal attribution."}, [], "inferred")
    failures = [r for r in rows if r["event_id"] in {"4625", "4776"}]
    successes = [r for r in rows if r["event_id"] == "4624"]
    tickets = [r for r in rows if r["event_id"] == "4769"]
    for eid, kind, text, observations in (
        ("auth-failure-observations", "authentication_failure", "PurpleSharp authentication failures: 4625 endpoint and 4776 DC views, not additional attempts.", failures),
        ("auth-success-observations", "authentication_success", "Observed successful network logons; success after a failure does not establish password recovery or compromise.", successes),
        ("auth-ticket-observations", "kerberos_ticket_request", "Service ticket requests; RC4 detection hypothesis does not prove cracking success.", tickets)):
        evidence(doc, eid, kind, text, observations)
    for attempt in correlation["attempts"]:
        target_id = "account-" + attempt["target_account"].casefold()
        group = [r for r in failures if r["observation_id"] in attempt["observation_ids"]]
        host = attempt["source_context"]["value"]
        host_id = stable_id("host", [host])
        entity(doc, host_id, "host", host, {"host": host, "source_context": attempt["source_context"]}, ["auth-failure-observations"])
        entity(doc, target_id, "account", attempt["target_account"], {"target_user": attempt["target_account"], "domain": attempt["target_domain"]}, ["auth-failure-observations"])
        fact(doc, attempt["attempt_id"], host_id, "failed_authentication_attempt", target_id, group, ["auth-failure-observations"],
             status=attempt["status"], attributes={"authentication_attempt": attempt})
        relationship(doc, "relation-" + attempt["attempt_id"], host_id, target_id, "attempted_authentication", group,
                     ["auth-failure-observations"], status=attempt["status"], attributes={"correlation_basis": attempt["correlation_basis"]})
    fact(doc, "auth-failure-survey", scope_id, "authentication_failure_survey", "source-account-outcome-fields", failures,
         ["auth-failure-observations"], attributes={"authentication_profiles": {k: survey["authentication_profiles"][k] for k in ("4625", "4776")}})
    fact(doc, "auth-correlation-summary", scope_id, "authentication_correlation", "deduplicated_attempts", failures,
         ["auth-failure-observations"], status="inferred", attributes={"authentication_correlation": {k: correlation[k] for k in ("tolerance_seconds", "failure_observations", "paired_attempts", "countable_attempts", "ambiguous_observations")},
                                                                     "spraying_candidates": spraying["findings"]})
    fact(doc, "auth-logon-context", scope_id, "logon_investigation", "same-name temporal candidates only", successes,
         ["auth-success-observations"], attributes={"logon_investigation": {k:v for k,v in logons.items() if k != "privileged_logon_context_links"}})
    fact(doc, "auth-ticket-context", scope_id, "ticket_request", "services", tickets,
         ["auth-ticket-observations"], attributes={"authentication_profiles": {"4769": survey["authentication_profiles"]["4769"]}})
    rule_id = rc4["metadata"]["id"]
    doc["sigma_findings"].append({"finding_id": "sigma-rc4", "rule_id": rule_id, "rule_title": rc4["metadata"]["title"], "rule_sha256": rc4["rule_sha256"],
        "status": "candidate", "observation_match_ids": [m["observation_id"] for m in rc4["matches"]], "behavior_match_ids": [],
        "evidence_ids": ["auth-ticket-observations"], "source_references": [reference(next(r for r in rows if r["observation_id"] == m["observation_id"])) for m in rc4["matches"]],
        "caveats": ["RC4 is a detection hypothesis; no password cracking or account compromise is established."]})
    derived = draft["sigma_rules"][1]
    if spraying["findings"]:
        doc["sigma_findings"].append({"finding_id": "sigma-spray-project", "rule_id": "8146a24e-c271-4d34-a679-6a361f71ccab",
            "rule_title": "Project suspected password spraying", "rule_sha256": derived["sha256"], "status": "candidate",
            "observation_match_ids": [r["observation_id"] for r in failures], "behavior_match_ids": [f["finding_id"] for f in spraying["findings"]],
            "evidence_ids": ["auth-failure-observations"], "source_references": refs(failures), "caveats": ["Project-derived correlation after view deduplication, not external SigmaHQ. Password sameness is unobserved."]})
    for tid, eids, rules, reason in (("T1110.003", ["auth-failure-observations"], ["8146a24e-c271-4d34-a679-6a361f71ccab"], "Observed concentrated failures across distinct accounts support suspected spraying; does not prove same password or compromise."),
                                   ("T1558.003", ["auth-ticket-observations"], [rule_id], "RC4 service tickets and rule matches support a Kerberoasting hypothesis, not successful cracking.")):
        assessment(doc, next(t for t in techniques if t["external_id"] == tid), eids, rules, reason)
    doc["summary"]["observed_behavior"] = [draft["expected_summary"], "Observed 49 successful logons; same-name associations and privileges are context only."]
    doc["summary"]["limitations"] = [*draft["review_notes"][1:], "Same-name success after failure does not prove recovered password, successful spraying or account compromise. No historical baseline establishes abnormal successful logon.",
                                     "No cracking success/password recovery is established. CTI campaign activity does not attribute an actor to this dataset."]
    return doc


def regsvr32_adapter(correlation: dict, sigma: list[dict], techniques: list[dict], provenance: list[dict]) -> dict:
    doc = core_document("regsvr32-c2", "3.3.3 Kịch bản kết nối mạng bất thường hoặc nghi vấn C2", provenance)
    selected = [g for g in correlation["processes"] if g["process_key"] in correlation["selected_process_keys"]]
    evidence_by_ref = {}
    timeline = []
    for group in selected:
        f, key, observations = group["creation"], group["process_key"], group["observations"]
        eid = "creation-" + key
        evidence(doc, eid, "process_creation", f"{basename(f['parent_process_name'])} created {basename(f['process_name'])}; Security/Sysmon observations describe one creation.", observations)
        for row in observations: evidence_by_ref[row["raw_record_ref"]] = eid
        entity(doc, key, "process", basename(f["process_name"]), {"host": f["host"], "process_name": f["process_name"], "process_id": f["process_id"], "process_guid": f["process_guid"]}, [eid])
        parents = [link for link in correlation["parent_child_links"] if link["target_process_key"] == key]
        parent = parents[0]["source_process_key"] if len(parents) == 1 else stable_id("external-parent", [f["host"], str(f.get("parent_process_guid")), str(f.get("parent_process_id")), str(f.get("parent_process_name"))])
        if not any(e["entity_id"] == parent for e in doc["entities"]):
            entity(doc, parent, "process", basename(f["parent_process_name"]), {"host": f["host"], "process_name": f["parent_process_name"],
                "process_id": f.get("parent_process_id"), "process_guid": f.get("parent_process_guid"), "creation_in_capture": False, "basis": "parent fields in child observation only"}, [eid])
        relationship(doc, "spawn-"+key, parent, key, "process_spawn", observations, [eid], status="observed",
                     attributes={"parent_link_basis": parents[0]["basis"] if parents else "reported_parent_in_child_creation"})
        fact(doc, "created-"+key, parent, "spawned_process", key, observations, [eid], attributes={"relationship_id": "spawn-"+key})
        timeline.append({"kind": "process_creation", "timestamp": f["timestamp"], "process_key": key, "source_references": refs(observations)})
    by_process = {}
    for connection in correlation["connections"]:
        by_process.setdefault(connection["process_key"], []).append(connection["observation"])
    for key, observations in by_process.items():
        eid = "connections-"+key
        evidence(doc, eid, "network_connection", "Observed process-bound Sysmon connections; not HTTP completion, transferred content, confirmed C2 or exfiltration bytes.", observations)
        for row in observations: evidence_by_ref[row["raw_record_ref"]] = eid
        first = observations[0]["canonical_fields"]
        endpoint = stable_id("endpoint", [str(first["destination_ip"]), str(first["destination_port"])])
        entity(doc, endpoint, "network_endpoint", f"{first['destination_ip']}:{first['destination_port']}", {"ip": first["destination_ip"], "port": first["destination_port"], "role": "observed_destination"}, [eid])
        summary = {"process_key": key, "process_name": first["process_name"], "observation_count": len(observations),
                   "destinations": [{"ip": ip, "port": port, "observations": count} for (ip,port),count in Counter((r["canonical_fields"]["destination_ip"], r["canonical_fields"]["destination_port"]) for r in observations).items()],
                   "start": min(r["canonical_fields"]["timestamp"] for r in observations), "end": max(r["canonical_fields"]["timestamp"] for r in observations),
                   "correlation_basis": "host_guid_lifetime", "assessment": "suspicious_network_context_not_confirmed_C2"}
        fact(doc, "network-"+key, key, "connected_to", endpoint, observations, [eid], attributes={"connection_summary": summary})
        relationship(doc, "connected-"+key, key, endpoint, "connected_to", observations, [eid], attributes={"evidence_layer": "inferred_correlation", "connection_summary": summary})
        for row in observations: timeline.append({"kind": "network_connection", "timestamp": row["canonical_fields"]["timestamp"], "process_key": key, "source_references": [reference(row)]})
    for result in sigma:
        matches = [m for m in result["matches"] if m["raw_record_ref"] in evidence_by_ref]
        if not matches: continue
        doc["sigma_findings"].append({"finding_id": "sigma-"+result["metadata"]["id"], "rule_id": result["metadata"]["id"],
            "rule_title": result["metadata"]["title"], "rule_sha256": result["rule_sha256"], "status": "candidate",
            "observation_match_ids": [m["raw_record_ref"] for m in matches], "behavior_match_ids": sorted({evidence_by_ref[m["raw_record_ref"]] for m in matches}),
            "evidence_ids": sorted({evidence_by_ref[m["raw_record_ref"]] for m in matches}), "source_references": [reference(m) for m in matches],
            "caveats": ["Raw-field tri-state subset; matches are detection hypotheses, not attack success. Unknown selections/exclusions remain indeterminate."]})
    assessment(doc, next(t for t in techniques if t["external_id"] == "T1218.010"), [e["evidence_id"] for e in doc["evidence"] if e["evidence_type"] == "process_creation"],
               [r["rule_id"] for r in doc["sigma_findings"]], "HTTP scriptlet regsvr32 command and parent/child evidence support suspected system binary proxy execution. Network endpoints do not prove C2 purpose.")
    root_key = next(g["process_key"] for g in selected if basename(g["creation"]["process_name"]) == "regsvr32.exe")
    fact(doc, "process-network-timeline", root_key, "process_network_correlation", "ordered_observations", [], [], status="inferred",
         attributes={"timeline": sorted(timeline, key=lambda t: t["timestamp"]), "correlation_policy": correlation["policy"],
                     "ambiguous_link_count": len(correlation["ambiguous_links"]), "background_connections_excluded": len(correlation["background_connections"]),
                     "unresolved_connections_not_forced": len(correlation["unresolved_connections"])})
    doc["summary"]["observed_behavior"] = ["PowerShell parent → regsvr32 HTTP /i scriptlet command with /n → encoded PowerShell child; observed regsvr32 port8444 and child PowerShell port80 connections."]
    doc["summary"]["limitations"] = ["Connections and command URL do not establish HTTP completion, response content, confirmed C2 purpose, exfiltration or bytes transferred.",
        "Network and process identity links are inferred from host/GUID/lifetime; PID fallback stops at next creation/exit and has a bounded age. Ambiguous links remain separate.",
        "Source timestamp conflicts are preserved. Canonical timestamps are not timezone-corrected. Security 5156 is inventoried separately, not counted again as Sysmon connection observations."]
    times = [t["timestamp"] for t in timeline]
    doc["scenario"]["time_window"] = {"start": min(times,default=None), "end": max(times,default=None)}
    return doc


def attach_cti(doc: dict, sources: list[dict], chunks: list[dict], corpus_path: str, corpus_sha256: str) -> None:
    """CTI is a candidate knowledge entity, never a telemetry evidence item."""
    topic_id = "knowledge-topic-"+doc["scenario"]["scenario_id"]
    entity(doc, topic_id, "behavior_concept", doc["scenario"]["scenario_name"], {"evidence_layer": "cti_context", "source_type": "project_behavior_concept"}, [], "candidate")
    for chunk in chunks:
        source = next(s for s in sources if s["source_id"] == chunk["source_id"])
        attrs = {"evidence_layer": "cti_context", "source_type": "cti_report", "source_id": source["source_id"], "text": chunk["text"],
                 "title": source["title"], "publisher": source["publisher"], "url": source["url"], "publication_date": source["publication_date"],
                 "accessed_at": source["accessed_at"], "snapshot_sha256": source["snapshot_sha256"], "citation": chunk["citation"],
                 "source_references": [{"source_file": source["source_id"], "raw_record_ref": f"text:chars:{chunk['citation']['char_start']}:{chunk['citation']['char_end']}"}],
                 "scope": chunk["scope"], "corpus_path": corpus_path, "corpus_sha256": corpus_sha256}
        entity(doc, chunk["chunk_id"], "cti_report", source["title"], attrs, [], "candidate")
        relationship(doc, "context-"+chunk["chunk_id"], chunk["chunk_id"], topic_id, "provides_technical_context_for", [], [], status="candidate", attributes=attrs)
    # A context edge to a scoped evidence group/process is not an evidence support
    # edge or an assertion that a publisher observed this host.
    target = next((e["entity_id"] for e in doc["entities"] if e["entity_type"] == "event_group"), None)
    if target is None:
        target = next((e["entity_id"] for e in doc["entities"] if e["entity_type"] == "process" and e["name"].casefold() in {"mshta.exe","regsvr32.exe"}), None)
    if target:
        relationship(doc, "context-topic-"+topic_id, topic_id, target, "technical_context_for", [], [], status="candidate",
                     attributes={"evidence_layer":"cti_context","semantics":"External technical context only; no local behavior support or compromise assertion."})
    doc["summary"]["limitations"].append("CTI facts are publisher-reported external context. They do not establish local host compromise, campaign attribution, HTTP completion or confirmed C2.")


def finish(doc: dict) -> dict:
    doc["summary"]["key_entities"] = [e["entity_id"] for e in doc["entities"] if e["entity_type"] not in {"cti_report", "behavior_concept"}]
    doc["summary"]["key_relationships"] = [r["relationship_id"] for r in doc["relationships"] if r["attributes"].get("evidence_layer") != "cti_context"]
    validate_ground_truth_document(doc)
    return doc


def enrich_consumers(doc: dict, corpus: dict, graph: dict) -> None:
    """Publish the same structured source objects in both retrieval and graph.

    This fixes the known field/assessment representation gap without injecting
    graph objects into RAG or weakening the validator. Legacy consumers unchanged.
    """
    objects = {}
    for collection, key in (("entities","entity_id"),("facts","fact_id"),("evidence","evidence_id"),("relationships","relationship_id"),("sigma_findings","finding_id"),("mitre_assessments","assessment_id")):
        for item in doc[collection]: objects[item[key]] = item
    for chunk in corpus["chunks"]:
        if chunk['chunk_type']=='scenario_summary':
            chunk['metadata']['scope_limitations']=deepcopy(doc['summary']['limitations'])
            chunk['metadata']['scope_limitations_pointer']='/summary/limitations'
        obj = objects.get(chunk["source"]["object_id"])
        if not obj: continue
        chunk["metadata"] = {"source_object": deepcopy(obj)}
        attrs = obj.get("attributes", {})
        chunk["metadata"]["evidence_layer"] = attrs.get("evidence_layer", "observed_telemetry" if obj.get("status") == "observed" else "inferred_correlation" if obj.get("status") == "inferred" else "candidate_assessment")
        if obj.get("entity_type") == "cti_report":
            chunk["chunk_type"] = "cti_report"
            chunk["content"] = f"CTI context ({attrs['publisher']}): {attrs['text']} {attrs['scope']}"
            chunk["source_references"] = deepcopy(attrs["source_references"])
            chunk["metadata"].update(deepcopy(attrs))
        elif chunk['chunk_type'] == 'fact':
            # Do not repeat raw fields inside prose AND structured metadata.
            compact = {k:v for k,v in attrs.items() if k != 'source_observations'}
            chunk['content'] = f"Fact {obj['fact_id']}. {obj['subject']} {obj['predicate']} {obj['object']}. Status: {obj['status']}. " + json.dumps(compact,ensure_ascii=False,separators=(',',':'))
        if chunk["chunk_type"] == "evidence":
            obs = []
            for fact_item in doc["facts"]:
                if obj["evidence_id"] in fact_item["evidence_ids"]:
                    obs.extend(fact_item["attributes"].get("source_observations", []))
            unique = {(r["source_file"],r["raw_record_ref"]):r for r in obs}
            chunk["metadata"]["source_observations"] = [unique[k] for k in sorted(unique)]
        if chunk["chunk_type"] == "mitre_assessment":
            chunk["metadata"].update({**deepcopy(obj), "model_confidence": "supported_by_observed_behavior" if obj["evidence_support"] == "supported_by_observed_behavior" and obj["stix_id"] else "candidate"})
        if chunk["chunk_type"] == "sigma_finding": chunk["metadata"].update(deepcopy(obj))
    for node in graph["nodes"]:
        obj = objects.get(node["source"]["object_id"])
        if obj and obj.get("entity_type") == "cti_report":
            node["node_type"] = "cti_report"
            node["source_references"] = deepcopy(obj["attributes"]["source_references"])
        if obj and node["node_type"] == "evidence":
            corresponding = next(c for c in corpus["chunks"] if c["source"]["object_id"] == obj["evidence_id"])
            node["attributes"]["source_observations"] = deepcopy(corresponding["metadata"]["source_observations"])
    # Fact nodes carry source fields. The incidence edges reference the same fact
    # and should not duplicate every raw observation for each endpoint.
    for edge in graph['edges']:
        if edge['edge_type'] in {'fact_subject','fact_object'}:
            edge['attributes'] = {"source_object_id":edge['source']['object_id'], "field_location":"returned fact node attributes"}
    # Context-only incidence edges and topic placeholders are graph navigation,
    # not additional knowledge documents. Index each CTI passage once.
    corpus['chunks']=[c for c in corpus['chunks'] if not (
        c['source']['object_type']=='relationship' and objects.get(c['source']['object_id'],{}).get('attributes',{}).get('evidence_layer')=='cti_context')
        and not (c['chunk_type']=='entity' and objects.get(c['source']['object_id'],{}).get('entity_type')=='behavior_concept')]
    corpus['metadata']['chunk_count']=len(corpus['chunks'])
    graph["metadata"]["node_type_counts"] = dict(sorted(Counter(n["node_type"] for n in graph["nodes"]).items()))
    validate_retrieval_corpus(corpus)
    validate_knowledge_graph(graph)
