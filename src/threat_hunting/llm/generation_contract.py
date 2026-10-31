"""Versioned, source-derived meaning annotations; never evaluation answers.

Consumers stay immutable. Only returned observations/findings are projected.
V5 has no such marker and retains its original prompt and validation path.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from .guardrail import context_catalog, _walk, _step_supported
from .schema import AttackStep
from threat_hunting.retrieval.context_packing import unpack_context

CONTRACT = "source-meaning/v2"
INSTRUCTIONS = """
SOURCE MEANING CONTRACT source-meaning/v2 (applies to every prose and structured field):
- sigma_matches contains exact rule_id values copied from sigma_rule_identifiers, never finding_id,
  source object ID, graph_node_id or chunk_id. A sigma- prefix on a finding is not part of rule_id.
  Do not transform IDs. If no allowed rule_id is available, leave sigma_matches empty.
- Authentication spans describe canonical timestamps of the selected observations or the inferred
  attempt anchors explicitly named in timestamp_semantics, not real attack/activity duration.
  Different source clocks are not demonstrated to be synchronized. Retain raw EventTime,
  @timestamp/TimeCreated/UtcTime, canonical mapping, inferred pairing and its tolerance/limits.
  Preserve conflicting/timezone-naive clocks; never invent a timezone correction.
  Do not turn a canonical timestamp span into attack duration or simultaneous physical attempts.
- process_creation_bindings states the actual parent -> created child for each cited observation.
  A command mentioning another program is only a command invocation string, not observation of
  that program's creation. Cite the creation record of the child for a process_spawn claim.
  In prose put exact supporting references in the same sentence as a creation claim; global
  evidence_refs alone does not bind that sentence. Keep commands, observed process creation,
  completion/output and service state separate. A process record proves none of those results.
- The meaning table is a derived view of returned sources, not new telemetry or approval.
  CTI remains external technical context and cannot establish local compromise or confirmed C2.
"""


def _span(values: list[str]) -> dict[str, Any]:
    ordered = sorted(v for v in values if v)
    if not ordered:
        return {}
    start, end = ordered[0], ordered[-1]
    seconds = (datetime.fromisoformat(end.replace("Z", "+00:00")) -
               datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds()
    return {"start": start, "end": end, "canonical_span_seconds": seconds}


def project_meaning(context: dict[str, Any]) -> dict[str, Any]:
    """Derive meaning from returned sources only, without duplicating them in context."""
    expanded = unpack_context(context)
    items = [h.get("chunk", {}) for h in expanded.get("retrieval", {}).get("hits", [])]
    items += expanded.get("traversal", {}).get("nodes", [])
    rules, observations, attempts = {}, {}, {}
    for item in items:
        attributes = item.get("attributes", item.get("metadata", {}))
        for value in _walk(attributes):
            digest = value.get("rule_sha256")
            if item.get("node_type", item.get("chunk_type")) == "sigma_finding" and value.get("rule_id") and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) and digest != "0" * 64:
                entry = rules.setdefault(value["rule_id"], {"rule_id": value["rule_id"], "rule_sha256": digest,
                    "finding_ids": [], "graph_node_ids": [], "chunk_ids": []})
                for key, identifier in (("finding_ids", item.get("source", {}).get("object_id")),
                                        ("graph_node_ids", item.get("node_id")), ("chunk_ids", item.get("chunk_id"))):
                    if identifier and identifier not in entry[key]:
                        entry[key].append(identifier)
            if value.get("source_file") and value.get("raw_record_ref") and (value.get("original_fields") or value.get("canonical_fields")):
                observations[(value["source_file"], value["raw_record_ref"])] = value
            if value.get("attempt_id") and value.get("correlation_basis"):
                attempts[value["attempt_id"]] = {k: deepcopy(value[k]) for k in (
                    "attempt_id", "timestamp", "status", "raw_record_refs", "correlation_basis", "limitations") if k in value}
    creations, auth_clocks = [], {}
    for (source, ref), observation in sorted(observations.items()):
        raw, canonical = observation.get("original_fields", {}), observation.get("canonical_fields", {})
        fields = {**raw, **canonical}
        event_id = str(fields.get("event_id", fields.get("EventID", "")))
        if event_id in {"1", "4688"}:
            parent = fields.get("parent_process_name") or fields.get("ParentImage") or fields.get("ParentProcessName")
            child = fields.get("process_name") or fields.get("Image") or fields.get("NewProcessName")
            if parent and child:
                creations.append({"source_file": source, "raw_record_ref": ref, "event_id": event_id,
                    "parent_process": parent, "created_process": child,
                    "observed_command_line": fields.get("command_line", fields.get("CommandLine")),
                    "meaning": "observed_parent_creates_child; command text does not prove another child or completion"})
        if event_id in {"4625", "4776", "4624", "4769"}:
            host = fields.get("host", fields.get("Hostname"))
            group = auth_clocks.setdefault((source, event_id, host), [])
            group.append({"raw_record_ref": ref, "canonical_timestamp": canonical.get("timestamp"),
                          "raw_clock_fields": {k: raw[k] for k in ("@timestamp", "TimeCreated", "EventTime", "UtcTime", "EventReceivedTime") if k in raw}})
    clocks = [{"source_file": source, "event_id": eid, "host": host,
               "selected_observation_count": len(rows), **_span([r["canonical_timestamp"] for r in rows]),
               "clock_observations": rows} for (source, eid, host), rows in sorted(auth_clocks.items())]
    return {"schema_version": CONTRACT, "evidence_layer": "derived_source_semantics",
        "sigma_rule_identifiers": [rules[k] for k in sorted(rules)], "process_creation_bindings": creations,
        "timestamp_semantics": {"span_meaning": "canonical timestamp span of selected observations/explicit inferred anchors only",
            "does_not_establish": ["real attack/activity duration", "cross-source clock synchronization"],
            "canonical_mapping": "existing canonical_fields.timestamp retained unchanged; raw clock fields retained alongside",
            "source_clock_groups": clocks, "inferred_attempt_anchors": [attempts[k] for k in sorted(attempts)],
            "inferred_anchor_window": _span([a.get("timestamp") for a in attempts.values()]),
            "pairing_caveat": "inferred view pairing; preserve source correlation_basis/limitations and original tolerance; no shared attempt ID or proven clock correction"}}


def projection_hash(projection: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def annotate_context(context: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(context)
    result["generation_evidence_contract"] = {"schema_version": CONTRACT,
        "meaning_projection_sha256": projection_hash(project_meaning(context)),
        "timestamp_semantics": "selected canonical spans only; not real activity duration or cross-source clock synchronization",
        "claim_binding": "command text, observed child creation and completion/output/service state are distinct",
        "sigma_namespace": "sigma_matches copies exact source rule_id, not finding_id or graph node ID"}
    return result


def build_messages(query: str, context: dict[str, Any]) -> list[dict[str, str]]:
    from .prompt import ThreatHuntingPromptBuilder, SYSTEM_PROMPT
    projection = project_meaning(context)
    if projection_hash(projection) != context["generation_evidence_contract"]["meaning_projection_sha256"]:
        raise ValueError("Source meaning projection hash mismatch")
    messages = ThreatHuntingPromptBuilder(system_prompt=SYSTEM_PROMPT + INSTRUCTIONS).build_messages(query, context)
    messages[1]["content"] += "\n[DERIVED SOURCE MEANING — exact identifiers and claim bindings]\n" + json.dumps(
        projection, ensure_ascii=False, sort_keys=True)
    return messages


PROCESS_CLAIM = re.compile(r"(?P<parent>[\w.-]+\.exe)(?:\s*\([^)]*\))?\s+(?:khởi chạy|tạo|spawns?|spawned|launches?|launched|starts?|started)\s+(?P<child>[\w.-]+\.exe)", re.I)
NEGATION = re.compile(r"\b(?:không|chưa|not|never|no evidence)\b", re.I)


def check_narrative(raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Check only explicit positive process-creation clauses with inline refs.

    This is a deliberately bounded deterministic check, not prose verification.
    Unbound/paraphrased claims remain unverified, not automatically true/false.
    """
    catalog = context_catalog(context)
    issues, checks = [], []
    for field in ("direct_answer", "executive_summary", "technical_analysis"):
        for sentence in re.split(r"\n|(?<=[.!?])\s+(?=[A-ZÀ-Ỹ])", raw.get(field, "")):
            for match in PROCESS_CLAIM.finditer(sentence):
                if NEGATION.search(sentence[:match.start()]):
                    continue
                refs = list(dict.fromkeys(re.findall(r"jsonl:line:\d+", sentence) +
                    [ref for ref in catalog if not ref.startswith("jsonl:") and ref in sentence]))
                if not refs:
                    checks.append({"field": field, "status": "unverified_no_inline_binding"})
                    continue
                supported = any(ref in catalog and _step_supported(AttackStep(step_number=1,
                    source_entity=match["parent"], target_entity=match["child"], action="process_spawn", evidence_ref=ref),
                    catalog[ref]) for ref in refs)
                checks.append({"field": field, "references": refs, "status": "supported" if supported else "unsupported"})
                if not supported:
                    issues.append({"code": "unsupported_narrative_creation_binding", "path": field,
                                   "reason": "Inline citations do not establish the stated parent -> created child.", "reference": refs})
    return {"scope": "explicit positive executable-parent/creation-verb/executable-child clauses with inline references only",
            "checks": checks, "issues": issues, "remaining_prose": "unverified; human review required"}


def validate_meaning(checked: dict[str, Any], raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    if projection_hash(project_meaning(context)) != context["generation_evidence_contract"]["meaning_projection_sha256"]:
        raise ValueError("Source meaning projection hash mismatch")
    result = deepcopy(checked)
    audit = check_narrative(raw, context)
    result["narrative_binding_audit"] = audit
    result["issues"].extend(audit["issues"])
    if audit["issues"]:
        result["status"] = "validation_failed"
        result["sanitized_report"]["verdict"] = "INSUFFICIENT_EVIDENCE"
    result["scope"] = "structured_claims_plus_bounded_inline_process_creation_bindings; all other prose unverified"
    return result
