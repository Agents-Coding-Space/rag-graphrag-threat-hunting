"""Fail-closed structured claim checks; narrative is explicitly unverified."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any, Iterator
from .schema import ThreatHuntingReport

@dataclass
class GuardrailResult:
    is_valid: bool
    hallucinated_entities: list[str] = field(default_factory=list)
    unsupported_evidence_refs: list[str] = field(default_factory=list)
    unsupported_techniques: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sanitized_report: ThreatHuntingReport | None = None
    validation_status: str = "passed"
    issues: list[dict[str, Any]] = field(default_factory=list)
    reference_checks: list[dict[str, str]] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=lambda: ["verdict", "direct_answer", "executive_summary", "technical_analysis", "containment_recommendations", "sigma_matches"])
    human_review_required: bool = True

def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)

def context_catalog(context: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Only structured aliases count; a substring in prose grants no validity."""
    catalog: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if 'source_observation_catalog' in context:
        from threat_hunting.retrieval.context_packing import unpack_context
        context = unpack_context(context)
    items = [h.get("chunk", {}) for h in context.get("retrieval", {}).get("hits", [])]
    items += context.get("traversal", {}).get("nodes", []) + context.get("traversal", {}).get("edges", [])
    for item in items:
        source = item.get("source") or {}
        aliases = [item.get("node_id"), item.get("edge_id"), item.get("chunk_id"), source.get("object_id"), source.get("json_pointer")]
        aliases += item.get("evidence_ids", [])
        aliases += [r["raw_record_ref"] for r in _walk(item) if r.get("source_file") and r.get("raw_record_ref")]
        for alias in dict.fromkeys(a for a in aliases if isinstance(a, str) and a):
            catalog[alias].append(item)
    return dict(catalog)

def _observations(item: dict[str, Any], ref: str = "") -> Iterator[dict[str, Any]]:
    # External context is citable but can never witness a local attack step.
    if any(value.get("evidence_layer") == "cti_context" for value in _walk(item.get("attributes", item.get("metadata", {})))):
        return
    for record in _walk(item.get("attributes", item.get("metadata", {}))):
        original = record.get("original_fields") if isinstance(record.get("original_fields"), dict) else {}
        canonical = record.get("canonical_fields") if isinstance(record.get("canonical_fields"), dict) else {}
        fields = {**original, **canonical} if original or canonical else None
        if isinstance(fields, dict) and (not ref.startswith("jsonl:") or record.get("raw_record_ref") == ref):
            yield fields

def _process(value: Any) -> str:
    match = re.search(r"([\w.-]+\.exe)\b", str(value), re.I)
    return match.group(1).casefold() if match else str(value).strip().casefold()

def _same_timestamp(left: str, right: str) -> bool:
    try:
        return datetime.fromisoformat(left.replace("Z", "+00:00")) == datetime.fromisoformat(right.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return False

def _pid_ok(entity: str, actual: Any) -> bool:
    claim = re.search(r"\bPID\s*[:=]?\s*(0x[0-9a-f]+|\d+)\b", entity, re.I)
    if not claim:
        return True
    try:
        def number(value: Any) -> int:
            text = str(value)
            return int(text, 16 if text.lower().startswith("0x") else 10)
        return number(claim.group(1)) == number(actual)
    except (ValueError, TypeError):
        return False

def _step_supported(step: Any, items: list[dict[str, Any]]) -> bool:
    for item in items:
        if item.get("node_type", item.get("chunk_type")) == "entity":
            continue
        for f in _observations(item, step.evidence_ref):
            event_id = str(f.get("event_id", f.get("EventID", "")))
            process = f.get("process_name") or f.get("Image") or f.get("NewProcessName")
            if step.action in ("spawned_process", "process_spawn", "spawned"):
                if event_id not in ("1", "4688"):
                    continue
                parent = f.get("parent_process_name") or f.get("ParentImage") or f.get("ParentProcessName")
                if not parent or not process:
                    continue
                ok = _process(step.source_entity) == _process(parent) and _process(step.target_entity) == _process(process)
                ok = ok and _pid_ok(step.source_entity, f.get("parent_process_id", f.get("ParentProcessId", f.get("ProcessId"))))
                ok = ok and _pid_ok(step.target_entity, f.get("process_id", f.get("NewProcessId", f.get("ProcessId"))))
            elif step.action in ("network_connection", "network_connect", "connected_to"):
                if event_id != "3":
                    continue
                ip, port = f.get("destination_ip", f.get("DestinationIp")), f.get("destination_port", f.get("DestinationPort"))
                if not process or not ip:
                    continue
                ok = _process(step.source_entity) == _process(process) and step.target_entity in (str(ip), f"{ip}:{port}")
                ok = ok and _pid_ok(step.source_entity, f.get("process_id", f.get("ProcessId")))
            elif step.action in ("authentication_failure", "failed_authentication", "authentication_success", "ticket_request"):
                expected_ids = {"authentication_failure": {"4625", "4776"}, "failed_authentication": {"4625", "4776"},
                                "authentication_success": {"4624"}, "ticket_request": {"4769"}}[step.action]
                if event_id not in expected_ids:
                    continue
                status = f.get("Status")
                if event_id == "4776":
                    try:
                        if int(str(status), 16) == 0: continue
                    except ValueError:
                        continue
                # Event host is the destination/recording host, and TargetUserName
                # is the target account. Neither is an inferred authentication source.
                sources = [f.get(k) for k in ("WorkstationName", "Workstation", "IpAddress", "source_ip")]
                target = f.get("ServiceName") if step.action == "ticket_request" else f.get("TargetUserName", f.get("target_user"))
                if step.action == "ticket_request":
                    sources = [f.get("TargetUserName"), f.get("target_user")]
                ok = any(isinstance(v,str) and v not in {"", "-"} and step.source_entity.casefold() == v.casefold() for v in sources)
                ok = ok and isinstance(target,str) and step.target_entity.casefold() == target.casefold()
            else:
                continue
            timestamp = f.get("timestamp") or f.get("TimeCreated") or f.get("@timestamp")
            if ok and (step.timestamp is None or _same_timestamp(step.timestamp, timestamp)):
                return True
    return False

def _assessments(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    items = [h.get("chunk", {}) for h in context.get("retrieval", {}).get("hits", [])] + context.get("traversal", {}).get("nodes", [])
    for item in items:
        if item.get("node_type", item.get("chunk_type")) != "mitre_assessment":
            continue
        for value in _walk(item.get("attributes") or item.get("metadata", {})):
            if value.get("external_id") and value.get("evidence_support"):
                key = value["external_id"].upper()
                assessment = {**value, "status": item.get("status", value.get("status", "candidate"))}
                if key in result and result[key].get("evidence_support") != assessment["evidence_support"]:
                    assessment["evidence_support"] = "not_assessed"
                result[key] = assessment
    return result

def extract_context_anchors(context: dict[str, Any]) -> dict[str, set[str]]:
    catalog = context_catalog(context)
    processes, ips = set(), set()
    for items in catalog.values():
        for item in items:
            for f in _observations(item):
                processes.update(_process(f[k]) for k in ("process_name", "parent_process_name", "Image", "ParentImage", "NewProcessName", "ParentProcessName") if f.get(k))
                ips.update(str(f[k]) for k in ("source_ip", "destination_ip", "SourceIp", "DestinationIp") if f.get(k))
    return {"evidence_refs": set(catalog), "techniques": set(_assessments(context)), "process_names": processes, "ips": ips, "text_content": set()}

class HallucinationGuardrail:
    """Check structured claims only; narrative/verdict always need human review."""
    def __init__(self, strict: bool = True) -> None:
        self.strict = strict

    def validate(self, report: ThreatHuntingReport, context: dict[str, Any]) -> GuardrailResult:
        catalog, assessments = context_catalog(context), _assessments(context)
        clean = report.model_copy(deep=True)
        issues: list[dict[str, Any]] = []
        invalid_refs, invalid_techniques, fabricated = [], [], []
        references = list(dict.fromkeys(report.evidence_refs + [s.evidence_ref for s in report.attack_chain]))
        supported_refs: set[str] = set()
        def issue(code: str, path: str, reason: str, reference: str | None = None) -> None:
            issues.append({"code": code, "path": path, "reason": reason, "reference": reference})
        for ref in references:
            if ref not in catalog:
                invalid_refs.append(ref)
                issue("unknown_reference", "evidence_refs", "Not an exact structured ID or pointer in supplied context.", ref)
        clean.evidence_refs = [ref for ref in report.evidence_refs if ref in catalog]
        clean.attack_chain = []
        known_processes = extract_context_anchors(context)["process_names"]
        for index, step in enumerate(report.attack_chain):
            if step.evidence_ref not in catalog or not _step_supported(step, catalog[step.evidence_ref]):
                issue("unsupported_step", f"attack_chain/{index}", "Cited fields do not establish this subject/action/object/timestamp; removed from checked chain.", step.evidence_ref)
                fabricated += [n for e in (step.source_entity, step.target_entity) if (n := _process(e)).endswith(".exe") and n not in known_processes]
            else:
                clean.attack_chain.append(step)
                supported_refs.add(step.evidence_ref)
        clean.mitre_mappings = []
        for index, mapping in enumerate(report.mitre_mappings):
            source = assessments.get(mapping.technique_id.upper())
            if source is None:
                invalid_techniques.append(mapping.technique_id)
                issue("unverified_technique", f"mitre_mappings/{index}", "No structured ATT&CK assessment; text/argument IDs are not support.")
                continue
            support = source["evidence_support"]
            stix_id = str(source.get("stix_id"))
            resolved = bool(re.fullmatch(r"attack-pattern--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", stix_id, re.I)) and not stix_id.startswith("attack-pattern--00000000-")
            allowed = "supported_by_observed_behavior" if support == "supported_by_observed_behavior" and resolved else "candidate"
            if mapping.confidence != allowed or (mapping.evidence_support is not None and mapping.evidence_support != support):
                issue("assessment_promotion", f"mitre_mappings/{index}", "Model confidence differs from source assessment; source status preserved.")
            if mapping.assessment_status is not None and mapping.assessment_status != source.get('status','candidate'):
                issue('assessment_status_mismatch',f'mitre_mappings/{index}','Assessment status differs from the supplied source; human approval is not inferred.')
            if mapping.review_status is not None and mapping.review_status != source.get('review_status','needs_review'):
                issue('assessment_review_mismatch',f'mitre_mappings/{index}','Review status differs from the supplied source.')
            if resolved and mapping.technique_name.casefold() != str(source.get("name", "")).casefold():
                issue("technique_name_mismatch", f"mitre_mappings/{index}", "Technique name differs from the structured source object.")
            clean.mitre_mappings.append(mapping.model_copy(update={"confidence": allowed, "technique_name": source.get("name", mapping.technique_id + " (unverified)"), "evidence_support": support, "assessment_status": source.get("status", "candidate"), "review_status": source.get("review_status", "needs_review"), "rationale": source.get("rationale", "Source assessment requires review.")}))
        sigma_ids = set()
        for items in catalog.values():
            for item in items:
                if item.get("node_type", item.get("chunk_type")) == "sigma_finding":
                    for value in _walk(item.get("attributes", item.get("metadata", {}))):
                        digest = value.get("rule_sha256")
                        if value.get("rule_id") and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) and digest != "0"*64:
                            sigma_ids.add(value["rule_id"])
        clean.sigma_matches = [ref for ref in report.sigma_matches if ref in sigma_ids]
        if clean.sigma_matches != report.sigma_matches:
            issue("unverified_sigma_match", "sigma_matches", "No structured finding with a recorded non-placeholder rule hash; removed. Sigma evaluation is not rerun by this guardrail.")
        if issues:
            clean.verdict = "INSUFFICIENT_EVIDENCE"
            clean.unverified_claims = list(dict.fromkeys(clean.unverified_claims + [f"{i['code']}: {i['reason']} ({i['reference'] or i['path']})" for i in issues]))
        checks = [{"reference": r, "status": "supports_structured_claim" if r in supported_refs else "exists_unverified" if r in catalog else "invalid_removed"} for r in references]
        return GuardrailResult(is_valid=not issues, hallucinated_entities=sorted(set(fabricated)), unsupported_evidence_refs=invalid_refs, unsupported_techniques=invalid_techniques, warnings=[i["reason"] for i in issues], sanitized_report=clean, validation_status="validation_failed" if issues else "passed", issues=issues, reference_checks=checks)
