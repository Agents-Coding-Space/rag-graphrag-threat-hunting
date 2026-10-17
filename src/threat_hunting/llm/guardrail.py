"""Forensic hallucination guardrails for Threat Hunting LLM outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any

from .schema import ThreatHuntingReport


_MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class GuardrailResult:
    """Outcome of hallucination validation on a generated threat hunting report."""

    is_valid: bool
    hallucinated_entities: list[str] = field(default_factory=list)
    unsupported_evidence_refs: list[str] = field(default_factory=list)
    unsupported_techniques: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sanitized_report: ThreatHuntingReport | None = None


def extract_context_anchors(context: dict[str, Any]) -> dict[str, set[str]]:
    """Extract all verifiable text anchors, entities, and evidence IDs from context."""
    anchors: dict[str, set[str]] = {
        "evidence_refs": set(),
        "techniques": set(),
        "process_names": set(),
        "ips": set(),
        "text_content": set(),
    }

    # 1. From Retrieval Chunks
    hits = context.get("retrieval", {}).get("hits", [])
    for hit in hits:
        chunk = hit.get("chunk", {})
        content = chunk.get("content", "")
        anchors["text_content"].add(content.lower())

        # Extract MITRE IDs
        for tech in _MITRE_PATTERN.findall(content):
            anchors["techniques"].add(tech.upper())

        # Extract IPs
        for ip in _IP_PATTERN.findall(content):
            anchors["ips"].add(ip)

        # Source pointer
        ptr = chunk.get("source", {}).get("json_pointer", "")
        if ptr:
            anchors["evidence_refs"].add(ptr)

        # Chunk metadata attributes
        attrs = chunk.get("metadata", {}).get("attributes", {})
        if isinstance(attrs, dict):
            for obs in attrs.get("source_observations", []):
                ref = obs.get("raw_record_ref")
                if ref:
                    anchors["evidence_refs"].add(ref)
                fields = obs.get("original_fields", {})
                for key in ("Image", "ParentImage", "NewProcessName", "ParentProcessName"):
                    val = fields.get(key)
                    if val and isinstance(val, str):
                        basename = val.split("\\")[-1].split("/")[-1].lower()
                        anchors["process_names"].add(basename)

    # 2. From Graph Traversal
    traversal = context.get("traversal", {})
    for node in traversal.get("nodes", []):
        node_id = node.get("node_id", "")
        if node_id:
            anchors["evidence_refs"].add(node_id)
        label = node.get("label", "")
        if label:
            anchors["text_content"].add(label.lower())
            for tech in _MITRE_PATTERN.findall(label):
                anchors["techniques"].add(tech.upper())

        # Check node attributes
        node_attrs = node.get("attributes", {})
        if isinstance(node_attrs, dict):
            inner_attrs = node_attrs.get("attributes", {})
            if isinstance(inner_attrs, dict):
                for obs in inner_attrs.get("source_observations", []):
                    ref = obs.get("raw_record_ref")
                    if ref:
                        anchors["evidence_refs"].add(ref)

    return anchors


class HallucinationGuardrail:
    """Verifies that threat hunting reports are strictly grounded in context."""

    def __init__(self, strict: bool = True) -> None:
        self.strict = strict

    def validate(self, report: ThreatHuntingReport, context: dict[str, Any]) -> GuardrailResult:
        """Validate a generated report against the forensic context."""
        anchors = extract_context_anchors(context)
        context_blob = " ".join(anchors["text_content"]).lower()

        unsupported_refs = []
        for ref in report.evidence_refs:
            # Check if ref exists in anchors or as substring in context blob
            if ref not in anchors["evidence_refs"] and ref.lower() not in context_blob:
                unsupported_refs.append(ref)

        for step in report.attack_chain:
            if step.evidence_ref not in anchors["evidence_refs"] and step.evidence_ref.lower() not in context_blob:
                if step.evidence_ref not in unsupported_refs:
                    unsupported_refs.append(step.evidence_ref)

        # Check MITRE Techniques
        unsupported_techniques = []
        for mapping in report.mitre_mappings:
            tech_id = mapping.technique_id.strip().upper()
            if tech_id not in anchors["techniques"] and tech_id.lower() not in context_blob:
                unsupported_techniques.append(tech_id)

        # Check for obvious fabricated processes in attack chain
        hallucinated_entities = []
        for step in report.attack_chain:
            for entity_str in (step.source_entity, step.target_entity):
                clean_name = entity_str.split()[0].split("\\")[-1].lower()
                if clean_name.endswith(".exe"):
                    if clean_name not in anchors["process_names"] and clean_name not in context_blob:
                        hallucinated_entities.append(clean_name)

        warnings = []
        is_valid = True

        if unsupported_refs:
            warnings.append(f"Report cites ungrounded evidence_refs: {unsupported_refs}")
            if self.strict:
                is_valid = False

        if unsupported_techniques:
            warnings.append(f"Report maps ungrounded MITRE techniques: {unsupported_techniques}")
            if self.strict:
                is_valid = False

        if hallucinated_entities:
            warnings.append(f"Report introduces fabricated entities: {hallucinated_entities}")
            is_valid = False

        # Build sanitized report if needed
        sanitized = None
        if not is_valid:
            sanitized = report.model_copy(deep=True)
            sanitized.verdict = "INSUFFICIENT_EVIDENCE"
            sanitized.unverified_claims.extend(warnings)

        return GuardrailResult(
            is_valid=is_valid,
            hallucinated_entities=hallucinated_entities,
            unsupported_evidence_refs=unsupported_refs,
            unsupported_techniques=unsupported_techniques,
            warnings=warnings,
            sanitized_report=sanitized or report,
        )
