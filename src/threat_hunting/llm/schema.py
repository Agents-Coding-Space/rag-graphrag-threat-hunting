"""Strict Pydantic schemas for Threat Hunting LLM outputs."""

from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field


VerdictType = Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "INSUFFICIENT_EVIDENCE"]
ConfidenceType = Literal["confirmed", "supported_by_observed_behavior", "candidate"]


class AttackStep(BaseModel):
    """An atomic verified step in the observed attack chain."""

    step_number: int = Field(..., description="Sequence number of this step in chronological order")
    source_entity: str = Field(..., description="Source actor or parent process (e.g., cmd.exe PID 5440)")
    action: str = Field(..., description="Observed action (e.g., process_spawn, network_connect, ticket_request)")
    target_entity: str = Field(..., description="Target process, destination IP, or service (e.g., mshta.exe PID 3624)")
    evidence_ref: str = Field(..., description="Mandatory reference to observed log record or evidence ID")
    timestamp: Optional[str] = Field(default=None, description="Observed event timestamp if present in log")


class MitreTechniqueMatch(BaseModel):
    """Mapped MITRE ATT&CK technique backed by observed evidence."""

    technique_id: str = Field(..., description="MITRE Technique ID (e.g., T1218.005)")
    technique_name: str = Field(..., description="Standard MITRE technique name")
    confidence: ConfidenceType = Field(..., description="Confidence level based on direct behavior vs candidate tag")
    rationale: str = Field(..., description="Forensic rationale citing observed command line or activity")


class ThreatHuntingReport(BaseModel):
    """Comprehensive forensic threat hunting analysis report."""

    schema_version: Literal["threat-hunting-report/v1"] = "threat-hunting-report/v1"
    verdict: VerdictType = Field(..., description="High-level threat assessment verdict")
    executive_summary: str = Field(..., description="Concise 2-3 sentence executive briefing for SOC commanders")
    technical_analysis: str = Field(..., description="Detailed forensic analysis of observed activity")
    attack_chain: List[AttackStep] = Field(default_factory=list, description="Verified steps with evidence references")
    mitre_mappings: List[MitreTechniqueMatch] = Field(default_factory=list, description="Associated MITRE techniques")
    sigma_matches: List[str] = Field(default_factory=list, description="Identifiers of triggered Sigma detection rules")
    containment_recommendations: List[str] = Field(default_factory=list, description="Actionable SOC containment recommendations")
    unverified_claims: List[str] = Field(
        default_factory=list,
        description="Hypotheses or claims that cannot be proven due to absence of corroborating telemetry",
    )
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Comprehensive list of unique evidence_id or raw_record_ref cited in this report",
    )
