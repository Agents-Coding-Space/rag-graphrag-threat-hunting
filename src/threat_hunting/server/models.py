"""API request and response models for Threat Hunting FastAPI server."""

from __future__ import annotations

from typing import Any, List, Literal, Optional
from pydantic import BaseModel, Field


class HuntRequest(BaseModel):
    """Investigation request from SOC analyst."""

    query: str = Field(..., description="Natural language investigation query in Vietnamese or English")
    scenario_id: str = Field(default="mshta-powershell", description="Scenario identifier (mshta-powershell, purplesharp-ad, regsvr32-c2)")
    enforce_gate: bool = Field(default=True, description="Whether to reject queries failing Two-Stage Gate")
    use_llm: bool = Field(default=False, description="Whether to invoke LLM analyst to synthesize forensic report")


class CytoscapeNodeData(BaseModel):
    id: str
    label: str
    type: str
    status: Optional[str] = None
    properties: dict[str, Any] = Field(default_factory=dict)


class CytoscapeEdgeData(BaseModel):
    id: str
    source: str
    target: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class CytoscapeElement(BaseModel):
    data: dict[str, Any]
    classes: Optional[str] = None


class GraphResponse(BaseModel):
    """Knowledge graph elements formatted for Cytoscape.js rendering."""

    scenario_id: str
    elements: List[CytoscapeElement] = Field(default_factory=list)
    node_count: int
    edge_count: int


class EvidenceItem(BaseModel):
    evidence_id: str
    evidence_type: str
    summary: str
    status: str
    observations: List[dict[str, Any]]
    source_references: List[dict[str, Any]]


class EvidenceResponse(BaseModel):
    """Forensic evidence details for SOC analysts."""

    scenario_id: str
    evidence_count: int
    evidence_items: List[EvidenceItem] = Field(default_factory=list)


class ScenarioInfo(BaseModel):
    scenario_id: str
    name: str
    description: str
    node_count: int
    edge_count: int
    chunk_count: int
    benchmark_cases: int


class HuntResponse(BaseModel):
    """Result of threat hunting investigation query."""

    status: Literal["proceed", "abstained"]
    scenario_id: str
    query: str
    gate_decision: Optional[dict[str, Any]] = None
    subgraph: Optional[GraphResponse] = None
    retrieval_hits: List[dict[str, Any]] = Field(default_factory=list)
    report: Optional[dict[str, Any]] = None
    reason: Optional[str] = None
    error_message: Optional[str] = None
