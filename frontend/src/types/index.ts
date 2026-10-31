export interface ScenarioInfo {
  scenario_id: string;
  name: string;
  description: string;
  node_count: number;
  edge_count: number;
  chunk_count: number;
  benchmark_cases: number;
}

export interface CytoscapeElement {
  data: {
    id: string;
    label?: string;
    source?: string;
    target?: string;
    type: string;
    status?: string;
    properties?: Record<string, any>;
  };
  classes?: string;
}

export interface GraphResponse {
  scenario_id: string;
  elements: CytoscapeElement[];
  node_count: number;
  edge_count: number;
}

export interface EvidenceObservation {
  source_file: string;
  raw_record_ref: string;
  provider?: string;
  event_id?: string;
  timestamp?: string;
}

export interface EvidenceItem {
  evidence_id: string;
  evidence_type: string;
  summary: string;
  status: string;
  observations: EvidenceObservation[];
  source_references: Array<{ source_file: string; raw_record_ref: string }>;
}

export interface EvidenceResponse {
  scenario_id: string;
  evidence_count: number;
  evidence_items: EvidenceItem[];
}

export interface AttackStep {
  step_number: number;
  source_entity: string;
  action: string;
  target_entity: string;
  evidence_ref: string;
  timestamp?: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  confidence: string;
  rationale: string;
  evidence_support?: string;
  assessment_status?: string;
  review_status?: string;
}

export interface ThreatReport {
  schema_version: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'INSUFFICIENT_EVIDENCE' | null;
  direct_answer?: string;
  ai_engine?: string;
  executive_summary: string;
  technical_analysis: string;
  attack_chain: AttackStep[];
  mitre_mappings: MitreMapping[];
  sigma_matches: string[];
  containment_recommendations: string[];
  unverified_claims: string[];
  evidence_refs: string[];
}

export interface HuntResponse {
  replay?: { mode: 'saved_response' | 'synthetic_fixture'; source_file: string; sha256: string | null; case_id: string };
  status: 'proceed' | 'abstained' | 'validation_failed' | 'provider_error';
  scenario_id: string;
  query: string;
  gate_decision?: {
    decision: 'proceed' | 'abstain';
    abstention_stage?: string;
    reason_codes?: string[];
  };
  subgraph?: GraphResponse;
  retrieval_hits: Array<{
    chunk_id: string;
    chunk_type: string;
    content: string;
    score: number;
    source_pointer?: string;
  }>;
  report?: ThreatReport;
  reason?: string;
  error_message?: string;
  scope_decision?: { decision: 'proceed' | 'abstain'; reason_codes: string[] };
  execution?: { source: 'none' | 'llm' | 'offline_fallback'; llm_called: boolean; generation_succeeded: boolean; llm_http_attempts: number | null; fallback_used: boolean; gate_enforced: boolean };
  provider_error?: { kind: string; http_status: number | null; retry_after_seconds: number | null; automatic_retry: boolean };
  validation?: { status: string; scope: string; unverified_fields?: string[]; human_review_required: boolean; issues?: Array<{ code: string; reason?: string }>; reference_checks?: Array<{ reference: string; status: string }> };
}
