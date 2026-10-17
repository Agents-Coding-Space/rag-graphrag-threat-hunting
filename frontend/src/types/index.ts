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
}

export interface ThreatReport {
  schema_version: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'INSUFFICIENT_EVIDENCE';
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
  status: 'proceed' | 'abstained';
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
}
