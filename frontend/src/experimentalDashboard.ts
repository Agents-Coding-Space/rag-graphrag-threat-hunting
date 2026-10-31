import { CytoscapeElement } from './types';
import { ExperimentalResponse } from './experimentalState';

export type ExperimentalBranch = 'rag' | 'graphrag';
export interface ExperimentalPreset { case_id: string; query: string; scenario_id: string }
export interface ExperimentalConfiguration {
  mode: 'experimental_offline_demo' | 'experimental_live_demo' | 'historical_replay_only';
  presets: ExperimentalPreset[];
  llm_http_attempts: number;
  maximum_llm_requests: number;
  stopped_reason: string | null;
  [key: string]: any;
}
export interface ExperimentalQuery { query: string; scenario_id: string; branch: ExperimentalBranch }

let artifactProfile: string | undefined;
export function selectArtifactProfile(profile: string): void { artifactProfile = profile; }

export async function experimentalApi<T>(path: string, init?: RequestInit): Promise<T> {
  const suffix = artifactProfile ? `${path.includes('?') ? '&' : '?'}profile=${encodeURIComponent(artifactProfile)}` : '';
  const response = await fetch(`/experimental-api/${path}${suffix}`, init);
  if (!response.ok) throw new Error(`Experimental HTTP ${response.status}; chưa có câu trả lời được chấp nhận.`);
  return response.json();
}

// The service owns generation mode, global attempt cap and the authentication/429 stop latch.
// A live server also requires explicit consent in this dashboard. Never send a hunt to it by default.
export async function runExperimental(
  request: ExperimentalQuery, liveEnabled: boolean,
  onConfiguration: (config: ExperimentalConfiguration) => void,
): Promise<ExperimentalResponse> {
  const config = await experimentalApi<ExperimentalConfiguration>('config');
  onConfiguration(config);
  if (config.mode === 'historical_replay_only') throw new Error('Checkpoint lịch sử chỉ cho phép saved replay; chọn cấu hình integrated để chạy câu hỏi.');
  if (config.mode === 'experimental_live_demo' && !liveEnabled) {
    throw new Error('Server đang ở chế độ live. Bật Live rõ ràng hoặc khởi động lại service mặc định offline. Chưa gửi hunt.');
  }
  const response = await experimentalApi<ExperimentalResponse>('hunt', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  });
  assertCurrentRequest(response, request);
  return response;
}

export function assertCurrentRequest(response: ExperimentalResponse, request: ExperimentalQuery): void {
  if (response.request.query !== request.query || response.request.scenario_id !== request.scenario_id ||
      response.request.branch !== request.branch) {
    throw new Error('Response không khớp câu hỏi/kịch bản/nhánh hiện tại; không hiển thị bằng chứng.');
  }
}

/** Project only the graph supplied by this response; never reconstruct a RAG graph from the corpus. */
export function experimentalGraph(response: ExperimentalResponse | null): CytoscapeElement[] {
  if (!response || response.request.branch !== 'graphrag' || response.outcome === 'abstain') return [];
  const traversal = response.context?.traversal;
  if (!traversal) return [];
  const nodes: CytoscapeElement[] = (traversal.nodes || []).map((node: any) => ({ data: {
    id: node.node_id, label: node.label, type: node.attributes?.entity_type || node.node_type,
    status: node.status, properties: { ...node.attributes, source: node.source,
      source_references: node.source_references, source_ground_truth: response.context?.source_ground_truth },
  } }));
  const ids = new Set(nodes.map(node => node.data.id));
  const edges: CytoscapeElement[] = (traversal.edges || [])
    .filter((edge: any) => ids.has(edge.source_node_id) && ids.has(edge.target_node_id))
    .map((edge: any) => ({ data: { id: edge.edge_id, source: edge.source_node_id, target: edge.target_node_id,
      label: edge.edge_type, type: edge.edge_type, status: edge.status,
      properties: { ...edge.attributes, source: edge.source, source_references: edge.source_references,
        evidence_ids: edge.evidence_ids } } }));
  return [...nodes, ...edges];
}
