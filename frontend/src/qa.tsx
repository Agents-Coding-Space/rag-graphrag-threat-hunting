import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { ChatPanel } from './components/ChatPanel';
import { EvidenceSidebar } from './components/EvidenceSidebar';
import { CytoscapeGraph } from './components/CytoscapeGraph';
import { EvidenceItem, HuntResponse } from './types';
import './index.css';

const CASES = ['RG04', 'MS01', 'MS04', 'PS02', 'RG05', 'provider_error', 'rate_limited', 'loading'];
const caseId = new URLSearchParams(location.search).get('case') || 'RG04';
const endpoint = `http://127.0.0.1:8001/qa-api/replay?case=${encodeURIComponent(caseId)}`;

function ReplayApp() {
  const [fixture, setFixture] = useState<{ response: HuntResponse | null; evidence_items: EvidenceItem[]; provenance: Record<string, string> } | null>(null);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    fetch(endpoint).then(response => {
      if (!response.ok) throw new Error(`Replay server HTTP ${response.status}`);
      return response.json();
    }).then(data => {
      setFixture(data);
      setSelectedNode(data.response?.subgraph?.elements.find((element: any) => !element.data.source)?.data || null);
    }).catch(error => setError(String(error)));
  }, []);
  const response = fixture?.response;
  return <div className="h-screen flex flex-col p-3 gap-2">
    <header className="p-3 border border-amber-700 rounded-xl bg-amber-950/60 text-amber-200 text-xs space-y-1">
      <div className="font-bold">REPLAY/MOCK — Không gọi API LLM. Historical source có thể là lượt LLM thật cũ; ảnh này là replay.</div>
      <div className="flex gap-3 flex-wrap">{CASES.map(id => <a key={id} className="underline" href={`/qa.html?case=${id}`}>{id}</a>)}</div>
      {fixture && <div className="text-[10px] break-all">{caseId} · {fixture.provenance.mode} · {fixture.provenance.source_file} · SHA-256 {fixture.provenance.sha256}</div>}
      {error && <div role="alert">{error}</div>}
    </header>
    {fixture && <main className="grid grid-cols-12 flex-1 min-h-0 border rounded-xl overflow-hidden">
      <section className="col-span-3 min-h-0"><EvidenceSidebar selectedNode={selectedNode} evidenceItems={fixture.evidence_items} theme="dark" /></section>
      <section className="col-span-4 min-h-0 p-2">{response?.subgraph?.elements.length ? <CytoscapeGraph elements={response.subgraph.elements} selectedNodeId={selectedNode?.id} onSelectNode={setSelectedNode} theme="dark" /> : <div className="p-4 text-xs text-soc-muted">{caseId === 'loading' ? 'SYNTHETIC loading fixture' : 'Không có subgraph trong response đã lưu.'}</div>}</section>
      <section className="col-span-5 min-h-0"><ChatPanel scenarios={[{ scenario_id: response?.scenario_id || 'mshta-powershell', name: `REPLAY ${caseId}`, description: '', node_count: 0, edge_count: 0, chunk_count: 0, benchmark_cases: 0 }]}
        selectedScenario={response?.scenario_id || 'mshta-powershell'} onSelectScenario={() => undefined}
        onHunt={async () => { setLoading(true); await new Promise(resolve => setTimeout(resolve, 900)); setLoading(false); return response || null; }}
        isLoading={loading || caseId === 'loading'} theme="dark" initialResponse={response || undefined}
        initialQuery={caseId === 'loading' ? '[SYNTHETIC] Loading UI QA — no request' : ''} /></section>
    </main>}
  </div>;
}

ReactDOM.createRoot(document.getElementById('root')!).render(<ReplayApp />);
