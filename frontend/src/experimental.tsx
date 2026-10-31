import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { acceptedExperimentalDraft, ExperimentalResponse, experimentalStatus } from './experimentalState';
import './index.css';

type Preset = { case_id: string; query: string; scenario_id: string };
type Configuration = Record<string, any> & { presets: Preset[]; fixture_ids: string[] };
const json = (value: unknown) => JSON.stringify(value, null, 2);

async function api(url: string, init?: RequestInit) {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`Backend HTTP ${response.status}; không có accepted answer.`);
  return response.json();
}

function JsonDetails({ title, value }: { title: string; value: unknown }) {
  return <details className="border border-slate-700 rounded-lg p-3 min-w-0">
    <summary className="cursor-pointer text-cyan-300">{title}</summary>
    <pre className="whitespace-pre-wrap break-all text-xs mt-3 select-text">{json(value)}</pre>
  </details>;
}

function ExperimentalApp() {
  const [configuration, setConfiguration] = useState<Configuration | null>(null);
  const [caseId, setCaseId] = useState('PS02');
  const [branch, setBranch] = useState('rag');
  const [scenario, setScenario] = useState('purplesharp-ad');
  const [query, setQuery] = useState('');
  const [response, setResponse] = useState<ExperimentalResponse | null>(null);
  const [fixture, setFixture] = useState('validation_failed');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const inFlight = useRef(false);
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    api('/experimental-api/config').then(data => {
      setConfiguration(data);
      const preset = data.presets.find((p: Preset) => p.case_id === 'PS02');
      setQuery(preset.query); setScenario(preset.scenario_id);
    }).catch(err => setError(String(err)));
  }, []);

  function selectCase(id: string) {
    setCaseId(id);
    const preset = configuration?.presets.find(p => p.case_id === id);
    if (preset) { setQuery(preset.query); setScenario(preset.scenario_id); }
    setResponse(null); setError('');
  }
  async function run(kind: 'hunt' | 'saved' | 'fixture') {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setResponse(null); setError('');
    try {
      const url = kind === 'hunt' ? '/experimental-api/hunt' : kind === 'saved' ?
        `/experimental-api/saved?case_id=${encodeURIComponent(caseId)}&branch=${branch}` :
        `/experimental-api/fixture?outcome=${encodeURIComponent(fixture)}`;
      const data = await api(url, kind === 'hunt' ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: json({ query, scenario_id: scenario, branch }) } : undefined);
      setResponse(data);
      setConfiguration(previous => previous ? { ...previous, ...data.configuration } : previous);
    } catch (err) { setError(String(err)); }
    finally { inFlight.current = false; setBusy(false); }
  }
  function download() {
    if (!response) return;
    const blob = new Blob([json(response)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url;
    link.download = `experimental-${response.provenance.mode}-${response.request.branch}-${response.outcome}.json`;
    link.click(); URL.revokeObjectURL(url);
  }
  const active = response?.configuration || configuration;
  const eligible = response?.eligibility?.decision || response?.gate?.decision || response?.scope?.decision;
  const reasons = response?.result.abstention_stage === 'context_budget' ? ['context_budget_exceeded'] :
    response?.gate?.reason_codes || response?.scope?.reason_codes || [];
  const presetUnchanged = configuration?.presets.some(p => p.case_id === caseId && p.query === query && p.scenario_id === scenario);
  return <main className="max-w-7xl mx-auto p-4 md:p-8 space-y-5 select-text">
    <header className="border border-amber-700 bg-amber-950/40 rounded-xl p-5 space-y-2">
      <h1 className="text-xl font-bold text-amber-200">EXPERIMENTAL · RAG / GraphRAG evidence-contract demo</h1>
      <p>Draft cần review. Demo tách khỏi benchmark 15×2 đã chốt.</p>
      <p className="font-mono text-sm break-all" data-testid="configuration">{active?.mode || 'Đang nạp cấu hình…'} · {active?.gate_contract} · {active?.model?.provider} / {active?.model?.model_name}</p>
      {active && <p className="text-sm">temperature {active.model.temperature} · max_tokens {active.model.max_tokens} · timeout {active.model.timeout_seconds}s · requests session {active.llm_http_attempts}/{active.maximum_llm_requests} · retry/fallback: tắt</p>}
      {active && <p className="text-sm">top_k {active.config.retrieval.top_k} / candidate_k {active.config.retrieval.candidate_k} · GraphRAG depth {active.config.graph_expansion.max_depth} · budgets context/messages {active.config.maximum_context_utf8_bytes}/{active.config.maximum_messages_utf8_bytes} UTF-8 bytes · prompt/schema/strict validator đã pin</p>}
    </header>
    <section className="grid md:grid-cols-3 gap-4">
      <div className="md:col-span-2 space-y-3 border border-slate-700 rounded-xl p-4">
        <div className="flex gap-4 flex-wrap">
          <label>Case đã khóa <select aria-label="Case đã khóa" className="ml-2 bg-slate-900 border p-2 rounded" value={caseId} onChange={e => selectCase(e.target.value)} disabled={busy}>
            {(configuration?.presets || []).map(p => <option key={p.case_id}>{p.case_id}</option>)}
          </select></label>
          <label>Nhánh <select aria-label="Nhánh" className="ml-2 bg-slate-900 border p-2 rounded" value={branch} onChange={e => { setBranch(e.target.value); setResponse(null); }} disabled={busy}>
            <option value="rag">RAG</option><option value="graphrag">GraphRAG</option>
          </select></label>
        </div>
        <p className="text-sm text-slate-400">Scenario: {scenario} · {presetUnchanged ? 'Query nguyên văn từ cases đã khóa' : 'Query tùy nhập, ngoài preset demo'}</p>
        <textarea aria-label="Câu hỏi" className="w-full min-h-28 p-3 bg-slate-900 rounded border border-slate-600" value={query} onChange={e => { setQuery(e.target.value); setResponse(null); }} disabled={busy} />
        <div className="flex gap-3 flex-wrap">
          <button className="bg-cyan-800 rounded px-4 py-2 disabled:opacity-40" disabled={!configuration || busy || !query.trim()} onClick={() => run('hunt')}>
            {busy ? 'Đang xử lý…' : configuration?.mode === 'experimental_live_demo' ? 'Chạy live · tối đa 1 request nếu proceed' : 'Chạy offline · 0 request LLM'}
          </button>
          <button className="border border-amber-700 rounded px-4 py-2 disabled:opacity-40" disabled={!configuration || busy || !presetUnchanged} onClick={() => run('saved')}>Saved experimental replay · 0 request</button>
        </div>
      </div>
      {configuration?.stopped_reason && <p role="alert" className="text-amber-200">Session live đã dừng: {configuration.stopped_reason}. Vẫn có thể kiểm tra gate; không gọi LLM thêm.</p>}
      <aside className="border border-slate-700 rounded-xl p-4 space-y-3">
        <h2 className="font-bold">Kiểm tra UI bằng fixtures</h2>
        <p className="text-sm text-slate-400">Synthetic, không phải kết quả benchmark hoặc lỗi provider đã đo. Loading hiển thị trong lúc xử lý.</p>
        <select aria-label="Synthetic fixture" value={fixture} className="w-full bg-slate-900 border p-2 rounded" onChange={e => setFixture(e.target.value)} disabled={busy}>
          {(configuration?.fixture_ids || []).map(id => <option key={id}>{id}</option>)}
        </select>
        <button className="border rounded px-4 py-2 disabled:opacity-40" onClick={() => run('fixture')} disabled={!configuration || busy}>Xem fixture · 0 request</button>
      </aside>
    </section>
    {busy && <p role="status" className="text-cyan-300 p-4 border rounded">Đang retrieval / gate / generation / validation theo chế độ server. Không tự retry.</p>}
    {error && <p role="alert" className="text-rose-300 border border-rose-700 rounded p-4">{error}</p>}
    {response && <section className="space-y-4" data-testid="result">
      <div className={`border rounded-xl p-5 space-y-2 ${acceptedExperimentalDraft(response) ? 'border-emerald-700' : 'border-amber-700'}`}>
        <p className="font-bold text-amber-200 break-all">Nguồn: {response.provenance.mode} · nhánh {response.request.branch.toUpperCase()} · scenario {response.request.scenario_id}</p>
        <h2 className="text-lg font-bold" data-testid="outcome">{experimentalStatus(response)}</h2>
        <p className="whitespace-pre-wrap">Câu hỏi của response: {response.request.query}</p>
        <p>Final eligibility: <strong>{eligible || 'not_assessed'}</strong> · Policy gate: {response.gate?.decision || 'not_run'} · stage: {response.result.abstention_stage || '—'}</p>
        <p className="break-all">Lý do: {reasons.length ? reasons.join(', ') : 'Không có reason code từ chối.'}</p>
        <p>{response.provenance.mode === 'saved_experimental_replay' ? `Replay dùng 0 request; lượt lịch sử: ${response.provenance.historical_llm_http_attempts} attempt.` : `LLM HTTP attempts lượt này: ${response.result.llm_http_attempts}.`} Human review required.</p>
        <button className="underline text-cyan-300" onClick={download}>Tải response + provenance JSON ({response.outcome})</button>
      </div>
      {acceptedExperimentalDraft(response) && <article className="border border-emerald-800 rounded-xl p-5 space-y-4" data-testid="accepted-answer">
        <h2 className="font-bold text-emerald-300">Accepted draft · structured validation passed · chưa human-approved</h2>
        <p className="whitespace-pre-wrap">{response.report?.direct_answer}</p>
        <p className="whitespace-pre-wrap">{response.report?.executive_summary}</p>
        <p className="whitespace-pre-wrap">{response.report?.technical_analysis}</p>
        {!!response.report?.unverified_claims?.length && <div className="text-amber-200"><p>Giới hạn / claims chưa xác minh trong draft:</p><ul className="list-disc pl-5">{response.report.unverified_claims.map((claim: string, i: number) => <li key={i}>{claim}</li>)}</ul></div>}
        <JsonDetails title="Toàn bộ draft và evidence_refs" value={response.report} />
      </article>}
      {response.diagnostic && <JsonDetails title="Rejected diagnostic — không phải accepted answer" value={response.diagnostic} />}
      {response.result.provider_error && <JsonDetails title="Provider error / rate limit — không fallback" value={response.result.provider_error} />}
      <section className="grid md:grid-cols-2 gap-3">
        <JsonDetails title="Scope, gate và final eligibility" value={{ scope: response.scope, gate: response.gate, eligibility: response.eligibility }} />
        <JsonDetails title="Configuration + artifact hashes + provenance" value={{ configuration: response.configuration, provenance: response.provenance }} />
      </section>
      <h2 className="font-bold">Evidence và citations từ supplied context</h2>
      <p className="text-sm text-slate-400">Raw references được giữ cùng source file, JSON pointer và provenance SHA. ID tồn tại chưa chứng minh semantic support; nguồn pending giữ nguyên.</p>
      <div className="space-y-2">{(response.evidence_contract?.units || []).map((unit: any, i: number) => <JsonDetails key={i}
        title={`${unit.origin.kind}: ${unit.origin.item_id} · ${unit.status} · ${unit.source.json_pointer || 'no pointer'}`}
        value={{ ...unit, source_ground_truth: response.evidence_contract?.source_ground_truth }} />)}</div>
      {!response.context && <p>Không retrieval context trong response này (ví dụ scope abstain hoặc synthetic fixture).</p>}
      <JsonDetails title="Supplied context (đúng context của generator/validator)" value={response.context} />
      <JsonDetails title="Messages từ prompt builder đã đánh giá" value={response.messages} />
      <JsonDetails title="Validation + result diagnostic" value={{ validation: response.validation, result: response.result }} />
    </section>}
  </main>;
}

ReactDOM.createRoot(document.getElementById('root')!).render(<ExperimentalApp />);
