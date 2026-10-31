import React from 'react';
import { acceptedExperimentalDraft, ExperimentalResponse, experimentalStatus } from '../experimentalState';

export function ExperimentalDetails({ title, value }: { title: string; value: unknown }) {
  return <details className="glass-card border rounded-lg p-2 text-[10px] min-w-0">
    <summary className="cursor-pointer text-cyan-400">{title}</summary>
    <pre className="whitespace-pre-wrap break-all mt-2 select-text max-h-64 overflow-auto">{JSON.stringify(value, null, 2)}</pre>
  </details>;
}

export function ExperimentalResult({ response }: { response: ExperimentalResponse }) {
  const accepted = acceptedExperimentalDraft(response);
  const reasons = response.result.abstention_stage === 'context_budget' ? ['context_budget_exceeded'] :
    response.gate?.reason_codes || response.scope?.reason_codes || [];
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url;
    link.download = `experimental-${response.provenance.mode}-${response.request.branch}-${response.outcome}.json`;
    link.click(); URL.revokeObjectURL(url);
  };
  return <div className="space-y-3 select-text break-words" data-testid="experimental-result">
    <div className="glass-card border rounded-xl p-3 space-y-2 text-xs">
      <p className="text-cyan-400 font-mono">{response.request.branch.toUpperCase()} · {response.request.scenario_id}</p>
      <p className="whitespace-pre-wrap">{response.request.query}</p>
      <h2 className={accepted ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'} data-testid="experimental-outcome">{experimentalStatus(response)}</h2>
      <p className="text-[10px] text-soc-muted break-all">Nguồn: {response.provenance.mode} · {response.provenance.mode === 'saved_experimental_replay'
        ? `Replay: 0 request mới; lịch sử ${response.provenance.historical_llm_http_attempts} attempt`
        : `Lượt này: ${response.result.llm_http_attempts ?? 0} LLM HTTP attempts`} · Cần human review.</p>
      <p className="text-[10px]">Eligibility: {response.eligibility?.decision || response.result.eligibility_decision || response.gate?.decision || response.scope?.decision || 'not_assessed'} · stage: {response.result.abstention_stage || '—'}</p>
      {!!reasons.length && <p className="text-[10px] break-all">Lý do: {reasons.join(', ')}</p>}
      <button onClick={download} className="text-cyan-400 underline text-[10px]">{accepted ? 'Tải JSON (draft + provenance)' : 'Tải diagnostic JSON'}</button>
    </div>
    {accepted && <article className="glass-card border border-emerald-700 rounded-xl p-3 space-y-2" data-testid="accepted-answer">
      <h3 className="font-semibold text-emerald-400">Accepted draft · chưa human-approved</h3>
      <p className="whitespace-pre-wrap">{response.report?.direct_answer}</p>
      <p className="whitespace-pre-wrap">{response.report?.executive_summary}</p>
      {!!response.report?.unverified_claims?.length && <ul className="list-disc pl-4 text-amber-400">{response.report.unverified_claims.map((claim: string, i: number) => <li key={i}>{claim}</li>)}</ul>}
      <ExperimentalDetails title="Chi tiết draft và citations" value={response.report} />
    </article>}
    {response.diagnostic && <ExperimentalDetails title="Rejected diagnostic — không phải accepted answer" value={response.diagnostic} />}
    {response.result.provider_error && <ExperimentalDetails title="Provider error — không retry/fallback" value={response.result.provider_error} />}
    <ExperimentalDetails title="Chi tiết kỹ thuật của response" value={{ scope: response.scope, gate: response.gate,
      eligibility: response.eligibility, validation: response.validation, result: response.result,
      configuration: response.configuration, provenance: response.provenance, messages: response.messages }} />
  </div>;
}
