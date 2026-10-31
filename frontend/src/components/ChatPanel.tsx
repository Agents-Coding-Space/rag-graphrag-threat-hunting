import React, { useState } from 'react';
import { TerminalIcon, SendIcon, DownloadIcon, CheckCircleIcon, AlertTriangleIcon, SparklesIcon, ShieldIcon } from './SvgIcons';
import { HuntResponse, ScenarioInfo } from '../types';
import { canExportAcceptedDraft, exportFilename, isRejected, responseMessage } from '../reportState';
import { ExperimentalResponse } from '../experimentalState';
import { ExperimentalBranch, ExperimentalConfiguration, ExperimentalPreset } from '../experimentalDashboard';
import { ExperimentalDetails, ExperimentalResult } from './ExperimentalResult';

export interface ExperimentalChat {
  configuration: ExperimentalConfiguration | null;
  response: ExperimentalResponse | null;
  branch: ExperimentalBranch;
  query: string;
  liveEnabled: boolean;
  error: string | null;
  onBranchChange: (value: ExperimentalBranch) => void;
  onQueryChange: (value: string) => void;
  onPreset: (value: ExperimentalPreset) => void;
  onLiveChange: (value: boolean) => void;
  onHunt: (query: string) => Promise<void>;
  onReplay: (preset: ExperimentalPreset) => Promise<void>;
  onProfileChange?: (profile: string) => Promise<void>;
}

interface Props {
  scenarios: ScenarioInfo[];
  selectedScenario: string;
  onSelectScenario: (scenId: string) => void;
  onHunt: (query: string, enforceGate: boolean, useLLM: boolean) => Promise<HuntResponse | null>;
  isLoading: boolean;
  theme: 'dark' | 'light';
  initialResponse?: HuntResponse;
  initialQuery?: string;
  mode?: 'legacy' | 'experimental';
  onModeChange?: (value: 'legacy' | 'experimental') => void;
  experimental?: ExperimentalChat;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  response?: HuntResponse;
  timestamp: string;
}

export const ChatPanel: React.FC<Props> = ({
  scenarios,
  selectedScenario,
  onSelectScenario,
  onHunt,
  isLoading,
  theme,
  initialResponse,
  initialQuery = '',
  mode = 'legacy',
  onModeChange,
  experimental,
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [enforceGate, setEnforceGate] = useState(true);
  const [useLLM, setUseLLM] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showDetailsMap, setShowDetailsMap] = useState<Record<string, boolean>>({});
  const [messages, setMessages] = useState<ChatMessage[]>(initialResponse ? [
    { id: 'replay-user', sender: 'user', text: initialResponse.query, timestamp: 'REPLAY' },
    { id: 'replay-response', sender: 'assistant', text: responseMessage(initialResponse), response: initialResponse, timestamp: 'REPLAY' },
  ] : [
    {
      id: 'welcome',
      sender: 'assistant',
      text: 'Xin chào Chuyên viên SOC! Tôi là Trợ lý Truy tìm Mối đe dọa (Threat Hunting Co-Pilot) kết hợp RAG, GraphRAG và LLM. Hãy chọn kịch bản và nhập câu hỏi điều tra.',
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const quickQueries: Record<string, string[]> = {
    'mshta-powershell': [
      'Which process chain led to powershell.exe in the reviewed evidence?',
      'Kỹ thuật MITRE ATT&CK nào được ánh xạ cho hành vi của mshta?',
      'Cmdlet nào đã chạy thành công bên trong PowerShell?',
    ],
    'purplesharp-ad': [
      'Which command line parameters were passed to PurpleSharp.exe?',
      'Những tài khoản người dùng Active Directory nào bị nhắm tới?',
      'Mật khẩu của tài khoản Administrator có bị lộ không?',
    ],
    'regsvr32-c2': [
      'To which remote IP address and port did regsvr32.exe connect?',
      'Kỹ thuật Squiblydoo lợi dụng binary nào để tải file .sct từ xa?',
      'Nội dung mã nguồn chi tiết bên trong file launcher.sct là gì?',
    ],
  };

  const handleSend = async (textToSend?: string) => {
    const q = (textToSend ?? (experimental ? experimental.query : query)).trim();
    if (!q || isLoading) return;
    if (experimental) { await experimental.onHunt(q); return; }

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setQuery('');

    const res = await onHunt(q, enforceGate, useLLM);
    if (res) {
      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        sender: 'assistant',
        text: responseMessage(res),
        response: res,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, botMsg]);
    }
  };

  const downloadJsonReport = (response: HuntResponse) => {
    const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = exportFilename(response, 'json');
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = (res: HuntResponse) => {
    if (!canExportAcceptedDraft(res)) return;
    const report = res.report;
    const lines = [
      `# BẢN NHÁP ĐIỀU TRA — CẦN HUMAN REVIEW`,
      ...(res.replay ? [`**REPLAY/MOCK:** ${res.replay.mode}; nguồn ${res.replay.source_file}; không phải lượt gọi live mới.  `] : []),
      `**Kịch bản:** ${res.scenario_id}  `,
      `**Truy vấn của chuyên viên:** "${res.query}"  `,
      `**Thời gian lập báo cáo (UTC):** ${new Date().toISOString()}  `,
      `**Trạng thái request:** ${res.status}  `,
      `**Gate:** ${res.gate_decision?.decision || 'chưa đánh giá'}  `,
      `**Nguồn:** ${res.execution?.source || report?.ai_engine || 'chưa xác định'}  `,
      `**Validation:** ${res.validation?.status || 'chưa đánh giá'} (${res.validation?.scope || 'chưa rõ'})  `,
      `**Giới hạn:** Narrative và verdict chưa được xác minh semantic support, cần người dùng duyệt.  `,
      `**Provider:** ${res.provider_error?.kind || 'không ghi nhận lỗi'} ${res.provider_error?.http_status || ''}  `,
      ``,
      `---`,
      `## 1. KẾT LUẬN ĐIỀU HÀNH (EXECUTIVE VERDICT)`,
      `**Đánh giá dự thảo:** ${report?.verdict || 'CHƯA ĐÁNH GIÁ'}  `,
      `**Tóm tắt:** ${report?.executive_summary || 'Chưa có phân tích.'}`,
      ``,
      `## 2. CHUỖI TẤN CÔNG (ATTACK CHAIN)`,
    ];

    if (report?.attack_chain && report.attack_chain.length > 0) {
      lines.push(`| Bước | Thực thể nguồn | Hành vi | Thực thể đích | Mã bằng chứng (Evidence Ref) |`);
      lines.push(`| :---: | :--- | :--- | :--- | :--- |`);
      report.attack_chain.forEach((s) => {
        lines.push(`| ${s.step_number} | \`${s.source_entity}\` | ${s.action} | \`${s.target_entity}\` | \`${s.evidence_ref}\` |`);
      });
    } else {
      lines.push(`*Không có chuỗi bước tấn công nào được xác nhận thêm.*`);
    }

    lines.push(``);
    lines.push(`## 3. ÁNH XẠ KỸ THUẬT MITRE ATT&CK`);
    if (report?.mitre_mappings && report.mitre_mappings.length > 0) {
      report.mitre_mappings.forEach((m) => {
        lines.push(`- **${m.technique_id} - ${m.technique_name}** (${m.confidence}; ${m.evidence_support || 'unverified'}; ${m.assessment_status || 'chưa duyệt'})`);
        lines.push(`  * Căn cứ: ${m.rationale}`);
      });
    }

    if (report?.unverified_claims && report.unverified_claims.length > 0) {
      lines.push(``);
      lines.push(`## 4. CÁC ĐIỂM NGHI VẤN CHƯA THỂ XÁC MINH (UNVERIFIED CLAIMS)`);
      report.unverified_claims.forEach((c) => {
        lines.push(`- ⚠️ ${c}`);
      });
    }

    lines.push(``);
    lines.push(`## KIỂM TRA REFERENCE (không xác minh toàn bộ narrative)`);
    res.validation?.reference_checks?.forEach((c) => lines.push(`- ${c.reference}: ${c.status}`));
    lines.push(`---`);
    lines.push(`*Báo cáo được trích xuất tự động từ Hệ thống SOC Threat Hunting Workbench (RAG + GraphRAG + LLM).*`);

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = exportFilename(res, 'md');
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full glass-panel border-l overflow-hidden transition-colors duration-200">
      {/* Header */}
      <div className="p-3.5 border-b space-y-2.5" style={{ borderColor: 'var(--border-glass)' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-cyan-400" />
            <h1 className="font-bold text-xs tracking-wider uppercase font-mono">SOC THREAT HUNTING CHAT</h1>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            {experimental ? experimental.branch === 'rag' ? 'RAG' : 'GraphRAG' : 'GraphRAG'}
          </span>
        </div>

        {onModeChange && <div className="flex gap-2">
          <label className="flex-1 text-[10px] text-soc-muted">Chế độ
            <select aria-label="Chế độ" value={mode} disabled={isLoading}
              onChange={e => onModeChange(e.target.value as 'legacy' | 'experimental')}
              className="w-full bg-black/30 border rounded-lg px-2 py-1.5 text-xs text-soc-text">
              <option value="experimental">Experimental</option><option value="legacy">Dashboard legacy</option>
            </select>
          </label>
          {experimental && <label className="text-[10px] text-soc-muted">Nhánh
            <select aria-label="Nhánh" value={experimental.branch} disabled={isLoading}
              onChange={e => experimental.onBranchChange(e.target.value as ExperimentalBranch)}
              className="w-full bg-black/30 border rounded-lg px-2 py-1.5 text-xs text-soc-text">
              <option value="rag">RAG</option><option value="graphrag">GraphRAG</option>
            </select>
          </label>}
        </div>}
        {/* Scenario Selector */}
        <div>
          <label className="text-[10px] text-soc-muted block mb-1 font-mono uppercase tracking-wider">Kịch bản (Scenario):</label>
          <select
            aria-label="Kịch bản"
            disabled={isLoading}
            value={selectedScenario}
            onChange={(e) => onSelectScenario(e.target.value)}
            className="w-full bg-black/30 border rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-medium"
            style={{ borderColor: 'var(--border-glass)' }}
          >
            {experimental ? Object.entries({
              'purplesharp-ad': '3.3.1 Kịch bản brute force và đăng nhập bất thường',
              'mshta-powershell': '3.3.2 Kịch bản thực thi PowerShell nghi vấn',
              'regsvr32-c2': '3.3.3 Kịch bản kết nối mạng bất thường hoặc nghi vấn C2'
            }).map(([id, name]) =>
              <option key={id} value={id} className="bg-gray-900 text-white">{name}</option>) : scenarios.map((s) => (
              <option key={s.scenario_id} value={s.scenario_id} className="bg-gray-900 text-white">
                {s.name} ({s.node_count} nodes, {s.chunk_count} chunks)
              </option>
            ))}
          </select>
        </div>

        {experimental ? <div className="space-y-1 text-[10px]" data-testid="experimental-controls">
          <label className="block">Cấu hình artifacts
            <select aria-label="Cấu hình artifacts" disabled={isLoading} value={experimental.configuration?.profile_id || ''}
              onChange={e => experimental.onProfileChange?.(e.target.value)} className="w-full bg-gray-900 text-white rounded p-1">
              {(experimental.configuration?.artifact_profiles || []).map((p: any) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
          </label>
          <p>{experimental.configuration?.mode === 'historical_replay_only' ? 'Checkpoint lịch sử · saved replay only' : 'Integrated research draft · human review pending'}</p>
          <p className="text-cyan-400" data-testid="execution-mode">{experimental.configuration?.mode === 'experimental_live_demo'
            ? experimental.liveEnabled ? 'LIVE đã bật rõ ràng' : 'Live chưa bật tại dashboard — chưa gửi hunt'
            : 'Offline · 0 request LLM'}</p>
          <label className="flex items-center gap-2">
            <input aria-label="Bật Live" type="checkbox" checked={experimental.liveEnabled}
              disabled={isLoading || experimental.configuration?.mode !== 'experimental_live_demo'}
              onChange={e => experimental.onLiveChange(e.target.checked)} />
            Bật Live (cần service khởi động --live với request cap)
          </label>
          <p>Requests session: {experimental.configuration?.llm_http_attempts ?? 0}/{experimental.configuration?.maximum_llm_requests ?? 0} · không tự retry/fallback</p>
          {experimental.configuration?.stopped_reason && <p role="alert" className="text-amber-400">Session đã dừng: {experimental.configuration.stopped_reason}</p>}
          <ExperimentalDetails title="Cấu hình kỹ thuật" value={experimental.configuration} />
        </div> : <details className="text-[10px]">
        <summary className="cursor-pointer text-soc-muted">Cấu hình kỹ thuật</summary>
        <div className="flex items-center justify-between text-xs pt-2">
          <label className="flex items-center gap-1.5 cursor-pointer text-gray-300 hover:text-white">
            <input
              type="checkbox"
              checked={enforceGate}
              onChange={(e) => setEnforceGate(e.target.checked)}
              className="rounded bg-black/40 border-gray-700 text-cyan-400 focus:ring-0"
            />
            <span className="text-[11px] font-mono">Two-Stage Gate</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-gray-300 hover:text-white">
            <input
              type="checkbox"
              checked={useLLM}
              onChange={(e) => setUseLLM(e.target.checked)}
              className="rounded bg-black/40 border-gray-700 text-cyan-400 focus:ring-0"
            />
            <span className="text-[11px] font-mono flex items-center gap-1">
              <SparklesIcon className="w-3 h-3 text-cyan-400" /> Grounded LLM
            </span>
          </label>
        </div>
        </details>}
      </div>

      {/* Messages Feed */}
      <div className="flex-1 min-h-0 overflow-y-auto p-3.5 space-y-3.5 text-xs" data-testid="chat-feed">
        {experimental && <>
          {experimental.error && <p role="alert" className="text-rose-400 break-words">{experimental.error}</p>}
          {experimental.response ? <ExperimentalResult response={experimental.response} /> : !isLoading &&
            <p className="text-soc-muted">Nhập câu hỏi tự do. Presets chỉ là gợi ý; bản nháp vẫn cần human review.</p>}
        </>}
        {!experimental && messages.map((m) => (
          <div
            key={m.id}
            className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="text-[10px] font-mono text-soc-muted mb-1 flex items-center gap-1">
              <span>{m.sender === 'user' ? 'Analyst' : 'Threat Hunter Co-Pilot'}</span>
              <span>•</span>
              <span>{m.timestamp}</span>
            </div>

            <div
              className={`max-w-[92%] rounded-xl p-3 border leading-relaxed ${
                m.sender === 'user'
                  ? 'bg-cyan-950/60 border-cyan-500/40 text-cyan-100 shadow-sm'
                  : 'glass-card text-gray-200 shadow-sm'
              }`}
              style={{ borderColor: m.sender === 'user' ? undefined : 'var(--border-glass)' }}
            >
              <div>{m.text}</div>
              {m.response?.replay && (
                <div className="mt-2 text-[10px] text-amber-300 break-all">REPLAY/MOCK · {m.response.replay.mode} · {m.response.replay.source_file} · Không gọi API LLM.</div>
              )}

              {/* Forensic Report Card */}
              {m.response && m.response.status !== 'abstained' && (
                <div className="mt-3 pt-2.5 border-t space-y-2.5" style={{ borderColor: 'var(--border-glass)' }}>
                  {/* Gate Badge */}
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-1 text-emerald-400 font-mono font-medium">
                      <CheckCircleIcon className="w-3.5 h-3.5" /> Gate: {m.response.execution?.gate_enforced === false ? 'DISABLED' : m.response.gate_decision?.decision === 'proceed' ? 'PROCEED' : 'CHƯA ĐÁNH GIÁ'}
                    </span>
                    {m.response.subgraph && (
                      <span className="text-[10px] font-mono text-soc-muted">
                        Subgraph: {m.response.subgraph.node_count} nodes
                      </span>
                    )}
                  </div>

                  {m.response.provider_error && (
                    <div className="p-2 rounded border border-rose-800 text-rose-300 text-[11px]">
                      Provider: {m.response.provider_error.kind} (HTTP {m.response.provider_error.http_status ?? 'unknown'}) · {m.response.execution?.fallback_used ? 'Offline Fallback' : 'Chưa có câu trả lời LLM'} · Không phải kết luận thiếu bằng chứng.
                      {m.response.provider_error.retry_after_seconds != null && <div>Retry-After: {m.response.provider_error.retry_after_seconds}s · Không tự retry tại giao diện.</div>}
                    </div>
                  )}
                  {m.response.validation && (
                    <div className="p-2 rounded border border-amber-800 text-amber-300 text-[11px]">
                      Validation: {m.response.validation.status}. Phạm vi: {m.response.validation.scope}. Narrative và verdict là bản nháp chưa được người dùng duyệt.
                    </div>
                  )}
                  {/* LLM or explicitly identified offline draft */}
                  {isRejected(m.response) ? (
                    <div role="alert" className="p-2 rounded border border-rose-800 text-rose-300 text-[11px] space-y-1">
                      <div>Output bị từ chối. Chưa có câu trả lời được chấp nhận cho request này.</div>
                      {m.response.validation?.issues?.map((issue, index) => (
                        <div key={index}>{issue.code}: {issue.reason || 'Xem diagnostic JSON để biết chi tiết.'}</div>
                      ))}
                      <button onClick={() => downloadJsonReport(m.response!)} className="text-cyan-400 underline">
                        Tải diagnostic JSON (rejected output)
                      </button>
                    </div>
                  ) : m.response.report ? (
                    <div className="bg-black/40 border rounded-lg p-2.5 space-y-2" style={{ borderColor: 'var(--border-glass)' }}>
                      <div className="flex items-center justify-between">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase ${
                            m.response.report.verdict === 'MALICIOUS'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : m.response.report.verdict === 'SUSPICIOUS'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-gray-800 text-gray-300'
                          }`}
                        >
                          {m.response.report.verdict ?? 'CHƯA ĐÁNH GIÁ'}
                        </span>

                        <div className="flex gap-2">
                          {canExportAcceptedDraft(m.response) && <button
                            onClick={() => downloadMarkdownReport(m.response!)}
                            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[10px] font-mono transition"
                            title="Tải báo cáo điều tra Markdown"
                          >
                            <DownloadIcon className="w-3 h-3" /> Xuất MD (draft)
                          </button>}
                          <button
                            onClick={() => downloadJsonReport(m.response!)}
                            className="text-gray-400 hover:text-white flex items-center gap-1 text-[10px] font-mono transition"
                            title="Tải dữ liệu JSON"
                          >
                            <DownloadIcon className="w-3 h-3" /> {canExportAcceptedDraft(m.response) ? 'JSON (draft)' : 'Diagnostic JSON'}
                          </button>
                        </div>
                      </div>

                      {/* Direct Short Answer from AI */}
                      {m.response.report.direct_answer ? (
                        <div className="bg-cyan-950/40 border border-cyan-500/30 rounded-lg p-2 text-cyan-200 text-[11px] leading-relaxed">
                          <div className="flex items-center gap-1.5 font-semibold text-cyan-400 text-[10px] font-mono mb-1">
                            <SparklesIcon className="w-3.5 h-3.5" /> Bản nháp từ nguồn ({m.response.report.ai_engine || 'chưa xác định'}):
                          </div>
                          <div className="font-medium text-white">{m.response.report.direct_answer}</div>
                        </div>
                      ) : (
                        <div className="text-[11px] font-medium text-white leading-normal">
                          {m.response.report.executive_summary}
                        </div>
                      )}

                      {/* Toggle Details Button */}
                      <div className="pt-1 flex justify-end">
                        <button
                          type="button"
                          onClick={() => setShowDetailsMap(prev => ({ ...prev, [m.id]: !prev[m.id] }))}
                          className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          {showDetailsMap[m.id] ? "▲ Thu gọn chi tiết kỹ thuật" : "▼ Xem chi tiết chuỗi tấn công & MITRE"}
                        </button>
                      </div>

                      {/* Collapsible Details */}
                      {showDetailsMap[m.id] && (
                        <div className="pt-2 border-t space-y-2" style={{ borderColor: 'var(--border-glass)' }}>
                          {m.response.report.evidence_refs?.map((reference) => (
                            <div key={reference} className="text-[10px] text-cyan-300 break-all">Citation: {reference}</div>
                          ))}
                          {m.response.validation?.reference_checks?.map((check) => (
                            <div key={check.reference} className="text-[10px] text-amber-300 break-all">
                              Reference: {check.reference} · {check.status}
                            </div>
                          ))}
                          {/* Attack Chain */}
                          {(m.response.report.attack_chain?.length ?? 0) > 0 && (
                            <div className="space-y-1.5">
                              <span className="text-[10px] text-soc-muted uppercase font-mono font-semibold block">
                                Chuỗi Tấn Công (Attack Chain):
                              </span>
                              {m.response.report.attack_chain?.map((step) => (
                                <div
                                  key={step.step_number}
                                  className="text-[10px] font-mono bg-black/40 p-2 rounded-md flex flex-col gap-0.5 border"
                                  style={{ borderColor: 'var(--border-glass)' }}
                                >
                                  <div className="text-cyan-400 font-semibold">
                                    #{step.step_number}. {step.source_entity} ➔ {step.target_entity}
                                  </div>
                                  <div className="text-gray-400">Action: {step.action}</div>
                                  <div className="text-[9px] text-emerald-400">Ref: {step.evidence_ref}</div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* MITRE Mapping */}
                          {(m.response.report.mitre_mappings?.length ?? 0) > 0 && (
                            <div className="flex flex-wrap gap-1 pt-1">
                              {m.response.report.mitre_mappings?.map((mitre) => (
                                <span
                                  key={mitre.technique_id}
                                  className="px-1.5 py-0.5 rounded text-[10px] bg-rose-950/80 text-rose-300 border border-rose-900 font-mono"
                                  title={mitre.rationale}
                                >
                                  {mitre.technique_id} ({mitre.technique_name}) · {mitre.evidence_support || mitre.confidence} · {mitre.assessment_status || 'chưa duyệt'}
                                </span>
                              ))}
                            </div>
                          )}

                          {/* Unverified Claims */}
                          {(m.response.report.unverified_claims?.length ?? 0) > 0 && (
                            <div className="p-2 rounded bg-amber-950/30 border border-amber-900/60 text-[10px] text-amber-300 space-y-0.5">
                              <span className="font-semibold flex items-center gap-1 font-mono">
                                <AlertTriangleIcon className="w-3 h-3" /> Giới hạn bằng chứng (Unverified):
                              </span>
                              <ul className="list-disc list-inside">
                                {m.response.report.unverified_claims?.map((claim, idx) => (
                                  <li key={idx}>{claim}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ) : (
                    /* Fallback to raw retrieval hits */
                    <div className="space-y-1.5">
                      <span className="text-[10px] text-soc-muted font-mono block">Các đoạn tri thức truy xuất:</span>
                      {(m.response.retrieval_hits || []).slice(0, 3).map((h, i) => (
                        <div key={i} className="p-2 bg-black/40 rounded-md text-[10px] text-gray-300 font-mono border" style={{ borderColor: 'var(--border-glass)' }}>
                          <span className="text-cyan-400 font-semibold">[{h.chunk_type}]</span> {h.content?.slice(0, 160)}...
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Gate Rejection Alert */}
              {m.response && m.response.status === 'abstained' && (
                <div className="mt-2.5 p-2.5 bg-rose-950/40 border border-rose-900 rounded-lg text-rose-300 text-[11px] flex items-start gap-2">
                  <ShieldIcon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold font-mono">Truy vấn bị từ chối bởi gate ({m.response.gate_decision?.abstention_stage || 'chưa rõ'})</div>
                    <div className="text-[10px] text-rose-200/80 mt-0.5">
                      {m.response.reason || 'Câu hỏi thiếu bằng chứng log hoặc nằm ngoài phạm vi.'}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
        {isLoading && (
          <div role="status" className="flex items-center gap-2 text-soc-muted text-xs p-2 font-mono">
            <span className="animate-spin text-cyan-400">⏳</span>
            <span>Đang truy xuất đồ thị và phân tích bằng chứng...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts (Collapsible with Toggle button) */}
      <div className="border-t bg-black/20" style={{ borderColor: 'var(--border-glass)' }}>
        <div className="px-3.5 py-1.5 flex items-center justify-between">
          <span className="text-[10px] text-soc-muted font-mono uppercase tracking-wider font-semibold">Gợi ý truy vấn nhanh</span>
          <button
            type="button"
            onClick={() => setShowSuggestions((prev) => !prev)}
            className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/30 hover:bg-black/50 text-cyan-400 border transition flex items-center gap-1"
            style={{ borderColor: 'var(--border-glass)' }}
          >
            {showSuggestions ? "▲ Ẩn gợi ý" : "▼ Hiện gợi ý"}
          </button>
        </div>

        {showSuggestions && (
          <div className="px-3.5 pb-2.5 flex flex-wrap gap-1 max-h-48 overflow-y-auto">
            {experimental ? (experimental.configuration?.presets || []).map(preset => <button key={preset.case_id}
              disabled={isLoading} onClick={() => experimental.onPreset(preset)}
              className="text-[10px] bg-black/30 px-2 py-1 rounded-md border text-left break-words">
              Gợi ý {preset.case_id}: {preset.query}
            </button>) : (quickQueries[selectedScenario] || []).map((q, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(q)}
                className="text-[10px] bg-black/30 hover:bg-black/50 text-gray-300 hover:text-white px-2 py-1 rounded-md transition border font-mono truncate max-w-full text-left"
                style={{ borderColor: 'var(--border-glass)' }}
              >
                {q}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-3 border-t bg-black/30" style={{ borderColor: 'var(--border-glass)' }}>
        {experimental && experimental.configuration?.presets.filter(preset => preset.query === experimental.query.trim() && preset.scenario_id === selectedScenario).map(preset =>
          <button key={preset.case_id} disabled={isLoading} onClick={() => experimental.onReplay(preset)}
            className="text-[10px] text-amber-400 underline mb-2">Xem bản lưu {preset.case_id} · replay · 0 LLM mới</button>)}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex gap-2"
        >
          <input
            aria-label="Câu hỏi"
            type="text"
            value={experimental ? experimental.query : query}
            disabled={isLoading}
            maxLength={experimental ? 12000 : undefined}
            onChange={(e) => experimental ? experimental.onQueryChange(e.target.value) : setQuery(e.target.value)}
            placeholder="Nhập câu hỏi điều tra an toàn thông tin..."
            className="flex-1 min-w-0 bg-black/40 border rounded-xl px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-medium"
            style={{ borderColor: 'var(--border-glass)' }}
          />
          <button
            type="submit"
            disabled={isLoading || !(experimental ? experimental.query : query).trim() || !!experimental && !experimental.configuration}
            className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold px-3.5 py-2 rounded-xl text-xs flex items-center gap-1.5 transition font-mono shadow-sm"
          >
            <SendIcon className="w-3.5 h-3.5" />
            <span>{experimental ? experimental.liveEnabled ? 'Gửi Live' : 'Gửi offline' : 'Gửi'}</span>
          </button>
        </form>
      </div>
    </div>
  );
};
