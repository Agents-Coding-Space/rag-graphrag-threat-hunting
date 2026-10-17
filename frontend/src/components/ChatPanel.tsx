import React, { useState } from 'react';
import { TerminalIcon, SendIcon, DownloadIcon, CheckCircleIcon, AlertTriangleIcon, SparklesIcon, ShieldIcon } from './SvgIcons';
import { HuntResponse, ScenarioInfo, ThreatReport } from '../types';

interface Props {
  scenarios: ScenarioInfo[];
  selectedScenario: string;
  onSelectScenario: (scenId: string) => void;
  onHunt: (query: string, enforceGate: boolean, useLLM: boolean) => Promise<HuntResponse | null>;
  isLoading: boolean;
  theme: 'dark' | 'light';
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
}) => {
  const [query, setQuery] = useState('');
  const [enforceGate, setEnforceGate] = useState(true);
  const [useLLM, setUseLLM] = useState(true);
  const [messages, setMessages] = useState<ChatMessage[]>([
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
    const q = (textToSend || query).trim();
    if (!q || isLoading) return;

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
        text: res.status === 'proceed' ? 'Đã truy xuất và phân tích thành công chuỗi bằng chứng.' : `Yêu cầu bị từ chối: ${res.reason || 'Không đủ dữ kiện'}`,
        response: res,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, botMsg]);
    }
  };

  const downloadJsonReport = (report: ThreatReport) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-report-${selectedScenario}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = (res: HuntResponse) => {
    const report = res.report;
    const lines = [
      `# BÁO CÁO PHÁP Y ĐIỀU TRA MỐI ĐE DỌA AN TOÀN THÔNG TIN`,
      `**Kịch bản:** ${res.scenario_id}  `,
      `**Truy vấn của chuyên viên:** "${res.query}"  `,
      `**Thời gian lập báo cáo (UTC):** ${new Date().toISOString()}  `,
      `**Trạng thái Two-Stage Gate:** ${res.status.toUpperCase()}  `,
      ``,
      `---`,
      `## 1. KẾT LUẬN ĐIỀU HÀNH (EXECUTIVE VERDICT)`,
      `**Đánh giá:** ${report?.verdict || 'SUSPICIOUS'}  `,
      `**Tóm tắt:** ${report?.executive_summary || 'Đã ghi nhận chuỗi sự kiện bất thường từ log.'}`,
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
        lines.push(`- **${m.technique_id} - ${m.technique_name}** (Mức tin cậy: ${m.confidence})`);
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
    lines.push(`---`);
    lines.push(`*Báo cáo được trích xuất tự động từ Hệ thống SOC Threat Hunting Workbench (RAG + GraphRAG + LLM).*`);

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-report-${res.scenario_id}-${Date.now()}.md`;
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
            GraphRAG
          </span>
        </div>

        {/* Scenario Selector */}
        <div>
          <label className="text-[10px] text-soc-muted block mb-1 font-mono uppercase tracking-wider">Kịch bản (Scenario):</label>
          <select
            value={selectedScenario}
            onChange={(e) => onSelectScenario(e.target.value)}
            className="w-full bg-black/30 border rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-medium"
            style={{ borderColor: 'var(--border-glass)' }}
          >
            {scenarios.map((s) => (
              <option key={s.scenario_id} value={s.scenario_id} className="bg-gray-900 text-white">
                {s.name} ({s.node_count} nodes, {s.chunk_count} chunks)
              </option>
            ))}
          </select>
        </div>

        {/* Toggles */}
        <div className="flex items-center justify-between text-xs pt-0.5">
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
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5 text-xs">
        {messages.map((m) => (
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

              {/* Forensic Report Card */}
              {m.response && m.response.status === 'proceed' && (
                <div className="mt-3 pt-2.5 border-t space-y-2.5" style={{ borderColor: 'var(--border-glass)' }}>
                  {/* Gate Badge */}
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-1 text-emerald-400 font-mono font-medium">
                      <CheckCircleIcon className="w-3.5 h-3.5" /> Gate: PASSED
                    </span>
                    {m.response.subgraph && (
                      <span className="text-[10px] font-mono text-soc-muted">
                        Subgraph: {m.response.subgraph.node_count} nodes
                      </span>
                    )}
                  </div>

                  {/* LLM Threat Report */}
                  {m.response.report ? (
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
                          {m.response.report.verdict}
                        </span>

                        <div className="flex gap-2">
                          <button
                            onClick={() => downloadMarkdownReport(m.response!)}
                            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[10px] font-mono transition"
                            title="Tải báo cáo điều tra Markdown"
                          >
                            <DownloadIcon className="w-3 h-3" /> Xuất MD
                          </button>
                          <button
                            onClick={() => downloadJsonReport(m.response!.report!)}
                            className="text-gray-400 hover:text-white flex items-center gap-1 text-[10px] font-mono transition"
                            title="Tải dữ liệu JSON"
                          >
                            <DownloadIcon className="w-3 h-3" /> JSON
                          </button>
                        </div>
                      </div>

                      <div className="text-[11px] font-medium text-white leading-normal">
                        {m.response.report.executive_summary}
                      </div>

                      {/* Attack Chain */}
                      {(m.response.report.attack_chain?.length ?? 0) > 0 && (
                        <div className="pt-2 border-t space-y-1.5" style={{ borderColor: 'var(--border-glass)' }}>
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
                              {mitre.technique_id} ({mitre.technique_name})
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
                    <div className="font-semibold font-mono">Truy vấn bị từ chối bởi Two-Stage Gate</div>
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
          <div className="flex items-center gap-2 text-soc-muted text-xs p-2 font-mono">
            <span className="animate-spin text-cyan-400">⏳</span>
            <span>Đang truy xuất đồ thị và phân tích bằng chứng...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts */}
      <div className="px-3.5 py-2 border-t bg-black/20" style={{ borderColor: 'var(--border-glass)' }}>
        <span className="text-[10px] text-soc-muted font-mono block mb-1">Gợi ý truy vấn nhanh:</span>
        <div className="flex flex-wrap gap-1">
          {(quickQueries[selectedScenario] || []).map((q, idx) => (
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
      </div>

      {/* Input Area */}
      <div className="p-3 border-t bg-black/30" style={{ borderColor: 'var(--border-glass)' }}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Nhập câu hỏi điều tra an toàn thông tin..."
            className="flex-1 bg-black/40 border rounded-xl px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-medium"
            style={{ borderColor: 'var(--border-glass)' }}
          />
          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold px-3.5 py-2 rounded-xl text-xs flex items-center gap-1.5 transition font-mono shadow-sm"
          >
            <SendIcon className="w-3.5 h-3.5" />
            <span>Gửi</span>
          </button>
        </form>
      </div>
    </div>
  );
};
