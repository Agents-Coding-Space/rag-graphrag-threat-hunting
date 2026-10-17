import React, { useState } from 'react';
import { Send, ShieldAlert, CheckCircle, AlertTriangle, Cpu, Terminal, Download, Sparkles } from 'lucide-react';
import { HuntResponse, ScenarioInfo, ThreatReport } from '../types';

interface Props {
  scenarios: ScenarioInfo[];
  selectedScenario: string;
  onSelectScenario: (scenId: string) => void;
  onHunt: (query: string, enforceGate: boolean, useLLM: boolean) => Promise<HuntResponse | null>;
  isLoading: boolean;
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
        text: res.status === 'proceed' ? 'Đã truy xuất và phân tích thành công bằng chứng.' : `Yêu cầu bị từ chối: ${res.reason || 'Không đủ dữ kiện'}`,
        response: res,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, botMsg]);
    }
  };

  const downloadReport = (report: ThreatReport) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full bg-soc-card border-r border-soc-border overflow-hidden">
      {/* Scenario & Config Header */}
      <div className="p-4 border-b border-soc-border space-y-3 bg-[#0E1422]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-soc-accent" />
            <h1 className="font-bold text-sm tracking-wide">SOC THREAT HUNTING CHAT</h1>
          </div>
          <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded-full flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            GraphRAG Ready
          </span>
        </div>

        {/* Scenario Selector */}
        <div>
          <label className="text-[11px] text-soc-muted block mb-1 font-medium">Kịch bản điều tra (Scenario):</label>
          <select
            value={selectedScenario}
            onChange={(e) => onSelectScenario(e.target.value)}
            className="w-full bg-gray-900 border border-soc-border rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-soc-accent"
          >
            {scenarios.map((s) => (
              <option key={s.scenario_id} value={s.scenario_id}>
                {s.name} ({s.node_count} nodes, {s.chunk_count} chunks)
              </option>
            ))}
          </select>
        </div>

        {/* Gate & LLM Toggles */}
        <div className="flex items-center justify-between text-xs pt-1">
          <label className="flex items-center gap-1.5 cursor-pointer text-gray-300 hover:text-white">
            <input
              type="checkbox"
              checked={enforceGate}
              onChange={(e) => setEnforceGate(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-soc-accent focus:ring-0"
            />
            <span className="text-[11px]">Bật Two-Stage Gate</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-gray-300 hover:text-white">
            <input
              type="checkbox"
              checked={useLLM}
              onChange={(e) => setUseLLM(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-soc-accent focus:ring-0"
            />
            <span className="text-[11px] flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-400" /> Grounded LLM
            </span>
          </label>
        </div>
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="text-[10px] text-soc-muted mb-1 flex items-center gap-1">
              <span>{m.sender === 'user' ? 'Analyst' : 'Threat Hunter AI'}</span>
              <span>•</span>
              <span>{m.timestamp}</span>
            </div>

            <div
              className={`max-w-[90%] rounded-lg p-3 ${
                m.sender === 'user'
                  ? 'bg-cyan-950/60 border border-cyan-800 text-cyan-100'
                  : 'bg-gray-900/90 border border-soc-border text-gray-200'
              }`}
            >
              <div className="leading-relaxed">{m.text}</div>

              {/* Forensic Report Card */}
              {m.response && m.response.status === 'proceed' && (
                <div className="mt-3 pt-3 border-t border-gray-800 space-y-2.5">
                  {/* Gate Badge */}
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-1 text-soc-success font-medium">
                      <CheckCircle className="w-3.5 h-3.5" /> Two-Stage Gate: PASSED
                    </span>
                    {m.response.subgraph && (
                      <span className="text-[10px] text-soc-muted">
                        Traversed Subgraph: {m.response.subgraph.node_count} nodes
                      </span>
                    )}
                  </div>

                  {/* LLM Threat Report */}
                  {m.response.report ? (
                    <div className="bg-black/40 border border-gray-800 rounded p-2.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                            m.response.report.verdict === 'MALICIOUS'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : m.response.report.verdict === 'SUSPICIOUS'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-gray-800 text-gray-300'
                          }`}
                        >
                          {m.response.report.verdict}
                        </span>

                        <button
                          onClick={() => downloadReport(m.response!.report!)}
                          className="text-soc-muted hover:text-white flex items-center gap-1 text-[10px] transition"
                        >
                          <Download className="w-3 h-3" /> Xuất JSON
                        </button>
                      </div>

                      <div className="text-[11px] font-medium text-white">
                        {m.response.report.executive_summary}
                      </div>

                      {/* Attack Chain */}
                      {m.response.report.attack_chain.length > 0 && (
                        <div className="pt-2 border-t border-gray-800 space-y-1.5">
                          <span className="text-[10px] text-soc-muted uppercase font-semibold block">
                            Chuỗi Tấn Công (Attack Chain):
                          </span>
                          {m.response.report.attack_chain.map((step) => (
                            <div
                              key={step.step_number}
                              className="text-[10px] font-mono bg-gray-900/80 p-1.5 rounded flex flex-col gap-0.5 border border-gray-800"
                            >
                              <div className="text-soc-accent">
                                #{step.step_number}. {step.source_entity} ➔ {step.target_entity}
                              </div>
                              <div className="text-gray-400">Action: {step.action}</div>
                              <div className="text-[9px] text-emerald-400">Ref: {step.evidence_ref}</div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* MITRE Mapping */}
                      {m.response.report.mitre_mappings.length > 0 && (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {m.response.report.mitre_mappings.map((mitre) => (
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
                      {m.response.report.unverified_claims.length > 0 && (
                        <div className="p-2 rounded bg-amber-950/20 border border-amber-900/50 text-[10px] text-amber-300 space-y-0.5">
                          <span className="font-semibold flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" /> Giới hạn bằng chứng (Unverified):
                          </span>
                          <ul className="list-disc list-inside">
                            {m.response.report.unverified_claims.map((claim, idx) => (
                              <li key={idx}>{claim}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ) : (
                    /* Fallback to raw retrieval hits */
                    <div className="space-y-1.5">
                      <span className="text-[10px] text-soc-muted block">Các đoạn tri thức truy xuất:</span>
                      {m.response.retrieval_hits.slice(0, 3).map((h, i) => (
                        <div key={i} className="p-2 bg-black/40 rounded text-[10px] text-gray-300 font-mono">
                          <span className="text-soc-accent font-semibold">[{h.chunk_type}]</span> {h.content.slice(0, 160)}...
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Gate Rejection Alert */}
              {m.response && m.response.status === 'abstained' && (
                <div className="mt-2.5 p-2.5 bg-rose-950/40 border border-rose-900 rounded text-rose-300 text-[11px] flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold">Truy vấn bị từ chối bởi Two-Stage Gate</div>
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
          <div className="flex items-center gap-2 text-soc-muted text-xs p-2">
            <Cpu className="w-4 h-4 animate-spin text-soc-accent" />
            <span>Đang truy xuất đồ thị và phân tích bằng chứng...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts */}
      <div className="px-4 py-2 border-t border-soc-border bg-gray-900/50">
        <span className="text-[10px] text-soc-muted block mb-1">Gợi ý câu hỏi nhanh:</span>
        <div className="flex flex-wrap gap-1.5">
          {(quickQueries[selectedScenario] || []).map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(q)}
              className="text-[10px] bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white px-2 py-1 rounded transition border border-gray-700 text-left truncate max-w-full"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-soc-border bg-[#0E1422]">
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
            className="flex-1 bg-gray-900 border border-soc-border rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent"
          />
          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="bg-soc-accent hover:bg-cyan-500 disabled:opacity-50 text-black font-semibold px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Gửi</span>
          </button>
        </form>
      </div>
    </div>
  );
};
