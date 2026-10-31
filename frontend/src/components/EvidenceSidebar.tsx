import React from 'react';
import { DatabaseIcon, ShieldIcon, CheckCircleIcon } from './SvgIcons';
import { EvidenceItem } from '../types';
import { ExperimentalResponse } from '../experimentalState';
import { ExperimentalDetails } from './ExperimentalResult';

interface Props {
  selectedNode: any | null;
  evidenceItems: EvidenceItem[];
  theme: 'dark' | 'light';
  experimental?: { response: ExperimentalResponse | null };
}

export const EvidenceSidebar: React.FC<Props> = ({ selectedNode, evidenceItems, theme, experimental }) => {
  return (
    <div className="flex flex-col h-full glass-panel border-r overflow-hidden transition-colors duration-200">
      {/* Header */}
      <div className="p-3.5 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-glass)' }}>
        <div className="flex items-center gap-2">
          <DatabaseIcon className="w-4 h-4 text-cyan-400" />
          <h2 className="font-semibold text-xs tracking-wider uppercase font-mono">PHÁP Y & BẰNG CHỨNG</h2>
        </div>
        {selectedNode && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase font-semibold">
            {selectedNode.type}
          </span>
        )}
      </div>

      {/* Content Body */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-4 text-xs">
        {experimental ? <div className="space-y-3 select-text" data-testid="experimental-evidence">
          <p className="text-soc-muted text-[10px]">Evidence từ response hiện tại · không phải toàn bộ scenario.</p>
          {!experimental.response && <p>Gửi câu hỏi để xem bằng chứng của lượt này.</p>}
          {experimental.response && <>
            <p className="text-cyan-400 break-words">{experimental.response.request.query}</p>
            <p className="text-[10px] break-all">{experimental.response.provenance.mode} · {experimental.response.request.branch.toUpperCase()}</p>
            {experimental.response.outcome === 'abstain' && <p className="text-amber-400">Query abstain. Context truy xuất dưới đây chưa đủ để tạo câu trả lời.</p>}
            {selectedNode && <ExperimentalDetails title={`Thực thể đã chọn: ${selectedNode.label}`} value={selectedNode} />}
            {!(experimental.response.evidence_contract?.units || []).length && <p>Response này không có evidence units.</p>}
            {(experimental.response.evidence_contract?.units || []).map((unit: any, index: number) => <div
              key={`${unit.origin.kind}-${unit.origin.item_id}-${index}`} className="glass-card border rounded-xl p-3 space-y-2" data-testid="evidence-unit">
              <p className="font-mono text-[10px] text-cyan-400 break-all">{unit.origin.kind} · {unit.origin.item_id}</p>
              <p className="text-[10px]">{unit.status} · {unit.source.json_pointer || 'Không có pointer'}</p>
              <p className="font-semibold text-amber-300">{unit.evidence_layer === 'cti_context' ? 'CTI report · bối cảnh bên ngoài' : unit.evidence_layer === 'inferred_correlation' ? 'Correlation · inferred' : unit.evidence_layer || 'Nguồn từ context'}</p>
              {unit.evidence_layer === 'cti_context' && (() => {
                const source = unit.properties?.source_object?.attributes || unit.properties?.attributes || unit.properties;
                return source?.publisher && <div className="text-[10px] space-y-1">
                  <p>{source.publisher} · {source.publication_date || 'Ngày công bố chưa có'} · accessed {source.accessed_at || 'chưa có'}</p>
                  {typeof source.url === 'string' && /^https?:\/\//.test(source.url) && <a href={source.url} target="_blank" rel="noreferrer"
                    className="text-cyan-400 underline break-all">Nguồn CTI: {source.url}</a>}
                </div>;
              })()}
              <p className="whitespace-pre-wrap break-words text-[11px]">{unit.text}</p>
              {(unit.source_references || []).map((ref: any, i: number) => <p className="text-[10px] font-mono break-all" key={i}>{ref.source_file} · {ref.raw_record_ref}</p>)}
              <ExperimentalDetails title="Original fields và source provenance" value={{ ...unit,
                source_ground_truth: experimental.response?.evidence_contract?.source_ground_truth }} />
            </div>)}
            <ExperimentalDetails title="Supplied context của lượt này" value={experimental.response.context} />
          </>}
        </div> : selectedNode ? (
          <div className="space-y-4">
            {/* Selected Node Card */}
            <div className="glass-card border rounded-xl p-3 space-y-2.5">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse" />
                <span className="font-semibold text-sm truncate">{selectedNode.label}</span>
              </div>

              <div>
                <span className="text-[10px] text-soc-muted block mb-0.5 uppercase tracking-wider font-mono">Định danh (Node ID):</span>
                <code className="text-[10px] text-cyan-400 bg-black/30 px-2 py-1 rounded block break-all font-mono border" style={{ borderColor: 'var(--border-glass)' }}>
                  {selectedNode.id}
                </code>
              </div>

              {selectedNode.properties && (
                <div>
                  <span className="text-[10px] text-soc-muted block mb-1 uppercase tracking-wider font-mono">Thuộc tính (Attributes):</span>
                  <div className="bg-black/30 border rounded-lg p-2 space-y-1 font-mono text-[10px]" style={{ borderColor: 'var(--border-glass)' }}>
                    {Object.entries(selectedNode.properties).map(([k, v]) => {
                      if (typeof v === 'object') return null;
                      return (
                        <div key={k} className="flex flex-col">
                          <span className="text-gray-400">{k}:</span>
                          <span className="text-gray-200 break-all font-medium">{String(v)}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Related Evidence Records (RLESS Process Card style) */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-soc-muted uppercase tracking-wider">
                <span className="flex items-center gap-1.5 font-semibold">
                  <ShieldIcon className="w-3.5 h-3.5 text-emerald-400" /> Bằng chứng scenario ({evidenceItems.length})
                </span>
              </div>

              <div className="space-y-2">
                {evidenceItems.map((ev) => (
                  <div key={ev.evidence_id} className="glass-card border rounded-xl p-3 space-y-2 hover:border-cyan-500/40 transition">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400" />
                        <span className="font-mono font-semibold text-cyan-400 text-[11px]">{ev.evidence_id}</span>
                      </div>
                      <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
                        <CheckCircleIcon className="w-3 h-3" /> {ev.status}
                      </span>
                    </div>

                    <div className="text-[11px] leading-relaxed text-gray-200">{ev.summary}</div>

                    {/* Progress Bar Mini decoration */}
                    <div className="w-full bg-gray-800/80 h-1 rounded-full overflow-hidden">
                      <div className="bg-cyan-500 h-full rounded-full w-2/3" />
                    </div>

                    {/* Observations details */}
                    {ev.observations.length > 0 && (
                      <div className="pt-2 border-t space-y-1.5" style={{ borderColor: 'var(--border-glass)' }}>
                        <span className="text-[10px] text-soc-muted font-mono block">Nhật ký quan sát (Observations):</span>
                        {ev.observations.map((obs, idx) => (
                          <div key={idx} className="bg-black/40 border px-2 py-1.5 rounded-md text-[10px] font-mono text-gray-300 space-y-0.5" style={{ borderColor: 'var(--border-glass)' }}>
                            <div className="flex justify-between">
                              <span>Event ID: <strong className="text-white">{obs.event_id}</strong></span>
                              <span className="text-cyan-400">{obs.raw_record_ref}</span>
                            </div>
                            <div className="text-gray-400 truncate">{obs.provider}</div>
                            <div className="text-gray-400 break-all">{obs.source_file}</div>
                            {obs.timestamp && <div className="text-[9px] text-gray-500">{obs.timestamp}</div>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center text-soc-muted p-6 space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-1">
              <DatabaseIcon className="w-6 h-6 text-cyan-400" />
            </div>
            <p className="text-xs font-semibold text-gray-300">Chưa chọn thực thể</p>
            <p className="text-[11px] text-gray-500 leading-relaxed max-w-[200px]">
              Nhấp vào một nút trên đồ thị để xem chi tiết bản ghi log và bằng chứng pháp y.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
