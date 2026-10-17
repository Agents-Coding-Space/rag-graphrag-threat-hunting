import React from 'react';
import { Shield, FileText, Activity, AlertCircle, Database, CheckCircle2 } from 'lucide-react';
import { EvidenceItem } from '../types';

interface Props {
  selectedNode: any | null;
  evidenceItems: EvidenceItem[];
}

export const EvidenceSidebar: React.FC<Props> = ({ selectedNode, evidenceItems }) => {
  return (
    <div className="flex flex-col h-full bg-soc-card border-l border-soc-border overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-soc-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Database className="w-5 h-5 text-soc-accent" />
          <h2 className="font-semibold text-sm tracking-wide">PHÁP Y & BẰNG CHỨNG (EVIDENCE)</h2>
        </div>
        {selectedNode && (
          <span className="text-[11px] px-2 py-0.5 rounded bg-soc-accent/20 text-soc-accent border border-soc-accent/30 uppercase">
            {selectedNode.type}
          </span>
        )}
      </div>

      {/* Content Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5 text-xs">
        {selectedNode ? (
          <div>
            <div className="space-y-3">
              <div>
                <span className="text-soc-muted block mb-1">Định danh thực thể (Node ID):</span>
                <code className="text-soc-accent bg-gray-900 px-2 py-1 rounded block break-all text-[11px]">
                  {selectedNode.id}
                </code>
              </div>

              <div>
                <span className="text-soc-muted block mb-1">Nhãn / Tên:</span>
                <div className="font-medium text-sm text-white">{selectedNode.label}</div>
              </div>

              {selectedNode.properties && (
                <div>
                  <span className="text-soc-muted block mb-1.5 font-medium">Thuộc tính pháp y (Attributes):</span>
                  <div className="bg-gray-900/80 border border-soc-border rounded p-2.5 space-y-1.5 font-mono text-[11px]">
                    {Object.entries(selectedNode.properties).map(([k, v]) => {
                      if (typeof v === 'object') return null;
                      return (
                        <div key={k} className="flex flex-col">
                          <span className="text-soc-muted">{k}:</span>
                          <span className="text-gray-200 break-all">{String(v)}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Related Evidence Records */}
            <div className="mt-6 pt-4 border-t border-soc-border">
              <h3 className="font-medium text-soc-muted uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-soc-success" /> Bằng chứng liên kết:
              </h3>
              <div className="space-y-2">
                {evidenceItems.map((ev) => (
                  <div key={ev.evidence_id} className="p-2.5 bg-gray-900/50 border border-gray-800 rounded space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-soc-accent text-[11px]">{ev.evidence_id}</span>
                      <span className="text-[10px] text-soc-success flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> {ev.status}
                      </span>
                    </div>
                    <div className="text-gray-300 text-[11px]">{ev.summary}</div>
                    
                    {ev.observations.length > 0 && (
                      <div className="pt-1.5 border-t border-gray-800/80 space-y-1">
                        <span className="text-[10px] text-soc-muted block">Quan sát log (Observations):</span>
                        {ev.observations.map((obs, idx) => (
                          <div key={idx} className="bg-black/40 px-2 py-1 rounded text-[10px] font-mono text-gray-400">
                            <div>Event ID: <span className="text-white">{obs.event_id}</span> | {obs.provider}</div>
                            <div>Ref: <span className="text-soc-accent">{obs.raw_record_ref}</span></div>
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
          <div className="h-full flex flex-col items-center justify-center text-center text-soc-muted p-6">
            <Activity className="w-10 h-10 text-gray-700 mb-3" />
            <p className="text-sm font-medium text-gray-400 mb-1">Chưa chọn thực thể nào</p>
            <p className="text-xs text-gray-600">
              Nhấp vào một nút (Node) bất kỳ trên Đồ thị Tri thức để xem chi tiết bằng chứng và thuộc tính pháp y.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
