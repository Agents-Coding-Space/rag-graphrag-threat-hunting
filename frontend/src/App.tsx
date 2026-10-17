import React, { useState, useEffect } from 'react';
import { CytoscapeGraph } from './components/CytoscapeGraph';
import { ChatPanel } from './components/ChatPanel';
import { EvidenceSidebar } from './components/EvidenceSidebar';
import { CytoscapeElement, EvidenceItem, HuntResponse, ScenarioInfo } from './types';
import { ShieldAlert, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('mshta-powershell');
  const [graphElements, setGraphElements] = useState<CytoscapeElement[]>([]);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // 1. Fetch scenarios on load
  useEffect(() => {
    fetch('/api/scenarios')
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setScenarios(data);
          setSelectedScenario(data[0].scenario_id);
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err);
        setErrorMessage('Không thể kết nối tới FastAPI backend. Vui lòng kiểm tra cổng 8000.');
      });
  }, []);

  // 2. Fetch full graph and evidence when scenario changes
  const loadScenarioData = (scenId: string) => {
    setSelectedNode(null);
    setErrorMessage(null);

    // Fetch full scenario graph
    fetch(`/api/graph?scenario_id=${scenId}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.elements) {
          setGraphElements(data.elements);
        }
      })
      .catch((err) => console.error('Failed to load graph:', err));

    // Fetch evidence items
    fetch(`/api/evidence?scenario_id=${scenId}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.evidence_items) {
          setEvidenceItems(data.evidence_items);
        }
      })
      .catch((err) => console.error('Failed to load evidence:', err));
  };

  useEffect(() => {
    if (selectedScenario) {
      loadScenarioData(selectedScenario);
    }
  }, [selectedScenario]);

  // 3. Handle Threat Hunting query from ChatPanel
  const handleHunt = async (query: string, enforceGate: boolean, useLLM: boolean): Promise<HuntResponse | null> => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          scenario_id: selectedScenario,
          enforce_gate: enforceGate,
          use_llm: useLLM,
        }),
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }

      const data: HuntResponse = await resp.json();

      // If proceed and subgraph returned, update graph to traversed subgraph
      if (data.status === 'proceed' && data.subgraph && data.subgraph.elements.length > 0) {
        setGraphElements(data.subgraph.elements);
        // Select first node if available
        const firstNode = data.subgraph.elements.find((el) => !el.data.source);
        if (firstNode) {
          setSelectedNode(firstNode.data);
        }
      }

      return data;
    } catch (err: any) {
      console.error('Hunt request failed:', err);
      setErrorMessage(`Lỗi truy vấn: ${err.message}`);
      return null;
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-soc-dark text-soc-text overflow-hidden select-none">
      {/* Top Navigation Bar */}
      <header className="h-12 border-b border-soc-border bg-[#0B0F19] px-4 flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 rounded bg-soc-accent/20 border border-soc-accent/50 flex items-center justify-center">
            <span className="font-bold text-xs text-soc-accent">PH</span>
          </div>
          <div>
            <h1 className="font-bold text-xs tracking-wider uppercase flex items-center gap-2">
              <span>SOC Threat Hunting Workbench</span>
              <span className="text-[10px] text-soc-muted font-normal">| RAG + GraphRAG + LLM Co-Pilot</span>
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {errorMessage && (
            <span className="text-rose-400 flex items-center gap-1 text-[11px] bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900">
              <ShieldAlert className="w-3.5 h-3.5" /> {errorMessage}
            </span>
          )}

          <button
            onClick={() => loadScenarioData(selectedScenario)}
            className="flex items-center gap-1 text-soc-muted hover:text-white bg-gray-900 hover:bg-gray-800 border border-soc-border px-2.5 py-1 rounded transition text-[11px]"
            title="Tải lại toàn bộ đồ thị kịch bản"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Toàn cảnh đồ thị</span>
          </button>
        </div>
      </header>

      {/* Main 3-Pane Workspace */}
      <main className="flex-1 grid grid-cols-12 overflow-hidden">
        {/* Left Pane: Chat (30% -> 4 cols) */}
        <section className="col-span-4 h-full overflow-hidden">
          <ChatPanel
            scenarios={scenarios}
            selectedScenario={selectedScenario}
            onSelectScenario={(scenId) => setSelectedScenario(scenId)}
            onHunt={handleHunt}
            isLoading={isLoading}
          />
        </section>

        {/* Center Pane: Cytoscape Knowledge Graph Canvas (45% -> 5 cols) */}
        <section className="col-span-5 h-full p-2 bg-[#060910] overflow-hidden">
          <CytoscapeGraph
            elements={graphElements}
            onSelectNode={(nodeData) => setSelectedNode(nodeData)}
            selectedNodeId={selectedNode?.id}
          />
        </section>

        {/* Right Pane: Forensic Evidence Sidebar (25% -> 3 cols) */}
        <section className="col-span-3 h-full overflow-hidden">
          <EvidenceSidebar
            selectedNode={selectedNode}
            evidenceItems={evidenceItems}
          />
        </section>
      </main>
    </div>
  );
};

export default App;
