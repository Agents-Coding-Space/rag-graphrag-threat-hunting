import React, { useState, useEffect } from 'react';
import { CytoscapeGraph } from './components/CytoscapeGraph';
import { ChatPanel } from './components/ChatPanel';
import { EvidenceSidebar } from './components/EvidenceSidebar';
import { CyberGraphShieldIcon, SunIcon, MoonIcon, RefreshIcon } from './components/SvgIcons';
import { CytoscapeElement, EvidenceItem, HuntResponse, ScenarioInfo } from './types';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('soc_theme') as 'dark' | 'light') || 'dark';
  });

  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('mshta-powershell');
  const [graphElements, setGraphElements] = useState<CytoscapeElement[]>([]);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Sync theme attribute
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('soc_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

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

    fetch(`/api/graph?scenario_id=${scenId}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.elements) {
          setGraphElements(data.elements);
        }
      })
      .catch((err) => console.error('Failed to load graph:', err));

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

      if (data.status === 'proceed' && data.subgraph && data.subgraph.elements.length > 0) {
        setGraphElements(data.subgraph.elements);
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
    <div className="flex items-center justify-center h-screen w-screen p-3 overflow-hidden select-none bg-cover bg-center">
      {/* MacOS Floating Glass Window Container */}
      <div className="flex flex-col h-full w-full max-w-[1920px] glass-panel border rounded-2xl overflow-hidden shadow-2xl relative">
        {/* Glass Header */}
        <header className="h-12 border-b px-4 flex items-center justify-between z-10 glass-card" style={{ borderColor: 'var(--border-glass)' }}>
          {/* Left: Cyber Graph Shield Logo & Title */}
          <div className="flex items-center gap-3">
            <CyberGraphShieldIcon className="w-6 h-6" />
            <div className="flex items-center gap-2">
              <span className="font-bold text-xs tracking-wider uppercase font-mono">SOC THREAT HUNTING</span>
              <span className="text-[10px] text-soc-muted font-mono hidden md:inline">• GraphRAG & LLM Co-Pilot</span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Engine Active</span>
            </div>
          </div>

          {/* Right: Actions & Theme Toggle */}
          <div className="flex items-center gap-2.5 text-xs">
            {errorMessage ? (
              <span className="text-rose-400 text-[10px] font-mono bg-rose-950/40 px-2 py-0.5 rounded-lg border border-rose-900">
                ⚠️ {errorMessage}
              </span>
            ) : (
              <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-soc-muted">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                <span>Backend: 127.0.0.1:8000</span>
              </div>
            )}

            <button
              onClick={() => loadScenarioData(selectedScenario)}
              className="flex items-center gap-1.5 text-soc-muted hover:text-white glass-card border px-2.5 py-1.5 rounded-xl transition text-[11px] font-mono shadow-sm"
              title="Tải lại toàn cảnh đồ thị"
            >
              <RefreshIcon className="w-3 h-3 text-cyan-400" />
              <span className="hidden sm:inline">Toàn cảnh</span>
            </button>

            {/* Theme Toggle Button (1 duy nhất) */}
            <button
              onClick={toggleTheme}
              className="p-1.5 glass-card border text-soc-muted hover:text-white rounded-xl transition shadow-sm"
              title={theme === 'dark' ? 'Chuyển sang Giao diện Sáng' : 'Chuyển sang Giao diện Tối'}
            >
              {theme === 'dark' ? <SunIcon className="w-4 h-4 text-amber-400" /> : <MoonIcon className="w-4 h-4 text-cyan-600" />}
            </button>
          </div>
        </header>

        {/* Main 3-Pane Layout: Left (Evidence) | Center (Graph) | Right (Chat) */}
        <main className="flex-1 grid grid-cols-12 overflow-hidden">
          {/* Left Column: Forensic Evidence Sidebar (3 cols) */}
          <section className="col-span-3 h-full overflow-hidden">
            <EvidenceSidebar
              selectedNode={selectedNode}
              evidenceItems={evidenceItems}
              theme={theme}
            />
          </section>

          {/* Center Column: Cytoscape Knowledge Graph Canvas (5 cols) */}
          <section className="col-span-5 h-full p-2.5 overflow-hidden">
            {graphElements.length > 0 ? (
              <CytoscapeGraph
                elements={graphElements}
                onSelectNode={(nodeData) => setSelectedNode(nodeData)}
                selectedNodeId={selectedNode?.id}
                theme={theme}
              />
            ) : (
              <div className="w-full h-full flex flex-col items-center justify-center text-soc-muted border rounded-2xl glass-card">
                <div className="animate-spin text-cyan-400 mb-2">⏳</div>
                <p className="text-xs font-mono">Đang nạp đồ thị tri thức...</p>
              </div>
            )}
          </section>

          {/* Right Column: Threat Hunting Chat Panel (4 cols) */}
          <section className="col-span-4 h-full overflow-hidden">
            <ChatPanel
              scenarios={scenarios}
              selectedScenario={selectedScenario}
              onSelectScenario={(scenId) => setSelectedScenario(scenId)}
              onHunt={handleHunt}
              isLoading={isLoading}
              theme={theme}
            />
          </section>
        </main>

        {/* MacOS Style Footer Shortcut Hints Bar (như mẫu RLESS) */}
        <footer className="h-7 border-t px-4 flex items-center justify-between text-[10px] font-mono text-soc-muted glass-card select-none" style={{ borderColor: 'var(--border-glass)' }}>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>Tab</kbd>
              <span>Đổi kịch bản</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>D</kbd>
              <span>Sáng / Tối</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>G</kbd>
              <span>Toàn cảnh đồ thị</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-emerald-400 font-semibold uppercase">Học viện Kỹ thuật Mật mã — 2026</span>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default App;
