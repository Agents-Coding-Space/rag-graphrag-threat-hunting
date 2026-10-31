import React, { useState, useEffect, useMemo, useRef } from 'react';
import { CytoscapeGraph } from './components/CytoscapeGraph';
import { ChatPanel } from './components/ChatPanel';
import { EvidenceSidebar } from './components/EvidenceSidebar';
import { CyberGraphShieldIcon, SunIcon, MoonIcon, RefreshIcon } from './components/SvgIcons';
import { CytoscapeElement, EvidenceItem, HuntResponse, ScenarioInfo } from './types';
import { ExperimentalResponse } from './experimentalState';
import { assertCurrentRequest, experimentalApi, ExperimentalBranch, ExperimentalConfiguration,
  ExperimentalPreset, experimentalGraph, runExperimental, selectArtifactProfile } from './experimentalDashboard';

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
  const [mode, setMode] = useState<'legacy' | 'experimental'>('experimental');
  const [branch, setBranch] = useState<ExperimentalBranch>('rag');
  const [configuration, setConfiguration] = useState<ExperimentalConfiguration | null>(null);
  const [experimentalResponse, setExperimentalResponse] = useState<ExperimentalResponse | null>(null);
  const [experimentalQuery, setExperimentalQuery] = useState('');
  const [liveEnabled, setLiveEnabled] = useState(false);
  const epoch = useRef(0);
  const inFlight = useRef(false);
  const displayedGraph = useMemo(() => mode === 'experimental' ? experimentalGraph(experimentalResponse) : graphElements,
    [mode, experimentalResponse, graphElements]);

  const clearResult = () => {
    epoch.current += 1;
    setExperimentalResponse(null); setGraphElements([]); setEvidenceItems([]);
    setSelectedNode(null); setErrorMessage(null);
  };
  const selectScenario = (value: string) => { clearResult(); setSelectedScenario(value); };
  const selectMode = (value: 'legacy' | 'experimental') => {
    clearResult(); setLiveEnabled(false); setMode(value);
  };

  // Sync theme attribute
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('soc_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Isolate both modes: experimental never loads whole-scenario production evidence/graphs.
  useEffect(() => {
    let active = true;
    if (mode === 'experimental') {
      experimentalApi<ExperimentalConfiguration>('config')
        .then(data => { if (active) setConfiguration(data); })
        .catch(err => { if (active) setErrorMessage(String(err)); });
      return () => { active = false; };
    }
    fetch('/api/scenarios')
      .then((res) => res.json())
      .then((data) => {
        if (active && Array.isArray(data) && data.length > 0) {
          setScenarios(data);
          setSelectedScenario(data[0].scenario_id);
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err);
        if (active) setErrorMessage('Không thể kết nối tới FastAPI backend. Vui lòng kiểm tra cổng 8000.');
      });
    return () => { active = false; };
  }, [mode]);

  // 2. Fetch full graph and evidence when scenario changes
  const loadScenarioData = (scenId: string) => {
    if (mode !== 'legacy') return;
    const token = epoch.current;
    setSelectedNode(null);
    setErrorMessage(null);

    fetch(`/api/graph?scenario_id=${scenId}`)
      .then((res) => res.json())
      .then((data) => {
        if (token === epoch.current && data.elements) {
          setGraphElements(data.elements);
        }
      })
      .catch((err) => console.error('Failed to load graph:', err));

    fetch(`/api/evidence?scenario_id=${scenId}`)
      .then((res) => res.json())
      .then((data) => {
        if (token === epoch.current && data.evidence_items) {
          setEvidenceItems(data.evidence_items);
        }
      })
      .catch((err) => console.error('Failed to load evidence:', err));
  };

  useEffect(() => {
    if (mode === 'legacy' && selectedScenario) {
      loadScenarioData(selectedScenario);
    }
    return () => { epoch.current += 1; };
  }, [selectedScenario, mode]);

  const handleExperimental = async (query: string, preset?: ExperimentalPreset) => {
    if (inFlight.current || !query.trim()) return;
    inFlight.current = true;
    clearResult();
    const token = epoch.current;
    const request = { query: query.trim(), scenario_id: selectedScenario, branch };
    setIsLoading(true);
    try {
      const response = preset
        ? await experimentalApi<ExperimentalResponse>(`saved?case_id=${encodeURIComponent(preset.case_id)}&branch=${branch}`)
        : await runExperimental(request, liveEnabled, data => { if (token === epoch.current) setConfiguration(data); });
      assertCurrentRequest(response, request);
      if (token === epoch.current) {
        setExperimentalResponse(response);
        setConfiguration(previous => previous ? { ...previous, ...response.configuration } : previous);
      }
    } catch (err) {
      if (token === epoch.current) setErrorMessage(String(err));
    } finally {
      inFlight.current = false;
      setIsLoading(false);
    }
  };

  // 3. Handle Threat Hunting query from ChatPanel
  const handleHunt = async (query: string, enforceGate: boolean, useLLM: boolean): Promise<HuntResponse | null> => {
    if (mode !== 'legacy' || inFlight.current) return null;
    inFlight.current = true;
    clearResult();
    const token = epoch.current;
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
      if (token !== epoch.current) return null;

      if (data.status !== 'abstained' && data.subgraph && data.subgraph.elements.length > 0) {
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
      inFlight.current = false;
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
              <span>{mode === 'experimental' ? 'Experimental' : 'Legacy'}</span>
            </div>
          </div>

          {/* Right: Actions & Theme Toggle */}
          <div className="flex items-center gap-2.5 text-xs">
            {errorMessage ? (
              <span title={errorMessage} className="text-rose-400 text-[10px] font-mono bg-rose-950/40 px-2 py-0.5 rounded-lg border border-rose-900 max-w-[260px] truncate">
                ⚠️ {errorMessage}
              </span>
            ) : (
              <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-soc-muted">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                <span>Backend: {mode === 'experimental' ? '/experimental-api' : '127.0.0.1:8000'}</span>
              </div>
            )}

            <button
              onClick={() => mode === 'experimental' ? clearResult() : loadScenarioData(selectedScenario)}
              disabled={isLoading}
              className="flex items-center gap-1.5 text-soc-muted hover:text-white glass-card border px-2.5 py-1.5 rounded-xl transition text-[11px] font-mono shadow-sm"
              title={mode === 'experimental' ? 'Xóa kết quả hiện tại' : 'Tải lại toàn cảnh đồ thị'}
            >
              <RefreshIcon className="w-3 h-3 text-cyan-400" />
              <span className="hidden sm:inline">{mode === 'experimental' ? 'Xóa kết quả' : 'Toàn cảnh'}</span>
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
          <section className="col-span-3 h-full overflow-hidden min-w-0">
            <EvidenceSidebar
              selectedNode={selectedNode}
              evidenceItems={evidenceItems}
              theme={theme}
              experimental={mode === 'experimental' ? { response: experimentalResponse } : undefined}
            />
          </section>

          {/* Center Column: Cytoscape Knowledge Graph Canvas (5 cols) */}
          <section className="col-span-5 h-full p-2.5 overflow-hidden min-w-0" data-testid="graph-pane" data-element-count={displayedGraph.length}>
            {displayedGraph.length > 0 ? (
              <CytoscapeGraph
                elements={displayedGraph}
                onSelectNode={(nodeData) => setSelectedNode(nodeData)}
                selectedNodeId={selectedNode?.id}
                theme={theme}
              />
            ) : (
              <div className="w-full h-full flex flex-col items-center justify-center text-soc-muted border rounded-2xl glass-card">
                {isLoading && <div className="animate-spin text-cyan-400 mb-2">⏳</div>}
                <p className="text-xs font-mono text-center px-5" data-testid="graph-empty">{mode === 'legacy' ? 'Đang nạp đồ thị tri thức...' :
                  isLoading ? 'Đang xử lý câu hỏi mới; graph cũ đã được xóa.' :
                  experimentalResponse?.outcome === 'abstain' ? 'Query abstain — không hiển thị graph.' :
                  branch === 'rag' ? 'RAG chỉ dùng retrieval evidence; không có graph.' :
                  'Chưa có graph từ response hiện tại.'}</p>
              </div>
            )}
          </section>

          {/* Right Column: Threat Hunting Chat Panel (4 cols) */}
          <section className="col-span-4 h-full overflow-hidden min-w-0">
            <ChatPanel
              scenarios={scenarios}
              selectedScenario={selectedScenario}
              onSelectScenario={selectScenario}
              onHunt={handleHunt}
              isLoading={isLoading}
              theme={theme}
              mode={mode}
              onModeChange={selectMode}
              experimental={mode === 'experimental' ? {
                configuration, response: experimentalResponse, branch, query: experimentalQuery, liveEnabled,
                error: errorMessage,
                onBranchChange: value => { clearResult(); setBranch(value); },
                onQueryChange: value => { clearResult(); setExperimentalQuery(value); },
                onPreset: preset => { clearResult(); setSelectedScenario(preset.scenario_id); setExperimentalQuery(preset.query); },
                onProfileChange: async profile => {
                  clearResult(); setLiveEnabled(false); selectArtifactProfile(profile);
                  try { setConfiguration(await experimentalApi<ExperimentalConfiguration>('config')); }
                  catch (err) { setErrorMessage(String(err)); }
                },
                onLiveChange: value => { clearResult(); setLiveEnabled(value); },
                onHunt: query => handleExperimental(query),
                onReplay: preset => handleExperimental(preset.query, preset),
              } : undefined}
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
