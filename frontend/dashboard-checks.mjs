/** Offline contract/projection/render checks for the main dashboard. No provider requests. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = dirname(fileURLToPath(import.meta.url));
const server = await createServer({ root, server: { middlewareMode: true }, appType: 'custom' });
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); };
const read = file => JSON.parse(readFileSync(resolve(root, '..', file), 'utf8'));
const branchResponse = branch => {
  const base = `outputs/experiments/rag-graphrag-pilot-source-contract-02/PS02_${branch}`;
  const validation = read(`${base}/validation.json`);
  return { request: { query: read(`${base}/context.json`).query.text, scenario_id: 'purplesharp-ad', branch },
    outcome: 'accepted_draft', result: read(`${base}/result.json`), validation, report: validation.sanitized_report,
    context: read(`${base}/context.json`), evidence_contract: read(`${base}/evidence_contract.json`),
    configuration: {}, provenance: { mode: 'saved_experimental_replay', historical_llm_http_attempts: 1 },
    human_review_required: true };
};
const savedFetch = globalThis.fetch;
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => null } });
try {
  const { experimentalGraph, assertCurrentRequest, runExperimental } = await server.ssrLoadModule('/src/experimentalDashboard.ts');
  const { ExperimentalResult } = await server.ssrLoadModule('/src/components/ExperimentalResult.tsx');
  const { EvidenceSidebar } = await server.ssrLoadModule('/src/components/EvidenceSidebar.tsx');
  const { ChatPanel } = await server.ssrLoadModule('/src/components/ChatPanel.tsx');
  const { App } = await server.ssrLoadModule('/src/App.tsx');
  const graph = branchResponse('graphrag');
  const rag = branchResponse('rag');
  const render = response => renderToStaticMarkup(React.createElement(ExperimentalResult, { response }));
  check('GraphRAG maps exact current traversal node/edge IDs and provenance', () => {
    const elements = experimentalGraph(graph);
    assert.equal(elements.length, graph.context.traversal.nodes.length + graph.context.traversal.edges.length);
    assert.deepEqual(elements.filter(e => e.data.source).map(e => e.data.source), graph.context.traversal.edges.map(e => e.source_node_id));
    assert.deepEqual(elements[0].data.properties.source_ground_truth, graph.context.source_ground_truth);
    assert.equal(elements.filter(e => e.data.type === 'process').length, 2);
  });
  check('RAG never displays graph, even if response contains a traversal', () => {
    assert.deepEqual(experimentalGraph(rag), []);
    assert.deepEqual(experimentalGraph({ ...graph, request: { ...graph.request, branch: 'rag' } }), []);
  });
  check('Abstain and absent context always clear graph', () => {
    assert.deepEqual(experimentalGraph({ ...graph, outcome: 'abstain' }), []);
    assert.deepEqual(experimentalGraph({ ...graph, context: null }), []);
    assert.deepEqual(experimentalGraph(null), []);
  });
  check('A response from a different question/scenario/branch is rejected', () => {
    assertCurrentRequest(graph, graph.request);
    for (const [key, value] of [['query', 'another question'], ['scenario_id', 'regsvr32-c2'], ['branch', 'rag']])
      assert.throws(() => assertCurrentRequest(graph, { ...graph.request, [key]: value }));
  });
  check('Accepted draft uses current answer and explicit replay/human review labels', () => {
    const html = render(graph);
    assert.match(html, /data-testid="accepted-answer"/);
    assert.match(html, /saved_experimental_replay/);
    assert.match(html, /chưa human-approved/);
    assert.ok(html.includes(graph.report.direct_answer.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;')));
  });
  check('Rejection, abstain and all error/cap/stop states never render an accepted answer', () => {
    for (const outcome of ['validation_failed', 'abstain', 'provider_error', 'rate_limited', 'runtime_error', 'not_run_request_limit', 'not_run_after_stop', 'dry_run_no_generation']) {
      const html = render({ ...graph, outcome });
      assert.doesNotMatch(html, /data-testid="accepted-answer"/);
      assert.ok(!html.includes(graph.report.direct_answer));
    }
    assert.doesNotMatch(render({ ...graph, validation: { status: 'validation_failed' } }), /data-testid="accepted-answer"/);
    assert.doesNotMatch(render({ ...graph, result: { fallback_used: true } }), /data-testid="accepted-answer"/);
  });
  check('Evidence uses response units without requiring a graph node selection', () => {
    const html = renderToStaticMarkup(React.createElement(EvidenceSidebar, {
      selectedNode: null, evidenceItems: [{ evidence_id: 'STALE_SCENARIO_EVIDENCE' }], theme: 'dark', experimental: { response: rag },
    }));
    assert.match(html, /jsonl:line:16/);
    assert.match(html, /source_ground_truth/);
    assert.doesNotMatch(html, /STALE_SCENARIO_EVIDENCE/);
    assert.equal((html.match(/data-testid="evidence-unit"/g) || []).length, rag.evidence_contract.units.length);
  });
  check('Main dashboard keeps the three panes, defaults offline, hides fixtures and collapses config', () => {
    const html = renderToStaticMarkup(React.createElement(App));
    assert.match(html, /PHÁP Y &amp; BẰNG CHỨNG/);
    assert.match(html, /SOC THREAT HUNTING CHAT/);
    assert.match(html, /data-testid="graph-pane"/);
    assert.match(html, /Offline · 0 request LLM/);
    assert.match(html, /value="experimental" selected/);
    assert.doesNotMatch(html, /Synthetic fixture|Xem fixture|<details[^>]*\bopen/);
  });
  check('Free text input is editable and presets are suggestions, not immediate hunt buttons', () => {
    const html = renderToStaticMarkup(React.createElement(ChatPanel, {
      scenarios: [], selectedScenario: 'purplesharp-ad', onSelectScenario() {}, onHunt: async () => null,
      isLoading: false, theme: 'dark', mode: 'experimental',
      experimental: { query: 'Một câu hỏi tự do không thuộc preset', branch: 'rag', liveEnabled: false,
        configuration: { presets: [] }, response: null, error: null },
    }));
    assert.match(html, /Một câu hỏi tự do không thuộc preset/);
    assert.match(html, /Presets chỉ là gợi ý/);
    assert.match(html, /Gửi offline/);
    assert.doesNotMatch(html, /readOnly/);
  });
  const calls = [];
  let serviceMode = 'experimental_offline_demo';
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/config')) return { ok: true, json: async () => ({ mode: serviceMode }) };
    return { ok: true, json: async () => ({ ...rag, request: JSON.parse(init.body) }) };
  };
  const request = { query: 'Câu hỏi tự do ngoài presets?', scenario_id: 'purplesharp-ad', branch: 'rag' };
  await runExperimental(request, false, () => {});
  check('Free query sends only existing ExperimentalRequest fields to the experimental endpoint', () => {
    assert.equal(calls[1].url, '/experimental-api/hunt');
    assert.deepEqual(JSON.parse(calls[1].init.body), request);
  });
  calls.length = 0; serviceMode = 'experimental_live_demo';
  await assert.rejects(runExperimental(request, false, () => {}), /Chưa gửi hunt/);
  check('Live server is rechecked; without explicit UI consent no hunt is sent', () => assert.equal(calls.length, 1));
  await runExperimental(request, true, () => {});
  check('Explicit live selection keeps server payload/cap/stop control unchanged', () => assert.deepEqual(JSON.parse(calls.at(-1).init.body), request));
  console.log(JSON.stringify({ passed: true, checks, llm_requests: 0 }, null, 2));
} finally {
  globalThis.fetch = savedFetch;
  await server.close();
}
