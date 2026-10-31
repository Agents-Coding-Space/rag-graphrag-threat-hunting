/** Offline render checks of the same ChatPanel used by App and qa.html. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = dirname(fileURLToPath(import.meta.url));
const server = await createServer({ root, server: { middlewareMode: true }, appType: 'custom' });
try {
  const { ChatPanel } = await server.ssrLoadModule('/src/components/ChatPanel.tsx');
  const { canExportAcceptedDraft, exportFilename, isRejected } = await server.ssrLoadModule('/src/reportState.ts');
  const saved = (file) => JSON.parse(readFileSync(resolve(root, '..', file), 'utf8'));
  const accepted = saved('outputs/review/three_case_corrective_regression/20261025T223111_976089Z/MS04_response.json');
  const rejected = saved('outputs/review/three_case_corrective_regression/20261025T223111_976089Z/MS01_response.json');
  const abstained = saved('outputs/review/live_llm_fixes/20261025T212918_870968Z/RG05.json');
  const render = (response, isLoading = false) => renderToStaticMarkup(React.createElement(ChatPanel, {
    scenarios: [], selectedScenario: 'mshta-powershell', onSelectScenario: () => {}, onHunt: async () => null,
    isLoading, theme: 'dark', initialResponse: response,
  }));
  assert(canExportAcceptedDraft(accepted));
  assert.match(render(accepted), /Xuất MD \(draft\)/);
  assert.match(render(accepted), /chưa được người dùng duyệt/);
  assert.match(render(accepted), /completion|hoàn tất/);
  assert(!canExportAcceptedDraft(rejected));
  assert.match(render(rejected), /Output bị từ chối/);
  assert.doesNotMatch(render(rejected), /Xuất MD/);
  assert(!render(rejected).includes(rejected.report.direct_answer));
  assert.match(exportFilename(rejected, 'json'), /^rejected-diagnostic-/);
  const inconsistent = { ...rejected, status: 'proceed' };
  assert(isRejected(inconsistent));
  assert.doesNotMatch(render(inconsistent), /Xuất MD/);
  assert.match(render(abstained), /Truy vấn bị từ chối bởi gate/);
  assert.doesNotMatch(render(abstained), /Xuất MD|JSON \(draft\)/);
  const fallback = { ...accepted, status: 'provider_error', provider_error: { kind: 'rate_limited', http_status: 429, retry_after_seconds: 60, automatic_retry: false }, execution: { ...accepted.execution, source: 'offline_fallback', fallback_used: true, generation_succeeded: false } };
  assert(!canExportAcceptedDraft(fallback));
  assert.match(render(fallback), /rate_limited.*HTTP 429/);
  assert.match(render(fallback), /Diagnostic JSON/);
  assert.doesNotMatch(render(fallback), /Xuất MD/);
  assert.match(exportFilename(fallback, 'json'), /^fallback-diagnostic-/);
  const replay = { ...accepted, replay: { mode: 'saved_response', source_file: 'saved-response.json', sha256: 'a'.repeat(64), case_id: 'MS04' } };
  assert.match(render(replay), /REPLAY\/MOCK/);
  assert.match(exportFilename(replay, 'md'), /^replay-accepted-draft-/);
  assert.match(render(undefined, true), /Đang truy xuất đồ thị/);
  assert.match(render(undefined, true), /disabled/);
  console.log(JSON.stringify({ result: 'passed', assertions: 22, mode: 'offline React server rendering; no browser or provider requests' }));
} finally {
  await server.close();
}
