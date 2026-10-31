/** Local Edge CDP smoke QA. No dependencies, no provider requests, no policy changes. */
import { mkdir, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';

const out = path.resolve(process.argv[2] || 'outputs/demo/experimental-ui-20261029-verification/browser');
await mkdir(out, { recursive: false });
const pages = await fetch('http://127.0.0.1:9224/json/list').then(r => r.json());
const candidates = pages.filter(p => p.type === 'page' && p.url === 'http://127.0.0.1:8002/experimental.html');
assert.equal(candidates.length, 1, 'Select exactly one local experimental page');
const socket = new WebSocket(candidates[0].webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let nextId = 0;
const pending = new Map();
const requests = [];
const consoleErrors = [];
socket.onmessage = event => {
  const value = JSON.parse(event.data);
  if (value.id) {
    const job = pending.get(value.id); pending.delete(value.id);
    if (value.error) job.reject(new Error(JSON.stringify(value.error))); else job.resolve(value.result);
  } else if (value.method === 'Network.requestWillBeSent') requests.push(value.params.request.url);
  else if (value.method === 'Runtime.exceptionThrown') consoleErrors.push(value.params.exceptionDetails.text);
};
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++nextId; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
});
async function evaluate(expression) {
  const value = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (value.exceptionDetails) throw new Error(JSON.stringify(value.exceptionDetails));
  return value.result.value;
}
async function waitFor(expression, timeout = 180000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error(`Timed out: ${expression}`);
}
const choose = async (label, value) => {
  await evaluate(`(() => { const e = document.querySelector('select[aria-label=${JSON.stringify(label)}]'); e.value=${JSON.stringify(value)}; e.dispatchEvent(new Event('change',{bubbles:true})); })()`);
  await new Promise(resolve => setTimeout(resolve, 100));
};
const click = text => evaluate(`(() => { const e = [...document.querySelectorAll('button')].find(b => b.textContent.includes(${JSON.stringify(text)})); if (!e || e.disabled) throw new Error('Missing/disabled button'); e.click(); })()`);
async function screenshot(name) {
  const screenshot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  await writeFile(path.join(out, `${name}.png`), Buffer.from(screenshot.data, 'base64'));
}
const checks = [];
try {
  await send('Runtime.enable'); await send('Network.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1080, deviceScaleFactor: 1, mobile: false });
  await send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: out });
  await send('Page.reload', { ignoreCache: true });
  await waitFor(`document.querySelector('[data-testid="configuration"]')?.textContent.includes('experimental_offline_demo') && document.querySelector('textarea')?.value.includes('PurpleSharp.exe')`);
  await screenshot('01_offline_initial');
  const lockedQueries = await evaluate(`fetch('/experimental-api/config').then(r=>r.json()).then(c=>c.presets)`);
  for (const preset of lockedQueries) {
    await choose('Case đã khóa', preset.case_id);
    assert.equal(await evaluate(`document.querySelector('textarea').value`), preset.query);
    for (const branch of ['rag', 'graphrag']) {
      await choose('Nhánh', branch);
      await click('Chạy offline');
      if (preset.case_id === 'PS02' && branch === 'rag') {
        await waitFor(`!!document.querySelector('[role="status"]')`);
        await screenshot('02_loading');
        checks.push({ check: 'loading_visible', passed: true });
      }
      await waitFor(`!!document.querySelector('[data-testid="result"]') && !document.querySelector('[role="status"]')`);
      const status = await evaluate(`document.querySelector('[data-testid="outcome"]').textContent`);
      assert.ok(status.includes(preset.case_id === 'PS02' ? 'offline dry-run' : 'Abstain'));
      assert.equal(await evaluate(`document.querySelectorAll('[data-testid="accepted-answer"]').length`), 0);
      checks.push({ case_id: preset.case_id, branch, status, query_unchanged: true });
      await screenshot(`03_${preset.case_id}_${branch}_offline`);
      console.log(`Verified ${preset.case_id}/${branch}: ${status}`);
    }
  }
  await choose('Case đã khóa', 'PS02');
  for (const branch of ['rag', 'graphrag']) {
    await choose('Nhánh', branch);
    await click('Saved experimental replay');
    await waitFor(`document.querySelector('[data-testid="outcome"]')?.textContent.includes('Accepted draft')`);
    assert.equal(await evaluate(`document.querySelectorAll('[data-testid="accepted-answer"]').length`), 1);
    const content = await evaluate('document.body.innerText');
    assert.ok(content.includes('saved_experimental_replay') && content.includes('T1110.003'));
    await evaluate(`document.querySelector('[data-testid="result"]').scrollIntoView()`);
    await screenshot(`04_PS02_${branch}_saved_draft`);
    checks.push({ case_id: 'PS02', branch, mode: 'saved_experimental_replay', accepted_draft_visible: true });
  }
  await click('Tải response');
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.ok((await readdir(out)).some(f => f.includes('saved_experimental_replay-graphrag-accepted_draft.json')));
  for (const fixture of ['accepted_draft', 'validation_failed', 'provider_error', 'rate_limited', 'abstain', 'dry_run_no_generation', 'runtime_error', 'not_run_request_limit', 'not_run_after_stop']) {
    await choose('Synthetic fixture', fixture);
    await click('Xem fixture');
    await waitFor(`document.querySelector('[data-testid="result"]')?.textContent.includes('synthetic_fixture') && !document.querySelector('[role="status"]')`);
    const hasAnswer = await evaluate(`document.querySelectorAll('[data-testid="accepted-answer"]').length`);
    assert.equal(hasAnswer, fixture === 'accepted_draft' ? 1 : 0);
    const text = await evaluate(`document.querySelector('[data-testid="result"]').innerText`);
    if (fixture === 'validation_failed') assert.ok(text.includes('Rejected diagnostic'));
    if (fixture === 'provider_error' || fixture === 'rate_limited') assert.ok(text.includes('không fallback') || text.includes('không retry/fallback'));
    await evaluate(`document.querySelector('[data-testid="result"]').scrollIntoView()`);
    await screenshot(`05_fixture_${fixture}`);
    checks.push({ fixture, labeled: true, accepted_answer_count: hasAnswer });
  }
  await choose('Synthetic fixture', 'validation_failed'); await click('Xem fixture');
  await waitFor(`document.querySelector('[data-testid="outcome"]')?.textContent.includes('Validation_failed')`);
  await click('Tải response');
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.ok((await readdir(out)).some(f => f.includes('synthetic_fixture-rag-validation_failed.json')));
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
  await evaluate('window.scrollTo(0,0)');
  await screenshot('06_mobile_width');
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'No mobile horizontal overflow');
  assert.equal(consoleErrors.length, 0);
  assert.ok(requests.every(url => url.startsWith('http://127.0.0.1:8002/')));
  assert.ok(requests.every(url => !url.includes('/api/hunt')));
  // Leave the page at the initial offline preset.
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1080, deviceScaleFactor: 1, mobile: false });
  await send('Page.reload', { ignoreCache: true });
  const result = { passed: true, checks, requests, consoleErrors, provider_requests: 0, mode: 'headless_Edge_local_offline',
    limitations: 'Live provider not invoked; desktop headful rendering not separately tested.' };
  await writeFile(path.join(out, 'browser_check.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({ passed: true, checks: checks.length, provider_requests: 0 }));
} catch (error) {
  await screenshot('failure').catch(() => {});
  await writeFile(path.join(out, 'failure.json'), JSON.stringify({ error: String(error), checks, requests, consoleErrors }, null, 2));
  throw error;
} finally { socket.close(); }
