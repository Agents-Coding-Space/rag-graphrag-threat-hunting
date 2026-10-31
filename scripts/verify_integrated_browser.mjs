/** Existing dashboard DOM smoke test via Edge CDP; built-in Node APIs only. */
import { mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const output = process.argv[2];
await mkdir(output, { recursive: true });
const pages = await fetch('http://127.0.0.1:9226/json/list').then(r=>r.json());
const page = pages.find(p=>p.type==='page' && p.url==='http://127.0.0.1:8003/');
assert.ok(page, 'Integrated dashboard page must exist');
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
let id=0;const pending=new Map();const errors=[];const urls=[];
socket.onmessage=e=>{const v=JSON.parse(e.data);if(v.id){const p=pending.get(v.id);pending.delete(v.id);v.error?p.reject(Error(JSON.stringify(v.error))):p.resolve(v.result);}
else if(v.method==='Runtime.exceptionThrown')errors.push(v.params.exceptionDetails.text);
else if(v.method==='Network.requestWillBeSent')urls.push(v.params.request.url);};
const send=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});socket.send(JSON.stringify({id:key,method,params}));});
const evaluate=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
async function wait(expression){const end=Date.now()+20000;while(Date.now()<end){if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,100));}throw Error('DOM timeout: '+expression);}
const click=async text=>evaluate(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.textContent.includes(${JSON.stringify(text)}));if(!b||b.disabled)throw Error('Button missing/disabled');b.click();})()`);
const choose=async(label,value)=>evaluate(`(()=>{const e=document.querySelector('select[aria-label=${JSON.stringify(label)}]');if(!e)throw Error('Selector missing');e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('change',{bubbles:true}));})()`);
const checks=[];
try{
 await send('Runtime.enable');await send('Network.enable');await send('Page.enable');
 await send('Emulation.setDeviceMetricsOverride',{width:1600,height:1050,deviceScaleFactor:1,mobile:false});
 await send('Page.reload',{ignoreCache:true});
 await wait(`document.querySelector('select[aria-label="Cấu hình artifacts"]')?.value==='integrated-three-scenarios-cti-v5'`);
 assert.equal(await evaluate(`document.querySelector('input[aria-label="Bật Live"]').checked`),false);
 if(!await evaluate(`!![...document.querySelectorAll('button')].find(b=>b.textContent.includes('Gợi ý AUTH-CTI:'))`))await click('Hiện gợi ý');
 for(const caseId of ['AUTH-CTI','PS-CTI','NET-CTI']){
  await click('Gợi ý '+caseId+':');await wait(`!![...document.querySelectorAll('button')].find(b=>b.textContent.includes('Xem bản lưu ${caseId}'))`);
  await click('Xem bản lưu '+caseId);
  await wait(`!!document.querySelector('[data-testid="experimental-evidence"] [data-testid="evidence-unit"]')`);
  await wait(`document.querySelector('[data-testid="experimental-evidence"]').textContent.includes('CTI report')`);
  const text=await evaluate(`document.querySelector('[data-testid="experimental-evidence"]').textContent`);
  assert.ok(text.includes('text:chars:') && text.includes('CTI report'));
  checks.push({case_id:caseId,cti_source_label:true,source_locations_visible:true});
 }
 await evaluate(`(()=>{const card=[...document.querySelectorAll('[data-testid="evidence-unit"]')].find(e=>e.textContent.includes('Nguồn CTI:'));card?.scrollIntoView({block:'center'});})()`);
 const image=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
 await writeFile(output+'/integrated-dashboard.png',Buffer.from(image.data,'base64'));
 await choose('Cấu hình artifacts','historical-replay');
 await wait(`document.body.textContent.includes('Checkpoint lịch sử · saved replay only')`);
 checks.push({historical_profile_saved_only:true});
 await choose('Cấu hình artifacts','integrated-three-scenarios-cti-v5');
 await wait(`document.body.textContent.includes('Integrated research draft')`);
 assert.equal(await evaluate(`fetch('/experimental-api/config').then(r=>r.json()).then(x=>x.llm_http_attempts)`),0);
 assert.deepEqual(errors,[]);
 assert.ok(!urls.some(u=>u.includes('/api/hunt')||u.includes('/experimental-api/hunt')),'Browser smoke uses saved replay only');
 await writeFile(output+'/browser_qa.json',JSON.stringify({checks,console_errors:errors,requests:urls,llm_requests:0},null,2)+'\n');
 process.stdout.write(JSON.stringify({checks:checks.length,console_errors:errors.length,llm_requests:0})+'\n');
}finally{socket.close();}
