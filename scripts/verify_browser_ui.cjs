/* Real Chromium → localhost ASGI → source audit smoke; no mocked fetch or wallet.
 * Verified with Playwright 1.62.1 and @sparticuz/chromium 133.0.0 (Chromium 133.0.6943.0).
 * Optional local dependencies (kept outside the repository):
 *   npm install --prefix /tmp/veritas-browser playwright@1.62.1
 *   /tmp/veritas-browser/node_modules/.bin/playwright install chromium
 *   NODE_PATH=/tmp/veritas-browser/node_modules node scripts/verify_browser_ui.cjs
 * The project .venv must contain backend dependencies. VERITAS_PYTHON overrides it.
 * Screenshots + result.json go to a temporary directory (or VERITAS_BROWSER_OUTPUT).
 * Existing browser installations can use VERITAS_CHROMIUM_EXECUTABLE; Lambda-style
 * distributions may also set VERITAS_CHROMIUM_MODULE for their launch arguments.
 * No private credentials, remote agent repositories, funded orders or wallet signing
 * are used. AI, execution and official orders are disabled in this local server.
 */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawn}=require('node:child_process');
const net=require('node:net');
const os=require('node:os');
const {chromium:pw}=require(process.env.VERITAS_PLAYWRIGHT_MODULE||'playwright');
const ROOT=path.resolve(__dirname,'..');
const OUT=process.env.VERITAS_BROWSER_OUTPUT||fs.mkdtempSync(path.join(os.tmpdir(),'veritas-browser-'));
fs.mkdirSync(OUT,{recursive:true});
const launchOptions={headless:true};
if(process.env.VERITAS_CHROMIUM_EXECUTABLE)launchOptions.executablePath=process.env.VERITAS_CHROMIUM_EXECUTABLE;
if(process.env.VERITAS_CHROMIUM_MODULE)launchOptions.args=require(process.env.VERITAS_CHROMIUM_MODULE).args;
const pause=(ms)=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}

async function inspectLayout(page){
 return page.evaluate(()=>({viewport:window.innerWidth,body:document.body.scrollWidth,document:document.documentElement.scrollWidth,
  surfaces:[...document.querySelectorAll('.site-header,.site-header nav,.hero-copy,.workspace,.dossier,#review-result')].filter(e=>e.getBoundingClientRect().width>0).map(e=>{const r=e.getBoundingClientRect();return {selector:e.id||e.className,left:r.left,right:r.right,width:r.width};}),
  overflow:[...document.querySelectorAll('body *')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&(r.right>window.innerWidth+1||r.left < -1)&&!e.closest('.evidence-art')&&!e.classList.contains('sr-only');}).slice(0,12).map(e=>({tag:e.tagName,id:e.id,className:e.className,right:e.getBoundingClientRect().right}))}));
}
function assertLayout(value,label){
 assert(value.document<=value.viewport+1,`${label} horizontal page overflow: ${JSON.stringify(value)}`);
 for(const surface of value.surfaces)assert(surface.left>=-1&&surface.right<=value.viewport+1,`${label} overflowing surface: ${JSON.stringify(surface)}`);
 assert.deepEqual(value.overflow,[],`${label} overflowing content`);
}

(async()=>{
 const port=await freePort(); const base=`http://127.0.0.1:${port}`;
 const server=spawn(process.env.VERITAS_PYTHON||path.join(ROOT,'.venv','bin','python'),['-m','uvicorn','app:app','--host','127.0.0.1','--port',String(port)],{cwd:ROOT,env:{...process.env,STELLAR_NETWORK:'offline',ENABLE_SANDBOX_RUNTIME:'false',STATELESS_STUDIO:'true',ENABLE_PUBLIC_AI_REVIEW:'false',ENABLE_OFFICIAL_ORDERS:'false',LLM_API_KEY:''},stdio:['ignore','ignore','pipe']});
 let serverError=''; server.stderr.on('data',x=>{serverError+=x.toString();});
 let browser;
 try{
  let healthy=false;
  for(let i=0;i<100;i++){try{if((await fetch(base+'/api/v1/health')).ok){healthy=true;break;}}catch{} await pause(100);}
  assert(healthy,'Local app failed to start: '+serverError.slice(-1000));
  browser=await pw.launch(launchOptions);
  const ctx=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',acceptDownloads:true});
  const errors=[],consoleErrors=[],failedRequests=[],responses=[];
  ctx.on('page',(p)=>{
   p.on('pageerror',e=>errors.push(e.message));
   p.on('console',m=>{if(m.type()==='error')consoleErrors.push(m.text());});
   p.on('requestfailed',r=>failedRequests.push({url:r.url(),failure:r.failure()?.errorText}));
   p.on('response',r=>{if(r.status()>=400)responses.push({status:r.status(),url:r.url()});});
  });
  const page=await ctx.newPage();
  await page.goto(base,{waitUntil:'networkidle'});
  await page.waitForFunction(()=>document.querySelectorAll('#audit-tiers input').length===3&&document.querySelectorAll('#audit-modules input').length===8);
  assert.equal(await page.title(),'AgentVeritas — Trust, with evidence.');
  assert.equal(await page.locator('#order-create').isDisabled(),true);
  const availability=await page.locator('#order-availability').textContent();
  assert(!availability.includes('Checking'),'Order availability did not resolve');
  const caps=await (await fetch(base+'/api/v1/studio/orders/capabilities')).json();
  assert.equal(caps.available,false);
  assert.equal(await page.evaluate(()=>typeof window.freighterApi.signMessage),'function');
  await page.screenshot({path:OUT+'/desktop-hero.png'});
  await page.locator('[data-example="reader"]').click();
  await page.waitForFunction(()=>document.querySelector('#agent-name').value.length>0&&!document.querySelector('#run-review').disabled);
  const readerName=await page.locator('#agent-name').inputValue();
  assert((await page.locator('#file-list').innerText()).length>0);
  await page.locator('#preview-audit-plan').click();
  await page.waitForFunction(()=>!document.querySelector('#audit-plan').hidden&&document.querySelector('#audit-plan').textContent.includes('PLAN /'));
  assert.match(await page.locator('#audit-plan').innerText(),/Preview investigation/);
  await page.locator('#run-review').click();
  await page.waitForFunction(()=>!document.querySelector('#review-result').hidden,null,{timeout:30000});
  assert.equal(await page.locator('#result-name').innerText(),readerName);
  const reportHash=(await page.locator('#report-hash').textContent()).trim();
  assert.match(reportHash,/[a-f0-9]{64}/);
  const readerDecision=await page.locator('#result-decision').innerText();
  await page.locator('.dossier').scrollIntoViewIfNeeded();
  await page.screenshot({path:OUT+'/desktop-audit.png'});
  await page.locator('[data-result-view="coverage"]').click();
  assert.equal(await page.locator('#view-coverage').isVisible(),true);
  const controls=await page.locator('#control-results > .control-row').count();
  assert.equal(controls,24);
  await page.locator('[data-result-view="delivery"]').click();
  assert.match(await page.locator('#credential-status').innerText(),/not issued|unverified/i);
  await page.locator('#prepare-delivery').click();
  await page.waitForFunction(()=>document.querySelector('#delivery-results').textContent.includes('not')||document.querySelector('#delivery-results').textContent.includes('prepared'));
  assert.notEqual(await page.locator('#credential-card').getAttribute('data-issued'),'true');
  const downloadPromise=page.waitForEvent('download');
  await page.locator('#download-designed-report').click();
  const download=await downloadPromise;
  await download.saveAs(OUT+'/downloaded-report.html');
  assert(fs.statSync(OUT+'/downloaded-report.html').size>1000);
  await page.locator('#agent-name').fill(readerName+' changed');
  assert.equal(await page.locator('#review-result').isVisible(),false);
  await page.locator('[data-example="payment"]').click();
  await page.waitForFunction(()=>!document.querySelector('#run-review').disabled);
  await page.locator('#run-review').click();
  await page.waitForFunction(()=>!document.querySelector('#review-result').hidden,null,{timeout:30000});
  assert(Number(await page.locator('#priority-count').innerText())>0);
  const unsafeDecision=await page.locator('#result-decision').innerText();
  const unsafePriority=await page.locator('#priority-count').innerText();
  await page.locator('.dossier').scrollIntoViewIfNeeded();
  await page.screenshot({path:OUT+'/desktop-unsafe-report.png'});
  await page.locator('#checkout-panel > summary').click();
  assert.equal(await page.locator('#order-create').isDisabled(),true);
  assert.equal(await page.locator('#order-recover').isDisabled(),true);
  await page.locator('#checkout-panel').scrollIntoViewIfNeeded();
  await page.screenshot({path:OUT+'/desktop-orders-unavailable.png'});
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  const desktopLayout=await inspectLayout(page);
  assertLayout(desktopLayout,'Desktop');
  const mobile=await ctx.newPage();
  await mobile.setViewportSize({width:390,height:844});
  await mobile.goto(base,{waitUntil:'networkidle'});
  await mobile.screenshot({path:OUT+'/mobile-hero.png'});
  await mobile.locator('#tab-files').click();
  await mobile.locator('#source-files').setInputFiles({name:'reader.py',mimeType:'text/plain',buffer:fs.readFileSync(ROOT+'/examples/runtime-reader/main.py')});
  await mobile.waitForFunction(()=>document.querySelector('#file-list').textContent.includes('reader.py'));
  await mobile.locator('#agent-name').fill('Mobile uploaded reader');
  await mobile.locator('#agent-purpose').fill('Read balances and summarize results without signing transactions.');
  await mobile.locator('#run-review').click();
  await mobile.waitForFunction(()=>!document.querySelector('#review-result').hidden,null,{timeout:30000});
  assert.equal(await mobile.locator('#result-name').innerText(),'Mobile uploaded reader');
  await mobile.locator('#dossier-title').scrollIntoViewIfNeeded();
  await mobile.screenshot({path:OUT+'/mobile-audit.png'});
  const layout=await inspectLayout(mobile);
  assertLayout(layout,'Mobile');
  await mobile.setViewportSize({width:320,height:740});
  const narrowLayout=await inspectLayout(mobile);
  assertLayout(narrowLayout,'Narrow mobile');
  // Optional live-chain QA of an already executed, delivered report. This is
  // report rendering/readback, not a recording of wallet signing or execution.
  let deliveredReport = null;
  if(process.env.VERITAS_DELIVERED_REPORT && process.env.VERITAS_DELIVERY_PROOF){
   const envelope=JSON.parse(fs.readFileSync(process.env.VERITAS_DELIVERED_REPORT,'utf8'));
   const proof=JSON.parse(fs.readFileSync(process.env.VERITAS_DELIVERY_PROOF,'utf8'));
   assert.equal(proof.status,'verified');
   const delivery=proof.delivery;
   assert.equal(delivery.report_sha256,envelope.report_sha256);
   const credential={contract_id:delivery.credential_contract_id,token_id:delivery.token_id,owner:delivery.owner};
   await page.evaluate(({envelope,credential,order_id})=>new Promise((resolve,reject)=>window.dispatchEvent(new CustomEvent('veritas:order-report',{detail:{envelope,credential,order_id,resolve,reject}}))),{envelope,credential,order_id:proof.order_id});
   await page.locator('[data-result-view="runtime"]').click();
   const runtimeText=await page.locator('#runtime-results').innerText();
   assert.match(runtimeText,/restart replay/);
   assert.match(runtimeText,/needs_investigation/);
   assert.match(runtimeText,/KeyError/);
   assert.match(runtimeText,/live_testnet/);
   await page.locator('#runtime-results').scrollIntoViewIfNeeded();
   await page.screenshot({path:OUT+'/delivered-deep-runtime.png'});
   assertLayout(await inspectLayout(page),'Delivered desktop');
   await page.locator('[data-result-view="delivery"]').click();
   assert.match(await page.locator('#delivery-results').innerText(),/Onchain record verified/);
   await page.locator('#credential-card').scrollIntoViewIfNeeded();
   await page.screenshot({path:OUT+'/delivered-deep-credential.png'});
   const downloaded=page.waitForEvent('download');
   await page.locator('#download-designed-report').click();
   await (await downloaded).saveAs(OUT+'/delivered-deep-report.html');
   await page.setViewportSize({width:390,height:844});
   await page.locator('[data-result-view="runtime"]').click();
   assertLayout(await inspectLayout(page),'Delivered mobile');
   deliveredReport={report_sha256:envelope.report_sha256,order_id:proof.order_id,
      live_credential_readback:true,workflow_findings_rendered:true,designed_report_downloaded:true,
      execution_replayed:false,wallet_signing_recorded:false};
  }
  assert.deepEqual(errors,[],'Uncaught browser errors');
  assert.deepEqual(consoleErrors,[],'Console errors');
  assert.deepEqual(failedRequests,[],'Failed requests');
  assert.deepEqual(responses,[],'HTTP errors');
  const result={deliveredReport,status:'passed',browser:await browser.version(),localhost:base,live_backend:true,desktop:{viewport:'1440x1000',layout:desktopLayout,tiers:3,official_modules:8,reader_decision:readerDecision,unsafe_decision:unsafeDecision,unsafe_priority_findings:Number(unsafePriority),coverage_controls:controls,report_download:true,source_edit_invalidates_report:true},mobile:{viewport:'390x844',real_file_upload_and_audit:true,layout,narrow_layout:narrowLayout},official_orders:{available:false,create_disabled:true,recovery_disabled:true,reason:availability},wallet:{library_loaded:true,extension_e2e:false},console_errors:consoleErrors,page_errors:errors,failed_requests:failedRequests,http_errors:responses,screenshots:['desktop-hero.png','desktop-audit.png','desktop-unsafe-report.png','desktop-orders-unavailable.png','mobile-hero.png','mobile-audit.png']};
  fs.writeFileSync(OUT+'/result.json',JSON.stringify(result,null,2)); console.log(JSON.stringify(result,null,2));
 }finally{if(browser)await browser.close();if(server.exitCode===null){server.kill('SIGTERM');await new Promise(r=>server.once('exit',r));}}
})().catch(e=>{console.error(e);process.exitCode=1;});
