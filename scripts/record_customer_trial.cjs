/* Genuine local UI recording. No mocked requests, wallet or success state.
 * Requires Playwright, Chromium and ffmpeg supplied by the operator.
 */
const fs=require('node:fs'),path=require('node:path'),{spawn}=require('node:child_process');
const {chromium}=require('playwright');
const ROOT=path.resolve(__dirname,'..'),OUT=process.env.TRIAL_VIDEO_OUT;
if(!OUT)throw Error('Set TRIAL_VIDEO_OUT');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 const server=spawn(path.join(ROOT,'.venv/bin/python'),['-m','uvicorn','app:app','--host','127.0.0.1','--port','8769'],{cwd:ROOT,env:{...process.env,STATELESS_STUDIO:'true',ENABLE_SANDBOX_RUNTIME:'false',ENABLE_PUBLIC_AI_REVIEW:'false',ENABLE_OFFICIAL_ORDERS:'false',STELLAR_NETWORK:'offline'},stdio:'ignore'});
 let browser,ctx;
 try{
  for(let i=0;i<100;i++){try{if((await fetch('http://127.0.0.1:8769/api/v1/health')).ok)break;}catch{}await pause(100);}
  const c=require('/tmp/agentveritas-browser-qa/node_modules/@sparticuz/chromium');
  browser=await chromium.launch({executablePath:await c.executablePath(),args:c.args,headless:true});
  ctx=await browser.newContext({viewport:{width:1440,height:1000},recordVideo:{dir:OUT,size:{width:1440,height:1000}},reducedMotion:'reduce',acceptDownloads:true});
  const page=await ctx.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:8769',{waitUntil:'networkidle'});
  async function caption(text){await page.evaluate(text=>{let e=document.getElementById('trial-tutorial-caption');if(!e){e=document.createElement('div');e.id='trial-tutorial-caption';Object.assign(e.style,{position:'fixed',bottom:'20px',left:'40px',right:'40px',zIndex:'99999',padding:'18px 24px',background:'#10202bf0',color:'white',font:'19px system-ui',borderRadius:'12px',boxShadow:'0 4px 30px #0003',pointerEvents:'none'});document.body.append(e);}e.textContent='KAYIT AÇIKLAMASI • '+text;},text);}
  await caption('Gerçek localhost kaydı. InvoicePilot: model kararıyla Testnet faturası ödeyen agent.');await pause(4000);
  await page.locator('#tab-files').click();
  await page.locator('#source-files').setInputFiles(ROOT+'/research/customer-trial-2026-10-15/invoicepilot.veritas');
  await page.waitForFunction(()=>document.querySelector('#agent-name').value==='invoicepilot');
  await page.locator('#file-list').scrollIntoViewIfNeeded();await caption('1. Zorunlu .veritas paketi yüklenir. Gerçek kaynaklar, giriş noktası, yetkiler ve senaryolar birlikte gelir.');await pause(6000);
  await page.locator('.capsule-details > summary').click();await page.locator('#capsule-state').scrollIntoViewIfNeeded();await pause(5000);
  await page.locator('#preview-audit-plan').click();
  await page.waitForFunction(()=>!document.querySelector('#audit-plan').hidden);
  await page.locator('#audit-plan').scrollIntoViewIfNeeded();
  await caption('2. Deep planı: 24 senaryo. Bu localhost ortamında izole çalışma kapalı; engel gizlenmiyor.');await pause(7000);
  const deepPlan=await page.locator('#audit-plan').innerText();
  // A separately sealed Quick capsule retains all source/policy/scenarios. Explicit tier change only.
  await page.reload({waitUntil:'networkidle'});await page.locator('#tab-files').click();
  await page.locator('#source-files').setInputFiles(OUT+'/invoicepilot-source-review.veritas');
  await page.waitForFunction(()=>document.querySelector('#agent-name').value==='invoicepilot');
  await caption('3. Ayrı Quick kapsülü: aynı kaynaklar, yalnız kaynak incelemesi. Bu sonuç davranış denetimi değildir.');
  await page.locator('#preview-audit-plan').click();await page.waitForFunction(()=>!document.querySelector('#audit-plan').hidden);
  await page.locator('#audit-plan').scrollIntoViewIfNeeded();await pause(5000);
  await page.locator('#run-review').click();
  await page.waitForFunction(()=>!document.querySelector('#review-result').hidden,null,{timeout:30000});
  await page.locator('#review-result').scrollIntoViewIfNeeded();
  await caption('4. Gerçek backend raporu: bulgular ve rapor özeti. Puan, güvenlik garantisi değildir.');await pause(7000);
  const decision=await page.locator('#result-decision').innerText();const hash=await page.locator('#report-hash').innerText();
  await page.locator('[data-result-view="coverage"]').click();await page.locator('#view-coverage').scrollIntoViewIfNeeded();
  await caption('5. Kapsamı inceleyin: çalıştırılmamış kontroller doğrulanmış sayılmaz.');await pause(7000);
  await page.locator('[data-result-view="delivery"]').click();await page.locator('#credential-status').scrollIntoViewIfNeeded();
  await caption('6. Bu kaynak incelemesinde NFT çıkarılmadı. İndirilebilir rapor ile zincirde çıkarılmış belge farklıdır.');await pause(6000);
  const promise=page.waitForEvent('download');await page.locator('#download-designed-report').click();const dl=await promise;await dl.saveAs(OUT+'/invoicepilot-source-report.html');
  await caption('7. Tasarımlı rapor indirildi. Canlı Testnet sonuçları ayrı kanıt tablosunda; bu kayıt cüzdan imzasını doğrulamaz.');await pause(5000);
  fs.writeFileSync(OUT+'/recording-evidence.json',JSON.stringify({real_local_backend:true,mocked_requests:false,deepPlan,decision,reportHash:hash,pageErrors:errors,wallet_extension_verified:false,nft_issued:false},null,2));
  const video=page.video();await ctx.close();ctx=null;fs.renameSync(await video.path(),OUT+'/agentveritas-usage.webm');console.log('Real UI recording completed');
 }finally{if(ctx)await ctx.close();if(browser)await browser.close();server.kill('SIGTERM');}
})().catch(e=>{console.error(e);process.exitCode=1;});
