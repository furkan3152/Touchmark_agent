/* Run with Node and jsdom 26.1.0 installed (or NODE_PATH pointing to it).
   All wallet, network and worker calls below are explicit test doubles. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto,createHash} = require('node:crypto');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'frontend/studio.html'), 'utf8');
const pilot = JSON.parse(fs.readFileSync(path.join(root, 'deployments/testnet-audit-delivery-2026-10-15.json'), 'utf8'));
const TESTNET = 'Test SDF Network ; September 2015';
const requester = pilot.roles.requester;
const id = 'b'.repeat(64), token = 'f'.repeat(64), planHash = 'a'.repeat(64), sourceHash = 'c'.repeat(64);
const tick = () => new Promise(resolve => setTimeout(resolve, 45));
function setup({available = true} = {}) {
  const dom = new JSDOM(html, {url:'https://example.test',runScripts:'outside-only',pretendToBeVisual:true});
  const w = dom.window;
  Object.defineProperty(w, 'crypto', {value:webcrypto});
  const originalTimeout = w.setTimeout;
  w.setTimeout = (fn, ms) => originalTimeout(fn, ms === 1500 ? 5 : ms);
  w.URL.createObjectURL = () => 'blob:private-receipt-test'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  const state = {funded:false, wrongNetwork:false, messageSigns:0, txSigns:0, submissions:0, reportOpened:0, calls:[], order:null, activeToken:token, preparedStep:'fund', refunded:false};
  const quote = {requester,network:'testnet',network_passphrase:TESTNET,tier_id:'quick',amount_atomic:'1000000',fee_bps:1500,expires_at:Math.floor(Date.now()/1000)+300,agent_id:'d'.repeat(64),request_id:id,source_sha256:sourceHash,plan_sha256:planHash};
  const summary = (status) => ({order_id:id,request_id:id,requester,status,source_sha256:sourceHash,plan_sha256:planHash,created_at:Date.now()/1000,updated_at:Date.now()/1000,attempts:0,report_available:false,report_sha256:null,payment_confirmed:state.funded,checked_at_ledger:123,failure_code:null,retryable:false,delivery:null});
  w.freighterApi = {isConnected:async()=>({isConnected:true}),requestAccess:async()=>({address:requester}),getAddress:async()=>({address:requester}),getNetworkDetails:async()=>({networkPassphrase:state.wrongNetwork?'Public Global Stellar Network ; September 2015':TESTNET}),signMessage:async(message,options)=>{state.messageSigns++;assert.match(message,/ownership/i);assert.equal(options.address,requester);assert.equal(options.networkPassphrase,TESTNET);return {signedMessage:new Uint8Array(64).fill(7),signerAddress:requester};},signTransaction:async(xdr,options)=>{state.txSigns++;assert.equal(xdr,'AAAA');assert.equal(options.networkPassphrase,TESTNET);return {signedTxXdr:'AAAASIGNED',signerAddress:requester};}};
  w.fetch = async (url,options={}) => {
    const body=options.body?JSON.parse(options.body):null;
    state.calls.push({url,method:options.method||'GET',headers:options.headers||{},body});
    let value,ok=true,status=200;
    if(url.endsWith('/orders/capabilities'))value={available,automatic_settlement:available,storage_mode:available?'durable_sqlite':'unavailable',reason:available?'':'Persistent worker unavailable.'};
    else if(url.endsWith('/checkout'))value={quote,quote_signature:'9'.repeat(64),status:state.funded?'funded':'ready',next_step:state.funded?null:'fund',steps:[{id:'register',label:'Register source',state:'complete'},{id:'fund',label:'Fund escrow',state:state.funded?'complete':'pending'}],chain:{wallet_funded:true},payment_confirmed:state.funded};
    else if(url.endsWith('/orders/challenge')){assert.equal(body.storage_consent,true);assert.equal(body.auto_settlement_consent,true);assert.equal(body.publication_consent,true);const now=Math.floor(Date.now()/1000);value={message:'AgentVeritas ownership proof for this private order',challenge:{domain:'agentveritas-stellar:official-order:v1',network_passphrase:TESTNET,requester,plan_sha256:planHash,submission_sha256:'1'.repeat(64),nonce:'2'.repeat(64),issued_at:now,expires_at:now+300},challenge_signature:'3'.repeat(64),signature_standard:'SEP-53',network:'testnet'};}
    else if(url.endsWith('/orders')&&options.method==='POST'){assert.equal(Buffer.from(body.wallet_proof.wallet_signature,'base64').length,64);assert.equal(state.funded,false);state.order=summary('awaiting_payment');value={...state.order,order_token:token};}
    else if(url.endsWith('/orders/recover')){assert.equal(state.funded,true);state.activeToken='6'.repeat(64);value={...state.order,order_token:state.activeToken};}
    else if(url.endsWith('/checkout/prepare')){assert.equal(options.headers['X-Order-ID'],id);assert.equal(options.headers['X-Order-Token'],state.activeToken);state.preparedStep='fund';value={unsigned_xdr:'AAAA',network_passphrase:TESTNET,signer:requester,step:'fund',transaction_hash:'e'.repeat(64),fee_atomic:'100',expires_at:Math.floor(Date.now()/1000)+100,simulation:{status:'succeeded'}};}
    else if(url.endsWith(`/orders/${id}/activate`)){assert.equal(state.funded,true);assert.equal(options.headers['X-Order-Token'],state.activeToken);state.order=summary(state.refunded?'refunded':'queued');value=state.order;}
    else if(url.endsWith(`/orders/${id}/refund/reconcile`)){assert.equal(options.headers['X-Order-Token'],state.activeToken);if(state.refunded)state.order=summary('refunded');value={...state.order,refund_checked_at_ledger:124,refund_eligible:!state.refunded};}
    else if(url.endsWith(`/orders/${id}/retry`)){assert.equal(options.headers['X-Order-Token'],state.activeToken);state.order=summary('settling');value=state.order;}
    else if(url.endsWith(`/orders/${id}/refund/prepare`)){assert.equal(options.headers['X-Order-Token'],state.activeToken);state.preparedStep='refund';value={request_id:id,unsigned_xdr:'AAAA',network_passphrase:TESTNET,signer:requester,step:'refund',transaction_hash:'e'.repeat(64),fee_atomic:'100',expires_at:Math.floor(Date.now()/1000)+100,simulation:{status:'succeeded'}};}
    else if(url.endsWith(`/orders/${id}/result`)){assert.equal(options.headers['X-Order-Token'],state.activeToken);value={report_json:'{}',report_sha256:state.order.report_sha256};}
    else if(url.endsWith(`/orders/${id}`)){if(options.headers['X-Order-Token']!==state.activeToken){ok=false;status=404;value={detail:'Order not found or private access key is invalid.'};}else value=state.order;}
    else if(body?.method==='sendTransaction'){state.submissions++;value={result:{status:'PENDING',hash:'e'.repeat(64)}};}
    else if(body?.method==='getTransaction'){state.funded=true;if(state.preparedStep==='refund')state.refunded=true;value={result:{status:'SUCCESS'}};}
    else throw new Error(`Unexpected request: ${url}`);
    return {ok,status,json:async()=>value};
  };
  w.addEventListener('veritas:order-report',(event)=>{state.reportOpened++;assert.equal(event.detail.order_id,id);event.detail.resolve();});
  w.eval(fs.readFileSync(path.join(root,'frontend/checkout.js'),'utf8'));
  w.eval(fs.readFileSync(path.join(root,'frontend/orders.js'),'utf8'));
  w.document.getElementById('checkout-key').value='mock-pilot-key';
  const engagement={source:{network:'testnet',ai_assistance:false},tier_id:'quick',module_ids:['intent'],execution_consent:false,plan_sha256:planHash};
  w.dispatchEvent(new w.CustomEvent('veritas:plan',{detail:{engagement,planned:{plan_sha256:planHash,plan:{source_sha256:sourceHash}}}}));
  return {dom,w,state,summary};
}

async function verifyReportBridge() {
  const dom=new JSDOM(html,{url:'https://example.test',runScripts:'outside-only'});const w=dom.window;
  try {
    w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;Object.defineProperty(w,'crypto',{value:webcrypto});
    const original=JSON.parse(fs.readFileSync(path.join(root,pilot.report.path),'utf8'));
    original.engagement={plan:{tier:{id:'quick',name:'Preview'},modules:[],budgets:{runtime_cases:0}},plan_sha256:planHash,module_results:[],runtime:null};
    const reportJson=JSON.stringify(original);const reportHash=createHash('sha256').update(reportJson).digest('hex');
    const envelope={report_json:reportJson,report_sha256:reportHash,decision:original.review_decision,scope:original.review_scope};
    let deliveryStatus='invalid';
    w.fetch=async(url,options)=>({ok:true,json:async()=>url.endsWith('/catalog')?{tiers:[{id:'quick',name:'Preview',budgets:{runtime_cases:0},price:{amount:'3',live:false}}],modules:[{id:'intent',name:'Intent Analyst',description:'Declared intent',default_selected:true}]}:url.endsWith('/capabilities')?{ai_available:false,controls:[]}:url.endsWith('/delivery')?{status:deliveryStatus,report_sha256:JSON.parse(options.body).report_sha256,proof:{note:'Test-double ledger response'},artifacts:{html:'report',svg:'svg',metadata:{}}}:{available:false}});
    w.eval(fs.readFileSync(path.join(root,'frontend/studio.js'),'utf8'));await tick();
    const open=(value,credential=null)=>new Promise((resolve,reject)=>w.dispatchEvent(new w.CustomEvent('veritas:order-report',{detail:{envelope:value,credential,order_id:id,resolve,reject}})));
    await open(envelope);
    assert.equal(w.document.getElementById('agent-name').value,'');assert.equal(w.document.getElementById('review-result').hidden,false);assert.equal(w.document.getElementById('download-bundle').hidden,true);assert.equal(w.document.getElementById('run-runtime').disabled,true);assert.equal(w.document.getElementById('report-hash').textContent,reportHash);
    await assert.rejects(open({...envelope,report_sha256:'0'.repeat(64)}),/integrity/);
    const credential={contract_id:pilot.contracts.credential.id,token_id:pilot.token_id,owner:requester};
    await open(envelope,credential);assert.equal(w.document.getElementById('credential-card').dataset.issued,'false');
    deliveryStatus='current';await open(envelope,credential);assert.equal(w.document.getElementById('credential-card').dataset.issued,'true');
  } finally {dom.window.close();}
}

(async()=>{
  let {dom,w,state,summary}=setup();
  try {
    await tick(); assert.equal(state.messageSigns,0);assert.equal(state.txSigns,0);
    w.document.getElementById('checkout-connect').click();await tick();w.document.getElementById('checkout-quote').click();await tick();
    w.document.querySelector('#checkout-quote-result>button').click();await tick();assert.equal(state.calls.filter(c=>c.url.endsWith('/checkout/prepare')).length,0);assert.match(w.document.getElementById('checkout-status').textContent,/private order/);
    w.document.getElementById('order-consent').click();w.document.getElementById('order-create').click();await tick();assert.equal(state.messageSigns,0);assert.equal(w.document.getElementById('order-challenge').hidden,false);
    state.wrongNetwork=true;w.document.getElementById('order-sign-create').click();await tick();assert.equal(state.messageSigns,0);assert.match(w.document.getElementById('order-intake-status').textContent,/Testnet/);
    state.wrongNetwork=false;w.document.getElementById('order-sign-create').click();await tick();await tick();assert.equal(state.messageSigns,1);assert.equal(w.document.getElementById('order-state').textContent,'Awaiting payment');assert.equal(state.submissions,0);assert.equal(w.document.body.textContent.includes(token),false);
    w.document.querySelector('#checkout-quote-result>button').click();await tick();w.document.getElementById('checkout-sign').click();await tick();assert.equal(state.txSigns,1);assert.equal(state.submissions,0);
    w.document.getElementById('checkout-submit').click();await tick();await tick();await tick();assert.equal(state.submissions,1);assert.equal(w.document.getElementById('order-state').textContent,'Queued');
    assert.ok(state.calls.findIndex(c=>c.url.endsWith('/orders')&&c.method==='POST')<state.calls.findIndex(c=>c.body?.method==='sendTransaction'));
    state.order={...summary('failed'),failure_code:'settlement_failed',retryable:true,report_available:true,report_sha256:'4'.repeat(64)};w.document.getElementById('order-refresh').click();await tick();assert.match(w.document.getElementById('order-description').textContent,/does not imply a refund/);assert.equal(w.document.getElementById('order-open-report').hidden,false);assert.equal(w.document.getElementById('order-retry').hidden,false);
    w.document.getElementById('order-open-report').click();await tick();assert.equal(state.reportOpened,1);
    w.document.getElementById('order-retry').click();await tick();assert.equal(w.document.getElementById('order-state').textContent,'Settling on Stellar');
    w.dispatchEvent(new w.CustomEvent('veritas:invalidate'));assert.equal(w.document.getElementById('official-order').hidden,false);assert.equal(w.document.getElementById('checkout-quote-result').hidden,true);
    assert.equal(w.localStorage.length,0);assert.equal(w.sessionStorage.length,0);
    w.document.getElementById('order-resume-id').value=id;w.document.getElementById('order-resume-token').value='0'.repeat(64);w.document.getElementById('order-resume').click();await tick();assert.match(w.document.getElementById('order-intake-status').textContent,/invalid/);
    w.document.getElementById('order-resume-token').value=token;w.document.getElementById('order-resume').click();await tick();assert.equal(w.document.getElementById('order-resume-token').value,'');
    w.dispatchEvent(new w.CustomEvent('veritas:plan',{detail:{engagement:{source:{network:'testnet'},tier_id:'quick',plan_sha256:planHash},planned:{plan_sha256:planHash,plan:{source_sha256:sourceHash}}}}));w.document.getElementById('checkout-quote').click();await tick();w.document.getElementById('order-recover').click();await tick();assert.match(w.document.getElementById('order-sign-create').textContent,/recover/);w.document.getElementById('order-sign-create').click();await tick();await tick();assert.equal(state.activeToken,'6'.repeat(64));assert.match(w.document.getElementById('order-intake-status').textContent,/previous access token is invalid/);
    w.document.getElementById('order-refund').click();await tick();assert.match(w.document.getElementById('checkout-transaction-detail').textContent,/Refund for order/);assert.equal(state.submissions,1);w.document.getElementById('checkout-sign').click();await tick();assert.equal(state.submissions,1);w.document.getElementById('checkout-submit').click();await tick();await tick();await tick();assert.equal(state.submissions,2);assert.equal(w.document.getElementById('order-state').textContent,'Refund confirmed');
  } finally {dom.window.close();}
  ({dom,w,state}=setup({available:false}));
  try {await tick();w.document.getElementById('checkout-requester').value=requester;w.document.getElementById('checkout-quote').click();await tick();w.document.getElementById('order-consent').click();assert.equal(w.document.getElementById('order-create').disabled,true);w.document.querySelector('#checkout-quote-result>button').click();await tick();assert.match(w.document.getElementById('checkout-status').textContent,/unavailable/);assert.equal(state.submissions,0);} finally {dom.window.close();}
  await verifyReportBridge();
  console.log('PASS official order UI: explicit SEP-53 ownership, pre-funding capability gate, separate payment submission, funded activation, honest progress/failure, protected report access and canonical hash verification, live credential gating, secure resume/recovery, separately signed refund, unavailable-worker block; no browser persistence.');
})().catch(error=>{console.error(error);process.exitCode=1;});
