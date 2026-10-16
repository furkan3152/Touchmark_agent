/* Private official orders. Access capabilities stay in memory or an explicitly downloaded receipt. */
"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  const node = (tag,text,className) => {const item=document.createElement(tag);if(text!==undefined)item.textContent=text;if(className)item.className=className;return item;};
  const HEX = /^[a-f0-9]{64}$/;
  const STATES = ["awaiting_payment","queued","running","report_ready","settling","delivered","failed","refunded"];
  const ACTIVE = new Set(["queued","running","report_ready","settling"]);
  const STEPS = [["queued","Queued"],["running","Official review"],["report_ready","Report ready"],["settling","Stellar settlement"],["delivered","Delivered"]];
  let context=null, capability=null, order=null, capabilities=null, timer=null, working=false, generation=0, challenge=null, refreshSequence=0, pendingRefund=null;
  function intake(text){byId("order-intake-status").textContent=text;}
  function status(text){byId("order-status-note").textContent=text;}
  function available(){return capabilities?.available===true&&capabilities?.automatic_settlement===true;}
  function clearTimer(){if(timer){clearTimeout(timer);timer=null;}}
  function setWorking(value){working=value;for(const id of ["order-resume","order-refresh","order-activate","order-open-report","order-retry","order-sign-create","order-refund"])byId(id).disabled=value;updateCreate();}
  function updateCreate(){byId("order-recover").disabled=working||!available()||!context||!byId("order-consent").checked;byId("order-create").disabled=working||!available()||!context||context.checkout.payment_confirmed===true||!byId("order-consent").checked||Boolean(context&&matchQuote(context.checkout.quote));}
  function errorMessage(value,http){return typeof value.detail==="string"?value.detail:Array.isArray(value.detail)?value.detail.map((item)=>item.msg).join("; "):value.detail?.message||`The order request could not be completed (HTTP ${http}).`;}
  async function request(path,{method="GET",body,cap=capability,ai=false}={}){
    const key=byId("checkout-key").value.trim();if(!key)throw new Error("Enter the pilot access key in the checkout panel to open this private order.");
    const headers={Authorization:`Bearer ${key}`};if(cap)headers["X-Order-Token"]=cap.order_token;if(body!==undefined)headers["Content-Type"]="application/json";
    if(ai&&byId("ai-access-key").value.trim())headers["X-AI-Review-Key"]=byId("ai-access-key").value.trim();
    const response=await fetch(`/api/v1/studio/${path}`,{method,headers,...(body!==undefined?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(45000)});
    const value=await response.json();if(!response.ok)throw new Error(errorMessage(value,response.status));return value;
  }
  function matchQuote(quote){return capability&&order&&order.order_id===quote.request_id&&order.requester===quote.requester&&order.plan_sha256===quote.plan_sha256&&order.source_sha256===quote.source_sha256;}
  function verifiedDelivery(value){const d=value.delivery;return value.status==="delivered"&&d?.is_current===true&&d.report_sha256===value.report_sha256&&HEX.test(d.token_id||"")&&/^C[A-Z2-7]{55}$/.test(d.credential_contract_id||"")&&/^[GC][A-Z2-7]{55}$/.test(d.owner||"")&&Number.isInteger(d.checked_at_ledger);}
  // A completed review that did not pass: payment settled, no credential by design.
  function deliveredWithoutCredential(value){const d=value.delivery;return value.status==="delivered"&&d?.credential_status==="not_eligible"&&d.is_current===false&&d.token_id===null&&d.payment_state==="Complete"&&d.report_sha256===value.report_sha256&&Number.isInteger(d.checked_at_ledger);}
  function render(value){
    if(!capability||value.order_id!==capability.order_id||!STATES.includes(value.status))throw new Error("The returned order does not match this private receipt.");
    order=value;updateCreate();
    const section=byId("official-order");section.hidden=false;section.dataset.state=value.status;
    const stateNames={awaiting_payment:"Awaiting payment",queued:"Queued",running:"Review in progress",report_ready:"Report ready",settling:"Settling on Stellar",delivered:verifiedDelivery(value)?"Delivered":deliveredWithoutCredential(value)?"Delivered · no credential":"Delivery needs verification",failed:"Action needed",refunded:"Refund confirmed"};
    byId("order-state").textContent=stateNames[value.status];
    const copy={
      awaiting_payment:["Your scope is saved.","Complete the wallet funding steps. The official review starts after the funded escrow is verified."],
      queued:["Your review is in the queue.","Funding was checked by the service. Your saved source and selected plan are waiting for the official worker."],
      running:["The evidence is taking shape.","Official reviewers are processing the saved scope. Only completed checks will appear as evidence in the report."],
      report_ready:["Your report is ready.","Open the findings now. Payment settlement and credential delivery have their own verified steps."],
      settling:["The record is moving onchain.","The worker is committing the report, settling the scoped escrow and issuing its credential. Delivery is shown after ledger readback."],
      delivered:verifiedDelivery(value)?["Your report. Your record.","The service recorded matching report, owner and credential readbacks. Open the dossier to check the credential against the live ledger."]:deliveredWithoutCredential(value)?["Your report is delivered.","The audit did not pass, so no credential was issued. The review payment settled. Open the report for the fixes or evidence that are required."]:["The delivery needs a closer look.","A delivered status arrived without a complete matching credential receipt. Open the report and verify its chain record before relying on delivery."],
      failed:["Your order needs attention.","Processing stopped at a reported failure. Your existing report, when available, remains accessible. This does not imply a refund."],
      refunded:["The escrow refund is recorded.","The service reports a confirmed refund for this order. Any available report remains a record of work already completed."]
    };
    byId("order-title").textContent=copy[value.status][0];byId("order-description").textContent=copy[value.status][1];
    const progress=byId("order-progress");progress.replaceChildren();const index=STEPS.findIndex(([id])=>id===value.status);
    STEPS.forEach(([id,label],i)=>{const item=node("li");const complete=index>=0&&i<index||(value.status==="delivered"&&(verifiedDelivery(value)||deliveredWithoutCredential(value)));item.dataset.state=complete?"complete":i===index?"active":"pending";item.append(node("span",complete?"✓":String(i+1).padStart(2,"0"),"order-step-number"),node("strong",label),node("span",complete?"Recorded":i===index?"Current":"Pending","order-step-status"));progress.append(item);});
    const issue=byId("order-issue");issue.hidden=value.status!=="failed";issue.replaceChildren();
    if(value.status==="failed"){
      const reasons={payment_not_confirmed:"Funding could not be verified. Check the escrow state before attempting further payment.",runtime_unavailable:"The isolated runtime provider is unavailable.",audit_failed:"The scoped audit did not finish.",publication_failed:"The private report could not be stored for delivery.",settlement_failed:"The Stellar settlement did not complete.",credential_failed:"The credential could not be issued or verified.",deadline_expired:"The escrow deadline has passed."};
      issue.append(node("strong",reasons[value.failure_code]||"The service reported a processing failure."));
      if(value.failure_code)issue.append(node("code",`Reference: ${value.failure_code}`));
      issue.append(node("p",value.retryable===true?"This order is eligible for a server-controlled retry. Completed work is not automatically purchased again.":"Automatic retry is not available for this state. Contact the official operator with your order ID. A refund is shown only after confirmation."));
    }
    byId("order-open-report").hidden=value.report_available!==true;
    if(value.status==="refunded"||value.status==="delivered")pendingRefund=null;
    byId("order-activate").hidden=value.status!=="awaiting_payment"&&pendingRefund!==value.order_id;
    byId("order-activate").textContent=pendingRefund===value.order_id?"Check refund receipt":"Check funding & continue";
    byId("order-refund").hidden=["delivered","refunded"].includes(value.status);
    byId("order-retry").hidden=!(value.status==="failed"&&value.retryable===true);
    byId("order-id").textContent=`ORDER / ${value.order_id}`;byId("order-source-hash").textContent=`SOURCE / ${value.source_sha256||"Not returned"}`;byId("order-plan-hash").textContent=`PLAN / ${value.plan_sha256||"Not returned"}`;
    if(value.updated_at){const updated=new Date(typeof value.updated_at==="number"?value.updated_at*1000:value.updated_at);status(Number.isNaN(updated.getTime())?"This view follows recorded server states.":`Last service update: ${updated.toISOString().replace("T"," ").slice(0,19)} UTC. This view follows recorded server states.`);}
    schedule();
  }
  function schedule(){clearTimer();if(order&&ACTIVE.has(order.status)&&!document.hidden)timer=setTimeout(()=>refresh(false),4000);}
  async function refresh(manual=true){
    if(!capability||working){if(!manual)schedule();return;}
    const captured=capability;const current=generation;const sequence=++refreshSequence;
    if(manual)setWorking(true);
    try{const value=await request(`orders/${captured.order_id}`,{cap:captured});if(current!==generation||sequence!==refreshSequence)return;render(value);}
    catch(error){if(current===generation){clearTimer();status(`${error.message} Your saved order is not cancelled. Use Refresh status to try again.`);}}
    finally{if(manual)setWorking(false);}
  }
  async function activate(){
    if(!capability||working||(order?.status!=="awaiting_payment"&&pendingRefund!==order?.order_id))return;
    setWorking(true);clearTimer();const current=generation;
    try{status(pendingRefund===order?.order_id?"Checking the refund against live escrow state…":"Checking escrow funding before the review can enter the queue…");const path=pendingRefund===order?.order_id?`orders/${capability.order_id}/refund/reconcile`:`orders/${capability.order_id}/activate`;const value=await request(path,{method:"POST",body:{}});if(current===generation)render(value);}
    catch(error){status(`${error.message} No queued state is assumed. Refresh status or check funding again.`);}
    finally{setWorking(false);}
  }
  async function openCapability(id,token){
    if(!HEX.test(id)||!HEX.test(token))throw new Error("Use the 64-character order ID and private access token from your receipt.");
    const cap={order_id:id,order_token:token};const value=await request(`orders/${id}`,{cap});
    clearTimer();generation++;capability=cap;render(value);byId("order-resume-token").value="";
    intake("Private order opened. Its source and report stay behind the order capability.");
  }
  window.addEventListener("veritas:checkout-ready",(event)=>{context=event.detail;updateCreate();if(context.checkout.payment_confirmed&&!matchQuote(context.checkout.quote))intake("This funded request needs its existing private receipt. Resume that order; a replacement order will not be created.");});
  window.addEventListener("veritas:checkout-reset",()=>{context=null;challenge=null;byId("order-challenge").hidden=true;updateCreate();});
  window.addEventListener("veritas:order-required",(event)=>{event.preventDefault();if(!available()){event.detail.reject(new Error("Official order processing is unavailable. Funding stays blocked until the service is ready."));return;}if(!matchQuote(event.detail.quote)){event.detail.reject(new Error("Create or resume the private order matching this quote before funding."));return;}if(order.status!=="awaiting_payment"){event.detail.reject(new Error("This private order is not awaiting payment. Refresh its state before funding."));return;}event.detail.resolve({...capability});});
  window.addEventListener("veritas:order-funded",(event)=>{if(matchQuote(event.detail.quote)&&order.status==="awaiting_payment")activate();});
  byId("order-consent").addEventListener("change",updateCreate);
  async function prepareChallenge(action="create"){
    if(working||!context||!available()||!byId("order-consent").checked)return;
    const captured=context;setWorking(true);intake("Preparing the wallet ownership message for this exact review scope…");
    try{
      const submission={engagement:captured.engagement,requester:captured.checkout.quote.requester,storage_consent:true,auto_settlement_consent:true,publication_consent:true};
      const value=await request("orders/challenge",{method:"POST",body:submission,cap:null,ai:captured.engagement.ai_assistance===true||captured.engagement.source?.ai_assistance===true});
      if(context!==captured)throw new Error("The review scope changed. Prepare a new ownership message.");
      const message=value.message||value.challenge?.message;
      const c=value.challenge;
      if(!c||value.signature_standard!=="SEP-53"||value.network!=="testnet"||c.network_passphrase!=="Test SDF Network ; September 2015"||c.requester!==submission.requester||c.plan_sha256!==captured.planned.plan_sha256||!Number.isFinite(c.expires_at)||c.expires_at<=Date.now()/1000||c.expires_at-c.issued_at!==300||!HEX.test(value.challenge_signature||"")||typeof message!=="string"||!message||message.length>12000)throw new Error("The service did not return a matching, unexpired ownership challenge.");
      challenge={response:value,submission,context:captured,message,action};byId("order-challenge-message").value=message;byId("order-challenge").hidden=false;byId("order-sign-create").textContent=action==="recover"?"Sign ownership & recover access ↗":"Sign ownership & create order ↗";
      intake(action==="recover"?"Review the ownership message. Signing will rotate access to this existing order; your previous receipt will stop working.":"Review the ownership message. Sign it in Freighter to create the private order before funding.");
    }catch(error){intake(error.message);}finally{setWorking(false);}
  }
  byId("order-create").addEventListener("click",()=>prepareChallenge("create"));
  byId("order-recover").addEventListener("click",()=>prepareChallenge("recover"));
  function signatureBase64(value){
    if(typeof value==="string"){const decoded=atob(value);if(decoded.length!==64)throw new Error("The wallet returned an invalid ownership signature.");return btoa(decoded);}
    const bytes=Array.isArray(value)?value:ArrayBuffer.isView(value)?Array.from(value):value?.type==="Buffer"&&Array.isArray(value.data)?value.data:null;
    if(!bytes||bytes.length!==64||bytes.some((v)=>!Number.isInteger(v)||v<0||v>255))throw new Error("The wallet returned an unsupported ownership signature.");
    return btoa(String.fromCharCode(...bytes));
  }
  byId("order-sign-create").addEventListener("click",async()=>{
    if(working||!challenge||!byId("order-consent").checked)return;
    const captured=challenge;setWorking(true);
    try{
      if(captured.response.challenge.expires_at<=Date.now()/1000)throw new Error("The ownership message expired. Prepare a new private order challenge.");
      const api=window.freighterApi;if(!api)throw new Error("The Freighter library is unavailable. Reload this workspace before creating an order.");
      const installed=await api.isConnected();if(installed.error||!installed.isConnected)throw new Error("Connect Freighter on Stellar Testnet to prove ownership of the requester account.");
      const account=await api.getAddress();const network=await api.getNetworkDetails();
      if(account.error||account.address!==captured.submission.requester)throw new Error("The active Freighter account must match the requester in this quote.");
      if(network.error||network.networkPassphrase!=="Test SDF Network ; September 2015")throw new Error("Switch Freighter to Stellar Testnet before signing ownership.");
      if(challenge!==captured||context!==captured.context)throw new Error("The scope changed. Prepare a fresh ownership message.");
      const proof=await api.signMessage(captured.message,{address:account.address,networkPassphrase:"Test SDF Network ; September 2015"});
      if(proof.error||proof.signerAddress!==account.address)throw new Error(proof.error?.message||"The expected requester did not sign the ownership message.");
      if(challenge!==captured||context!==captured.context||!byId("order-consent").checked)throw new Error("The scope or consent changed. No order was created from this signature.");
      if(captured.response.challenge.expires_at<=Date.now()/1000)throw new Error("The ownership message expired during signing. Prepare a fresh challenge.");
      const body={...captured.submission,wallet_proof:{challenge:captured.response.challenge,challenge_signature:captured.response.challenge_signature,wallet_signature:signatureBase64(proof.signedMessage)}};
      const value=await request(captured.action==="recover"?"orders/recover":"orders",{method:"POST",body,cap:null,ai:captured.submission.engagement.ai_assistance===true||captured.submission.engagement.source?.ai_assistance===true});
      if(!HEX.test(value.order_id||"")||!HEX.test(value.order_token||"")||value.order_id!==captured.context.checkout.quote.request_id)throw new Error("The order response did not contain the expected private receipt. Do not fund this quote.");
      clearTimer();generation++;capability={order_id:value.order_id,order_token:value.order_token};
      challenge=null;byId("order-challenge").hidden=true;byId("official-order").hidden=false;byId("order-state").textContent="Order saved";status("Save your private receipt now. Loading the saved order state…");
      const summary=await request(`orders/${value.order_id}`);render(summary);
      intake(captured.action==="recover"?"Order access recovered. Save the new private receipt; the previous access token is invalid.":"Private order saved. Save the receipt before funding; its access token is returned only once.");
    }catch(error){intake(error.message);if(capability)status("If an order was saved, keep its private receipt before leaving this tab. Refresh status to check it.");}
    finally{setWorking(false);}
  });
  byId("order-resume").addEventListener("click",async()=>{if(working)return;setWorking(true);try{await openCapability(byId("order-resume-id").value.trim().toLowerCase(),byId("order-resume-token").value.trim().toLowerCase());}catch(error){intake(error.message);}finally{setWorking(false);}});
  byId("order-receipt-file").addEventListener("change",async(event)=>{if(working)return;setWorking(true);try{const file=event.target.files?.[0];if(!file||file.size>8192)throw new Error("Choose a private order receipt smaller than 8 KB.");const value=JSON.parse(await file.text());if(value.protocol!=="veritas.order-receipt/v1"||value.network!=="testnet")throw new Error("This is not a Veritas Testnet private receipt.");await openCapability(value.order_id,value.order_token);}catch(error){intake(error.message);}finally{event.target.value="";setWorking(false);}});
  byId("order-receipt").addEventListener("click",()=>{if(!capability)return;const receipt={protocol:"veritas.order-receipt/v1",network:"testnet",...capability};const url=URL.createObjectURL(new Blob([JSON.stringify(receipt,null,2)],{type:"application/json;charset=utf-8"}));const link=node("a");link.href=url;link.download=`veritas-private-order-${capability.order_id.slice(0,12)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);status("Private receipt downloaded. It grants access to this order; keep it secure and separate from public report files.");});
  byId("order-refresh").addEventListener("click",()=>refresh());byId("order-activate").addEventListener("click",activate);
  byId("order-retry").addEventListener("click",async()=>{if(working||!capability||order?.status!=="failed"||!order.retryable)return;setWorking(true);try{render(await request(`orders/${capability.order_id}/retry`,{method:"POST",body:{}}));}catch(error){status(error.message);}finally{setWorking(false);}});
  byId("order-open-report").addEventListener("click",async()=>{
    if(working||!capability||!order?.report_available)return;setWorking(true);const captured=order;const current=generation;
    try{
      const envelope=await request(`orders/${capability.order_id}/result`);if(current!==generation)return;
      if(!HEX.test(envelope.report_sha256||"")||envelope.report_sha256!==captured.report_sha256)throw new Error("The report does not match this order's recorded commitment.");
      const d=verifiedDelivery(captured)?captured.delivery:null;const credential=d?{contract_id:d.credential_contract_id,token_id:d.token_id,owner:d.owner}:null;
      await new Promise((resolve,reject)=>window.dispatchEvent(new CustomEvent("veritas:order-report",{detail:{envelope,credential,order_id:captured.order_id,resolve,reject}})));
      status(credential?"Report opened and its credential checked against the live ledger. Review the Credential tab for the returned status.":deliveredWithoutCredential(captured)?"Report opened. This audit did not pass, so no credential was issued.":"Report opened. An onchain credential is not yet verified for this order.");
    }catch(error){status(error.message);}finally{setWorking(false);}
  });

  byId("order-refund").addEventListener("click",async()=>{
    if(working||!capability||!order||["delivered","refunded"].includes(order.status))return;
    setWorking(true);const captured=order;
    try{
      const transaction=await request(`orders/${capability.order_id}/refund/prepare`,{method:"POST",body:{}});
      if(transaction.request_id!==captured.order_id||transaction.step!=="refund"||transaction.signer!==captured.requester)throw new Error("The refund transaction does not match this private order.");
      await new Promise((resolve,reject)=>{const handled=!window.dispatchEvent(new CustomEvent("veritas:refund-prepared",{cancelable:true,detail:{transaction,order:captured,resolve,reject}}));if(!handled)reject(new Error("The wallet transaction panel is unavailable."));});
      byId("checkout-panel").open=true;status("Refund eligibility passed and an unsigned transaction was prepared. Review, sign and submit it explicitly in the wallet panel. No refund is confirmed yet.");
    }catch(error){status(`${error.message} No refund is assumed or automatically submitted.`);}finally{setWorking(false);}
  });
  window.addEventListener("veritas:refund-pending",(event)=>{if(order?.order_id===event.detail.order_id){pendingRefund=order.order_id;byId("order-activate").hidden=false;byId("order-activate").textContent="Check refund receipt";}});
  window.addEventListener("veritas:refund-submitted",async(event)=>{
    if(!capability||capability.order_id!==event.detail.order_id||working)return;
    setWorking(true);try{render(await request(`orders/${capability.order_id}/refund/reconcile`,{method:"POST",body:{}}));}catch(error){status(`${error.message} Use Check refund receipt to read the escrow state again.`);}finally{setWorking(false);}
  });

  document.addEventListener("visibilitychange",()=>{if(document.hidden)clearTimer();else if(capability&&ACTIVE.has(order?.status))refresh(false);});
  fetch("/api/v1/studio/orders/capabilities").then((response)=>{if(!response.ok)throw new Error();return response.json();}).then((value)=>{capabilities=value;byId("order-availability").textContent=available()?"Official orders are available. A saved order is required before funding; verified funding starts its scoped review.":value.reason||"Automatic official orders are unavailable on this deployment. No automated delivery is claimed.";updateCreate();}).catch(()=>{byId("order-availability").textContent="Official order availability could not be checked. New order creation stays disabled.";updateCreate();});
})();
