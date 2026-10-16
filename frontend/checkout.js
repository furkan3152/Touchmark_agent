/* Testnet-only wallet flow. No private keys, automatic signing or automatic submission. */
"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  const TESTNET = "Test SDF Network ; September 2015";
  const RPC = "https://soroban-testnet.stellar.org";
  const node = (tag,text,className) => {const value=document.createElement(tag);if(text !== undefined)value.textContent=text;if(className)value.className=className;return value;};
  let engagement = null, planned = null, checkout = null, prepared = null, signed = null;
  let working = false, revision = 0;
  const message = (text) => {byId("checkout-status").textContent=text;};
  function clearTransaction() {prepared=null;signed=null;byId("checkout-transaction").hidden=true;byId("checkout-xdr").value="";byId("checkout-submit").hidden=true;}
  function resetQuote() {revision++;window.dispatchEvent(new CustomEvent("veritas:checkout-reset"));checkout=null;clearTransaction();byId("checkout-quote-result").hidden=true;byId("checkout-refresh").hidden=true;}
  function lock(value) {working=value;document.querySelectorAll("#checkout-panel button,#checkout-panel input").forEach((input)=>{input.disabled=value;});}
  function failure(value,status) {return typeof value.detail === "string" ? value.detail : Array.isArray(value.detail) ? value.detail.map((item)=>item.msg).join("; ") : value.detail?.message || `Checkout request failed (HTTP ${status}).`;}
  async function request(path,body,extraHeaders={}) {
    const key=byId("checkout-key").value.trim();if(!key)throw new Error("Enter the checkout pilot access key. Never enter a wallet secret key.");
    const response=await fetch(`/api/v1/studio/${path}`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${key}`,...extraHeaders},body:JSON.stringify(body),signal:AbortSignal.timeout(45000)});
    const value=await response.json();if(!response.ok)throw new Error(failure(value,response.status));return value;
  }
  function amount(value) {
    if(!/^\d{1,30}$/.test(String(value)))return "Unknown amount";
    const v=BigInt(value),fraction=(v%10000000n).toString().padStart(7,"0").replace(/0+$/,"");return `${v/10000000n}${fraction?"."+fraction:""} test XLM`;
  }
  function walletError(value,fallback) {return value.error?.message || (typeof value.error === "string" ? value.error : fallback);}
  async function walletState(requestAccess=false) {
    const api=window.freighterApi;if(!api)throw new Error("The wallet library is unavailable. Download the prepared XDR to use a compatible wallet.");
    const installed=await api.isConnected();if(installed.error||!installed.isConnected)throw new Error("Install the Freighter browser extension, then connect. You can also use the unsigned XDR with another wallet.");
    const access=await (requestAccess?api.requestAccess():api.getAddress());if(access.error||!/^G[A-Z2-7]{55}$/.test(access.address||""))throw new Error(walletError(access,"Connect your Freighter account first."));
    const network=await api.getNetworkDetails();if(network.error||network.networkPassphrase!==TESTNET)throw new Error("Switch Freighter to Stellar Testnet before continuing. Mainnet signing is disabled.");
    return {api,address:access.address};
  }
  function assertCurrent(token) {if(token!==revision)throw new Error("The audit inputs changed. Request a fresh quote before continuing.");}
  function renderQuote(value) {
    const quote=value.quote;
    if(!quote||quote.network!=="testnet"||quote.network_passphrase!==TESTNET||quote.requester!==byId("checkout-requester").value.trim()||quote.plan_sha256!==planned?.plan_sha256||(planned?.plan?.source_sha256&&quote.source_sha256!==planned.plan.source_sha256)||!Number.isFinite(quote.expires_at)||quote.expires_at<=Date.now()/1000||!/^[a-f0-9]{64}$/.test(value.quote_signature||""))throw new Error("The quote does not match this Testnet requester.");
    checkout=value;clearTransaction();
    const panel=byId("checkout-quote-result");panel.hidden=false;panel.replaceChildren();
    panel.append(node("span","TESTNET QUOTE","eyebrow"),node("h4",amount(quote.amount_atomic)));
    panel.append(node("p",`Fixed audit amount · ${quote.fee_bps/100}% included platform fee · network transaction fees are additional.`,"help"));
    const steps=node("ol",undefined,"checkout-steps");
    (value.steps||[]).forEach((step)=>{const item=node("li");item.dataset.state=step.state;item.append(node("strong",step.label),node("span",step.state.replaceAll("_"," ")));steps.append(item);});panel.append(steps);
    if(value.status==="ready"&&value.next_step){const button=node("button","Prepare next wallet transaction ↗","secondary");button.type="button";button.addEventListener("click",prepareNext);panel.append(button);}
    const details=node("details",undefined,"checkout-technical");details.append(node("summary","Quote identity and expiry"),node("code",`AGENT / ${quote.agent_id}`),node("code",`REQUEST / ${quote.request_id}`),node("code",`SOURCE / ${quote.source_sha256}`));
    if(Number.isFinite(quote.expires_at))details.append(node("p",`Quote expires ${new Date(quote.expires_at*1000).toISOString()}. Request a fresh quote after expiry.`,"help"));panel.append(details);
    byId("checkout-refresh").hidden=false;
    window.dispatchEvent(new CustomEvent("veritas:checkout-ready",{detail:{engagement:{...engagement,plan_sha256:planned.plan_sha256},planned,checkout:value}}));
    if(value.payment_confirmed===true)window.dispatchEvent(new CustomEvent("veritas:order-funded",{detail:{quote}}));
    if(value.status==="refunded"){message("This Testnet escrow job was refunded. No further funding is requested for this job.");return;}
    if(value.status==="deadline_expired"){message("This escrow deadline has passed. No payment transaction will be prepared for this job.");return;}
    if(value.status==="settled"){message("This Testnet escrow is settled according to contract state. Review the official report and credential separately.");return;}
    message(value.payment_confirmed===true?"Testnet funding confirmed from contract state. Your matching private order can now enter the official review queue. Follow its verified status in the dossier.":value.chain?.wallet_funded===false?"The requester needs a funded Testnet account before preparing transactions. No payment is confirmed.":"Quote ready. Review and sign each transaction separately. No payment is confirmed yet.");
  }
  async function refreshQuote() {
    if(!engagement||!planned)throw new Error("Preview your audit plan above first.");
    const requester=byId("checkout-requester").value.trim();if(!/^G[A-Z2-7]{55}$/.test(requester))throw new Error("Enter a public G-account on Stellar Testnet. Never enter a secret key.");
    if(engagement.source?.network&&engagement.source.network!=="testnet")throw new Error("Select Stellar Testnet in the audit intake before requesting this pilot quote.");
    const token=revision;
    const value=await request("checkout",{engagement:{...engagement,plan_sha256:planned.plan_sha256},requester});assertCurrent(token);renderQuote(value);
  }
  async function prepareNext() {
    if(working||!checkout?.next_step)return;lock(true);const token=revision;
    try {
      clearTransaction();message("Reading the ledger and simulating the next transaction…");
      const step=checkout.next_step;
      const capability=step==="fund"?await new Promise((resolve,reject)=>{const handled=!window.dispatchEvent(new CustomEvent("veritas:order-required",{cancelable:true,detail:{quote:checkout.quote,resolve,reject}}));if(!handled)reject(new Error("Create a private official order before funding. Order automation is unavailable in this workspace."));}):null;
      assertCurrent(token);
      const value=await request("checkout/prepare",{quote:checkout.quote,quote_signature:checkout.quote_signature,step},capability?{"X-Order-ID":capability.order_id,"X-Order-Token":capability.order_token}:{});assertCurrent(token);
      if(!value.unsigned_xdr){if(value.quote)renderQuote(value);else message("No transaction was prepared. Refresh ledger state to find the next step.");return;}
      if(value.network_passphrase!==TESTNET||value.signer!==checkout.quote.requester||value.simulation?.status!=="succeeded"||value.step!==step||!Number.isFinite(value.expires_at)||value.expires_at<=Date.now()/1000||!/^[a-f0-9]{64}$/.test(value.transaction_hash||""))throw new Error("Prepared transaction failed the Testnet scope checks.");
      prepared=value;byId("checkout-transaction").hidden=false;byId("checkout-xdr").value=value.unsigned_xdr;
      byId("checkout-transaction-detail").textContent=`${step.replaceAll("_"," ")} · ${amount(value.fee_atomic)} maximum transaction fee · simulation passed. Review the full operation in your wallet.`;
      message("Transaction prepared and simulated. Choose a download or review it in Freighter. Nothing has been signed or submitted.");
    }catch(error){message(error.message);}finally{lock(false);}
  }
  window.addEventListener("veritas:plan",(event)=>{resetQuote();engagement=event.detail.engagement;planned=event.detail.planned;message("Audit plan ready. Connect a Testnet account or enter its public address, then request a quote.");});
  window.addEventListener("veritas:invalidate",()=>{resetQuote();engagement=null;planned=null;message("Audit inputs changed. Preview a new audit plan before requesting a quote.");});
  byId("checkout-requester").addEventListener("input",()=>{resetQuote();message("Requester changed. Get a fresh quote for this public account.");});
  byId("checkout-connect").addEventListener("click",async()=>{if(working)return;lock(true);const token=revision;try{const wallet=await walletState(true);assertCurrent(token);resetQuote();byId("checkout-requester").value=wallet.address;message("Freighter connected on Testnet. Your wallet has not signed a transaction.");}catch(error){message(error.message);}finally{lock(false);}});
  for(const id of ["checkout-quote","checkout-refresh"])byId(id).addEventListener("click",async()=>{if(working)return;lock(true);try{message("Checking the quoted scope and current ledger state…");await refreshQuote();}catch(error){message(error.message);}finally{lock(false);}});
  byId("checkout-download").addEventListener("click",()=>{if(!prepared)return;const url=URL.createObjectURL(new Blob([prepared.unsigned_xdr],{type:"text/plain;charset=utf-8"}));const link=node("a");link.href=url;link.download=`veritas-testnet-${prepared.step}.xdr`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  byId("checkout-sign").addEventListener("click",async()=>{
    if(working||!prepared||!checkout)return;lock(true);const token=revision;const transaction=prepared;
    try {
      if(transaction.expires_at<=Date.now()/1000)throw new Error("The prepared transaction expired. Refresh the quote and prepare a new transaction.");
      const wallet=await walletState();assertCurrent(token);if(wallet.address!==checkout.quote.requester)throw new Error("The active wallet differs from the quoted requester. Switch accounts or request a new quote.");
      const value=await wallet.api.signTransaction(transaction.unsigned_xdr,{networkPassphrase:TESTNET,address:wallet.address});assertCurrent(token);
      if(value.error||!value.signedTxXdr||value.signerAddress!==wallet.address)throw new Error(walletError(value,"The expected account did not sign this transaction."));
      signed=value.signedTxXdr;byId("checkout-submit").hidden=false;message("Signed in your wallet. Click Submit to send this transaction to Stellar Testnet. Funding is still unconfirmed.");
    }catch(error){signed=null;byId("checkout-submit").hidden=true;message(error.message);}finally{lock(false);}
  });

  window.addEventListener("veritas:refund-prepared",(event)=>{
    event.preventDefault();
    try{
      if(working)throw new Error("Finish the current wallet action before preparing a refund.");
      const {transaction,order}=event.detail;
      if(transaction.step!=="refund"||transaction.request_id!==order.order_id||transaction.signer!==order.requester||transaction.network_passphrase!==TESTNET||transaction.simulation?.status!=="succeeded"||!Number.isFinite(transaction.expires_at)||transaction.expires_at<=Date.now()/1000||!/^[a-f0-9]{64}$/.test(transaction.transaction_hash||"")||typeof transaction.unsigned_xdr!=="string")throw new Error("The prepared refund failed the Testnet identity checks.");
      resetQuote();engagement=null;planned=null;
      checkout={quote:{requester:order.requester,request_id:order.order_id,plan_sha256:order.plan_sha256,source_sha256:order.source_sha256,network:"testnet",network_passphrase:TESTNET}};
      prepared=transaction;byId("checkout-requester").value=order.requester;byId("checkout-transaction").hidden=false;byId("checkout-xdr").value=transaction.unsigned_xdr;
      byId("checkout-transaction-detail").textContent=`Refund for order ${order.order_id.slice(0,12)} · ${amount(transaction.fee_atomic)} maximum transaction fee · simulation passed. The wallet must approve this request.`;
      message("Refund transaction prepared for the saved order. Review and sign it, then use the separate Submit button. No funds have been returned yet.");
      event.detail.resolve();
    }catch(error){event.detail.reject(error);}
  });

  async function rpc(method,params){const response=await fetch(RPC,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:crypto.randomUUID(),method,params}),signal:AbortSignal.timeout(20000)});const value=await response.json();if(!response.ok||value.error||!value.result)throw new Error("Testnet RPC did not confirm this request. Refresh ledger state before trying another transaction.");return value.result;}
  byId("checkout-submit").addEventListener("click",async()=>{
    if(working||!prepared||!signed||!checkout)return;lock(true);const token=revision;const transaction=prepared;const signedXdr=signed;
    try {
      if(transaction.expires_at<=Date.now()/1000)throw new Error("The signed transaction expired. Refresh ledger state before preparing a replacement.");
      const wallet=await walletState();assertCurrent(token);if(wallet.address!==checkout.quote.requester)throw new Error("Wallet account changed. Refresh the quote before submitting.");
      byId("checkout-submit").hidden=true;signed=null;
      if(transaction.step==="refund")window.dispatchEvent(new CustomEvent("veritas:refund-pending",{detail:{order_id:transaction.request_id}}));
      const sent=await rpc("sendTransaction",{transaction:signedXdr});assertCurrent(token);
      if(sent.hash!==transaction.transaction_hash)throw new Error("The returned transaction hash differs from the prepared transaction. Inspect ledger state before continuing.");
      if(!["PENDING","DUPLICATE"].includes(sent.status))throw new Error(`Transaction submission returned ${sent.status}. Refresh ledger state; payment is not confirmed.`);
      message("Transaction submitted. Waiting for ledger confirmation…");
      let confirmed=false;
      for(let attempt=0;attempt<8;attempt++){
        await new Promise(resolve=>setTimeout(resolve,1500));assertCurrent(token);
        const state=await rpc("getTransaction",{hash:sent.hash});assertCurrent(token);
        if(state.status==="FAILED")throw new Error("The transaction failed on Stellar Testnet. Refresh ledger state before preparing another transaction.");
        if(state.status==="SUCCESS"){confirmed=true;break;}
      }
      if(confirmed){if(transaction.step==="refund"){window.dispatchEvent(new CustomEvent("veritas:refund-submitted",{detail:{order_id:transaction.request_id}}));message("The refund transaction succeeded on Testnet. Checking the saved order's refund state…");}else await refreshQuote();}else message("Transaction is still pending. Refresh ledger state to confirm the step; do not assume funding is complete.");
    }catch(error){message(error.message);}finally{clearTransaction();lock(false);}
  });
})();
