/* Immediate review state stays in memory. Private order persistence and explicit wallet actions live in orders.js and checkout.js. */
"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  const form = byId("review-form");
  let files = {};
  let dependencies = [];
  let result = null;
  let submitted = null;
  let busy = false;
  let sourceReference = "";
  let sourceRevision = "";
  let runtimeResult = null;
  let catalogue = null;
  let auditPlan = null;
  let capsule = null;
  let activeTier = "quick";
  let selectedModules = new Set();
  let deliveryState = null;

  function requestError(value, status) {
    const detail = value.detail;
    if (Array.isArray(detail)) return detail.map((item) => `${item.loc?.slice(-1).join("") || "Input"}: ${item.msg}`).join("; ");
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object") return detail.message || detail.reason || (detail.blockers || []).join(" ") || `Request needs attention (HTTP ${status}).`;
    return `Request could not be completed (HTTP ${status}).`;
  }
  function sourceInput() {
    const tools = JSON.parse(byId("tool-manifest").value);
    if (!Array.isArray(tools)) throw new Error("Tool permissions must be a JSON array.");
    if (!Object.keys(files).length && !byId("agent-prompt").value.trim() && !byId("stellar-address").value.trim()) throw new Error("Add a public Stellar address, source files or system instructions first.");
    return {name:byId("agent-name").value, purpose:byId("agent-purpose").value, system_prompt:byId("agent-prompt").value, files:{...files}, tools, dependencies, stellar_address:byId("stellar-address").value.trim(), network:byId("stellar-network").value, source_reference:sourceReference, source_revision:sourceRevision, architecture:JSON.parse(byId("architecture-manifest").value), ai_assistance:byId("ai-consent").checked, external_processing_consent:byId("ai-consent").checked};
  }
  function applyCapsuleLock() {
    const locked = Boolean(capsule);
    const ids = ["agent-name","agent-purpose","agent-prompt","tool-manifest","architecture-manifest","stellar-address","stellar-network","source-files","source-folder","import-github","identify-address"];
    ids.forEach((id) => {byId(id).disabled = locked;});
    document.querySelectorAll("[data-scope], [data-example], #file-list button, #audit-tiers input, #audit-modules input").forEach((control) => {control.disabled = locked;});
    byId("edit-capsule-draft").hidden = !locked;
    byId("export-capsule").textContent = locked ? "Download this capsule ↗" : "Create & download capsule ↗";
  }
  function renderCapsuleState(message) {
    const panel = byId("capsule-state"); panel.replaceChildren(node("strong", message));
    if (!capsule) return;
    panel.append(node("p", "Committed inputs and audit selection are locked. Editing as a new draft resets custom policy and scenarios."));
    panel.append(node("p", `${Object.keys(capsule.source?.files || {}).length} source files · ${capsule.capabilities?.length || 0} capabilities · ${capsule.policy?.rules?.length || 0} policy rules · ${capsule.scenarios?.length || 0} declared scenarios`));
    if (capsule.subject?.forbidden_goals?.length) panel.append(node("p", `Forbidden goals: ${capsule.subject.forbidden_goals.join("; ")}`));
    if (capsule.commitments?.capsule_sha256) panel.append(node("code", `CAPSULE / ${capsule.commitments.capsule_sha256}`, "blueprint-fingerprint"));
  }
  function auditRequest(source) {
    if (!selectedModules.size) throw new Error("Choose at least one official reviewer.");
    return {...(capsule ? {capsule,ai_assistance:source.ai_assistance,external_processing_consent:source.external_processing_consent} : {source}), tier_id:activeTier, module_ids:[...selectedModules], entrypoint:byId("audit-entrypoint").value.trim(), execution_consent:byId("audit-execution-consent").checked};
  }
  function updateRunLabel() {
    const tier = catalogue?.tiers?.find((item) => item.id === activeTier);
    byId("run-review").textContent = `Run ${tier?.name || "Preview"} review`;
  }
  function describeBudget(tier) {
    const budget = tier.budgets || {};
    const cases = budget.runtime_cases ?? budget.max_runtime_cases ?? 0;
    return cases ? `Up to ${cases} runtime cases · isolated execution` : "Source review · no execution";
  }
  function tierPrice(tier) {
    const price = tier.price || {};
    if (price.live) return `${price.amount} ${price.asset || price.currency || "USD"}`;
    const target = price.amount ?? price.proposed_usd ?? price.usd;
    return target !== undefined ? `$${target} proposed · pilot` : "Pilot · no automatic payment";
  }
  function renderAuditOptions() {
    if (!catalogue) return;
    const tiers = byId("audit-tiers"); tiers.replaceChildren();
    catalogue.tiers.forEach((tier) => {
      const label = node("label", undefined, "tier-choice");
      const radio = node("input"); radio.type = "radio"; radio.name = "audit-tier"; radio.value = tier.id; radio.checked = activeTier === tier.id;
      radio.addEventListener("change", () => { activeTier = tier.id; invalidate(); updateRunLabel(); renderAuditOptions(); });
      const copy = node("span"); copy.append(node("strong", tier.name), node("small", describeBudget(tier)), node("em", tierPrice(tier)));
      label.append(radio, copy); tiers.append(label);
    });
    const modules = byId("audit-modules"); modules.replaceChildren();
    catalogue.modules.forEach((module) => {
      const label = node("label", undefined, "module-choice");
      const checkbox = node("input"); checkbox.type = "checkbox"; checkbox.checked = selectedModules.has(module.id); checkbox.value = module.id;
      checkbox.addEventListener("change", () => { checkbox.checked ? selectedModules.add(module.id) : selectedModules.delete(module.id); invalidate(); byId("module-count").textContent = `${selectedModules.size} selected`; });
      const copy = node("span"); copy.append(node("strong", module.name), node("small", module.description));
      if (module.methods?.length) copy.append(node("em", module.methods.map((item) => typeof item === "string" ? item.replaceAll("_", " ") : item.name).join(" · ")));
      label.append(checkbox, copy); modules.append(label);
    });
    byId("module-count").textContent = `${selectedModules.size} selected`;
    byId("execution-options").hidden = activeTier === "quick";
    updateRunLabel();
  }
  function renderPublicPlans() {
    const panel = byId("public-plans"); panel.replaceChildren();
    catalogue.tiers.forEach((tier) => {
      const card = node("article", undefined, `price-card${tier.id === "quick" ? " available-plan" : ""}`);
      card.append(node("span", tier.price?.live ? "AVAILABLE" : "PILOT PRICING · NOT CHARGED", "plan-status"), node("h3", tier.name));
      const amount = tier.price?.amount ?? tier.price?.proposed_usd ?? tier.price?.usd;
      card.append(node("p", amount !== undefined ? `$${amount}` : "Testnet pilot", "price"), node("p", tier.description || describeBudget(tier)), node("span", describeBudget(tier), "plan-footer"));
      const link = node("a", `Choose ${tier.name} ↗`); link.href = "#workspace";
      link.addEventListener("click", () => { if (busy || capsule) return; activeTier = tier.id; invalidate(); renderAuditOptions(); });
      card.append(link); panel.append(card);
    });
    byId("pricing-status").textContent = "Proposed prices are per audit, regardless of findings. Testnet escrow uses test XLM. Production checkout is not active; this workspace never charges automatically.";
  }
  function renderAuditPlan(value) {
    const plan = value.plan; const panel = byId("audit-plan"); panel.hidden = false; panel.replaceChildren();
    const title = typeof plan.tier === "object" ? plan.tier.name : catalogue?.tiers.find((item) => item.id === plan.tier)?.name || plan.tier;
    panel.append(node("span", "YOUR AUDIT PLAN", "eyebrow"), node("h3", `${title || "Official"} investigation`));
    const modules = plan.modules || [];
    panel.append(node("p", `${modules.length} official reviewers · ${plan.entrypoint?.id || plan.entrypoint || "Source inspection"}`));
    const budget = plan.budgets || {};
    const counts = node("div", undefined, "plan-facts");
    [["Case budget", budget.runtime_cases ?? budget.max_runtime_cases ?? 0], ["Source files", Object.keys(files).length], ["Test asset", plan.price?.testnet_amount ? `${plan.price.testnet_amount} XLM` : "No payment taken"]].forEach(([label,value]) => { const fact = node("div"); fact.append(node("strong",String(value)),node("span",label)); counts.append(fact); }); panel.append(counts);
    if (plan.execution_profile) {
      panel.append(node("p", `${plan.planned_runtime_cases} committed workflows · restart and external tool evidence`));
      panel.append(node("p", "Declared clients use a controlled broker. Model calls and disposable Testnet payments are bounded; native client transports are outside this execution scope.", "help"));
    }
    const blockers = plan.blockers || [];
    if (blockers.length) {
      const list = node("ul", undefined, "plan-blockers"); blockers.forEach((item) => list.append(node("li", typeof item === "string" ? item : item.message || item.reason))); panel.append(node("strong", "Before this plan can run"), list);
    } else panel.append(node("p", "Plan prepared. Execution starts only when you run the review.", "help"));
    panel.append(node("code", `PLAN / ${value.plan_sha256}`, "blueprint-fingerprint"));
    window.dispatchEvent(new CustomEvent("veritas:plan", {detail:{engagement:auditRequest(sourceInput()),planned:value}}));
  }
  byId("preview-audit-plan").addEventListener("click", async () => {
    if (busy) return;
    error(); setBusy(true);
    try { auditPlan = await post("plan", auditRequest(sourceInput())); renderAuditPlan(auditPlan); }
    catch (failure) {error(failure.message);}
    finally {setBusy(false);}
  });
  byId("export-capsule").addEventListener("click", async () => {
    if (busy) return;
    if (capsule) {download("agent.veritas", JSON.stringify(capsule,null,2)); return;}
    error(); setBusy(true);
    try {
      const value = await post("capsule/export", {source:sourceInput(),tier_id:activeTier,module_ids:[...selectedModules]});
      if (value.compiled?.source) loadBundle(value.compiled.source);
      capsule = value.capsule;
      download("agent.veritas", JSON.stringify(capsule, null, 2));
      renderCapsuleState("Capsule exported. Review its declarations before sharing.");
    } catch (failure) {error(failure.message);}
    finally {setBusy(false);}
  });
  byId("edit-capsule-draft").addEventListener("click", () => {
    if (busy) return;
    capsule = null; invalidate(); applyCapsuleLock();
    byId("capsule-state").textContent = "New editable draft. Imported custom policy and scenarios are no longer attached. Your original capsule download remains unchanged.";
  });
  function renderEngagement(report, {renderPlan = true} = {}) {
    const engagement = report.engagement;
    if (!engagement) return;
    const runtime = engagement.runtime;
    const moduleResults = engagement.module_results || [];
    byId("dossier-state").textContent = "Official review complete";
    byId("result-summary").textContent = runtime ? "Source findings and isolated execution evidence are bound to this review. Open questions remain visible in Coverage." : "Source findings are bound to your chosen plan. Coverage distinguishes inspected evidence from checks still required.";
    if (renderPlan && engagement.plan) renderAuditPlan({plan:engagement.plan,plan_sha256:engagement.plan_sha256});
    const results = Array.isArray(moduleResults) ? moduleResults : Object.entries(moduleResults).map(([id,value]) => ({id,...value}));
    if (results.length) {
      const block = node("section", undefined, "official-results"); block.append(node("h4", "Your official reviewers"));
      results.forEach((item) => {
        const row = node("div", undefined, "official-result");
        const name = item.name || catalogue?.modules.find((module) => module.id === (item.module_id || item.id))?.name || item.module_id || item.id;
        row.append(node("strong", name), node("span", item.runtime === "sampled" ? `${item.runtime_observation_ids?.length || 0} runtime samples` : "Source reviewed"));
        if (item.summary || item.note) row.append(node("p", item.summary || item.note));
        block.append(row);
      });
      byId("control-results").prepend(block);
    }
    if (runtime) {
      const evidence = runtime.report || runtime;
      const observations = evidence.observations || [];
      const attention = observations.filter((item) => item.status !== "observed");
      if (attention.length) {
        byId("result-summary").textContent = `${attention.length} of ${observations.length} runtime cases require attention. Open Runtime for failed checks, exceptions and incomplete evidence. Source findings are listed separately.`;
      }
      byId("runtime-results").replaceChildren();
      observations.forEach((item) => {
        const card = node("article", undefined, "runtime-observation");
        card.append(node("strong", `${item.id?.replaceAll("_", " ") || "Probe"} · ${item.status}`), node("p",item.response || item.dependency || item.error || "No usable response."));
        if (item.assertion) card.append(node("p",`Declared expectation: ${item.assertion.result?.replaceAll("_", " ") || "not evaluated"}. ${item.assertion.meaning || ""}`));
        if (item.blocked_reason) card.append(node("p", `Blocked: ${item.blocked_reason.replaceAll("_", " ")}`));
        (item.assertions || []).forEach((check) => card.append(node("p", `${check.kind || check.operator}: ${check.result?.replaceAll("_", " ")} · ${check.evidence || "agent output assertion"}${check.actual !== undefined ? " · observed " + JSON.stringify(check.actual).slice(0,160) : ""}`)));
        (item.step_outcomes || []).forEach((step) => {if (step.error) card.append(node("p", `Step ${step.step + 1}: ${step.error}`));});
        byId("runtime-results").append(card);
      });
      if (evidence.broker_evidence) {
        const block = node("article", undefined, "runtime-observation");
        block.append(node("strong", "External tool evidence"), node("p", "These events were recorded outside the agent sandbox. Agent outputs remain untrusted."));
        (evidence.broker_evidence.events || []).forEach((event) => {
          const row = node("p", `${event.workflow} · ${event.method} · ${event.mode || "broker"} · ${event.status}`);
          if (/^[a-f0-9]{64}$/.test(event.receipt?.hash || "")) {
            const link = node("a", " View confirmed Testnet transaction ↗");
            link.href = `https://stellar.expert/explorer/testnet/tx/${event.receipt.hash}`;
            link.target = "_blank"; link.rel = "noopener noreferrer"; row.append(link);
          }
          block.append(row);
        });
        byId("runtime-results").append(block);
      }
      byId("runtime-status").textContent = observations.length ? `${observations.length} runtime observations recorded in your audit dossier.` : evidence.note || evidence.reason || `Runtime status: ${evidence.status || "no observations"}.`;
      if (runtime.report_json) {runtimeResult = runtime; byId("download-runtime").hidden = false;}
      byId("missing-evidence").firstElementChild?.remove();
      byId("missing-evidence").prepend(node("li", "Production behavior, external services and controls outside the executed plan remain unverified."));
    }
  }
  function renderCredential(value) {
    byId("credential-card").dataset.issued = "false";
    byId("credential-name").textContent = value.report.agent.name;
    byId("credential-short-hash").textContent = `SHA-256 / ${value.report_sha256.slice(0,12)}`;
    byId("credential-status").textContent = "Local evidence record · not issued onchain";
    byId("delivery-note").textContent = "Download a designed report and evidence card. A matching live credential must be verified before this record is presented as issued.";
  }
  async function prepareDelivery(credential) {
    if (!result) throw new Error("Run a review first.");
    const original = result;
    const value = await post("delivery", {report_json:original.report_json,report_sha256:original.report_sha256,...(credential ? {credential} : {})});
    if (result !== original) throw new Error("The source changed while delivery was being prepared. Run a new review.");
    if (value.report_sha256 !== original.report_sha256) throw new Error("Delivery evidence does not match this report.");
    deliveryState = value;
    const verified = value.status === "current";
    byId("credential-card").dataset.issued = String(verified);
    byId("credential-status").textContent = verified ? "Current credential · ledger verified" : "Local evidence record · not issued onchain";
    byId("delivery-note").textContent = verified ? "The ledger record matches this report. Check scope and expiry before relying on the assessment." : "Your designed evidence package is ready. Downloading it does not issue an onchain credential.";
    const panel = byId("delivery-results"); panel.replaceChildren(node("strong", verified ? "Onchain record verified" : "Evidence package prepared"));
    if (value.proof?.note || value.proof?.reason) panel.append(node("p", value.proof.note || value.proof.reason));
    if (value.artifacts?.metadata) {
      const button = node("button", "Download credential metadata", "text-button"); button.type = "button";
      button.addEventListener("click", () => download("agent-credential-metadata.json", JSON.stringify(value.artifacts.metadata,null,2))); panel.append(button);
    }
    return value;
  }
  async function deliveryAction(button, artifact, filename, type) {
    if (!result || busy) return;
    const previous = button.textContent; button.disabled = true; button.textContent = "Preparing…";
    try {
      const value = deliveryState || await prepareDelivery();
      if (!value.artifacts?.[artifact]) throw new Error("This report artifact is not available yet.");
      download(filename,value.artifacts[artifact],type);
    } catch (failure) {byId("download-note").textContent = failure.message;}
    finally {button.disabled = false;button.textContent = previous;}
  }
  byId("download-designed-report").addEventListener("click", (event) => deliveryAction(event.currentTarget,"html","agent-veritas-report.html","text/html;charset=utf-8"));
  byId("download-evidence-card").addEventListener("click", (event) => deliveryAction(event.currentTarget,"svg","agent-veritas-evidence.svg","image/svg+xml;charset=utf-8"));
  byId("prepare-delivery").addEventListener("click", async (event) => {
    if (!result || busy) return;
    const button = event.currentTarget; button.disabled = true;
    try {await prepareDelivery();}
    catch (failure) {byId("delivery-results").textContent = failure.message;}
    finally {button.disabled = false;}
  });
  byId("verify-credential").addEventListener("click", async (event) => {
    if (!result || busy) return;
    const button = event.currentTarget;
    const credential = {contract_id:byId("credential-contract").value.trim(), token_id:byId("credential-token").value.trim().toLowerCase(), owner:byId("credential-owner").value.trim()};
    if (!/^C[A-Z2-7]{55}$/.test(credential.contract_id) || !/^[a-f0-9]{64}$/.test(credential.token_id) || !/^[GC][A-Z2-7]{55}$/.test(credential.owner)) {byId("delivery-results").textContent = "Enter the public contract, 64-character token ID and public owner address.";return;}
    button.disabled = true;
    try {await prepareDelivery(credential);}
    catch (failure) {byId("delivery-results").textContent = failure.message;}
    finally {button.disabled = false;}
  });

  function renderPilotProof(value) {
    const evidence = value.evidence;
    if (!value.available || !evidence || evidence.status !== "verified") {
      byId("pilot-proof-state").textContent = "Receipt pending verification";
      byId("pilot-proof-summary").textContent = "The complete pilot receipt is not yet available. A completed lifecycle is displayed here only after its recorded checks pass.";
      return;
    }
    const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
    const passed = new Set(checks.filter((check) => check.ok === true).map((check) => check.label));
    const required = ["settlement.provider_exact_payout","settlement.treasury_exact_fee","delivery.same_content_hash","delivery.escrow_complete","delivery.credential_owner","delivery.credential_current"];
    if (!required.every((label) => passed.has(label)) || checks.some((check) => check.ok === false)) {
      byId("pilot-proof-state").textContent = "Receipt requires review";
      byId("pilot-proof-summary").textContent = "The published receipt does not contain all required lifecycle checks. No completed pilot claim is displayed.";
      return;
    }
    const transactions = (evidence.transactions || []).filter((tx) => tx.status === "SUCCESS" && /^[a-f0-9]{64}$/.test(tx.hash));
    const rejected = (evidence.negative_simulations || []).filter((item) => item.rejected === true && item.transaction_submitted === false);
    const panel = byId("pilot-proof-content"); panel.hidden = false; panel.replaceChildren();
    byId("pilot-proof-state").textContent = "Lifecycle verified · Testnet";
    byId("pilot-proof-summary").textContent = "A real source review funded through escrow. The report hash matched across registry, settlement and credential. Distinct signing roles, operated by Veritas Official.";
    const atomic = (text) => {
      if (!/^\d{1,20}$/.test(String(text))) return null;
      const value = BigInt(text); const whole = value / 10000000n;
      const remainder = (value % 10000000n).toString().padStart(7,"0").replace(/0+$/, "");
      return `${whole}${remainder ? "." + remainder : ""}`;
    };
    const amount = atomic(evidence.settlement?.amount_atomic);
    const payout = atomic(evidence.settlement?.provider_payout_atomic);
    const fee = atomic(evidence.settlement?.fee_atomic);
    const metrics = node("div",undefined,"proof-metrics");
    [[amount ? `${amount} test XLM` : "Funded", "Escrow settled"], [String(transactions.length), "Successful ledger transactions"], [String(rejected.length), "Rejected simulations"]].forEach(([metric,label]) => {const item = node("div");item.append(node("strong",metric),node("span",label));metrics.append(item);}); panel.append(metrics);
    const flow = node("ol",undefined,"proof-lifecycle");
    [["Report committed","One content fingerprint across all three contracts."],["Payment settled",payout && fee ? `${payout} test XLM to the provider · ${fee} test XLM platform fee.` : "Provider and platform payouts checked against ledger balances."],["Credential issued","Owner and report read back from the official credential contract."]].forEach(([title,detail]) => {const item = node("li");item.append(node("strong",title),node("span",detail));flow.append(item);});panel.append(flow);
    const details = node("details",undefined,"proof-evidence"); details.append(node("summary","Inspect transactions and boundaries"));
    const links = node("div",undefined,"proof-links");
    const labels = {"delivery.fund":"Escrow funding","delivery.respond":"Report commitment","delivery.complete":"Payment settlement","delivery.issue_credential":"Credential issuance"};
    transactions.filter((tx) => labels[tx.label]).forEach((tx) => {const link=node("a",`${labels[tx.label]} ↗`);link.href=`https://stellar.expert/explorer/testnet/tx/${tx.hash}`;link.target="_blank";link.rel="noopener noreferrer";links.append(link);});
    Object.entries(evidence.contracts || {}).forEach(([name,contract]) => {if (!/^C[A-Z2-7]{55}$/.test(contract.id || "")) return;const link=node("a",`${name.charAt(0).toUpperCase()+name.slice(1)} contract ↗`);link.href=`https://stellar.expert/explorer/testnet/contract/${contract.id}`;link.target="_blank";link.rel="noopener noreferrer";links.append(link);});
    const reportURL = value.report_url || evidence.report?.uri || "";
    if (/^https:\/\/raw\.githubusercontent\.com\/furkan3152\/agentveritas-stellar\/[a-f0-9]{40}\/deployments\/reports\/[a-f0-9]{64}\.json$/.test(reportURL)) {const link=node("a","Read the committed report ↗");link.href=reportURL;link.target="_blank";link.rel="noopener noreferrer";links.append(link);}
    details.append(links);
    if (evidence.report?.sha256) details.append(node("code",`REPORT / ${evidence.report.sha256}`,"blueprint-fingerprint"));
    if (rejected.length) details.append(node("p",`Rejected before transaction submission: ${rejected.map((item) => item.label.replaceAll("_"," ")).join("; ")}. These are RPC simulations, separate from successful ledger transactions.`));
    details.append(node("p","This report covers bounded static source review of the published fixture. The pilot does not establish live AI behavior, complete security or independent operator consensus."));
    const recorded = evidence.verified_at || evidence.completed_at || evidence.created_at;
    if (recorded && !Number.isNaN(Date.parse(recorded))) details.append(node("p",`Receipt recorded ${new Date(recorded).toISOString().slice(0,10)}. Credential status is a recorded readback; current expiry and revocation require a fresh ledger check.`));
    panel.append(details);
  }
  fetch("/api/v1/studio/delivery/pilot").then((response) => {if (!response.ok) throw new Error();return response.json();}).then(renderPilotProof).catch(() => {
    byId("pilot-proof-state").textContent = "Receipt unavailable";
    byId("pilot-proof-summary").textContent = "The published lifecycle receipt could not be loaded. Retry later to inspect the Testnet evidence.";
  });

  fetch("/api/v1/studio/catalog").then((response) => {if (!response.ok) throw new Error(); return response.json();}).then((value) => {
    if (!Array.isArray(value.tiers) || !Array.isArray(value.modules)) throw new Error();
    catalogue = value;
    selectedModules = capsule ? new Set(capsule.audit.modules) : new Set(value.modules.filter((module) => module.default_selected !== false).map((module) => module.id));
    if (capsule) activeTier = capsule.audit.tier;
    renderAuditOptions(); renderPublicPlans(); if (!busy) applyCapsuleLock();
    byId("catalog-status").textContent = "Official catalogue loaded. Reviewers share one accountable platform operator.";
  }).catch(() => {
    byId("catalog-status").textContent = "Reviewer catalogue unavailable. Refresh before starting an audit.";
    byId("audit-tiers").replaceChildren(node("p","Plans could not be loaded.","help"));
  });

  function sourceMode(mode) {
    const panels = { address: "source-address", github: "source-github", files: "source-upload" };
    document.querySelectorAll("[data-source-mode]").forEach((button) => {
      const active = button.dataset.sourceMode === mode;
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    Object.entries(panels).forEach(([key,id]) => { byId(id).hidden = key !== mode; });
  }
  document.querySelectorAll("[data-source-mode]").forEach((button, index, buttons) => {
    button.addEventListener("click", () => sourceMode(button.dataset.sourceMode));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      sourceMode(buttons[next].dataset.sourceMode); buttons[next].focus();
    });
  });

  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const error = (message = "") => {
    byId("form-error").textContent = message;
    byId("form-error").hidden = !message;
  };
  function invalidate() {
    result = null;
    submitted = null;
    runtimeResult = null;
    auditPlan = null;
    window.dispatchEvent(new CustomEvent("veritas:invalidate"));
    deliveryState = null;
    byId("audit-plan").hidden = true;
    byId("delivery-results").replaceChildren();
    byId("runtime-results").replaceChildren();
    byId("download-runtime").hidden = true;
    byId("discovery-results").hidden = true;
    byId("review-result").hidden = true;
    byId("empty-report").hidden = false;
    byId("dossier-state").textContent = "Awaiting review";
    byId("run-status").textContent = "Review your plan before starting. No automatic transaction or payment.";
    byId("download-note").textContent = "Your report stays in this tab until you leave or run another review.";
  }
  function setBusy(value) {
    busy = value;
    document.querySelectorAll("#review-form input, #review-form textarea, #review-form select, #review-form button, [data-example]").forEach((element) => { element.disabled = value; });
    byId("ai-consent").disabled = value || byId("ai-consent").dataset.available !== "true";
    form.setAttribute("aria-busy", String(value));
    if (!value) applyCapsuleLock();
  }
  function renderFiles() {
    const list = byId("file-list");
    list.replaceChildren();
    Object.entries(files).forEach(([name, content]) => {
      const row = node("div", undefined, "file-row");
      row.append(node("span", `${name} · ${new TextEncoder().encode(content).length.toLocaleString("en-US")} bytes`));
      const remove = node("button", "Remove");
      remove.type = "button";
      remove.setAttribute("aria-label", `Remove ${name}`);
      remove.addEventListener("click", () => { delete files[name]; sourceRevision = ""; invalidate(); renderFiles(); });
      row.append(remove);
      list.append(row);
    });
    if (!Object.keys(files).length) list.append(node("p", "No source files added."));
  }
  function updateToolCount() {
    try {
      const tools = JSON.parse(byId("tool-manifest").value);
      byId("tool-count").textContent = Array.isArray(tools) ? `${tools.length} declared` : "Use a JSON array";
      if (Array.isArray(tools)) {
        const scopes = new Set(tools.flatMap((tool) => tool.scopes || []));
        document.querySelectorAll("[data-scope]").forEach((input) => { input.checked = scopes.has(input.dataset.scope); });
      }
    } catch { byId("tool-count").textContent = "Invalid JSON"; }
  }
  function loadBundle(bundle) {
    capsule = null; byId("audit-entrypoint").value = "";
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("An audit bundle must be a JSON object.");
    const allowed = new Set(["name", "purpose", "system_prompt", "files", "tools", "dependencies", "stellar_address", "network", "source_reference", "source_revision", "architecture", "ai_assistance", "external_processing_consent"]);
    if (Object.keys(bundle).some((key) => !allowed.has(key))) throw new Error("Unknown bundle fields. Use an exported agent-audit.json as the template.");
    if (bundle.files && (Array.isArray(bundle.files) || typeof bundle.files !== "object" || Object.values(bundle.files).some((value) => typeof value !== "string"))) throw new Error("Bundle files must map filenames to source text.");
    if (bundle.tools && !Array.isArray(bundle.tools)) throw new Error("Bundle tools must be an array.");
    byId("agent-name").value = bundle.name || "";
    byId("agent-purpose").value = bundle.purpose || "";
    byId("agent-prompt").value = bundle.system_prompt || "";
    files = { ...(bundle.files || {}) };
    dependencies = bundle.dependencies || [];
    byId("architecture-manifest").value = JSON.stringify(bundle.architecture || {}, null, 2);
    byId("ai-consent").checked = false; byId("ai-access-settings").hidden = true; byId("ai-access-key").value = "";
    byId("stellar-address").value = bundle.stellar_address || "";
    byId("stellar-network").value = bundle.network || "testnet";
    sourceReference = bundle.source_reference || "";
    sourceRevision = bundle.source_revision || "";
    byId("address-status").textContent = "Address not checked for this bundle. A source review does not prove ownership.";
    byId("address-status").removeAttribute("data-state");
    byId("tool-manifest").value = JSON.stringify(bundle.tools || [], null, 2);
    byId("source-files").value = "";
    renderFiles(); updateToolCount(); invalidate();
  }
  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (busy) return;
      error(); setBusy(true);
      try {
        const response = await fetch("/ui/studio-fixtures.json");
        if (!response.ok) throw new Error("Example unavailable. Add your own source files instead.");
        loadBundle((await response.json())[button.dataset.example]);
        sourceMode("files");
        document.querySelectorAll("[data-example]").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
      } catch (failure) { error(failure.message); }
      finally { setBusy(false); }
    });
  });
  byId("source-files").addEventListener("change", async (event) => {
    if (busy) return;
    error(); setBusy(true);
    try {
      const selected = [...event.target.files];
      if (selected.some((file) => file.size > 131072)) throw new Error("File too large. Source files must be at most 32 KB; an audit bundle at most 128 KiB.");
      if (selected.length === 1 && selected[0].name.endsWith(".veritas")) {
        const value = await post("capsule/import", {document: await selected[0].text()});
        loadBundle(value.source); capsule = value.capsule;
        if (capsule.audit?.tier) activeTier = capsule.audit.tier;
        if (capsule.audit?.modules) selectedModules = new Set(capsule.audit.modules);
        renderAuditOptions();
        renderCapsuleState("Capsule imported and validated.");
      } else if (selected.length === 1 && selected[0].name === "agent-audit.json") {
        loadBundle(JSON.parse(await selected[0].text()));
      } else {
        const pending = { ...files };
        for (const file of selected) {
          if (Object.keys(pending).some((name) => name.toLowerCase() === file.name.toLowerCase())) throw new Error(`${file.name} already exists. Remove it before adding a replacement.`);
          if (file.size > 32000) throw new Error(`${file.name} exceeds 32 KB.`);
          pending[file.name] = await file.text();
        }
        if (Object.keys(pending).length > 12 || Object.values(pending).reduce((sum, content) => sum + new TextEncoder().encode(content).length, 0) > 64000) throw new Error("A review accepts at most 12 files and 64 KB of source.");
        files = pending; sourceReference = ""; sourceRevision = ""; invalidate(); renderFiles();
      }
      document.querySelectorAll("[data-example]").forEach((item) => item.setAttribute("aria-pressed", "false"));
    } catch (failure) { error(failure.message); }
    finally { event.target.value = ""; setBusy(false); }
  });
  form.addEventListener("input", (event) => {
    if (busy || ["ai-access-key","audit-runtime-key"].includes(event.target.id)) return;
    invalidate(); error();
    if (!event.target.closest(".audit-builder") && event.target.id !== "ai-consent") {
      capsule = null;
      byId("capsule-state").textContent = "Source edited. Export a fresh capsule to bind the updated project.";
    }
    if (!event.target.matches("[data-scope]")) updateToolCount();
    if (["stellar-address", "stellar-network"].includes(event.target.id)) {
      byId("address-status").textContent = "Click Check address to look up this address on the selected network.";
      byId("address-status").removeAttribute("data-state");
    }
  });
  document.querySelectorAll("[data-scope]").forEach((input) => input.addEventListener("change", () => {
    let tools;
    try { tools = JSON.parse(byId("tool-manifest").value); if (!Array.isArray(tools)) throw new Error(); }
    catch { error("Fix the advanced tool JSON before changing capabilities."); return; }
    const scope = input.dataset.scope;
    if (input.checked && !tools.some((tool) => (tool.scopes || []).includes(scope))) {
      tools.push({ name: {"read:chain":"read_stellar","read:web":"browse_web","sign:tx":"stellar_signer","exec:host":"run_code"}[scope], scopes: [scope], requires_signature: scope === "sign:tx", network_access: ["read:chain","read:web"].includes(scope) });
    } else if (!input.checked) {
      tools = tools.map((tool) => ({ ...tool, scopes: (tool.scopes || []).filter((item) => item !== scope), ...(scope === "sign:tx" ? {requires_signature: false} : {}) })).filter((tool) => tool.scopes.length);
    }
    byId("tool-manifest").value = JSON.stringify(tools, null, 2); updateToolCount(); invalidate();
  }));

  async function post(path, body) {
    const response = await fetch(`/api/v1/studio/${path}`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body),signal:AbortSignal.timeout(35000)});
    const data = await response.json();
    if (!response.ok) throw new Error(requestError(data, response.status));
    return data;
  }
  byId("identify-address").addEventListener("click", async () => {
    if (busy) return;
    const address = byId("stellar-address").value.trim();
    if (!/^[GC][A-Z2-7]{55}$/.test(address)) { error("Enter a public G-account or C-contract address. Never enter a secret key."); return; }
    error(); setBusy(true); byId("address-status").textContent = "Looking up the public ledger…";
    try {
      const value = await post("identify", {address, network: byId("stellar-network").value});
      byId("address-status").dataset.state = value.ledger_presence;
      byId("address-status").textContent = value.ledger_presence === "found" ? `Stellar ${value.kind} found. Ownership and agent behavior are not verified. Add source for a code audit.` : value.ledger_presence === "not_found" ? "Not found in active ledger state on this network. Check the network; a contract may also be archived." : "Ledger lookup unavailable. Retry later; no verification is claimed.";
      if (!byId("agent-name").value) byId("agent-name").value = `Stellar agent ${address.slice(-6)}`;
      if (!byId("agent-purpose").value) byId("agent-purpose").value = "Review the evidence available for this Stellar agent.";
    } catch (failure) { error(failure.message); byId("address-status").textContent = "Address could not be checked. No verification is claimed."; }
    finally { setBusy(false); }
  });
  byId("import-github").addEventListener("click", async () => {
    if (busy) return;
    error(); setBusy(true); byId("import-status").textContent = "Discovering the repository at a fixed commit…";
    try {
      const value = await post("import", {repository:byId("github-repository").value.trim()});
      loadBundle({...value.bundle, source_reference:value.source});
      renderDiscovery(value.discovery);
      byId("import-status").textContent = `Imported ${Object.keys(files).length} files at ${value.revision.slice(0,8)}. ${value.import_scope.eligible_files_omitted} eligible files outside scope or limits. Selection: ${value.import_scope.selection || "provisional discovery"}.`;
    } catch (failure) { error(failure.message); byId("import-status").textContent = "Nothing imported. You can upload files instead."; }
    finally { setBusy(false); }
  });
  byId("download-template").addEventListener("click", async () => {
    try {
      const response = await fetch("/ui/studio-fixtures.json");
      if (!response.ok) throw new Error("Template unavailable. Try again.");
      const fixtures = await response.json(); download("agent-audit.json", JSON.stringify(fixtures.reader, null, 2));
    } catch (failure) { error(failure.message); }
  });


  function renderDiscovery(plan) {
    if (!plan) return;
    const panel = byId("discovery-results"); panel.hidden = false; panel.replaceChildren();
    if (plan.agent_identity) panel.append(node("p", "Agent identity: unverified. A callable, framework import or project declaration does not prove that this is the deployed agent.", "blueprint-blocker"));
    panel.append(node("strong", plan.frameworks.length ? plan.frameworks.join(" · ") : "Custom or unidentified framework"));
    panel.append(node("p", `${plan.files_inspected} files inspected. ${plan.entrypoints.length} possible entry points. ${plan.test_suites.length} test suites.`));
    if (plan.required_environment_names.length) panel.append(node("p", `Environment names found: ${plan.required_environment_names.join(", ")}. Values are never requested here.`));
    const list = node("ul");
    plan.entrypoints.forEach((entry) => list.append(node("li", `${entry.id} — ${entry.reason}`)));
    if (!plan.entrypoints.length) list.append(node("li", "No supported callable detected. Include the real entry module or a thin adapter to it."));
    panel.append(list);
    const blueprint = plan.blueprint;
    if (blueprint) {
      const map = node("section", undefined, "blueprint-map");
      map.append(node("span", "VERITAS BLUEPRINT / 01", "eyebrow"), node("h3", blueprint.status === "mapped" ? "Your project, mapped." : blueprint.status === "blocked" ? "Resolve the project map." : "Give your agent a project map."), node("p", blueprint.note || "The declaration could not be verified. Execution is blocked."));
      blueprint.blockers.forEach((message) => map.append(node("p", message, "blueprint-blocker")));
      if (blueprint.components.length) {
        const table = node("table", undefined, "blueprint-table");
        const head = node("thead"); const header = node("tr");
        ["Component", "Source path", "Evidence"].forEach((label) => header.append(node("th", label))); head.append(header); table.append(head);
        const body = node("tbody");
        blueprint.components.forEach((component) => {
          const row = node("tr"); const path = node("td"); path.append(node("code", component.path));
          row.append(node("td", `${component.id} · ${component.role}`), path, node("td", component.status)); body.append(row);
        }); table.append(body); map.append(table);
        const details = node("details"); details.append(node("summary", `${blueprint.checks.length} planned checks · ${(blueprint.boundaries || []).length} declared boundaries`));
        const checks = node("ul"); blueprint.checks.forEach((check) => checks.append(node("li", `${check.component}: ${check.id.replaceAll("_", " ")} · ${check.method.replaceAll("_", " ")} · ${check.status}`))); details.append(checks);
        (blueprint.boundaries || []).forEach((boundary) => details.append(node("p", `${boundary.source} → ${boundary.target}: ${boundary.permission}; approval ${boundary.approval_required ? "declared required" : "not declared required"}. Enforcement unverified.`)));
        (blueprint.source_edges || []).forEach((edge) => details.append(node("p", `${edge.from}:${edge.line} → ${edge.to} · ${edge.resolution.replaceAll("_", " ")}`)));
        map.append(details);
        const undeclared = Object.entries(blueprint.role_coverage || {}).filter(([,status]) => status === "not_declared").map(([role]) => role);
        if (undeclared.length) map.append(node("p", `Not declared: ${undeclared.join(", ")}. These surfaces are outside the mapped scope, not verified absent.`));
        (blueprint.analysis_limits || []).forEach((limit) => map.append(node("p", limit)));
      }
      if (blueprint.plan_sha256) map.append(node("p", `Plan fingerprint: ${blueprint.plan_sha256}`, "blueprint-fingerprint"));
      if (plan.blueprint_draft?.manifest) {
        const button = node("button", "Download veritas.json draft", "text-button"); button.type = "button";
        button.addEventListener("click", () => download("veritas.json", JSON.stringify({...plan.blueprint_draft.manifest, name: byId("agent-name").value || "My agent", purpose: byId("agent-purpose").value || plan.blueprint_draft.manifest.purpose}, null, 2)));
        map.append(button, node("p", "Review roles, purpose and boundaries. Place this file at your project root, then upload the folder again."));
      } else if (plan.blueprint_draft) map.append(node("p", "Choose your real entry point in veritas.json. Automatic discovery cannot resolve an ambiguous or unsupported project."));
      panel.append(map);
    }
    const select = byId("runtime-entrypoint"); select.replaceChildren();
    plan.entrypoints.filter((entry) => entry.adapter === "python_text").forEach((entry) => {
      const option = node("option", entry.id); option.value = entry.id; select.append(option);
    });
    if (select.options.length && !byId("audit-entrypoint").value) byId("audit-entrypoint").value = select.options[0].value;
    byId("runtime-status").textContent = select.options.length ? "Confirm that this callable reaches the real agent. Runtime access is required." : "This project needs an adapter or an operator-reviewed framework image before execution.";
  }
  byId("discover-project").addEventListener("click", async () => {
    if (busy) return;
    error(); setBusy(true);
    try {
      const plan = await post("discover", {name: byId("agent-name").value || "Uploaded project", purpose: byId("agent-purpose").value || "Inspect the actual project behavior and security boundaries.", files});
      renderDiscovery(plan);
    } catch (failure) { error(failure.message); } finally { setBusy(false); }
  });
  byId("source-folder").addEventListener("change", async (event) => {
    if (busy) return;
    error(); setBusy(true);
    try {
      const all = [...event.target.files];
      const eligible = all.map((file) => ({file,path:file.webkitRelativePath.split("/").slice(1).join("/")}))
        .filter(({file,path}) => file.size <= 32000 && path.length <= 160 && !path.split("/").some((part) => part.startsWith(".") || ["node_modules","vendor","target","dist","build","venv","__pycache__"].includes(part)) && /\.(py|js|ts|tsx|jsx|mjs|cjs|rs|go|json|md|txt|toml|ya?ml)$/.test(path) && !/(^|\/)(credentials|secrets?|id_rsa|service.account)([._-]|$)/i.test(path));
      const declaration = all.find((file) => file.webkitRelativePath.split("/").slice(1).join("/") === "veritas.json");
      if (declaration && !eligible.some((item) => item.path === "veritas.json")) throw new Error("veritas.json exceeds the upload limit. Automatic fallback is disabled.");
      let declaredPaths = null;
      if (declaration) {
        try {
          const manifest = JSON.parse(await declaration.text()); declaredPaths = new Set(["veritas.json", ...(manifest.components || []).map((component) => component.path)]);
          if (!byId("agent-name").value && typeof manifest.name === "string") byId("agent-name").value = manifest.name;
          if (!byId("agent-purpose").value && typeof manifest.purpose === "string") byId("agent-purpose").value = manifest.purpose;
        }
        catch { declaredPaths = new Set(["veritas.json"]); }
      }
      const rank = (path) => path === "veritas.json" ? -1 : /(^|\/)(package.json|pyproject.toml|requirements.txt)$/.test(path) ? 0 : /\.(py|js|ts)$/.test(path) ? 1 : 2;
      eligible.sort((a,b) => rank(a.path)-rank(b.path) || a.path.split("/").length-b.path.split("/").length || a.path.localeCompare(b.path));
      const next = {}; let bytes = 0;
      for (const {file,path} of eligible) {
        if (declaredPaths && !declaredPaths.has(path)) continue;
        if (Object.keys(next).length >= 12 || bytes + file.size > 64000) continue;
        next[path] = await file.text(); bytes += file.size;
      }
      files = next; sourceReference = ""; sourceRevision = ""; invalidate(); renderFiles();
      byId("folder-status").textContent = `${Object.keys(files).length} source files selected; ${all.length - Object.keys(files).length} files excluded or over the review limit. Review the list before auditing.`;
      if (!byId("agent-name").value) byId("agent-name").value = all[0]?.webkitRelativePath.split("/")[0] || "Uploaded project";
    } catch (failure) { error(failure.message); } finally { setBusy(false); event.target.value = ""; }
  });
  byId("run-runtime").addEventListener("click", async () => {
    if (busy || !submitted) return;
    const key = byId("runtime-access").value.trim();
    if (!byId("runtime-consent").checked || !key || !byId("runtime-entrypoint").value) { byId("runtime-status").textContent = "Select a supported entry point, provide the pilot key and authorize execution."; return; }
    setBusy(true); byId("run-runtime").disabled = true; byId("runtime-status").textContent = "Creating an isolated microVM and executing the bounded probe plan…";
    try {
      const runtimeHeaders = {"Content-Type":"application/json",Authorization:`Bearer ${key}`};
      if (submitted.ai_assistance && byId("ai-access-key").value.trim()) runtimeHeaders["X-AI-Review-Key"] = byId("ai-access-key").value.trim();
      const response = await fetch("/api/v1/studio/runtime", {method:"POST", headers:runtimeHeaders, body:JSON.stringify({source:submitted,entrypoint:byId("runtime-entrypoint").value,execution_consent:true,plan_sha256:result?.report?.discovery?.blueprint?.plan_sha256 || null}),signal:AbortSignal.timeout(60000)});
      const value = await response.json(); if (!response.ok) throw new Error(typeof value.detail === "string" ? value.detail : "Runtime request could not be validated.");
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value.report_json)))].map((b)=>b.toString(16).padStart(2,"0")).join("");
      if (hash !== value.report_sha256) throw new Error("Runtime report integrity mismatch.");
      runtimeResult = value; const report = JSON.parse(value.report_json);
      const panel = byId("runtime-results"); panel.replaceChildren();
      report.observations.forEach((item) => {
        const card = node("article",undefined,"runtime-observation");
        card.append(node("strong",`${item.id.replaceAll("_"," ")} · ${item.status}`),node("p", item.response || item.dependency || item.error || "No usable response."));
        if (item.assertion) card.append(node("p", `Developer text assertion: ${item.assertion.result.replaceAll("_", " ")}. ${item.assertion.meaning}`));
        panel.append(card);
      });
      byId("runtime-status").textContent = "Execution finished. These observations do not certify controls or production safety.";
      byId("download-runtime").hidden = false;
    } catch (failure) {byId("runtime-status").textContent = failure.message;}
    finally {setBusy(false); byId("run-runtime").disabled = false; byId("runtime-access").value = "";}
  });
  byId("download-runtime").addEventListener("click", () => {if(runtimeResult) download("agent-runtime-evidence.json", runtimeResult.report_json);});

  const findingTitles = {
    "security-path-untrusted-to-command": "Untrusted input reaches code execution",
    "security-path-untrusted-to-financial-sink": "Untrusted input reaches a Stellar transaction",
    "security-path-secret-to-exfiltration": "A secret reaches logging or a network call",
    "security-systemic-code-execution-wallet": "Code execution and signing share an agent",
    "security-path-controls-not-enforced": "Signing controls need implementation evidence",
    "security-a-01": "Prompt disclosure defenses need verification",
    "security-a-02": "Untrusted tool output needs an isolation boundary",
    "security-a-03": "Role-change defenses need verification",
    "security-a-04": "Secret-handling defenses need verification",
    "security-a-05": "Authority escalation defenses need verification",
    "security-a-06": "Resource-exhaustion defenses need verification",
    "security-a-07": "Recipient and spending limits need verification",
    "security-a-08": "Tool chaining controls need verification",
    "security-a-09": "Owner impersonation defenses need verification",
    "security-a-10": "Long-context behavior needs verification",
  };
  const names = { intent: "Intent", security: "Security", economic: "Spending", compliance: "Compliance signals", reliability: "Reliability", stellar_native: "Stellar integration", provenance: "Provenance" };
  function renderReport(value) {
    byId("empty-report").hidden = true;
    byId("review-result").hidden = false;
    byId("dossier-state").textContent = "Source review complete";
    const decisions = {
      pass: "Passed: no open high or critical risk in the reviewed scope",
      needs_fixes: "Fixes required before granting authority",
      needs_evidence: "More evidence required",
    };
    byId("result-decision").textContent = decisions[value.decision] || decisions.needs_evidence;
    byId("result-name").textContent = value.report.agent.name;
    byId("result-summary").textContent = "Source inspected. Runtime behavior, owner identity and onchain publication have not been verified.";
    renderDiscovery(value.report.discovery);
    const subject = value.report.subject || {};
    byId("result-subject").textContent = `${subject.network === "mainnet" ? "Stellar Mainnet" : "Stellar Testnet"}${subject.stellar_address ? " · " + subject.stellar_address : " · No wallet linked"}`;
    const findings = [...value.report.findings].sort((a,b) => ["critical","high","medium","low","info"].indexOf(a.severity) - ["critical","high","medium","low","info"].indexOf(b.severity));
    byId("finding-count").textContent = String(findings.length);
    const priorityIds = new Set(value.report.priority_finding_ids);
    byId("priority-count").textContent = String(priorityIds.size);
    byId("dimension-count").textContent = `${value.report.auditors.length} / 7`;
    const container = byId("findings");
    container.replaceChildren();
    const observations = node("details", undefined, "technical");
    const secondary = findings.filter((finding) => !priorityIds.has(finding.id));
    observations.append(node("summary", `Other observations (${secondary.length})`));
    findings.forEach((finding, index) => {
      const details = node("details", undefined, "finding");
      details.open = false;
      const summary = node("summary");
      const fallback = finding.id.replace(/^[^-]+-/, "").replaceAll("-", " ");
      summary.append(node("span", finding.title || findingTitles[finding.id] || fallback.charAt(0).toUpperCase() + fallback.slice(1)), node("span", finding.severity, "severity"));
      details.append(summary, node("p", finding.detail));
      details.append(node("p", finding.kind === "evidence_gap" ? "Evidence gap — missing supporting evidence, not a vulnerability; it does not lower the risk score." : finding.kind === "warning" ? "Warning — the agent acts without a human approval step. Small score penalty; it does not block a pass." : finding.evidence_grade === "confirmed" ? "Direct source or configuration evidence — not a runtime exploit." : "Heuristic signal — requires validation.", "evidence-kind"));
      if (finding.evidence) details.append(node("pre", finding.evidence));
      if (finding.remediation) details.append(node("p", `Next check: ${finding.remediation}`));
      if (secondary.includes(finding)) observations.append(details);
      else container.append(details);
    });
    if (secondary.length) container.append(observations);
    if (!priorityIds.size) container.prepend(node("p", "No directly evidenced high-priority source findings. Review the remaining observations; this is not a safety clearance.", "help"));
    const assurance = value.report.assurance;
    byId("control-results").replaceChildren();
    if (assurance) {
      byId("coverage-summary").textContent = `${assurance.surfaces_located} / ${assurance.total} surfaces located. ${assurance.runtime_verified} runtime-verified controls. Presence is not proof of enforcement.`;
      assurance.controls.forEach((control) => {
        const item = node("details", undefined, "control-row");
        const title = node("summary", control.name);
        title.append(node("span", control.status === "not_provided" ? "Evidence missing" : "Needs validation"));
        item.append(title, node("p", control.evidence_needed));
        if (control.source_references.length) item.append(node("code", control.source_references.map((r) => `${r.file}:${r.line}`).join(" · ")));
        byId("control-results").append(item);
      });
    }
    const ai = value.report.ai_review || {status:"not_requested",observations:[]};
    byId("ai-results").replaceChildren(node("p", ai.note || "AI review was not requested. The static evidence above is independent of a language model.", "help"));
    ai.observations.forEach((observation) => {
      const card = node("article", undefined, "finding");
      card.append(node("h4", observation.title), node("p", observation.risk), node("code", `${observation.file}:${observation.line}`), node("p", observation.remediation), node("p", "AI hypothesis · requires validation", "evidence-kind"));
      byId("ai-results").append(card);
    });
    const gaps = byId("missing-evidence");
    gaps.replaceChildren();
    ["Runtime behavior under adversarial inputs and tool failures", "Owner identity bound to this exact agent version", "A successful Soroban transaction and matching registry readback"].forEach((text) => gaps.append(node("li", text)));
    const surfaces = value.report.result.coverage.surface_coverage?.surfaces || {};
    if (!surfaces.implementation && !surfaces.behavioral_contract) byId("result-summary").textContent = "Address-only review. Source code, instructions and runtime behavior were not inspected. Add source files to continue.";
    const missing = { behavioral_contract: "System instructions were not supplied", tool_permissions: "Tool permissions were not declared", implementation: "Executable source was not supplied", supply_chain: "Dependency versions were not supplied" };
    Object.entries(missing).forEach(([key,text]) => { if (!surfaces[key]) gaps.append(node("li", text)); });
    byId("dimensions").replaceChildren();
    value.report.auditors.forEach((auditor) => {
      const row = node("div", undefined, "dimension-row");
      row.append(node("span", names[auditor.dimension] || auditor.dimension), node("span", `${auditor.coverage.findings} findings · static`));
      byId("dimensions").append(row);
    });
    byId("report-hash").textContent = value.report_sha256;
    byId("scope-limits").replaceChildren(...value.scope.limits.map((text) => node("li", text)));
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    error(); invalidate();
    let input;
    try {
      input = sourceInput();
    } catch (failure) { error(failure.message); return; }
    setBusy(true);
    byId("run-review").textContent = "Building evidence…";
    byId("run-status").textContent = activeTier === "quick" ? "Official reviewers are inspecting the submitted evidence…" : "Preparing your plan, then running the authorized investigation…";
    try {
      if (!catalogue) throw new Error("The reviewer catalogue is unavailable. Refresh to check the current audit options.");
      const body = auditRequest(input);
      auditPlan = await post("plan", body);
      renderAuditPlan(auditPlan);
      if (auditPlan.plan.blockers?.length) throw new Error(auditPlan.plan.blockers.map((item) => typeof item === "string" ? item : item.message || item.reason).join(" "));
      const headers = {"Content-Type":"application/json"};
      const runtimeKey = byId("audit-runtime-key").value.trim();
      if (activeTier !== "quick" && runtimeKey) headers.Authorization = `Bearer ${runtimeKey}`;
      if (input.ai_assistance && byId("ai-access-key").value.trim()) headers["X-AI-Review-Key"] = byId("ai-access-key").value.trim();
      const response = await fetch("/api/v1/studio/audit", { method: "POST", headers, body: JSON.stringify({...body, plan_sha256:auditPlan.plan_sha256}), signal: AbortSignal.timeout(activeTier === "quick" ? 45000 : 120000) });
      const value = await response.json();
      if (!response.ok) throw new Error(requestError(value, response.status));
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.report_json));
      const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2,"0")).join("");
      if (hash !== value.report_sha256) throw new Error("Report integrity check failed. Run a new review.");
      // Render the committed bytes, not a potentially divergent response view.
      value.report = JSON.parse(value.report_json);
      result = value; submitted = input;
      byId("download-bundle").hidden = false; byId("run-runtime").disabled = false;
      renderReport(value); renderEngagement(value.report); renderCredential(value);
      byId("run-status").textContent = "Review complete. Download your evidence before leaving.";
      if (window.innerWidth <= 720) byId("dossier-title").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    } catch (failure) {
      error(failure.name === "TimeoutError" ? "The review timed out. Retry with a smaller source bundle." : failure.message);
      byId("run-status").textContent = "No completed review. Your inputs are still available to retry.";
    } finally { setBusy(false); updateRunLabel(); byId("audit-runtime-key").value = ""; byId("ai-access-key").value = ""; }
  });
  function download(filename, text, type = "application/json;charset=utf-8") {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = node("a"); link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  document.querySelectorAll("[data-result-view]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-result-view]").forEach((b) => {
        const selected = b === button;
        b.setAttribute("aria-pressed", String(selected));
        byId(`view-${b.dataset.resultView}`).hidden = !selected;
      });
    });
  });
  byId("ai-consent").addEventListener("change", () => {byId("ai-access-settings").hidden = !byId("ai-consent").checked; if (!byId("ai-consent").checked) byId("ai-access-key").value = "";});
  fetch("/api/v1/studio/capabilities").then((r) => { if (!r.ok) throw new Error(); return r.json(); }).then((value) => {
    byId("ai-consent").disabled = !value.ai_available;
    byId("ai-consent").dataset.available = String(value.ai_available);
    byId("ai-availability").textContent = value.ai_available ? `I consent to send redacted source to ${value.ai_provider}. Never include secrets; automatic redaction is best effort.` : "Not enabled on this deployment. Static review is available.";
    value.controls.forEach((control) => {
      const item = node("article"); item.append(node("strong", control.name), node("p", control.evidence_needed));
      byId("control-catalogue").append(item);
    });
  }).catch(() => { byId("ai-availability").textContent = "AI availability could not be checked. Static review remains available."; });
  byId("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const output = byId("verify-result");
    try {
      const file = byId("verify-file").files[0];
      if (!file || file.size > 2000000) throw new Error("Choose a report smaller than 2 MB.");
      const bytes = await file.arrayBuffer();
      const report = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(bytes));
      if (!report.schema || !report.input_hash) throw new Error("The file is not an AgentVeritas audit report.");
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((v) => v.toString(16).padStart(2,"0")).join("");
      output.textContent = hash === byId("verify-hash").value.toLowerCase() ? "Integrity match. Exact bytes match your fingerprint. Issuer, chain status, expiry and revocation are not checked here." : "Mismatch. This file does not match the expected fingerprint. Do not rely on this copy.";
    } catch (failure) { output.textContent = failure.message || "Verification failed."; }
  });
  byId("policy-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const now = Math.floor(Date.now()/1000);
    const policy = {agent_id:"demo-treasury",version:"a".repeat(64),network:"testnet",asset:"XLM",allowed_tools:["payment"],allowed_destinations:["approved-treasury"],max_per_action:100000000,max_total:500000000,max_depth:1,expires_at:now+3600,require_approval:false};
    const action = {nonce:crypto.randomUUID(),agent_id:policy.agent_id,version:policy.version,network:"testnet",tool:"payment",asset:"XLM",destination:"approved-treasury",amount:50000000,depth:0,expires_at:now+60};
    const scenario = byId("policy-scenario").value;
    if (scenario === "overspend") action.amount = 110000000;
    if (scenario === "destination") action.destination = "unrecognized-recipient";
    if (scenario === "version") action.version = "b".repeat(64);
    if (scenario === "depth") action.depth = 3;
    const button = event.target.querySelector("button"); button.disabled = true;
    try {
      const response = await fetch("/api/v1/studio/policy", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({policy,action,paused:scenario === "paused",spent:0}),signal:AbortSignal.timeout(10000)});
      const value = await response.json(); if (!response.ok) throw new Error(typeof value.detail === "string" ? value.detail : "Policy check unavailable.");
      byId("policy-decision").textContent = value.allowed ? "Within the policy." : "Action blocked.";
      const reasons = {emergency_stop:"The emergency stop is active.",version_mismatch:"Source version differs from the approved version.",destination_denied:"The recipient is outside the allowlist.",per_action_limit:"The amount exceeds the 10 XLM action limit.",delegation_depth:"The delegation chain exceeds one level."};
      byId("policy-reasons").textContent = value.allowed ? "All simulated conditions satisfied. No real approval, reservation or transaction was created." : value.reasons.map((r) => reasons[r] || r.replaceAll("_", " ")).join(" ");
    } catch (failure) { byId("policy-decision").textContent = "Check unavailable."; byId("policy-reasons").textContent = failure.message; }
    finally { button.disabled = false; }
  });

  window.addEventListener("veritas:order-report", async (event) => {
    const {envelope,credential,order_id} = event.detail;
    try {
      if (busy) throw new Error("Wait for the current review to finish before opening the order report.");
      if (!envelope || typeof envelope.report_json !== "string" || !/^[a-f0-9]{64}$/.test(envelope.report_sha256 || "")) throw new Error("The order report is incomplete.");
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(envelope.report_json)))].map((byte) => byte.toString(16).padStart(2,"0")).join("");
      if (hash !== envelope.report_sha256) throw new Error("Order report integrity did not match its commitment.");
      if (busy) throw new Error("A new review started while this report was loading. Open the order report after it finishes.");
      const committed = JSON.parse(envelope.report_json);
      const value = {...envelope, report:committed, scope:committed.review_scope, decision:committed.review_decision || envelope.decision};
      result = value; submitted = null; runtimeResult = null; deliveryState = null;
      renderReport(value); renderEngagement(committed,{renderPlan:false}); renderCredential(value);
      byId("download-bundle").hidden = true; byId("run-runtime").disabled = true;
      byId("download-note").textContent = `Private order ${order_id.slice(0,12)} · report commitment checked. The current intake fields were not changed.`;
      if (credential) {
        byId("credential-contract").value = credential.contract_id;
        byId("credential-token").value = credential.token_id;
        byId("credential-owner").value = credential.owner;
        await prepareDelivery(credential);
      }
      event.detail.resolve?.();
    } catch (failure) {event.detail.reject?.(failure);}
  });

  byId("download-report").addEventListener("click", () => { if (result) { download("agent-review.json", result.report_json); byId("download-note").textContent = "Report exported. Verify its SHA-256 against the fingerprint below."; } });
  byId("download-bundle").addEventListener("click", () => { if (submitted) download("agent-audit.json", JSON.stringify(submitted, null, 2)); });
})();
