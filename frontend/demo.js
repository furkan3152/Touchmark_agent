"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const form = $("audit-form"), input = $("reference"), run = $("run");
  let current = null;

  const HEADLINES = {
    pass: "No actionable risk found. Eligible for a Stellar credential.",
    needs_fixes: "Do not give this agent the keys yet.",
    needs_evidence: "No actionable risk, but part of the agent could not be reviewed.",
  };

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v; else if (k === "text") node.textContent = v; else node.setAttribute(k, v);
    }
    for (const child of children) if (child) node.append(child);
    return node;
  }

  function step(name, state) {
    const item = document.querySelector(`[data-step="${name}"]`);
    if (item) { item.classList.remove("active", "done", "skip"); if (state) item.classList.add(state); }
  }

  function resetSteps() { for (const s of ["resolve", "analyse", "decide", "credential"]) step(s, ""); }

  function showError(message) { $("error").textContent = message; $("error").hidden = false; }

  async function post(path, body) {
    const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${response.status})`);
    return data;
  }

  function finding(f) {
    return el("li", { class: f.severity },
      el("span", { class: "sev", text: f.severity }), el("span", { class: "title", text: f.title }),
      f.evidence ? el("code", { text: f.evidence }) : null,
      f.remediation ? el("p", { class: "fix", text: "Fix: " + f.remediation }) : null);
  }

  function render(data) {
    current = data;
    $("result").hidden = false;
    $("score").textContent = Number(data.score).toFixed(1);
    $("ring").style.strokeDashoffset = String(327 - 327 * Math.max(0, Math.min(100, data.score)) / 100);
    $("ring").style.stroke = data.decision === "pass" ? "var(--green)" : data.decision === "needs_fixes" ? "var(--red)" : "var(--amber)";
    const decision = $("decision");
    decision.className = "decision " + data.decision;
    decision.textContent = data.decision.replace("_", " ");
    $("headline").textContent = HEADLINES[data.decision] || data.decision;

    const source = $("source"); source.textContent = "";
    const src = data.source || {};
    if (src.repository) {
      const commit = (src.revision || "").slice(0, 10);
      const href = `${src.repository}/tree/${src.revision}${src.path ? "/" + src.path : ""}`;
      source.append("Source pinned to ", el("a", { href, target: "_blank", rel: "noopener", text: `${src.repository.replace("https://github.com/", "")}${src.path ? "/" + src.path : ""} @ ${commit}` }));
    } else {
      source.textContent = "No source bound: " + (data.steps || []).map((s) => `${s.check}: ${s.result}`).join(" · ");
    }
    const c = data.counts || {};
    $("counts").textContent = `${data.files || 0} ${data.files === 1 ? "file" : "files"} analysed · ${c.risks || 0} risks (${c.critical || 0} critical, ${c.high || 0} high) · ${c.gaps || 0} evidence gaps`;

    const risks = $("risks"); risks.textContent = "";
    if (!data.risks.length) risks.append(el("li", { class: "low" }, el("span", { class: "title", text: "No exploitable path from untrusted input to keys, payments, commands or network was found." })));
    data.risks.forEach((f) => risks.append(finding(f)));
    const gaps = $("gaps"); gaps.textContent = "";
    data.gaps.forEach((f) => gaps.append(finding(f)));
    $("gap-count").textContent = `(${(data.counts || {}).gaps || 0})`;

    const b = data.breakdown || {};
    const rows = $("why").querySelector("tbody"); rows.textContent = "";
    (b.deductions || []).forEach((d) => rows.append(el("tr", {},
      el("td", {}, el("span", { text: d.title || d.id }), d.restates ? el("div", { class: "restated", text: "same root cause as above: counted at 30%" }) : null),
      el("td", { class: "sev-" + d.severity, text: d.severity }),
      el("td", { text: String(d.places || 1) }),
      el("td", { text: "−" + Number(d.deduction).toFixed(1) }))));
    if (!(b.deductions || []).length) rows.append(el("tr", {}, el("td", { text: "No risk found" }), el("td"), el("td"), el("td", { text: "0" })));
    $("why-sum").textContent = `(${Number(b.total_deduction || 0).toFixed(1)} risk points → ${b.raw_score ?? data.score}${b.score !== b.raw_score ? " → " + b.score : ""})`;
    $("why-formula").textContent = "Each finding costs severity (critical 30, high 14, medium 6, low 2) × evidence (confirmed 1, inferred 0.6) × confidence × spread (more affected places, up to ×1.75). Score = 100 × e^(−risk points / 100)" + (b.band ? "; " + b.band + "." : ".");
    $("why-box").open = data.decision !== "pass";

    $("report-hash").textContent = data.report_sha256;
    $("cred-done").hidden = true;
    const issuance = data.issuance || {};
    const issue = $("issue");
    issue.hidden = !issuance.ticket;
    issue.disabled = false;
    const ownerNote = issuance.owner
      ? ` The repository names ${issuance.owner.slice(0, 6)}…${issuance.owner.slice(-4)} as owner: sign the registration with that account in Freighter and the credential is issued to it.`
      : (data.ownership && data.ownership.error)
        ? ` The ownership file was found but ${data.ownership.error}; the credential would go to the demo operator.`
        : " No owner is named, so it is issued to the demo operator (ownership not verified). Add agentveritas.json with {\"stellar_owner\": \"G…\"} to your repository to receive it yourself.";
    $("cred-note").textContent = issuance.ticket
      ? "This report passed. The validator writes its hash and score to the AgentVeritas registry, and the credential contract issues a non-transferable token bound to it." + ownerNote
      : issuance.reason || (issuance.enabled ? "" : "Credential issuance is not configured on this deployment.");
    $("issue").textContent = issuance.owner ? "Sign with Freighter and issue to my account" : "Issue credential on Stellar testnet";
    step("credential", issuance.ticket ? "" : "skip");
  }

  async function audit(reference) {
    $("error").hidden = true;
    $("result").hidden = true;
    $("steps").hidden = false;
    resetSteps();
    run.disabled = true;
    step("resolve", "active");
    const timers = [setTimeout(() => { step("resolve", "done"); step("analyse", "active"); }, 1600)];
    try {
      const data = await post("/api/v1/demo/audit", { reference });
      timers.forEach(clearTimeout);
      step("resolve", "done"); step("analyse", "done"); step("decide", "done");
      render(data);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      timers.forEach(clearTimeout);
      resetSteps();
      showError(error.message);
    } finally {
      run.disabled = false;
    }
  }

  async function issueCredential() {
    if (!current || !current.issuance || !current.issuance.ticket) return;
    const button = $("issue");
    button.disabled = true;
    button.textContent = "Writing to Stellar testnet…";
    step("credential", "active");
    try {
      const owner = current.issuance.owner;
      let signed = "";
      if (owner) {
        // The registry requires the owner's authorization: the named account signs in its own wallet.
        const api = window.freighterApi;
        if (!api) throw new Error("The Freighter library did not load. Install Freighter and reload.");
        const installed = await api.isConnected();
        if (installed.error || !installed.isConnected) throw new Error("Install the Freighter browser extension to sign as the owner.");
        const access = await api.requestAccess();
        if (access.error || access.address !== owner) throw new Error(`Switch Freighter to the account the repository names (${owner.slice(0, 6)}…${owner.slice(-4)}).`);
        const network = await api.getNetworkDetails();
        if (network.error || network.networkPassphrase !== "Test SDF Network ; September 2015") throw new Error("Switch Freighter to Stellar Testnet.");
        button.textContent = "Preparing your registration…";
        const prepared = await post("/api/v1/demo/credential/prepare", { ticket: current.issuance.ticket });
        if (prepared.signature_needed) {
          button.textContent = "Confirm in Freighter…";
          const value = await api.signTransaction(prepared.unsigned_xdr, { networkPassphrase: prepared.network_passphrase, address: owner });
          if (value.error || !value.signedTxXdr) throw new Error("The owner did not sign the registration.");
          signed = value.signedTxXdr;
        }
        button.textContent = "Writing to Stellar testnet…";
      }
      const cred = await post("/api/v1/demo/credential", { ticket: current.issuance.ticket, signed_xdr: signed });
      step("credential", "done");
      $("cred-idle").hidden = true;
      $("cred-done").hidden = false;
      $("token").textContent = cred.token_id;
      $("chain-score").textContent = `${cred.score} / 100${cred.is_current ? " · current" : ""}`;
      $("chain-hash").textContent = cred.report_matches ? "matches this report ✓" : "does not match this report";
      $("expires").textContent = new Date(cred.expires_at * 1000).toISOString().slice(0, 10);
      $("owner").textContent = `${cred.owner.slice(0, 6)}…${cred.owner.slice(-4)} · ${cred.owner_verified ? "verified: named in the repository and signed" : "demo operator (ownership not verified)"}`;
      const contract = $("contract"); contract.href = cred.contract_url; contract.textContent = cred.contract;
      const txs = $("txs"); txs.textContent = "";
      if (cred.already_issued && !cred.transactions.length) txs.append(el("li", { text: "This report was already credentialed; read back from the ledger." }));
      cred.transactions.forEach((tx) => txs.append(el("li", {}, el("a", { href: tx.url, target: "_blank", rel: "noopener", text: `${tx.function} · ${tx.hash.slice(0, 12)}…` }))));
    } catch (error) {
      step("credential", "");
      button.disabled = false;
      button.textContent = current.issuance.owner ? "Sign with Freighter and issue to my account" : "Issue credential on Stellar testnet";
      showError(error.message);
    }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); const value = input.value.trim(); if (value) audit(value); });
  document.querySelectorAll(".examples button").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.ref; audit(b.dataset.ref); }));
  async function recheck(event) {
    event.preventDefault();
    if (!current) return;
    const button = $("run-recheck"); button.disabled = true; button.textContent = "Auditing both versions…";
    $("error").hidden = true;
    try {
      const data = await post("/api/v1/demo/compare", { before: current.reference, after: $("fixed").value.trim() });
      const c = data.comparison;
      const sign = c.score_change >= 0 ? "+" : "";
      $("diff-head").textContent = `${c.before.decision} ${c.before.score} → ${c.after.decision} ${c.after.score} (${sign}${c.score_change})`;
      for (const [id, list] of [["diff-closed", c.closed], ["diff-remaining", c.remaining], ["diff-introduced", c.introduced]]) {
        const ul = $(id); ul.textContent = "";
        if (!list.length) ul.append(el("li", { class: "low" }, el("span", { class: "title", text: "None" })));
        list.forEach((f) => ul.append(el("li", { class: f.severity }, el("span", { class: "sev", text: f.severity }), el("span", { class: "title", text: f.title || f.id }))));
      }
      $("diff").hidden = false;
    } catch (error) {
      showError(error.message);
    } finally {
      button.disabled = false; button.textContent = "Compare →";
    }
  }

  $("recheck").addEventListener("submit", recheck);
  $("issue").addEventListener("click", issueCredential);
  $("download").addEventListener("click", () => {
    if (!current) return;
    const blob = new Blob([current.report_json], { type: "application/json" });
    const link = el("a", { href: URL.createObjectURL(blob), download: `agentveritas-${current.report_sha256.slice(0, 12)}.json` });
    document.body.append(link); link.click(); link.remove();
  });
  const preset = new URLSearchParams(location.search).get("ref");
  if (preset) { input.value = preset; audit(preset); }
})();
