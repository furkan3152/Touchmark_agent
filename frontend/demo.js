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
    $("score").textContent = data.score;
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

    $("report-hash").textContent = data.report_sha256;
    $("cred-done").hidden = true;
    const issuance = data.issuance || {};
    const issue = $("issue");
    issue.hidden = !issuance.ticket;
    issue.disabled = false;
    $("cred-note").textContent = issuance.ticket
      ? "This report passed. The validator writes its hash and score to the AgentVeritas registry, and the credential contract issues a non-transferable token bound to it."
      : issuance.reason || (issuance.enabled ? "" : "Credential issuance is not configured on this deployment.");
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
      const cred = await post("/api/v1/demo/credential", { ticket: current.issuance.ticket });
      step("credential", "done");
      $("cred-idle").hidden = true;
      $("cred-done").hidden = false;
      $("token").textContent = cred.token_id;
      $("chain-score").textContent = `${cred.score} / 100${cred.is_current ? " · current" : ""}`;
      $("chain-hash").textContent = cred.report_matches ? "matches this report ✓" : "does not match this report";
      $("expires").textContent = new Date(cred.expires_at * 1000).toISOString().slice(0, 10);
      const contract = $("contract"); contract.href = cred.contract_url; contract.textContent = cred.contract;
      const txs = $("txs"); txs.textContent = "";
      if (cred.already_issued && !cred.transactions.length) txs.append(el("li", { text: "This report was already credentialed; read back from the ledger." }));
      cred.transactions.forEach((tx) => txs.append(el("li", {}, el("a", { href: tx.url, target: "_blank", rel: "noopener", text: `${tx.function} · ${tx.hash.slice(0, 12)}…` }))));
    } catch (error) {
      step("credential", "");
      button.disabled = false;
      button.textContent = "Issue credential on Stellar testnet";
      showError(error.message);
    }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); const value = input.value.trim(); if (value) audit(value); });
  document.querySelectorAll(".examples button").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.ref; audit(b.dataset.ref); }));
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
