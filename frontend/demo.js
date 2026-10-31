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

  // A proxy or the platform answered instead of the audit (no JSON detail): say what to do.
  function failureMessage(status) {
    if (status === 502 || status === 503) return "The audit service did not answer (the connection was cut or the function restarted). Nothing was lost: run it again; large repositories may need a folder link instead of the whole repository.";
    if (status === 504) return "The audit took longer than the time limit. Try a folder link to the agent's code, or run scripts/ci_audit.py locally.";
    if (status === 413) return "The request is too large. Shorten the .tmark or audit a smaller folder.";
    if (status === 429) return "Too many requests right now. Wait a minute and try again.";
    return `The request failed (HTTP ${status}). Try again in a moment.`;
  }

  function requestError(data, status) {
    const detail = data && data.detail;
    if (typeof detail === "string") return new Error(detail);
    if (detail && detail.tmark_errors) {
      showTmarkErrors(detail.tmark_errors);
      return new Error(detail.message || "The .tmark is not valid.");
    }
    return new Error(failureMessage(status));
  }

  async function post(path, body) {
    let response;
    try {
      response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } catch {
      throw new Error("The request did not reach the server. Check your connection and try again.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw requestError(data, response.status);
    return data;
  }

  const STAGES = { queued: "Starting", resolving: "Pinning the source", fetching: "Fetching the repository", rules: "Running the rules",
    deep_review: "Model review", verifier: "Verifying findings", done: "Sealing the report" };

  function progressLine(event) {
    let text = STAGES[event.stage] || event.stage || "Working";
    if (event.stage === "deep_review" && event.files_total) text += `: read ${event.files_read || 0} of ${event.files_total} files`;
    if (event.stage === "verifier" && event.total) text += `: ${event.checked || 0} of ${event.total} findings checked`;
    $("progress").textContent = `${text} · ${Math.round(event.elapsed || 0)} s`;
    $("progress").hidden = false;
    if (["resolving", "fetching"].includes(event.stage)) step("resolve", "active");
    if (["rules", "deep_review", "verifier"].includes(event.stage)) { step("resolve", "done"); step("analyse", "active"); }
    if (event.stage === "done") { step("analyse", "done"); step("decide", "active"); }
  }

  // The audit streams NDJSON (stage events and heartbeats) so the connection stays alive; a
  // plain JSON answer (an older server, a proxy that buffers) is read the same way.
  async function streamAudit(body) {
    let response;
    try {
      response = await fetch("/api/v1/demo/audit", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" }, body: JSON.stringify(body) });
    } catch {
      throw new Error("The request did not reach the server. Check your connection and try again.");
    }
    if (!response.ok || !(response.headers.get("content-type") || "").includes("ndjson") || !response.body) {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw requestError(data, response.status);
      return data;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "", result = null;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let cut;
        while ((cut = buffer.indexOf("\n")) >= 0) {
          const text = buffer.slice(0, cut).trim(); buffer = buffer.slice(cut + 1);
          if (!text) continue;
          const event = JSON.parse(text);
          if (event.type === "result") result = event.data;
          else if (event.type === "error") throw requestError({ detail: event.detail }, event.status);
          else progressLine(event);
        }
      }
    } catch (error) {
      if (error instanceof SyntaxError || error.name === "TypeError") throw new Error(failureMessage(502));
      throw error;
    }
    if (!result) throw new Error(failureMessage(502));
    return result;
  }

  function showTmarkErrors(errors) {
    const list = $("tmark-result"); list.textContent = "";
    errors.forEach((e) => list.append(el("li", { class: "high" }, el("span", { class: "sev", text: e.line ? `line ${e.line}` : "file" }),
      el("span", { class: "title", text: `${e.field}: ${e.message}` }))));
    document.querySelector(".declare").open = true;
  }

  async function checkTmark() {
    const text = $("tmark").value.trim();
    const list = $("tmark-result"); list.textContent = "";
    if (!text) { list.append(el("li", { class: "low" }, el("span", { class: "title", text: "Paste a .tmark or choose the file first." }))); return; }
    try {
      const data = await post("/api/v1/tmark/check", { text });
      if (!data.valid) { showTmarkErrors(data.error_details || []); return; }
      (data.summary || []).forEach((line) => list.append(el("li", { class: "low" }, el("span", { class: "title", text: line }))));
    } catch (error) { showError(error.message); }
  }

  async function draftTmark() {
    const reference = input.value.trim();
    if (!reference) { showError("Enter the repository link above first; the draft is made from its code."); return; }
    const button = $("tmark-draft"); button.disabled = true; button.textContent = "Reading the code…";
    try {
      const data = await post("/api/v1/tmark/template", { reference });
      $("tmark").value = JSON.stringify(data.draft, null, 2);
      const list = $("tmark-result"); list.textContent = "";
      list.append(el("li", { class: "low" }, el("span", { class: "title", text: data.note })));
    } catch (error) { showError(error.message); }
    finally { button.disabled = false; button.textContent = "Draft one from the repository"; }
  }

  const STAMP_WORDS = { pass: "Touchmarked", needs_fixes: "Not yet", needs_evidence: "Show more" };

  const VERDICTS = {
    confirmed: "Verified: a second model confirmed this in the code",
    partial: "Partly verified: real, but narrower or less severe",
    refuted: "Disputed: a second model could not confirm this",
    unverifiable: "Not verified: the cited code could not be checked",
  };

  function finding(f) {
    const v = f.verification && f.verification.verdict;
    return el("li", { class: f.severity },
      el("span", { class: "sev", text: f.severity }), el("span", { class: "title", text: f.title }),
      f.source === "ai_review" ? el("span", { class: "tag", text: "AI review" }) : null,
      v ? el("span", { class: "tag verdict-" + v, text: VERDICTS[v] || v, title: f.verification.reason || "" }) : null,
      f.evidence ? el("code", { text: f.evidence }) : null,
      f.remediation ? el("p", { class: "fix", text: "Fix: " + f.remediation }) : null);
  }

  function tmarkLine(t) {
  const which = t.source === "supplied" ? "your .tmark" : ".tmark";
  if (t.status === "valid") {
    let line = `${which} declared, checked against the code`;
    if (t.source === "supplied" && t.repository_status === "valid") line += (t.mismatches || []).length ? `; differs from the repository's .tmark in ${t.mismatches.length} ${t.mismatches.length === 1 ? "place" : "places"}` : "; same as the repository's";
    return line;
  }
  if (t.status === "invalid") return `${which} invalid (${(t.errors || []).length} ${(t.errors || []).length === 1 ? "error" : "errors"}), not used`;
  if (t.status === "not_used") return "your .tmark was not used: no source is linked";
  return "no .tmark declaration";
}

function aiLine(ai) {
    if (ai.review === "no_source") return "AI review: not applicable; no source code is linked to this reference.";
    if (ai.review === "off") return "AI review: not enabled on this deployment; rules only.";
    if (ai.review === "no_consent") return "AI review: not run; you did not consent to sending the source. Rules only.";
    if (["rate_limited", "store_unavailable", "not_configured"].includes(ai.review)) return "AI review: " + (ai.note || "allowance used; this audit used the rules only.");
    if (!ai.review) return "";
    const status = { completed: "completed", timeout: "stopped at the time limit (findings so far kept)",
      skipped: "skipped (no time left)", unavailable: "unavailable (provider error)", incomplete: "incomplete" }[ai.review] || ai.review;
    let line = `AI review ${status}: read ${ai.files_read || 0} of ${ai.files_total || 0} files, added ${ai.findings_added || 0} findings.`;
    const v = ai.verification || {};
    if (v.checked) line += ` Verifier re-checked ${v.checked}: ${v.confirmed || 0} confirmed, ${v.partial || 0} partly, ${v.refuted || 0} disputed.`;
    return line;
  }

  function render(data) {
    current = data;
    $("result").hidden = false;
    // With no code to review there is nothing to score: show a dash, not a perfect 100.
    const unscored = !data.files && data.decision === "needs_evidence";
    $("score").textContent = unscored ? "—" : Number(data.score).toFixed(1);
    $("ring").style.strokeDashoffset = "327";
    const stamp = $("stamp");
    stamp.className = "stamp " + data.decision;
    $("stamp-word").textContent = STAMP_WORDS[data.decision] || data.decision;
    void stamp.offsetWidth; // restart the stamp animation on every result
    stamp.classList.add("slam");
    requestAnimationFrame(() => {
      $("ring").style.strokeDashoffset = String(327 - 327 * (unscored ? 0 : Math.max(0, Math.min(100, data.score))) / 100);
    });
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
    $("counts").textContent = `${data.files || 0} ${data.files === 1 ? "file" : "files"} analysed · ${c.risks || 0} risks (${c.critical || 0} critical, ${c.high || 0} high) · ${c.gaps || 0} evidence gaps · ${tmarkLine(data.tmark || {})}`;

    $("ai").textContent = aiLine(data.ai || {});
    const risks = $("risks"); risks.textContent = "";
    if (!data.risks.length) risks.append(el("li", { class: "low" }, el("span", { class: "title", text: "No exploitable path from untrusted input to keys, payments, commands or network was found." })));
    data.risks.forEach((f) => risks.append(finding(f)));
    const more = (c.risks || 0) - data.risks.length;
    if (more > 0) risks.append(el("li", { class: "low" }, el("span", { class: "title", text: `${more} more lower-severity ${more === 1 ? "risk" : "risks"} in the report JSON.` })));
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
        : " No owner is named, so it is issued to the demo operator (ownership not verified). Add a .tmark file with owner.stellar_account to your repository to receive it yourself (see /schemas/tmark-v1.json).";
    $("cred-note").textContent = issuance.ticket
      ? "This report passed. The validator writes its hash and score to the Touchmark registry, and the credential contract issues a non-transferable token bound to it: the touchmark." + ownerNote
      : issuance.reason || (issuance.enabled ? "" : "Credential issuance is not configured on this deployment.");
    $("issue").textContent = issuance.owner ? "Sign with Freighter and issue to my account" : "Stamp it on Stellar testnet";
    step("credential", issuance.ticket ? "" : "skip");
  }

  async function audit(reference) {
    $("error").hidden = true;
    $("result").hidden = true;
    $("steps").hidden = false;
    $("tmark-result").textContent = "";
    resetSteps();
    run.disabled = true;
    step("resolve", "active");
    const started = Date.now();
    // Elapsed time keeps moving even when the server sends only heartbeats.
    const clock = setInterval(() => { const p = $("progress"); p.hidden = false; p.textContent = p.textContent.replace(/· \d+ s$/, "") + `· ${Math.round((Date.now() - started) / 1000)} s`; }, 1000);
    const body = { reference, model_review_consent: $("consent").checked };
    const declared = $("tmark").value.trim();
    if (declared) body.tmark = declared;
    try {
      const data = await streamAudit(body);
      step("resolve", "done"); step("analyse", "done"); step("decide", "done");
      render(data);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      resetSteps();
      showError(error.message);
    } finally {
      clearInterval(clock);
      $("progress").hidden = true; $("progress").textContent = "";
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
      if (cred.card_svg) {
        const card = new Blob([cred.card_svg], { type: "image/svg+xml" });
        // A data URL: the page CSP allows data: images, not blob: ones.
        $("cred-card").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(cred.card_svg);
        $("dl-card").onclick = () => save(card, `touchmark-${cred.token_id.slice(0, 12)}.svg`);
        $("dl-meta").onclick = () => save(new Blob([JSON.stringify(cred.metadata, null, 2)], { type: "application/json" }), `touchmark-${cred.token_id.slice(0, 12)}.json`);
      }
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
      button.textContent = current.issuance.owner ? "Sign with Freighter and issue to my account" : "Stamp it on Stellar testnet";
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
      $("diff-head").textContent = `${data.mode === "rules_only" ? "Rules only: " : ""}${c.before.decision} ${c.before.score} → ${c.after.decision} ${c.after.score} (${sign}${c.score_change})`;
      $("diff-note").textContent = data.note || "";
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
  $("tmark-check").addEventListener("click", checkTmark);
  $("tmark-draft").addEventListener("click", draftTmark);
  $("tmark-file").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 64000) { showError("The .tmark is larger than 64 KB."); return; }
    $("tmark").value = await file.text();
    event.target.value = "";
    checkTmark();
  });
  // Consent is needed only where the model review can run; say so when it cannot.
  fetch("/api/v1/demo/config").then((r) => r.ok ? r.json() : null).then((config) => {
    const review = config && config.model_review;
    if (review && !review.available) {
      $("consent").disabled = true;
      $("consent-text").textContent = "The model review is not enabled on this deployment; the audit runs the deterministic rules only.";
    }
  }).catch(() => {});
  $("issue").addEventListener("click", issueCredential);
  function save(blob, name) {
    const link = el("a", { href: URL.createObjectURL(blob), download: name });
    document.body.append(link); link.click(); link.remove();
  }
  $("download").addEventListener("click", () => {
    if (!current) return;
    save(new Blob([current.report_json], { type: "application/json" }), `touchmark-${current.report_sha256.slice(0, 12)}.json`);
  });
  const preset = new URLSearchParams(location.search).get("ref");
  if (preset) { input.value = preset; audit(preset); }
})();
