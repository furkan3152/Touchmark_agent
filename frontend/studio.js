/* No source persistence, external scripts, wallet access or automatic submissions. */
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
    byId("review-result").hidden = true;
    byId("empty-report").hidden = false;
    byId("dossier-state").textContent = "Awaiting review";
    byId("run-status").textContent = "Free source review. No transaction or payment.";
    byId("download-note").textContent = "Your report stays in this tab until you leave or run another review.";
  }
  function setBusy(value) {
    busy = value;
    document.querySelectorAll("#review-form input, #review-form textarea, #review-form select, #review-form button, [data-example]").forEach((element) => { element.disabled = value; });
    form.setAttribute("aria-busy", String(value));
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
      remove.addEventListener("click", () => { delete files[name]; invalidate(); renderFiles(); });
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
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("An audit bundle must be a JSON object.");
    const allowed = new Set(["name", "purpose", "system_prompt", "files", "tools", "dependencies", "stellar_address", "network", "source_reference"]);
    if (Object.keys(bundle).some((key) => !allowed.has(key))) throw new Error("Unknown bundle fields. Use an exported agent-audit.json as the template.");
    if (bundle.files && (Array.isArray(bundle.files) || typeof bundle.files !== "object" || Object.values(bundle.files).some((value) => typeof value !== "string"))) throw new Error("Bundle files must map filenames to source text.");
    if (bundle.tools && !Array.isArray(bundle.tools)) throw new Error("Bundle tools must be an array.");
    byId("agent-name").value = bundle.name || "";
    byId("agent-purpose").value = bundle.purpose || "";
    byId("agent-prompt").value = bundle.system_prompt || "";
    files = { ...(bundle.files || {}) };
    dependencies = bundle.dependencies || [];
    byId("stellar-address").value = bundle.stellar_address || "";
    byId("stellar-network").value = bundle.network || "testnet";
    sourceReference = bundle.source_reference || "";
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
      if (selected.length === 1 && selected[0].name === "agent-audit.json") {
        loadBundle(JSON.parse(await selected[0].text()));
      } else {
        const pending = { ...files };
        for (const file of selected) {
          if (Object.keys(pending).some((name) => name.toLowerCase() === file.name.toLowerCase())) throw new Error(`${file.name} already exists. Remove it before adding a replacement.`);
          if (file.size > 32000) throw new Error(`${file.name} exceeds 32 KB.`);
          pending[file.name] = await file.text();
        }
        if (Object.keys(pending).length > 12 || Object.values(pending).reduce((sum, content) => sum + new TextEncoder().encode(content).length, 0) > 64000) throw new Error("A review accepts at most 12 files and 64 KB of source.");
        files = pending; invalidate(); renderFiles();
      }
      document.querySelectorAll("[data-example]").forEach((item) => item.setAttribute("aria-pressed", "false"));
    } catch (failure) { error(failure.message); }
    finally { event.target.value = ""; setBusy(false); }
  });
  form.addEventListener("input", (event) => {
    if (busy) return;
    invalidate(); error();
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
    const response = await fetch(`/api/v1/studio/${path}`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
    const data = await response.json();
    if (!response.ok) throw new Error(Array.isArray(data.detail) ? data.detail.map((item) => item.msg).join("; ") : data.detail || "Request failed. Please retry.");
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
    error(); setBusy(true); byId("import-status").textContent = "Importing the public bundle…";
    try {
      const value = await post("import", {repository:byId("github-repository").value.trim()});
      loadBundle({...value.bundle, source_reference:value.source});
      byId("import-status").textContent = `Imported ${Object.keys(files).length} files. Check the details below, then start the audit.`;
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
    byId("result-decision").textContent = value.decision === "needs_fixes" ? "Investigate before deployment" : "More evidence required";
    byId("result-name").textContent = value.report.agent.name;
    byId("result-summary").textContent = "Source inspected. Runtime behavior, owner identity and onchain publication have not been verified.";
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
      summary.append(node("span", findingTitles[finding.id] || fallback.charAt(0).toUpperCase() + fallback.slice(1)), node("span", finding.severity, "severity"));
      details.append(summary, node("p", finding.detail));
      details.append(node("p", finding.evidence_grade === "confirmed" ? "Direct source or configuration evidence — not a runtime exploit." : "Heuristic signal — requires validation.", "evidence-kind"));
      if (finding.evidence) details.append(node("pre", finding.evidence));
      if (finding.remediation) details.append(node("p", `Next check: ${finding.remediation}`));
      if (secondary.includes(finding)) observations.append(details);
      else container.append(details);
    });
    if (secondary.length) container.append(observations);
    if (!priorityIds.size) container.prepend(node("p", "No directly evidenced high-priority source findings. Review the remaining observations; this is not a safety clearance.", "help"));
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
      const tools = JSON.parse(byId("tool-manifest").value);
      if (!Array.isArray(tools)) throw new Error("Tool permissions must be a JSON array.");
      if (!Object.keys(files).length && !byId("agent-prompt").value.trim() && !byId("stellar-address").value.trim()) throw new Error("Add a public Stellar address, source files or system instructions first.");
      input = { name: byId("agent-name").value, purpose: byId("agent-purpose").value, system_prompt: byId("agent-prompt").value, files: { ...files }, tools, dependencies, stellar_address:byId("stellar-address").value.trim(), network:byId("stellar-network").value, source_reference:sourceReference };
    } catch (failure) { error(failure.message); return; }
    setBusy(true);
    byId("run-review").textContent = "Reviewing source…";
    byId("run-status").textContent = "Checking the submitted bundle across seven dimensions…";
    try {
      const response = await fetch("/api/v1/studio/review", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input), signal: AbortSignal.timeout(45000) });
      const value = await response.json();
      if (!response.ok) throw new Error(Array.isArray(value.detail) ? value.detail.map((item) => item.msg).join("; ") : value.detail || `Review failed (HTTP ${response.status}).`);
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.report_json));
      const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2,"0")).join("");
      if (hash !== value.report_sha256) throw new Error("Report integrity check failed. Run a new review.");
      // Render the committed bytes, not a potentially divergent response view.
      value.report = JSON.parse(value.report_json);
      result = value; submitted = input;
      renderReport(value);
      byId("run-status").textContent = "Review complete. Download your evidence before leaving.";
      if (window.innerWidth <= 720) byId("dossier-title").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    } catch (failure) {
      error(failure.name === "TimeoutError" ? "The review timed out. Retry with a smaller source bundle." : failure.message);
      byId("run-status").textContent = "No completed review. Your inputs are still available to retry.";
    } finally { setBusy(false); byId("run-review").textContent = "Audit agent — free"; }
  });
  function download(filename, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json;charset=utf-8" }));
    const link = node("a"); link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  byId("download-report").addEventListener("click", () => { if (result) { download("agent-review.json", result.report_json); byId("download-note").textContent = "Report exported. Verify its SHA-256 against the fingerprint below."; } });
  byId("download-bundle").addEventListener("click", () => { if (submitted) download("agent-audit.json", JSON.stringify(submitted, null, 2)); });
})();
