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
  let sourceRevision = "";
  let runtimeResult = null;

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
    byId("runtime-results").replaceChildren();
    byId("download-runtime").hidden = true;
    byId("discovery-results").hidden = true;
    byId("review-result").hidden = true;
    byId("empty-report").hidden = false;
    byId("dossier-state").textContent = "Awaiting review";
    byId("run-status").textContent = "Free source review. No transaction or payment.";
    byId("download-note").textContent = "Your report stays in this tab until you leave or run another review.";
  }
  function setBusy(value) {
    busy = value;
    document.querySelectorAll("#review-form input, #review-form textarea, #review-form select, #review-form button, [data-example]").forEach((element) => { element.disabled = value; });
    byId("ai-consent").disabled = value || byId("ai-consent").dataset.available !== "true";
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
    byId("ai-consent").checked = false;
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
        files = pending; sourceReference = ""; sourceRevision = ""; invalidate(); renderFiles();
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
    const response = await fetch(`/api/v1/studio/${path}`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body),signal:AbortSignal.timeout(35000)});
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
      const response = await fetch("/api/v1/studio/runtime", {method:"POST", headers:{"Content-Type":"application/json",Authorization:`Bearer ${key}`}, body:JSON.stringify({source:submitted,entrypoint:byId("runtime-entrypoint").value,execution_consent:true,plan_sha256:result?.report?.discovery?.blueprint?.plan_sha256 || null}),signal:AbortSignal.timeout(60000)});
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
    byId("result-decision").textContent = value.decision === "needs_fixes" ? "Investigate before deployment" : "More evidence required";
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
      details.append(node("p", finding.evidence_grade === "confirmed" ? "Direct source or configuration evidence — not a runtime exploit." : "Heuristic signal — requires validation.", "evidence-kind"));
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
      const tools = JSON.parse(byId("tool-manifest").value);
      if (!Array.isArray(tools)) throw new Error("Tool permissions must be a JSON array.");
      if (!Object.keys(files).length && !byId("agent-prompt").value.trim() && !byId("stellar-address").value.trim()) throw new Error("Add a public Stellar address, source files or system instructions first.");
      input = { name: byId("agent-name").value, purpose: byId("agent-purpose").value, system_prompt: byId("agent-prompt").value, files: { ...files }, tools, dependencies, stellar_address:byId("stellar-address").value.trim(), network:byId("stellar-network").value, source_reference:sourceReference, source_revision:sourceRevision, architecture:JSON.parse(byId("architecture-manifest").value), ai_assistance:byId("ai-consent").checked, external_processing_consent:byId("ai-consent").checked };
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
  document.querySelectorAll("[data-result-view]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-result-view]").forEach((b) => {
        const selected = b === button;
        b.setAttribute("aria-pressed", String(selected));
        byId(`view-${b.dataset.resultView}`).hidden = !selected;
      });
    });
  });
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
  byId("download-report").addEventListener("click", () => { if (result) { download("agent-review.json", result.report_json); byId("download-note").textContent = "Report exported. Verify its SHA-256 against the fingerprint below."; } });
  byId("download-bundle").addEventListener("click", () => { if (submitted) download("agent-audit.json", JSON.stringify(submitted, null, 2)); });
})();
