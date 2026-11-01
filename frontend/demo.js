"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const form = $("audit-form"), input = $("reference"), run = $("run");
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const scrollTo = (node, block = "start") => node && node.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block });
  let current = null;
  let config = null;
  let punch = null;

  const HEADLINES = {
    pass: "No actionable risk found. Eligible for a Stellar credential.",
    needs_fixes: "Do not give this agent the keys yet.",
    needs_evidence: "No actionable risk, but part of the agent could not be reviewed.",
  };
  const DECISION_WORDS = { pass: "pass", needs_fixes: "needs fixes", needs_evidence: "needs evidence" };

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v; else if (k === "text") node.textContent = v; else node.setAttribute(k, v);
    }
    for (const child of children) if (child !== null && child !== undefined && child !== false) node.append(child);
    return node;
  }
  const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
  const clock = (seconds) => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, "0")}`;
  const localTime = (iso) => { try { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); } catch { return ""; } };

  function inlineError(id, message) { const box = $(id); box.textContent = message || ""; box.hidden = !message; }

  // ------------------------------------------------------------------ requests
  /** An Error with what the visitor can do about it: status, kind and, for a bad .tmark, the errors. */
  function failure(status, detail) {
    if (detail && typeof detail === "object" && detail.tmark_errors) {
      const error = new Error(detail.message || "The .tmark is not valid, so nothing was audited.");
      return Object.assign(error, { status, kind: "tmark", tmarkErrors: detail.tmark_errors });
    }
    if (typeof detail === "string" && detail) return Object.assign(new Error(detail), { status, kind: status === 422 ? "input" : "server" });
    const known = {
      413: ["The request is too large. Shorten the .tmark or audit a smaller folder.", "input"],
      429: ["Too many requests from this connection right now. Wait a minute, then try again.", "busy"],
      410: ["This audit is no longer kept on the server (audits expire after a day). Run it again.", "expired"],
      502: ["The audit service did not answer: the connection was cut or the function restarted. Nothing was lost, so run it again.", "server"],
      503: ["The audit service is unavailable for a moment. Run it again in a minute.", "server"],
      504: ["One request ended before the audit could save its place. Run it again, or run scripts/ci_audit.py locally.", "slow"],
    }[status];
    if (known) return Object.assign(new Error(known[0]), { status, kind: known[1] });
    return Object.assign(new Error(`The request failed (HTTP ${status}). Try again in a moment.`), { status, kind: "server" });
  }
  const offline = () => Object.assign(new Error("The request did not reach Touchmark. Check your connection and try again."), { kind: "network" });
  const aborted = () => Object.assign(new Error("Cancelled."), { kind: "aborted" });
  const cancelled = () => Object.assign(new Error("The audit was cancelled."), { kind: "cancelled" });
  const sleep = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (signal) signal.addEventListener("abort", () => { clearTimeout(timer); reject(aborted()); }, { once: true });
  });

  async function post(path, body) {
    let response;
    try {
      response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } catch { throw offline(); }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw failure(response.status, data && data.detail);
    return data;
  }

  // An audit is a job of one or more requests ("legs"): no clock stops the review, so a large
  // repository needs several. Each leg streams NDJSON (a job event, stage events, heartbeats)
  // and ends with the result, or "continue" (open the next leg now), "busy" (another request is
  // advancing it: try again shortly) or "cancelled". The job id is kept in sessionStorage, so a
  // reload picks the audit up where it is. A plain JSON answer (an older server, a proxy that
  // buffers) is read the same way, just without the stages.
  const JOB_KEY = "touchmark.audit.job";
  const saveJob = (job) => { try { sessionStorage.setItem(JOB_KEY, JSON.stringify(job)); } catch { /* storage off: no resume after reload */ } };
  const loadJob = () => { try { return JSON.parse(sessionStorage.getItem(JOB_KEY) || "null"); } catch { return null; } };
  const dropJob = () => { try { sessionStorage.removeItem(JOB_KEY); } catch { /* nothing kept */ } };
  const ENDINGS = ["continue", "busy", "cancelled"];

  async function streamLeg(path, body, onEvent, signal) {
    let response;
    try {
      response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" }, body: JSON.stringify(body), signal });
    } catch (error) { throw error.name === "AbortError" ? aborted() : offline(); }
    const streamed = (response.headers.get("content-type") || "").includes("ndjson") && response.body;
    if (!response.ok || !streamed) {
      const data = await response.json().catch(() => null);
      if (!response.ok) throw failure(response.status, data && data.detail);
      if (!data) throw failure(502);
      onEvent({ type: "unstreamed" });
      if (response.status === 202 && ENDINGS.includes(data.type)) return { kind: data.type, event: data };
      return { kind: "result", data };
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "", outcome = null;
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
          if (event.type === "result") outcome = { kind: "result", data: event.data };
          else if (event.type === "error") throw failure(event.status, event.detail);
          else if (ENDINGS.includes(event.type)) outcome = { kind: event.type, event };
          else onEvent(event);
        }
      }
    } catch (error) {
      if (error.name === "AbortError") throw aborted();
      if (error instanceof SyntaxError || error.name === "TypeError") throw failure(502);
      throw error;
    }
    if (!outcome) throw failure(502);
    return outcome;
  }

  // ------------------------------------------------------------------ the desk (progress)
  const STAGES = ["resolving", "fetching", "rules", "deep_review", "verifier", "done"];
  const desk = { started: 0, last: 0, timer: null, stage: "", streamed: true, leg: 1, furthest: 0, waiting: "" };
  //: What a later leg is doing before the review resumes where it stopped.
  const REPLAY = { resolving: "pinning the same commit again", fetching: "fetching that commit again",
    rules: "re-running the rules on it (they give the same result)" };

  function stageItem(name) { return $("timeline").querySelector(`[data-stage="${name}"]`); }
  function mark(name, state, detail) {
    const item = stageItem(name);
    if (!item) return;
    if (state) item.dataset.state = state;
    if (detail !== undefined) item.querySelector(".t-detail").textContent = detail;
  }
  function bar(name, done, total) {
    const fill = stageItem(name).querySelector(".t-bar i");
    if (!fill) return;
    stageItem(name).classList.toggle("has-bar", !!total);
    fill.style.width = total ? `${Math.min(100, Math.round(100 * (done || 0) / total))}%` : "0";
  }
  function announce(text) { $("desk-live").textContent = text; }

  function openDesk(reference, consent) {
    const box = $("desk");
    box.hidden = false;
    box.dataset.state = "running";
    $("desk-error").hidden = true;
    $("desk-title").textContent = "Punch is reading the agent";
    $("desk-ref").textContent = reference.replace(/^https:\/\/github\.com\//, "");
    $("desk-wait").textContent = "";
    for (const name of STAGES) { mark(name, "pending", ""); bar(name, 0, 0); }
    $("desk-actions").hidden = true; $("desk-part").textContent = "";
    $("desk-cancel").disabled = false; $("desk-cancel").hidden = false;
    const review = config && config.model_review;
    if (review && !review.available) {
      mark("deep_review", "skipped", "Not available on this deployment: rules only");
      mark("verifier", "skipped", "Runs only after a model review");
    } else if (!consent) {
      mark("deep_review", "skipped", "Off: you did not tick the model review, so the source stays here");
      mark("verifier", "skipped", "Runs only after a model review");
    }
    mark("resolving", "active", "Resolving the reference to one commit");
    if (window.TouchmarkMascot) {
      punch = punch || TouchmarkMascot.mount("#desk-punch", "scanning", { size: 132 });
      if (punch) punch.set("scanning");
    }
    desk.started = desk.last = Date.now();
    desk.stage = "resolving"; desk.streamed = true; desk.leg = 1; desk.furthest = 0; desk.waiting = "";
    clearInterval(desk.timer);
    desk.timer = setInterval(tick, 1000);
    tick();
    announce("Audit started: pinning the source.");
  }

  function tick() {
    const now = Date.now();
    $("desk-elapsed").textContent = clock((now - desk.started) / 1000);
    const quiet = Math.round((now - desk.last) / 1000);
    if (!desk.streamed) $("desk-wait").textContent = "This connection does not stream progress; the full result arrives in one piece.";
    else if (desk.waiting) $("desk-wait").textContent = desk.waiting;
    else if (quiet >= 25) $("desk-wait").textContent = `No signal for ${quiet} s. The audit carries on at the server; the answer is on its way.`;
    else $("desk-wait").textContent = desk.stage === "deep_review"
      ? "The model review reads every file, the ones holding keys, signing and payments first. A large repository takes several minutes and several requests; it carries on by itself."
      : "";
  }

  function beat() {
    desk.last = Date.now();
    const pulse = $("desk-pulse");
    pulse.classList.remove("beat"); void pulse.offsetWidth; pulse.classList.add("beat");
  }

  function finishUpTo(stage) {
    const at = STAGES.indexOf(stage);
    STAGES.slice(0, at).forEach((name) => {
      const item = stageItem(name);
      if (item.dataset.state === "active") item.dataset.state = "done";
      else if (item.dataset.state === "pending") item.dataset.state = "passed";
    });
  }

  function onJob(event) {
    activeJob = { job_id: event.job_id, reference: event.reference || (activeJob && activeJob.reference) || "", consent: !!event.consent };
    saveJob(activeJob);
    desk.leg = event.leg || 1;
    desk.waiting = "";
    // One clock for the whole audit, across requests and reloads.
    if (typeof event.elapsed === "number") desk.started = Math.min(desk.started, Date.now() - event.elapsed * 1000);
    $("desk-actions").hidden = false;
    $("desk-part").textContent = desk.leg > 1 ? `Request ${desk.leg} of this audit: it continues where the last one stopped.` : "Runs until every file is read; only a spend cap could stop it.";
    const p = event.progress || {};
    if (p.stage === "deep_review" || p.stage === "verifier") {
      finishUpTo(p.stage);
      desk.stage = p.stage; desk.furthest = Math.max(desk.furthest, STAGES.indexOf(p.stage));
      if (p.stage === "deep_review" && p.files_total) { mark("deep_review", "active", `Read ${p.files_read || 0} of ${plural(p.files_total, "file")}`); bar("deep_review", p.files_read, p.files_total); }
      if (p.stage === "verifier" && p.total) { mark("verifier", "active", `Re-checked ${p.checked || 0} of ${plural(p.total, "finding")} at the cited line`); bar("verifier", p.checked, p.total); }
    }
    tick();
  }

  function onEvent(event) {
    if (event.type === "unstreamed") { desk.streamed = false; tick(); return; }
    beat();
    if (event.type === "job") { onJob(event); return; }
    if (event.type === "heartbeat" || !event.stage || event.stage === "queued") return;
    const s = event.stage;
    if (!STAGES.includes(s)) return;
    if (STAGES.indexOf(s) < desk.furthest) {
      // A later request re-reads the pinned commit before the review resumes: keep the timeline.
      desk.waiting = REPLAY[s] ? `Request ${desk.leg}: ${REPLAY[s]}, then the review continues.` : "";
      tick();
      return;
    }
    desk.waiting = "";
    desk.furthest = Math.max(desk.furthest, STAGES.indexOf(s));
    if (s !== desk.stage) finishUpTo(s);
    desk.stage = s;
    if (s === "resolving") { mark(s, "active", "Resolving the reference to one commit"); }
    if (s === "fetching") {
      const repo = (event.repository || "").replace("https://github.com/", "");
      mark(s, "active", repo ? `${repo} @ ${event.revision || ""}` : "Downloading the source");
      announce(`Fetching ${repo || "the source"}.`);
    }
    if (s === "rules") {
      mark(s, "active", event.files ? `Tracing ${plural(event.files, "file")} from input to keys, payments and network` : "Tracing input to keys, payments and network");
      announce("Running the rules.");
    }
    if (s === "deep_review") {
      const total = event.files_total || 0;
      mark(s, "active", total ? `Read ${event.files_read || 0} of ${plural(total, "file")}` : "Reading the files that hold authority");
      bar(s, event.files_read, total);
      if (!event.files_read) announce("The model review started.");
    }
    if (s === "verifier") {
      const total = event.total || 0;
      mark(s, "active", total ? `Re-checked ${event.checked || 0} of ${plural(total, "finding")} at the cited line` : "Re-checking each finding at the cited line");
      bar(s, event.checked, total);
      if (!event.checked) announce("Verifying the findings.");
    }
    if (s === "done") { mark(s, "active", "Deciding, then sealing the report with its SHA-256"); announce("Sealing the report."); }
    tick();
  }

  const REVIEW_STAGE = {
    completed: ["done", null], capped: ["done", "Stopped at a spend cap; findings kept, unread files listed"],
    timeout: ["done", "Stopped at the local time limit; findings so far kept"],
    incomplete: ["done", "Incomplete: not every file that holds authority was read"],
    skipped: ["skipped", "Skipped: no time was left after the rules"],
    unavailable: ["failed", "The model provider did not answer"],
    no_consent: ["skipped", "Off: you did not tick the model review"],
    rate_limited: ["skipped", "Allowance used up for now: rules only"],
    store_unavailable: ["skipped", "Allowance could not be checked: rules only"],
    not_configured: ["skipped", "No allowance store here: rules only"],
    off: ["skipped", "Not available on this deployment: rules only"],
    no_source: ["skipped", "No source code to review"],
  };

  function closeDesk(data) {
    clearInterval(desk.timer);
    finishUpTo("done");
    const ai = data.ai || {};
    const [state, note] = REVIEW_STAGE[ai.review] || ["done", null];
    const deep = stageItem("deep_review");
    if (deep.dataset.state !== "done" || state !== "done" || note) mark("deep_review", state, note || undefined);
    if ((ai.review === "completed" || ai.review === "capped") && ai.files_total) { mark("deep_review", "done", `Read ${ai.files_read} of ${plural(ai.files_total, "file")}, added ${plural(ai.findings_added || 0, "finding")}`); bar("deep_review", ai.files_read, ai.files_total); }
    const v = ai.verification || {};
    if (v.checked) { mark("verifier", "done", `${v.confirmed || 0} confirmed, ${v.partial || 0} partly, ${v.refuted || 0} disputed of ${v.checked}`); bar("verifier", v.checked, v.checked); }
    else if (state !== "done") mark("verifier", "skipped", "Runs only after a model review");
    else if (stageItem("verifier").dataset.state !== "done") mark("verifier", "passed", "Nothing to re-check");
    if (!data.source || !data.source.repository) { mark("fetching", "skipped", "No source repository is linked"); mark("rules", "passed", "Read the ledger record only"); }
    mark("done", "done", `Sealed · SHA-256 ${String(data.report_sha256 || "").slice(0, 12)}…`);
    const seconds = Math.round((Date.now() - desk.started) / 1000);
    $("desk").dataset.state = "done";
    $("desk-title").textContent = `Done in ${clock(seconds)}: ${DECISION_WORDS[data.decision] || data.decision}`;
    $("desk-actions").hidden = !(data.job && data.job.legs > 1);
    $("desk-cancel").hidden = true;
    $("desk-part").textContent = data.job && data.job.legs > 1 ? `Ran in ${data.job.legs} requests, one after another; the review never stopped on time.` : "";
    $("desk-wait").textContent = "";
    $("desk-elapsed").textContent = clock(seconds);
    if (punch && window.TouchmarkMascot) {
      const { state: mood, tone } = TouchmarkMascot.forDecision(data.decision);
      punch.set(mood, { tone });
    }
    announce(`Audit finished: ${DECISION_WORDS[data.decision] || data.decision}, score ${data.score}.`);
  }

  function cancelledDesk() {
    clearInterval(desk.timer);
    $("desk").dataset.state = "failed";
    $("desk-title").textContent = "Audit cancelled";
    $("desk-wait").textContent = "Nothing more runs or is spent on it. Start a new audit whenever you like.";
    $("desk-actions").hidden = true;
    $("desk-error").hidden = true;
    const item = stageItem(desk.stage || "resolving");
    if (item && item.dataset.state === "active") item.dataset.state = "skipped";
    if (punch) punch.set("idle");
    announce("The audit was cancelled.");
  }

  function failDesk(error, retry) {
    clearInterval(desk.timer);
    $("desk-actions").hidden = true;
    const item = stageItem(desk.stage || "resolving");
    if (error.kind === "tmark") mark("resolving", "pending", "Not started: a pasted .tmark is checked before anything else");
    else if (item) item.dataset.state = "failed";
    $("desk").dataset.state = "failed";
    $("desk-title").textContent = error.kind === "tmark" ? "The .tmark needs fixing first" : "The audit stopped";
    $("desk-wait").textContent = "";
    $("desk-error-text").textContent = error.message;
    const actions = $("desk-error-actions"); actions.textContent = "";
    if (error.kind === "tmark") {
      const show = el("button", { type: "button", class: "ghost", text: "Show the problems" });
      show.addEventListener("click", () => { $("declare").open = true; scrollTo($("declare"), "center"); setTimeout(() => $("tmark").focus({ preventScroll: true }), 250); });
      actions.append(show);
    } else if (error.kind === "input") {
      const fix = el("button", { type: "button", class: "ghost", text: "Edit the link" });
      fix.addEventListener("click", () => { scrollTo(form, "center"); input.focus({ preventScroll: true }); input.select(); });
      actions.append(fix);
    } else {
      const again = el("button", { type: "button", class: "ghost", text: error.kind === "busy" ? "Try again" : "Run it again" });
      again.addEventListener("click", retry);
      actions.append(again);
      if (error.kind === "slow") actions.append(el("a", { class: "ghost", href: "/guide#audit", text: "How to link a folder" }));
    }
    $("desk-error").hidden = false;
    if (punch) punch.set("error");
    announce(`The audit stopped. ${error.message}`);
  }

  // ------------------------------------------------------------------ model-review consent
  function consentState(state, text) {
    const box = $("consent-box"), check = $("consent");
    box.dataset.state = state;
    check.disabled = state === "unavailable" || state === "used_up";
    if (check.disabled) check.checked = false;
    $("consent-status").textContent = text;
  }

  function describeAllowance(allowance, limits) {
    if (!allowance) return "Available. Each connection has a small hourly allowance of model reviews.";
    if (allowance.used_up) {
      const when = allowance.resets_at ? ` They reset at ${localTime(allowance.resets_at)}.` : "";
      const whose = { client_hour: "This connection has used its model reviews for this hour.",
        hour: "The demo has used its model reviews for this hour.", day: "The demo has reached today's model-review ceiling.",
        daily_cost: "The demo has reached today's model-review limit." }[allowance.reason]
        || "The model-review allowance is used up for now.";
      return `${whose}${when} Audits run on the rules meanwhile.`;
    }
    const per = limits && limits.per_client_per_hour;
    const left = allowance.left_this_hour;
    return left === null || left === undefined ? "Available." : `Available: ${left}${per ? ` of ${per}` : ""} model ${left === 1 ? "review" : "reviews"} left for you this hour.`;
  }

  function applyConfig(cfg) {
    config = cfg;
    const review = cfg && cfg.model_review;
    if (!review) { consentState("unknown", "Availability could not be checked. If the model review cannot run, the audit says so and uses the rules."); return; }
    if (!review.available) {
      consentState("unavailable", review.configured
        ? "Unavailable here: no durable allowance store is configured, so the audit runs on the rules only."
        : "Not enabled on this deployment, so the audit runs on Touchmark's rules only.");
      return;
    }
    const allowance = cfg.allowance;
    consentState(allowance && allowance.used_up ? "used_up" : "available", describeAllowance(allowance, review.limits));
  }

  function noteAllowance(ai) {
    if (!config || !config.model_review || !config.model_review.available) return;
    if (ai.allowance) { config.allowance = ai.allowance; applyConfig(config); }
    else if (ai.review === "rate_limited") { config.allowance = { used_up: true, reason: ai.limit || "", resets_at: "" }; applyConfig(config); }
  }

  // ------------------------------------------------------------------ .tmark
  const rules = () => window.TmarkRules;
  let liveTimer = null;

  function chip(state, text) { const c = $("tmark-chip"); c.dataset.state = state; c.textContent = text; }

  function problems(list, { server } = {}) {
    const box = $("tmark-result"); box.textContent = "";
    list.slice(0, 20).forEach((e) => {
      const where = server ? (e.line ? `line ${e.line}` : "file") : "";
      const parts = [where ? el("span", { class: "p-line", text: where }) : null,
        el("code", { class: "p-field", text: server ? e.field : e.path }), el("span", { class: "p-msg", text: server ? e.message : e.msg })];
      if (server && e.line) {
        // Jump to the line in the editor.
        const jump = el("button", { type: "button", class: "p-jump", title: `Go to line ${e.line}` }, ...parts);
        jump.addEventListener("click", () => goToLine(e.line));
        box.append(el("li", {}, jump));
      } else box.append(el("li", {}, ...parts));
    });
  }
  function goToLine(line) {
    const area = $("tmark");
    const rows = area.value.split("\n");
    const start = rows.slice(0, line - 1).reduce((n, row) => n + row.length + 1, 0);
    area.focus();
    area.setSelectionRange(start, start + (rows[line - 1] || "").length);
    const lh = parseFloat(getComputedStyle(area).lineHeight) || 19;
    area.scrollTop = Math.max(0, (line - 3) * lh);
  }
  function notes(lines, cls = "ok") {
    const box = $("tmark-result"); box.textContent = "";
    lines.forEach((line) => box.append(el("li", { class: cls }, el("span", { class: "p-msg", text: line }))));
  }

  /** Validate as the visitor types, with the same rules the server uses (tmark-builder.js). */
  function liveCheck() {
    const text = $("tmark").value;
    if (!text.trim()) { chip("none", "none"); $("tmark-live").textContent = "Paste a file, upload one, or draft one from the repository."; $("tmark-result").textContent = ""; return; }
    if (!rules()) { chip("unchecked", "pasted"); $("tmark-live").textContent = "Checked by Touchmark when the audit starts."; return; }
    const { obj, errors } = rules().check(text);
    if (errors.length) {
      chip("bad", plural(errors.length, "problem"));
      $("tmark-live").textContent = !obj ? "Not readable JSON yet." : `${plural(errors.length, "problem")} to fix before it can be used.`;
      problems(errors);
      return;
    }
    const version = obj.tmark;
    chip("ok", `valid · ${version}`);
    $("tmark-live").textContent = `Valid .tmark ${version}${obj.agent && obj.agent.name ? ` for “${obj.agent.name}”` : ""}. It will be held against the code.`;
    $("tmark-result").textContent = "";
  }
  function scheduleLive() { clearTimeout(liveTimer); liveTimer = setTimeout(liveCheck, 160); }

  async function checkTmark() {
    const text = $("tmark").value.trim();
    if (!text) { notes(["Paste a .tmark or upload the file first."], "info"); $("tmark").focus(); return; }
    const button = $("tmark-check"); button.disabled = true; button.textContent = "Checking…";
    try {
      const data = await post("/api/v1/tmark/check", { text });
      if (!data.valid) {
        chip("bad", plural((data.error_details || []).length, "problem"));
        $("tmark-live").textContent = "Touchmark says: not valid. Each problem is listed with its line.";
        problems(data.error_details || [], { server: true });
        return;
      }
      chip("ok", `valid · ${data.version}`);
      $("tmark-live").textContent = `Touchmark says: valid .tmark ${data.version}. What it declares:`;
      notes(data.summary || []);
    } catch (error) { notes([error.message], "bad"); }
    finally { button.disabled = false; button.textContent = "Check with Touchmark"; }
  }

  async function draftTmark() {
    const reference = input.value.trim();
    if (!reference) { notes(["Enter the repository link above first: the draft is made from its code."], "info"); input.focus(); return; }
    const button = $("tmark-draft"); button.disabled = true; button.textContent = "Reading the code…";
    $("tmark-live").textContent = "Reading the repository to draft a .tmark…";
    try {
      const data = await post("/api/v1/tmark/template", { reference });
      $("tmark").value = JSON.stringify(data.draft, null, 2) + "\n";
      liveCheck();
      const found = (data.tools || []).length;
      $("tmark-live").textContent = `Drafted from the code${found ? `: ${plural(found, "tool")} found` : ""}. Fill in the empty fields here or in the builder.`;
      const box = $("tmark-result");
      box.prepend(el("li", { class: "info" }, el("span", { class: "p-msg", text: data.note })));
      $("tmark-builder-link").classList.add("nudge");
    } catch (error) { notes([error.message], "bad"); $("tmark-live").textContent = "The draft could not be made."; }
    finally { button.disabled = false; button.textContent = "Draft one from this repo"; }
  }

  function handToBuilder() {
    const text = $("tmark").value;
    try {
      if (text.trim()) sessionStorage.setItem("touchmark.tmark.toBuilder", JSON.stringify({ text, reference: input.value.trim() }));
      else sessionStorage.removeItem("touchmark.tmark.toBuilder");
    } catch { /* storage off: the builder opens with its example */ }
  }

  function takeFromBuilder() {
    let handed = null;
    try { handed = JSON.parse(sessionStorage.getItem("touchmark.tmark.toAudit") || "null"); sessionStorage.removeItem("touchmark.tmark.toAudit"); } catch { handed = null; }
    if (handed && typeof handed.text === "string" && handed.text.trim()) {
      $("tmark").value = handed.text;
      if (handed.reference && !input.value) input.value = handed.reference;
      $("declare").open = true;
      liveCheck();
      $("tmark-live").textContent = `From the builder. ${$("tmark-live").textContent}`;
      return true;
    }
    return false;
  }

  // ------------------------------------------------------------------ the report
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

  function cell(id, badge, tone, lead, ...rest) {
    const body = $(id).querySelector(".read-body"); body.textContent = "";
    body.append(el("p", { class: "read-badge " + tone, text: badge }), ...[lead ? el("p", { class: "read-lead", text: lead }) : null, ...rest].filter(Boolean));
  }

  function renderTmark(t) {
    const supplied = t.source === "supplied";
    if (t.status === "valid") {
      const mism = t.mismatches || [];
      const lead = supplied
        ? (t.repository_status === "valid" ? (mism.length ? `Your pasted .tmark was used. It differs from the one the repository commits in ${plural(mism.length, "place")}:` : "Your pasted .tmark was used. It says the same as the repository's own.")
          : "Your pasted .tmark was used; the repository commits none.")
        : `The repository's .tmark${t.version ? ` (${t.version})` : ""} was read and every claim checked against the code.`;
      const list = mism.length ? el("ul", { class: "read-list" }, ...mism.slice(0, 8).map((m) => el("li", { text: m }))) : null;
      const what = (t.summary || []).length ? el("details", { class: "read-more" }, el("summary", { text: "What it declares" }),
        el("ul", { class: "read-list" }, ...t.summary.map((line) => el("li", { text: line })))) : null;
      cell("read-tmark", supplied ? "Your .tmark" : "Repository .tmark", mism.length ? "warn" : "ok", lead, list, what);
    } else if (t.status === "invalid") {
      const errs = t.errors || [];
      cell("read-tmark", supplied ? "Your .tmark: invalid" : "Repository .tmark: invalid", "bad",
        `It has ${plural(errs.length, "error")}, so nothing in it was used.`,
        el("ul", { class: "read-list" }, ...errs.slice(0, 6).map((m) => el("li", { text: m }))),
        el("p", { class: "read-fine" }, el("a", { href: "/guide/tmark#mistakes", text: "Common mistakes and fixes" })));
    } else if (t.status === "not_used") {
      cell("read-tmark", "Not used", "warn", "Your .tmark could not be checked: no source code is linked to this reference.");
    } else {
      cell("read-tmark", "No .tmark", "muted", "The repository commits no declaration, so the code was judged on what it can do in general.",
        el("p", { class: "read-fine" }, el("a", { href: "/guide/tmark", text: "Add one" }), " and the audit can hold the code to what you say it does."));
    }
  }

  function renderScope(data) {
    const scope = data.scope || {};
    const excluded = Object.entries(scope.excluded || {});
    const files = scope.files ?? data.files ?? 0;
    if (!data.source || !data.source.repository) {
      cell("read-scope", "No source", "muted", "No repository is linked to this reference, so there was no code to read.");
      return;
    }
    const lead = `${plural(files, "source file")} read${scope.complete === false ? "; some files were left out by the size budget" : ""}.`;
    const list = excluded.length
      ? el("ul", { class: "read-list" }, ...excluded.slice(0, 8).map(([path, count]) => el("li", {}, el("code", { text: path }), ` · ${plural(count, "file")} not held against the agent`)))
      : null;
    cell("read-scope", scope.complete === false ? "Partly read" : "Read in full", scope.complete === false ? "warn" : "ok", lead,
      list || el("p", { class: "read-fine", text: "Tests, examples, demos and docs are excluded: they are not the agent." }));
  }

  const REVIEW_COPY = {
    no_consent: ["Rules only", "muted", "You did not tick the model review, so the source stayed on this server and only the deterministic rules ran."],
    rate_limited: ["Rules only", "warn", "The model-review allowance is used up for now, so this audit used the rules."],
    store_unavailable: ["Rules only", "warn", "The allowance could not be checked, so Touchmark played safe: no source was sent and the rules ran."],
    not_configured: ["Rules only", "muted", "This deployment has no allowance store for the model review, so it is off."],
    off: ["Rules only", "muted", "The model review is not enabled on this deployment."],
    no_source: ["Not applicable", "muted", "No source code is linked to this reference."],
    capped: ["Stopped at a spend cap", "warn", "The review reached a spend cap before it read every file. Its findings are kept, and each unread file is listed with the cap that stopped it. Nothing stops a review on time."],
    timeout: ["Stopped at the time limit", "warn", "A local run's time limit stopped the review. Findings so far are kept, and the report says what was not read."],
    skipped: ["Skipped", "warn", "No time was left after the rules for the model review."],
    unavailable: ["Provider error", "bad", "The model provider did not answer; the rules still ran."],
    incomplete: ["Incomplete", "warn", "Not every file that holds authority was read."],
  };

  const UNREAD_WHY = {
    token_cap: "stopped at the per-audit token cap", cost_cap: "stopped at the per-audit cost cap",
    file_cap: "beyond the per-audit file cap", daily_cost_cap: "stopped at the demo's daily limit",
    daily_budget: "stopped at the daily token budget",
    daily_budget_unavailable: "the daily budget could not be checked", not_opened: "the model did not open it when asked",
    provider_unavailable: "the model provider stopped answering", model_declined: "the model declined to continue",
    turn_limit: "a pass reached its turn limit", time_limit: "a local run's time limit",
  };

  function renderReview(ai, decision) {
    const v = ai.verification || {};
    const rest = [];
    if (ai.review === "completed" || ai.files_total) {
      rest.push(el("p", { class: "read-fine", text: `Read ${ai.files_read || 0} of ${plural(ai.files_total || 0, "file")}; added ${plural(ai.findings_added || 0, "finding")}.` }));
      if (v.checked) rest.push(el("p", { class: "read-fine", text: `Verifier re-checked ${v.checked}: ${v.confirmed || 0} confirmed, ${v.partial || 0} partly, ${v.refuted || 0} disputed.` }));
    }
    const unread = ai.not_reviewed || [];
    if (unread.length) {
      const count = ai.not_reviewed_count || unread.length;
      const list = el("ul", { class: "read-list" }, ...unread.slice(0, 60).map((f) => el("li", {}, el("code", { text: f.path }), ` · ${UNREAD_WHY[f.reason] || f.reason}`)));
      const more = count > 60 ? el("p", { class: "read-fine", text: `${count - 60} more in the report JSON (deep_review.coverage.not_reviewed).` }) : null;
      rest.push(el("details", { class: "read-more" }, el("summary", { text: `Not reviewed: ${plural(count, "file")}` }), list, more));
    }
    if (ai.allowance && !ai.allowance.used_up && ai.allowance.left_this_hour !== null && ai.allowance.left_this_hour !== undefined) rest.push(el("p", { class: "read-fine", text: `${plural(ai.allowance.left_this_hour, "model review")} left for you this hour.` }));
    if (ai.review === "rate_limited" && ai.note) rest.push(el("p", { class: "read-fine", text: ai.note }));
    if (ai.review === "rate_limited" && ai.allowance && ai.allowance.used_up && ai.allowance.resets_at) rest.push(el("p", { class: "read-fine", text: `Model reviews are available again at ${localTime(ai.allowance.resets_at)}.` }));
    if (ai.review !== "completed" && decision !== "needs_fixes" && ai.review !== "no_source") rest.push(el("p", { class: "read-fine", text: "Without a completed model review an audit can reach needs evidence at best; it cannot pass or be stamped." }));
    if (ai.review === "completed") {
      const all = ai.files_total && ai.files_read >= ai.files_total;
      cell("read-ai", "Completed", "ok", `A model read ${all ? "every source file of the agent" : "the agent's authority code"}, and a second call re-checked each of its findings at the cited line.`, ...rest);
      return;
    }
    const [badge, tone, lead] = REVIEW_COPY[ai.review] || [ai.review || "Unknown", "muted", ai.note || ""];
    cell("read-ai", badge, tone, lead, ...rest);
  }

  function render(data) {
    current = data;
    Object.assign($("result").dataset, { reference: data.reference || "", repository: (data.source || {}).repository || "", decision: data.decision || "" }); // read by studio-cta.js
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
    decision.textContent = DECISION_WORDS[data.decision] || data.decision;
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
    $("counts").textContent = `${plural(data.files || 0, "file")} analysed · ${plural(c.risks || 0, "risk")} (${c.critical || 0} critical, ${c.high || 0} high) · ${plural(c.gaps || 0, "evidence gap")}`;

    renderTmark(data.tmark || {});
    renderScope(data);
    renderReview(data.ai || {}, data.decision);

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
    $("cred-idle").hidden = false;
    inlineError("cred-error", "");
    const issuance = data.issuance || {};
    const issue = $("issue");
    issue.hidden = !issuance.ticket;
    issue.disabled = false;
    const ownerNote = issuance.owner
      ? ` The repository names ${issuance.owner.slice(0, 6)}…${issuance.owner.slice(-4)} as owner: sign the registration with that account in Freighter and the credential is issued to it.`
      : (data.ownership && data.ownership.error)
        ? ` The ownership file was found but ${data.ownership.error}; the credential would go to the demo operator.`
        : " No owner is named, so it is issued to the demo operator (ownership not verified). Add owner.stellar_account to the repository's .tmark to receive it yourself.";
    $("cred-note").textContent = issuance.ticket
      ? "This report passed. The validator writes its hash and score to the Touchmark registry, and the credential contract issues a non-transferable token bound to it: the touchmark." + ownerNote
      : issuance.reason || (issuance.enabled ? "" : "Credential issuance is not configured on this deployment.");
    $("issue").textContent = issuance.owner ? "Sign with Freighter and issue to my account" : "Stamp it on Stellar testnet";
    $("diff").hidden = true; inlineError("diff-error", "");
  }

  // ------------------------------------------------------------------ the audit
  let running = false;
  let activeJob = null;
  let controller = null;

  /** Drive a job to its end: open each next leg as soon as the last one says continue, wait
   *  when another request holds it, and ride out a dropped connection (the job is saved). */
  async function drive(first) {
    let outcome = null, drops = 0, attempt = first;
    for (;;) {
      try {
        outcome = await attempt();
        drops = 0;
      } catch (error) {
        const transient = (error.kind === "server" || error.kind === "network") && error.status !== 422 && error.status !== 410;
        if (!transient || !activeJob || ++drops > 6) throw error;
        outcome = { kind: "busy", event: { retry_after: Math.min(30, 3 * drops) } };
        desk.waiting = "The connection dropped. The audit is saved at the server; reconnecting…";
        tick();
      }
      if (outcome.kind === "result") { dropJob(); activeJob = null; return outcome.data; }
      if (outcome.kind === "cancelled") { dropJob(); activeJob = null; throw cancelled(); }
      if (!activeJob) throw failure(502);
      const wait = Math.max(0, Number(outcome.event.retry_after) || 0);
      if (outcome.kind === "busy" && !desk.waiting) desk.waiting = "Another request is advancing this audit (another tab, or one that just ended). Waiting for it…";
      if (outcome.kind === "continue") desk.waiting = "Continuing in a fresh request…";
      tick();
      if (wait) await sleep(wait * 1000, controller.signal);
      const id = activeJob.job_id;
      attempt = () => streamLeg("/api/v1/demo/audit/continue", { job_id: id }, onEvent, controller.signal);
    }
  }

  async function follow(reference, consent, first) {
    running = true;
    controller = new AbortController();
    $("error").hidden = true;
    $("result").hidden = true;
    run.disabled = true; run.setAttribute("aria-busy", "true");
    openDesk(reference, consent);
    scrollTo($("desk"), "nearest");
    try {
      const data = await drive(first);
      closeDesk(data);
      noteAllowance(data.ai || {});
      render(data);
      scrollTo($("result"));
    } catch (error) {
      if (error.kind === "aborted") return; // Cancel: the desk already says so
      if (error.kind === "cancelled") { cancelledDesk(); return; }
      if (error.kind === "expired") dropJob();
      if (error.kind === "tmark") {
        $("declare").open = true;
        chip("bad", plural(error.tmarkErrors.length, "problem"));
        $("tmark-live").textContent = "Touchmark says: not valid, so nothing was audited. Each problem is listed with its line.";
        problems(error.tmarkErrors, { server: true });
      }
      if (error.kind !== "server" && error.kind !== "network") { dropJob(); activeJob = null; }
      failDesk(error, () => (activeJob ? resume(activeJob) : audit(reference)));
    } finally {
      running = false;
      run.disabled = false; run.removeAttribute("aria-busy");
    }
  }

  async function audit(reference) {
    if (running) return;
    const consent = $("consent").checked && !$("consent").disabled;
    const body = { reference, model_review_consent: consent };
    const declared = $("tmark").value.trim();
    if (declared) body.tmark = declared;
    dropJob(); activeJob = null;
    await follow(reference, consent, () => streamLeg("/api/v1/demo/audit", body, onEvent, controller.signal));
  }

  /** A returning visitor (reload, back) sees the audit they started carry on. */
  async function resume(job) {
    if (running || !job || !job.job_id) return;
    activeJob = job;
    if (job.reference) input.value = job.reference;
    await follow(job.reference || "", !!job.consent, () => streamLeg("/api/v1/demo/audit/continue", { job_id: job.job_id }, onEvent, controller.signal));
  }

  async function cancelAudit() {
    const job = activeJob;
    $("desk-cancel").disabled = true;
    if (controller) controller.abort();
    dropJob(); activeJob = null;
    cancelledDesk();
    if (job) {
      try { await post("/api/v1/demo/audit/cancel", { job_id: job.job_id }); }
      catch { $("desk-wait").textContent = "Cancelled here. The server could not be told; the audit stops after its current request anyway."; }
    }
  }

  async function issueCredential() {
    if (!current || !current.issuance || !current.issuance.ticket) return;
    const button = $("issue");
    button.disabled = true;
    button.textContent = "Writing to Stellar testnet…";
    inlineError("cred-error", "");
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
      if (punch) punch.flash("success", 2400, { tone: "risk" });
    } catch (error) {
      button.disabled = false;
      button.textContent = current.issuance.owner ? "Sign with Freighter and issue to my account" : "Stamp it on Stellar testnet";
      inlineError("cred-error", error.message);
    }
  }

  async function recheck(event) {
    event.preventDefault();
    if (!current) return;
    const button = $("run-recheck"); button.disabled = true; button.textContent = "Testing both versions…";
    inlineError("diff-error", "");
    try {
      const data = await post("/api/v1/demo/compare", { before: current.reference, after: $("fixed").value.trim() });
      const c = data.comparison;
      const sign = c.score_change >= 0 ? "+" : "";
      const head = $("diff-head"); head.textContent = "";
      head.append(data.mode === "rules_only" ? el("span", { class: "badge", text: "Rules only" }) : null,
        el("span", { text: `${DECISION_WORDS[c.before.decision] || c.before.decision} ${c.before.score} → ${DECISION_WORDS[c.after.decision] || c.after.decision} ${c.after.score} (${sign}${c.score_change})` }));
      $("diff-note").textContent = data.note || "";
      for (const [id, list] of [["diff-closed", c.closed], ["diff-remaining", c.remaining], ["diff-introduced", c.introduced]]) {
        const ul = $(id); ul.textContent = "";
        if (!list.length) ul.append(el("li", { class: "low" }, el("span", { class: "title", text: "None" })));
        list.forEach((f) => ul.append(el("li", { class: f.severity }, el("span", { class: "sev", text: f.severity }), el("span", { class: "title", text: f.title || f.id }))));
      }
      $("diff").hidden = false;
    } catch (error) {
      inlineError("diff-error", error.message);
    } finally {
      button.disabled = false; button.innerHTML = 'Compare <span aria-hidden="true">→</span>';
    }
  }

  function save(blob, name) {
    const link = el("a", { href: URL.createObjectURL(blob), download: name });
    document.body.append(link); link.click(); link.remove();
  }

  // ------------------------------------------------------------------ wiring
  form.addEventListener("submit", (event) => { event.preventDefault(); const value = input.value.trim(); if (value) audit(value); });
  document.querySelectorAll(".examples button").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.ref; audit(b.dataset.ref); }));
  $("recheck").addEventListener("submit", recheck);
  $("tmark").addEventListener("input", scheduleLive);
  $("tmark-check").addEventListener("click", checkTmark);
  $("tmark-draft").addEventListener("click", draftTmark);
  $("tmark-builder-link").addEventListener("click", handToBuilder);
  $("tmark-clear").addEventListener("click", () => { $("tmark").value = ""; liveCheck(); $("tmark").focus(); });
  $("tmark-file").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = "";
    if (file.size > 64000) { notes(["The file is larger than 64 KB, the .tmark limit."], "bad"); return; }
    $("tmark").value = await file.text();
    liveCheck();
  });
  $("issue").addEventListener("click", issueCredential);
  $("desk-cancel").addEventListener("click", cancelAudit);
  $("download").addEventListener("click", () => {
    if (!current) return;
    save(new Blob([current.report_json], { type: "application/json" }), `touchmark-${current.report_sha256.slice(0, 12)}.json`);
  });

  // Consent is needed only where the model review can run; say so when it cannot.
  fetch("/api/v1/demo/config").then((r) => r.ok ? r.json() : null).then(applyConfig).catch(() => applyConfig(null));

  const fromBuilder = takeFromBuilder();
  if (location.hash === "#declare" || fromBuilder) {
    $("declare").open = true;
    requestAnimationFrame(() => scrollTo($("declare"), "center"));
  }
  const preset = new URLSearchParams(location.search).get("ref");
  const unfinished = loadJob();
  if (preset) { input.value = preset; audit(preset); }
  else if (unfinished && unfinished.job_id) resume(unfinished);
})();
