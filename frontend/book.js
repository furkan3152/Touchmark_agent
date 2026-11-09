/* The assay book page: statistics and the latest entries, each linked to its transactions. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const WORDS = { pass: "Pass", needs_fixes: "Needs fixes", needs_evidence: "Needs evidence" };

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "text") node.textContent = v; else if (k === "class") node.className = v; else node.setAttribute(k, v);
    }
    children.flat().forEach((c) => c != null && node.append(c));
    return node;
  }
  const link = (href, text) => el("a", { href, text, target: "_blank", rel: "noopener" });
  const short = (s, a = 8, b = 4) => (s && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s || "");
  const day = (ts) => (ts ? new Date(ts * 1000).toISOString().slice(0, 10) : "–");
  function ago(ts) {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }

  /* Check one row here, in the visitor's browser: the entry's bytes are hashed with Web Crypto and
     the transactions are read from Horizon directly, so the result does not rest on this site. */
  const HORIZON = "https://horizon-testnet.stellar.org";
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const memoHex = (tx) => (tx.memo_type === "hash" ? hex(Uint8Array.from(atob(tx.memo), (c) => c.charCodeAt(0))) : "");
  const txId = (url) => url.split("/").pop();
  async function getJson(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(`${new URL(url, location.href).hostname} answered ${r.status}`);
    return r.json();
  }
  async function verifyRow(e, account) {
    const rec = await getJson(`/api/v1/assay/entry/${e.entry_sha256}`);
    const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rec.canonical))));
    if (digest !== e.entry_sha256) return "the entry does not hash to its id";
    const entry = JSON.parse(rec.canonical);
    if (entry.decision !== e.decision || entry.revision !== e.revision) return "the entry differs from this row";
    const stamp = await getJson(`${HORIZON}/transactions/${e.stamp_tx}`);
    if (!stamp.successful || stamp.source_account !== account) return "the stamp is not a successful transaction of the book account";
    if (memoHex(stamp) !== e.entry_sha256) return "the stamp's memo is not the entry hash";
    const done = ["hash", `stamp ${stamp.created_at.replace("T", " ").slice(0, 16)} UTC`];
    if (e.paid) {
      const pay = await getJson(`${HORIZON}/transactions/${txId(e.payment_url)}`);
      if (!pay.successful || pay.memo_type !== "text" || pay.memo !== "tm:" + e.entry_sha256.slice(0, 20)) return "the payment does not name this entry";
      done.push("payment");
      if (e.receipt_url) {
        const receipt = await getJson(`${HORIZON}/transactions/${txId(e.receipt_url)}`);
        if (!receipt.successful || receipt.source_account !== account || memoHex(receipt) !== e.entry_sha256) return "the receipt does not answer this entry";
        done.push("receipt");
      }
    }
    return done;
  }
  async function verifyAll(data) {
    const button = $("verify-all"), out = $("verify-result");
    button.disabled = true;
    let ok = 0, n = 0;
    for (const e of data.latest) {
      const cell = document.querySelector(`[data-check="${e.entry_sha256}"]`);
      cell.className = "check"; cell.textContent = "checking…";
      let result;
      try { result = await verifyRow(e, data.account); } catch (err) { result = err.message || "could not be read"; }
      n += 1;
      if (Array.isArray(result)) { ok += 1; cell.classList.add("ok"); cell.textContent = "✓ " + result.join(" · "); }
      else { cell.classList.add("bad"); cell.textContent = "✗ " + result; }
      out.textContent = `${ok} of ${n} rows match the ledger`;
    }
    out.textContent = `${ok} of ${n} rows match the ledger, checked in this browser against ${new URL(HORIZON).hostname}`;
    button.disabled = false;
  }

  async function load() {
    let data;
    try {
      const r = await fetch("/api/v1/assay/book", { headers: { Accept: "application/json" } });
      data = await r.json();
    } catch {
      $("rows").textContent = "";
      $("rows").append(el("tr", {}, el("td", { colspan: "6", class: "book-empty", text: "The book could not be read. Try again in a minute." })));
      return;
    }
    if (!data.enabled) { $("book").hidden = true; $("book-off").hidden = false; return; }
    const s = data.stats;
    $("c-entries").textContent = s.entries;
    $("c-agents").textContent = s.agents;
    $("c-findings").textContent = s.critical + s.high;
    $("c-paid").textContent = s.paid_reports;
    $("c-paid-label").textContent = `reports paid for · ${s.xlm_received} XLM received`;
    $("c-reviewed").textContent = s.model_reviewed;
    $("c-score").textContent = s.average_score == null ? "–" : s.average_score;
    $("c-payers").textContent = s.payers;
    $("c-since").textContent = day(s.first_at);
    $("c-since-label").textContent = s.last_at ? `first entry · latest ${ago(s.last_at)}` : "first entry";
    const acct = $("acct"); acct.href = data.account_url; acct.textContent = short(data.account, 6, 4);

    const split = $("split"), legend = $("legend");
    split.textContent = ""; legend.textContent = "";
    const total = Object.values(s.decisions).reduce((a, b) => a + b, 0) || 1;
    for (const [d, n] of Object.entries(s.decisions)) {
      if (n) split.append(el("i", { class: "s-" + d, style: `width:${(100 * n) / total}%`, title: `${WORDS[d]}: ${n}` }));
      legend.append(el("span", {}, el("i", { class: "s-" + d, style: `background:var(--${d === "pass" ? "green" : d === "needs_fixes" ? "red" : "amber"})` }), `${WORDS[d]} ${n}`));
    }

    const rows = $("rows"); rows.textContent = "";
    if (!data.latest.length) rows.append(el("tr", {}, el("td", { colspan: "6", class: "book-empty", text: "No entries yet. Audit an agent and it is entered here." })));
    data.latest.forEach((e) => {
      const name = (e.repository || e.reference || "").replace("https://github.com/", "") + (e.path ? "/" + e.path : "");
      const proof = el("td", {}, link(e.stamp_url, `stamp ${short(e.stamp_tx)}`));
      if (e.paid) {
        proof.append(el("br"), link(e.payment_url, "payment"));
        if (e.receipt_url) proof.append(" · ", link(e.receipt_url, "receipt"));
      }
      proof.append(el("div", { class: "check", "data-check": e.entry_sha256 }));
      rows.append(el("tr", {},
        el("td", { text: ago(e.audited_at), title: new Date(e.audited_at * 1000).toISOString() }),
        el("td", { class: "agent" }, name || "—", el("small", { text: `${(e.revision || "").slice(0, 10)} · entry ${e.entry_sha256.slice(0, 8)}` })),
        el("td", {}, el("span", { class: "pill " + e.decision, text: WORDS[e.decision] || e.decision }), el("div", { class: "quiet", text: e.score == null ? "" : `${Math.round(e.score)} / 100${e.model_review ? "" : " · rules"}` })),
        el("td", { text: `${e.critical} critical · ${e.high} high · ${e.medium} medium` }),
        proof,
        el("td", {}, e.paid ? el("span", { class: "pill paid", text: "Paid" }) : null, " ", el("a", { href: `/report/${e.entry_sha256}`, text: e.paid ? "Open" : "Get it" }))));
    });
    $("verify-all").hidden = !data.latest.length;
    $("verify-all").onclick = () => verifyAll(data);
  }
  document.addEventListener("DOMContentLoaded", load);
})();
