"""The printed report a payer receives, and the locked page before payment (HTML, press style).

Server-rendered so the report reads without scripts; frontend/assay.js only drives the payment
on the locked page. Every value from a report or entry is escaped.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .assay_book import account_url, memo_code, tx_url

SEVERITIES = ("critical", "high", "medium", "low", "info")
WORDS = {"pass": "Pass", "needs_fixes": "Needs fixes", "needs_evidence": "Needs evidence"}
MASCOT = {"pass": "success", "needs_fixes": "warning", "needs_evidence": "warning"}


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _date(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    except (TypeError, ValueError):
        return ""


def _short(value: str, head: int = 6, tail: int = 4) -> str:
    return value if len(value) <= head + tail + 1 else f"{value[:head]}…{value[-tail:]}"


def _agent(entry: dict) -> tuple[str, str]:
    repo = entry.get("repository") or ""
    name = repo.replace("https://github.com/", "") or entry.get("reference", "")
    if entry.get("path"):
        name += "/" + entry["path"]
    href = ""
    if repo and entry.get("revision"):
        href = f"{repo}/tree/{entry['revision']}" + (f"/{entry['path']}" if entry.get("path") else "")
    return name, href


def _page(title: str, body: str, *, script: bool = False) -> str:
    scripts = '<script src="/ui/mascot.js" defer></script>'
    if script:
        scripts += '<script src="/ui/vendor/freighter-api-6.0.1.min.js" defer></script><script src="/ui/assay.js" defer></script>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title>
<link rel="icon" href="/ui/brand/mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="/ui/fonts/fonts.css"><link rel="stylesheet" href="/ui/press.css">
<link rel="stylesheet" href="/ui/mascot.css"><link rel="stylesheet" href="/ui/assay.css">
{scripts}</head>
<body class="assay-page">
<svg width="0" height="0" class="defs" aria-hidden="true"><filter id="ink"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="4"/><feDisplacementMap in="SourceGraphic" scale="2.4"/></filter></svg>
<header class="bar"><a class="brand" href="/" aria-label="Touchmark home"><img class="logo" src="/ui/brand/mark.svg" alt="" width="34" height="34"><span class="word">touchmark</span><span class="where">on Stellar</span></a>
<nav><a href="/">Test an agent</a><a href="/book">Assay book</a><a href="/guide">Guide</a><a href="https://github.com/furkan3152/Touchmark_agent" rel="noopener">GitHub</a></nav></header>
<main class="assay-main">{body}</main>
<footer class="foot">Touchmark · Stellar testnet · every entry can be checked on the ledger</footer>
</body></html>"""


def _seal(entry: dict, sha: str) -> str:
    decision = entry.get("decision", "")
    score = entry.get("score")
    f = entry.get("findings") or {}
    name, href = _agent(entry)
    agent = f'<a href="{_e(href)}" rel="noopener">{_e(name)}</a>' if href else _e(name)
    commit = _e((entry.get("revision") or "")[:10])
    review = "Model review and independent verifier" if entry.get("model_review") else "Deterministic rules only"
    return f"""
<section class="seal-sheet tone-{_e(decision)}">
  <div class="seal-copy">
    <p class="kicker"><span>Assay report</span><span>Entry {_e(sha[:8])}</span></p>
    <h1>{agent}</h1>
    <p class="seal-meta">Commit <code>{commit or '—'}</code> · {_e(_date(entry.get('audited_at')))} · {_e(review)}</p>
    <ul class="tally">
      <li class="sev-critical"><b>{int(f.get('critical', 0))}</b>critical</li>
      <li class="sev-high"><b>{int(f.get('high', 0))}</b>high</li>
      <li class="sev-medium"><b>{int(f.get('medium', 0))}</b>medium</li>
      <li><b>{int(f.get('gaps', 0))}</b>evidence gaps</li>
      <li><b>{int(entry.get('files', 0))}</b>files read</li>
    </ul>
  </div>
  <div class="seal-mark" aria-label="Decision: {_e(WORDS.get(decision, decision))}, score {_e(score)}">
    <span class="seal-ring"><span class="seal-word">{_e(WORDS.get(decision, decision))}</span><span class="seal-score">{_e('' if score is None else round(float(score)))}</span><span class="seal-of">/ 100</span></span>
    <span class="seal-punch" data-tm-mascot="{MASCOT.get(decision, 'idle')}" data-tm-size="104" data-tm-decorative></span>
  </div>
</section>"""


def _proof(record: dict, sha: str, paid: dict | None) -> str:
    entry = record["entry"]
    rows = [("Entry SHA-256", f"<code>{_e(sha)}</code>"),
            ("Report SHA-256", f"<code>{_e(entry.get('report_sha256'))}</code>"),
            ("Stamped in", f'<a href="{_e(tx_url(record["stamp_tx"]))}" rel="noopener">tx {_e(_short(record["stamp_tx"], 10, 6))}</a> · memo = entry hash'),
            ("Book account", f'<a href="{_e(account_url(record["account"]))}" rel="noopener">{_e(_short(record["account"]))}</a>')]
    if paid:
        rows.append(("Paid by", f'<a href="{_e(account_url(paid["payer"]))}" rel="noopener">{_e(_short(paid["payer"]))}</a> · '
                                f'{_e(paid["amount"])} XLM · <a href="{_e(tx_url(paid["payment_tx"]))}" rel="noopener">tx {_e(_short(paid["payment_tx"], 10, 6))}</a>'))
        if paid.get("receipt_tx"):
            rows.append(("Receipt stamp", f'<a href="{_e(tx_url(paid["receipt_tx"]))}" rel="noopener">tx {_e(_short(paid["receipt_tx"], 10, 6))}</a> · sent to the payer, memo = entry hash'))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return f"""
<section class="proof">
  <h2>Check it yourself</h2>
  <dl>{dl}</dl>
  <ol class="steps">
    <li>Download the <a href="/api/v1/assay/entry/{_e(sha)}">entry</a>. Its SHA-256 over the <code>entry</code> object (canonical JSON) is the entry hash above.</li>
    <li>Open the stamp transaction: its memo (hash) is the same 32 bytes, written {_e(_date(entry.get('audited_at')))} by the book account.</li>
    <li>{'Download the <a href="/api/v1/assay/report/' + _e(sha) + '.json">report JSON</a>: its SHA-256 is the entry&#39;s <code>report_sha256</code>.' if paid else 'The report itself is released for a testnet payment; its SHA-256 is already fixed in the entry.'}</li>
  </ol>
</section>"""


def _location(f: dict) -> str:
    v = f.get("verification") or {}
    file, line = v.get("file") or f.get("file") or "", v.get("line") or f.get("line") or ""
    return f"{file}:{line}" if file and line else file


def _finding(f: dict) -> str:
    sev = f.get("severity", "info")
    v = f.get("verification") or {}
    verdict = v.get("verdict", "")
    loc = _location(f)
    parts = [f'<li class="slip sev-{_e(sev)}"><header><span class="badge">{_e(sev)}</span><b>{_e(f.get("title", f.get("id", "")))}</b></header>']
    if loc:
        parts.append(f"<code class=\"loc\">{_e(loc)}</code>")
    if f.get("evidence"):
        parts.append(f"<p>{_e(str(f['evidence'])[:900])}</p>")
    if f.get("remediation"):
        parts.append(f"<p class=\"fix\"><span>Fix</span>{_e(str(f['remediation'])[:700])}</p>")
    if verdict:
        parts.append(f"<p class=\"verdict v-{_e(verdict)}\">Verifier: {_e(verdict)}"
                     + (f" — {_e(str(v.get('reason') or '')[:300])}" if v.get("reason") else "") + "</p>")
    parts.append("</li>")
    return "".join(parts)


def report_page(record: dict, report_bytes: bytes, paid: dict) -> str:
    sha = record["entry_sha256"]
    entry = record["entry"]
    report = json.loads(report_bytes)
    findings = report.get("findings") or []
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    risks = sorted((f for f in findings if f.get("kind", "risk") == "risk"), key=lambda f: rank.get(f.get("severity"), 9))
    gaps = [f for f in findings if f.get("kind") == "evidence_gap"]
    checks = (((report.get("deep_review") or {}).get("ledger") or {}).get("checks") or [])
    failing = [c for c in checks if c.get("verdict") == "fails"]
    holding = sum(1 for c in checks if c.get("verdict") == "holds")
    risk_html = "".join(_finding(f) for f in risks) or '<li class="slip sev-low"><header><b>No exploitable path from untrusted input to keys, payments, commands or network was found.</b></header></li>'
    gap_html = "".join(_finding(f) for f in gaps[:30])
    check_html = "".join(f'<li><b>{_e(c.get("title", c.get("id", "")))}</b>'
                         + (f' <code>{_e(c.get("file", ""))}:{_e(c.get("line", ""))}</code>' if c.get("file") else "")
                         + f'<p>{_e(str(c.get("reason") or "")[:500])}</p></li>' for c in failing)
    ledger = ""
    if checks:
        ledger = (f'<section class="sheet"><h2>Check ledger <small>{holding} hold · {len(failing)} fail · '
                  f'{len(checks) - holding - len(failing)} other</small></h2>'
                  + (f'<ul class="fails">{check_html}</ul>' if failing else '<p class="quiet">No check failed.</p>')
                  + "</section>")
    body = (_seal(entry, sha)
            + f'<section class="sheet"><h2>What can go wrong <small>{len(risks)}</small></h2><ol class="slips">{risk_html}</ol></section>'
            + ledger
            + (f'<section class="sheet"><details><summary><h2>Evidence not yet provided <small>{len(gaps)}</small></h2></summary>'
               f'<p class="quiet">What a reviewer would need to see before trusting the parts the code alone cannot show.</p>'
               f'<ol class="slips small">{gap_html}</ol></details></section>' if gaps else "")
            + _proof(record, sha, paid)
            + f'<p class="actions"><a class="button" href="/api/v1/assay/report/{_e(sha)}.json" download>Download report JSON</a>'
              f'<a class="button ghost" href="/book">See the assay book</a></p>')
    name, _ = _agent(entry)
    return _page(f"{name} · Touchmark report", body)


def locked_page(record: dict, price: str) -> str:
    sha = record["entry_sha256"]
    entry = record["entry"]
    account = record["account"]
    body = (_seal(entry, sha) + f"""
<section class="paywall" id="paywall" data-entry="{_e(sha)}" data-destination="{_e(account)}" data-amount="{_e(price)}" data-memo="{_e(memo_code(sha))}">
  <div class="ticket-copy">
    <p class="kicker"><span>Printed report</span><span>Stellar testnet</span></p>
    <h2>Take the full report for <em>{_e(price)} XLM</em></h2>
    <p>Every finding with the line it cites, what the verifier said, the check ledger and how to fix it. Pay on testnet; Punch reads your payment from the ledger, releases the report and sends a receipt stamp back to your wallet.</p>
    <div class="pay-row"><button type="button" class="pay-freighter">Pay with Freighter</button><span class="or">or send it from any testnet wallet</span></div>
    <dl class="manual">
      <dt>To</dt><dd><code id="pay-to">{_e(account)}</code><button type="button" class="copy" data-copy="{_e(account)}">Copy</button></dd>
      <dt>Amount</dt><dd><code>{_e(price)} XLM</code></dd>
      <dt>Memo (text)</dt><dd><code>{_e(memo_code(sha))}</code><button type="button" class="copy" data-copy="{_e(memo_code(sha))}">Copy</button></dd>
    </dl>
    <form class="check-row" id="check-form"><input id="check-tx" placeholder="Transaction hash (optional)" maxlength="64" aria-label="Payment transaction hash, optional"><button type="submit" class="ghost">I paid · check the ledger</button></form>
    <p class="status" id="pay-status" role="status"></p>
    <p class="quiet">No testnet XLM? <a href="https://lab.stellar.org/account/fund?$=network$id=testnet" rel="noopener">Fund an account with Friendbot</a>. Testnet XLM has no value.</p>
  </div>
</section>""" + _proof(record, sha, None))
    name, _ = _agent(entry)
    return _page(f"{name} · Touchmark report", body, script=True)


def missing_page() -> str:
    return _page("Not in the book · Touchmark",
                 '<section class="sheet"><h2>No such entry</h2><p>This entry is not in the assay book. '
                 '<a href="/book">See every entry</a>.</p></section>')
