#!/usr/bin/env python3
"""Verify assay-book entries from public data only: the site's public API and a Horizon server.

    python3 scripts/verify_assay.py <entry> [<entry> ...] [--site URL] [--horizon URL] [--json]
    python3 scripts/verify_assay.py --latest 10

For each entry it checks, without trusting the server's word for anything it can recompute:

  1. sha256(canonical JSON of the entry) is the entry id;
  2. the stamp transaction exists, is successful, comes from the book account, and its memo
     (MEMO_HASH) is the entry id; its ledger time is reported;
  3. for a paid entry: the payment transaction is a successful native payment of at least the
     price to the book account with the text memo tm:<first 20 hex of the entry>, the receipt
     transaction sends that payer one stroop from the book account with the entry id as memo,
     and the released report's bytes hash to the entry's report_sha256.

Standard library only. Exits 1 if any check fails.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from decimal import Decimal

UA = {"User-Agent": "touchmark-verify/1", "Accept": "application/json"}


def get(url: str):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def get_json(url: str):
    status, body = get(url)
    return status, (json.loads(body) if body and body.strip()[:1] in (b"{", b"[") else None)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def memo_hex(tx: dict) -> str:
    return base64.b64decode(tx["memo"]).hex() if tx.get("memo_type") == "hash" else ""


def verify(entry: str, site: str, horizon: str, row: dict | None, price: str) -> dict:
    out = {"entry": entry, "checks": [], "ok": True}

    def check(name: str, passed: bool, detail: str = ""):
        out["checks"].append({"check": name, "ok": bool(passed), "detail": detail})
        out["ok"] = out["ok"] and bool(passed)

    status, rec = get_json(f"{site}/api/v1/assay/entry/{entry}")
    if status != 200 or not rec:
        check("entry is published", False, f"HTTP {status}")
        return out
    e = rec["entry"]
    out.update(agent=(e.get("repository") or e.get("reference", "")) + (f"/{e['path']}" if e.get("path") else ""),
               commit=e.get("revision", ""), decision=e.get("decision"), score=e.get("score"),
               findings=e.get("findings"), model_review=e.get("model_review"), account=rec["account"])
    check("sha256(canonical entry) == entry id", hashlib.sha256(canonical(e)).hexdigest() == entry)

    status, stamp = get_json(f"{horizon}/transactions/{rec['stamp_tx']}")
    ok = status == 200 and stamp and stamp.get("successful")
    check("stamp transaction on the ledger and successful", ok, rec["stamp_tx"])
    if ok:
        check("stamp memo == entry id", memo_hex(stamp) == entry)
        check("stamp sent by the book account", stamp["source_account"] == rec["account"], stamp["source_account"])
        out["stamped_at"] = stamp["created_at"]
        out["stamp_tx"] = rec["stamp_tx"]

    if not rec.get("paid"):
        out["paid"] = False
        return out
    out["paid"] = True
    pay_tx = (row or {}).get("payment_url", "").rsplit("/", 1)[-1]
    receipt_tx = (row or {}).get("receipt_url", "").rsplit("/", 1)[-1]
    if pay_tx:
        status, tx = get_json(f"{horizon}/transactions/{pay_tx}")
        _, ops = get_json(f"{horizon}/transactions/{pay_tx}/operations")
        pay = next((o for o in (ops or {}).get("_embedded", {}).get("records", []) if o.get("type") == "payment"), {})
        check("payment successful", status == 200 and tx and tx.get("successful"), pay_tx)
        check("payment memo == tm:<entry[:20]>", tx and tx.get("memo_type") == "text" and tx.get("memo") == "tm:" + entry[:20])
        check("payment to the book account, native, at least the price",
              pay.get("to") == rec["account"] and pay.get("asset_type") == "native" and Decimal(pay.get("amount", "0")) >= Decimal(price),
              f"{pay.get('amount')} XLM from {pay.get('from')}")
        out.update(payment_tx=pay_tx, payer=pay.get("from"), amount=pay.get("amount"))
        if receipt_tx:
            status, rtx = get_json(f"{horizon}/transactions/{receipt_tx}")
            _, rops = get_json(f"{horizon}/transactions/{receipt_tx}/operations")
            rop = next((o for o in (rops or {}).get("_embedded", {}).get("records", []) if o.get("type") == "payment"), {})
            check("receipt from the book account to the payer, memo == entry id",
                  status == 200 and rtx and rtx.get("successful") and memo_hex(rtx) == entry
                  and rop.get("from") == rec["account"] and rop.get("to") == pay.get("from"), receipt_tx)
            out["receipt_tx"] = receipt_tx
    else:
        check("payment transaction listed in the book", False, "not among the latest rows; pass --latest N")
    status, body = get(f"{site}/api/v1/assay/report/{entry}.json")
    check("released report hashes to entry.report_sha256",
          status == 200 and hashlib.sha256(body).hexdigest() == e.get("report_sha256"), e.get("report_sha256", ""))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("entries", nargs="*")
    ap.add_argument("--latest", type=int, default=0, help="verify the latest N entries of the book")
    ap.add_argument("--site", default="https://usetouchmark.app")
    ap.add_argument("--horizon", default="https://horizon-testnet.stellar.org")
    ap.add_argument("--json", action="store_true", help="print one JSON document")
    args = ap.parse_args(argv)
    _, book = get_json(f"{args.site}/api/v1/assay/book")
    rows = {r["entry_sha256"]: r for r in (book or {}).get("latest", [])}
    entries = list(args.entries) + [r["entry_sha256"] for r in (book or {}).get("latest", [])[: args.latest]]
    results = [verify(e, args.site, args.horizon, rows.get(e), (book or {}).get("price_xlm", "2")) for e in dict.fromkeys(entries)]
    if args.json:
        print(json.dumps({"site": args.site, "horizon": args.horizon, "results": results}, indent=1))
    else:
        for r in results:
            print(f"{'OK  ' if r['ok'] else 'FAIL'} {r['entry'][:16]}… {r.get('agent', '')} {r.get('decision', '')} "
                  f"{r.get('score', '')}{'  paid' if r.get('paid') else ''}")
            for c in r["checks"]:
                print(f"     {'✓' if c['ok'] else '✗'} {c['check']}" + (f"  ({c['detail']})" if c["detail"] else ""))
    return 0 if results and all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
