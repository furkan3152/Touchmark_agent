#!/usr/bin/env python3
"""Verify assay-book entries from public data only: the site's public API and a Horizon server.

    python3 scripts/verify_assay.py <entry> [<entry> ...] [--site URL] [--horizon URL] [--json]
    python3 scripts/verify_assay.py --latest 10
    python3 scripts/verify_assay.py --ledger                 # count the book from the ledger, not the site
    python3 scripts/verify_assay.py --latest 10 --json --archive > proof.json
    python3 scripts/verify_assay.py --verify-archive proof.json   # offline, needs: pip install stellar-sdk

For each entry it checks, without trusting the server's word for anything it can recompute:

  1. sha256(canonical JSON of the entry) is the entry id;
  2. the stamp transaction exists, is successful, comes from the book account, and its memo
     (MEMO_HASH) is the entry id; its ledger time is reported;
  3. for a paid entry: the payment transaction is a successful native payment of at least the
     price to the book account with the text memo tm:<first 20 hex of the entry>, the receipt
     transaction sends that payer one stroop from the book account with the entry id as memo,
     and the released report's bytes hash to the entry's report_sha256.

--ledger enumerates every stamp, receipt and incoming payment of the book account straight from
Horizon, checks that each stamped entry is published by the site with that stamp, and compares
the ledger's totals with the statistics the site shows. An entry missing from the site, or a
total that disagrees, fails.

--archive keeps each transaction as the ledger returned it (signed envelope and result XDR).
Testnet is reset from time to time; --verify-archive then still proves offline that each
envelope hashes to its transaction id and carries a valid signature of its source account.

Standard library only (except --verify-archive). Exits 1 if any check fails.
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


def archived(horizon: str, tx_hash: str) -> dict | None:
    status, tx = get_json(f"{horizon}/transactions/{tx_hash}")
    if status != 200 or not tx:
        return None
    return {k: tx.get(k) for k in ("hash", "ledger", "created_at", "source_account", "memo_type", "memo",
                                   "successful", "envelope_xdr", "result_xdr")}


def memo_hex(tx: dict) -> str:
    return base64.b64decode(tx["memo"]).hex() if tx.get("memo_type") == "hash" else ""


def verify(entry: str, site: str, horizon: str, row: dict | None, price: str, archive: bool = False) -> dict:
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

    if archive and out.get("stamp_tx"):
        out["archive"] = [a for a in [archived(horizon, out["stamp_tx"])] if a]
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
    if archive:
        out.setdefault("archive", []).extend(a for a in (archived(horizon, t) for t in (out.get("payment_tx"), out.get("receipt_tx")) if t) if a)
    status, body = get(f"{site}/api/v1/assay/report/{entry}.json")
    check("released report hashes to entry.report_sha256",
          status == 200 and hashlib.sha256(body).hexdigest() == e.get("report_sha256"), e.get("report_sha256", ""))
    return out


def ledger_audit(site: str, horizon: str, account: str, stats: dict, price: str) -> dict:
    """The book counted from the ledger: every stamp, receipt and payment of the book account."""
    stamps, receipts, payments, cursor = [], [], [], ""
    for _ in range(200):  # 200 pages of 200 operations at most
        status, page = get_json(f"{horizon}/accounts/{account}/operations?order=asc&limit=200&join=transactions"
                                + (f"&cursor={cursor}" if cursor else ""))
        records = ((page or {}).get("_embedded") or {}).get("records") or []
        for op in records:
            tx = op.get("transaction") or {}
            if not op.get("transaction_successful", tx.get("successful", True)):
                continue
            if op["type"] == "bump_sequence" and tx.get("source_account") == account and tx.get("memo_type") == "hash":
                stamps.append({"entry": memo_hex(tx), "tx": op["transaction_hash"], "at": tx.get("created_at")})
            elif op["type"] == "payment" and op.get("from") == account and tx.get("memo_type") == "hash":
                receipts.append({"entry": memo_hex(tx), "tx": op["transaction_hash"], "to": op.get("to")})
            elif (op["type"] == "payment" and op.get("to") == account and op.get("asset_type") == "native"
                  and tx.get("memo_type") == "text" and str(tx.get("memo", "")).startswith("tm:")):
                payments.append({"memo": tx["memo"], "tx": op["transaction_hash"], "from": op.get("from"),
                                 "amount": op.get("amount")})
        if len(records) < 200:
            break
        cursor = records[-1]["paging_token"]
    out = {"account": account, "checks": [], "ok": True, "stamps": len(stamps), "receipts": len(receipts),
           "payments": len(payments)}

    def check(name, passed, detail=""):
        out["checks"].append({"check": name, "ok": bool(passed), "detail": detail})
        out["ok"] = out["ok"] and bool(passed)

    missing = []
    for st in stamps:
        status, rec = get_json(f"{site}/api/v1/assay/entry/{st['entry']}")
        if status != 200 or not rec or rec.get("stamp_tx") != st["tx"]:
            missing.append(st["entry"])
    check("every stamp on the ledger is published by the site, with that stamp", not missing,
          f"{len(stamps) - len(missing)} of {len(stamps)}" + (f"; missing {', '.join(m[:12] for m in missing)}" if missing else ""))
    stamped = {st["entry"] for st in stamps}
    paid = {}
    for p in payments:  # a payment counts for the entry its memo names, once, at the price or more
        entry = next((e for e in stamped if "tm:" + e[:20] == p["memo"]), None)
        if entry and Decimal(p["amount"]) >= Decimal(price) and entry not in paid:
            paid[entry] = p
    xlm = sum((Decimal(p["amount"]) for p in paid.values()), Decimal(0))
    out.update(paid_entries=len(paid), xlm_for_reports=format(xlm.normalize(), "f") if xlm else "0",
               payers=len({p["from"] for p in paid.values()}))
    check("the site's audit count matches the ledger", stats.get("entries") == len(stamps),
          f"site {stats.get('entries')}, ledger {len(stamps)}")
    check("the site's paid-report count matches the ledger", stats.get("paid_reports") == len(paid),
          f"site {stats.get('paid_reports')}, ledger {len(paid)}")
    check("the site's XLM received matches the ledger",
          Decimal(str(stats.get("xlm_received", "0"))) == xlm, f"site {stats.get('xlm_received')}, ledger {out['xlm_for_reports']}")
    check("every paid entry has a receipt stamp to its payer",
          all(any(r["entry"] == e and r["to"] == p["from"] for r in receipts) for e, p in paid.items()),
          f"{len(receipts)} receipts")
    return out


def verify_archive(path: str, passphrase: str = "Test SDF Network ; September 2015") -> int:
    """Offline: every archived envelope hashes to its id and is signed by its source account."""
    from stellar_sdk import Keypair, TransactionEnvelope
    doc = json.loads(open(path).read())
    items = [a for r in doc.get("results", doc.get("runs", [])) for a in ((r.get("verified") or r).get("archive") or [])]
    items += [a for r in doc.get("runs", []) for a in (r.get("credential_archive") or [])]
    bad = 0
    for a in items:
        env = TransactionEnvelope.from_xdr(a["envelope_xdr"], passphrase)
        tx = env.transaction
        source = tx.source.account_id if hasattr(tx.source, "account_id") else tx.source
        key = Keypair.from_public_key(source)
        signed = any(_verifies(key, env.hash(), sig.signature) for sig in env.signatures)
        ok = env.hash_hex() == a["hash"] and signed
        bad += not ok
        print(f"{'✓' if ok else '✗'} {a['hash'][:16]}… ledger {a.get('ledger')} {a.get('created_at')} signed by {source[:6]}…{source[-4:]}")
    print(f"{len(items) - bad} of {len(items)} archived transactions verified offline")
    return 0 if items and not bad else 1


def _verifies(key, data: bytes, signature: bytes) -> bool:
    try:
        key.verify(data, signature)
        return True
    except Exception:  # noqa: BLE001 - a signature of another key, or none
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("entries", nargs="*")
    ap.add_argument("--latest", type=int, default=0, help="verify the latest N entries of the book")
    ap.add_argument("--site", default="https://usetouchmark.app")
    ap.add_argument("--horizon", default="https://horizon-testnet.stellar.org")
    ap.add_argument("--json", action="store_true", help="print one JSON document")
    ap.add_argument("--ledger", action="store_true", help="count the book from the ledger and compare with the site")
    ap.add_argument("--archive", action="store_true", help="keep each transaction's signed envelope and result")
    ap.add_argument("--verify-archive", metavar="FILE", help="offline: check the envelopes archived in FILE")
    args = ap.parse_args(argv)
    if args.verify_archive:
        return verify_archive(args.verify_archive)
    _, book = get_json(f"{args.site}/api/v1/assay/book")
    rows = {r["entry_sha256"]: r for r in (book or {}).get("latest", [])}
    entries = list(args.entries) + [r["entry_sha256"] for r in (book or {}).get("latest", [])[: args.latest]]
    results = [verify(e, args.site, args.horizon, rows.get(e), (book or {}).get("price_xlm", "2"), args.archive)
               for e in dict.fromkeys(entries)]
    ledger = (ledger_audit(args.site, args.horizon, (book or {}).get("account", ""), (book or {}).get("stats") or {},
                           (book or {}).get("price_xlm", "2")) if args.ledger else None)
    if args.json:
        print(json.dumps({"site": args.site, "horizon": args.horizon, "results": results,
                          **({"ledger": ledger} if ledger else {})}, indent=1))
    else:
        for r in results:
            print(f"{'OK  ' if r['ok'] else 'FAIL'} {r['entry'][:16]}… {r.get('agent', '')} {r.get('decision', '')} "
                  f"{r.get('score', '')}{'  paid' if r.get('paid') else ''}")
            for c in r["checks"]:
                print(f"     {'✓' if c['ok'] else '✗'} {c['check']}" + (f"  ({c['detail']})" if c["detail"] else ""))
    if ledger and not args.json:
        print(f"{'OK  ' if ledger['ok'] else 'FAIL'} the book counted from the ledger: {ledger['stamps']} stamps, "
              f"{ledger['paid_entries']} paid reports, {ledger['xlm_for_reports']} XLM, {ledger['payers']} payers")
        for c in ledger["checks"]:
            print(f"     {'✓' if c['ok'] else '✗'} {c['check']}" + (f"  ({c['detail']})" if c["detail"] else ""))
    checked = results + ([ledger] if ledger else [])
    return 0 if checked and all(r["ok"] for r in checked) else 1


if __name__ == "__main__":
    sys.exit(main())
