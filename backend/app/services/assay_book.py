"""The assay book: every audit the demo runs is entered on Stellar testnet, and a report is
released for a testnet payment that anyone can trace.

An entry is a small canonical JSON record of one audit: what was audited (repository, commit,
folder), the decision, the score, the finding counts, whether the model review completed, and
the SHA-256 of the full report. The entry's SHA-256 is written to Stellar testnet as the
MEMO_HASH of a transaction from the demo operator account (a bump-sequence operation, which
changes nothing else). So for every entry:

    sha256(entry JSON) == memo of the stamp transaction      (the audit happened, then)
    entry.report_sha256 == sha256(report JSON)                (this is the report it produced)

A report is released for a payment of ``price`` XLM on testnet to the same account, with the
text memo ``tm:<first 20 hex of the entry hash>``. The payment is read back from Horizon, never
taken from the client. Once it is found, the operator sends the payer a receipt stamp: a
payment of one stroop whose MEMO_HASH is the entry hash. The payer's own account history then
shows both sides: their payment for the entry and the stamp that answers it.

Records are kept in the deployment's private Vercel Blob store (process memory where none is
configured). Each is written once and never changed; the stamp and payment facts are in the
object names, so the book's statistics come from two listings. Every figure the book shows
links to the transaction that proves it.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

import httpx

HORIZON = "https://horizon-testnet.stellar.org"
PASSPHRASE = "Test SDF Network ; September 2015"
EXPLORER = "https://stellar.expert/explorer/testnet"
SCHEMA = "touchmark.assay-entry.v1"
ENTRIES = "assay/entries/"
BY_ENTRY = "assay/by-entry/"
REPORTS = "assay/reports/"
PAID = "assay/paid/"
CLAIMS = "assay/claims/"
RECEIPT_AMOUNT = "0.0000001"
DECISIONS = ("pass", "needs_fixes", "needs_evidence")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CACHE: dict = {}
_CACHE_SECONDS = 45


class BookError(ValueError):
    """A request the book refuses, with a message safe to show."""


# ------------------------------------------------------------------ storage
class MemoryBook:
    """Process memory, for tests and a long-lived local server."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def put_new(self, path: str, data: bytes) -> bool:
        if path in self.objects:
            return False
        self.objects[path] = data
        return True

    async def listing(self, prefix: str) -> dict[str, str]:
        return {p: p for p in sorted(self.objects) if p.startswith(prefix)}

    async def read(self, url: str) -> bytes | None:
        return self.objects.get(url)


_memory = MemoryBook()


def store_from_settings(settings):
    token = getattr(settings, "blob_read_write_token", "")
    if token:
        from .rate_limit import BlobStore
        return BlobStore(token)
    import os
    return None if os.environ.get("VERCEL") == "1" else _memory


# ------------------------------------------------------------------ entries
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_for(out: dict, report: dict, *, audited_at: int | None = None) -> dict:
    """The entry for one finished demo audit (``out`` is run_demo_audit's result)."""
    source = out.get("source") or {}
    counts = out.get("counts") or {}
    review = (report.get("deep_review") or {})
    return {
        "schema": SCHEMA,
        "reference": out.get("reference", ""),
        "repository": source.get("repository", ""),
        "revision": source.get("revision", ""),
        "path": source.get("path", ""),
        "decision": out.get("decision", ""),
        "score": out.get("score"),
        "report_sha256": out.get("report_sha256", ""),
        "findings": {k: int(counts.get(k, 0) or 0) for k in ("critical", "high", "medium", "low", "risks", "gaps")},
        "files": int(out.get("files") or 0),
        "model_review": review.get("status") == "completed",
        "model": review.get("model", "") if review.get("status") == "completed" else "",
        "audited_at": int(audited_at if audited_at is not None else time.time()),
    }


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(canonical(entry)).hexdigest()


def memo_code(entry_sha: str) -> str:
    """The text memo a payment for this entry carries (28 bytes at most on Stellar)."""
    return "tm:" + entry_sha[:20]


def _agent_key(entry: dict) -> str:
    who = entry.get("repository") or entry.get("reference") or ""
    return hashlib.sha256(f"{who.lower()}|{entry.get('path', '')}".encode()).hexdigest()[:10]


def _entry_path(entry: dict, sha: str, stamp_tx: str) -> str:
    f = entry["findings"]
    score = entry.get("score")
    score_s = "na" if score is None else f"{float(score):.1f}"
    decision = entry["decision"] if entry["decision"] in DECISIONS else "other"
    return (f"{ENTRIES}{entry['audited_at']:010d}_{sha}_{decision}_{score_s}_{f['critical']}_{f['high']}_"
            f"{f['medium']}_{int(entry['model_review'])}_{_agent_key(entry)}_{stamp_tx}.json")


def parse_entry_path(path: str) -> dict | None:
    """Inverse of _entry_path. The decision itself may contain one underscore (needs_fixes)."""
    name = path.rsplit("/", 1)[-1].removesuffix(".json")
    parts = name.split("_")
    if len(parts) == 11:  # needs_fixes / needs_evidence
        parts = parts[:2] + [parts[2] + "_" + parts[3]] + parts[4:]
    if len(parts) != 10 or not _HEX64.match(parts[1]):
        return None
    ts, sha, decision, score, crit, high, medium, reviewed, agent, tx = parts
    try:
        return {"audited_at": int(ts), "entry_sha256": sha, "decision": decision,
                "score": None if score == "na" else float(score), "critical": int(crit), "high": int(high),
                "medium": int(medium), "model_review": reviewed == "1", "agent": agent, "stamp_tx": tx}
    except ValueError:
        return None


def _paid_path(sha: str, payment_tx: str, payer: str, amount: str, receipt_tx: str) -> str:
    return f"{PAID}{sha}_{payment_tx}_{payer}_{amount}_{receipt_tx or 'none'}_{int(time.time()):010d}.json"


def parse_paid_path(path: str) -> dict | None:
    parts = path.rsplit("/", 1)[-1].removesuffix(".json").split("_")
    if len(parts) != 6 or not _HEX64.match(parts[0]):
        return None
    sha, payment_tx, payer, amount, receipt, ts = parts
    return {"entry_sha256": sha, "payment_tx": payment_tx, "payer": payer, "amount": amount,
            "receipt_tx": "" if receipt == "none" else receipt, "paid_at": int(ts) if ts.isdigit() else 0}


# ------------------------------------------------------------------ Stellar
@dataclass
class Operator:
    secret: str

    @property
    def keypair(self):
        from stellar_sdk import Keypair
        return Keypair.from_secret(self.secret)

    @property
    def public_key(self) -> str:
        return self.keypair.public_key


def operator() -> Operator | None:
    from .demo_flow import _operator_secret
    secret = _operator_secret()
    return Operator(secret) if secret else None


def tx_url(tx: str) -> str:
    return f"{EXPLORER}/tx/{tx}"


def account_url(account: str) -> str:
    return f"{EXPLORER}/account/{account}"


async def _sequence(client: httpx.AsyncClient, account: str) -> int:
    r = await client.get(f"{HORIZON}/accounts/{account}")
    if r.status_code == 404:
        raise BookError("This account does not exist on Stellar testnet yet. Fund it with Friendbot first.")
    r.raise_for_status()
    return int(r.json()["sequence"])


async def _post_tx(client: httpx.AsyncClient, xdr_b64: str) -> dict:
    r = await client.post(f"{HORIZON}/transactions", data={"tx": xdr_b64})
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code == 200:
        return body
    codes = ((body.get("extras") or {}).get("result_codes") or {})
    raise _Rejected(codes.get("transaction", f"http_{r.status_code}"), codes.get("operations") or [])


class _Rejected(RuntimeError):
    def __init__(self, code: str, ops: list) -> None:
        super().__init__(code)
        self.code, self.ops = code, ops


async def submit_from_operator(op: Operator, memo_hash: str, *, pay_to: str = "",
                               client: httpx.AsyncClient | None = None) -> str:
    """Submit a stamp from the operator account and return its hash. With ``pay_to`` the stamp
    is a one-stroop payment to that account, otherwise a bump-sequence operation that changes
    nothing. The operator also signs Soroban calls, so a stale sequence is retried."""
    from stellar_sdk import Account, Asset, TransactionBuilder
    own = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        last = None
        for attempt in range(4):
            seq = await _sequence(client, op.public_key)
            builder = TransactionBuilder(Account(op.public_key, seq), PASSPHRASE, base_fee=1000)
            builder.add_hash_memo(bytes.fromhex(memo_hash)).set_timeout(120)
            if pay_to:
                builder.append_payment_op(pay_to, Asset.native(), RECEIPT_AMOUNT)
            else:
                builder.append_bump_sequence_op(0)
            tx = builder.build()
            tx.sign(op.keypair)
            try:
                return (await _post_tx(client, tx.to_xdr()))["hash"]
            except _Rejected as exc:
                last = exc
                if exc.code != "tx_bad_seq":
                    break
                await asyncio.sleep(0.6 * (attempt + 1))
        raise BookError(f"Stellar testnet refused the stamp ({last.code if last else 'unknown'}).")
    finally:
        if own:
            await client.aclose()


# ------------------------------------------------------------------ stamping
async def stamp(out: dict, report: dict, report_json: str, settings, *, store=None, op: Operator | None = None,
                client: httpx.AsyncClient | None = None, now: int | None = None) -> dict:
    """Enter one finished audit in the book. Never raises: an audit is never lost because the
    book could not be written; the result says what happened."""
    store = store if store is not None else store_from_settings(settings)
    op = op if op is not None else operator()
    if store is None or op is None:
        return {"status": "off", "reason": "The assay book is not configured on this deployment."}
    try:
        entry = entry_for(out, report, audited_at=now)
        sha = entry_hash(entry)
        report_bytes = report_json.encode() if isinstance(report_json, str) else report_json
        if hashlib.sha256(report_bytes).hexdigest() != entry["report_sha256"]:
            return {"status": "failed", "reason": "The report bytes do not match their hash; nothing was stamped."}
        await store.put_new(f"{REPORTS}{entry['report_sha256']}.json", report_bytes)
        stamp_tx = await submit_from_operator(op, sha, client=client)
        record = {"entry": entry, "entry_sha256": sha, "stamp_tx": stamp_tx, "account": op.public_key}
        await store.put_new(f"{BY_ENTRY}{sha}.json", canonical(record))
        await store.put_new(_entry_path(entry, sha, stamp_tx), b"")
        _CACHE.clear()
        return _public(record, settings)
    except BookError as exc:
        return {"status": "failed", "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - the audit result must still be returned
        return {"status": "failed", "reason": f"The stamp could not be written ({type(exc).__name__})."}


def price_xlm(settings) -> str:
    raw = str(getattr(settings, "assay_price_xlm", "") or "2")
    try:
        value = Decimal(raw)
    except InvalidOperation:
        value = Decimal(2)
    return format(value.normalize(), "f") if value > 0 else "2"


def _public(record: dict, settings) -> dict:
    sha = record["entry_sha256"]
    return {"status": "stamped", "entry_sha256": sha, "entry": record["entry"],
            "stamp_tx": record["stamp_tx"], "stamp_url": tx_url(record["stamp_tx"]),
            "account": record["account"], "account_url": account_url(record["account"]),
            "payment": {"price_xlm": price_xlm(settings), "destination": record["account"], "memo": memo_code(sha)},
            "entry_url": f"/api/v1/assay/entry/{sha}", "report_url": f"/report/{sha}"}


async def load_entry(store, sha: str) -> dict | None:
    if not _HEX64.match(sha or ""):
        return None
    listing = await store.listing(f"{BY_ENTRY}{sha}.json")
    url = listing.get(f"{BY_ENTRY}{sha}.json")
    data = await store.read(url) if url else None
    return json.loads(data) if data else None


async def load_report(store, report_sha: str) -> bytes | None:
    listing = await store.listing(f"{REPORTS}{report_sha}.json")
    url = listing.get(f"{REPORTS}{report_sha}.json")
    return await store.read(url) if url else None


async def paid_record(store, sha: str) -> dict | None:
    for path in (await store.listing(f"{PAID}{sha}_")):
        parsed = parse_paid_path(path)
        if parsed:
            return parsed
    return None


# ------------------------------------------------------------------ payment
def _payment_ok(op: dict, destination: str, price: Decimal) -> bool:
    return (op.get("type") == "payment" and op.get("to") == destination and op.get("asset_type") == "native"
            and op.get("transaction_successful", True) is not False and Decimal(op.get("amount", "0")) >= price)


async def find_payment(destination: str, code: str, price: Decimal, *, tx_hash: str = "",
                       client: httpx.AsyncClient) -> dict | None:
    """The first successful native payment of at least ``price`` to ``destination`` whose
    transaction carries the text memo ``code``, read from Horizon."""
    if tx_hash:
        r = await client.get(f"{HORIZON}/transactions/{tx_hash}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        tx = r.json()
        if not tx.get("successful") or tx.get("memo_type") != "text" or tx.get("memo") != code:
            return None
        ops = (await client.get(f"{HORIZON}/transactions/{tx_hash}/operations", params={"limit": 50})).json()
        for op in ops.get("_embedded", {}).get("records", []):
            if _payment_ok(op, destination, price):
                return {"payment_tx": tx_hash, "payer": op["from"], "amount": op["amount"]}
        return None
    r = await client.get(f"{HORIZON}/accounts/{destination}/payments",
                         params={"order": "desc", "limit": 200, "join": "transactions"})
    r.raise_for_status()
    for op in r.json().get("_embedded", {}).get("records", []):
        tx = op.get("transaction") or {}
        if tx.get("memo_type") == "text" and tx.get("memo") == code and tx.get("successful") \
                and _payment_ok(op, destination, price):
            return {"payment_tx": op["transaction_hash"], "payer": op["from"], "amount": op["amount"]}
    return None


async def claim(sha: str, settings, *, tx_hash: str = "", store=None, op: Operator | None = None,
                client: httpx.AsyncClient | None = None) -> dict:
    """Release the report for an entry once its payment is on the ledger, and send the payer the
    receipt stamp. Idempotent: a paid entry answers with its existing record."""
    store = store if store is not None else store_from_settings(settings)
    op = op if op is not None else operator()
    if store is None or op is None:
        raise BookError("The assay book is not configured on this deployment.")
    if not _HEX64.match(sha or ""):
        raise BookError("Not an entry id.")
    if tx_hash and not _HEX64.match(tx_hash):
        raise BookError("Not a transaction hash.")
    record = await load_entry(store, sha)
    if record is None:
        raise BookError("No such entry in the assay book.")
    existing = await paid_record(store, sha)
    if existing:
        return _released(sha, existing)
    own = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        price = Decimal(price_xlm(settings))
        found = await find_payment(record["account"], memo_code(sha), price, tx_hash=tx_hash, client=client)
        if not found:
            return {"paid": False, "entry_sha256": sha,
                    "message": f"No payment of {price_xlm(settings)} XLM with memo {memo_code(sha)} has reached "
                               f"{record['account'][:6]}…{record['account'][-4:]} yet. Testnet usually confirms "
                               "within ten seconds; check again."}
        if not await store.put_new(f"{CLAIMS}{sha}.json", canonical(found)):
            # Another request is releasing this entry at this moment: it sends the one receipt stamp.
            for _ in range(12):
                await asyncio.sleep(1)
                existing = await paid_record(store, sha)
                if existing:
                    return _released(sha, existing)
            # That request stopped before recording the payment: record it, without a second receipt.
            receipt = ""
        else:
            try:
                receipt = await submit_from_operator(op, sha, pay_to=found["payer"], client=client)
            except BookError:
                receipt = ""  # the payment stands; the receipt stamp can be missing, never the report
        if not await paid_record(store, sha):
            await store.put_new(_paid_path(sha, found["payment_tx"], found["payer"], found["amount"], receipt), b"")
        _CACHE.clear()
        return _released(sha, (await paid_record(store, sha)) or {**found, "receipt_tx": receipt})
    finally:
        if own:
            await client.aclose()


def _released(sha: str, paid: dict) -> dict:
    return {"paid": True, "entry_sha256": sha, "payer": paid["payer"], "amount": paid["amount"],
            "payment_tx": paid["payment_tx"], "payment_url": tx_url(paid["payment_tx"]),
            "receipt_tx": paid.get("receipt_tx", ""),
            "receipt_url": tx_url(paid["receipt_tx"]) if paid.get("receipt_tx") else "",
            "report_url": f"/report/{sha}"}


async def prepare_payment(sha: str, payer: str, settings, *, store=None,
                          client: httpx.AsyncClient | None = None) -> dict:
    """An unsigned payment for the payer's wallet to sign (Freighter)."""
    from stellar_sdk import Account, Asset, StrKey, TransactionBuilder
    store = store if store is not None else store_from_settings(settings)
    if store is None:
        raise BookError("The assay book is not configured on this deployment.")
    if not StrKey.is_valid_ed25519_public_key(payer or ""):
        raise BookError("Use a Stellar testnet G-address.")
    record = await load_entry(store, sha)
    if record is None:
        raise BookError("No such entry in the assay book.")
    own = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        seq = await _sequence(client, payer)
    finally:
        if own:
            await client.aclose()
    tx = (TransactionBuilder(Account(payer, seq), PASSPHRASE, base_fee=1000)
          .add_text_memo(memo_code(sha))
          .append_payment_op(record["account"], Asset.native(), price_xlm(settings))
          .set_timeout(600).build())
    return {"unsigned_xdr": tx.to_xdr(), "network_passphrase": PASSPHRASE, "destination": record["account"],
            "amount": price_xlm(settings), "memo": memo_code(sha)}


async def submit_payment(sha: str, signed_xdr: str, settings, *, store=None,
                         client: httpx.AsyncClient | None = None) -> str:
    """Relay a payer-signed payment to Horizon, only when it is exactly a payment for this entry."""
    from stellar_sdk import TransactionEnvelope
    from stellar_sdk.operation import Payment
    store = store if store is not None else store_from_settings(settings)
    if store is None:
        raise BookError("The assay book is not configured on this deployment.")
    record = await load_entry(store, sha)
    if record is None:
        raise BookError("No such entry in the assay book.")
    try:
        env = TransactionEnvelope.from_xdr(signed_xdr, PASSPHRASE)
    except Exception as exc:  # noqa: BLE001
        raise BookError("That is not a signed testnet transaction.") from exc
    tx = env.transaction
    ops = tx.operations
    memo = getattr(tx.memo, "memo_text", b"")
    memo = memo.decode() if isinstance(memo, bytes) else memo
    if (len(ops) != 1 or not isinstance(ops[0], Payment) or ops[0].destination.account_id != record["account"]
            or not ops[0].asset.is_native() or Decimal(ops[0].amount) < Decimal(price_xlm(settings))
            or memo != memo_code(sha) or not env.signatures):
        raise BookError("This transaction is not the payment for this entry.")
    own = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        try:
            return (await _post_tx(client, signed_xdr))["hash"]
        except _Rejected as exc:
            hint = " The account has too little testnet XLM; fund it with Friendbot." if "op_underfunded" in exc.ops else ""
            raise BookError(f"Stellar testnet refused the payment ({exc.code}).{hint}") from exc
    finally:
        if own:
            await client.aclose()


# ------------------------------------------------------------------ the book
async def book(settings, *, store=None, op: Operator | None = None, latest: int = 25) -> dict:
    """Statistics over every entry, and the latest entries with their transactions."""
    store = store if store is not None else store_from_settings(settings)
    op = op if op is not None else operator()
    if store is None or op is None:
        return {"enabled": False}
    key = id(store)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < _CACHE_SECONDS:
        return hit[1]
    entries = [e for e in (parse_entry_path(p) for p in await store.listing(ENTRIES)) if e]
    paid = {p["entry_sha256"]: p for p in (parse_paid_path(x) for x in await store.listing(PAID)) if p}
    entries.sort(key=lambda e: e["audited_at"], reverse=True)
    scores = [e["score"] for e in entries if e["score"] is not None]
    decisions = {d: sum(1 for e in entries if e["decision"] == d) for d in DECISIONS}
    xlm = sum((Decimal(p["amount"]) for p in paid.values()), Decimal(0))
    stats = {
        "entries": len(entries),
        "model_reviewed": sum(1 for e in entries if e["model_review"]),
        "agents": len({e["agent"] for e in entries}),
        "decisions": decisions,
        "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        "critical": sum(e["critical"] for e in entries),
        "high": sum(e["high"] for e in entries),
        "medium": sum(e["medium"] for e in entries),
        "paid_reports": len(paid),
        "payers": len({p["payer"] for p in paid.values()}),
        "xlm_received": format(xlm.normalize(), "f") if xlm else "0",
        "first_at": entries[-1]["audited_at"] if entries else None,
        "last_at": entries[0]["audited_at"] if entries else None,
    }
    rows = []
    for e in entries[:latest]:
        record = await load_entry(store, e["entry_sha256"]) or {}
        entry = record.get("entry") or {}
        p = paid.get(e["entry_sha256"])
        rows.append({**e, "stamp_url": tx_url(e["stamp_tx"]),
                     "repository": entry.get("repository", ""), "revision": entry.get("revision", ""),
                     "path": entry.get("path", ""), "reference": entry.get("reference", ""),
                     "paid": bool(p), "payment_url": tx_url(p["payment_tx"]) if p else "",
                     "receipt_url": tx_url(p["receipt_tx"]) if p and p.get("receipt_tx") else ""})
    out = {"enabled": True, "account": op.public_key, "account_url": account_url(op.public_key),
           "network": "testnet", "price_xlm": price_xlm(settings), "stats": stats, "latest": rows,
           "generated_at": int(time.time())}
    _CACHE[key] = (time.time(), out)
    return out
