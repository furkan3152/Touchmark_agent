"""The assay book: every demo audit stamped on Stellar testnet, and a report released for a
testnet payment read back from Horizon. Horizon is simulated; the transactions are real XDR."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from stellar_sdk import Account, Asset, Keypair, TransactionBuilder, TransactionEnvelope

from backend.app import api
from backend.app.config import Settings
from backend.app.services import assay_book as ab
from backend.app.services import assay_render

OPERATOR = Keypair.random()
PAYER = Keypair.random()
SETTINGS = Settings(enable_assay_book=True, assay_price_xlm="2")


def run(coro):
    return asyncio.run(coro)


class Horizon:
    """Accounts, submitted transactions and payments, as Horizon answers them."""

    def __init__(self) -> None:
        self.sequences = {OPERATOR.public_key: 100, PAYER.public_key: 500}
        self.submitted: list[TransactionEnvelope] = []
        self.payments: list[dict] = []
        self.bad_seq_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/accounts/") and path.endswith("/payments"):
            return httpx.Response(200, json={"_embedded": {"records": self.payments}})
        if path.startswith("/accounts/"):
            account = path.split("/")[2]
            if account not in self.sequences:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"sequence": str(self.sequences[account])})
        if path == "/transactions" and request.method == "POST":
            xdr = dict(httpx.QueryParams(request.content.decode()))["tx"]
            env = TransactionEnvelope.from_xdr(xdr, ab.PASSPHRASE)
            if self.bad_seq_once:
                self.bad_seq_once = False
                return httpx.Response(400, json={"extras": {"result_codes": {"transaction": "tx_bad_seq"}}})
            self.submitted.append(env)
            source = env.transaction.source.account_id
            self.sequences[source] += 1
            digest = env.hash_hex()
            op = env.transaction.operations[0]
            if getattr(op, "destination", None) is not None and source == PAYER.public_key:
                memo = env.transaction.memo.memo_text.decode()
                self.payments.insert(0, {"type": "payment", "from": source, "to": op.destination.account_id,
                                         "asset_type": "native", "amount": f"{Decimal(op.amount):.7f}",
                                         "transaction_hash": digest,
                                         "transaction": {"memo_type": "text", "memo": memo, "successful": True}})
            return httpx.Response(200, json={"hash": digest})
        if path.startswith("/transactions/") and path.endswith("/operations"):
            digest = path.split("/")[2]
            return httpx.Response(200, json={"_embedded": {"records": [p for p in self.payments if p["transaction_hash"] == digest]}})
        if path.startswith("/transactions/"):
            digest = path.split("/")[2]
            for p in self.payments:
                if p["transaction_hash"] == digest:
                    return httpx.Response(200, json={"successful": True, **p["transaction"]})
            return httpx.Response(404, json={})
        return httpx.Response(404, json={})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def audited(decision="needs_fixes", score=58.3, *, review=True):
    report = {"findings": [{"id": "f1", "kind": "risk", "severity": "high", "title": "Signs whatever the request says",
                            "evidence": "tx.sign(AGENT_SECRET)", "verification": {"verdict": "confirmed", "file": "pay.ts", "line": 41}},
                           {"id": "g1", "kind": "evidence_gap", "severity": "low", "title": "<script>gap</script>"}],
              "deep_review": {"status": "completed" if review else "skipped", "model": "m"}}
    report_json = json.dumps(report)
    out = {"reference": "https://github.com/o/agent", "decision": decision, "score": score,
           "source": {"repository": "https://github.com/o/agent", "revision": "a" * 40, "path": "bot"},
           "report_sha256": hashlib.sha256(report_json.encode()).hexdigest(),
           "counts": {"risks": 1, "gaps": 1, "high": 1}, "files": 4}
    return out, report, report_json


def stamped(horizon, store, **kw):
    out, report, report_json = audited(**kw)
    async def go():
        async with horizon.client() as client:
            return await ab.stamp(out, report, report_json, SETTINGS, store=store, op=ab.Operator(OPERATOR.secret),
                                  client=client)
    return run(go())


def pay(horizon, entry, *, amount="2", memo=None, destination=None):
    seq = horizon.sequences[PAYER.public_key]
    tx = (TransactionBuilder(Account(PAYER.public_key, seq), ab.PASSPHRASE, base_fee=100)
          .add_text_memo(memo or ab.memo_code(entry))
          .append_payment_op(destination or OPERATOR.public_key, Asset.native(), amount).set_timeout(60).build())
    tx.sign(PAYER)
    return tx.to_xdr()


# ------------------------------------------------------------------ entries
def test_the_stamp_memo_is_the_entry_hash_and_the_entry_binds_the_report():
    horizon, store = Horizon(), ab.MemoryBook()
    result = stamped(horizon, store)
    assert result["status"] == "stamped"
    env = horizon.submitted[-1]
    assert env.transaction.memo.memo_hash.hex() == result["entry_sha256"] == ab.entry_hash(result["entry"])
    assert type(env.transaction.operations[0]).__name__ == "BumpSequence"
    assert env.transaction.source.account_id == OPERATOR.public_key
    stored = run(ab.load_report(store, result["entry"]["report_sha256"]))
    assert hashlib.sha256(stored).hexdigest() == result["entry"]["report_sha256"]
    assert result["payment"] == {"price_xlm": "2", "destination": OPERATOR.public_key,
                                 "memo": "tm:" + result["entry_sha256"][:20]}
    assert len(result["payment"]["memo"].encode()) <= 28


def test_a_stale_sequence_is_retried():
    horizon, store = Horizon(), ab.MemoryBook()
    horizon.bad_seq_once = True
    assert stamped(horizon, store)["status"] == "stamped"


def test_report_bytes_that_do_not_match_their_hash_are_never_stamped():
    horizon, store = Horizon(), ab.MemoryBook()
    out, report, _ = audited()
    async def go():
        async with horizon.client() as client:
            return await ab.stamp(out, report, "{}", SETTINGS, store=store, op=ab.Operator(OPERATOR.secret), client=client)
    assert run(go())["status"] == "failed"
    assert not horizon.submitted


def test_without_an_operator_key_the_book_is_off_and_the_audit_unaffected(monkeypatch):
    monkeypatch.setattr(ab, "operator", lambda: None)
    out, report, report_json = audited()
    assert run(ab.stamp(out, report, report_json, SETTINGS, store=ab.MemoryBook()))["status"] == "off"


@pytest.mark.parametrize("decision", ["pass", "needs_fixes", "needs_evidence"])
def test_entry_names_round_trip(decision):
    out, report, _ = audited(decision=decision)
    entry = ab.entry_for(out, report, audited_at=1_800_000_000)
    sha, tx = ab.entry_hash(entry), "b" * 64
    parsed = ab.parse_entry_path(ab._entry_path(entry, sha, tx))
    assert parsed["decision"] == decision and parsed["entry_sha256"] == sha and parsed["stamp_tx"] == tx
    assert parsed["score"] == 58.3 and parsed["high"] == 1 and parsed["model_review"] is True


# ------------------------------------------------------------------ payment
def test_payment_releases_the_report_and_sends_a_receipt_stamp():
    horizon, store = Horizon(), ab.MemoryBook()
    sha = stamped(horizon, store)["entry_sha256"]
    op = ab.Operator(OPERATOR.secret)

    async def go():
        async with horizon.client() as client:
            before = await ab.claim(sha, SETTINGS, store=store, op=op, client=client)
            prepared = await ab.prepare_payment(sha, PAYER.public_key, SETTINGS, store=store, client=client)
            env = TransactionEnvelope.from_xdr(prepared["unsigned_xdr"], ab.PASSPHRASE)
            env.sign(PAYER)
            digest = await ab.submit_payment(sha, env.to_xdr(), SETTINGS, store=store, client=client)
            after = await ab.claim(sha, SETTINGS, tx_hash=digest, store=store, op=op, client=client)
            again = await ab.claim(sha, SETTINGS, store=store, op=op, client=client)
            return before, digest, after, again

    before, digest, after, again = run(go())
    assert before["paid"] is False and "tm:" in before["message"]
    assert after["paid"] and after["payer"] == PAYER.public_key and after["payment_tx"] == digest
    receipt = horizon.submitted[-1]
    assert receipt.transaction.operations[0].destination.account_id == PAYER.public_key
    assert receipt.transaction.memo.memo_hash.hex() == sha
    assert after["receipt_tx"] == receipt.hash_hex()
    assert again["payment_tx"] == digest and len(horizon.submitted) == 3  # stamp, payment, receipt: no second receipt


def test_a_payment_sent_from_any_wallet_is_found_by_its_memo():
    horizon, store = Horizon(), ab.MemoryBook()
    sha = stamped(horizon, store)["entry_sha256"]
    async def go():
        async with horizon.client() as client:
            await ab._post_tx(client, pay(horizon, sha))
            return await ab.claim(sha, SETTINGS, store=store, op=ab.Operator(OPERATOR.secret), client=client)
    assert run(go())["paid"] is True


@pytest.mark.parametrize("kw", [{"amount": "1.9999999"}, {"memo": "tm:0000000000000000000"}])
def test_too_little_or_the_wrong_memo_releases_nothing(kw):
    horizon, store = Horizon(), ab.MemoryBook()
    sha = stamped(horizon, store)["entry_sha256"]
    async def go():
        async with horizon.client() as client:
            await ab._post_tx(client, pay(horizon, sha, **kw))
            return await ab.claim(sha, SETTINGS, store=store, op=ab.Operator(OPERATOR.secret), client=client)
    assert run(go())["paid"] is False
    assert not run(ab.paid_record(store, sha))


@pytest.mark.parametrize("kw", [{"destination": Keypair.random().public_key}, {"memo": "tm:other"}, {"amount": "1"}])
def test_the_relay_submits_only_the_payment_for_this_entry(kw):
    horizon, store = Horizon(), ab.MemoryBook()
    sha = stamped(horizon, store)["entry_sha256"]
    with pytest.raises(ab.BookError):
        run(ab.submit_payment(sha, pay(horizon, sha, **kw), SETTINGS, store=store))
    assert len(horizon.submitted) == 1


def test_the_book_counts_what_the_ledger_shows():
    horizon, store = Horizon(), ab.MemoryBook()
    first = stamped(horizon, store)["entry_sha256"]
    stamped(horizon, store, decision="pass", score=90.0)
    async def go():
        async with horizon.client() as client:
            await ab._post_tx(client, pay(horizon, first, amount="3"))
            await ab.claim(first, SETTINGS, store=store, op=ab.Operator(OPERATOR.secret), client=client)
        return await ab.book(SETTINGS, store=store, op=ab.Operator(OPERATOR.secret))
    book = run(go())
    s = book["stats"]
    assert s["entries"] == 2 and s["decisions"] == {"pass": 1, "needs_fixes": 1, "needs_evidence": 0}
    assert s["paid_reports"] == 1 and s["xlm_received"] == "3" and s["payers"] == 1 and s["agents"] == 1
    assert s["average_score"] == round((58.3 + 90.0) / 2, 1)
    assert all(row["stamp_url"].endswith(row["stamp_tx"]) for row in book["latest"])


# ------------------------------------------------------------------ pages and routes
def test_the_report_page_escapes_and_the_locked_page_shows_how_to_pay():
    horizon, store = Horizon(), ab.MemoryBook()
    result = stamped(horizon, store)
    record = run(ab.load_entry(store, result["entry_sha256"]))
    locked = assay_render.locked_page(record, "2")
    assert result["payment"]["memo"] in locked and OPERATOR.public_key in locked and "pay.ts" not in locked
    data = run(ab.load_report(store, result["entry"]["report_sha256"]))
    page = assay_render.report_page(record, data, {"payer": PAYER.public_key, "amount": "2.0000000",
                                                   "payment_tx": "c" * 64, "receipt_tx": "d" * 64})
    assert "pay.ts:41" in page and "&lt;script&gt;gap&lt;/script&gt;" in page and "<script>gap" not in page
    assert result["entry_sha256"] in page and "d" * 10 in page


def test_routes_are_closed_when_the_book_is_off_and_public_on_the_vercel_surface():
    client = TestClient(api.app, client=("192.0.2.91", 50000))
    assert client.get("/api/v1/assay/book").json() == {"enabled": False}
    assert client.get("/api/v1/assay/entry/" + "a" * 64).status_code == 404
    assert client.post("/api/v1/assay/claim", json={"entry": "nothex"}).status_code == 422
    assert client.get("/report/" + "a" * 64).status_code == 404
    # The serverless entry point's public surface allows the book, the report pages and its API.
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "app.py").read_text()
    assert '"/book"' in source and '"/report/"' in source and '"/api/v1/assay/"' in source


def test_the_docs_page_is_served_and_public():
    client = TestClient(api.app, client=("192.0.2.91", 50000))
    page = client.get("/docs")
    assert page.status_code == 200 and "Touchmark <em>documentation</em>" in page.text
    for anchor in ("overview", "api", "stream", "verify", "credential", "self-host"):
        assert f'id="{anchor}"' in page.text and f'href="#{anchor}"' in page.text
    from pathlib import Path
    assert '"/docs"' in (Path(__file__).resolve().parents[2] / "app.py").read_text()


def test_two_claims_at_once_send_one_receipt_and_record_one_payment():
    horizon, store = Horizon(), ab.MemoryBook()
    sha = stamped(horizon, store)["entry_sha256"]
    op = ab.Operator(OPERATOR.secret)

    async def go():
        async with horizon.client() as client:
            await ab._post_tx(client, pay(horizon, sha))
            first, second = await asyncio.gather(ab.claim(sha, SETTINGS, store=store, op=op, client=client),
                                                 ab.claim(sha, SETTINGS, store=store, op=op, client=client))
            return first, second, await store.listing(ab.PAID)

    first, second, paid = run(go())
    assert first["paid"] and second["paid"] and first["payment_tx"] == second["payment_tx"]
    receipts = [e for e in horizon.submitted if e.transaction.source.account_id == OPERATOR.public_key
                and getattr(e.transaction.operations[0], "destination", None) is not None]
    assert len(receipts) == 1 and len(paid) == 1


def test_horizon_not_answering_is_a_503_that_says_so(monkeypatch):
    store = ab.MemoryBook()
    sha = stamped(Horizon(), store)["entry_sha256"]
    monkeypatch.setattr(api.settings, "enable_assay_book", True)
    monkeypatch.setattr(ab, "store_from_settings", lambda _settings: store)
    monkeypatch.setattr(ab, "operator", lambda: ab.Operator(OPERATOR.secret))

    async def down(*_args, **_kwargs):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(ab, "find_payment", down)
    answer = TestClient(api.app, client=("192.0.2.91", 50000)).post("/api/v1/assay/claim", json={"entry": sha})
    assert answer.status_code == 503 and "did not answer" in answer.json()["detail"]
    assert "no route" not in answer.text


def _verifier():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "scripts/verify_assay.py"
    spec = importlib.util.spec_from_file_location("verify_assay", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ledger_world(monkeypatch, *, site_hides=False, site_stats=None):
    """A book account with two stamps, one paid; the site and Horizon as the verifier reads them."""
    v = _verifier()
    book, payer = OPERATOR.public_key, PAYER.public_key
    e1, e2 = "a" * 64, "b" * 64
    b64 = lambda hexs: base64.b64encode(bytes.fromhex(hexs)).decode()  # noqa: E731
    ops = [
        {"type": "bump_sequence", "transaction_hash": "1" * 64, "paging_token": "1",
         "transaction": {"source_account": book, "memo_type": "hash", "memo": b64(e1), "successful": True}},
        {"type": "bump_sequence", "transaction_hash": "2" * 64, "paging_token": "2",
         "transaction": {"source_account": book, "memo_type": "hash", "memo": b64(e2), "successful": True}},
        {"type": "payment", "from": payer, "to": book, "asset_type": "native", "amount": "2.0000000",
         "transaction_hash": "3" * 64, "paging_token": "3",
         "transaction": {"source_account": payer, "memo_type": "text", "memo": "tm:" + e1[:20], "successful": True}},
        {"type": "payment", "from": book, "to": payer, "asset_type": "native", "amount": "0.0000001",
         "transaction_hash": "4" * 64, "paging_token": "4",
         "transaction": {"source_account": book, "memo_type": "hash", "memo": b64(e1), "successful": True}},
    ]

    def get_json(url):
        if "/operations" in url:
            return 200, {"_embedded": {"records": ops}}
        for e, tx in ((e1, "1" * 64), (e2, "2" * 64)):
            if url.endswith(f"/api/v1/assay/entry/{e}"):
                return (404, None) if (site_hides and e == e2) else (200, {"stamp_tx": tx})
        return 404, None
    monkeypatch.setattr(v, "get_json", get_json)
    stats = site_stats or {"entries": 2, "paid_reports": 1, "xlm_received": "2"}
    return v.ledger_audit("https://site", "https://horizon", book, stats, "2")


def test_the_book_counted_from_the_ledger_agrees_with_the_site(monkeypatch):
    out = _ledger_world(monkeypatch)
    assert out["ok"] and out["stamps"] == 2 and out["paid_entries"] == 1 and out["xlm_for_reports"] == "2"


@pytest.mark.parametrize("kw", [{"site_hides": True},
                                {"site_stats": {"entries": 3, "paid_reports": 1, "xlm_received": "2"}},
                                {"site_stats": {"entries": 2, "paid_reports": 2, "xlm_received": "4"}}])
def test_a_hidden_entry_or_an_inflated_figure_fails_the_ledger_check(monkeypatch, kw):
    assert not _ledger_world(monkeypatch, **kw)["ok"]


def test_archived_envelopes_verify_offline_and_a_forgery_does_not(tmp_path):
    v = _verifier()
    tx = (TransactionBuilder(Account(OPERATOR.public_key, 7), ab.PASSPHRASE, base_fee=100)
          .add_hash_memo(bytes.fromhex("c" * 64)).append_bump_sequence_op(0).set_timeout(60).build())
    tx.sign(OPERATOR)
    good = {"hash": tx.hash_hex(), "envelope_xdr": tx.to_xdr(), "ledger": 1, "created_at": "now"}
    path = tmp_path / "proof.json"
    path.write_text(json.dumps({"results": [{"archive": [good]}]}))
    assert v.verify_archive(str(path)) == 0
    # Signed by someone else, or a hash that is not this envelope's: both fail.
    other = (TransactionBuilder(Account(OPERATOR.public_key, 7), ab.PASSPHRASE, base_fee=100)
             .add_hash_memo(bytes.fromhex("c" * 64)).append_bump_sequence_op(0).set_timeout(60).build())
    other.sign(PAYER)
    for forged in ({**good, "hash": "d" * 64}, {**good, "envelope_xdr": other.to_xdr(), "hash": other.hash_hex()}):
        path.write_text(json.dumps({"results": [{"archive": [forged]}]}))
        assert v.verify_archive(str(path)) == 1
