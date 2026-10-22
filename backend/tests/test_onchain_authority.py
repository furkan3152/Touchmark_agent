"""Ledger authority facts drive Stellar findings and oversight (Horizon is mocked)."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path

import httpx
import pytest

from backend.app.config import Settings
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.stellar import authority
from backend.app.stellar.authority import AuthorityReader

AGENT_ACCOUNT = "GAKSCPZBPKBGR6TTAIZGYPPTMCR4QWE5BER4MMZX5CLVA2V6XSVCBCE6"
AGENT_KEY = "GBOKJ36MRC5ZMSLUJHILYBO7VNUKLBWEZEU7OLOFGMVTAS6TFUYK4WTT"
EXCHANGE = "GDSTL33DJ5NU5IWBW2Z67IEAXRJIFLQBI3FDWYV73XEDG4JBVQBQZXSP"
MISSING = "GDJILV6PJ6WFJ4TI4M3KNBO3BHAFZEHN5CPI6LYQUCXSQ2KAQF5YZMTC"
CORPUS = json.loads((Path(__file__).parent / "fixtures" / "agent_corpus.json").read_text())


def account(address, *, agent_weight=1, med=2, high=3, memo_required=False, home_domain=""):
    return {"account_id": address, "home_domain": home_domain, "last_modified_ledger": 777,
            "thresholds": {"low_threshold": 1, "med_threshold": med, "high_threshold": high},
            "signers": [{"key": address, "weight": 2, "type": "ed25519_public_key"},
                        {"key": AGENT_KEY, "weight": agent_weight, "type": "ed25519_public_key"}],
            "flags": {}, "balances": [{"asset_type": "native", "balance": "100.0"},
                                      {"asset_type": "credit_alphanum4", "asset_code": "USDC",
                                       "asset_issuer": EXCHANGE, "limit": authority.MAX_LIMIT, "balance": "1"}],
            "data": {"config.memo_required": base64.b64encode(b"1").decode()} if memo_required else {}}


def horizon(accounts: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        address = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=accounts[address]) if address in accounts else httpx.Response(404, json={})
    return httpx.MockTransport(handler)


def collect(accounts, **kwargs):
    reader = AuthorityReader("testnet", transport=horizon(accounts))
    return asyncio.run(reader.collect(**kwargs))


def test_account_view_reports_agent_weight_against_thresholds():
    facts = collect({AGENT_ACCOUNT: account(AGENT_ACCOUNT)}, address=AGENT_ACCOUNT, agent_key=AGENT_KEY, fetch_toml=False)
    view = facts["account"]
    assert view["agent_key"] == {"key": AGENT_KEY, "weight": 1, "is_signer": True,
                                 "can_pay_alone": False, "can_administer_alone": False}
    assert view["trustlines"][0]["unlimited"] is True
    assert view["last_modified_ledger"] == 777  # part of the chain identity an audit commits to


def test_hardcoded_destination_requiring_a_memo_is_found():
    code = {"pay.py": f'EXCHANGE = "{EXCHANGE}"\nGONE = "{MISSING}"\n'}
    facts = collect({EXCHANGE: account(EXCHANGE, memo_required=True)}, code_files=code)
    by_address = {d["address"]: d for d in facts["destinations"]}
    assert by_address[EXCHANGE]["memo_required"] is True and by_address[EXCHANGE]["code_attaches_memo"] is False
    assert by_address[MISSING]["status"] == "not_found"


def run_review(monkeypatch, case, accounts, **extra):
    original = AuthorityReader.__init__

    def patched(self, network, *, transport=None, timeout=8.0):
        original(self, network, transport=horizon(accounts), timeout=timeout)
    monkeypatch.setattr(AuthorityReader, "__init__", patched)
    monkeypatch.setattr(authority, "guard_remote_url", lambda url: url)
    bundle = copy.deepcopy(CORPUS[case]["bundle"])
    bundle.update(extra)
    return asyncio.run(review_source(ReviewRequest(**bundle),
                                     Settings(_env_file=None, enable_onchain_verification=True)))


def test_cosigner_on_the_ledger_satisfies_oversight(monkeypatch):
    without = asyncio.run(review_source(ReviewRequest(**CORPUS["case-02"]["bundle"]), Settings(_env_file=None)))
    with_chain = run_review(monkeypatch, "case-02", {AGENT_ACCOUNT: account(AGENT_ACCOUNT)},
                            stellar_address=AGENT_ACCOUNT, agent_signing_key=AGENT_KEY)
    ids = {f["id"] for f in with_chain["report"]["findings"]}
    assert "stellar_native-onchain-cosigner-required" in ids
    assert "compliance-no-human-oversight" not in ids
    assert with_chain["report"]["onchain_authority"]["account"]["agent_key"]["can_pay_alone"] is False
    assert without["decision"] == with_chain["decision"] == "pass"


def test_agent_key_that_can_administer_the_account_needs_fixes(monkeypatch):
    result = run_review(monkeypatch, "C2-guarded-payments", {AGENT_ACCOUNT: account(AGENT_ACCOUNT, agent_weight=5)},
                        stellar_address=AGENT_ACCOUNT, agent_signing_key=AGENT_KEY)
    assert "stellar_native-onchain-agent-key-administers-account" in result["priority_finding_ids"]
    assert result["decision"] == "needs_fixes"


def test_memo_required_destination_without_memo_needs_fixes(monkeypatch):
    bundle = copy.deepcopy(CORPUS["C2-guarded-payments"]["bundle"])
    source = bundle["files"]["payroll.py"]
    allowlisted = source.split('ALLOWLIST = {"')[1].split('"')[0]
    bundle["files"]["payroll.py"] = source.replace(allowlisted, EXCHANGE)
    result = run_review(monkeypatch, "C2-guarded-payments", {EXCHANGE: account(EXCHANGE, memo_required=True)},
                        files=bundle["files"])
    assert any(i.startswith("stellar_native-onchain-memo-required") for i in result["priority_finding_ids"])
    assert result["decision"] == "needs_fixes"


def test_ledger_outage_never_fails_the_review(monkeypatch):
    def broken(request):
        raise httpx.ConnectError("down")
    original = AuthorityReader.__init__
    monkeypatch.setattr(AuthorityReader, "__init__",
                        lambda self, network, transport=None, timeout=8.0: original(self, network, transport=httpx.MockTransport(broken)))
    bundle = copy.deepcopy(CORPUS["C1-readonly-summarizer"]["bundle"])
    bundle["stellar_address"] = AGENT_ACCOUNT
    result = asyncio.run(review_source(ReviewRequest(**bundle), Settings(_env_file=None, enable_onchain_verification=True)))
    assert result["report"]["onchain_authority"]["account"]["status"] == "unavailable"
    assert result["decision"] == "pass"
