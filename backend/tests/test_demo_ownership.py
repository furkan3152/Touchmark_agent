"""Owner-bound credentials: the repository names the owner, and only that owner's own
signed registration of this exact agent is accepted."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from stellar_sdk import Account, Keypair, Network, TransactionBuilder, scval

from backend.app.services import demo_flow
from backend.app.services.repo_audit import ownership_claim, select_repository

REGISTRY = "CBIZOECNI22Y6RXANQWS7SYL2QGV2ZX2QZ4CS3GOOETFJ66SIN6YJZ6W"
OWNER = Keypair.random()
TICKET = {"report_sha256": "b" * 64, "score": 99, "repository": "https://github.com/o/r", "revision": "a" * 40,
          "owner": OWNER.public_key}


def test_ownership_file_is_read_from_the_audited_commit(tmp_path):
    (tmp_path / "agent.py").write_text("def run():\n    return 1\n")
    (tmp_path / "agentveritas.json").write_text(json.dumps({"stellar_owner": OWNER.public_key}))
    _, selection = select_repository(tmp_path)
    assert ownership_claim(selection["ownership"]) == {"path": "agentveritas.json", "stellar_owner": OWNER.public_key}
    assert "error" in ownership_claim({"path": "agentveritas.json", "text": '{"stellar_owner": "GBAD"}'})
    assert ownership_claim({}) == {}


@pytest.fixture
def chain(monkeypatch):
    fake = SimpleNamespace(registry=REGISTRY, passphrase=Network.TESTNET_NETWORK_PASSPHRASE)
    args = [scval.to_address(OWNER.public_key), scval.to_bytes(b"\x01" * 32), scval.to_string("https://github.com/o/r"),
            scval.to_bytes(b"\x02" * 32), scval.to_bytes(b"\x03" * 32), scval.to_uint32(1)]
    monkeypatch.setattr(demo_flow, "_registration", lambda c, t: ("reg_agent", 1, args))
    return fake, args


def envelope(signer, args, *, source=None, fn="reg_agent"):
    account = Account(source or OWNER.public_key, 1)
    tx = (TransactionBuilder(account, Network.TESTNET_NETWORK_PASSPHRASE, base_fee=100)
          .append_invoke_contract_function_op(contract_id=REGISTRY, function_name=fn, parameters=args)
          .set_timeout(300).build())
    tx.sign(signer)
    return tx.to_xdr()


def test_the_owners_own_registration_is_accepted(chain):
    fake, args = chain
    assert len(demo_flow._check_owner_signature(fake, TICKET, envelope(OWNER, args))) == 64


def test_someone_elses_signature_or_registration_is_refused(chain):
    fake, args = chain
    other = Keypair.random()
    with pytest.raises(demo_flow.DemoError, match="did not sign"):
        demo_flow._check_owner_signature(fake, TICKET, envelope(other, args))
    with pytest.raises(demo_flow.DemoError, match="owner account"):
        demo_flow._check_owner_signature(fake, TICKET, envelope(other, args, source=other.public_key))
    changed = args[:3] + [scval.to_bytes(b"\x09" * 32)] + args[4:]
    with pytest.raises(demo_flow.DemoError, match="does not register this agent"):
        demo_flow._check_owner_signature(fake, TICKET, envelope(OWNER, changed))
    with pytest.raises(demo_flow.DemoError, match="does not register"):
        demo_flow._check_owner_signature(fake, TICKET, envelope(OWNER, args, fn="upd_agent"))


def test_owner_claim_reaches_the_ticket(monkeypatch):
    monkeypatch.setenv("DEMO_OPERATOR_SECRET", Keypair.random().secret)
    monkeypatch.setattr(demo_flow, "manifest", lambda: {"contracts": {"credential": {"id": "C" + "A" * 55}}})
    report = {"result": {"overall_score": 99.6}, "findings": [], "deep_review": {"status": "completed"},
              "repository": {"ownership_claim": {"path": "agentveritas.json", "stellar_owner": OWNER.public_key}},
              "resolution": {"source": {"repository": "https://github.com/o/r", "revision": "a" * 40}, "steps": []}}

    async def fake(*a, **k):
        return {"decision": "pass", "report": report, "report_json": "{}", "report_sha256": "b" * 64}
    monkeypatch.setattr(demo_flow, "audit_reference", fake)
    import asyncio
    from backend.app.config import Settings
    out = asyncio.run(demo_flow.run_demo_audit("https://github.com/o/r", Settings(_env_file=None)))
    assert out["issuance"]["owner"] == OWNER.public_key
    assert demo_flow._verify(out["issuance"]["ticket"])["owner"] == OWNER.public_key
