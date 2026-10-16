"""Exact escrow ABI, fail-closed preparation, payment separation, and local CID."""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from stellar_sdk import StrKey, scval, xdr

from backend.app.models import AuditTier
from backend.app.reporting.ipfs import IpfsPublisher, local_cid
from backend.app.services.escrow import EscrowService, ExternalSignatureRequired

CONTRACT = StrKey.encode_contract(bytes([1]) * 32)
TOKEN = StrKey.encode_contract(bytes([2]) * 32)
REQUESTER, PROVIDER, EVALUATOR = [StrKey.encode_ed25519_public_key(bytes([i]) * 32) for i in (3, 4, 5)]


def enabled(settings, **overrides):
    return settings.model_copy(update={
        "stellar_network": "testnet", "enable_audit_escrow": True,
        "audit_escrow_contract_id": CONTRACT, "sac_contract_id": TOKEN, **overrides,
    })


def opened(service, **overrides):
    values = {
        "provider": PROVIDER, "evaluator": EVALUATOR,
        "amount_atomic": 25_000_000, "deadline": 987654,
        **overrides,
    }
    return service.open("job-2", AuditTier.BASIC, REQUESTER, **values)


def test_validation_core_does_not_require_payment(settings, run):
    service = EscrowService(settings)
    record = service.open("job-1", AuditTier.DEEP, "")
    assert record.mode == "not_required"
    assert record.amount_usdc == 0
    run(service.fund(record))
    run(service.settle(record, {"auditor": 99.0}))
    assert record.funded is True
    assert record.settled is True
    assert record.platform_fee_usdc == 0
    assert record.swarm_payout_usdc == 0
    assert record.payouts == {}


def test_enabled_escrow_requires_external_signature(settings, run):
    configured = enabled(settings)
    service = EscrowService(configured)
    record = opened(service)
    assert record.mode == "prepared"
    assert record.amount_usdc == configured.price_basic_usdc
    with pytest.raises(ExternalSignatureRequired):
        run(service.fund(record))
    assert record.funded is False
    assert record.tx_hashes == {}


def test_all_prepared_calls_match_contract_abi_and_scval_types(settings, run, repo_root):
    service = EscrowService(enabled(settings))
    record = opened(service, amount_atomic=2**100 + 1)
    invocations = [json.loads(record.tx_ref)]
    with pytest.raises(ExternalSignatureRequired):
        run(service.fund(record))
    invocations.append(json.loads(record.tx_ref))
    content_hash = hashlib.sha256(b'{"audit":"published bytes"}').hexdigest()
    submitted = run(service.submit_deliverable(record, "ipfs://file", 88, provider=PROVIDER, report_hash=content_hash))
    invocations.append(json.loads(submitted))
    with pytest.raises(ExternalSignatureRequired):
        run(service.settle(record, {}, evaluator=EVALUATOR, score=88))
    invocations.append(json.loads(record.tx_ref))
    with pytest.raises(ExternalSignatureRequired):
        run(service.refund(record, "timeout"))
    invocations.append(json.loads(record.tx_ref))
    source = (repo_root / "contracts/audit-escrow/src/lib.rs").read_text()
    decoders = {"Address": lambda x: scval.from_address(x).address, "u32": scval.from_uint32,
                "i128": lambda x: str(scval.from_int128(x)), "BytesN<32>": lambda x: scval.from_bytes(x).hex()}
    for invocation in invocations:
        signature = re.search(r"pub fn " + invocation["function"] + r"\((.*?)\) ->", source, re.S).group(1)
        abi = re.findall(r"(\w+):\s*(BytesN<32>|Address|u32|i128)", signature)
        assert [(p["name"], p["type"]) for p in invocation["parameters"]] == abi
        assert set(invocation["arguments"]) == {name for name, _ in abi}
        for param in invocation["parameters"]:
            assert decoders[param["type"]](xdr.SCVal.from_xdr(param["scval_xdr"])) == param["value"]
        assert invocation["contract_id"] == CONTRACT
        assert invocation["configured_token_contract_id"] == TOKEN
        assert invocation["network"] == "testnet"
        assert invocation["network_id"] == hashlib.sha256(service.settings.network_passphrase.encode()).hexdigest()
        assert invocation["contract_state_verified"] is False
        assert invocation["simulation_verified"] is False
        assert invocation["transaction_prepared"] is False
    assert invocations[0]["arguments"]["amount"] == str(2**100 + 1)
    assert invocations[2]["arguments"]["del_hash"] == content_hash
    assert content_hash != hashlib.sha256(b"ipfs://file").hexdigest()
    assert record.settled is False
    assert record.funded is False
    assert record.tx_hashes == {}


def test_missing_create_inputs_are_disclosed_and_no_call_prepared(settings, run):
    service = EscrowService(enabled(settings))
    record = service.open("job", AuditTier.BASIC, REQUESTER)
    assert record.mode == "unavailable"
    assert record.tx_ref == ""
    for name in ("provider", "evaluator", "amount", "deadline"):
        assert name in record.note
    with pytest.raises(ExternalSignatureRequired, match="preparation blocked"):
        run(service.fund(record))
    assert record.tx_ref == ""


@pytest.mark.parametrize("overrides, note", [
    ({"amount_atomic": 0}, "positive exact integer"),
    ({"amount_atomic": 2.5}, "positive exact integer"),
    ({"amount_atomic": True}, "positive exact integer"),
    ({"amount_atomic": 2**127}, "128-bit integer"),
    ({"deadline": 2**32}, "32-bit integer"),
    ({"deadline": -1}, "ledger sequence"),
    ({"provider": REQUESTER}, "distinct"),
    ({"provider": "not-an-address"}, "valid Stellar account"),
])
def test_invalid_create_parameters_never_prepare(settings, overrides, note):
    record = opened(EscrowService(enabled(settings)), **overrides)
    assert record.mode == "unavailable"
    assert record.tx_ref == ""
    assert note in record.note


@pytest.mark.parametrize("overrides, note", [
    ({"audit_escrow_contract_id": ""}, "contract_id"),
    ({"sac_contract_id": ""}, "sac_contract_id"),
    ({"stellar_network": "offline"}, "supported_network"),
    ({"stellar_network": "mainnet", "allow_mainnet": False}, "supported_network"),
])
def test_enabled_but_unconfigured_escrow_is_not_reported_as_optional(settings, overrides, note):
    record = opened(EscrowService(enabled(settings, **overrides)))
    assert record.mode == "unavailable"
    assert record.tx_ref == ""
    assert note in record.note


def test_legacy_submit_cannot_commit_uri_hash_or_leave_stale_invocation(settings, run):
    service = EscrowService(enabled(settings))
    record = opened(service)
    assert record.tx_ref
    with pytest.raises(ExternalSignatureRequired, match="provider, del_hash"):
        run(service.submit_deliverable(record, "ipfs://some-report", 99))
    assert record.tx_ref == ""
    assert record.mode == "unavailable"


def test_settlement_requires_explicit_evaluator_and_score(settings, run):
    service = EscrowService(enabled(settings))
    record = opened(service)
    with pytest.raises(ExternalSignatureRequired, match="evaluator, score"):
        run(service.settle(record, {}))
    assert record.tx_ref == ""
    assert record.settled is False


def test_submit_hash_is_exact_not_dependent_on_uri(settings, run):
    service = EscrowService(enabled(settings))
    record = opened(service)
    content_hash = hashlib.sha256(b"actual content").hexdigest()
    first = run(service.submit_deliverable(record, "ipfs://first", provider=PROVIDER, report_hash=content_hash))
    second = run(service.submit_deliverable(record, "https://example.org/report", provider=PROVIDER, report_hash=content_hash))
    assert first == second
    with pytest.raises(ExternalSignatureRequired, match="cannot be zero"):
        run(service.submit_deliverable(record, "ipfs://first", provider=PROVIDER, report_hash="00" * 32))
    assert record.tx_ref == ""


def test_monitoring_does_not_claim_payment(settings):
    entry = EscrowService(settings).charge_nanopayment("agent-1", "monitor")
    assert entry["amount_usdc"] == 0
    assert entry["scheme"] == "disabled"


def test_local_cid_is_deterministic_cidv1():
    cid = local_cid(b'{"a":1}')
    assert cid == local_cid(b'{"a":1}')
    assert cid != local_cid(b'{"a":2}')
    assert cid.startswith("bafkrei")


def test_publish_writes_local_copy(settings, run):
    publisher = IpfsPublisher(settings)
    cid, uri = run(publisher.publish("report.json", '{"score":84}'))
    assert uri.startswith("local-cas://")
    assert publisher.read(cid) == '{"score":84}'
