"""Ödeme-çekirdek ayrımı, external signer sınırı ve yerel CID."""

from __future__ import annotations

import pytest

from backend.app.models import AuditTier
from backend.app.reporting.ipfs import IpfsPublisher, local_cid
from backend.app.services.escrow import EscrowService, ExternalSignatureRequired


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
    configured = settings.model_copy(
        update={
            "enable_audit_escrow": True,
            "audit_escrow_contract_id": "C" + "A" * 55,
            "sac_contract_id": "C" + "B" * 55,
        }
    )
    service = EscrowService(configured)
    record = service.open("job-2", AuditTier.BASIC, "G" + "A" * 55)
    assert record.mode == "prepared"
    assert record.amount_usdc == configured.price_basic_usdc
    with pytest.raises(ExternalSignatureRequired):
        run(service.fund(record))
    assert record.funded is False
    assert record.tx_hashes == {}


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
