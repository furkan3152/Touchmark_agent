from __future__ import annotations

import json

from backend.app.models import Badge
from backend.app.stellar.attestation import Attestor, request_id


def test_request_id_is_deterministic_and_network_specific_namespace():
    assert request_id("agent", "job") == request_id("agent", "job")
    assert request_id("agent", "job") != request_id("agent", "job-2")
    assert len(request_id("agent", "job")) == 64


def test_prepared_attestation_has_no_fake_tx(settings, run):
    configured = settings.model_copy(
        update={"agent_registry_contract_id": "C" + "A" * 55}
    )
    attestation = run(
        Attestor(configured).attest(
            agent_address="G" + "B" * 55,
            req_hash="11" * 32,
            score=87.6,
            badge=Badge.SAFE,
            report_uri="ipfs://report",
            report_hash="33" * 32,
        )
    )
    invocation = json.loads(attestation.invocation_json)
    assert attestation.mode == "prepared"
    assert attestation.confirmed is False
    assert attestation.tx_hash == ""
    assert invocation["function"] == "respond"
    assert invocation["arguments"]["score"] == 88
    assert invocation["arguments"]["rep_hash"] == "33" * 32


def test_unconfigured_registry_is_unavailable(settings, run):
    attestation = run(
        Attestor(settings).attest(
            agent_address="",
            req_hash="22" * 32,
            score=50,
            badge=Badge.CAUTION,
            report_uri="local-cas://report",
            report_hash="44" * 32,
        )
    )
    assert attestation.mode == "unavailable"
    assert attestation.confirmed is False


def test_zero_report_hash_is_rejected(settings, run):
    import pytest

    with pytest.raises(ValueError, match="sıfır"):
        run(
            Attestor(settings).attest(
                agent_address="",
                req_hash="22" * 32,
                score=50,
                badge=Badge.CAUTION,
                report_uri="local-cas://report",
                report_hash="00" * 32,
            )
        )
