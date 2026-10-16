from __future__ import annotations

import hashlib
import json
import re

import pytest
from stellar_sdk import StrKey, scval, xdr

from backend.app.models import Badge
from backend.app.stellar.attestation import Attestor, request_id

CONTRACT = StrKey.encode_contract(bytes([1]) * 32)
VALIDATOR = StrKey.encode_ed25519_public_key(bytes([2]) * 32)


def configured_settings(settings):
    return settings.model_copy(update={"stellar_network": "testnet", "agent_registry_contract_id": CONTRACT})


def inputs(**overrides):
    return {
        "agent_address": StrKey.encode_ed25519_public_key(bytes([3]) * 32),
        "req_hash": "11" * 32,
        "score": 87.6,
        "badge": Badge.SAFE,
        "report_uri": "ipfs://report",
        "report_hash": "33" * 32,
        "validator_address": VALIDATOR,
        **overrides,
    }


def test_request_id_is_deterministic():
    assert request_id("agent", "job") == request_id("agent", "job")
    assert request_id("agent", "job") != request_id("agent", "job-2")
    assert len(request_id("agent", "job")) == 64


def test_prepared_attestation_matches_rust_abi_and_has_no_fake_tx(settings, run, repo_root):
    configured = configured_settings(settings)
    attestation = run(Attestor(configured).attest(**inputs()))
    invocation = json.loads(attestation.invocation_json)
    assert attestation.mode == "prepared"
    assert attestation.confirmed is False
    assert attestation.tx_hash == ""
    assert attestation.validator_address == VALIDATOR
    assert invocation["function"] == "respond"
    assert invocation["contract_id"] == CONTRACT
    assert invocation["arguments"] == {
        "validator": VALIDATOR, "req_id": "11" * 32, "score": 88,
        "rep_uri": "ipfs://report", "rep_hash": "33" * 32,
    }
    # Check checked-in Rust ABI, not another hand-maintained Python signature.
    source = (repo_root / "contracts/agent-registry/src/lib.rs").read_text()
    signature = re.search(r"pub fn respond\((.*?)\) ->", source, re.S).group(1)
    abi = re.findall(r"(\w+):\s*(BytesN<32>|Address|u32|String)", signature)
    assert [(p["name"], p["type"]) for p in invocation["parameters"]] == abi
    args = [xdr.SCVal.from_xdr(p["scval_xdr"]) for p in invocation["parameters"]]
    assert scval.from_address(args[0]).address == VALIDATOR
    assert scval.from_bytes(args[1]) == bytes.fromhex("11" * 32)
    assert scval.from_uint32(args[2]) == 88
    assert scval.from_string(args[3]) == b"ipfs://report"
    assert scval.from_bytes(args[4]) == bytes.fromhex("33" * 32)
    assert invocation["network"] == "testnet"
    assert invocation["network_passphrase"] == configured.network_passphrase
    assert invocation["network_id"] == hashlib.sha256(configured.network_passphrase.encode()).hexdigest()
    assert invocation["transaction_prepared"] is False
    assert invocation["simulation_verified"] is False
    assert invocation["contract_state_verified"] is False


@pytest.mark.parametrize("changes, note", [
    ({"agent_registry_contract_id": ""}, "contract_id"),
    ({"agent_registry_contract_id": "C" + "A" * 55}, "valid Stellar contract"),
    ({"stellar_network": "offline"}, "supported_network_and_passphrase"),
    ({"stellar_network": "mainnet", "allow_mainnet": False}, "supported_network_and_passphrase"),
])
def test_bad_configuration_is_unavailable(settings, run, changes, note):
    configured = configured_settings(settings).model_copy(update=changes)
    attestation = run(Attestor(configured).attest(**inputs()))
    assert attestation.mode == "unavailable"
    assert attestation.invocation_json == ""
    assert attestation.confirmed is False
    assert note in attestation.note


@pytest.mark.parametrize("overrides, note", [
    ({"validator_address": ""}, "validator"),
    ({"validator_address": "<external-signer-address>"}, "valid Stellar account"),
    ({"report_uri": ""}, "rep_uri"),
    ({"report_uri": "é" * 257}, "512 UTF-8 bytes"),
    ({"score": float("nan")}, "score"),
    ({"score": -1}, "score"),
    ({"score": 101}, "score"),
    ({"score": True}, "score"),
])
def test_missing_or_invalid_arguments_are_not_prepared(settings, run, overrides, note):
    attestation = run(Attestor(configured_settings(settings)).attest(**inputs(**overrides)))
    assert attestation.mode == "unavailable"
    assert attestation.invocation_json == ""
    assert note in attestation.note


@pytest.mark.parametrize("field,value", [
    ("report_hash", "00" * 32), ("req_hash", "00" * 32),
    ("req_hash", "not-a-hash"), ("report_hash", "12" * 31),
])
def test_invalid_hashes_are_rejected(settings, run, field, value):
    with pytest.raises(ValueError):
        run(Attestor(configured_settings(settings)).attest(**inputs(**{field: value})))


def test_content_hash_is_preserved_independent_of_report_uri(settings, run):
    digest = hashlib.sha256(b'{"report":"exact published bytes"}').hexdigest()
    attestor = Attestor(configured_settings(settings))
    first = run(attestor.attest(**inputs(report_hash="0x" + digest.upper())))
    second = run(attestor.attest(**inputs(report_uri="https://example.org/report", report_hash=digest)))
    assert first.report_hash == second.report_hash == digest
    assert json.loads(first.invocation_json)["arguments"]["rep_hash"] == digest
    assert json.loads(second.invocation_json)["arguments"]["rep_hash"] == digest
