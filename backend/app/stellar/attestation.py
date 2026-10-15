"""Prepare unsigned Soroban calls that match the checked-in contract ABI.

A prepared invocation is not a transaction, a simulation, or chain confirmation.
The external signer must check contract state, simulate, and authorize the call.
"""

from __future__ import annotations

import hashlib
import json
import math

from stellar_sdk import StrKey, scval

from ..config import Settings
from ..models import Attestation, Badge


class InvocationParametersError(ValueError):
    """The provided inputs cannot represent a valid contract invocation."""


def request_id(agent_ref: str, job_id: str) -> str:
    return hashlib.sha256(f"agentveritas:stellar:{agent_ref}:{job_id}".encode()).hexdigest()


def hash32(value: str, name: str) -> str:
    normalized = value.removeprefix("0x").lower() if isinstance(value, str) else ""
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise InvocationParametersError(f"{name} must be a 32-byte hexadecimal value")
    if normalized == "0" * 64:
        raise InvocationParametersError(f"{name} cannot be zero (sıfır)")
    return normalized


def prepare_invocation(
    settings: Settings,
    contract_id: str,
    function: str,
    parameters: list[tuple[str, str, object]],
) -> str:
    """Encode ordered SCVals; named arguments are a human-readable mirror only."""
    missing = [name for name, _, value in parameters if value is None or value == ""]
    if not contract_id:
        missing.insert(0, "contract_id")
    network = settings.network_or_none
    if network is None or not network.passphrase:
        missing.insert(0, "supported_network_and_passphrase")
    if missing:
        raise InvocationParametersError("Missing required parameters: " + ", ".join(missing))
    if not StrKey.is_valid_contract(contract_id):
        raise InvocationParametersError("contract_id must be a valid Stellar contract address")
    encoded = []
    for name, kind, value in parameters:
        if kind == "Address":
            if not isinstance(value, str) or not (
                StrKey.is_valid_ed25519_public_key(value) or StrKey.is_valid_contract(value)
            ):
                raise InvocationParametersError(f"{name} must be a valid Stellar account or contract address")
            val = scval.to_address(value)
        elif kind == "BytesN<32>":
            value = hash32(value, name)
            val = scval.to_bytes(bytes.fromhex(value))
        elif kind == "u32":
            if type(value) is not int or not 0 <= value <= 2**32 - 1:
                raise InvocationParametersError(f"{name} must be an unsigned 32-bit integer")
            val = scval.to_uint32(value)
        elif kind == "i128":
            if type(value) is not int or not -(2**127) <= value < 2**127:
                raise InvocationParametersError(f"{name} must be an exact signed 128-bit integer")
            val = scval.to_int128(value)
            # JSON consumers must not round atomic amounts through a JS Number.
            value = str(value)
        elif kind == "String":
            if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 512:
                raise InvocationParametersError(f"{name} must contain 1..512 UTF-8 bytes")
            val = scval.to_string(value)
        else:
            raise InvocationParametersError(f"Unsupported ABI type: {kind}")
        encoded.append({"name": name, "type": kind, "value": value, "scval_xdr": val.to_xdr()})
    return json.dumps(
        {
            "schema": "agentveritas.soroban-invocation/v1",
            "network": network.key,
            "network_passphrase": network.passphrase,
            "network_id": hashlib.sha256(network.passphrase.encode("utf-8")).hexdigest(),
            "contract_id": contract_id,
            "function": function,
            "arguments": {item["name"]: item["value"] for item in encoded},
            "parameters": encoded,
            "transaction_prepared": False,
            "simulation_verified": False,
            "contract_state_verified": False,
            "signature_required": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class Attestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def attest(
        self,
        *,
        agent_address: str,
        req_hash: str,
        score: float,
        badge: Badge,
        report_uri: str,
        report_hash: str,
        validator_address: str = "",
    ) -> Attestation:
        # These are report metadata, never extra respond ABI arguments.
        del agent_address, badge
        normalized_hash = hash32(report_hash, "report_hash")
        normalized_request = hash32(req_hash, "req_id")
        invocation = ""
        try:
            if isinstance(score, bool) or not math.isfinite(score) or not 0 <= score <= 100:
                raise InvocationParametersError("score must be finite and within 0..100")
            invocation = prepare_invocation(
                self.settings,
                self.settings.agent_registry_contract_id,
                "respond",
                [
                    ("validator", "Address", validator_address),
                    ("req_id", "BytesN<32>", normalized_request),
                    ("score", "u32", int(round(score))),
                    ("rep_uri", "String", report_uri),
                    ("rep_hash", "BytesN<32>", normalized_hash),
                ],
            )
            note = (
                "Unsigned invocation only. An existing pending validation request assigned to this "
                "validator, unchanged agent version, validator authorization, simulation, external "
                "signature and RPC confirmation are still required."
            )
        except InvocationParametersError as exc:
            note = f"Attestation unavailable: {exc}. No invocation was prepared."
        return Attestation(
            mode="prepared" if invocation else "unavailable",
            registry_contract_id=self.settings.agent_registry_contract_id,
            request_id=normalized_request,
            invocation_json=invocation,
            report_hash=normalized_hash,
            validator_address=validator_address if invocation else "",
            network=self.settings.stellar_network,
            confirmed=False,
            note=note,
        )
