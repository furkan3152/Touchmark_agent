"""G-account signatures; keeps the SEP-45 boundary explicit for C-account sessions."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from stellar_sdk import Keypair

SEP53_PREFIX = b"Stellar Signed Message:\n"


@dataclass(frozen=True)
class OwnershipCheck:
    verified: bool
    reason: str
    recovered: str = ""
    evidence: str = ""


def canonical_message(agent_ref: str, owner: str, network_passphrase: str) -> str:
    return (
        "AgentVeritas Stellar ownership proof\n"
        f"network={network_passphrase}\n"
        f"agent={agent_ref}\n"
        f"owner={owner}\n"
        "purpose=agent-registration"
    )


def sep53_payload_hash(message: str) -> bytes:
    """SEP-53: SHA-256(prefix || UTF-8 message)."""
    return hashlib.sha256(SEP53_PREFIX + message.encode("utf-8")).digest()


def verify_owner(
    agent_ref: str,
    owner: str,
    signature: str,
    network_passphrase: str,
) -> OwnershipCheck:
    if not owner or not signature:
        return OwnershipCheck(False, "no owner or signature", evidence="ownership not proven")
    if owner.startswith("C"):
        return OwnershipCheck(
            False,
            "contract account",
            evidence="C-account ownership cannot be verified with a raw signature; a SEP-45 challenge is required",
        )
    if not owner.startswith("G"):
        return OwnershipCheck(False, "invalid Stellar owner", evidence="expected a G... account")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
        message = canonical_message(agent_ref, owner, network_passphrase)
        Keypair.from_public_key(owner).verify(sep53_payload_hash(message), raw_signature)
    except Exception as exc:
        return OwnershipCheck(False, "invalid signature", evidence=f"Ed25519 verification failed: {exc}")
    return OwnershipCheck(
        True,
        "ed25519",
        recovered=owner,
        evidence=f"G-account SEP-53 Ed25519 signature verified: {owner}",
    )
