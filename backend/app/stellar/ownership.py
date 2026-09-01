"""G-account imzası; C-account oturumları için SEP-45 sınırını açık tutar."""

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
        return OwnershipCheck(False, "owner veya imza yok", evidence="sahiplik kanıtlanmadı")
    if owner.startswith("C"):
        return OwnershipCheck(
            False,
            "contract account",
            evidence="C-account sahipliği raw imzayla doğrulanmaz; SEP-45 challenge gerekir",
        )
    if not owner.startswith("G"):
        return OwnershipCheck(False, "geçersiz Stellar owner", evidence="G... account bekleniyor")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
        message = canonical_message(agent_ref, owner, network_passphrase)
        Keypair.from_public_key(owner).verify(sep53_payload_hash(message), raw_signature)
    except Exception as exc:
        return OwnershipCheck(False, "imza geçersiz", evidence=f"Ed25519 doğrulanamadı: {exc}")
    return OwnershipCheck(
        True,
        "ed25519",
        recovered=owner,
        evidence=f"G-account SEP-53 Ed25519 imzası doğrulandı: {owner}",
    )
