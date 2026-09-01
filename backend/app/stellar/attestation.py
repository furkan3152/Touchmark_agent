"""Soroban registry çağrısı için imzasız, kanonik doğrulama hazırlığı.

Backend hiçbir zaman tx hash uydurmaz ve kullanıcı adına imzalamaz. Başarı ancak
dış imzalayıcıdan gelen transaction hash RPC ile doğrulandıktan sonra onchain
olarak işaretlenebilir.
"""

from __future__ import annotations

import hashlib
import json

from ..config import Settings
from ..models import Attestation, Badge


def request_id(agent_ref: str, job_id: str) -> str:
    return hashlib.sha256(f"agentveritas:stellar:{agent_ref}:{job_id}".encode()).hexdigest()


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
    ) -> Attestation:
        normalized_hash = report_hash.removeprefix("0x").lower()
        if len(normalized_hash) != 64 or any(c not in "0123456789abcdef" for c in normalized_hash):
            raise ValueError("report_hash 32-byte hex olmalı")
        if normalized_hash == "0" * 64:
            raise ValueError("report_hash sıfır olamaz")
        invocation = {
            "contract_id": self.settings.agent_registry_contract_id,
            "function": "respond",
            "arguments": {
                "validator": "<external-signer-address>",
                "req_id": req_hash.removeprefix("0x"),
                "score": max(0, min(100, int(round(score)))),
                "rep_uri": report_uri,
                "rep_hash": normalized_hash,
                "badge": badge.value,
                "agent": agent_address,
            },
        }
        configured = bool(self.settings.agent_registry_contract_id)
        return Attestation(
            mode="prepared" if configured else "unavailable",
            registry_contract_id=self.settings.agent_registry_contract_id,
            request_id=req_hash,
            invocation_json=(
                json.dumps(invocation, sort_keys=True, separators=(",", ":"))
                if configured
                else ""
            ),
            report_hash=normalized_hash,
            network=self.settings.stellar_network,
            confirmed=False,
            note=(
                "Dış imza ve RPC state/event doğrulaması gerekli; henüz zincir başarısı değil."
                if configured
                else "AGENT_REGISTRY_CONTRACT_ID tanımlı değil; attestation hazırlanmadı."
            ),
        )
