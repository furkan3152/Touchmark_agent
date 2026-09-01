"""Opsiyonel Soroban audit-escrow sınırı.

Agent doğrulama çekirdeği ödeme gerektirmez. Backend anahtar saklamadığı için
escrow etkinleştirildiğinde yalnız imzalanacak çağrıyı hazırlar; fonlanmış veya
settled saymaz. Varsayılan yol `not_required` ve parasal başarı iddia etmez.
"""

from __future__ import annotations

import hashlib
import json

from ..config import Settings
from ..models import AuditTier, EscrowRecord


class EscrowIndeterminateError(RuntimeError):
    pass


class ExternalSignatureRequired(RuntimeError):
    pass


class EscrowService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.platform_balance_usdc = 0.0
        self.nanopayment_ledger: list[dict] = []

    def price_for(self, tier: AuditTier) -> float:
        if not self.settings.audit_escrow_enabled:
            return 0.0
        return self.settings.price_deep_usdc if tier == AuditTier.DEEP else self.settings.price_basic_usdc

    def open(self, job_id: str, tier: AuditTier, requester: str = "") -> EscrowRecord:
        record = EscrowRecord(
            job_id=job_id,
            tier=tier,
            amount_usdc=self.price_for(tier),
            funder=requester,
            mode="prepared" if self.settings.audit_escrow_enabled else "not_required",
        )
        if self.settings.audit_escrow_enabled:
            record.tx_ref = self._invocation("create", record)
            record.note = "Dış Stellar imzası gerekir; bu kayıt fonlanmış değildir."
        return record

    async def fund(self, record: EscrowRecord, funder: str = "") -> EscrowRecord:
        if record.funded:
            return record
        if self.settings.audit_escrow_enabled:
            record.funder = funder or record.funder
            record.tx_ref = self._invocation("fund", record)
            raise ExternalSignatureRequired(
                "Soroban escrow fonlama dış imza ve RPC event/state doğrulaması bekliyor"
            )
        record.funded = True
        record.mode = "not_required"
        record.note = "Agent validation çekirdeğinde ödeme zorunlu değil."
        return record

    async def submit_deliverable(self, record: EscrowRecord, report_uri: str, score: int) -> str:
        if self.settings.audit_escrow_enabled:
            return json.dumps(
                {
                    "contract_id": self.settings.audit_escrow_contract_id,
                    "function": "submit",
                    "job_id": self._job_id(record.job_id),
                    "deliverable_hash": hashlib.sha256(report_uri.encode()).hexdigest(),
                    "score": max(0, min(100, score)),
                },
                sort_keys=True,
            )
        return "not_required"

    async def settle(self, record: EscrowRecord, payouts: dict[str, float]) -> EscrowRecord:
        if self.settings.audit_escrow_enabled:
            record.tx_ref = self._invocation("complete", record)
            raise ExternalSignatureRequired(
                "Soroban escrow completion dış evaluator imzası ve RPC doğrulaması bekliyor"
            )
        record.settled = True
        record.payouts = {}
        record.platform_fee_usdc = 0.0
        record.swarm_payout_usdc = 0.0
        return record

    async def refund(self, record: EscrowRecord, reason: str) -> EscrowRecord:
        if self.settings.audit_escrow_enabled:
            record.tx_ref = self._invocation("refund", record)
            raise ExternalSignatureRequired(
                "Soroban refund dış requester imzası ve RPC doğrulaması bekliyor"
            )
        record.settled = True
        record.payouts = {}
        record.note = f"ödeme yok; refund uygulanmadı ({reason})"
        return record

    def charge_nanopayment(self, agent_id: str, purpose: str) -> dict:
        entry = {
            "agent_id": agent_id,
            "purpose": purpose,
            "amount_usdc": 0.0,
            "scheme": "disabled",
            "note": "monitoring billing çekirdek doğrulama akışında etkin değil",
        }
        self.nanopayment_ledger.append(entry)
        return entry

    def _invocation(self, function: str, record: EscrowRecord) -> str:
        return json.dumps(
            {
                "contract_id": self.settings.audit_escrow_contract_id,
                "function": function,
                "job_id": self._job_id(record.job_id),
                "amount_usdc": record.amount_usdc,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _job_id(job_id: str) -> str:
        return hashlib.sha256(job_id.encode()).hexdigest()
