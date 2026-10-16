"""Optional unsigned escrow invocation preparation; no transaction signing.

All monetary amounts supplied to the contract are explicit integer token units.
The legacy amount_usdc field is a display quote, never an on-chain amount.
"""

from __future__ import annotations

import hashlib
import json

from stellar_sdk import StrKey

from ..config import Settings
from ..models import AuditTier, EscrowRecord
from ..stellar.attestation import InvocationParametersError, prepare_invocation


class EscrowIndeterminateError(RuntimeError):
    pass


class ExternalSignatureRequired(RuntimeError):
    state = "awaiting_signature"


class InvocationPreparationBlocked(ExternalSignatureRequired):
    """No signable invocation exists; signing cannot resolve missing inputs."""

    state = "preparation_blocked"


class EscrowService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.platform_balance_usdc = 0.0
        self.nanopayment_ledger: list[dict] = []

    def price_for(self, tier: AuditTier) -> float:
        if not self.settings.enable_audit_escrow:
            return 0.0
        return self.settings.price_deep_usdc if tier == AuditTier.DEEP else self.settings.price_basic_usdc

    def open(
        self,
        job_id: str,
        tier: AuditTier,
        requester: str = "",
        *,
        provider: str = "",
        evaluator: str = "",
        amount_atomic: int | None = None,
        deadline: int | None = None,
    ) -> EscrowRecord:
        record = EscrowRecord(
            job_id=job_id,
            tier=tier,
            amount_usdc=self.price_for(tier),
            funder=requester,
            mode="unavailable" if self.settings.enable_audit_escrow else "not_required",
        )
        if self.settings.enable_audit_escrow:
            try:
                if amount_atomic is not None and (type(amount_atomic) is not int or amount_atomic <= 0):
                    raise InvocationParametersError("amount_atomic must be a positive exact integer token amount")
                if deadline is not None and (type(deadline) is not int or deadline <= 0):
                    raise InvocationParametersError("deadline must be a positive ledger sequence (u32)")
                if requester and provider and evaluator and len({requester, provider, evaluator}) != 3:
                    raise InvocationParametersError("requester, provider and evaluator must be distinct addresses")
                record.tx_ref = self._invocation(
                    "create",
                    [
                        ("requester", "Address", requester),
                        ("job_id", "BytesN<32>", self._job_id(job_id)),
                        ("provider", "Address", provider),
                        ("evaluator", "Address", evaluator),
                        ("amount", "i128", amount_atomic),
                        ("deadline", "u32", deadline),
                    ],
                )
                record.mode = "prepared"
                record.note = (
                    "Unsigned create invocation only; not funded. Token configuration, future ledger "
                    "deadline, contract state, simulation and external signature require verification."
                )
            except InvocationParametersError as exc:
                self._blocked(record, exc)
        return record

    async def fund(self, record: EscrowRecord, funder: str = "") -> EscrowRecord:
        if record.funded:
            return record
        if self.settings.enable_audit_escrow:
            if record.mode == "unavailable":
                raise InvocationPreparationBlocked(record.note)
            requester = funder or record.funder
            self._prepare_record(record, "fund", [
                ("requester", "Address", requester),
                ("job_id", "BytesN<32>", self._job_id(record.job_id)),
            ])
            record.funder = requester
            raise ExternalSignatureRequired(
                "Unsigned fund invocation prepared; external requester signature and RPC verification required"
            )
        record.funded = True
        record.mode = "not_required"
        record.note = "Agent validation çekirdeğinde ödeme zorunlu değil."
        return record

    async def submit_deliverable(
        self,
        record: EscrowRecord,
        report_uri: str,
        score: int | None = None,
        *,
        provider: str = "",
        report_hash: str = "",
    ) -> str:
        # A URL and score are not submit parameters. The exact published report's
        # content digest must be supplied by the caller; never hash its location.
        del report_uri, score
        if self.settings.enable_audit_escrow:
            self._prepare_record(record, "submit", [
                ("provider", "Address", provider),
                ("job_id", "BytesN<32>", self._job_id(record.job_id)),
                ("del_hash", "BytesN<32>", report_hash),
            ])
            return record.tx_ref
        return "not_required"

    async def settle(
        self,
        record: EscrowRecord,
        payouts: dict[str, float],
        *,
        evaluator: str = "",
        score: int | None = None,
    ) -> EscrowRecord:
        if self.settings.enable_audit_escrow:
            if score is not None and (type(score) is not int or not 0 <= score <= 100):
                self._blocked(record, InvocationParametersError("score must be an integer within 0..100"))
                raise InvocationPreparationBlocked(record.note)
            self._prepare_record(record, "complete", [
                ("evaluator", "Address", evaluator),
                ("job_id", "BytesN<32>", self._job_id(record.job_id)),
                ("score", "u32", score),
            ])
            raise ExternalSignatureRequired(
                "Unsigned complete invocation prepared; external evaluator signature and RPC verification required"
            )
        record.settled = True
        record.payouts = {}
        record.platform_fee_usdc = 0.0
        record.swarm_payout_usdc = 0.0
        return record

    async def refund(self, record: EscrowRecord, reason: str) -> EscrowRecord:
        if self.settings.enable_audit_escrow:
            self._prepare_record(record, "refund", [
                ("requester", "Address", record.funder),
                ("job_id", "BytesN<32>", self._job_id(record.job_id)),
            ])
            raise ExternalSignatureRequired(
                "Unsigned refund invocation prepared; requester signature, eligible state/deadline and RPC verification required"
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

    def _invocation(self, function: str, parameters: list[tuple[str, str, object]]) -> str:
        if not StrKey.is_valid_contract(self.settings.sac_contract_id):
            raise InvocationParametersError("sac_contract_id must be a configured valid token contract address")
        encoded = json.loads(prepare_invocation(
            self.settings, self.settings.audit_escrow_contract_id, function, parameters
        ))
        # The escrow contract stores its token at initialization. This configured
        # address is a signer check, not an extra ABI argument or a readback claim.
        encoded["configured_token_contract_id"] = self.settings.sac_contract_id
        return json.dumps(encoded, sort_keys=True, separators=(",", ":"))

    def _prepare_record(
        self, record: EscrowRecord, function: str, parameters: list[tuple[str, str, object]]
    ) -> None:
        try:
            record.tx_ref = self._invocation(function, parameters)
            record.mode = "prepared"
            record.note = "Unsigned invocation only; no transaction sent or chain state verified."
        except InvocationParametersError as exc:
            self._blocked(record, exc)
            raise InvocationPreparationBlocked(record.note) from exc

    @staticmethod
    def _blocked(record: EscrowRecord, exc: InvocationParametersError) -> None:
        record.tx_ref = ""
        record.mode = "unavailable"
        record.note = f"Escrow preparation blocked: {exc}. No invocation was prepared."

    @staticmethod
    def _job_id(job_id: str) -> str:
        if not job_id:
            raise InvocationParametersError("job_id is required")
        return hashlib.sha256(job_id.encode()).hexdigest()
