"""Audit sonucu görünümü; registry confirmation yerine geçmeyen offchain etiketler."""

from __future__ import annotations

import time

from ..config import Settings
from ..models import AgentArtifact, AuditReport, Badge

VALIDITY_DAYS = {Badge.SAFE: 90, Badge.CAUTION: 45, Badge.HIGH_RISK: 30, Badge.BLOCKLIST: 365}


class BadgeRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.records: dict[str, dict] = {}
        self.history: dict[str, list[dict]] = {}

    def issue(self, artifact: AgentArtifact, report: AuditReport) -> dict:
        key = (artifact.agent_contract_id or artifact.agent_wallet or artifact.id).lower()
        expires = time.time() + VALIDITY_DAYS[report.badge] * 86_400
        attestation = report.attestation
        record = {
            "agent_id": artifact.id,
            "agent_name": artifact.name,
            "account": artifact.agent_wallet,
            "agent_contract_id": artifact.agent_contract_id,
            "badge": report.badge.value,
            "score": report.overall_score,
            "job_id": report.job_id,
            "report_cid": report.report_cid,
            "report_uri": report.report_uri,
            "issued_at": time.time(),
            "expires_at": expires,
            "attestation_mode": attestation.mode if attestation else "none",
            "attestation_confirmed": attestation.confirmed if attestation else False,
            "attestation_tx_hash": attestation.tx_hash if attestation else "",
            "marketplace_label": self._label(report.badge, report.overall_score),
            "evidence_boundary": "offchain label until registry event/state confirms response",
        }
        self.records[key] = record
        self.history.setdefault(key, []).append(
            {
                "at": record["issued_at"],
                "badge": record["badge"],
                "score": record["score"],
                "job_id": record["job_id"],
                "confirmed": record["attestation_confirmed"],
            }
        )
        return record

    def get(self, identifier: str) -> dict | None:
        return self.records.get(identifier.lower())

    def get_history(self, identifier: str) -> list[dict]:
        return self.history.get(identifier.lower(), [])

    def all_badges(self) -> list[dict]:
        return sorted(self.records.values(), key=lambda row: -row["score"])

    @staticmethod
    def _label(badge: Badge, score: float) -> str:
        if badge == Badge.SAFE:
            return f"Audited by AgentVeritas · {score:.0f}/100"
        if badge == Badge.CAUTION:
            return f"Audited · caution · {score:.0f}/100"
        if badge == Badge.HIGH_RISK:
            return f"High risk · {score:.0f}/100"
        return "Blocklist recommendation · AgentVeritas"
