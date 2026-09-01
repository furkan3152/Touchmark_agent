"""Audit pipeline: artifact → swarm → report → Soroban validation preparation."""

from __future__ import annotations

import hashlib
import time

from ..stellar.attestation import Attestor, request_id
from ..config import Settings
from ..models import (
    AgentArtifact,
    AuditReport,
    AuditTier,
    Badge,
    EvidenceGrade,
    Job,
    JobState,
    MonitorSubscription,
    Severity,
)
from ..reporting.generator import canonical_json, render_markdown, report_to_dict
from ..reporting.ipfs import IpfsPublisher
from ..swarm import AuditSwarm
from .badges import BadgeRegistry
from .escrow import EscrowIndeterminateError, EscrowService, ExternalSignatureRequired
from .store import Store


class AuditPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = Store(settings)
        self.swarm = AuditSwarm(settings)
        self.escrow = EscrowService(settings)
        self.ipfs = IpfsPublisher(settings)
        self.attestor = Attestor(settings)
        self.badges = BadgeRegistry(settings)

    # ------------------------------------------------------------------- jobs
    def create_job(
        self,
        agent_id: str,
        tier: AuditTier,
        requester: str = "",
        validation_request_hash: str = "",
    ) -> Job:
        artifact = self.store.get_agent(agent_id)
        if not artifact:
            raise KeyError(f"agent bulunamadı: {agent_id}")

        job = Job(agent_id=agent_id, tier=tier, requester=requester)
        job.validation_request_hash = validation_request_hash or request_id(
            artifact.agent_wallet or artifact.id, job.id
        )
        job.escrow = self.escrow.open(job.id, tier, requester)
        job.log(
            f"job açıldı · tier={tier.value} · opsiyonel escrow={job.escrow.amount_usdc} USDC · "
            f"validationRequest={job.validation_request_hash[:18]}…"
        )
        return self.store.put_job(job)

    async def fund_job(self, job_id: str, funder: str = "") -> Job:
        job = self._job(job_id)
        if job.state in (
            JobState.FUNDED,
            JobState.RUNNING,
            JobState.DELIVERED,
            JobState.SETTLED,
            JobState.COMPLETED,
        ):
            return job
        if job.state is JobState.INDETERMINATE:
            raise EscrowIndeterminateError("job reconciliation bekliyor")
        if job.escrow is None:
            job.escrow = self.escrow.open(job.id, job.tier, funder)
        try:
            await self.escrow.fund(job.escrow, funder)
        except ExternalSignatureRequired as exc:
            job.state = JobState.AWAITING_SIGNATURE
            job.error = str(exc)
            job.log(f"DIŞ İMZA BEKLENİYOR: {exc}")
            self.store.put_job(job)
            raise
        except EscrowIndeterminateError as exc:
            job.state = JobState.INDETERMINATE
            job.error = str(exc)
            job.log(f"ESCROW BELİRSİZ: {exc}")
            self.store.put_job(job)
            raise
        job.state = JobState.FUNDED
        job.log(
            f"escrow yatırıldı ({job.escrow.mode}): {job.escrow.amount_usdc} USDC "
            f"({funder or 'anon'})"
        )
        if job.escrow.note:
            job.log(f"escrow notu: {job.escrow.note}")
        return self.store.put_job(job)

    async def run_job(self, job_id: str) -> Job:
        job = self._job(job_id)
        if job.state in (JobState.SETTLED, JobState.COMPLETED):
            return job
        if job.state in (
            JobState.AWAITING_SIGNATURE,
            JobState.RUNNING,
            JobState.DELIVERED,
            JobState.INDETERMINATE,
        ):
            raise RuntimeError(f"job bu durumda yeniden çalıştırılamaz: {job.state.value}")
        artifact = self.store.get_agent(job.agent_id)
        if not artifact:
            job.state = JobState.FAILED
            job.error = "agent artifact bulunamadı"
            return self.store.put_job(job)

        if job.escrow and not job.escrow.funded:
            await self.fund_job(job_id, job.requester)
            job = self._job(job_id)

        job.state = JobState.RUNNING
        job.log("swarm başlatıldı (5 denetçi paralel)")
        self.store.put_job(job)

        try:
            reward_pool = 0.0
            if job.escrow:
                reward_pool = job.escrow.amount_usdc * (
                    1 - self.settings.platform_fee_bps / 10_000
                )
            report = await self.swarm.run(artifact, job.id, job.tier, reward_pool)
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            job.log(f"HATA: {job.error}")
            if job.escrow:
                try:
                    await self.escrow.refund(job.escrow, "swarm_failure")
                    job.state = JobState.REFUNDED
                    job.log("escrow iade edildi")
                except (EscrowIndeterminateError, ExternalSignatureRequired) as refund_exc:
                    job.state = JobState.INDETERMINATE
                    job.error += f"; refund belirsiz: {refund_exc}"
            return self.store.put_job(job)

        job.log(
            f"swarm tamamlandı · skor={report.overall_score} · badge={report.badge.value} · "
            f"{len(report.findings)} bulgu · {report.duration_ms} ms"
        )

        await self._publish_and_attest(job, artifact, report)

        job.report = report
        job.state = JobState.DELIVERED

        if job.escrow and job.escrow.mode != "not_required":
            payouts = self.swarm.last_payouts
            try:
                if job.report or report.report_uri:
                    await self.escrow.submit_deliverable(
                        job.escrow, report.report_uri, int(round(report.overall_score))
                    )
                await self.escrow.settle(job.escrow, payouts)
            except (EscrowIndeterminateError, ExternalSignatureRequired) as exc:
                job.state = JobState.INDETERMINATE
                job.error = str(exc)
                job.log(f"SETTLEMENT BELİRSİZ: {exc}")
                return self.store.put_job(job)
            job.state = JobState.SETTLED
            job.log(
                f"settlement ({job.escrow.mode}) · platform fee={job.escrow.platform_fee_usdc} USDC · "
                f"swarm payout={job.escrow.swarm_payout_usdc} USDC"
            )
            if job.escrow.note:
                job.log(f"escrow notu: {job.escrow.note}")
        else:
            job.state = JobState.COMPLETED
            job.log("agent validation tamamlandı · ödeme çekirdeğe dahil değil")

        self.badges.issue(artifact, report)
        job.log(f"badge yayımlandı: {report.badge.value}")
        return self.store.put_job(job)

    async def _publish_and_attest(
        self, job: Job, artifact: AgentArtifact, report: AuditReport
    ) -> None:
        payload = report_to_dict(report, artifact)
        canonical_payload = canonical_json(payload)
        report_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        cid, uri = await self.ipfs.publish(f"{job.id}.json", canonical_payload)
        report.report_cid = cid
        report.report_uri = uri
        job.log(f"rapor yayımlandı: {cid}")

        att = await self.attestor.attest(
            agent_address=artifact.agent_wallet,
            req_hash=job.validation_request_hash,
            score=report.overall_score,
            badge=report.badge,
            report_uri=uri,
            report_hash=report_hash,
        )
        report.attestation = att
        job.log(
            f"attestation ({att.mode}) → Soroban registry {att.registry_contract_id[:12] or 'yok'} · "
            f"confirmed={att.confirmed}"
        )

        # markdown'ı da sakla
        md = render_markdown(report, artifact)
        (self.settings.data_path / "reports").mkdir(parents=True, exist_ok=True)
        (self.settings.data_path / "reports" / f"{job.id}.md").write_text(md)

    def markdown_for(self, job_id: str) -> str:
        job = self._job(job_id)
        artifact = self.store.get_agent(job.agent_id)
        if not job.report or not artifact:
            raise KeyError("rapor hazır değil")
        return render_markdown(job.report, artifact)

    def json_for(self, job_id: str) -> dict:
        job = self._job(job_id)
        artifact = self.store.get_agent(job.agent_id)
        if not job.report or not artifact:
            raise KeyError("rapor hazır değil")
        return report_to_dict(job.report, artifact)

    # -------------------------------------------------------------- monitoring
    def subscribe_monitor(
        self, agent_id: str, interval_minutes: int, prepaid_usdc: float
    ) -> MonitorSubscription:
        if not self.store.get_agent(agent_id):
            raise KeyError(f"agent bulunamadı: {agent_id}")
        sub = MonitorSubscription(
            agent_id=agent_id,
            interval_minutes=max(15, min(1440, interval_minutes)),
            balance_usdc=prepaid_usdc,
        )
        return self.store.put_subscription(sub)

    async def monitor_tick(self, force: bool = False) -> list[dict]:
        """Tüm aktif abonelikler için patrol turu; her tur x402 mikro ödemesi keser."""
        results: list[dict] = []
        now = time.time()

        for sub in self.store.active_subscriptions():
            due = (
                force
                or sub.last_tick_at is None
                or (now - sub.last_tick_at) >= sub.interval_minutes * 60
            )
            if not due:
                continue

            price = self.settings.monitor_tick_price_usdc
            if sub.balance_usdc < price:
                sub.active = False
                sub.alerts.append("bakiye tükendi, izleme durduruldu")
                self.store.put_subscription(sub)
                results.append({"subscription": sub.id, "status": "insufficient_balance"})
                continue

            artifact = self.store.get_agent(sub.agent_id)
            if not artifact:
                sub.active = False
                self.store.put_subscription(sub)
                continue

            sub.balance_usdc = round(sub.balance_usdc - price, 8)
            payment = self.escrow.charge_nanopayment(sub.agent_id, "continuous_monitoring")

            report = await self.swarm.run(artifact, f"{sub.id}-tick{sub.ticks + 1}", AuditTier.BASIC, 0.0)
            drift = None
            if sub.last_score is not None:
                drift = round(report.overall_score - sub.last_score, 1)
                if drift <= -8:
                    sub.alerts.append(
                        f"skor düşüşü {drift} ({sub.last_score} → {report.overall_score})"
                    )
            badge_rank = {
                Badge.SAFE.value: 3,
                Badge.CAUTION.value: 2,
                Badge.HIGH_RISK.value: 1,
                Badge.BLOCKLIST.value: 0,
            }
            if sub.last_badge and badge_rank[report.badge.value] < badge_rank[sub.last_badge]:
                sub.alerts.append(f"badge düşüşü: {sub.last_badge} → {report.badge.value}")
            elif not sub.last_badge and report.badge in (Badge.HIGH_RISK, Badge.BLOCKLIST):
                sub.alerts.append(f"ilk denetim risk badge'i: {report.badge.value}")

            confirmed_risks = sorted(
                finding.id
                for finding in report.findings
                if finding.evidence_grade is EvidenceGrade.CONFIRMED
                and finding.severity in (Severity.HIGH, Severity.CRITICAL)
            )
            finding_set_changed = bool(
                sub.last_finding_set_hash
                and sub.last_finding_set_hash != report.finding_set_hash
            )
            new_confirmed_risks = (
                sorted(set(confirmed_risks) - set(sub.last_confirmed_risk_ids))
                if sub.last_finding_set_hash
                else []
            )
            if new_confirmed_risks:
                sub.alerts.append(
                    "yeni doğrulanmış high/critical bulgu: "
                    + ", ".join(new_confirmed_risks)
                )

            assurance_rank = {"simulated": 0, "partial": 1, "verified": 2}
            current_assurance = report.assurance_level.value
            if (
                sub.last_assurance_level
                and assurance_rank[current_assurance]
                < assurance_rank[sub.last_assurance_level]
            ):
                sub.alerts.append(
                    f"kanıt güvencesi düştü: {sub.last_assurance_level} → {current_assurance}"
                )

            sub.ticks += 1
            sub.last_tick_at = now
            sub.last_score = report.overall_score
            sub.last_badge = report.badge.value
            sub.last_finding_set_hash = report.finding_set_hash
            sub.last_confirmed_risk_ids = confirmed_risks
            sub.last_assurance_level = current_assurance
            sub.alerts = sub.alerts[-100:]
            self.store.put_subscription(sub)
            self.badges.issue(artifact, report)

            results.append(
                {
                    "subscription": sub.id,
                    "agent_id": sub.agent_id,
                    "score": report.overall_score,
                    "badge": report.badge.value,
                    "assurance_level": current_assurance,
                    "drift": drift,
                    "finding_set_changed": finding_set_changed,
                    "new_confirmed_risks": new_confirmed_risks,
                    "charged_usdc": payment["amount_usdc"],
                    "remaining_balance_usdc": sub.balance_usdc,
                    "alerts": sub.alerts[-3:],
                }
            )
        return results

    # ------------------------------------------------------------------ utils
    def _job(self, job_id: str) -> Job:
        job = self.store.get_job(job_id)
        if not job:
            raise KeyError(f"job bulunamadı: {job_id}")
        return job

    def stats(self) -> dict:
        jobs = list(self.store.jobs.values())
        completed = [j for j in jobs if j.report]
        scores = [j.report.overall_score for j in completed if j.report]
        badge_counts: dict[str, int] = {}
        for j in completed:
            if j.report:
                badge_counts[j.report.badge.value] = badge_counts.get(j.report.badge.value, 0) + 1
        return {
            "agents": len(self.store.agents),
            "jobs": len(jobs),
            "completed_audits": len(completed),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "badge_distribution": badge_counts,
            "platform_revenue_usdc": round(self.escrow.platform_balance_usdc, 6),
            "nanopayments": len(self.escrow.nanopayment_ledger),
            "active_monitors": len(self.store.active_subscriptions()),
            "modes": {
                "llm": self.settings.llm_enabled,
                "stellar_rpc": self.settings.rpc_enabled,
                "contract_submission": False,
                "ipfs": self.settings.ipfs_enabled,
                "screening": self.settings.screening_enabled,
            },
        }
