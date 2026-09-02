"""Audit Swarm orchestrator — runs independent dimensions in parallel."""

from __future__ import annotations

import asyncio
import time

from ..config import Settings
from ..models import (
    DIMENSION_WEIGHTS,
    AgentArtifact,
    AuditReport,
    AuditTier,
    AuditorVerdict,
    EvidenceGrade,
    Severity,
    SwarmMemberStats,
)
from .stellar_native import StellarNativeAuditor
from .compliance import ComplianceAuditor
from .economic import EconomicAuditor
from .intent import IntentAuditor
from .judge import SynthesisJudge
from .llm import LlmClient
from .reliability import ReliabilityAuditor
from .security import SecurityAuditor
from .provenance import ProvenanceAuditor
from .policy import (
    AUDIT_POLICY_VERSION,
    artifact_commitment,
    audit_surface_coverage,
    evidence_summary,
    finding_set_commitment,
)


class AuditSwarm:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        llm = LlmClient(settings)
        self.auditors = [
            IntentAuditor(settings, llm),
            SecurityAuditor(settings, llm),
            EconomicAuditor(settings, llm),
            ComplianceAuditor(settings, llm),
            ReliabilityAuditor(settings, llm),
            StellarNativeAuditor(settings, llm),
            ProvenanceAuditor(settings, llm),
        ]
        self.judge = SynthesisJudge(settings, llm)
        self.stats: dict[str, SwarmMemberStats] = {
            a.name: SwarmMemberStats(name=a.name, dimension=a.dimension) for a in self.auditors
        }

    def _validate_roster(self) -> None:
        names = [auditor.name for auditor in self.auditors]
        dimensions = [auditor.dimension for auditor in self.auditors]
        expected_dimensions = set(DIMENSION_WEIGHTS)
        if len(names) != len(set(names)):
            raise RuntimeError("Duplicate auditor name in audit roster")
        if len(dimensions) != len(set(dimensions)):
            raise RuntimeError("Duplicate dimension in audit roster")
        if set(dimensions) != expected_dimensions:
            missing = sorted(d.value for d in expected_dimensions - set(dimensions))
            extra = sorted(d.value for d in set(dimensions) - expected_dimensions)
            raise RuntimeError(f"Invalid audit roster dimensions (missing={missing}, extra={extra})")

    @staticmethod
    def _verdict_violation(auditor, verdict: AuditorVerdict) -> str:
        """Re-validates the verdict envelope even if the Auditor object is bypassed."""
        if not 0.0 <= verdict.score <= 100.0:
            return f"score out of bounds: {verdict.score}"
        if verdict.duration_ms < 0:
            return "negative duration"

        finding_ids: set[str] = set()
        for finding in verdict.findings:
            if finding.dimension is not auditor.dimension or finding.auditor != auditor.name:
                return f"finding id/dimension mismatch: {finding.id}"
            if not finding.id or finding.id in finding_ids:
                return f"duplicate/empty finding id: {finding.id!r}"
            finding_ids.add(finding.id)
            if finding.severity.rank >= Severity.HIGH.rank and not finding.remediation.strip():
                return f"critical/high finding has no remediation: {finding.id}"
            if (
                finding.evidence_grade is EvidenceGrade.CONFIRMED
                and not finding.evidence.strip()
            ):
                return f"confirmed finding has no evidence: {finding.id}"

        scenario_ids: set[str] = set()
        for scenario in verdict.scenarios:
            if not scenario.scenario_id or scenario.scenario_id in scenario_ids:
                return f"duplicate/empty scenario id: {scenario.scenario_id!r}"
            scenario_ids.add(scenario.scenario_id)
            if (
                scenario.evidence_grade is EvidenceGrade.CONFIRMED
                and not scenario.evidence.strip()
            ):
                return f"confirmed scenario has no evidence: {scenario.scenario_id}"

        expected_coverage = {
            "findings": len(verdict.findings),
            "scenarios": len(verdict.scenarios),
            "scenarios_passed": sum(1 for scenario in verdict.scenarios if scenario.passed),
        }
        if any(verdict.coverage.get(key) != value for key, value in expected_coverage.items()):
            return f"coverage declaration mismatch: {verdict.coverage}"
        return ""

    async def run(
        self,
        artifact: AgentArtifact,
        job_id: str,
        tier: AuditTier = AuditTier.BASIC,
        reward_pool_usdc: float = 0.0,
    ) -> AuditReport:
        t0 = time.perf_counter()
        deep = tier == AuditTier.DEEP
        self._validate_roster()

        results = await asyncio.gather(
            *(
                asyncio.wait_for(
                    auditor.run(artifact, deep),
                    timeout=self.settings.auditor_timeout_seconds,
                )
                for auditor in self.auditors
            ),
            return_exceptions=True,
        )
        verdicts: list[AuditorVerdict] = []
        failures: list[str] = []
        for auditor, result in zip(self.auditors, results):
            if isinstance(result, asyncio.TimeoutError):
                failures.append(f"{auditor.name}: timeout")
                continue
            if isinstance(result, BaseException):
                failures.append(f"{auditor.name}: {type(result).__name__}: {result}")
                continue
            if not isinstance(result, AuditorVerdict):
                failures.append(f"{auditor.name}: invalid verdict type")
                continue
            if result.auditor != auditor.name or result.dimension is not auditor.dimension:
                failures.append(
                    f"{auditor.name}: identity/dimension mismatch "
                    f"({result.auditor}/{result.dimension.value})"
                )
                continue
            if result.status != "completed":
                failures.append(f"{auditor.name}: {result.error or result.status}")
                continue
            if result.rule_set != AUDIT_POLICY_VERSION:
                failures.append(f"{auditor.name}: policy version mismatch")
                continue
            if violation := self._verdict_violation(auditor, result):
                failures.append(f"{auditor.name}: {violation}")
                continue
            verdicts.append(result)
        if failures or len(verdicts) != len(self.auditors):
            raise RuntimeError("Audit quorum not completed: " + "; ".join(failures))

        score, badge, dim_scores, findings, notes, disagreement, assurance = (
            self.judge.synthesise(artifact, verdicts, tier=tier)
        )
        verdict_text, judge_llm_consulted = await self.judge.llm_arbitrate(
            artifact, verdicts, score
        )
        notes.insert(0, verdict_text)

        payouts = self.judge.settle_stakes(verdicts, score, self.stats, reward_pool_usdc)
        if payouts:
            notes.append(
                "Stake distribution: "
                + ", ".join(f"{k}={v:.4f} USDC" for k, v in payouts.items())
            )

        processors: list[str] = []
        if judge_llm_consulted or any(verdict.llm_consulted for verdict in verdicts):
            processors.append(f"{self.settings.llm_provider}:{self.settings.llm_model}")

        limitations = [
            "Static and scenario-based audit is not an independent security certificate.",
            "Prepared invocation/tx hash is not ledger and contract state/event verification.",
        ]
        if not artifact.owner_verified:
            limitations.append("Agent ownership not verified; SAFE assurance cannot be achieved.")
        if artifact.onchain.data_source in ("none", "horizon_account", "simulated"):
            limitations.append(
                f"Stellar behavior scope limited: data_source={artifact.onchain.data_source}."
            )
        if processors:
            limitations.append("External LLM used; report is not deterministic.")
        surface_coverage = audit_surface_coverage(artifact)
        if tier is AuditTier.DEEP and not surface_coverage["deep_core_complete"]:
            limitations.append(
                "Deep audit core surface incomplete: "
                + ", ".join(
                    gap
                    for gap in surface_coverage["gaps"]
                    if gap in ("behavioral_contract", "tool_permissions", "implementation")
                )
                + "."
            )

        report = AuditReport(
            job_id=job_id,
            agent_id=artifact.id,
            agent_name=artifact.name,
            tier=tier,
            duration_ms=int((time.perf_counter() - t0) * 1000),
            overall_score=score,
            badge=badge,
            dimension_scores=dim_scores,
            verdicts=verdicts,
            findings=findings,
            judge_notes=notes,
            disagreement_index=disagreement,
            completed_dimensions=[v.dimension.value for v in verdicts],
            limitations=limitations,
            policy_version=AUDIT_POLICY_VERSION,
            input_hash=artifact_commitment(artifact),
            finding_set_hash=finding_set_commitment(findings),
            assurance_level=assurance,
            evidence_summary=evidence_summary(findings),
            coverage={
                "expected_auditors": len(self.auditors),
                "completed_auditors": len(verdicts),
                "expected_dimensions": len(DIMENSION_WEIGHTS),
                "completed_dimensions": len({v.dimension for v in verdicts}),
                "scenarios": sum(len(v.scenarios) for v in verdicts),
                "scenarios_passed": sum(
                    1 for v in verdicts for scenario in v.scenarios if scenario.passed
                ),
                "surface_coverage": surface_coverage,
                "attack_paths": sum(
                    1
                    for finding in findings
                    if "-path-" in finding.id or "-systemic-" in finding.id
                ),
            },
            deterministic=not processors,
            external_processors=processors,
        )
        self._last_payouts = payouts

        return report

    @property
    def last_payouts(self) -> dict[str, float]:
        return getattr(self, "_last_payouts", {})

    def leaderboard(self) -> list[dict]:
        rows = sorted(self.stats.values(), key=lambda s: -s.elo)
        return [
            {
                "name": s.name,
                "dimension": s.dimension.value,
                "elo": s.elo,
                "stake_usdc": s.stake_usdc,
                "audits": s.audits,
                "accuracy": s.accuracy,
                "earned_usdc": round(s.earned_usdc, 4),
                "slashed_usdc": round(s.slashed_usdc, 4),
            }
            for s in rows
        ]
