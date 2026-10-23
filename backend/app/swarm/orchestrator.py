"""Audit Swarm orchestrator — runs independent dimensions in parallel."""

from __future__ import annotations

import asyncio
import re
import time

from ..config import Settings
from ..models import (
    DIMENSION_WEIGHTS,
    AgentArtifact,
    AuditReport,
    AuditTier,
    AuditorVerdict,
    EvidenceGrade,
    FindingKind,
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
from .capabilities import effective_artifact
from .policy import (
    AUDIT_POLICY_VERSION,
    artifact_commitment,
    audit_surface_coverage,
    candidate,
    evidence_summary,
    finding_set_commitment,
    review_decision,
)


#: Findings about funds, keys or code execution: the verifier may dispute them, but not
#: lower their severity (on hand-audited agents it under-rated real ones when it did).
#: Ledger and bytecode facts (onchain-contract-*) are kept too: the verifier only reads source.
_KEEPS_SEVERITY = re.compile(
    r"-ai-(?:unauthorized-payment|foreign-transaction-signing|account-takeover|control-bypass|economic-loss|"
    r"code-execution|secret-exposure)-\d+$|^security-path-(?:untrusted-to-financial-sink|external-transaction-signed|"
    r"key-signs-arbitrary-bytes|untrusted-account-control|untrusted-to-command|secret)|"
    r"^stellar_native-onchain-contract-|^stellar_native-soroban-(?:upgrade|token-move)-")


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
        deep_reviewer=None,
        chain_facts: dict | None = None,
        finding_verifier=None,
    ) -> AuditReport:
        t0 = time.perf_counter()
        deep = tier == AuditTier.DEEP
        self._validate_roster()
        # Commit to what was submitted, then judge what the source can actually do.
        input_hash = artifact_commitment(artifact)
        artifact = effective_artifact(artifact)

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

        verdicts = self._apply_verifiability(artifact, verdicts)
        deep_record: dict = {}
        if deep_reviewer is not None:
            verdicts, deep_record = await self._deep_review(deep_reviewer, artifact, verdicts, chain_facts)
        verification: dict = {}
        if finding_verifier is not None:
            from ..services.finding_verifier import verify_artifact
            verification = await verify_artifact(finding_verifier, artifact, [f for v in verdicts for f in v.findings])
            verdicts = self._apply_disputes(verdicts, verification)
        verdicts = self._require_deep_review(artifact, verdicts, deep_record)
        verdicts = self._consolidate(verdicts)

        score, badge, dim_scores, findings, notes, disagreement, breakdown, assurance = (
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
        if deep_record.get("status") not in (None, "not_run", "unavailable"):
            processors.append(f"anthropic:{deep_record.get('model')}")

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
        decision = review_decision(findings, surface_coverage, score)
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
            decision=decision,
            dimension_scores=dim_scores,
            score_breakdown=breakdown,
            verdicts=verdicts,
            findings=findings,
            judge_notes=notes,
            disagreement_index=disagreement,
            completed_dimensions=[v.dimension.value for v in verdicts],
            limitations=limitations,
            policy_version=AUDIT_POLICY_VERSION,
            input_hash=input_hash,
            finding_set_hash=finding_set_commitment(findings),
            verification=verification,
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
                "observed_capabilities": artifact.code_profile.get("capabilities", {}),
                "enforced_controls": artifact.code_profile.get("controls", {}),
                "observed_tools": [t.name for t in artifact.tools if t.origin == "observed"],
                "attack_paths": sum(
                    1
                    for finding in findings
                    if "-path-" in finding.id or "-systemic-" in finding.id
                ),
            },
            deterministic=not processors,
            deep_review=deep_record,
            external_processors=processors,
        )
        self._last_payouts = payouts

        return report

    @staticmethod
    def _rescore(verdict, findings):
        from .base import BaseAuditor
        return verdict.model_copy(update={
            "findings": findings, "score": BaseAuditor.score_from(findings, verdict.scenarios),
            "coverage": {**verdict.coverage, "findings": len(findings)}})

    def _apply_verifiability(self, artifact, verdicts):
        """Turn unverifiable absence claims into gaps, and add a blocking gap for them.

        "No spending limit" is evidence only where the analyser can see limits. Authority
        in TypeScript or Rust is judged by the deep review; until it reads those files the
        review cannot pass.
        """
        from ..models import Dimension, EvidenceGrade, Finding, FindingKind, Severity
        from .capabilities import unverifiable_control_files
        from .policy import ABSENCE_OF_CONTROL_RULES, DECLARATION_RULES
        unverifiable = unverifiable_control_files(artifact)
        declared_any = any(t.origin == "declared" for t in artifact.tools)
        updated = []
        for verdict in verdicts:
            changed = False
            findings = []
            for finding in verdict.findings:
                if ((unverifiable and finding.id in ABSENCE_OF_CONTROL_RULES)
                        or (not declared_any and finding.id in DECLARATION_RULES)):
                    reason = ("Controls in " + ", ".join(unverifiable[:5]) + " are not visible to data-flow analysis; "
                              "the deep review judges them." if finding.id in ABSENCE_OF_CONTROL_RULES
                              else "No tool declaration was supplied, so there is nothing to contradict.")
                    finding = finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP,
                                                         "detail": finding.detail + " " + reason})
                    changed = True
                findings.append(finding)
            if verdict.dimension is Dimension.SECURITY and unverifiable:
                findings.append(Finding(
                    id="security-controls-unverifiable", dimension=Dimension.SECURITY, severity=Severity.MEDIUM,
                    title="Signing or execution authority is in code the rules cannot verify",
                    detail="Spending limits, recipient checks and approvals in these files must be read to be "
                           "judged. A passing decision requires a completed deep review that read all of them.",
                    evidence=", ".join(unverifiable[:20]), evidence_grade=EvidenceGrade.CONFIRMED,
                    remediation="Run the deep review, or move signing behind a Python policy layer or an on-chain "
                                "spending policy that can be verified.",
                    auditor=verdict.auditor, confidence=0.9, kind=FindingKind.EVIDENCE_GAP))
                changed = True
            updated.append(self._rescore(verdict, findings) if changed else verdict)
        return updated

    def _require_deep_review(self, artifact, verdicts, deep_record: dict):
        """Pattern rules cannot see application logic: a replayable payment proof, an endpoint
        anyone can call, a budget keyed on an address an attacker can rotate. On agents no rule
        author had seen, rules alone passed one with three such high defects. So a passing
        decision needs a completed deep review that read every file holding the agent's
        authority; without one the decision is needs_evidence, never pass."""
        from ..models import Dimension, Finding, FindingKind
        from ..services.deep_review import authority_files
        if not artifact.code_files:
            return verdicts
        needed = authority_files(artifact)
        read = set((deep_record.get("coverage") or {}).get("files_read") or [])
        status = deep_record.get("status") or "not_run"
        unread = sorted(needed - read)
        if status == "completed" and not unread:
            return verdicts
        reason = (f"The deep review did not run ({status})." if status != "completed" else
                  f"The deep review did not read {len(unread)} file(s) holding the agent's authority.")
        gap = Finding(
            id="security-deep-review-incomplete", dimension=Dimension.SECURITY, severity=Severity.MEDIUM,
            title="The code holding the agent's authority was not fully read by the deep review",
            detail=reason + " Pattern rules cannot judge application logic such as replayable payment "
                   "proofs, unauthenticated endpoints or budgets an attacker can sidestep, so the audit "
                   "cannot pass on rules alone.",
            evidence=", ".join(unread[:20]) or status, evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Run the audit with the deep review enabled and enough time to read these files.",
            auditor="security", confidence=0.9, kind=FindingKind.EVIDENCE_GAP)
        out, added = [], False
        for verdict in verdicts:
            if not added and verdict.dimension is Dimension.SECURITY:
                verdict = self._rescore(verdict, [*verdict.findings, gap])
                added = True
            out.append(verdict)
        return out

    @staticmethod
    def _apply_disputes(verdicts, verification: dict):
        """Record each verdict on its finding. A rule finding that independent verification
        refutes, quoting the code that contradicts it, is lowered one level and marked as disputed. It is never removed;
        a candidate-rule finding (policy.CANDIDATE_RULES) is dismissed to a zero-weight note instead. Model-review findings are not lowered: the verifier is a second opinion on the
        pattern rules, which cannot read intent, not a way to talk a risk away."""
        results = {r["finding_id"]: r for r in verification.get("results", []) if r.get("quote_verified")
                   and not str(r.get("quote", "")).lstrip().startswith(("#", "//", "*", "/*"))}
        if not results:
            return verdicts
        out = []
        for verdict in verdicts:
            findings = []
            for f in verdict.findings:
                r = results.get(f.id)
                if r is not None and r.get("verdict") in {"confirmed", "partial", "refuted"}:
                    # Recorded for the decision: a confirmed bypass blocks a pass (policy.actionable_risks).
                    f = f.model_copy(update={"verified": r["verdict"]})
                reviewed = Severity.__members__.get(str((r or {}).get("reviewed_severity", "")).upper())
                if (r is not None and r.get("verdict") in {"confirmed", "partial"} and reviewed is not None
                        and reviewed.rank < f.severity.rank and f.is_risk
                        and f.severity is not Severity.CRITICAL and not _KEEPS_SEVERITY.search(f.id)):
                    # The verifier re-reads the cited code for this one claim. Against hand audits it
                    # corrected the reviewer's habit of rating a level high, but it also lowered real
                    # critical and fund-control findings, so those keep the severity they were given.
                    f = f.model_copy(update={
                        "severity": reviewed,
                        "detail": f.detail + f" Independent verification rates this {reviewed.value}: "
                                  f"{str(r.get('reason', ''))[:240]}"})
                refuted = (r is not None and r.get("verdict") == "refuted" and "-ai-" not in f.id and f.is_risk
                           and not f.id.startswith("stellar_native-onchain-contract-"))  # a source quote cannot refute bytecode
                no_issue = (r is not None and r.get("verdict") in {"confirmed", "partial"} and f.is_risk
                            and str(r.get("reviewed_severity", "")).lower() == "none")
                if (refuted or no_issue) and candidate(f) and not _KEEPS_SEVERITY.search(f.id):
                    # A candidate rule only proposes a defect; refuted at a quoted code line, or
                    # rated as no issue at all, it is dismissed. It stays visible but carries no weight.
                    f = f.model_copy(update={
                        "kind": FindingKind.WARNING, "severity": Severity.INFO,
                        "title": "Dismissed candidate: " + f.title,
                        "detail": f.detail + f" Independent verification {'refutes' if refuted else 'finds no issue in'} this candidate ({r.get('file', '')}:"
                                  f"{r.get('line', '')}): {str(r.get('reason', ''))[:240]}",
                        "confidence": min(f.confidence, 0.3)})
                elif refuted:
                    f = f.model_copy(update={
                        "severity": f.severity.downgrade(1),
                        "detail": f.detail + f" Independent verification disputes this finding ({r.get('file', '')}:"
                                  f"{r.get('line', '')}): {str(r.get('reason', ''))[:240]}",
                        "confidence": min(f.confidence, 0.5)})
                findings.append(f)
            out.append(AuditSwarm._rescore(verdict, findings) if findings != verdict.findings
                       else verdict.model_copy(update={"findings": findings}))
        return out

    def _consolidate(self, verdicts):
        """One finding per defect: see swarm/consolidate.py."""
        from .consolidate import consolidate
        merged = {f.id: f for f in consolidate([f for v in verdicts for f in v.findings])}
        out = []
        for verdict in verdicts:
            findings = [merged[f.id] for f in verdict.findings if f.id in merged]
            out.append(self._rescore(verdict, findings) if findings != verdict.findings else verdict)
        return out

    async def _deep_review(self, reviewer, artifact, verdicts, chain_facts):
        """Add verified model findings to the matching dimension. Never removes a finding."""
        from .base import BaseAuditor
        from .policy import classify_finding
        existing = [f for v in verdicts for f in v.findings]
        result = await reviewer.review(artifact, existing, chain_facts or artifact.chain_authority or None)
        by_dimension: dict = {}
        for finding in result.findings:
            by_dimension.setdefault(finding.dimension, []).append(classify_finding(finding))
        # The unverifiable-controls gap is closed by evidence (every such file was read in a
        # completed review), never by the model's opinion of those files.
        from .capabilities import unverifiable_control_files
        closed = (result.status == "completed"
                  and set(unverifiable_control_files(artifact)) <= set(result.files_read))
        # Files the parser could not read are covered only when the review read each of them;
        # an analyser crash (profile error) is never closed this way.
        unparsed = set(artifact.code_profile.get("unparsed_files", []))
        parsed_gap_closed = (result.status == "completed" and bool(unparsed)
                             and not artifact.code_profile.get("error") and unparsed <= set(result.files_read)
                             and not artifact.raw_metadata.get("source_not_selected"))
        updated = []
        for verdict in verdicts:
            findings = [f for f in verdict.findings
                        if not (closed and f.id == "security-controls-unverifiable")
                        and not (parsed_gap_closed and f.id == "security-source-analysis-incomplete")]
            findings += by_dimension.get(verdict.dimension, [])
            if findings != verdict.findings:
                verdict = self._rescore(verdict, findings)
            updated.append(verdict)
        record = result.report()
        record["unverifiable_controls_resolved"] = closed
        record["unparsed_files_read"] = parsed_gap_closed
        return updated, record

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
