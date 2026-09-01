"""Continuous monitoring must react to evidence drift, not score alone."""

from __future__ import annotations

from backend.app.models import (
    AgentArtifact,
    AssuranceLevel,
    AuditReport,
    AuditTier,
    Badge,
    Dimension,
    EvidenceGrade,
    Finding,
    Severity,
    SourceKind,
)
from backend.app.services.pipeline import AuditPipeline


def _report(agent_id, *, finding_hash, assurance, findings=None):
    return AuditReport(
        job_id=f"job_{finding_hash}",
        agent_id=agent_id,
        agent_name="stellar-monitored",
        tier=AuditTier.BASIC,
        overall_score=80,
        badge=Badge.CAUTION,
        findings=findings or [],
        finding_set_hash=finding_hash,
        assurance_level=assurance,
    )


def test_monitor_alerts_new_confirmed_risk_and_assurance_downgrade(settings, run, monkeypatch):
    pipeline = AuditPipeline(settings)
    artifact = AgentArtifact(source_kind=SourceKind.WIZARD, name="stellar-monitored")
    pipeline.store.put_agent(artifact)
    pipeline.subscribe_monitor(artifact.id, interval_minutes=15, prepaid_usdc=0)

    risk = Finding(
        id="security-new-critical",
        dimension=Dimension.SECURITY,
        severity=Severity.CRITICAL,
        title="new risk",
        detail="new risk",
        evidence="contract/src/lib.rs:10",
        evidence_grade=EvidenceGrade.CONFIRMED,
    )
    reports = iter(
        [
            _report(artifact.id, finding_hash="sha256:first", assurance=AssuranceLevel.VERIFIED),
            _report(
                artifact.id,
                finding_hash="sha256:second",
                assurance=AssuranceLevel.PARTIAL,
                findings=[risk],
            ),
        ]
    )

    async def fake_run(*args, **kwargs):
        del args, kwargs
        return next(reports)

    monkeypatch.setattr(pipeline.swarm, "run", fake_run)
    run(pipeline.monitor_tick(force=True))
    second = run(pipeline.monitor_tick(force=True))[0]

    assert second["drift"] == 0
    assert second["finding_set_changed"] is True
    assert second["new_confirmed_risks"] == ["security-new-critical"]
    assert any("yeni doğrulanmış" in alert for alert in second["alerts"])
    assert any("kanıt güvencesi düştü" in alert for alert in second["alerts"])
