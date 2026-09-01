"""Uçtan uca: pipeline güvenli ve zafiyetli ajanı doğru ayırt ediyor mu?

Bu dosya projenin en önemli davranışsal garantisini korur: zafiyetli ajan
güvenli ajandan belirgin biçimde daha düşük skor almalı, ama güvenli ajan da
yanlış pozitiflerle blocklist'e düşmemeli.
"""

from __future__ import annotations

import pytest

from backend.app.ingestion import IngestionService, IngestRequest
from backend.app.models import (
    DIMENSION_WEIGHTS,
    AuditTier,
    Badge,
    Dimension,
    EvidenceGrade,
    Severity,
)
from backend.app.services.pipeline import AuditPipeline

EXPECTED_DIMENSIONS = len(DIMENSION_WEIGHTS)


def _audit(settings, repo_root, folder: str, tier: AuditTier):
    pipeline = AuditPipeline(settings)
    ingestion = IngestionService(settings)

    async def go():
        artifact = await ingestion.ingest(
            IngestRequest(kind="repo", local_path=str(repo_root / "examples" / folder))
        )
        pipeline.store.put_agent(artifact)
        job = pipeline.create_job(artifact.id, tier)
        await pipeline.fund_job(job.id)
        return artifact, await pipeline.run_job(job.id)

    import asyncio

    artifact, job = asyncio.run(go())
    return pipeline, artifact, job


@pytest.fixture(scope="module")
def _cache():
    return {}


# ------------------------------------------------------------------ safe agent
def test_safe_agent_is_not_blocklisted(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    report = job.report

    assert report is not None
    assert report.badge in (Badge.SAFE, Badge.CAUTION), (
        f"iyi yapılandırılmış ajan {report.badge} aldı — yanlış pozitif "
        f"(skor {report.overall_score})"
    )
    assert report.overall_score >= 65.0


def test_safe_agent_dimensions_are_healthy(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    scores = {d.dimension: d.score for d in job.report.dimension_scores}

    assert len(scores) == EXPECTED_DIMENSIONS, "tüm boyutlar skorlanmalı"
    assert Dimension.STELLAR_NATIVE in scores, "Stellar'a özgü boyut çalışmalı"
    # hiçbir boyut çıkarım kaynaklı olarak sıfırlanmamalı
    assert min(scores.values()) > 40.0, scores


# ------------------------------------------------------- vulnerable agent
def test_vulnerable_agent_is_flagged(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "vulnerable_agent", AuditTier.DEEP)
    report = job.report

    assert report.badge in (Badge.HIGH_RISK, Badge.BLOCKLIST), (
        f"kasıtlı zafiyetli ajan {report.badge} aldı (skor {report.overall_score})"
    )
    counts = report.counts()
    assert counts["critical"] >= 1, counts


def test_vulnerable_agent_has_confirmed_evidence(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "vulnerable_agent", AuditTier.DEEP)
    confirmed_critical = [
        f
        for f in job.report.findings
        if f.severity is Severity.CRITICAL and f.evidence_grade is EvidenceGrade.CONFIRMED
    ]
    assert confirmed_critical, "gömülü özel anahtar / eval gibi doğrudan kanıt beklenir"
    # doğrudan kanıt dosya/satır referansı taşımalı
    assert any(f.evidence for f in confirmed_critical)


def test_security_dimension_reacts_to_static_findings(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "vulnerable_agent", AuditTier.DEEP)
    scores = {d.dimension: d.score for d in job.report.dimension_scores}
    assert scores[Dimension.SECURITY] < 40.0, scores


# ------------------------------------------------------------ discrimination
def test_safe_scores_clearly_above_vulnerable(settings, repo_root):
    _, _, safe_job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    _, _, vuln_job = _audit(settings, repo_root, "vulnerable_agent", AuditTier.DEEP)

    gap = safe_job.report.overall_score - vuln_job.report.overall_score
    assert gap >= 25.0, (
        f"ayrım gücü zayıf: safe={safe_job.report.overall_score} "
        f"vuln={vuln_job.report.overall_score}"
    )


# ------------------------------------------------- rapor / attestation / badge
def test_report_is_published_and_attested(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    report = job.report

    assert report.report_cid.startswith("bafkrei")
    assert report.report_uri
    assert report.attestation is not None
    # Registry yapılandırılmadı: zincir sonucu veya sahte hash üretilmemeli.
    assert report.attestation.mode == "unavailable"
    assert report.attestation.confirmed is False
    assert report.attestation.tx_hash == ""
    assert report.attestation.invocation_json == ""


def test_core_validation_does_not_claim_payment_or_settlement(settings, repo_root):
    _, _, job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    escrow = job.escrow

    assert escrow is not None
    assert escrow.mode == "not_required"
    assert escrow.amount_usdc == 0.0
    assert escrow.settled is False
    assert escrow.platform_fee_usdc == 0.0
    assert escrow.swarm_payout_usdc == 0.0
    assert job.state.value == "completed"


def test_badge_record_and_markdown_are_produced(settings, repo_root):
    pipeline, artifact, job = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)

    record = pipeline.badges.get(artifact.agent_wallet or artifact.id)
    assert record is not None
    assert record["badge"] == job.report.badge.value
    assert record["expires_at"] > record["issued_at"]
    assert record["attestation_confirmed"] is False
    assert record["attestation_tx_hash"] == ""

    md = pipeline.markdown_for(job.id)
    assert "AgentVeritas" in md
    assert job.report.badge.value in md

    payload = pipeline.json_for(job.id)
    assert payload["schema"] == "agentveritas.audit.v2"
    assert payload["policy_version"].startswith("agentveritas.stellar.policy.")
    assert payload["input_hash"].startswith("sha256:")
    assert payload["finding_set_hash"].startswith("sha256:")
    assert payload["result"]["overall_score"] == job.report.overall_score
    assert payload["result"]["badge"] == job.report.badge.value
    assert payload["result"]["assurance_level"] == job.report.assurance_level.value
    assert payload["result"]["coverage"]["completed_auditors"] == EXPECTED_DIMENSIONS
    assert payload["result"]["deterministic"] is True
    assert payload["agent"]["id"] == artifact.id


def test_leaderboard_updates_after_audit(settings, repo_root):
    pipeline, _, _ = _audit(settings, repo_root, "safe_agent", AuditTier.BASIC)
    rows = pipeline.swarm.leaderboard()

    assert len(rows) == EXPECTED_DIMENSIONS
    assert all(r["audits"] >= 1 for r in rows)
    assert all(800.0 <= r["elo"] <= 2400.0 for r in rows)
