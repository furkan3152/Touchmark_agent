"""False positive discipline — Stellar addresses should not be accused without evidence.

These tests are a regression test: when the wallet screening provider is not configured,
a random "high risk / mixer_proximity" was previously generated from the sha256 of the address,
and in the previous implementation risk was derived from the address hash, causing clean accounts to get CRITICAL.
Now, if there is no screening, a scope finding must be generated, not a claim."""

from __future__ import annotations

import pytest

from backend.app.models import (
    AgentArtifact,
    EvidenceGrade,
    OnchainActivity,
    Severity,
    SourceKind,
)
from backend.app.swarm.compliance import ComplianceAuditor

# Geçerli biçimde üretilmiş test public key'leri; riskli olduklarına dair kanıt yok.
VERIFIED = [
    "GBSTXJ5BPYC7BWVXQNWHJVS675ZUOANGOQMC3UA4NSAJ4CYAZKCP3IF2",
    "GB3ZOFUNZ7EVPA7BMEKCYHMP7I76IP4O6MWZJOOOJ32ZY2R4J2EDHNRD",
    "GDPM6KGOD7GHXSWASB3GHZQZHYUSQVIRC64TR6KWMLUY4YHS5NV66FJK",
    "GCOEQ5XONZCDN6WUOV5KPZWJC4U4BAZW43URRA7PQOXYCZ7ZKDUV6IGU",
    "GCXA4DQZENE7EYEEIRNRAL4AVJUNEZSMYYSAG2EIK4UXE3HTYVVXUQAV",
    "GBKYK6R2PIRDBZYRLFWU525FXEPRRK7UPRGRV3SSDCXU76JZLTUNCZWR",
    "GBNCVK4YPQDS3YZRSG5VWRTTXZZSUPWQYAJAQZ6DJDM5XQBNDZ3U2PJY",
    "GBVAOG2QFIQRM63J2KQN23SLOWZ2CRMRSGWFEL6M7VYR3QTDXFOWGWVX",
    "GCXUOI4LMO4AONW2Y6JQHWFE6ISTC6UXNSBCJRXOAJTWYMZBGW2XODGL",
]


def _artifact(wallet: str) -> AgentArtifact:
    return AgentArtifact(
        name="onchain-agent",
        source_kind=SourceKind.ONCHAIN_ADDRESS,
        source_ref=wallet,
        agent_wallet=wallet,
        onchain=OnchainActivity(data_source="indexer", tx_count=25, is_contract=True),
    )


@pytest.mark.parametrize("wallet", VERIFIED)
def test_no_fabricated_screening_risk(settings, run, wallet):
    """Sağlayıcı yoksa hiçbir adres 'yüksek risk' damgası almamalı."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(wallet)))

    screening_hits = [f for f in verdict.findings if f.id.startswith("wallet-screening-hit")]
    assert screening_hits == []
    assert not any(f.severity == Severity.CRITICAL for f in verdict.findings)


def test_screening_gap_reported_as_scope_not_claim(settings, run):
    """Tarama yapılmadıysa tek bir LOW kapsam bulgusu üretilir."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(VERIFIED[0])))

    gaps = [f for f in verdict.findings if f.id.endswith("wallet-screening-unavailable")]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.severity == Severity.LOW
    # Kapsam boşluğunun *kendisi* doğrulanmış bir olgudur (sağlayıcı gerçekten yok).
    assert gap.evidence_grade == EvidenceGrade.CONFIRMED
    assert "kapsam" in gap.detail.lower() or "taranmadı" in gap.detail.lower()


def test_screening_not_counted_as_passed_scenario(settings, run):
    """Yapılmamış tarama 'geçti' senaryosu olarak sayılmamalı (skor şişmesin)."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(VERIFIED[1])))

    ids = {s.scenario_id for s in verdict.scenarios}
    assert "C-06" not in ids


def test_screening_gap_costs_only_a_few_points(settings, run):
    """Kapsam bulgusunun bedeli küçük olmalı; eski CRITICAL ~25 puan götürüyordu."""
    checker = ComplianceAuditor(settings)
    with_wallet = run(checker.run(_artifact(VERIFIED[2])))
    without = run(checker.run(_artifact("")))

    delta = without.score - with_wallet.score
    assert 0 <= delta <= 5, (without.score, with_wallet.score)


def test_verified_contracts_score_consistently(settings, run):
    """Aynı profildeki doğrulanmış kontratlar adres hash'ine göre farklı skor almamalı.

    Eski rastgele tarama, aynı davranışa sahip kontratlara adresine bağlı olarak
    83.7 veya 82.6 gibi farklı skorlar veriyordu; determinizm adresten değil
    kanıttan gelmelidir.
    """
    checker = ComplianceAuditor(settings)
    scores = {w: run(checker.run(_artifact(w))).score for w in VERIFIED}

    assert len(set(round(s, 3) for s in scores.values())) == 1, scores
