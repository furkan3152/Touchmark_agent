"""Stellar addresses are not accused without evidence.

Regression tests: deriving a "high risk / mixer_proximity" from the address hash when
no screening provider is configured gave clean accounts CRITICAL findings. Without
screening, the result must be a scope finding, not a claim."""

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

# Validly generated test public keys; there is no evidence that they are risky.
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
    """Without a provider no address may be stamped 'high risk'."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(wallet)))

    screening_hits = [f for f in verdict.findings if f.id.startswith("wallet-screening-hit")]
    assert screening_hits == []
    assert not any(f.severity == Severity.CRITICAL for f in verdict.findings)


def test_screening_gap_reported_as_scope_not_claim(settings, run):
    """Without screening a single LOW coverage finding is produced."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(VERIFIED[0])))

    gaps = [f for f in verdict.findings if f.id.endswith("wallet-screening-unavailable")]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.severity == Severity.LOW
    # The coverage gap *itself* is a confirmed fact (there really is no provider).
    assert gap.evidence_grade == EvidenceGrade.CONFIRMED
    assert "coverage" in gap.detail.lower() or "scope" in gap.detail.lower()


def test_screening_not_counted_as_passed_scenario(settings, run):
    """Screening that did not run must not count as a passed scenario (no score inflation)."""
    checker = ComplianceAuditor(settings)
    verdict = run(checker.run(_artifact(VERIFIED[1])))

    ids = {s.scenario_id for s in verdict.scenarios}
    assert "C-06" not in ids


def test_screening_gap_costs_only_a_few_points(settings, run):
    """The coverage finding must cost little; the old CRITICAL took ~25 points."""
    checker = ComplianceAuditor(settings)
    with_wallet = run(checker.run(_artifact(VERIFIED[2])))
    without = run(checker.run(_artifact("")))

    delta = without.score - with_wallet.score
    assert 0 <= delta <= 5, (without.score, with_wallet.score)


def test_verified_contracts_score_consistently(settings, run):
    """Verified contracts with the same profile must not score differently by address hash.

    The old random screening gave contracts with identical behaviour different scores,
    such as 83.7 or 82.6, depending on their address; determinism must come from the
    evidence, not the address.
    """
    checker = ComplianceAuditor(settings)
    scores = {w: run(checker.run(_artifact(w))).score for w in VERIFIED}

    assert len(set(round(s, 3) for s in scores.values())) == 1, scores
