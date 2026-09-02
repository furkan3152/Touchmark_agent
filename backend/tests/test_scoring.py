"""EvidenceGrade-based scoring and badge ceiling tests.

The main issue here is: direct evidence (CONFIRMED) and inference (INFERRED/SIMULATED)
must not be penalized with the same weight, and only CONFIRMED must enforce the badge ceiling."""

from __future__ import annotations

from backend.app.models import (
    Badge,
    Dimension,
    EvidenceGrade,
    Finding,
    ScenarioResult,
    Severity,
)
from backend.app.swarm.base import BaseAuditor


def finding(
    slug: str,
    severity: Severity,
    grade: EvidenceGrade = EvidenceGrade.CONFIRMED,
    confidence: float = 1.0,
    dimension: Dimension = Dimension.SECURITY,
) -> Finding:
    return Finding(
        id=slug,
        dimension=dimension,
        severity=severity,
        title=slug,
        detail="test",
        evidence_grade=grade,
        confidence=confidence,
    )


# --------------------------------------------------------------- ceza ağırlıkları
def test_penalty_scales_with_evidence_grade():
    confirmed = finding("a", Severity.HIGH, EvidenceGrade.CONFIRMED)
    inferred = finding("b", Severity.HIGH, EvidenceGrade.INFERRED)
    simulated = finding("c", Severity.HIGH, EvidenceGrade.SIMULATED)

    assert confirmed.penalty > inferred.penalty > simulated.penalty
    assert inferred.penalty == confirmed.penalty * 0.6
    assert round(simulated.penalty, 6) == round(confirmed.penalty * 0.35, 6)


def test_confidence_floor_is_applied():
    low = finding("a", Severity.CRITICAL, confidence=0.1)
    # 0.4 taban uygulanır, 0.1 değil
    assert low.penalty == Severity.CRITICAL.weight * 1.0 * 0.4


def test_severity_downgrade():
    assert Severity.CRITICAL.downgrade() is Severity.HIGH
    assert Severity.HIGH.downgrade(2) is Severity.LOW
    assert Severity.LOW.downgrade(5) is Severity.INFO


# ------------------------------------------------------------------ score_from
def test_score_from_has_diminishing_returns():
    """Aynı ciddiyette çok bulgu bir boyutu sıfırlamamalı."""
    many = [finding(f"f{i}", Severity.HIGH, EvidenceGrade.INFERRED) for i in range(10)]
    score = BaseAuditor.score_from(many, [])
    assert score > 0.0, "10 adet INFERRED high bulgusu skoru sıfırlamamalı"

    one = BaseAuditor.score_from([many[0]], [])
    assert one > score


def test_score_from_penalises_failed_scenarios():
    scenarios = [
        ScenarioResult(scenario_id="S-1", name="a", passed=True),
        ScenarioResult(scenario_id="S-2", name="b", passed=False),
    ]
    with_fail = BaseAuditor.score_from([], scenarios)
    all_pass = BaseAuditor.score_from(
        [], [ScenarioResult(scenario_id="S-1", name="a", passed=True)]
    )
    assert all_pass == 100.0
    assert with_fail == 94.0  # 1/2 başarısız INFERRED senaryo → 6 puan


def test_confirmed_failed_scenario_gets_full_penalty():
    scenarios = [
        ScenarioResult(scenario_id="S-1", name="a", passed=True),
        ScenarioResult(
            scenario_id="S-2",
            name="b",
            passed=False,
            evidence_grade=EvidenceGrade.CONFIRMED,
            evidence="canlı Stellar probe başarısız",
        ),
    ]
    assert BaseAuditor.score_from([], scenarios) == 90.0


def test_clean_agent_scores_full():
    assert BaseAuditor.score_from([], []) == 100.0


def test_confirmed_critical_costs_more_than_inferred_critical():
    confirmed = BaseAuditor.score_from([finding("a", Severity.CRITICAL)], [])
    inferred = BaseAuditor.score_from(
        [finding("a", Severity.CRITICAL, EvidenceGrade.INFERRED)], []
    )
    assert confirmed < inferred


# ---------------------------------------------------------------- badge tavanı
def test_blocks_badge_only_for_confirmed():
    assert EvidenceGrade.CONFIRMED.blocks_badge is True
    assert EvidenceGrade.INFERRED.blocks_badge is False
    assert EvidenceGrade.SIMULATED.blocks_badge is False


def test_badge_thresholds():
    from backend.app.swarm.judge import SynthesisJudge

    assert SynthesisJudge.badge_for(92.0) is Badge.SAFE
    assert SynthesisJudge.badge_for(85.0) is Badge.SAFE
    assert SynthesisJudge.badge_for(84.9) is Badge.CAUTION
    assert SynthesisJudge.badge_for(65.0) is Badge.CAUTION
    assert SynthesisJudge.badge_for(64.0) is Badge.HIGH_RISK
    assert SynthesisJudge.badge_for(39.9) is Badge.BLOCKLIST
