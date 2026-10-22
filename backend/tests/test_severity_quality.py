"""Severity that the evidence supports, and one finding per defect.

From hand audits of 23 Stellar agents: impression-based severities ran a level high, the
verifier corrected that but also lowered real critical findings, and the same defect was
often reported twice. Each test pins one of those behaviours."""

from __future__ import annotations

from backend.app.models import AuditorVerdict, Dimension, Finding, FindingKind, Severity
from backend.app.swarm.consolidate import consolidate, fold_absence_notes, merge_duplicates
from backend.app.swarm.orchestrator import AuditSwarm


def _f(fid: str, sev: Severity = Severity.HIGH, evidence: str = "src/a.ts:10 `x`", **kw) -> Finding:
    return Finding(id=fid, dimension=Dimension.SECURITY, severity=sev, title=fid, detail="d.", evidence=evidence,
                   auditor="t", **kw)


def test_a_repeated_model_finding_is_folded_into_the_first_and_distinct_ones_stay():
    first = _f("security-ai-control-bypass-1")
    again = _f("security-ai-control-bypass-5", Severity.CRITICAL)
    other_kind = _f("reliability-ai-functional-defect-6")                       # same line, different defect
    other_line = _f("security-ai-control-bypass-7", evidence="src/a.ts:40 `y`")
    out = merge_duplicates([first, again, other_kind, other_line])
    assert [f.id for f in out] == ["security-ai-control-bypass-1", "reliability-ai-functional-defect-6",
                                   "security-ai-control-bypass-7"]
    assert out[0].severity == Severity.CRITICAL and "Also reported as security-ai-control-bypass-5" in out[0].detail


def test_a_model_finding_corroborates_the_rule_finding_of_the_same_kind_only():
    rule = _f("security-path-untrusted-to-financial-sink", Severity.CRITICAL, "src/a.ts:12 `tx.sign(k)`", confidence=0.9)
    same = _f("security-ai-unauthorized-payment-2", Severity.HIGH, "src/a.ts:11 `pay(to)`")
    unrelated = _f("reliability-ai-reliability-failure-3", Severity.MEDIUM, "src/a.ts:12 `tx.sign(k)`")
    out = merge_duplicates([rule, same, unrelated])
    assert [f.id for f in out] == [rule.id, unrelated.id]
    assert out[0].severity == Severity.CRITICAL and out[0].confidence > rule.confidence


def test_absence_notes_become_warnings_only_when_a_concrete_payment_finding_exists():
    note = _f("economic-no-spend-policy", evidence="")
    alone = fold_absence_notes([note])
    assert alone[0].kind is FindingKind.RISK
    oversight = _f("compliance-no-human-oversight", evidence="", kind=FindingKind.WARNING)
    out = consolidate([note, oversight, _f("security-ai-unauthorized-payment-1")])
    assert all(f.kind is FindingKind.WARNING and f.severity is Severity.LOW for f in out[:2])
    assert "security-ai-unauthorized-payment-1" in out[0].detail


def test_the_verifier_lowers_an_overrated_finding_but_not_a_critical_or_fund_finding():
    def run(fid, sev):
        verdict = AuditorVerdict(auditor="a", dimension=Dimension.SECURITY, score=50.0, findings=[_f(fid, sev)])
        result = {"results": [{"finding_id": fid, "verdict": "partial", "reviewed_severity": "low",
                               "quote_verified": True, "quote": "x = 1", "reason": "narrow"}]}
        return AuditSwarm._apply_disputes([verdict], result)[0].findings[0]
    lowered = run("reliability-ai-functional-defect-1", Severity.HIGH)
    assert lowered.severity == Severity.LOW and "Independent verification rates this low" in lowered.detail
    assert run("reliability-ai-functional-defect-2", Severity.CRITICAL).severity == Severity.CRITICAL
    assert run("security-ai-unauthorized-payment-3", Severity.HIGH).severity == Severity.HIGH
    assert run("security-path-untrusted-to-financial-sink", Severity.HIGH).severity == Severity.HIGH
