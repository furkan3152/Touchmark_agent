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


# ----------------------------------------------------------------- payment bypasses no verifier checked
def test_an_unverified_medium_payment_bypass_holds_back_a_pass():
    from backend.app.swarm.policy import review_decision
    complete = {"deep_core_complete": True}
    # Rule ids other tracks emit, with and without a stable-id suffix: matched by pattern.
    for fid in ("security-ai-control-bypass-1", "security-x402-spend-controls-disabled",
                "security-mpp-store-missing-1a2b3c4d", "security-x402-settle-unchecked-0f0e0d0c",
                "x402-verify-without-settle-89abcdef", "security-x402-requirements-from-payer",
                "stellar_native-tx-hash-proof-unbound-01234567", "security-path-sponsor-rebuild-unchecked"):
        assert review_decision([_f(fid, Severity.MEDIUM)], complete, 90.0) == "needs_evidence", fid
        assert review_decision([_f(fid, Severity.MEDIUM, verified="unverifiable")], complete, 90.0) == "needs_evidence"
        assert review_decision([_f(fid, Severity.MEDIUM, verified="refuted")], complete, 90.0) == "pass"
        assert review_decision([_f(fid, Severity.MEDIUM, verified="confirmed")], complete, 90.0) == "needs_fixes"
        assert review_decision([_f(fid, Severity.LOW)], complete, 90.0) == "pass"
    # Near misses: other rules, and a needs_fixes verdict that the gate never softens.
    for fid in ("security-path-x402-payment-unbounded-test", "security-x402", "reliability-ai-functional-defect-2",
                "security-path-untrusted-to-network", "x402-settle-unchecked-notahexid"):
        assert review_decision([_f(fid, Severity.MEDIUM)], complete, 90.0) == "pass", fid
    both = [_f("security-x402-settle-unchecked", Severity.MEDIUM), _f("security-path-untrusted-to-financial-sink")]
    assert review_decision(both, complete, 50.0) == "needs_fixes"


def test_a_deep_review_that_times_out_keeps_every_deterministic_finding():
    import asyncio

    from backend.app.config import Settings
    from backend.app.models import AgentArtifact, AuditTier, SourceKind
    from backend.app.services.deep_review import DeepReviewResult

    class TimedOut:
        async def review(self, artifact, existing, chain_facts):
            return DeepReviewResult(status="timeout", note="stopped at its time limit")

    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="a", system_prompt="Pays vendors.",
                             code_files={"src/pay.py": "def pay(to, amount):\n    tx.sign(key)\n"})
    swarm = lambda: AuditSwarm(Settings(_env_file=None, stellar_network="offline"))  # noqa: E731
    plain = asyncio.run(swarm().run(artifact, "a", AuditTier.DEEP))
    reviewed = asyncio.run(swarm().run(artifact, "b", AuditTier.DEEP, deep_reviewer=TimedOut()))
    assert [(f.id, f.severity) for f in reviewed.findings] == [(f.id, f.severity) for f in plain.findings]
    assert reviewed.deep_review["status"] == "timeout"
