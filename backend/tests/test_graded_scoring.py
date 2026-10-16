"""Graded score caps and autonomy warnings."""

from __future__ import annotations

import asyncio
import copy
import json
import math
from pathlib import Path

from backend.app.config import Settings
from backend.app.models import Dimension, EvidenceGrade, Finding, FindingKind, Severity
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.swarm.judge import BLOCKLIST_BAND, FIX_BAND, band_score, score_breakdown
from backend.app.swarm.policy import PASS_SCORE, classify_finding, review_decision

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "agent_corpus.json").read_text())


def risk(i, severity=Severity.HIGH, grade=EvidenceGrade.CONFIRMED, confidence=0.85):
    return Finding(id=f"security-r{i}", dimension=Dimension.SECURITY, severity=severity, title="r",
                   detail="d", evidence_grade=grade, confidence=confidence)


def scored(findings):
    breakdown = score_breakdown(findings)
    actionable = [f for f in findings if f.is_risk and f.severity.rank >= Severity.HIGH.rank]
    return band_score(breakdown["raw_score"], actionable)[0], breakdown


def test_score_falls_with_number_severity_certainty_and_scope():
    one, _ = scored([risk(1)])
    three, _ = scored([risk(1), risk(2), risk(3)])
    inferred, _ = scored([risk(1, grade=EvidenceGrade.INFERRED, confidence=0.5)])
    wide = risk(4)
    wide.evidence = "a.ts:1 x; a.ts:9 y; b.ts:4 z; c.ts:7 w"
    widespread, _ = scored([wide])
    critical, _ = scored([risk(1, Severity.CRITICAL)])
    two_critical, _ = scored([risk(1, Severity.CRITICAL), risk(2, Severity.CRITICAL)])
    assert inferred > one > widespread and one > three
    assert all(FIX_BAND[0] <= s <= FIX_BAND[1] for s in (one, three, inferred, widespread))
    assert BLOCKLIST_BAND[0] <= two_critical < critical <= BLOCKLIST_BAND[1]


def test_breakdown_adds_up_and_gaps_cost_nothing():
    gap = Finding(id="provenance-missing-lockfile", dimension=Dimension.PROVENANCE, severity=Severity.MEDIUM,
                  title="g", detail="d", kind=FindingKind.EVIDENCE_GAP)
    medium = risk(1, Severity.MEDIUM)
    score, breakdown = scored([gap, medium])
    assert [d["id"] for d in breakdown["deductions"]] == ["security-r1"]
    assert breakdown["raw_score"] == round(100 * math.exp(-breakdown["total_deduction"] / 100), 1) == score
    assert 90 < score < 100


def test_one_root_cause_is_not_punished_five_times():
    family = ["economic-no-spend-policy", "security-unbounded-spend", "security-path-controls-not-enforced"]
    restated = [Finding(id=i, dimension=Dimension.SECURITY, severity=Severity.HIGH, title="t", detail="d",
                        evidence_grade=EvidenceGrade.CONFIRMED, confidence=0.85) for i in family]
    distinct = [risk(i) for i in range(3)]
    grouped = score_breakdown(restated)
    assert [d.get("restates") for d in grouped["deductions"]] == [None, "spend_control", "spend_control"]
    assert grouped["total_deduction"] < score_breakdown(distinct)["total_deduction"]


def test_clean_reports_are_not_flattened_to_one_number():
    clean, _ = scored([])
    one_medium, _ = scored([risk(1, Severity.MEDIUM)])
    two_medium, _ = scored([risk(1, Severity.MEDIUM), risk(2, Severity.MEDIUM, grade=EvidenceGrade.INFERRED)])
    assert clean == 100.0 > one_medium > two_medium >= PASS_SCORE


def test_autonomy_findings_are_warnings_with_a_small_penalty():
    f = classify_finding(Finding(id="intent-full-autonomy-over-funds", dimension=Dimension.INTENT,
                                 severity=Severity.HIGH, title="t", detail="d", confidence=0.85))
    assert f.kind is FindingKind.WARNING and not f.is_risk
    full = risk(1).penalty
    assert 0 < f.penalty < full / 3
    coverage = {"deep_core_complete": True}
    assert review_decision([f], coverage, PASS_SCORE + 10) == "pass"


def test_corpus_scores_are_graded_not_plateaued():
    settings = Settings(_env_file=None)
    scores = []
    for case in ("V4-ssrf-fetch-tool", "V9-hardcoded-seed", "V3-exec-llm-code"):
        bundle = copy.deepcopy(CORPUS[case]["bundle"])
        bundle = json.loads(json.dumps(bundle).replace("{{GENERATED_SEED}}", __import__("stellar_sdk").Keypair.random().secret))
        result = asyncio.run(review_source(ReviewRequest(**bundle), settings))
        assert result["decision"] == "needs_fixes"
        scores.append(result["report"]["result"]["overall_score"])
    assert len(set(scores)) == 3 and all(s < PASS_SCORE for s in scores)


def test_bounded_agent_without_approval_passes_with_a_warning():
    # C2 with its approval gate removed: recipients and amounts stay bounded in code.
    bundle = copy.deepcopy(CORPUS["C2-guarded-payments"]["bundle"])
    gate = ('    if not _approved(batch_id, approval_token):\n'
            '        raise PermissionError("human approval required")\n')
    assert gate in bundle["files"]["payroll.py"]
    bundle["files"]["payroll.py"] = bundle["files"]["payroll.py"].replace(gate, "")
    bundle["system_prompt"] = "Prepare payroll."
    result = asyncio.run(review_source(ReviewRequest(**bundle), Settings(_env_file=None)))
    warnings = [f for f in result["report"]["findings"] if f.get("kind") == "warning"]
    assert result["decision"] == "pass" and result["report"]["result"]["overall_score"] >= PASS_SCORE
    assert [w["id"] for w in warnings] == ["intent-full-autonomy-over-funds"]
    assert warnings[0]["severity"] == "low" and result["report"]["result"]["warning_count"] == 1


def test_approval_gate_removes_the_warning():
    result = asyncio.run(review_source(ReviewRequest(**CORPUS["C2-guarded-payments"]["bundle"]), Settings(_env_file=None)))
    assert result["decision"] == "pass"
    assert not [f for f in result["report"]["findings"] if f.get("kind") == "warning"]


def test_very_bad_agents_still_differ():
    bad, _ = scored([risk(i, Severity.CRITICAL) for i in range(4)])
    worse, _ = scored([risk(i, Severity.CRITICAL) for i in range(8)])
    assert 0 < worse < bad


def test_report_breakdown_matches_the_findings_and_the_score():
    bundle = copy.deepcopy(CORPUS["V4-ssrf-fetch-tool"]["bundle"])
    result = asyncio.run(review_source(ReviewRequest(**bundle), Settings(_env_file=None)))
    report = result["report"]
    breakdown = report["result"]["score_breakdown"]
    titles = {f["id"]: f["title"] for f in report["findings"]}
    assert breakdown["deductions"] and all(d["title"] == titles[d["id"]] for d in breakdown["deductions"])
    assert breakdown["score"] == report["result"]["overall_score"]
