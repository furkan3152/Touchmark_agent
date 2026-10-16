"""Graded score caps and autonomy warnings."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

from backend.app.config import Settings
from backend.app.models import Dimension, EvidenceGrade, Finding, FindingKind, Severity
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.swarm.judge import BLOCKLIST_CEILING, HIGH_RISK_CEILING, graded_ceiling
from backend.app.swarm.policy import PASS_SCORE, classify_finding, review_decision

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "agent_corpus.json").read_text())


def risk(i, severity=Severity.HIGH, grade=EvidenceGrade.CONFIRMED, confidence=0.85):
    return Finding(id=f"security-r{i}", dimension=Dimension.SECURITY, severity=severity, title="r",
                   detail="d", evidence_grade=grade, confidence=confidence)


def test_ceiling_falls_with_number_severity_and_certainty():
    one = graded_ceiling([risk(1)])
    three = graded_ceiling([risk(1), risk(2), risk(3)])
    inferred = graded_ceiling([risk(1, grade=EvidenceGrade.INFERRED, confidence=0.5)])
    critical = graded_ceiling([risk(1, Severity.CRITICAL)])
    assert graded_ceiling([]) is None
    assert inferred > one > three
    assert all(c < PASS_SCORE for c in (one, three, inferred)) and one <= HIGH_RISK_CEILING
    assert critical <= BLOCKLIST_CEILING and critical > graded_ceiling([risk(1, Severity.CRITICAL), risk(2, Severity.CRITICAL)])


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
