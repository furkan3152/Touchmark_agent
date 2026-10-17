"""A re-audit shows what a fix closed, what remains and what it introduced."""

from __future__ import annotations

import asyncio
from pathlib import Path

from backend.app.config import Settings
from backend.app.services.repo_audit import audit_repository
from backend.app.services.report_diff import compare_reports

DEMO = Path(__file__).resolve().parents[2] / "examples/demo"


def audit(folder):
    return asyncio.run(audit_repository(DEMO / folder, name=folder, purpose="", settings=Settings(_env_file=None),
                                        deep=False))["report"]


def test_fixing_the_treasury_agent_closes_its_risks():
    diff = compare_reports(audit("unsafe-treasury-agent"), audit("safe-treasury-agent"))
    closed = {f["id"] for f in diff["closed"]}
    assert {"security-path-untrusted-to-financial-sink", "security-path-untrusted-to-network"} <= closed
    assert not [f for f in diff["introduced"] if f["severity"] in ("critical", "high")]
    assert diff["before"]["decision"] == "needs_fixes" and diff["after"]["decision"] == "pass"
    assert diff["score_change"] > 50


def test_model_findings_match_by_title_not_running_number():
    before = {"result": {"overall_score": 40}, "findings": [
        {"id": "security-ai-ssrf-3", "title": "Fetch URL from model", "severity": "high", "kind": "risk"}]}
    after = {"result": {"overall_score": 41}, "findings": [
        {"id": "security-ai-ssrf-1", "title": "Fetch  URL from model", "severity": "high", "kind": "risk"}]}
    diff = compare_reports(before, after)
    assert not diff["closed"] and not diff["introduced"] and len(diff["remaining"]) == 1
