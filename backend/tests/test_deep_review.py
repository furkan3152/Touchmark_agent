"""Deep review loop, verification gate and merge rules, with a scripted model client."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.app.config import Settings
from backend.app.models import AgentArtifact, AuditTier, SourceKind, ToolSpec
from backend.app.services import deep_review
from backend.app.services.deep_review import DeepReviewer
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.swarm.orchestrator import AuditSwarm

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "agent_corpus.json").read_text())


def call(name, **args):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}_{len(args)}_{id(args)}", name=name, input=args)


def reply(*blocks, stop="tool_use"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=100, output_tokens=50,
                                                 cache_read_input_tokens=80, cache_creation_input_tokens=0))


class ScriptedClient:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        if not self.turns:
            return reply(SimpleNamespace(type="text", text="done"), stop="end_turn")
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn


def bundle(case_id):
    return copy.deepcopy(CORPUS[case_id]["bundle"])


def review(case_id, client, settings_overrides=None):
    b = bundle(case_id)
    b.update(ai_assistance=True, external_processing_consent=True)
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5")
    original = deep_review.reviewer_from_settings
    deep_review.reviewer_from_settings = lambda settings: reviewer
    try:
        return asyncio.run(review_source(ReviewRequest(**b), Settings(_env_file=None)))
    finally:
        deep_review.reviewer_from_settings = original


OPERATING = call("describe_operating_model", purpose="Pays payroll", triggers="Operator call",
                 example_run="Operator approves batch, agent pays", trust_boundaries=["operator"],
                 assets_at_risk=["XLM balance"])


def test_verified_model_finding_enters_the_decision():
    # C2 passes on rules alone. A verified model finding must be able to change that.
    client = ScriptedClient([
        reply(OPERATING),
        reply(call("record_finding", category="replay_or_idempotency", severity="high",
                   title="Daily cap resets on restart", file="payroll.py", line=12,
                   evidence_quote='_spent_today = Decimal("0")',
                   attack_scenario="Restart the worker to reset the cap and pay the daily cap again.",
                   stellar_impact="Repeated payroll payments from the treasury.",
                   remediation="Persist spent totals with the ledger sequence.")),
        reply(call("finish", summary="One replay issue.")),
    ])
    result = review("C2-guarded-payments", client)
    ids = [f["id"] for f in result["report"]["findings"]]
    assert any(i.startswith("stellar_native-ai-replay-or-idempotency") for i in ids)
    assert result["decision"] == "needs_fixes"
    deep = result["report"]["deep_review"]
    assert deep["status"] == "completed" and deep["operating_model"]["purpose"] == "Pays payroll"
    assert result["report"]["result"]["deterministic"] is False


def test_unverifiable_claims_are_rejected_and_do_not_change_the_decision():
    client = ScriptedClient([
        reply(OPERATING,
              call("record_finding", category="secret_exposure", severity="critical", title="Invented",
                   file="payroll.py", line=3, evidence_quote="print(SECRET)", attack_scenario="x",
                   stellar_impact="x", remediation="x"),
              call("record_finding", category="secret_exposure", severity="critical", title="No such file",
                   file="missing.py", line=1, evidence_quote="anything", attack_scenario="x",
                   stellar_impact="x", remediation="x")),
        reply(call("finish", summary="nothing verified")),
    ])
    result = review("C2-guarded-payments", client)
    deep = result["report"]["deep_review"]
    assert deep["accepted_findings"] == []
    assert {r["reason"] for r in deep["rejected_claims"]} == {"quote not found at the cited line", "unknown file"}
    assert result["decision"] == "pass"


def test_model_cannot_talk_the_audit_out_of_a_rule_finding():
    client = ScriptedClient([
        reply(OPERATING),
        reply(call("assess_flow", flow_id="F1", verdict="mitigated", reason="The comment says it is safe.",
                   file="agent/main.py", line=16, evidence_quote="tx.sign(kp)")),
        reply(call("finish", summary="claims mitigated")),
    ])
    result = review("V1-memo-injection-payment", client)
    assert result["decision"] == "needs_fixes"
    assert "security-path-untrusted-to-financial-sink" in result["priority_finding_ids"]
    assessment = result["report"]["deep_review"]["flow_assessments"][0]
    assert assessment["verdict"] == "mitigated" and assessment["quote_verified"] is True


@pytest.mark.parametrize("failure,status", [
    (RuntimeError("provider down"), "unavailable"),
    (reply(stop="refusal"), "refused"),
])
def test_provider_failure_or_refusal_keeps_the_rule_audit(failure, status):
    result = review("V4-ssrf-fetch-tool", ScriptedClient([failure]))
    assert result["report"]["deep_review"]["status"] == status
    assert result["decision"] == "needs_fixes"
    assert "security-path-untrusted-to-network" in result["priority_finding_ids"]


def test_request_shape_uses_strict_tools_adaptive_thinking_and_fallbacks():
    client = ScriptedClient([reply(call("finish", summary="ok"))])
    review("C1-readonly-summarizer", client)
    request = client.requests[0]
    assert request["model"] == "claude-sonnet-5-5"
    assert request["thinking"] == {"type": "adaptive"}
    assert request["output_config"] == {"effort": "high"}
    assert request["fallbacks"] == "default" and request["betas"] == ["server-side-fallback-2026-07-01"]
    assert "tool_choice" not in request
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in request["tools"])
    pack = request["messages"][0]["content"][0]["text"]
    assert '"observed_capabilities"' in pack and '"flows"' in pack and '"onchain_authority"' in pack


def test_reviewer_is_only_built_with_explicit_enablement_and_key():
    assert deep_review.reviewer_from_settings(Settings(_env_file=None)) is None
    assert deep_review.reviewer_from_settings(Settings(_env_file=None, enable_deep_review=True)) is None
    reviewer = deep_review.reviewer_from_settings(
        Settings(_env_file=None, enable_deep_review=True, anthropic_api_key="test-key-not-real"))
    assert reviewer is not None and reviewer.model == "claude-sonnet-5-5"


def test_tool_loop_tools_read_and_search_source():
    artifact = AgentArtifact(source_kind=SourceKind.UPLOAD, name="x",
                             code_files={"a.py": "def pay(x):\n    send(x)\n"})
    reviewer = DeepReviewer(ScriptedClient([]), model="m")
    result = deep_review.DeepReviewResult()
    assert "2:     send(x)" in reviewer._run_tool("read_source", {"path": "a.py", "start_line": 1, "end_line": 5}, artifact, {}, result)
    assert "a.py:2" in reviewer._run_tool("search_source", {"pattern": r"send\("}, artifact, {}, result)
    assert "Destination must come" in reviewer._run_tool("stellar_reference", {"topic": "payments"}, artifact, {}, result)


def test_model_quotes_of_secret_literals_are_masked_in_the_report():
    from stellar_sdk import Keypair
    seed = Keypair.random().secret
    artifact = AgentArtifact(source_kind=SourceKind.UPLOAD, name="x",
                             code_files={"a.py": f'KP = Keypair.from_secret("{seed}")\n'})
    reviewer = DeepReviewer(ScriptedClient([]), model="m")
    result = deep_review.DeepReviewResult()
    reviewer._run_tool("record_finding", {"category": "secret_exposure", "severity": "critical", "title": "Seed",
        "file": "a.py", "line": 1, "evidence_quote": f'Keypair.from_secret("{seed}")',
        "attack_scenario": f"Anyone reading {seed} controls the account", "stellar_impact": "x",
        "remediation": "rotate"}, artifact, {}, result)
    finding = result.findings[0]
    assert seed not in finding.evidence and seed not in finding.detail
    assert "[REDACTED]" in finding.evidence


def test_a_passed_deadline_skips_the_review_without_calling_the_model():
    import time
    client = ScriptedClient([])
    reviewer = DeepReviewer(client, model="m")
    reviewer.deadline = time.monotonic() + 5  # below the minimum useful review time
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="a", code_files={"a.py": "x = 1\n"})
    result = asyncio.run(reviewer.review(artifact, []))
    assert result.status == "skipped" and not client.requests


def test_a_missing_model_sdk_leaves_the_rules_running(monkeypatch):
    import sys
    from backend.app.services.finding_verifier import verifier_from_settings
    monkeypatch.setitem(sys.modules, "anthropic", None)  # import fails as on a deployment without it
    keyed = Settings(_env_file=None, enable_deep_review=True, enable_finding_verification=True, anthropic_ai_key="k")
    assert deep_review.reviewer_from_settings(keyed) is None and verifier_from_settings(keyed) is None
