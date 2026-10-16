"""Absence-of-control claims are evidence only where the analyser can see controls."""

from __future__ import annotations

import asyncio

from stellar_sdk import Keypair

from backend.app.config import Settings
from backend.app.models import AgentArtifact, AuditTier, SourceKind, ToolSpec
from backend.app.services.deep_review import DeepReviewer
from backend.app.swarm.orchestrator import AuditSwarm
from backend.tests.test_deep_review import ScriptedClient, call, reply

TS_AGENT = {
    "src/pay.ts": 'import { Keypair } from "@stellar/stellar-sdk";\n'
                  'export async function pay(to: string, amount: string) {\n'
                  '  if (!ALLOW.has(to) || Number(amount) > MAX) throw new Error("denied");\n'
                  '  const kp = Keypair.fromSecret(process.env.WALLET_SECRET!);\n'
                  '  return server.submitTransaction(build(kp, to, amount));\n}\n',
    "src/util.ts": "export const MAX = 50;\n",
}


def artifact(files=TS_AGENT, tools=None):
    return AgentArtifact(source_kind=SourceKind.REPO, name="ts-agent", system_prompt="Pay allowlisted vendors only, up to 50 XLM.",
                         code_files=files, tools=tools or [])


def run(art, reviewer=None):
    return asyncio.run(AuditSwarm(Settings(_env_file=None, stellar_network="offline")).run(
        art, "job", AuditTier.DEEP, deep_reviewer=reviewer))


def test_typescript_authority_without_deep_review_cannot_pass():
    report = run(artifact())
    by_id = {f.id: f for f in report.findings}
    assert by_id["security-controls-unverifiable"].kind.value == "evidence_gap"
    for rule in ("economic-no-spend-policy", "security-path-controls-not-enforced"):
        if rule in by_id:
            assert by_id[rule].kind.value == "evidence_gap"
    assert report.decision == "needs_evidence"


def test_completed_deep_review_that_read_every_file_closes_the_gap():
    client = ScriptedClient([
        reply(call("describe_operating_model", purpose="pay", triggers="operator", example_run="pay vendor",
                   trust_boundaries=["operator"], assets_at_risk=["XLM"]),
              call("read_source", path="src/pay.ts", start_line=1, end_line=6),
              call("read_source", path="src/util.ts", start_line=1, end_line=1)),
        reply(call("finish", summary="allowlist and cap enforced before signing")),
    ])
    report = run(artifact(), DeepReviewer(client, model="claude-sonnet-5-5"))
    assert "security-controls-unverifiable" not in {f.id for f in report.findings}
    assert report.deep_review["unverifiable_controls_resolved"] is True
    assert report.decision == "pass"


def test_partial_reading_keeps_the_gap():
    client = ScriptedClient([
        reply(call("read_source", path="src/util.ts", start_line=1, end_line=1)),
        reply(call("finish", summary="skimmed")),
    ])
    report = run(artifact(), DeepReviewer(client, model="claude-sonnet-5-5"))
    assert "security-controls-unverifiable" in {f.id for f in report.findings}
    assert report.decision == "needs_evidence"


def test_missing_declaration_is_a_gap_but_an_understated_one_is_a_risk():
    undeclared = {f.id: f for f in run(artifact()).findings}
    assert undeclared["security-undeclared-capability"].kind.value == "evidence_gap"
    understated = {f.id: f for f in run(artifact(tools=[ToolSpec(name="read", scopes=["read:chain"])])).findings}
    assert understated["security-undeclared-capability"].kind.value == "risk"


def test_placeholder_seeds_are_ignored_and_test_seeds_are_medium():
    placeholder = "S" + "A" * 55
    real = Keypair.random().secret
    findings = {f.id: f for f in run(artifact({"src/pay.ts": f'const k = "{placeholder}";\n'})).findings}
    assert "stellar_native-stellar-secret-seed" not in findings
    findings = {f.id: f for f in run(artifact({"scripts/smoke-test.ts": f'const k = "{real}";\n'})).findings}
    assert findings["stellar_native-stellar-secret-seed"].severity.value == "medium"
    assert real not in findings["stellar_native-stellar-secret-seed"].evidence
