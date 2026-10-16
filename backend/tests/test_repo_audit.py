"""Repository selection and multi-pass deep review (no network, scripted model)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from backend.app.config import Settings
from backend.app.services import deep_review
from backend.app.services.deep_review import DeepReviewer
from backend.app.services.repo_audit import audit_repository, select_repository
from backend.tests.test_deep_review import ScriptedClient, call, reply


def make_repo(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "pay.ts").write_text(
        'import { Keypair } from "@stellar/stellar-sdk";\n'
        'server.tool("send_payment", async ({ to, amount }) => {\n'
        '  const kp = Keypair.fromSecret(process.env.WALLET_SECRET!);\n'
        '  return submitTransaction(buildPayment(kp, to, amount));\n});\n')
    (root / "src" / "util.ts").write_text("export const add = (a: number, b: number) => a + b;\n")
    (root / "tests").mkdir()
    (root / "tests" / "pay.test.ts").write_text("test('x', () => {});\n")
    (root / "node_modules" / "lib").mkdir(parents=True)
    (root / "node_modules" / "lib" / "index.js").write_text("module.exports = 1;\n")
    (root / "SKILL.md").write_text("Pay only allowlisted recipients.\n")
    (root / "package.json").write_text('{"dependencies": {"@stellar/stellar-sdk": "^13.0.0"}}')
    return root


def test_selection_ranks_agent_code_and_skips_tests_and_vendored_code(tmp_path):
    files, selection = select_repository(make_repo(tmp_path))
    assert list(files) == ["src/pay.ts", "src/util.ts", "package.json"]
    manifest = selection["manifest"]
    assert manifest["manifest_files"] == ["package.json"] and manifest["source_files_selected"] == 2
    assert manifest["files_skipped_as_tests_or_builds"] == 2 and manifest["complete"] is True
    assert manifest["instruction_files"] == ["SKILL.md"]


def test_selection_budget_is_reported(tmp_path):
    files, selection = select_repository(make_repo(tmp_path), max_files=1)
    assert list(files) == ["src/pay.ts", "package.json"]
    assert selection["manifest"]["complete"] is False
    assert selection["manifest"]["source_files_not_selected"] == ["src/util.ts"]


def test_challenger_pass_sees_prior_findings_and_unread_files(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    client = ScriptedClient([
        reply(call("describe_operating_model", purpose="pay", triggers="mcp client", example_run="send",
                   trust_boundaries=["mcp"], assets_at_risk=["wallet"]),
              call("read_source", path="src/pay.ts", start_line=1, end_line=5)),
        reply(call("record_finding", category="unauthorized_payment", severity="critical",
                   title="Model-chosen recipient and amount", file="src/pay.ts", line=2,
                   evidence_quote='server.tool("send_payment"', attack_scenario="Injected prompt pays attacker.",
                   stellar_impact="Wallet drained.", remediation="Allowlist and cap."),
              call("finish", summary="pass one")),
        reply(call("finish", summary="pass two found nothing new")),
    ])
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5", passes=2)
    monkeypatch.setattr(deep_review, "reviewer_from_settings", lambda settings: reviewer)
    result = asyncio.run(audit_repository(repo, name="pay", purpose="Pay invoices.", settings=Settings(_env_file=None)))
    deep = result["report"]["deep_review"]
    assert [p["pass"] for p in deep["passes"]] == [1, 2] and deep["passes"][0]["new_findings"] == 1
    challenge = client.requests[2]["messages"][0]["content"][1]["text"]
    assert "Challenge pass 2" in challenge and "Model-chosen recipient" in challenge and "src/util.ts" in challenge
    assert deep["coverage"] == {"files_read": ["src/pay.ts"], "files_total": 2, "ratio": 0.5}
    assert result["decision"] == "needs_fixes"
    assert result["report"]["repository"]["source_files_selected"] == 2
