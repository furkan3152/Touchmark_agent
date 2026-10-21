"""False alarms found by comparing Touchmark with blind hand audits of real Stellar agents.

Each case is a pattern that was reported but is not a defect, next to the near case that
still is one, so a fix for the false alarm cannot hide the real risk."""

from __future__ import annotations

from backend.app.models import AuditorVerdict, Dimension, Finding, Severity
from backend.app.swarm.codeflow import analyse_code
from backend.app.swarm.orchestrator import AuditSwarm
from backend.tests.test_deep_checks import PY_MCP, TS_MCP, audit

PAY_TOOL = '''
@mcp.tool()
def pay(to: str, amount: str) -> str:
    tx = TransactionBuilder(horizon.load_account(key.public_key), Network.TESTNET_NETWORK_PASSPHRASE)
    tx = tx.append_payment_op(to, Asset.native(), amount).build()
    tx.sign(key)
    return horizon.submit_transaction(tx)["hash"]
'''


def test_coding_assistant_guides_are_not_runtime_instructions(tmp_path):
    rule = "# Agent notes\n\nThe agent must never pay more than 10 XLM without approval.\n"
    found = audit(tmp_path / "a", {"server.py": PY_MCP + PAY_TOOL, "AGENTS.md": rule})
    assert "security-policy-only-in-prompt" not in found
    found = audit(tmp_path / "b", {"server.py": PY_MCP + PAY_TOOL, "SKILL.md": rule})
    assert "security-policy-only-in-prompt" in found


def test_a_fixed_program_with_list_arguments_is_not_command_execution():
    fixed = 'import subprocess\ndef build(name):\n    subprocess.run(["cargo", "build", "-p", name], check=True)\n'
    shell = 'import subprocess\ndef build(name):\n    subprocess.run(f"cargo build -p {name}", shell=True)\n'
    assert not analyse_code({"tools.py": fixed}).capabilities.get("code_execution")
    assert analyse_code({"tools.py": shell}).capabilities.get("code_execution")


def test_trustlines_are_not_account_control():
    ts = TS_MCP + 'export const trust = (code: string, issuer: string) => Operation.changeTrust({ asset: new Asset(code, issuer) });\n'
    caps = analyse_code({"src/trust.ts": ts}).capabilities
    assert caps.get("trustline") and not caps.get("account_control")
    merge = TS_MCP + 'export const close = (dest: string) => Operation.accountMerge({ destination: dest });\n'
    assert analyse_code({"src/close.ts": merge}).capabilities.get("account_control")


def test_a_retry_counter_is_not_a_spending_cap():
    retry = 'def send(tx):\n    attempts = 0\n    while True:\n        if attempts > 3:\n            raise RuntimeError("gave up")\n        attempts += 1\n'
    assert not analyse_code({"send.py": retry}).controls.get("amount_cap")


def _verdict(finding_id: str) -> AuditorVerdict:
    f = Finding(id=finding_id, dimension=Dimension.SECURITY, severity=Severity.HIGH, title="t", detail="d.",
                evidence="e", auditor="security", confidence=0.9)
    return AuditorVerdict(auditor="security", dimension=Dimension.SECURITY, score=50.0, findings=[f])


def test_a_refuted_rule_finding_is_lowered_once_and_kept():
    refuted = {"results": [{"finding_id": "security-x", "verdict": "refuted", "quote_verified": True,
                            "quote": "if (amount > MAX) throw", "file": "a.ts", "line": 3, "reason": "capped"},
                           {"finding_id": "security-ai-y", "verdict": "refuted", "quote_verified": True,
                            "quote": "x", "reason": "r"},
                           {"finding_id": "security-z", "verdict": "refuted", "quote_verified": True,
                            "quote": "// this is safe", "reason": "comment"}]}
    out = AuditSwarm._apply_disputes([_verdict("security-x"), _verdict("security-ai-y"), _verdict("security-z")], refuted)
    x, ai, z = (v.findings[0] for v in out)
    assert x.severity == Severity.MEDIUM and "disputes" in x.detail and x.confidence == 0.5
    assert ai.severity == Severity.HIGH  # model findings are not talked away by a second model
    assert z.severity == Severity.HIGH  # a quoted comment proves nothing about the code


def test_a_secret_with_a_shipped_default_is_reported(tmp_path):
    compose = "services:\n  router:\n    environment:\n      ADMIN_API_KEY: ${ADMIN_API_KEY:-change-me}\n"
    ts = ('export const token = process.env.API_TOKEN || "dev-token";\nexport const pub = process.env.PUBLIC_KEY || "G";\n'
          'export const usdc = process.env.USDC_TOKEN || "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";\n'
          'export const tmpl = process.env.DEPLOYER_SECRET || "YOUR_DEPLOYER_SECRET";\n')
    py = 'import os\nSECRET = os.getenv("JWT_SECRET", "insecure")\nREQUIRED = os.environ["AGENT_SECRET"]\n'
    found = audit(tmp_path, {"docker-compose.yml": compose, "src/config.ts": ts, "app/settings.py": py})
    evidence = found["security-default-secret"]["evidence"]
    assert "ADMIN_API_KEY" in evidence and "API_TOKEN" in evidence and "JWT_SECRET" in evidence
    assert "PUBLIC_KEY" not in evidence and "AGENT_SECRET" not in evidence and "DEPLOYER_SECRET" not in evidence and "USDC_TOKEN" not in evidence
