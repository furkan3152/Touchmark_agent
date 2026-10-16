"""Unit semantics of the project-wide source analyser (sources are parsed, never executed)."""

from __future__ import annotations

import pytest

from backend.app.models import AgentArtifact, SourceKind, ToolSpec
from backend.app.swarm.capabilities import effective_artifact
from backend.app.swarm.codeflow import analyse_code
from backend.app.swarm.policy import review_decision
from backend.app.swarm.security import SecurityAuditor

PAY = '''import os
from stellar_sdk import Keypair, Server, TransactionBuilder, Network, Asset
kp = Keypair.from_secret(os.environ["WALLET_SECRET"])
server = Server("https://horizon-testnet.stellar.org")
TOOLS = [{{"name": "pay", "input_schema": {{}}}}]
CAP = 100
def pay(destination, amount):
{guard}
    account = server.load_account(kp.public_key)
    tx = TransactionBuilder(account, Network.TESTNET_NETWORK_PASSPHRASE).append_payment_op(destination, Asset.native(), amount).build()
    tx.sign(kp)
HANDLERS = {{"pay": pay}}
'''


def categories(code: str) -> set[str]:
    return {flow.category for flow in analyse_code({"agent.py": code}).flows}


@pytest.mark.parametrize("guard,flagged", [
    ("    pass", True),
    ("    if amount <= 0:\n        raise ValueError()", True),  # lower bound only
    ("    if amount > CAP:\n        print('over cap')", True),  # does not stop execution
    ("    if destination not in {'GA'}:\n        raise ValueError()\n    if not 0 < amount <= CAP:\n        raise ValueError()", False),
    ("    if not approved_by_operator(destination, amount):\n        raise PermissionError()", False),
])
def test_payment_controls_must_fail_closed(guard, flagged):
    assert ("financial" in categories(PAY.format(guard=guard))) is flagged


def test_constant_named_approved_is_an_allowlist_not_human_approval():
    code = PAY.format(guard="    if destination not in APPROVED:\n        raise ValueError()").replace(
        "CAP = 100", "CAP = 100\nAPPROVED = {'GA'}")
    flows = [f for f in analyse_code({"agent.py": code}).flows if f.category == "financial"]
    assert flows and "unbounded payment amount" in flows[0].detail


def test_import_alias_and_cross_file_call_reach_the_sink():
    files = {"main.py": "from os import system as launch\nfrom util import run\nTOOLS=[{'input_schema':{}}]\n"
                        "def tool(cmd):\n    return run(cmd)\nH={'t': tool}\n",
             "util.py": "from os import system as launch\ndef run(value):\n    return launch(value)\n"}
    flows = analyse_code(files).flows
    assert any(f.category == "command" and f.location.file == "util.py" for f in flows)


def test_fixed_caller_does_not_create_a_path():
    files = {"agent.py": "from executor import execute\ndef handle(request):\n    return execute('echo ok')\n",
             "executor.py": "import subprocess\ndef execute(command):\n    return subprocess.run(command, shell=True)\n"}
    assert not analyse_code(files).flows


def test_unparsable_source_cannot_pass(settings, run):
    artifact = AgentArtifact(source_kind=SourceKind.UPLOAD, name="x", system_prompt="Read balances only.",
                             tools=[ToolSpec(name="read", scopes=["read:chain"])],
                             code_files={"main.py": "def broken(:\n    pass\n"})
    effective = effective_artifact(artifact)
    verdict = run(SecurityAuditor(settings).run(effective, deep=True))
    ids = {f.id for f in verdict.findings}
    assert "security-source-analysis-incomplete" in ids
    assert review_decision(verdict.findings, {"deep_core_complete": True}, 90.0) == "needs_evidence"


def test_declaration_cannot_hide_signing_capability():
    artifact = AgentArtifact(source_kind=SourceKind.UPLOAD, name="x",
                             tools=[ToolSpec(name="pay", scopes=["read:chain"])],
                             code_files={"agent.py": PAY.format(guard="    pass")})
    effective = effective_artifact(artifact)
    observed = [t for t in effective.tools if t.origin == "observed"]
    assert observed and observed[0].requires_signature
    assert artifact.tools == [ToolSpec(name="pay", scopes=["read:chain"])]  # submitted input unchanged
