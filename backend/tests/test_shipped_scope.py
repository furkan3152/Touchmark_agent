"""Declaration checks judge the agent as it runs, not its tests, setup scripts or demos."""

from __future__ import annotations

from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.capabilities import effective_artifact, executes_code, shipped

SIGNS = ('import { Keypair, TransactionBuilder } from "@stellar/stellar-sdk";\n'
         'const kp = Keypair.fromSecret(process.env.SECRET!);\n'
         'export async function run(tx: any) { tx.sign(kp); }\n')


def _artifact(files, tmark=None):
    return AgentArtifact(id="a", name="a", purpose="Reads balances for the operator.", source_kind=SourceKind.REPO,
                         code_files=files, raw_metadata={"tmark": tmark} if tmark else {})


def test_tool_names_are_matched_by_word():
    assert not executes_code("execute_payment") and not executes_code("executeTrade")
    assert executes_code("run_code") and executes_code("shell_command") and executes_code("execCommand")


def test_paths_outside_the_running_agent():
    for path in ("scripts/setup-usdc.ts:69", "apps/e2e-stellar/src/a.ts", "sandbox-server/server.ts",
                 "src/a.test.ts", "tests/x.py", "sdk-python/setup.py"):
        assert not shipped(path), path
    assert shipped("src/server.ts:10") and shipped("apps/agent/src/agent.ts")


def test_signing_only_in_a_setup_script_is_not_an_undeclared_capability():
    eff = effective_artifact(_artifact({"scripts/setup.ts": SIGNS, "src/index.ts": "export const x = 1;\n"}))
    assert not any(t.name == "observed:stellar_signing" for t in eff.tools)
    eff = effective_artifact(_artifact({"src/agent.ts": SIGNS}))
    assert any(t.name == "observed:stellar_signing" for t in eff.tools)


def test_tmark_authority_discloses_signing():
    tmark = {"status": "valid", "declared": {"authority": {"holds_keys": True, "key_source": "env", "signs": ["payments"]}}}
    eff = effective_artifact(_artifact({"src/agent.ts": SIGNS}, tmark))
    assert not any(t.name == "observed:stellar_signing" for t in eff.tools)
