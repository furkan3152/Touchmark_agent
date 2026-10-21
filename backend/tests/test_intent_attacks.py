"""Requests the model refuses plainly but carries out when reworded: the controls that only look like controls."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from backend.app.config import Settings
from backend.app.services.repo_audit import audit_repository

ROOT = Path(__file__).resolve().parents[2]

TS_HEAD = '''import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Keypair, Horizon, TransactionBuilder, Operation, Asset, Networks } from "@stellar/stellar-sdk";
import { z } from "zod";
import { askOperator } from "./operator";
const vault = Keypair.fromSecret(process.env.VAULT_SECRET!);
const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");
const server = new McpServer({ name: "vault", version: "1" });
server.tool("send_payment", { to: z.string(), amount: z.string(), approved: z.boolean() }, async (args) => {
'''
TS_TAIL = '''  const account = await horizon.loadAccount(vault.publicKey());
  const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.payment({ destination: args.to, asset: Asset.native(), amount: args.amount })).setTimeout(30).build();
  tx.sign(vault);
  return { content: [{ type: "text", text: (await horizon.submitTransaction(tx)).hash }] };
});
'''
PY_HEAD = '''from mcp.server.fastmcp import FastMCP
from stellar_sdk import Keypair, Server, TransactionBuilder, Network, Asset
import os
from operator_console import request_human_approval
mcp = FastMCP("vault")
vault = Keypair.from_secret(os.environ["VAULT_SECRET"])
horizon = Server("https://horizon-testnet.stellar.org")
@mcp.tool()
def send_payment(to: str, amount: str, approved: bool) -> str:
'''
PY_TAIL = '''    account = horizon.load_account(vault.public_key)
    tx = TransactionBuilder(account, Network.TESTNET_NETWORK_PASSPHRASE, 100).append_payment_op(to, Asset.native(), amount).build()
    tx.sign(vault)
    return horizon.submit_transaction(tx)["hash"]
'''


def audit(tmp_path, files: dict[str, str], base: str | None = None):
    root = tmp_path / "agent"
    if base:
        shutil.copytree(ROOT / "examples/demo" / base, root)
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    out = asyncio.run(audit_repository(root, name="agent", purpose="", settings=Settings(_env_file=None), deep=False))
    return out, {f["id"] for f in out["report"]["findings"]}


@pytest.mark.parametrize("path,source", [
    ("src/index.ts", TS_HEAD + '  if (!args.approved) throw new Error("A human must approve.");\n' + TS_TAIL),
    ("src/server.py", PY_HEAD + '    if not approved:\n        raise ValueError("A human must approve.")\n' + PY_TAIL),
])
def test_an_approval_flag_the_model_sets_is_not_an_approval(tmp_path, path, source):
    out, ids = audit(tmp_path, {path: source})
    assert "security-path-forgeable-approval" in ids and "security-path-untrusted-to-financial-sink" in ids
    assert out["decision"] == "needs_fixes" and out["report"]["result"]["overall_score"] < 40


@pytest.mark.parametrize("path,source", [
    ("src/index.ts", TS_HEAD + '  const decision = await askOperator(`Pay ${args.amount} XLM to ${args.to}?`);\n'
                               '  if (!decision.approved) throw new Error("Rejected by the operator.");\n' + TS_TAIL),
    ("src/server.py", PY_HEAD + '    decision = request_human_approval(to, amount)\n    if not decision.approved:\n'
                                '        raise ValueError("Rejected by the operator.")\n' + PY_TAIL),
])
def test_a_decision_a_person_returns_is_an_approval(tmp_path, path, source):
    _, ids = audit(tmp_path, {path: source})
    assert "security-path-forgeable-approval" not in ids and "security-path-untrusted-to-financial-sink" not in ids


def test_a_payment_rule_only_in_the_instructions_is_reported(tmp_path):
    skill = "You pay supplier invoices. Never send more than 50 XLM and only pay recipients the operator approved.\n"
    _, ids = audit(tmp_path, {"SKILL.md": skill}, base="unsafe-treasury-agent")
    assert "security-policy-only-in-prompt" in ids


def test_a_rule_the_code_enforces_is_not_reported_as_prompt_only(tmp_path):
    skill = "You pay supplier invoices. Never send more than 500 XLM and only pay approved suppliers.\n"
    out, ids = audit(tmp_path, {"SKILL.md": skill}, base="safe-treasury-agent")
    assert "security-policy-only-in-prompt" not in ids and out["decision"] == "pass"


def test_a_per_call_cap_without_a_running_total_is_reported(tmp_path):
    _, ids = audit(tmp_path, {}, base="safe-treasury-agent")
    assert "security-per-call-cap-only" in ids


DECLARED_SIGNER = '{"tools": [{"name": "pay", "requires_signature": true}]}'
UNRELATED_UI = 'export const Step = ({ step }) => <div className={step >= 1 ? "opacity-100" : "opacity-0"} />;\n'


def test_a_comparison_in_unrelated_ui_code_is_not_a_spending_limit(tmp_path):
    out, ids = audit(tmp_path, {"agentveritas.json": DECLARED_SIGNER, "site/Step.tsx": UNRELATED_UI,
                                "src/wallet.py": "def pay(amount, to):\n    return wallet.pay(amount, to)\n"})
    assert "security-unbounded-spend" in ids
    from backend.app.swarm.codeflow import analyse_code
    assert not analyse_code({"site/Step.tsx": UNRELATED_UI}).controls.get("amount_cap")


def test_a_clamp_that_passes_the_amount_on_is_still_a_control(tmp_path):
    clamp = ('import { Keypair } from "@stellar/stellar-sdk";\nconst MAX = 50;\n'
             'export function cap(amount: number) { return amount <= MAX ? amount : MAX; }\n')
    from backend.app.swarm.codeflow import analyse_code
    assert analyse_code({"src/cap.ts": clamp}).controls.get("amount_cap")


def test_a_price_check_on_money_received_is_not_a_spending_limit():
    from backend.app.swarm.codeflow import analyse_code
    ts = ('export function verify(paidStroops: bigint, requiredStroops: bigint) {\n'
          '  if (paidStroops < requiredStroops) { throw new Error("underpaid"); }\n}\n')
    py = 'def verify(paid_amount, required_amount):\n    if paid_amount < required_amount:\n        raise ValueError("underpaid")\n'
    assert not analyse_code({"src/verify.ts": ts}).controls.get("amount_cap")
    assert not analyse_code({"src/verify.py": py}).controls.get("amount_cap")
    capped = 'def pay(amount):\n    if amount > MAX_AMOUNT:\n        raise ValueError("too much")\n'
    assert analyse_code({"src/pay.py": capped}).controls.get("amount_cap")


def test_input_choosing_the_rpc_server_is_reported(tmp_path):
    source = ('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
              'import { Keypair, rpc, TransactionBuilder, Networks } from "@stellar/stellar-sdk";\nimport { z } from "zod";\n'
              'const key = Keypair.fromSecret(process.env.AGENT_SECRET!);\nconst server = new McpServer({ name: "p", version: "1" });\n'
              'server.tool("invoke", { rpcUrl: z.string(), xdr: z.string() }, async (args) => {\n'
              '  const node = new rpc.Server(args.rpcUrl);\n  const tx = TransactionBuilder.fromXDR(args.xdr, Networks.TESTNET);\n'
              '  const prepared = await node.prepareTransaction(tx);\n  prepared.sign(key);\n'
              '  return { content: [{ type: "text", text: (await node.sendTransaction(prepared)).hash }] };\n});\n')
    _, ids = audit(tmp_path / "a", {"src/index.ts": source})
    assert "security-path-untrusted-ledger-endpoint" in ids
    fixed = source.replace("new rpc.Server(args.rpcUrl)", 'new rpc.Server("https://soroban-testnet.stellar.org")')
    _, ids = audit(tmp_path / "b", {"src/index.ts": fixed})
    assert "security-path-untrusted-ledger-endpoint" not in ids


def test_a_secret_seed_in_a_committed_text_file_is_found(tmp_path):
    from stellar_sdk import Keypair
    seed = Keypair.random().secret  # generated at test time; never a committed literal
    out, ids = audit(tmp_path, {"agent-keys.txt": f"Secret Key: {seed}\n"}, base="safe-treasury-agent")
    finding = next(f for f in out["report"]["findings"] if f["id"] == "stellar_native-stellar-secret-seed")
    assert finding["severity"] == "critical" and "agent-keys.txt:1" in finding["evidence"] and seed not in finding["evidence"]


def test_running_one_fixed_program_is_not_command_injection(tmp_path):
    source = ('import { execFileSync } from "node:child_process";\n'
              'export function loadSecret(identity: string) {\n'
              '  return execFileSync("stellar", ["keys", "secret", identity], { encoding: "utf8" });\n}\n'
              'loadSecret(process.argv[2]);\n')
    _, ids = audit(tmp_path, {"src/secret.ts": source})
    assert "security-path-untrusted-to-command" not in ids


def test_build_and_smoke_test_scripts_are_not_the_agent(tmp_path):
    out, ids = audit(tmp_path, {"build.ts": 'import { execSync } from "child_process";\nexecSync(process.argv[2]);\n',
                                "scripts/smoke-test-pay.ts": 'console.log(process.env.AGENT_SECRET);\n'},
                     base="safe-treasury-agent")
    assert "security-path-untrusted-to-command" not in ids and out["decision"] == "pass"


def test_spending_authority_that_is_only_declared_is_latent(tmp_path):
    out, _ = audit(tmp_path, {"agentveritas.json": '{"tools": [{"name": "pay", "requires_signature": true}]}',
                              "src/wallet.py": "def balance(client, account):\n    return client.load_account(account)\n"})
    spend = {f["id"]: f["severity"] for f in out["report"]["findings"]
             if f["id"] in ("security-unbounded-spend", "economic-no-spend-policy")}
    assert spend and set(spend.values()) == {"medium"}
