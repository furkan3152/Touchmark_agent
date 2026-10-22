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
          'export const usdc = process.env.ORACLE_USDC_TOKEN || "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWUIE3USSTHZX5ACUSDC";\n'
          'export const tmpl = process.env.DEPLOYER_SECRET || "YOUR_DEPLOYER_SECRET";\n')
    py = 'import os\nSECRET = os.getenv("JWT_SECRET", "insecure")\nREQUIRED = os.environ["AGENT_SECRET"]\n'
    found = audit(tmp_path, {"docker-compose.yml": compose, "src/config.ts": ts, "app/settings.py": py})
    evidence = found["security-default-secret"]["evidence"]
    assert "ADMIN_API_KEY" in evidence and "API_TOKEN" in evidence and "JWT_SECRET" in evidence
    assert "PUBLIC_KEY" not in evidence and "AGENT_SECRET" not in evidence and "DEPLOYER_SECRET" not in evidence and "USDC_TOKEN" not in evidence


KIT = '''import { z } from "zod";
import { Horizon, TransactionBuilder, Operation, Asset } from "@stellar/stellar-sdk";
export const payAction = {
  name: "pay",
  description: "Pay an address",
  schema: z.object({ to: z.string(), amount: z.string() }),
  handler: async (agent: any, input: { to: string; amount: string }) => {
    const horizon = new Horizon.Server(agent.config.horizonUrl);
    const account = await horizon.loadAccount(agent.wallet.publicKey);
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: agent.config.networkPassphrase })
      .addOperation(Operation.payment({ destination: input.to, asset: Asset.native(), amount: input.amount }))
      .setTimeout(30).build();
    tx.sign(agent.wallet.keypair);
    return horizon.submitTransaction(tx);
  },
};
'''


def test_an_agent_kit_handler_takes_model_input_after_the_agent(tmp_path):
    found = audit(tmp_path, {"src/pay.ts": KIT})
    assert "security-path-untrusted-ledger-endpoint" not in found  # the kit's own config, not the model's
    assert found["security-path-untrusted-to-financial-sink"]["severity"] == "high"  # input.to still is


def test_an_approval_flag_only_an_unseen_caller_sets_is_not_confirmed(tmp_path):
    lib = TS_MCP + ('export async function applyEdit(dest: string, opts: { confirmed: boolean }) {\n'
                    '  if (!opts.confirmed) { throw new Error("confirm first"); }\n'
                    '  const account = await horizon.loadAccount(key.publicKey());\n'
                    '  const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })\n'
                    '    .addOperation(Operation.accountMerge({ destination: "GDM7FY4WBPRLTY4WYE7FKFHQVUI5FYE3WDLNHTDVNKMJ2VNTTQEPBYZV" })).setTimeout(30).build();\n'
                    '  tx.sign(key);\n  return horizon.submitTransaction(tx);\n}\n')
    finding = audit(tmp_path / "a", {"src/soul.ts": lib})["security-path-forgeable-approval"]
    assert finding["severity"] == "low" and finding["evidence_grade"] == "inferred"
    tool = lib + ('server.tool("merge", { dest: z.string(), confirmed: z.boolean() },\n'
                  '  async (args) => applyEdit(args.dest, { confirmed: args.confirmed }));\n')
    assert audit(tmp_path / "b", {"src/soul.ts": tool})["security-path-forgeable-approval"]["severity"] == "critical"


CONTRACT = '''#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        env.storage().instance().set(&to, &amount);
    }
}
'''


def test_only_soroban_crate_sources_are_judged_as_contracts(tmp_path):
    wallet = "pub fn set_submit_timeout(&mut self, secs: u64) { self.timeout = secs; }\n"
    loose = audit(tmp_path / "a", {"contracts/vault.rs": CONTRACT, "README.md": "Sample contracts for testing."})
    assert "stellar_native-soroban-auth-missing" not in loose
    workspace = audit(tmp_path / "b", {"Cargo.toml": '[workspace]\nmembers = ["wallet"]\n', "wallet/src/lib.rs": wallet,
                                       "wallet/Cargo.toml": '[package]\nname = "wallet"\n'})
    assert "stellar_native-soroban-auth-missing" not in workspace
    crate = audit(tmp_path / "c", {"vault/Cargo.toml": '[package]\nname = "vault"\n[dependencies]\nsoroban-sdk = "22"\n',
                                   "vault/src/lib.rs": CONTRACT})
    assert crate["stellar_native-soroban-auth-missing"]["severity"] == "medium"


def test_text_written_as_html_is_reported_and_escaped_or_constant_html_is_not(tmp_path):
    chat = ('const box = document.getElementById("chat");\n'
            'function addMessage(role, html) {\n  const div = document.createElement("div");\n  div.innerHTML = html;\n'
            '  box.appendChild(div);\n}\n'
            'document.getElementById("send").onclick = () => addMessage("user", `<b>You:</b> ${input.value}`);\n')
    found = audit(tmp_path / "a", {"web/app.js": chat})
    assert found["security-html-injection"]["evidence"] == "web/app.js:4"
    safe = ('const THEME = "document.documentElement.dataset.theme = localStorage.theme";\n'
            'export const Theme = () => <script dangerouslySetInnerHTML={{ __html: THEME }} />;\n'
            'function show(el, text) { el.innerHTML = DOMPurify.sanitize(`<p>${text}</p>`); }\n'
            'function render(el, html) { el.innerHTML = html; }\nrender(document.body, "<p>static</p>");\n')
    assert "security-html-injection" not in audit(tmp_path / "b", {"web/theme.tsx": safe})


def test_a_valid_seed_committed_in_example_tests_is_reported(tmp_path):
    from stellar_sdk import Keypair
    seed = Keypair.random().secret
    found = audit(tmp_path, {"server.py": PY_MCP, "examples/rust-x402/tests/integration.rs":
                             f'#[test]\nfn pays() {{ let s = "{seed}"; }}\n'})
    finding = found["stellar_native-stellar-secret-seed"]
    assert finding["severity"] == "medium" and "examples/rust-x402/tests/integration.rs:2" in finding["evidence"]
    assert seed not in finding["evidence"]


def test_a_confirmed_medium_bypass_rules_out_a_pass_but_a_functional_defect_does_not():
    from backend.app.swarm.policy import actionable_risks, review_decision

    def finding(fid: str, verified: str = "") -> Finding:
        return Finding(id=fid, dimension=Dimension.SECURITY, severity=Severity.MEDIUM, title="t", detail="d.",
                       auditor="deep", verified=verified)
    complete = {"deep_core_complete": True}
    bypass = finding("security-ai-control-bypass-1", "confirmed")
    assert actionable_risks([bypass]) == [bypass]
    assert review_decision([bypass], complete, 85.0) == "needs_fixes"
    for other in (finding("security-ai-control-bypass-1", "partial"), finding("security-ai-control-bypass-1"),
                  finding("reliability-ai-functional-defect-2", "confirmed"),
                  finding("security-ai-secret-exposure-14", "confirmed")):  # conditional exposure, not a bypass
        assert review_decision([other], complete, 85.0) == "pass"
    assert "verified" not in bypass.model_dump()  # not part of the serialized finding or its hash


def test_verification_verdicts_are_recorded_on_findings():
    results = {"results": [{"finding_id": "security-ai-y", "verdict": "confirmed", "quote_verified": True, "quote": "pay(x)"},
                           {"finding_id": "security-x", "verdict": "confirmed", "quote_verified": False, "quote": "pay(x)"}]}
    out = AuditSwarm._apply_disputes([_verdict("security-ai-y"), _verdict("security-x")], results)
    assert out[0].findings[0].verified == "confirmed"
    assert out[1].findings[0].verified == ""  # an unverifiable quote confirms nothing


def test_a_running_total_plus_the_payment_is_a_spending_cap():
    js = ('let spent = 0;\nconst MAX = 1;\nexport async function pay(price) {\n'
          '  if (spent + price > MAX) { throw new Error("budget"); }\n  spent += price;\n}\n')
    py = 'spent = 0\nLIMIT = 5\ndef pay(amount):\n    if spent + amount > LIMIT:\n        raise ValueError("budget")\n'
    assert analyse_code({"a.mjs": js}).controls.get("amount_cap")
    assert analyse_code({"a.py": py}).controls.get("amount_cap")


def test_signing_an_x402_payload_is_a_payment_capability():
    js = ('import { createEd25519Signer, ExactStellarScheme } from "@x402/stellar";\n'
          'export async function pay(req) {\n  const signer = createEd25519Signer(process.env.SECRET);\n'
          '  return new ExactStellarScheme(signer).createPaymentPayload(2, req);\n}\n')
    caps = analyse_code({"pay.mjs": js}).capabilities
    assert caps.get("payment") and caps.get("stellar_signing")


def test_per_record_state_in_instance_storage_is_reported(tmp_path):
    channel = CONTRACT.replace("env.storage().instance().set(&to, &amount);",
                               "to.require_auth();\n        env.storage().instance().set(&DataKey::Channel(to.clone()), &amount);")
    config = CONTRACT.replace("env.storage().instance().set(&to, &amount);",
                              "to.require_auth();\n        env.storage().instance().set(&DataKey::Admin, &to);")
    manifest = '[package]\nname = "vault"\n[dependencies]\nsoroban-sdk = "22"\n'
    found = audit(tmp_path / "a", {"vault/Cargo.toml": manifest, "vault/src/lib.rs": channel})
    assert found["stellar_native-instance-storage-records"]["evidence"] == "vault/src/lib.rs:9"
    assert "stellar_native-instance-storage-records" not in audit(tmp_path / "b", {"vault/Cargo.toml": manifest, "vault/src/lib.rs": config})


def test_the_model_review_is_told_which_contract_files_no_crate_builds():
    from backend.app.services.deep_review import _unbuilt_contracts
    files = {"contracts/sample.rs": "", "vault/Cargo.toml": "", "vault/src/lib.rs": "", "README.md": ""}
    assert _unbuilt_contracts(files) == ["contracts/sample.rs"]
    assert _unbuilt_contracts({"Cargo.toml": "", "src/lib.rs": ""}) == []
