"""An honest .tmark must never make the score worse through false positives.

The fixtures under fixtures/honest_declarations/ are minimal snippets (data, never executed)
of public Stellar agents a live evaluation audited with and without their declaration; the
declarations they were evaluated with are in fixtures/declarations/. Each test pairs the false
positive with the near case that must still be reported, so a fix cannot hide a real risk.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from stellar_sdk import Keypair

from backend.app.config import Settings
from backend.app.services import tmark
from backend.app.services.repo_audit import audit_repository
from backend.app.swarm.codeflow import analyse_code

FIXTURES = Path(__file__).parent / "fixtures"
HONEST = FIXTURES / "honest_declarations"


def run(root: Path, tmark_text: str | None = None) -> dict:
    override = {"text": tmark_text} if tmark_text is not None else None
    return asyncio.run(audit_repository(root, name=root.name, purpose="", settings=Settings(_env_file=None),
                                        deep=False, tmark_override=override))["report"]


def ids(report: dict, kind: str | None = None) -> set[str]:
    return {f["id"] for f in report["findings"] if kind is None or f.get("kind") == kind}


def without_tmark(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    shutil.copytree(HONEST / name, root)
    (root / ".tmark").unlink()
    return root


@pytest.mark.parametrize("name", ["syronlabs", "kalepail", "x402"])
def test_an_honest_declaration_never_lowers_the_score(tmp_path, name):
    with_decl = run(HONEST / name)
    bare = run(without_tmark(tmp_path, name))
    assert with_decl["repository"]["declarations"]["tmark"]["status"] == "valid"
    assert with_decl["result"]["overall_score"] >= bare["result"]["overall_score"]
    assert ids(with_decl, "risk") <= ids(bare, "risk") | {"intent-tmark-supplied-differs"}


# (a) ------------------------------------------------------------------ price exposure
def test_supply_in_an_asset_issuing_tool_is_not_price_exposure():
    report = run(HONEST / "syronlabs")
    assert "economic-no-mev-protection" not in ids(report)


def test_swap_and_lending_tools_still_need_price_protection(tmp_path):
    from backend.app.models import AgentArtifact, SourceKind, ToolSpec
    from backend.app.swarm.economic import EconomicAuditor
    for description, exposed in (("Swap USDC for XLM on the DEX", True),
                                 ("Supply USDC to the Blend lending pool for yield", True),
                                 ("Pay the full supply to the distributor", False),
                                 ("Stake a bond with the operator", False)):
        art = AgentArtifact(name="a", source_kind=SourceKind.UPLOAD, source_ref="r",
                            tools=[ToolSpec(name="tool", description=description)])
        assert EconomicAuditor._price_exposure(art)[0] is exposed, description


# (b) ------------------------------------------------------------- financial disclosure
def test_declared_contract_calls_and_fund_moving_tools_disclose_financial_authority():
    report = run(HONEST / "kalepail")
    assert "intent-undeclared-financial-capability" not in ids(report)
    decl = tmark.to_declaration(tmark.parse((HONEST / "kalepail/.tmark").read_text())[0])
    assert "moves_funds" in decl["capabilities"] and decl["tools"][0]["moves_funds"] is True
    assert decl["limits"] == {"per_payment": None, "per_day": None, "recipients": "any", "human_approval": "never"}


def test_a_card_that_names_no_financial_authority_is_still_reported():
    from backend.app.models import AgentArtifact, SourceKind, ToolSpec
    from backend.app.swarm.intent import IntentAuditor
    art = AgentArtifact(name="a", source_kind=SourceKind.UPLOAD, source_ref="r", declared_capabilities=["web_research"],
                        description="Researches suppliers and pays their invoices for the operator.",
                        system_prompt="You research suppliers on the web and pay invoices.",
                        tools=[ToolSpec(name="pay", requires_signature=True, origin="declared")])
    verdict = asyncio.run(IntentAuditor(Settings(_env_file=None)).run(art, deep=False))
    assert any(f.id == "intent-undeclared-financial-capability" for f in verdict.findings)


# (c) ------------------------------------------------------------------ analysed scope
def test_declared_tools_whose_code_is_outside_the_analysed_scope_are_a_scope_gap():
    report = run(HONEST / "x402")
    found = {f["id"]: f for f in report["findings"]}
    assert "security-unbounded-spend" not in found and "economic-no-spend-policy" not in found
    gap = found["security-declared-tools-outside-scope"]
    assert gap["kind"] == "evidence_gap" and "client-cli" in gap["detail"] and "examples/" in gap["evidence"]
    assert report["repository"]["excluded_scope"] == {"examples/": 1}


def test_unbounded_spend_in_analysed_code_is_still_a_risk(tmp_path):
    root = tmp_path / "x402-in-scope"
    shutil.copytree(HONEST / "x402", root)
    (root / "src").mkdir()
    shutil.move(str(root / "examples/client-cli/src/index.ts"), root / "src/client.ts")
    found = {f["id"]: f for f in run(root)["findings"]}
    assert "security-declared-tools-outside-scope" not in found
    # In scope, the missing limit is judged again (here it restates the concrete payment path).
    assert "security-unbounded-spend" in found and found["security-path-controls-not-enforced"]["kind"] == "risk"


# (d) ------------------------------------------------------------------ network binding
TESTNET_TMARK = {"$schema": tmark.SCHEMA_URL, "tmark": "1",
                 "agent": {"name": "gen", "purpose": "Generates Stellar MCP servers from contract specs for testnet.",
                           "kind": "mcp_server", "network": "testnet"},
                 "authority": {"holds_keys": False, "key_source": "none", "signs": []}}
MAINNET_CODE = 'import { Networks } from "@stellar/stellar-sdk";\nexport const passphrase = Networks.PUBLIC;\n'


@pytest.mark.parametrize("path,flagged", [
    ("templates/smart-wallet/src/lib/passkey.ts", False),
    ("stellar-mcp-generator/src/emit.ts", False),
    ("src/server/server.ts.hbs", False),
    ("src/network.ts", True),
])
def test_templates_and_generators_are_not_shipped_network_evidence(tmp_path, path, flagged):
    root = tmp_path / "agent"
    (root / path).parent.mkdir(parents=True)
    (root / path).write_text(MAINNET_CODE)
    (root / "src").mkdir(exist_ok=True)
    (root / "src/index.ts").write_text('export const name = "generator";\n')
    report = run(root, json.dumps(TESTNET_TMARK))
    assert ("intent-tmark-network-mismatch" in ids(report)) is flagged


# (e) ------------------------------------------------------------------ test-only seeds
def test_a_seed_only_in_test_files_is_low_at_most(tmp_path):
    root = tmp_path / "sdk"
    (root / "sdk/src").mkdir(parents=True)
    (root / "sdk/src/env.ts").write_text("export const network = process.env.NETWORK;\n")
    (root / "sdk/src/env.test.ts").write_text(f'const SECRET = "{Keypair.random().secret}";\n')
    finding = next(f for f in run(root)["findings"] if f["id"] == "stellar_native-stellar-secret-seed")
    assert finding["severity"] == "low"
    (root / "agent-keys.txt").write_text(f"Secret: {Keypair.random().secret}\n")
    finding = next(f for f in run(root)["findings"] if f["id"] == "stellar_native-stellar-secret-seed")
    assert finding["severity"] == "critical"


# (f) ------------------------------------------------------------ locally built transactions
def test_a_transaction_built_from_a_contract_spec_is_not_a_foreign_envelope():
    flows = analyse_code({"src/index.ts": (HONEST / "kalepail/src/index.ts").read_text()}).flows
    categories = {f.category for f in flows}
    assert "foreign_signing" not in categories
    # The model still chooses the contract arguments that get signed: reported as such.
    assert "financial" in categories


def test_a_caller_supplied_envelope_is_still_foreign():
    source = ('import { TransactionBuilder, Keypair, Networks } from "@stellar/stellar-sdk";\n'
              'server.tool("sign", "sign", { xdr: z.string() }, async ({ xdr }) => {\n'
              '  const tx = TransactionBuilder.fromXDR(xdr, Networks.TESTNET);\n'
              '  tx.sign(Keypair.fromSecret(process.env.SECRET));\n  return tx.toXDR();\n});\n')
    assert "foreign_signing" in {f.category for f in analyse_code({"src/a.ts": source}).flows}


# ----------------------------------------------------------------------- evidence-gap noise
def test_no_declaration_based_gaps_without_a_declaration(tmp_path):
    report = run(without_tmark(tmp_path, "syronlabs"))
    assert not ids(report) & {"security-undeclared-capability", "intent-undeclared-financial-capability"}


def test_unexecuted_test_inputs_are_stellar_specific_and_not_critical(tmp_path):
    report = run(HONEST / "syronlabs")
    gaps = [f for f in report["findings"] if f["id"].startswith("security-a-")]
    assert gaps and all("0x" not in f["evidence"] for f in gaps)
    # An MCP server has no system prompt of its own: the host's prompt decides, so it is a note.
    assert {f["severity"] for f in gaps} <= {"low", "info"}
    injection = next(f for f in gaps if f["id"] == "security-a-02")
    assert "Stellar account" in injection["evidence"]


def test_an_agent_with_its_own_prompt_gets_medium_gaps_at_most(tmp_path):
    root = tmp_path / "agent"
    shutil.copytree(HONEST / "syronlabs", root)
    (root / "AGENTS.md").write_text("You are a payments agent. Pay invoices for the operator.\n")
    gaps = [f for f in run(root)["findings"] if f["id"].startswith("security-a-")]
    assert gaps and "medium" in {f["severity"] for f in gaps}
    assert {f["severity"] for f in gaps} <= {"medium", "low", "info"}
