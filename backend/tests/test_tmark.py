""".tmark: one strict declaration file, checked against the code."""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path

from backend.app.config import Settings
from backend.app.services import tmark
from backend.app.services.repo_audit import audit_repository
from backend.app.swarm.tmark_check import _MAINNET, network_hits

ROOT = Path(__file__).resolve().parents[2]
OWNER = "GDM7FY4WBPRLTY4WYE7FKFHQVUI5FYE3WDLNHTDVNKMJ2VNTTQEPBYZV"


def example_tmark() -> dict:
    return json.loads((ROOT / "examples/demo/safe-treasury-agent/.tmark").read_text())


def audit(tmp_path, example, tmark_doc=None, extra: dict | None = None):
    root = tmp_path / example
    shutil.copytree(ROOT / "examples/demo" / example, root)
    (root / ".tmark").unlink(missing_ok=True)
    if tmark_doc is not None:
        (root / ".tmark").write_text(tmark_doc if isinstance(tmark_doc, str) else json.dumps(tmark_doc))
    for rel, text in (extra or {}).items():
        (root / rel).write_text(text)
    out = asyncio.run(audit_repository(root, name=example, purpose="", settings=Settings(_env_file=None), deep=False))
    return out, {f["id"]: f for f in out["report"]["findings"]}


def test_the_examples_are_valid_and_the_schema_is_published():
    for example in ("safe-treasury-agent", "owned-treasury-agent"):
        parsed, errors = tmark.parse((ROOT / "examples/demo" / example / ".tmark").read_text())
        assert errors == [] and parsed.agent.network == "testnet"
    published = json.loads((ROOT / "public/schemas/tmark-v1.json").read_text())
    assert published == json.loads(json.dumps(tmark.schema())), "run: python scripts/tmark.py schema > public/schemas/tmark-v1.json"


def test_errors_name_the_field_and_nothing_partial_is_used():
    doc = example_tmark()
    doc["limits"]["per_payment"]["amount"] = "five hundred"
    doc["agent"]["kind"] = "robot"
    doc["extra"] = 1
    doc["authority"]["holds_keys"] = False
    parsed, errors = tmark.parse(json.dumps(doc))
    assert parsed is None
    text = "\n".join(errors)
    assert "limits.per_payment.amount" in text and "agent.kind" in text and "extra: unknown field" in text
    assert "key_source env or kms" in text


def test_paying_agents_must_declare_limits_and_assets_need_issuers():
    doc = example_tmark()
    del doc["limits"]
    assert any("limits is required" in e for e in tmark.parse(json.dumps(doc))[1])
    doc = example_tmark()
    doc["limits"]["per_payment"]["asset"] = "USDC:GNOTANACCOUNT"
    assert any("limits.per_payment.asset" in e for e in tmark.parse(json.dumps(doc))[1])


def test_a_valid_tmark_on_safe_code_passes_with_owner_and_purpose(tmp_path):
    doc = {**example_tmark(), "owner": {"stellar_account": OWNER}}
    out, found = audit(tmp_path, "safe-treasury-agent", doc)
    assert out["decision"] == "pass"
    assert not [f for f in found if f.startswith("intent-tmark")]
    repo = out["report"]["repository"]
    assert repo["declarations"]["tmark"] == {"status": "valid", "errors": []}
    assert repo["ownership_claim"] == {"path": ".tmark", "stellar_owner": OWNER}
    assert out["report"]["subject"]["purpose"] == doc["agent"]["purpose"]


def test_declared_limits_the_code_breaks_are_reported(tmp_path):
    doc = example_tmark()
    doc["limits"]["human_approval"] = "always"
    out, found = audit(tmp_path, "unsafe-treasury-agent", doc)
    broken = found["intent-tmark-limit-not-enforced"]["evidence"]
    assert "recipients: allowlist" in broken and "per_payment 500 XLM" in broken and "human_approval: always" in broken
    assert out["decision"] == "needs_fixes"


def test_testnet_claim_with_mainnet_code_and_hidden_authority_are_reported(tmp_path):
    doc = example_tmark()
    doc["authority"] = {"holds_keys": False, "key_source": "none", "signs": []}
    doc["tools"] = [t for t in doc["tools"] if not t["moves_funds"]]
    del doc["limits"]
    mainnet = 'export const NET = "Public Global Stellar Network ; September 2015";\n'
    _, found = audit(tmp_path, "safe-treasury-agent", doc, {"src/net.ts": mainnet})
    assert "src/net.ts:1" in found["intent-tmark-network-mismatch"]["evidence"]
    assert "intent-tmark-authority-mismatch" in found


def test_an_invalid_tmark_is_a_gap_and_older_files_are_not_read(tmp_path):
    out, found = audit(tmp_path, "safe-treasury-agent", "{not json", {"touchmark.json": json.dumps({"stellar_owner": OWNER})})
    assert found["intent-tmark-invalid"]["severity"] == "medium"
    assert out["report"]["repository"]["ownership_claim"]["error"] == "the .tmark is invalid"
    assert out["decision"] == "pass"  # a gap, not a risk


def test_older_files_still_work_and_ask_to_migrate(tmp_path):
    out, found = audit(tmp_path, "safe-treasury-agent", None, {"touchmark.json": json.dumps({"stellar_owner": OWNER})})
    assert found["intent-tmark-legacy"]["severity"] == "low"
    assert out["report"]["repository"]["ownership_claim"]["stellar_owner"] == OWNER


def test_template_is_prefilled_from_what_the_code_can_do():
    t = tmark.template({"payment", "stellar_signing"})
    assert t["authority"] == {"holds_keys": True, "key_source": "env", "signs": ["payments"]}
    assert t["limits"]["recipients"] == "allowlist"
    assert "limits" not in tmark.template(set())


# ----------------------------------------------------------------- caps in any asset, C agents, networks
def documented_tmark() -> dict:
    text = (ROOT / "docs/TMARK.md").read_text()
    return json.loads(text.split("## Example", 1)[1].split("```json", 1)[1].split("```", 1)[0])


def test_the_documented_xlm_cap_is_kept_in_its_asset():
    parsed, errors = tmark.parse(json.dumps(documented_tmark()))
    assert errors == []
    tool = next(t for t in tmark.to_declaration(parsed)["tools"] if t["name"] == "send_payment")
    assert tool["spend_limit"] == {"amount": "500.0000000", "asset": "XLM"} and tool["spend_limit_usdc"] is None
    assert tmark.stroops("0.5") == 5_000_000 and tmark.stroops("500") == 5_000_000_000


def test_a_usdc_cap_also_fills_the_older_field():
    usdc = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
    doc = documented_tmark()
    doc["tools"][0]["max_amount"] = {"amount": "25", "asset": usdc}
    tool = tmark.to_declaration(tmark.parse(json.dumps(doc))[0])["tools"][0]
    assert tool["spend_limit"] == {"amount": "25.0000000", "asset": usdc} and tool["spend_limit_usdc"] == 25.0


def test_a_declared_cap_in_any_asset_counts_as_a_cap(settings, run):
    from backend.app.models import AgentArtifact, SourceKind, ToolSpec
    from backend.app.swarm.economic import EconomicAuditor
    from backend.app.swarm.security import SecurityAuditor

    def findings(cap):
        tool = ToolSpec(name="send_payment", requires_signature=True, scopes=["payments", "sign"], spend_limit=cap)
        artifact = AgentArtifact(name="a", source_kind=SourceKind.UPLOAD, source_ref="t", tools=[tool],
                                 system_prompt="You pay listed suppliers.")
        security = run(SecurityAuditor(settings).run(artifact, deep=True))
        economic = run(EconomicAuditor(settings).run(artifact, deep=True))
        e01 = next(s for s in economic.scenarios if s.scenario_id == "E-01")
        return {f.id for f in security.findings + economic.findings}, e01.passed

    ids, passed = findings({"amount": "500.0000000", "asset": "XLM"})
    assert "security-unbounded-spend" not in ids and "economic-no-spend-policy" not in ids and passed
    ids, passed = findings(None)  # near miss: no cap at all
    assert "security-unbounded-spend" in ids and not passed


def test_the_documented_example_with_its_code_enforced_cap_has_no_unbounded_spend(tmp_path):
    out, found = audit(tmp_path, "safe-treasury-agent", documented_tmark())
    assert "security-unbounded-spend" not in found and "economic-no-spend-policy" not in found


def test_a_c_account_agent_is_read_as_a_contract(tmp_path, monkeypatch):
    from backend.app.stellar.soroban_reader import SorobanReader
    agent = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
    doc = example_tmark()
    doc["authority"]["agent_account"] = agent
    declaration = tmark.to_declaration(tmark.parse(json.dumps(doc))[0])
    assert declaration["agent_contract_id"] == agent and declaration["agent_wallet"] == ""

    read: list[str] = []

    async def contract(self, contract_id, **_):
        read.append(contract_id)
        return {"status": "found", "contract_id": contract_id, "network": self.network, "executable": "wasm",
                "wasm_hash": "00" * 32, "functions": []}
    monkeypatch.setattr(SorobanReader, "contract", contract)
    out, _ = audit(tmp_path / "off", "safe-treasury-agent", doc)
    assert out["report"]["agent"]["agent_contract_id"] == agent and read == []  # ledger reads are off
    root = tmp_path / "on" / "safe-treasury-agent"
    shutil.copytree(ROOT / "examples/demo/safe-treasury-agent", root)
    (root / ".tmark").write_text(json.dumps(doc))
    settings = Settings(_env_file=None, enable_onchain_verification=True)
    monkeypatch.setattr("backend.app.services.repo_audit._chain_facts", _no_account)
    out = asyncio.run(audit_repository(root, name="a", purpose="", settings=settings, deep=False))
    assert read == [agent] and out["report"]["agent"]["agent_contract_id"] == agent
    assert out["report"]["agent"]["wallet"] == ""


async def _no_account(*_args, **_kwargs):
    return {}


def network_findings(tmp_path, network: str, code: str):
    doc = example_tmark()
    doc["agent"]["network"] = network
    _, found = audit(tmp_path, "safe-treasury-agent", doc, {"src/net.ts": code})
    return found.get("intent-tmark-network-mismatch")


def test_a_pubnet_caip2_id_breaks_a_testnet_declaration(tmp_path):
    finding = network_findings(tmp_path / "a", "testnet", "export const cfg = { network: 'stellar:pubnet' };\n")
    assert finding["severity"] == "high" and "src/net.ts:1" in finding["evidence"]
    # A switch that can pick the public network is not a map that merely lists it.
    ternary = "export const passphrase = (n: string) => n === 'pubnet' ? Networks.PUBLIC : Networks.TESTNET;\n"
    assert network_findings(tmp_path / "b", "testnet", ternary)["severity"] == "high"


def test_a_network_keyed_map_does_not_break_a_testnet_declaration(tmp_path):
    usdc = ("export const USDC = {'stellar:pubnet': 'CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75',\n"
            "  'stellar:testnet': 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA'}[NET];\n"
            "// mainnet: https://horizon.stellar.org\n")
    assert network_findings(tmp_path, "testnet", usdc) is None


def test_mainnet_declared_with_only_testnet_code_is_low(tmp_path):
    finding = network_findings(tmp_path / "a", "mainnet", "export const NET = 'stellar:testnet';\n")
    assert finding["severity"] == "low" and "src/index.ts" in finding["evidence"]
    # Near misses: the code can still select mainnet.
    assert network_findings(tmp_path / "b", "mainnet", "export const NET = process.env.STELLAR_NETWORK;\n") is None
    assert network_findings(tmp_path / "c", "mainnet", "export const NET = isProd ? 'mainnet' : 'testnet';\n") is None


def test_a_private_field_is_code_and_a_python_comment_is_not(tmp_path):
    field = "export class Wallet {\n  #horizon = 'https://horizon.stellar.org';\n}\n"
    assert network_findings(tmp_path / "a", "testnet", field)["severity"] == "high"
    assert not network_hits({"src/net.py": "# mainnet: https://horizon.stellar.org\nHORIZON = 'https://horizon-testnet.stellar.org'\n"},
                            _MAINNET)


def test_a_nested_network_keyed_config_does_not_break_a_testnet_declaration(tmp_path):
    nested = ("export const CONFIG = {\n  mainnet: {\n    horizonUrl: 'https://horizon.stellar.org',\n"
              "    passphrase: Networks.PUBLIC,\n  },\n  testnet: {\n    horizonUrl: 'https://horizon-testnet.stellar.org',\n"
              "    passphrase: Networks.TESTNET,\n  },\n}[process.env.NET];\n")
    assert network_findings(tmp_path / "a", "testnet", nested) is None
    # Near miss: a block under a key that is not a network, with no testnet sibling.
    server = "export const CONFIG = {\n  server: {\n    horizonUrl: 'https://horizon.stellar.org',\n  },\n};\n"
    assert network_findings(tmp_path / "b", "testnet", server)["severity"] == "high"


def test_a_long_line_before_a_network_marker_costs_little():
    # Minified code or a hex blob before the marker; then thousands of keyed markers on one line.
    for line, limit in (("a" * 100_000 + " https://horizon.stellar.org", 0.1), ("x." * 50_000 + "horizon.stellar.org", 0.1),
                        ("mainnet: 'https://horizon.stellar.org', testnet: 'x', " * 3_000, 0.5),
                        ("{ mainnet: {" + " u: 'https://horizon.stellar.org'," * 3_000 + " }, testnet: {} }", 0.5),
                        # Nested keyed blocks, each with a marker, whose testnet sibling follows them all.
                        ("c = " + "mainnet: { u: 'https://horizon.stellar.org', " * 1_400 + "}" * 1_400 + " testnet: {}", 0.5)):
        started = time.perf_counter()
        network_hits({"src/min.js": line + "\n"}, _MAINNET)
        assert time.perf_counter() - started < limit, line[:20]


def test_a_network_the_paid_server_or_a_tool_picks_breaks_a_testnet_declaration(tmp_path):
    mpp = ("import { stellar } from '@stellar/mpp/charge/client';\n"
           "export const method = stellar.charge({ secretKey: process.env.STELLAR_SECRET });\n")
    finding = network_findings(tmp_path / "a", "testnet", mpp)
    assert finding["severity"] == "high" and "the paid server's challenge picks the network" in finding["evidence"]
    # Near miss: the RPC is pinned, so a pubnet challenge fails instead of paying.
    pinned = mpp.replace("process.env.STELLAR_SECRET", "process.env.STELLAR_SECRET, rpcUrl: process.env.RPC_URL")
    assert network_findings(tmp_path / "b", "testnet", pinned) is None


def test_a_marker_in_a_trailing_comment_a_block_comment_or_a_docstring_is_not_use(tmp_path):
    for name, text in {
        "src/a.ts": "const url = 'https://horizon-testnet.stellar.org'; // not https://horizon.stellar.org\n",
        "src/b.ts": "/*\n  Production uses https://horizon.stellar.org\n*/\nconst url = 'https://horizon-testnet.stellar.org';\n",
        "src/c.py": 'def submit(tx):\n    """Testnet only; mainnet (horizon.stellar.org) is refused."""\n    return tx\n',
        "src/d.py": '"""\nNotes:\n  horizon.stellar.org is mainnet\n"""\nURL = "https://horizon-testnet.stellar.org"\n',
    }.items():
        assert not network_hits({name: text}, _MAINNET), name
    # Near misses: the same marker as a value, and a '//' inside a string, are code.
    assert network_hits({"src/e.ts": "const url = 'https://horizon.stellar.org'; // mainnet\n"}, _MAINNET) == ["src/e.ts:1"]
    assert network_hits({"src/f.py": "URL = 'https://horizon.stellar.org'  # not a docstring\n"}, _MAINNET) == ["src/f.py:1"]
    # A Rust lifetime or a quote in a regular-expression literal opens no string: the comment after it is a comment.
    assert not network_hits({"src/g.rs": "fn f(x: &'static str) {} // PUBLIC_NETWORK_PASSPHRASE\n"}, _MAINNET)
    assert not network_hits({"src/h.ts": "const q = /'/; // https://horizon.stellar.org\n"}, _MAINNET)
    assert network_hits({"src/i.rs": "fn f(x: &'static str) { PUBLIC_NETWORK_PASSPHRASE }\n"}, _MAINNET) == ["src/i.rs:1"]
    trailing = "export const HORIZON = 'https://horizon-testnet.stellar.org'; // mainnet would be https://horizon.stellar.org\n"
    assert network_findings(tmp_path, "testnet", trailing) is None


def test_a_guard_that_refuses_mainnet_is_not_use_but_one_that_requires_it_is(tmp_path):
    guard = ("import { Networks } from '@stellar/stellar-sdk';\nexport function assertTestnet(p: string) {\n"
             "  if (p === Networks.PUBLIC) {\n    console.error('refused');\n    throw new Error('this agent refuses mainnet');\n  }\n}\n")
    assert network_findings(tmp_path / "a", "testnet", guard) is None
    python = ("from stellar_sdk import Network\n\ndef check(p):\n    if p == Network.PUBLIC_NETWORK_PASSPHRASE:\n"
              "        raise ValueError('mainnet is not allowed')\n")
    assert not network_hits({"agent.py": python}, _MAINNET)
    for near_miss in (guard.replace("p === Networks.PUBLIC", "p !== Networks.PUBLIC"),          # mainnet only
                      guard.replace("p === Networks.PUBLIC", "p === Networks.PUBLIC && !allow"),  # refusal can be lifted
                      guard.replace("throw new Error('this agent refuses mainnet')", "server = mainnet()"),
                      guard + "export const passphrase = Networks.PUBLIC;\n"):
        assert network_hits({"src/net.ts": near_miss}, _MAINNET), near_miss
    assert network_hits({"agent.py": python.replace("raise ValueError('mainnet is not allowed')", "submit()")}, _MAINNET)


def test_many_refusal_guards_or_an_unclosed_guard_cost_linear_time():
    for name, text in (("src/a.ts", "if (p === Networks.PUBLIC) throw new Error('x');\n" * 8_000),
                       ("src/b.ts", "if (p === Networks.PUBLIC) {" + " x;" * 100_000),
                       ("b.py", "if p == Network.PUBLIC_NETWORK_PASSPHRASE:\n    raise ValueError('x')\n" * 5_000)):
        started = time.perf_counter()
        network_hits({name: text}, _MAINNET)
        assert time.perf_counter() - started < 1.0, name


def test_one_python_guard_with_thousands_of_markers_is_read_once():
    # 4000 or-ed markers in one `if` (160 KB on one line), and a long inline branch.
    chained = "if " + " or ".join(["p == Network.PUBLIC_NETWORK_PASSPHRASE"] * 4_000) + ":\n    raise ValueError('no')\n"
    for text, expected in ((chained, []), (chained.replace(":\n", " and strict:\n", 1), ["a.py:1"]),
                           ("if p == Network.PUBLIC_NETWORK_PASSPHRASE:" + " " * 200_000 + ";\n", ["a.py:1"])):
        started = time.perf_counter()
        assert network_hits({"a.py": text}, _MAINNET) == expected
        assert time.perf_counter() - started < 1.0
