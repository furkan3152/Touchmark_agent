"""The older declaration files (agentveritas.json, touchmark.json, veritas.json) still feed the audit, but never rescue it.

The examples now carry a .tmark, which takes precedence; these tests remove it to exercise the old files."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from backend.app.config import Settings
from backend.app.services.repo_audit import audit_repository, declarations

ROOT = Path(__file__).resolve().parents[2]
DECLARATION = {
    "stellar_owner": "GDM7FY4WBPRLTY4WYE7FKFHQVUI5FYE3WDLNHTDVNKMJ2VNTTQEPBYZV",
    "purpose": "Pays approved supplier invoices from the treasury on Stellar testnet.",
    "forbidden_goals": ["pay a recipient outside the approved supplier table"],
    "tools": [{"name": "send_payment", "requires_signature": True, "spend_limit_usdc": 500},
              {"name": "fetch_invoice", "network_access": True}],
    "discloses_ai": True,
}


def _copy(example, root):
    shutil.copytree(ROOT / "examples/demo" / example, root)
    (root / ".tmark").unlink(missing_ok=True)


def audit(tmp_path, example, declaration=None, blueprint=None):
    root = tmp_path / example
    _copy(example, root)
    if declaration is not None:
        (root / "agentveritas.json").write_text(json.dumps(declaration))
    if blueprint is not None:
        (root / "veritas.json").write_text(json.dumps(blueprint))
    out = asyncio.run(audit_repository(root, name=example, purpose="", settings=Settings(_env_file=None), deep=False))
    return out, {f["id"] for f in out["report"]["findings"]}


def test_a_declaration_closes_declaration_gaps_without_changing_the_decision(tmp_path):
    before, before_ids = audit(tmp_path / "a", "safe-treasury-agent")
    after, after_ids = audit(tmp_path / "b", "safe-treasury-agent", DECLARATION)
    assert {"intent-undeclared-financial-capability", "compliance-no-ai-disclosure"} <= before_ids - after_ids
    assert after["decision"] == before["decision"] == "pass"
    record = after["report"]["repository"]["declarations"]
    assert record["files"] == ["agentveritas.json"] and record["tools_declared"] == ["send_payment", "fetch_invoice"]
    assert after["report"]["repository"]["ownership_claim"]["stellar_owner"] == DECLARATION["stellar_owner"]
    assert after["report"]["subject"]["purpose"] == DECLARATION["purpose"]


def test_a_declared_limit_the_code_does_not_enforce_is_reported_not_credited(tmp_path):
    before, _ = audit(tmp_path / "a", "unsafe-treasury-agent")
    after, ids = audit(tmp_path / "b", "unsafe-treasury-agent", DECLARATION)
    assert "security-declared-limit-not-enforced" in ids
    assert after["decision"] == "needs_fixes" and after["report"]["result"]["overall_score"] <= before["report"]["result"]["overall_score"]


def test_invalid_declarations_are_reported_and_ignored(tmp_path):
    out, _ = audit(tmp_path, "safe-treasury-agent", {"tools": [{"name": "x", "spend_limit_usdc": -5}]},
                   blueprint={"protocol": "veritas.blueprint/v1", "name": "x"})
    record = out["report"]["repository"]["declarations"]
    assert record["files"] == [] and len(record["errors"]) == 2 and out["decision"] == "pass"


def test_blueprint_purpose_and_missing_components():
    blueprint = {"protocol": "veritas.blueprint/v1", "name": "t", "purpose": "Pays approved invoices only.",
                 "components": [{"id": "entry", "role": "entrypoint", "path": "src/index.ts"}],
                 "entrypoint": {"component": "entry", "symbol": "main"}}
    found = declarations({"blueprint": {"path": "veritas.json", "text": json.dumps(blueprint)}})
    assert found["files"] == ["veritas.json"] and found["blueprint"].purpose == "Pays approved invoices only."


def test_touchmark_json_is_read_and_preferred(tmp_path):
    root = tmp_path / "agent"
    _copy("safe-treasury-agent", root)
    (root / "agentveritas.json").write_text(json.dumps({"purpose": "Old name, should be ignored here."}))
    (root / "touchmark.json").write_text(json.dumps(DECLARATION))
    out = asyncio.run(audit_repository(root, name="a", purpose="", settings=Settings(_env_file=None), deep=False))
    assert out["report"]["repository"]["declarations"]["files"] == ["touchmark.json"]
    assert out["report"]["subject"]["purpose"] == DECLARATION["purpose"]
