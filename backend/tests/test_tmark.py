""".tmark: one strict declaration file, checked against the code."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from backend.app.config import Settings
from backend.app.services import tmark
from backend.app.services.repo_audit import audit_repository

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
