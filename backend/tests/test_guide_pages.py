"""The Guide (/guide), the .tmark guide (/guide/tmark) and the mascot assets.

The pages are static, so the tests pin what can silently break them: the routes and the public
Vercel surface, the files they load, the ids their scripts look up, and the .tmark builder's
client-side rules, which must say exactly what the server says.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.services import tmark

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
PAGES = {"/guide": "guide.html", "/guide/tmark": "guide-tmark.html"}
NODE = shutil.which("node")


def test_guide_pages_are_served_and_linked_from_the_home_page():
    with TestClient(api.app) as client:
        guide = client.get("/guide")
        tmark_page = client.get("/guide/tmark")
        home = client.get("/")
        assets = [client.get(f"/ui/{name}") for name in
                  ("guide.css", "guide.js", "mascot.css", "mascot.js", "tmark-builder.css", "tmark-builder.js")]
        mascot = client.get("/mascot/idle.svg")
    assert guide.status_code == 200 and 'id="guide-start"' in guide.text
    assert 'href="/guide/tmark"' in guide.text
    assert tmark_page.status_code == 200 and 'id="tmark-builder"' in tmark_page.text
    assert 'data-endpoint="/api/v1/tmark/check"' in tmark_page.text
    assert 'href="/guide"' in home.text
    assert all(a.status_code == 200 for a in assets)
    assert mascot.status_code == 200 and 'data-state="idle"' in mascot.text


def test_guide_routes_are_on_the_public_vercel_surface():
    """app.py answers 404 for any path it does not list; the guide must be listed."""
    entry = (ROOT / "app.py").read_text(encoding="utf-8")
    for path in ('"/guide"', '"/guide/tmark"', '"/mascot/"'):
        assert path in entry


@pytest.mark.parametrize("page", PAGES.values())
def test_guide_pages_load_only_local_files_that_exist(page):
    html = (FRONTEND / page).read_text(encoding="utf-8")
    refs = re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', html)
    assert refs, "no assets found"
    for ref in refs:
        assert ref.startswith("/ui/"), f"{page} loads a non-local asset: {ref}"
        assert (FRONTEND / ref.removeprefix("/ui/")).is_file(), f"{page}: missing {ref}"
    # The page CSP is script-src 'self': inline scripts would not run.
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)


def test_every_id_the_guide_scripts_look_up_exists():
    guide = (FRONTEND / "guide.html").read_text(encoding="utf-8")
    tmark_page = (FRONTEND / "guide-tmark.html").read_text(encoding="utf-8")
    ids = lambda html: set(re.findall(r'\bid="([^"]+)"', html))  # noqa: E731
    looked_up = lambda js: set(re.findall(r'(?:\$|getElementById)\("([A-Za-z0-9_-]+)"\)', js))  # noqa: E731
    # guide.js runs on both pages and tolerates a missing element; every id it uses must exist on one.
    assert looked_up((FRONTEND / "guide.js").read_text(encoding="utf-8")) <= ids(guide) | ids(tmark_page)
    builder = looked_up((FRONTEND / "tmark-builder.js").read_text(encoding="utf-8"))
    assert builder <= ids(tmark_page), sorted(builder - ids(tmark_page))


@pytest.mark.parametrize("page", PAGES.values())
def test_every_form_control_has_a_label(page):
    html = (FRONTEND / page).read_text(encoding="utf-8")
    labelled = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', html))
    for tag in re.findall(r"<(?:input|textarea|select)\b[^>]*>", html):
        if 'type="radio"' in tag or 'type="checkbox"' in tag or "aria-label=" in tag:
            continue  # radios and checkboxes sit inside their <label>
        control = re.search(r'\bid="([^"]+)"', tag)
        assert control and control.group(1) in labelled, f"{page}: unlabelled control {tag[:80]}"


def _node(script: str) -> str:
    if not NODE:
        pytest.skip("node is not installed")
    return subprocess.run([NODE, "-e", script], cwd=ROOT, capture_output=True, text=True, check=True, timeout=60).stdout


_RULES = """
global.window = global; global.location = { search: "" };
global.document = { querySelectorAll: () => [], querySelector: () => null, getElementById: () => null };
require("./frontend/tmark-builder.js");
"""


def test_builder_examples_are_valid_tmark_files():
    examples = json.loads(_node(_RULES + "process.stdout.write(JSON.stringify(window.TmarkRules.EXAMPLES));"))
    assert {"minimal", "payments", "mcp", "sdk"} <= set(examples)
    for name, example in examples.items():
        if name == "blank":
            continue
        parsed, errors = tmark.parse(json.dumps(example))
        assert parsed is not None, f"{name}: {errors}"
    # The payments example is the demo agent's own declaration.
    demo = json.loads((ROOT / "examples/demo/safe-treasury-agent/.tmark").read_text())
    assert tmark.parse(json.dumps(examples["payments"]))[0] == tmark.parse(json.dumps(demo))[0]


_BROKEN = [
    {},
    {"tmark": 1, "agent": {"name": "x", "purpose": "short", "kind": "bot", "network": "pubnet"},
     "authority": {"holds_keys": True, "key_source": "none"}, "extra": True},
    {"tmark": "1", "agent": {"name": "Payer", "purpose": "Pays suppliers on request, twenty chars", "kind": "sdk", "network": "testnet"},
     "authority": {"holds_keys": True, "key_source": "env", "signs": ["payments"]}},
    {"tmark": "1", "agent": {"name": "Payer", "purpose": "Pays suppliers on request, twenty chars", "kind": "sdk", "network": "testnet"},
     "authority": {"holds_keys": False, "key_source": "kms", "signs": ["payments", "payments"]}},
    {"tmark": "1", "agent": {"name": "Payer", "purpose": "Pays suppliers on request, twenty chars", "kind": "sdk", "network": "testnet"},
     "owner": {"stellar_account": "GDM7FY4WBPRLTY4WYE7FKFHQVUI5FYE3WDLNHTDVNKMJ2VNTTQEPBYZA"},
     "authority": {"holds_keys": True, "key_source": "env", "signs": ["payments"], "agent_account": "XYZ"},
     "limits": {"per_payment": {"amount": "25.00000001", "asset": "USDC"}, "recipients": "none", "human_approval": "sometimes"},
     "tools": [{"name": "bad name", "description": "short", "moves_funds": False, "signs": True, "network": True,
                "max_amount": {"amount": "5", "asset": "XLM"}}],
     "forbidden": ["no"], "entrypoints": [{"path": "../x.py", "symbol": "1main"}], "contact": {"security": "x"}},
    {"tmark": "1", "agent": {"name": "Payer", "purpose": "Pays suppliers on request, twenty chars", "kind": "sdk", "network": "testnet"},
     "authority": {"holds_keys": True, "key_source": "env", "signs": []},
     "limits": {"recipients": "none", "human_approval": "never"},
     "tools": [{"name": "pay", "description": "pays someone", "moves_funds": True, "signs": True, "network": True}]},
    {"tmark": "1", "agent": {"name": "Payer", "purpose": "Pays suppliers on request, twenty chars", "kind": "sdk", "network": "testnet"},
     "authority": {"holds_keys": False, "key_source": "none"},
     "tools": [{"name": "a", "description": "reads things", "moves_funds": False, "signs": False, "network": True},
               {"name": "a", "description": "reads more things", "moves_funds": False, "signs": False, "network": True}]},
]


def test_builder_rules_say_what_the_server_says():
    """The builder validates in the browser with its own copy of the rules; each message
    must match services.tmark.parse word for word, or users fix the wrong thing."""
    script = _RULES + f"const cases = {json.dumps(_BROKEN)};" + """
process.stdout.write(JSON.stringify(cases.map((c) => window.TmarkRules.validate(c).map((e) => `${e.path}: ${e.msg}`))));"""
    client_side = json.loads(_node(script))
    for case, local in zip(_BROKEN, client_side):
        _, server = tmark.parse(json.dumps(case))
        assert sorted(local) == sorted(server), json.dumps(case)[:120]


def test_standalone_mascot_files_match_the_inline_mascot():
    if not NODE:
        pytest.skip("node is not installed")
    result = subprocess.run([NODE, "scripts/build_mascot.cjs", "--check"], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    for state in ("idle", "scanning", "success", "warning", "error", "pointing"):
        assert (ROOT / "public/mascot" / f"{state}.svg").is_file()
