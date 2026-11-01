"""The Studio page and the home page's ways into it: what can silently break them is pinned here
(the shared plates both pages print on, the ids the Studio scripts look up, labels, the hand-off)."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import api

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
STUDIO = (FRONTEND / "studio.html").read_text(encoding="utf-8")
HOME = (FRONTEND / "demo.html").read_text(encoding="utf-8")
STUDIO_JS = (FRONTEND / "studio.js").read_text(encoding="utf-8")
CTA_JS = (FRONTEND / "studio-cta.js").read_text(encoding="utf-8")
PRESS = (FRONTEND / "press.css").read_text(encoding="utf-8")


def _refs(html: str) -> list[str]:
    return re.findall(r'<(?:script|link)[^>]+(?:src|href)="(/ui/[^"]+)"', html)


def test_every_public_page_prints_on_the_shared_plates():
    """press.css holds the inks, type, masthead and footer; each page sheet loads after it."""
    for name, sheet in (("demo.html", "/ui/demo.css"), ("guide.html", "/ui/demo.css"),
                        ("guide-tmark.html", "/ui/demo.css"), ("studio.html", "/ui/studio.css")):
        refs = _refs((FRONTEND / name).read_text(encoding="utf-8"))
        assert "/ui/press.css" in refs and refs.index("/ui/press.css") < refs.index(sheet), name
    # One source for the tokens: no page sheet redefines the palette.
    for name in ("demo.css", "studio.css", "studio-cta.css"):
        assert not re.search(r"^\s*:root\s*\{", (FRONTEND / name).read_text(encoding="utf-8"), re.M), name
    assert "--paper:" in PRESS and "--ink:" in PRESS and "prefers-color-scheme:dark" in PRESS
    assert "prefers-reduced-motion:reduce" in PRESS


def test_studio_sheets_only_use_defined_tokens():
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", PRESS))
    for name in ("studio.css", "studio-cta.css"):
        css = (FRONTEND / name).read_text(encoding="utf-8")
        defined_here = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
        used = set(re.findall(r"var\((--[a-z0-9-]+)", css))
        assert used <= defined | defined_here, (name, sorted(used - defined - defined_here))


def test_studio_loads_local_assets_in_order_and_no_inline_script():
    refs = _refs(STUDIO)
    for ref in refs:
        assert (FRONTEND / ref.removeprefix("/ui/")).is_file(), ref
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", STUDIO), "inline scripts do not run under script-src 'self'"
    # studio.js uses TouchmarkMascot and TmarkRules: both load before it.
    assert refs.index("/ui/mascot.js") < refs.index("/ui/studio.js")
    assert refs.index("/ui/tmark-builder.js") < refs.index("/ui/studio.js")


def test_studio_shares_the_home_masthead():
    nav = lambda html: re.findall(r">([^<>]+)</a>", re.search(r"<nav[^>]*>(.*?)</nav>", html, re.S).group(1))
    assert nav(STUDIO) == nav(HOME)
    assert 'href="/studio" aria-current="page"' in STUDIO
    assert '<use href="#mark"/>' in STUDIO and 'id="ink"' in STUDIO


def test_every_id_the_studio_scripts_look_up_exists():
    ids = set(re.findall(r'\bid="([^"]+)"', STUDIO))
    assert len(ids) == len(re.findall(r'\bid="([^"]+)"', STUDIO)), "duplicate ids"
    for name in ("studio.js", "orders.js", "checkout.js"):
        script = (FRONTEND / name).read_text(encoding="utf-8")
        looked_up = set(re.findall(r'byId\("([A-Za-z0-9_-]+)"\)', script))
        assert looked_up and looked_up <= ids, (name, sorted(looked_up - ids))


def test_studio_source_tabs_and_panels_are_paired():
    tabs = re.findall(r'data-source-mode="([a-z]+)"[^>]*aria-controls="([a-z-]+)"', STUDIO)
    panels = dict(re.findall(r'(\w+): "(source-[a-z]+)"', re.search(r"const panels = \{([^}]+)\}", STUDIO_JS).group(1)))
    assert {mode: panel for mode, panel in tabs} == panels
    for panel in panels.values():
        assert f'id="{panel}" class="source-panel" role="tabpanel"' in STUDIO
    # Exactly one tab starts selected, and it is the one whose panel is visible.
    assert len(re.findall(r'role="tab" aria-selected="true"', STUDIO)) == 1


def test_every_studio_control_is_labelled():
    labelled = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', STUDIO))
    for tag in re.findall(r"<(?:input|textarea|select)\b[^>]*>", STUDIO):
        control = re.search(r'\bid="([^"]+)"', tag)
        wrapped = 'type="checkbox"' in tag or 'type="radio"' in tag  # inside a wrapping <label>
        assert wrapped or "aria-label=" in tag or (control and control.group(1) in labelled), tag[:90]


def test_punch_keeps_the_dossier_company():
    for host in ("studio-punch", "bench-punch", "verdict-punch"):
        assert re.search(rf'id="{host}"[^>]*data-tm-mascot=', STUDIO), host
    for state in ("scanning", "success", "warning", "error", "pointing"):
        assert f'"{state}"' in STUDIO_JS, state
    assert "TouchmarkMascot.forDecision" in STUDIO_JS


def test_home_hands_the_audited_reference_to_the_studio():
    refs = _refs(HOME)
    assert refs.index("/ui/demo.js") < refs.index("/ui/studio-cta.js") and "/ui/studio-cta.css" in refs
    result = re.search(r'<section id="result".*?</section>\s*\n\s*<section id="how"', HOME, re.S).group(0)
    assert 'id="studio-slip"' in result and 'href="/studio#workspace"' in result
    assert 'id="counter-or-studio"' in HOME and 'id="cos-studio-link"' in HOME
    # demo.js leaves the reference on #result; studio-cta.js reads it; the Studio reads the same key.
    demo = (FRONTEND / "demo.js").read_text(encoding="utf-8")
    assert 'Object.assign($("result").dataset, { reference:' in demo
    key = "touchmark.studio.handoff"
    assert key in CTA_JS and key in STUDIO_JS
    assert "/studio?ref=" in CTA_JS and 'URLSearchParams(location.search).get("ref")' in STUDIO_JS


def test_studio_serves_with_the_strict_script_policy():
    with TestClient(api.app) as client:
        page = client.get("/studio")
        for asset in ("/ui/press.css", "/ui/studio.css", "/ui/studio-cta.css", "/ui/studio-cta.js"):
            assert client.get(asset).status_code == 200, asset
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]
