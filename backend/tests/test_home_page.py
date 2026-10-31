"""The home page audit flow and the Studio page: what can silently break them is pinned here
(the files they load, the ids demo.js looks up, the stages the progress desk knows)."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import api

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
HOME = (FRONTEND / "demo.html").read_text(encoding="utf-8")
DEMO_JS = (FRONTEND / "demo.js").read_text(encoding="utf-8")


def test_the_home_page_loads_punch_and_the_tmark_rules_from_this_server():
    refs = re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', HOME)
    for ref in refs:
        assert ref.startswith("/ui/"), f"non-local asset {ref}"
        assert (FRONTEND / ref.removeprefix("/ui/")).is_file(), ref
    assert {"/ui/mascot.js", "/ui/mascot.css", "/ui/tmark-builder.js"} <= set(refs)
    # demo.js uses window.TmarkRules and TouchmarkMascot: both load before it.
    assert refs.index("/ui/tmark-builder.js") < refs.index("/ui/demo.js") and refs.index("/ui/mascot.js") < refs.index("/ui/demo.js")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", HOME), "inline scripts do not run under script-src 'self'"


def test_every_id_demo_js_looks_up_exists():
    ids = set(re.findall(r'\bid="([^"]+)"', HOME))
    looked_up = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', DEMO_JS))
    assert looked_up <= ids, sorted(looked_up - ids)


def test_the_desk_knows_every_stage_the_server_streams():
    emitted = set()
    for path in (ROOT / "backend/app").rglob("*.py"):
        emitted |= set(re.findall(r'\bemit\("([a-z_]+)"', path.read_text(encoding="utf-8")))
    shown = set(re.findall(r'data-stage="([a-z_]+)"', HOME))
    assert emitted and emitted <= shown, sorted(emitted - shown)


def test_the_consent_and_tmark_controls_are_labelled():
    labelled = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', HOME))
    for tag in re.findall(r"<(?:input|textarea|select)\b[^>]*>", HOME):
        control = re.search(r'\bid="([^"]+)"', tag)
        assert "aria-label=" in tag or (control and control.group(1) in labelled) or 'type="file"' in tag, tag[:80]
    assert 'aria-live="polite"' in HOME and 'id="desk-live"' in HOME
    # The consent copy says what is sent, to whom, and what happens without it.
    consent = re.search(r'id="consent-detail">([^<]+)<', HOME).group(1)
    assert "Anthropic" in consent and "verif" in consent and "rules" in consent


def test_studio_links_the_guide_and_shows_punch():
    with TestClient(api.app) as client:
        studio = client.get("/studio").text
    assert 'href="/guide"' in studio and 'data-tm-mascot="idle"' in studio
    assert "/ui/mascot.js" in studio and "/ui/mascot.css" in studio
