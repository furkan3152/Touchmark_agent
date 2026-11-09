"""Fixes from the code-health review: each test pins one defect that was found and fixed."""

from __future__ import annotations

import pytest

from backend.app.models import Severity
from backend.app.swarm.paths import is_testlike
from backend.app.swarm.stellar_native import _seed_severity


@pytest.mark.parametrize("path", [
    "testnet_wallet.py", "src/attestation.py", "src/latest.ts", "agent/inspect.py", "contest/pay.ts",
    "src/respect.py", "src/manifest.json", "src/latest_quote.rs",
])
def test_a_word_that_only_contains_test_is_shipped_code(path):
    assert not is_testlike(path)


@pytest.mark.parametrize("path", [
    "tests/test_x.py", "src/wallet_test.go", "src/wallet.test.ts", "src/wallet.spec.ts", "TestWallet.java",
    "conftest.py", "e2e-tests/run.ts", "examples/agent.py", "__tests__/a.js", "__mocks__/b.js",
    "src/mock_server.py", "fixtures/keys.json", "example.env", "docker-compose.test.yml",
])
def test_test_mock_fixture_and_example_paths_are_recognised(path):
    assert is_testlike(path)


def test_scripts_count_only_where_asked():
    assert not is_testlike("scripts/deploy.py")
    assert is_testlike("scripts/deploy.py", extra_dirs={"scripts"})


def test_a_seed_in_a_testnet_named_file_stays_critical_without_a_ledger_answer():
    # It used to be rated low: "testnet_wallet.py" contains "test".
    severity, _ = _seed_severity(None, ["src/testnet_wallet.py:3"])
    assert severity is Severity.CRITICAL
    assert _seed_severity(None, ["tests/test_wallet.py:3"])[0] is Severity.LOW


def test_every_host_the_pages_fetch_is_allowed_by_the_csp():
    # The Studio checkout used to post to an RPC host the CSP blocks, so no payment could be sent.
    import re
    from pathlib import Path
    from fastapi.testclient import TestClient
    from backend.app import api
    csp = TestClient(api.app, client=("192.0.2.92", 50000)).get("/api/v1/health").headers["content-security-policy"]
    allowed = set(re.search(r"connect-src ([^;]+)", csp).group(1).split())
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    for js in frontend.glob("*.js"):
        text = js.read_text()
        hosts = set(re.findall(r"""(?:const RPC|fetch\()\s*=?\s*["'`](https://[^/"'`]+)""", text))
        assert hosts <= allowed, (js.name, hosts - allowed)


@pytest.mark.parametrize("value,expected", [(64.6, 64), (64.99, 64), (65.0, 65), (100.0, 100), (0.4, 0),
                                            (float("nan"), 0), (True, 0), (-3, 0), (130, 100)])
def test_the_score_written_on_chain_is_rounded_down(value, expected):
    # A 64.6 report needs fixes; rounding it to 65 made it pass the credential contract's 65 floor.
    from backend.app.swarm.policy import chain_score
    assert chain_score(value) == expected


def test_a_model_opinion_without_code_never_rates_itself_above_medium():
    # The per-auditor LLM review let the model pick "critical" from the prompt and tool names alone.
    import asyncio
    from backend.app.config import Settings
    from backend.app.models import AgentArtifact
    from backend.app.swarm.economic import EconomicAuditor

    class Judge:
        async def judge(self, system, user):
            return {"findings": [{"title": "Drains the treasury", "detail": "It could.", "severity": "critical",
                                  "remediation": "Add caps."}]}

    auditor = EconomicAuditor(Settings(), Judge())
    from backend.app.models import SourceKind
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="a", system_prompt="pay anyone")
    found = asyncio.run(auditor.llm_review(artifact, []))
    assert [f.severity for f in found] == [Severity.MEDIUM]


def test_the_public_site_does_not_serve_the_operator_console():
    # frontend/index.html and app.js call operator APIs the public site refuses: the page was reachable at /ui/.
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    code = ("from fastapi.testclient import TestClient\nimport app\nc = TestClient(app.app)\n"
            "print([c.get(p).status_code for p in ('/ui/', '/ui/index.html', '/ui/app.js', '/ui/demo.js', '/docs', '/book')])")
    out = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True, timeout=120)
    assert out.stdout.strip().splitlines()[-1] == "[404, 404, 404, 200, 200, 200]", out.stderr[-500:]


def test_hidden_elements_with_a_display_rule_stay_hidden():
    # .book-strip{display:flex} beat the hidden attribute, so the home page showed "0 audits" before the book loaded.
    import re
    from pathlib import Path
    css = (Path(__file__).resolve().parents[2] / "frontend/assay.css").read_text()
    for cls in ("book-strip", "assay"):
        assert re.search(rf"\.{cls}\{{[^}}]*display:(flex|grid)", css)
        assert re.search(rf"\.{cls}\[hidden\][^{{]*\{{display:none\}}", css), cls


def test_credential_issuance_streams_heartbeats_until_the_result(monkeypatch):
    # Four Soroban transactions take about a minute; unstreamed, a proxy cut the request at ~30 s
    # and the user saw a failure while the credential was being issued.
    import json
    import time as _time
    from fastapi.testclient import TestClient
    from backend.app import api
    from backend.app.services import demo_flow

    async def slow_issue(ticket, signed_xdr=""):
        _time.sleep(0.35)  # synchronous, like the Soroban client: must not block the event loop
        return {"token_id": "t" * 64, "ticket": ticket}
    monkeypatch.setattr(demo_flow, "issue_demo_credential", slow_issue)
    monkeypatch.setattr(api, "HEARTBEAT_SECONDS", 0.1)
    monkeypatch.setattr(api, "_demo_issuance_allowed", lambda client: True)
    client = TestClient(api.app, client=("192.0.2.93", 50000))
    response = client.post("/api/v1/demo/credential", json={"ticket": "x" * 40},
                           headers={"Accept": "application/x-ndjson"})
    events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    kinds = [e["type"] for e in events]
    assert "heartbeat" in kinds and kinds[-1] == "result"
    assert events[-1]["data"]["token_id"] == "t" * 64
    plain = client.post("/api/v1/demo/credential", json={"ticket": "y" * 40})
    assert plain.status_code == 200 and plain.json()["ticket"] == "y" * 40


def test_testnet_endpoints_are_defined_once():
    # The RPC host, Horizon, the explorer and the passphrase lived in six modules; one drifted
    # (the checkout's RPC host) and the Studio could not pay. They now come from stellar/networks.py.
    import re
    from pathlib import Path
    app = Path(__file__).resolve().parents[2] / "backend/app"
    pattern = re.compile(r"horizon-testnet\.stellar\.org|stellar\.expert/explorer/testnet|"
                         r"soroban-rpc\.testnet\.stellar\.gateway\.fm|\"Test SDF Network ; September 2015\"")
    allowed = {"stellar/networks.py", "stellar/canonical.py"}  # the definition, and the reference catalog the rules read
    offenders = [str(p.relative_to(app)) for p in app.rglob("*.py")
                 if str(p.relative_to(app)) not in allowed and pattern.search(p.read_text())]
    assert offenders == []


def test_the_book_jobs_and_allowance_choose_their_store_by_one_rule(monkeypatch):
    from backend.app.config import Settings
    from backend.app.services import assay_book, audit_jobs
    from backend.app.services.rate_limit import BlobStore
    blob = Settings(blob_read_write_token="vercel_blob_rw_abc_def")
    assert isinstance(assay_book.store_from_settings(blob), BlobStore)
    assert isinstance(audit_jobs.job_store_from_settings(blob), BlobStore)
    off = Settings(deep_review_limit_store="none", blob_read_write_token="vercel_blob_rw_abc_def")
    assert assay_book.store_from_settings(off) is None and audit_jobs.job_store_from_settings(off) is None


def test_the_throttle_and_the_allowance_identify_a_client_alike(monkeypatch):
    from types import SimpleNamespace
    from backend.app import api
    from backend.app.studio_guard import StudioGuard
    monkeypatch.setenv("VERCEL", "1")
    headers = {"x-real-ip": "203.0.113.7", "x-forwarded-for": "198.51.100.1, 203.0.113.9"}
    request = SimpleNamespace(headers=headers, client=SimpleNamespace(host="10.0.0.1"))
    scope = {"headers": [(k.encode(), v.encode()) for k, v in headers.items()], "client": ("10.0.0.1", 1)}
    assert api._demo_client(request) == StudioGuard(None)._client(scope) == "203.0.113.7"
    monkeypatch.delenv("VERCEL")
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    assert api._demo_client(request) == StudioGuard(None)._client(scope) == "10.0.0.1"


def test_shared_definitions_have_one_source():
    from backend.app.services import file_map, severity
    from backend.app.swarm import agentic_paths, capabilities, judge, policy, security
    # Stellar authority is the map's authority without a bare secret or a shell (see severity.py).
    assert severity.AUTHORITY_KINDS == file_map.AUTHORITY_KINDS - {"holds_or_loads_secret", "executes_code"}
    assert security.SIGNING_SCOPES is capabilities.SIGNING_SCOPES is agentic_paths._SIGNING_SCOPES
    assert (policy.PASS_SCORE, judge.Badge.CAUTION) in judge.BADGE_THRESHOLDS


def test_every_page_has_the_same_menu_and_a_skip_link():
    # The menu differed on four kinds of page (book, docs and reports had no Studio; the guides
    # had no book or docs), and only the Studio had a skip link.
    import re
    from pathlib import Path
    from backend.app.services import assay_render
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    pages = {name: (frontend / name).read_text() for name in
             ("demo.html", "studio.html", "guide.html", "guide-tmark.html", "book.html", "docs.html")}
    pages["report page"] = assay_render.missing_page()
    menu = lambda html: re.findall(r">([^<>]+)</a>", re.search(r"<nav[^>]*>(.*?)</nav>", html, re.S).group(1))  # noqa: E731
    home = menu(pages["demo.html"])
    assert home == ["How it works", "Video", "Assay book", "Docs", "Guide", "GitHub", "Studio"]
    for name, html in pages.items():
        assert menu(html) == home, name
        skip = re.search(r'<a class="skip" href="#([\w-]+)"', html)
        assert skip and f'id="{skip.group(1)}"' in html, name


def test_stellar_toml_lists_the_contracts_the_demo_uses():
    # It listed only the paid-order pilot's contracts, so the demo's credential contract and the
    # assay book account could not be found from the domain (SEP-1).
    import tomllib
    from fastapi.testclient import TestClient
    from backend.app import api
    from backend.app.services.demo_flow import manifest
    toml = tomllib.loads(TestClient(api.app, client=("192.0.2.94", 50000)).get("/.well-known/stellar.toml").text)
    demo = manifest()
    assert toml["ACCOUNTS"] == [demo["operator"]]
    assert toml["DOCUMENTATION"]["ORG_URL"] == "https://usetouchmark.app"
    section = toml["TOUCHMARK"]
    assert section["ASSAY_BOOK_ACCOUNT"] == demo["operator"]
    assert section["DEMO_REGISTRY_CONTRACT"] == demo["contracts"]["registry"]["id"]
    assert section["DEMO_CREDENTIAL_CONTRACT"] == demo["contracts"]["credential"]["id"]
    assert {"ORDER_REGISTRY_CONTRACT", "ORDER_ESCROW_CONTRACT", "ORDER_CREDENTIAL_CONTRACT"} <= set(section)
