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
