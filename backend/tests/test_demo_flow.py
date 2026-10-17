"""The public demo: tickets cannot be forged or edited, only passing audits get one."""

from __future__ import annotations

import asyncio

import pytest

from backend.app.config import Settings
from backend.app.services import demo_flow
from backend.app.services.agent_resolver import github_subpath, parse_github


@pytest.fixture(autouse=True)
def operator(monkeypatch):
    monkeypatch.setenv("DEMO_OPERATOR_SECRET", "SCZANGBA5YHTNYVVV4C3U252E2B6P6F5T3U6MM63WBSBZATAQI3EBTQ4")
    monkeypatch.setattr(demo_flow, "manifest", lambda: {"contracts": {"credential": {"id": "C" + "A" * 55}}})


def fake_result(decision: str, score: float, path: str = "") -> dict:
    report = {"result": {"overall_score": score}, "repository": {"source_files_selected": 3},
              "findings": [{"id": "security-path-untrusted-to-financial-sink", "severity": "critical", "kind": "risk",
                            "title": "t", "evidence": "e"}] if decision == "needs_fixes" else [],
              "resolution": {"kind": "repository", "steps": [],
                             "source": {"repository": "https://github.com/o/r", "revision": "a" * 40,
                                        **({"path": path} if path else {})}}}
    return {"decision": decision, "report": report, "report_json": "{}", "report_sha256": "b" * 64}


def audit(monkeypatch, result):
    async def fake(reference, settings, **kwargs):
        return result
    monkeypatch.setattr(demo_flow, "audit_reference", fake)
    return asyncio.run(demo_flow.run_demo_audit("https://github.com/o/r", Settings(_env_file=None)))


def test_only_passing_audits_get_a_ticket(monkeypatch):
    failed = audit(monkeypatch, fake_result("needs_fixes", 14.5))
    assert "ticket" not in failed["issuance"] and "score >= 65" in failed["issuance"]["reason"]
    passed = audit(monkeypatch, fake_result("pass", 84.0, path="examples/demo/safe"))
    payload = demo_flow._verify(passed["issuance"]["ticket"])
    assert payload["score"] == 84 and payload["report_sha256"] == "b" * 64
    assert payload["repository"] == "https://github.com/o/r/tree/" + "a" * 40 + "/examples/demo/safe"


def test_tickets_cannot_be_edited_or_forged(monkeypatch):
    ticket = audit(monkeypatch, fake_result("pass", 84.0))["issuance"]["ticket"]
    body, mac = ticket.rsplit(".", 1)
    import base64, json
    raised = json.loads(base64.urlsafe_b64decode(body))
    raised["score"] = 100
    forged = base64.urlsafe_b64encode(json.dumps(raised, sort_keys=True, separators=(",", ":")).encode()).decode()
    with pytest.raises(demo_flow.DemoError):
        demo_flow._verify(f"{forged}.{mac}")
    monkeypatch.setenv("DEMO_OPERATOR_SECRET", "SDIFFERENTKEYDIFFERENTKEYDIFFERENTKEYDIFFERENTKEYDIFFER")
    with pytest.raises(demo_flow.DemoError):
        demo_flow._verify(ticket)


def test_expired_tickets_are_refused(monkeypatch):
    ticket = demo_flow._sign({"report_sha256": "b" * 64, "score": 80, "repository": "x", "revision": "y", "expires_at": 1})
    with pytest.raises(demo_flow.DemoError, match="expired"):
        demo_flow._verify(ticket)


def test_github_folder_links():
    url = "https://github.com/furkan3152/agentveritas-stellar/tree/main/examples/demo/safe-treasury-agent"
    assert parse_github(url) == ("furkan3152", "agentveritas-stellar", "main")
    assert github_subpath(url) == "examples/demo/safe-treasury-agent"
    assert github_subpath("https://github.com/o/r") == ""
    assert github_subpath("https://github.com/o/r/tree/main/../secret") == ""


def test_the_result_says_which_ai_checks_ran(monkeypatch):
    # No model review in the report: say whether it was off, rate-limited or not applicable.
    assert audit(monkeypatch, fake_result("pass", 99.0))["ai"] == {"review": "off"}
    keyed = Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k")
    assert demo_flow._ai_summary({"repository": {"source_files_selected": 1}}, False, keyed) == {"review": "rate_limited"}
    assert demo_flow._ai_summary({"repository": {"source_files_selected": 1}}, True, Settings(_env_file=None)) == {"review": "off"}
    assert demo_flow._ai_summary({}, True, keyed) == {"review": "no_source"}
    # A completed review reports its coverage and the verifier's verdicts.
    result = fake_result("needs_fixes", 30.0)
    result["report"]["deep_review"] = {"status": "completed", "accepted_findings": ["deep-1"],
                                       "coverage": {"files_read": ["a.ts", "b.ts"], "files_total": 3}}
    result["report"]["verification"] = {"checked": 2, "confirmed": 1, "partial": 0, "refuted": 1,
                                        "unverifiable": 0, "agreement": 0.5, "usage": {}}
    result["report"]["findings"][0].update(auditor="deep-review",
                                           verification={"verdict": "confirmed", "reason": "seen at line 3"})
    out = audit(monkeypatch, result)
    assert out["ai"]["review"] == "completed" and out["ai"]["files_read"] == 2 and out["ai"]["findings_added"] == 1
    assert out["ai"]["verification"] == {"checked": 2, "confirmed": 1, "partial": 0, "refuted": 1,
                                         "unverifiable": 0, "agreement": 0.5}
    assert out["risks"][0]["source"] == "ai_review" and out["risks"][0]["verification"]["verdict"] == "confirmed"


def test_model_reviews_are_limited_per_client(monkeypatch):
    from collections import defaultdict, deque
    from backend.app import api
    monkeypatch.setattr(api, "_demo_ai", defaultdict(deque))
    monkeypatch.setattr(api, "_demo_ai_all", deque())
    assert [api._demo_ai_allowed("a") for _ in range(6)] == [True] * 5 + [False]
    assert api._demo_ai_allowed("b")
