"""The public demo API on stateless serverless: a durable model-review allowance, consent,
a supplied .tmark, streamed progress, an explicit rules-only comparison and honest status."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import Settings
from backend.app.services import demo_flow, rate_limit
from backend.app.services.rate_limit import BlobStore, DeepReviewLimiter, MemoryStore, limiter_from_settings

ROOT = Path(__file__).resolve().parents[2]
SAFE = ROOT / "examples/demo/safe-treasury-agent"
CLOCK = lambda: datetime(2026, 10, 31, 14, 5, tzinfo=timezone.utc)  # noqa: E731
#: Its own client address, so the process-wide StudioGuard budget of other tests is untouched.
PEER = ("192.0.2.77", 50000)


# ----------------------------------------------------------------------- durable allowance
class FakeBlob:
    """Vercel Blob as the SDK sees it: create-only puts refuse an existing path."""

    def __init__(self, fail: bool = False):
        self.paths: dict[str, bytes] = {}
        self.fail, self.calls = fail, 0

    def client(self):
        store = self

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def put(self, path, body, *, access, content_type, add_random_suffix, overwrite):
                store.calls += 1
                assert access == "private" and overwrite is False and add_random_suffix is False
                if store.fail:
                    from vercel.blob import BlobServiceNotAvailable
                    raise BlobServiceNotAvailable()
                await asyncio.sleep(0)  # let concurrent claims interleave
                if path in store.paths:
                    from vercel.blob import BlobError
                    raise BlobError("This blob already exists, use `allowOverwrite: true` if you want to overwrite it.")
                store.paths[path] = body

            async def list_objects(self, *, prefix, limit, cursor=None):
                store.calls += 1
                if store.fail:
                    raise ConnectionError("down")
                blobs = [SimpleNamespace(url="https://blob/" + p, pathname=p) for p in sorted(store.paths) if p.startswith(prefix)]
                return SimpleNamespace(blobs=blobs, has_more=False, cursor=None)

            async def delete(self, urls):
                for url in urls:
                    store.paths.pop(url.removeprefix("https://blob/"), None)

        return Client()


def limiter(blob: FakeBlob, **limits) -> DeepReviewLimiter:
    """A fresh limiter per call, as on a fresh serverless invocation: only the store persists."""
    return DeepReviewLimiter(BlobStore("token", client_factory=blob.client), salt=b"s", clock=CLOCK,
                             **({"client_hour": 5, "hour": 60, "day": 200} | limits))


def test_the_allowance_holds_across_invocations_because_it_lives_in_the_store():
    blob = FakeBlob()
    decisions = [asyncio.run(limiter(blob).acquire("203.0.113.9")) for _ in range(7)]
    assert [d.allowed for d in decisions] == [True] * 5 + [False] * 2
    assert decisions[-1].reason == "client_hour" and "5 model reviews" in decisions[-1].message
    assert asyncio.run(limiter(blob).acquire("198.51.100.4")).allowed  # another client still can
    # No raw address is stored: slots carry an HMAC of it.
    assert not any("203.0.113.9" in p or "198.51.100.4" in p for p in blob.paths)
    assert any(re.search(r"/h14/c/[0-9a-f]{24}/\d+$", p) for p in blob.paths)


def test_concurrent_requests_cannot_overspend_the_daily_ceiling():
    blob = FakeBlob()

    async def burst():
        shared = limiter(blob, client_hour=100, hour=100, day=4)
        return await asyncio.gather(*(shared.acquire(f"10.0.0.{n}") for n in range(12)))
    decisions = asyncio.run(burst())
    assert sum(d.allowed for d in decisions) == 4
    assert {d.reason for d in decisions if not d.allowed} == {"day"}
    assert len([p for p in blob.paths if "/day/" in p]) == 4
    # Slots claimed for a request a later allowance refused were given back.
    assert len([p for p in blob.paths if "/all/" in p]) == 4


def test_the_hourly_overall_limit_and_refunds():
    blob = FakeBlob()
    assert [asyncio.run(limiter(blob, hour=2).acquire(f"c{n}")).allowed for n in range(3)] == [True, True, False]
    assert len([p for p in blob.paths if "/c/" in p]) == 2  # the refused client's slot was refunded


def test_an_unreachable_store_fails_closed():
    decision = asyncio.run(limiter(FakeBlob(fail=True)).acquire("c"))
    assert not decision.allowed and decision.reason == "store_unavailable"
    assert "could not be checked" in decision.message


def test_serverless_without_a_durable_store_runs_no_model_review(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    off = limiter_from_settings(Settings(_env_file=None))
    assert off.store is None and asyncio.run(off.acquire("c")).reason == "not_configured"
    blob = limiter_from_settings(Settings(_env_file=None, blob_read_write_token="vercel_blob_rw_x"))
    assert isinstance(blob.store, BlobStore)
    configured = Settings(_env_file=None, deep_review_daily_limit=7, deep_review_client_hourly_limit=2)
    assert limiter_from_settings(configured).limits == {"client_hour": 2, "hour": 60, "day": 7}
    monkeypatch.delenv("VERCEL")
    assert isinstance(limiter_from_settings(Settings(_env_file=None)).store, MemoryStore)


# ----------------------------------------------------------------------------- the endpoint
@pytest.fixture
def demo(monkeypatch, tmp_path):
    """The demo endpoint with the deep review configured, auditing a local folder (no network)."""
    from backend.app.services.repo_audit import audit_repository
    seen: dict = {}

    async def local(reference, settings, *, network, deep, deadline, tmark_override=None):
        from backend.app.services import progress
        progress.emit("resolving")
        seen.update(deep=deep, tmark=tmark_override)
        result = await audit_repository(SAFE, name="safe", purpose="", settings=Settings(_env_file=None), deep=False,
                                        tmark_override=tmark_override)
        result["report"]["resolution"] = {"kind": "repository", "steps": [], "source": {
            "repository": "https://github.com/o/r", "revision": "a" * 40}}
        return result
    monkeypatch.setattr(demo_flow, "audit_reference", local)
    store = MemoryStore()
    monkeypatch.setattr(rate_limit, "_memory", store)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setattr(api, "settings", Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k",
                                                  deep_review_limit_store="memory"))
    with TestClient(api.app, client=PEER) as client:
        yield client, seen, store


def test_no_source_goes_to_a_model_without_consent(demo):
    client, seen, store = demo
    out = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r"}).json()
    assert seen["deep"] is False and out["ai"]["review"] == "no_consent" and "consent" in out["ai"]["note"]
    assert not store.paths  # no allowance is spent without consent
    client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r", "model_review_consent": True})
    assert seen["deep"] is True and len(store.paths) == 3


def test_the_allowance_is_enforced_by_the_endpoint(demo, monkeypatch):
    client, seen, store = demo
    body = {"reference": "https://github.com/o/r", "model_review_consent": True}
    runs = [client.post("/api/v1/demo/audit", json=body).json() for _ in range(6)]
    assert seen["deep"] is False and runs[-1]["ai"]["review"] == "rate_limited"
    assert "rules only" in runs[-1]["ai"]["note"]


def test_a_supplied_tmark_is_validated_with_line_and_field(demo):
    client, seen, _ = demo
    bad = '{\n  "tmark": "1",\n  "agent": {"name": "x", "kind": "robot"}\n}'
    response = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r", "tmark": bad})
    assert response.status_code == 422
    errors = {e["field"]: e for e in response.json()["detail"]["tmark_errors"]}
    assert errors["agent.kind"]["line"] == 3 and errors["authority"]["message"] == "required"
    assert seen == {}  # nothing was audited


def test_a_supplied_tmark_is_used_and_the_report_says_so(demo):
    client, seen, _ = demo
    text = (SAFE / ".tmark").read_text().replace('"recipients": "allowlist"', '"recipients": "any"')
    out = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r", "tmark": text}).json()
    assert seen["tmark"] == {"text": text}
    tm = out["tmark"]
    assert tm["status"] == "valid" and tm["source"] == "supplied" and tm["repository_status"] == "valid"
    assert any("limits differ" in m for m in tm["mismatches"]) and tm["summary"][0].startswith("Treasury agent")
    assert any(g["id"] == "intent-tmark-supplied-differs" for g in out["gaps"])
    assert not out["issuance"]["eligible"] and "Commit the .tmark" in out["issuance"]["reason"]
    assert out["scope"]["excluded"] == {} and out["scope"]["files"] >= 1


def test_the_audit_streams_stage_events_and_heartbeats(demo, monkeypatch):
    client, _, _ = demo
    monkeypatch.setattr(api, "HEARTBEAT_SECONDS", 0.001)
    with client.stream("POST", "/api/v1/demo/audit", json={"reference": "https://github.com/o/r"},
                       headers={"Accept": "application/x-ndjson"}) as response:
        assert response.headers["content-type"].startswith("application/x-ndjson")
        events = [json.loads(line) for line in response.iter_lines() if line]
    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert stages[0] == "queued" and "resolving" in stages and "rules" in stages and stages[-1] == "done"
    assert events[-1]["type"] == "result" and events[-1]["data"]["decision"]
    assert all("elapsed" in e for e in events)


def test_a_streamed_error_is_a_line_not_a_bare_502(demo, monkeypatch):
    client, _, _ = demo

    async def broken(*args, **kwargs):
        raise ValueError("The repository could not be fetched: not found")
    monkeypatch.setattr(demo_flow, "audit_reference", broken)
    with client.stream("POST", "/api/v1/demo/audit", json={"reference": "https://github.com/o/missing"},
                       headers={"Accept": "application/x-ndjson"}) as response:
        events = [json.loads(line) for line in response.iter_lines() if line]
    assert events[-1] == {**events[-1], "type": "error", "status": 422,
                          "detail": "The repository could not be fetched: not found"}
    plain = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/missing"})
    assert plain.status_code == 422  # the non-streaming fallback is unchanged


def test_the_comparison_says_it_is_rules_only(monkeypatch):
    from backend.app.services import agent_resolver

    async def fake(reference, settings, **kwargs):
        assert kwargs["deep"] is False
        findings = [{"id": "security-path-untrusted-to-financial-sink", "severity": "high", "kind": "risk", "title": "t"}]
        report = {"result": {"overall_score": 40.0 if reference == "before" else 90.0, "decision": "needs_fixes"},
                  "review_decision": "needs_fixes", "findings": findings if reference == "before" else []}
        return {"report": report, "report_sha256": reference}
    monkeypatch.setattr(agent_resolver, "audit_reference", fake)
    with TestClient(api.app, client=PEER) as client:
        out = client.post("/api/v1/demo/compare", json={"before": "before", "after": "after"}).json()
    assert out["mode"] == "rules_only" and "never shown as closed" in out["note"]
    assert [f["id"] for f in out["comparison"]["closed"]] == ["security-path-untrusted-to-financial-sink"]


# ------------------------------------------------------------------------- .tmark endpoints
def test_tmark_check_returns_errors_by_line_or_the_normalized_declaration():
    with TestClient(api.app, client=PEER) as client:
        good = client.post("/api/v1/tmark/check", json={"text": (SAFE / ".tmark").read_text()}).json()
        bad = client.post("/api/v1/tmark/check", json={"text": '{"tmark": "9"}'}).json()
    assert good["valid"] and good["version"] == "1" and good["latest_version"] == "1.1"
    assert good["normalized"]["tools"][0]["executes_code"] is False and good["summary"]
    assert not bad["valid"] and bad["error_details"][0] == {"field": "tmark", "line": 1,
                                                            "message": bad["error_details"][0]["message"]}


def test_tmark_template_drafts_from_source_files():
    files = {"src/server.ts": 'import { Keypair } from "@stellar/stellar-sdk";\n'
                              'const key = Keypair.fromSecret(process.env.SECRET);\n'
                              'server.tool("pay", "pay", {}, async () => key.sign(Buffer.from("x")));\n'}
    with TestClient(api.app, client=PEER) as client:
        out = client.post("/api/v1/tmark/template", json={"files": files, "name": "payer"}).json()
        both = client.post("/api/v1/tmark/template", json={"files": files, "reference": "x"})
        generic = client.get("/api/v1/tmark/template").json()
    assert out["draft"]["agent"]["name"] == "payer" and out["draft"]["tools"][0]["name"] == "pay"
    assert out["draft"]["tools"][0]["signs"] is True and out["draft"]["authority"]["holds_keys"] is True
    assert both.status_code == 422 and generic["tmark"] == "1.1"


# ------------------------------------------------------------------------------- status
def test_health_separates_the_deep_review_from_the_ai_second_opinion(monkeypatch):
    monkeypatch.setattr(api, "settings", Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k",
                                                  blob_read_write_token="vercel_blob_rw_x"))
    with TestClient(api.app, client=PEER) as client:
        modes = client.get("/api/v1/health").json()["modes"]
        config = client.get("/api/v1/demo/config").json()
    assert modes["llm"] is False and modes["ai_second_opinion"]["configured"] is False
    review = modes["deep_review"]
    assert review["configured"] and review["available"] and review["provider"] == "anthropic"
    assert review["verifier"] and review["allowance_store"] == "vercel_blob" and review["consent_required"]
    assert review["limits"] == {"per_client_per_hour": 5, "per_hour": 60, "per_day": 200}
    assert config["model_review"] == review and config["streaming"] is True


def test_studio_capabilities_report_the_deep_review_as_the_ai_option(monkeypatch):
    keyed = dict(_env_file=None, enable_deep_review=True, anthropic_ai_key="k")
    monkeypatch.setattr(api, "settings", Settings(**keyed, ai_review_api_key="p" * 32))
    with TestClient(api.app, client=PEER) as client:
        on = client.get("/api/v1/studio/capabilities").json()
    monkeypatch.setattr(api, "settings", Settings(**keyed))
    with TestClient(api.app, client=PEER) as client:
        no_key = client.get("/api/v1/studio/capabilities").json()
    assert on["ai_available"] and on["ai_mode"] == "deep_review" and on["ai_provider"] == "anthropic"
    assert not no_key["ai_available"] and no_key["deep_review"]["configured"]
