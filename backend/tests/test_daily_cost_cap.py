"""The deployment's hard daily cost cap for model reviews, cost kept out of every public
response, and job ids kept out of the logs.

- the cap is claimed in create-only chunks in the allowance store (here a fake Vercel Blob),
  shared by concurrent audits on separate invocations, and passed by at most one chunk per
  running leg;
- reached mid-job, the review stops like at a per-audit cap (capped, daily_cost_cap, every
  unread file listed); reached before an audit, no model review starts and the visitor is told
  when it returns, without any amount;
- measured tokens and dollars stay in the job state and the server log;
- the HTTP client loggers, whose INFO lines name Blob paths (and so job ids), stay quiet."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import Settings
from backend.app.services import audit_jobs, demo_flow, rate_limit, review_budget
from backend.app.services.audit_jobs import JobManager, MemoryObjects, run_leg
from backend.app.services.deep_review import DeepReviewer, _priority
from backend.app.services.rate_limit import BlobStore, MemoryStore
from backend.app.services.review_budget import Budget, DailyCostBudget, Spend

from .test_audit_jobs import PER_CALL, USAGE, FakeModel, artifact, stream, tool
from .test_demo_api import PEER, FakeBlob

PRICES = {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.2}
#: What one FakeModel call costs, in millionths of a dollar.
CALL_MICRO = Spend(**USAGE).micro_usd(PRICES)


@pytest.fixture
def calls_cost_what_they_report(monkeypatch):
    """The first call is assumed to cost what every FakeModel call reports."""
    monkeypatch.setattr(review_budget, "FIRST_CALL_ESTIMATE", PER_CALL)


@pytest.fixture
def small_chunks(monkeypatch):
    """Chunks of three calls each, so a cap is reached within a few calls."""
    monkeypatch.setattr(DailyCostBudget, "chunk", 3 * CALL_MICRO)
    return 3 * CALL_MICRO


def blob_store(blob: FakeBlob) -> BlobStore:
    return BlobStore("token", client_factory=blob.client)


# ----------------------------------------------------------------------------- claims
def test_the_default_cap_is_100_usd_in_quarter_dollar_chunks():
    settings = Settings(_env_file=None)
    assert settings.deep_review_daily_cost_usd == 100.0 and settings.deep_review_max_cost_usd_per_audit == 30.0
    daily = DailyCostBudget(MemoryStore(), settings.deep_review_daily_cost_usd)
    assert review_budget.CHUNK_USD == 0.25 and daily.chunks == 400
    assert Budget.from_settings(settings, store=MemoryStore()).daily_cost.budget_usd == 100.0


def test_concurrent_claims_on_the_blob_store_never_pass_the_cap():
    """Twelve audits on separate invocations (a fresh budget object each) race for four chunks."""
    blob = FakeBlob()

    async def scenario():
        spends = [Spend() for _ in range(12)]
        got = await asyncio.gather(*(DailyCostBudget(blob_store(blob), 1.0).reserve(s, 1) for s in spends))
        return got, spends
    got, spends = asyncio.run(scenario())
    assert got.count("") == 4 and got.count("daily_cost_cap") == 8
    assert sum(s.reserved_micro_usd for s in spends) == 1_000_000
    chunks = [p for p in blob.paths if "/cost/" in p]
    assert len(chunks) == 4 and all(p.startswith("touchmark-limits/deep-review/") for p in chunks)
    # Exhausted for every later invocation too: it lives in the store.
    assert asyncio.run(DailyCostBudget(blob_store(blob), 1.0).exhausted()) is True
    assert asyncio.run(DailyCostBudget(blob_store(FakeBlob()), 1.0).exhausted()) is False


def test_an_unreachable_store_stops_the_review_rather_than_spend_unchecked():
    reason = asyncio.run(DailyCostBudget(blob_store(FakeBlob(fail=True)), 100.0).reserve(Spend(), 1))
    assert reason == "daily_budget_unavailable"


def test_concurrent_reviews_share_the_cap_and_pass_it_by_at_most_one_chunk_each(calls_cost_what_they_report,
                                                                               small_chunks):
    blob = FakeBlob()
    cap_usd = 5 * small_chunks / 1_000_000  # five chunks: fifteen calls in all
    models = [FakeModel(sorted(artifact(20).code_files)) for _ in range(4)]

    async def one(model):
        reviewer = DeepReviewer(model, model="m", files_per_pass=1)
        reviewer.budget = Budget(prices=PRICES, daily_cost=DailyCostBudget(blob_store(blob), cap_usd))
        return await reviewer.review(artifact(20), [])

    async def scenario():
        return await asyncio.gather(*(one(m) for m in models))
    results = asyncio.run(scenario())
    spent = sum(r.spend["cost_usd"] for r in results)
    assert spent <= cap_usd + len(results) * small_chunks / 1_000_000  # the documented bound
    assert spent <= cap_usd + 1e-9  # and with calls costing what they were estimated at, none at all
    assert len([p for p in blob.paths if "/cost/" in p]) == 5
    assert sum(m.calls for m in models) == 15
    for r in results:
        assert r.status == "capped" and r.stop_reason == "daily_cost_cap"
        assert {f["reason"] for f in r.not_reviewed} == {"daily_cost_cap"}


# ----------------------------------------------------------------------- reached mid-job
@pytest.fixture
def job_settings(monkeypatch):
    monkeypatch.setattr(rate_limit, "_memory", MemoryStore())
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setattr(review_budget, "MIN_CALL_SECONDS", 0.3)
    monkeypatch.setattr(review_budget, "LEG_MARGIN_SECONDS", 0.05)

    def make(**over):
        return Settings(_env_file=None, deep_review_limit_store="memory", **over)
    return make


def test_the_daily_cost_cap_reached_mid_job_stops_it_cleanly_and_lists_every_unread_file(
        job_settings, calls_cost_what_they_report, small_chunks, caplog):
    settings = job_settings(deep_review_daily_cost_usd=2 * small_chunks / 1_000_000)  # six calls today
    art = artifact(12)
    model = FakeModel(sorted(art.code_files), delay=0.05, finding_on="src/m01.py")

    async def audit(reference, settings, *, ai, tmark_text=None, skipped=None):
        result = await DeepReviewer(model, model="m", files_per_pass=1).review(art, [])
        return {"ai": demo_flow._ai_summary({"deep_review": result.report()}, ai, settings), "decision": "needs_evidence"}

    jobs = JobManager(MemoryObjects(), settings)
    caplog.set_level(logging.INFO, logger="touchmark.audit_jobs")

    async def scenario():
        handle = await jobs.create({"reference": "r", "ai": True})
        events = []
        while True:
            # Legs of about half a second (the setting's floor is 30 s): two or three calls each.
            events.append(await run_leg(handle, settings, started=time.monotonic() - settings.demo_leg_seconds + 0.45,
                                        audit=audit))
            if events[-1]["type"] != "continue":
                return handle, events
            status, handle, _ = await jobs.claim(handle.job_id)
            assert status == "claimed"
    handle, events = asyncio.run(scenario())
    assert len(events) >= 2 and [e["type"] for e in events[:-1]] == ["continue"] * (len(events) - 1)
    ai = events[-1]["data"]["ai"]
    assert model.calls == 6 and ai["review"] == "capped" and ai["stop_reason"] == "daily_cost_cap"
    assert ai["findings_added"] == 1  # kept
    unread = [f["path"] for f in ai["not_reviewed"]]
    assert unread == [p for p in _priority(art) if p not in model.read] and len(unread) == 6
    assert {f["reason"] for f in ai["not_reviewed"]} == {"daily_cost_cap"}
    # Two chunks claimed for the day, however many legs the job ran; its hold is in the job state.
    assert len([p for p in rate_limit._memory.paths if "/cost/" in p]) == 2
    assert Spend.from_dict(handle.state["spend"]).reserved_micro_usd == 2 * small_chunks
    # The server log has the spend, and never the job id.
    assert "USD" in caplog.text and "daily_cost_cap" in caplog.text
    assert handle.job_id not in caplog.text and handle.job_id.split("-", 1)[1] not in caplog.text
    assert_no_spend(events)


def test_a_review_whose_day_is_already_spent_makes_no_call():
    store = MemoryStore()
    asyncio.run(DailyCostBudget(store, 0.5).reserve(Spend(), 500_000))
    model = FakeModel(sorted(artifact(3).code_files))
    reviewer = DeepReviewer(model, model="m")
    reviewer.budget = Budget(daily_cost=DailyCostBudget(store, 0.5))
    result = asyncio.run(reviewer.review(artifact(3), []))
    assert model.calls == 0 and result.status == "capped" and result.stop_reason == "daily_cost_cap"
    assert "daily cost cap" in result.note


def test_the_verifier_stops_at_the_daily_cost_cap_too(calls_cost_what_they_report, small_chunks):
    from backend.app.models import Dimension, Finding, Severity
    from backend.app.services.finding_verifier import FindingVerifier
    findings = [Finding(id=f"security-x-{i}", dimension=Dimension.SECURITY, severity=Severity.HIGH, title="t",
                        detail="d", evidence="src/m00.py:1 `sign_00 = 1`") for i in range(5)]

    class Verdicts:
        calls = 0

        def __init__(self):
            self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

        async def create(self, **kwargs):
            self.calls += 1
            return SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(**USAGE), content=[
                tool("submit_verdict", self.calls, verdict="confirmed", reviewed_severity="high", file="src/m00.py",
                     line=1, evidence_quote="sign_00 = 1", reason="seen")])
    client = Verdicts()
    verifier = FindingVerifier(client, model="v", concurrency=1)
    verifier.budget = Budget(prices=PRICES, daily_cost=DailyCostBudget(MemoryStore(), small_chunks / 1_000_000))
    run = asyncio.run(verifier.verify(findings, artifact(1).code_files))
    assert client.calls == 3
    assert run.results[3].note == "not verified: stopped at daily_cost_cap"


# ----------------------------------------------------------------- reached before start
@pytest.fixture
def capped_api(monkeypatch):
    """The demo endpoints with the model review configured and today's cost cap used up."""
    seen: list[dict] = []

    async def audit(reference, settings, *, ai, tmark_text=None, skipped=None):
        seen.append({"ai": ai, "skipped": skipped})
        return {"ai": demo_flow._ai_summary({"repository": {"source_files_selected": 1}}, ai, settings, skipped),
                "decision": "needs_evidence"}
    monkeypatch.setattr(demo_flow, "run_demo_audit", audit)
    monkeypatch.setattr(rate_limit, "_memory", MemoryStore())
    monkeypatch.setattr(audit_jobs, "_memory", MemoryObjects())
    monkeypatch.setattr(api, "_allowance_cache", {})
    monkeypatch.delenv("VERCEL", raising=False)
    settings = Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k",
                        deep_review_limit_store="memory", deep_review_daily_cost_usd=0.5)
    monkeypatch.setattr(api, "settings", settings)
    with TestClient(api.app, client=PEER) as client:
        yield client, seen


def spend_today(usd: float) -> None:
    asyncio.run(DailyCostBudget(rate_limit._memory, usd).reserve(Spend(), int(usd * 1_000_000)))


def test_the_config_says_only_whether_the_daily_cap_allows_a_review(capped_api):
    client, _ = capped_api
    fresh = client.get("/api/v1/demo/config").json()
    assert fresh["allowance"]["daily_cost_available"] is True and fresh["allowance"]["used_up"] is False
    api._allowance_cache.clear()
    spend_today(0.5)
    config = client.get("/api/v1/demo/config").json()
    allowance = config["allowance"]
    assert allowance["used_up"] is True and allowance["reason"] == "daily_cost"
    assert allowance["daily_cost_available"] is False and allowance["resets_at"].endswith("T00:00:00+00:00")
    assert_no_spend(config)


def test_no_model_review_starts_once_the_daily_cap_is_reached(capped_api):
    client, seen = capped_api
    spend_today(0.5)
    events = stream(client, "/api/v1/demo/audit", {"reference": "https://github.com/o/r", "model_review_consent": True})
    result = events[-1]
    assert result["type"] == "result" and seen[0]["ai"] is False
    ai = result["data"]["ai"]
    assert ai["review"] == "rate_limited" and ai["limit"] == "daily_cost" and "resume at 00:00 UTC" in ai["note"]
    assert ai["allowance"]["used_up"] is True and ai["allowance"]["resets_at"]
    # No allowance slot was spent on a review that could not run.
    assert not [p for p in rate_limit._memory.paths if "/cost/" not in p]
    assert_no_spend(events)


# -------------------------------------------------------------- no cost in public data
FORBIDDEN_KEYS = {"spend", "usage", "cost_usd", "tokens", "input_tokens", "output_tokens", "cache_read_input_tokens",
                  "cache_creation_input_tokens", "estimated_tokens", "reserved_micro_usd", "daily_cost_usd",
                  "last_call_micro_usd"}


def assert_no_spend(value, path="$") -> None:
    """No key that carries measured spend, no number under a cost-like key, and no dollar sign."""
    if isinstance(value, dict):
        for key, item in value.items():
            assert key not in FORBIDDEN_KEYS, f"{path}.{key}"
            if re.search(r"cost|usd(?!c)|^spend", key.lower()):  # USDC fields describe the audited agent
                assert isinstance(item, (bool, str)) or item is None, f"{path}.{key}"
            if key == "report_json" and isinstance(item, str):
                item = json.loads(item)
            assert_no_spend(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            assert_no_spend(item, f"{path}[{i}]")
    elif isinstance(value, str):
        assert "$" not in value or "${" in value, path


def test_a_full_audit_with_review_and_verification_returns_no_spend(tmp_path, monkeypatch):
    from backend.app.services import deep_review, finding_verifier
    from backend.app.services.finding_verifier import FindingVerifier
    from backend.app.services.repo_audit import audit_repository
    from .test_repo_audit import make_repo

    repo = make_repo(tmp_path)
    reviewer = DeepReviewer(FakeModel(["src/pay.ts", "src/util.ts"]), model="m", passes=1)

    class Verdicts:
        def __init__(self):
            self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

        async def create(self, **kwargs):
            return SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(**USAGE), content=[
                tool("submit_verdict", 1, verdict="confirmed", reviewed_severity="high", file="src/pay.ts",
                     line=2, evidence_quote='server.tool("send_payment"', reason="seen")])
    monkeypatch.setattr(deep_review, "reviewer_from_settings", lambda settings: reviewer)
    monkeypatch.setattr(finding_verifier, "verifier_from_settings",
                        lambda settings: FindingVerifier(Verdicts(), model="v"))
    settings = Settings(_env_file=None)

    async def audit_reference(reference, settings, **kwargs):
        return await audit_repository(repo, name="pay", purpose="Pay invoices.", settings=settings, deep=True)
    monkeypatch.setattr(demo_flow, "audit_reference", audit_reference)
    out = asyncio.run(demo_flow.run_demo_audit("https://github.com/o/r", settings, ai=True))
    assert out["ai"]["files_read"] >= 1 and out["ai"]["verification"].get("checked", 0) >= 1
    assert reviewer.budget.spend.calls >= 1  # the review ran and was measured
    assert_no_spend(out)


# ------------------------------------------------------------------------------ logs
def test_the_http_client_loggers_never_log_requests_or_store_paths(caplog):
    import httpx
    api.quiet_http_client_logs()
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING
        assert not logging.getLogger(name).isEnabledFor(logging.INFO)
    caplog.set_level(logging.DEBUG)  # even with the root logger at its most verbose
    path = "touchmark-jobs/20261101/AbCdEfGhIjKlMnOpQrStUvWx/s/000003"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    with httpx.Client(transport=transport) as client:
        client.get(f"https://store.blob.vercel-storage.com/{path}")
    assert "AbCdEfGhIjKlMnOpQrStUvWx" not in caplog.text and "HTTP Request" not in caplog.text
    # A warning that names a store path is dropped as well; other warnings still get through.
    caplog.clear()
    logging.getLogger("httpx").warning("retrying %s", f"https://store.blob.vercel-storage.com/{path}")
    logging.getLogger("httpx").warning("connection pool is full")
    assert "AbCdEfGhIjKlMnOpQrStUvWx" not in caplog.text and "connection pool is full" in caplog.text
