"""Long audits as jobs of request legs, stopped only by spend caps: the state machine (resume,
idempotent and concurrent continues, cancel, expiry), the caps measured from reported usage,
per-request timeouts with retries, and one allowance slot per job through the API."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import Settings
from backend.app.models import AgentArtifact, SourceKind
from backend.app.services import audit_jobs, demo_flow, rate_limit, review_budget
from backend.app.services.audit_jobs import JobManager, MemoryObjects, run_leg
from backend.app.services.deep_review import DeepReviewer, _priority
from backend.app.services.finding_verifier import FindingVerifier
from backend.app.services.rate_limit import BlobStore, MemoryStore
from backend.app.services.review_budget import (Budget, DailyTokenBudget, Leg, LegSuspended, ReviewCancelled, Spend,
                                                leg_scope)

from .test_demo_api import PEER, FakeBlob

ROOT = Path(__file__).resolve().parents[2]
USAGE = dict(input_tokens=1000, output_tokens=200, cache_read_input_tokens=5000, cache_creation_input_tokens=300)
PER_CALL = sum(USAGE.values())


def tool(name, n, **args):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}_{n}", name=name, input=args)


class FakeModel:
    """Each call reads the next unread file it is offered and finishes its pass, reporting usage
    as Anthropic does. ``hang`` lists call numbers that never answer; ``fail`` ones that raise."""

    def __init__(self, files, *, hang=(), fail=(), finding_on=None, delay=0.0):
        self.order, self.calls, self.requests = list(files), 0, []
        self.hang, self.fail, self.finding_on, self.delay = set(hang), dict(fail), finding_on, delay
        self.read: list[str] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        n = self.calls
        self.calls += 1
        self.requests.append(kwargs)
        if n in self.hang:
            await asyncio.sleep(3600)
        if n in self.fail:
            raise self.fail[n]
        if self.delay:
            await asyncio.sleep(self.delay)
        blocks = []
        if n == 0:
            blocks.append(tool("describe_operating_model", n, purpose="pays", triggers="user", example_run="pay",
                               trust_boundaries=["user"], assets_at_risk=["XLM"]))
        nxt = next((p for p in self.order if p not in self.read), None)
        if nxt is not None:
            self.read.append(nxt)
            blocks.append(tool("read_source", n, path=nxt, start_line=1, end_line=5))
            if nxt == self.finding_on:
                blocks.append(tool("record_finding", n, category="unauthorized_payment", severity="high",
                                   title="Pays any recipient", file=nxt, line=1, evidence_quote=f"sign_{nxt[5:7]} = 1",
                                   attack_scenario="A request names the recipient.", stellar_impact="Funds sent.",
                                   remediation="Allowlist recipients."))
        blocks.append(tool("finish", n, summary="ok"))
        return SimpleNamespace(content=blocks, stop_reason="tool_use", usage=SimpleNamespace(**USAGE))


def artifact(n=12):
    files = {f"src/m{i:02d}.py": f"sign_{i:02d} = 1\n" for i in range(n)}
    return AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files)


def manager(store=None, **settings):
    return JobManager(store or MemoryObjects(), Settings(_env_file=None, **settings))


async def leg_of(handle, budget=None, deadline=None):
    return Leg(budget=budget or Budget(spend=Spend.from_dict(handle.state.get("spend"))), deadline=deadline,
               job=handle, review_state=handle.state.get("review"),
               verification_state=handle.state.get("verification"), pin=dict(handle.state.get("pin") or {}))


@pytest.fixture
def quick_legs(monkeypatch):
    """Legs that end after a fraction of a second instead of minutes."""
    monkeypatch.setattr(review_budget, "MIN_CALL_SECONDS", 0.3)
    monkeypatch.setattr(review_budget, "LEG_MARGIN_SECONDS", 0.05)


# ------------------------------------------------------------------------------ resume
def test_a_review_suspended_at_the_end_of_a_leg_resumes_where_it_stopped(quick_legs):
    art = artifact(12)
    model = FakeModel(sorted(art.code_files), delay=0.05)
    reviewer = DeepReviewer(model, model="m", passes=1, files_per_pass=3)
    jobs = manager()

    async def scenario():
        handle = await jobs.create({"reference": "r", "ai": True})
        legs = 0
        while True:
            legs += 1
            leg = await leg_of(handle, deadline=time.monotonic() + 0.3 + 0.2)  # about four calls per leg
            try:
                with leg_scope(leg):
                    result = await reviewer.review(art, [])
                return result, legs, leg, handle
            except LegSuspended:
                await handle.finish("suspended", spend=leg.budget.spend.to_dict())
            status, handle, _ = await jobs.claim(handle.job_id)
            assert status == "claimed"
    result, legs, leg, handle = asyncio.run(scenario())
    assert legs >= 3, "the review needed several legs"
    assert result.status == "completed" and len(result.files_read) == 12 and not result.not_reviewed
    # Every file was read once: no leg repeated what an earlier one had saved.
    assert model.read == sorted(art.code_files)
    # Spend is measured from usage and carried across legs: nothing lost, nothing counted twice.
    assert leg.budget.spend.calls == model.calls and leg.budget.spend.tokens() == model.calls * PER_CALL
    assert handle.state["progress"]["files_read"] == 12


def test_a_resumed_pass_continues_its_saved_conversation(quick_legs):
    art = artifact(6)
    model = FakeModel(sorted(art.code_files))
    reviewer = DeepReviewer(model, model="m", passes=1, files_per_pass=2)
    saved: dict = {}

    class Job:
        async def checkpoint(self, **sections):
            saved.update({k: v for k, v in sections.items() if v is not None})

        async def heartbeat(self, **_):
            pass

        async def cancel_requested(self):
            return False

    async def scenario():
        leg = Leg(budget=Budget(), deadline=None, job=Job())
        model.hang = {2}  # the third call never answers ...
        leg.budget.call_timeout = 0.2
        leg.budget.retries = 0
        with leg_scope(leg):
            result = await reviewer.review(art, [])
        return result
    result = asyncio.run(scenario())
    # ... so it is abandoned, and with no retries left the review ends as unavailable, keeping
    # what it read and saying which files it did not.
    assert result.status == "unavailable" and result.stop_reason == "provider_unavailable"
    assert {f["reason"] for f in result.not_reviewed} == {"provider_unavailable"}
    assert len(result.files_read) + len(result.not_reviewed) == 6
    assert saved["review"]["cursor"]["done"] is True


# ------------------------------------------------------------------ continue semantics
def test_continuing_a_finished_job_returns_the_same_result_and_runs_nothing():
    jobs = manager()
    calls = []

    async def audit(reference, settings, **kwargs):
        calls.append(reference)
        return {"ai": {}, "decision": "pass"}

    async def scenario():
        handle = await jobs.create({"reference": "r", "ai": False})
        first = await run_leg(handle, jobs.settings, started=time.monotonic(), audit=audit)
        again = [await jobs.claim(handle.job_id) for _ in range(3)]
        return first, again
    first, again = asyncio.run(scenario())
    assert first["type"] == "result" and first["data"]["job"]["legs"] == 1
    assert [a[0] for a in again] == ["completed"] * 3 and all(a[2]["result"] == first["data"] for a in again)
    assert calls == ["r"]


@pytest.mark.parametrize("kind", ["memory", "blob"])
def test_two_continues_at_once_run_exactly_one_leg(kind):
    store = MemoryObjects() if kind == "memory" else BlobStore("t", client_factory=BlobObjects().client)
    jobs = manager(store)

    async def scenario():
        handle = await jobs.create({"reference": "r"})
        await handle.finish("suspended")
        claims = await asyncio.gather(*(jobs.claim(handle.job_id) for _ in range(4)))
        return [c[0] for c in claims]
    statuses = asyncio.run(scenario())
    assert sorted(statuses) == ["busy", "busy", "busy", "claimed"]


def test_a_running_leg_holds_the_job_until_its_lease_goes_stale():
    now = [1_000_000.0]
    jobs = JobManager(MemoryObjects(), Settings(_env_file=None), clock=lambda: now[0])

    async def scenario():
        handle = await jobs.create({"reference": "r"})
        busy = await jobs.claim(handle.job_id)
        now[0] += audit_jobs.STALE_SECONDS + 1  # the request that held it is gone
        taken = await jobs.claim(handle.job_id)
        # The old leg wakes up and tries to save: it lost the job and stops without spending.
        with pytest.raises(LegSuspended) as lost:
            await handle.checkpoint(progress={"stage": "deep_review"})
        return busy, taken, lost.value.reason
    busy, taken, reason = asyncio.run(scenario())
    assert busy[0] == "busy" and 3 <= busy[2]["retry_after"] <= 15
    assert taken[0] == "claimed" and taken[1].state["leg"] == 2
    assert reason == "lease_lost"


# ------------------------------------------------------------------------------- caps
@pytest.fixture
def first_call_like_the_rest(monkeypatch):
    """Before any response, a call is assumed to cost FIRST_CALL_ESTIMATE; here, what the fake reports."""
    monkeypatch.setattr(review_budget, "FIRST_CALL_ESTIMATE", PER_CALL)


def test_a_token_cap_reached_mid_review_stops_cleanly_and_names_every_unread_file(first_call_like_the_rest):
    art = artifact(10)
    model = FakeModel(sorted(art.code_files), finding_on="src/m01.py")
    reviewer = DeepReviewer(model, model="m", passes=1, files_per_pass=2)
    reviewer.budget = Budget(max_tokens=PER_CALL * 4 + 10)  # room for four calls
    result = asyncio.run(reviewer.review(art, []))
    assert model.calls == 4 and result.status == "capped" and result.stop_reason == "token_cap"
    assert [f.title for f in result.findings] == ["Pays any recipient"]  # kept
    unread = [f["path"] for f in result.not_reviewed]
    assert unread == [p for p in _priority(art) if p not in result.files_read] and len(unread) == 6
    assert {f["reason"] for f in result.not_reviewed} == {"token_cap"}
    assert "token cap" in result.note and "never stops on time" in result.note
    record = result.report()
    assert record["coverage"]["not_reviewed_count"] == 6 and "spend" not in record and "usage" not in record
    # Spend is internal: kept on the result for the server log, not in the public record.
    assert result.spend["tokens"] == 4 * PER_CALL and result.spend["stopped_by"] == "token_cap"


def test_the_cost_cap_counts_cache_reads_and_writes_at_their_prices(first_call_like_the_rest):
    spend = Spend()
    spend.add(SimpleNamespace(**USAGE))
    prices = {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.2}
    assert spend.cost(prices) == round((1000 * 2 + 200 * 10 + 300 * 2.5 + 5000 * 0.2) / 1e6, 4)
    art = artifact(4)
    model = FakeModel(sorted(art.code_files))
    reviewer = DeepReviewer(model, model="m")
    # Each call is started only if one more like the last stays within the cap.
    reviewer.budget = Budget(max_cost=spend.cost(prices) * 2.5, prices=prices)
    result = asyncio.run(reviewer.review(art, []))
    assert result.stop_reason == "cost_cap" and model.calls == 2


def test_the_file_cap_refuses_new_files_and_lists_the_rest():
    art = artifact(8)
    model = FakeModel(sorted(art.code_files))
    reviewer = DeepReviewer(model, model="m", files_per_pass=3)
    reviewer.budget = Budget(max_files=5)
    result = asyncio.run(reviewer.review(art, []))
    assert len(result.files_read) == 5 and result.status == "capped" and result.stop_reason == "file_cap"
    assert {f["reason"] for f in result.not_reviewed} == {"file_cap"} and len(result.not_reviewed) == 3


def test_the_verifier_spends_from_the_same_budget_and_stops_at_the_cap(first_call_like_the_rest):
    from backend.app.models import Dimension, Finding, Severity
    findings = [Finding(id=f"security-x-{i}", dimension=Dimension.SECURITY, severity=Severity.HIGH, title="t",
                        detail="d", evidence="src/m00.py:1 `sign_00 = 1`") for i in range(3)]

    class Verdicts:
        def __init__(self):
            self.calls = 0
            self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

        async def create(self, **kwargs):
            self.calls += 1
            return SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(**USAGE), content=[
                tool("submit_verdict", self.calls, verdict="confirmed", reviewed_severity="high", file="src/m00.py",
                     line=1, evidence_quote="sign_00 = 1", reason="seen")])
    client = Verdicts()
    verifier = FindingVerifier(client, model="v", concurrency=1)
    verifier.budget = Budget(max_tokens=PER_CALL * 2 + 10)
    run = asyncio.run(verifier.verify(findings, artifact(1).code_files))
    assert client.calls == 2
    assert [r.verdict for r in run.results] == ["confirmed", "confirmed", "unverifiable"]
    assert run.results[2].note == "not verified: stopped at token_cap"


def test_the_daily_token_budget_is_shared_and_cannot_be_overspent():
    store = MemoryStore()

    async def scenario():
        daily = DailyTokenBudget(store, 3 * review_budget.CHUNK_TOKENS)
        spends = [Spend() for _ in range(5)]
        got = await asyncio.gather(*(daily.reserve(s, 10) for s in spends))
        return got, spends
    got, spends = asyncio.run(scenario())
    assert got.count("") == 3 and got.count("daily_budget") == 2
    assert sum(s.reserved_tokens for s in spends) == 3 * review_budget.CHUNK_TOKENS
    assert len([p for p in store.paths if "/tokens/" in p]) == 3


def test_an_exhausted_daily_budget_stops_the_review_before_any_call():
    art = artifact(3)
    model = FakeModel(sorted(art.code_files))
    reviewer = DeepReviewer(model, model="m")
    reviewer.budget = Budget(daily=DailyTokenBudget(MemoryStore(), 0))
    result = asyncio.run(reviewer.review(art, []))
    assert model.calls == 0 and result.stop_reason == "daily_budget"
    assert {f["reason"] for f in result.not_reviewed} == {"daily_budget"} and len(result.not_reviewed) == 3


# --------------------------------------------------------------- timeouts and retries
def test_a_hung_call_is_abandoned_and_retried_and_still_counted():
    art = artifact(3)
    model = FakeModel(sorted(art.code_files), hang={1})
    reviewer = DeepReviewer(model, model="m")
    slept = []

    async def no_wait(seconds):
        slept.append(seconds)
    reviewer.budget = Budget(call_timeout=0.2, retries=2, sleep=no_wait)
    result = asyncio.run(reviewer.review(art, []))
    assert result.status == "completed" and len(result.files_read) == 3
    spend = reviewer.budget.spend
    assert spend.cut_calls == 1 and spend.estimated_tokens == PER_CALL  # charged as the call before it
    assert spend.calls == model.calls - 1 and slept == [2]


def test_transient_provider_errors_are_retried_with_backoff_then_give_up():
    import anthropic
    import httpx
    overloaded = anthropic.InternalServerError("overloaded", response=httpx.Response(529, request=httpx.Request(
        "POST", "https://api.anthropic.com/v1/messages")), body=None)
    art = artifact(2)
    model = FakeModel(sorted(art.code_files), fail={0: overloaded, 1: overloaded, 2: overloaded})
    reviewer = DeepReviewer(model, model="m")
    slept = []

    async def no_wait(seconds):
        slept.append(seconds)
    reviewer.budget = Budget(retries=2, sleep=no_wait)
    result = asyncio.run(reviewer.review(art, []))
    assert model.calls == 3 and slept == [2, 4]
    assert result.status == "unavailable" and "after 3 attempts" in result.note


def test_a_call_the_leg_cuts_short_suspends_instead_of_failing(quick_legs):
    art = artifact(3)
    model = FakeModel(sorted(art.code_files), hang={0})
    reviewer = DeepReviewer(model, model="m")

    async def scenario():
        leg = Leg(budget=Budget(), deadline=time.monotonic() + 0.6)
        with leg_scope(leg):
            await reviewer.review(art, [])
    with pytest.raises(LegSuspended) as stop:
        asyncio.run(scenario())
    assert stop.value.reason == "leg_time"


# -------------------------------------------------------------------- cancel, cleanup
def test_cancel_stops_a_running_leg_before_its_next_model_call():
    art = artifact(6)
    model = FakeModel(sorted(art.code_files))
    reviewer = DeepReviewer(model, model="m")
    jobs = manager()

    async def scenario():
        handle = await jobs.create({"reference": "r", "ai": True})
        original = model.create

        async def cancel_after_two(**kwargs):
            if model.calls == 2:
                await jobs.cancel(handle.job_id)
                handle._cancel_checked = 0.0
            return await original(**kwargs)
        model.beta.messages.create = cancel_after_two
        leg = await leg_of(handle)
        with leg_scope(leg):
            with pytest.raises(ReviewCancelled):
                await reviewer.review(art, [])
        await handle.finish("cancelled")
        return await jobs.claim(handle.job_id)
    after = asyncio.run(scenario())
    assert model.calls == 3 and after[0] == "cancelled"


def test_cancelling_a_waiting_job_ends_it_at_once():
    jobs = manager()

    async def scenario():
        handle = await jobs.create({"reference": "r"})
        await handle.finish("suspended")
        return await jobs.cancel(handle.job_id), await jobs.claim(handle.job_id), await jobs.cancel(handle.job_id)
    cancel, claim, again = asyncio.run(scenario())
    assert cancel == "cancelled" and claim[0] == "cancelled" and again == "cancelled"


def test_jobs_expire_and_old_days_are_swept():
    now = [1_793_500_000.0]
    store = MemoryObjects()
    jobs = JobManager(store, Settings(_env_file=None, demo_job_ttl_hours=24), clock=lambda: now[0])

    async def scenario():
        old = await jobs.create({"reference": "r"})
        await old.finish("suspended")
        now[0] += 25 * 3600
        expired = await jobs.claim(old.job_id)
        stale = await jobs.create({"reference": "r"})
        now[0] += 3 * 86400
        swept = await jobs.cleanup()
        return expired, stale, swept
    expired, stale, swept = asyncio.run(scenario())
    assert expired[0] == "expired"
    assert not any(stale.job_id.split("-")[1] in p for p in store.objects), "days past the TTL are deleted"
    assert swept and all(p.startswith("touchmark-jobs/") for p in swept)


def test_job_ids_are_validated_before_any_store_path_is_built():
    jobs = manager()
    for bad in ("../../touchmark-limits", "20261101-short", "20261101-" + "a" * 23 + "/", ""):
        with pytest.raises(ValueError):
            asyncio.run(jobs.claim(bad))


# --------------------------------------------------------------------------- priority
def test_signing_keys_and_payments_are_read_before_network_and_helpers():
    files = {"src/util.py": "", "src/fetch.py": "", "src/keys.py": "", "src/pay.py": "", "tests/test_pay.py": "",
             "src/handler.py": ""}
    art = AgentArtifact(source_kind=SourceKind.REPO, name="a", code_files=files)
    art.code_profile = {"capabilities": {"network_fetch": ["src/fetch.py:1 `get`"], "key_custody": ["src/keys.py:1 `k`"],
                                         "payment": ["src/pay.py:3 `pay`"]},
                        "entrypoints": {"src/handler.py:1": "tool"}}
    order = _priority(art)
    assert order.index("src/keys.py") < order.index("src/fetch.py") and order.index("src/pay.py") < order.index("src/fetch.py")
    assert order.index("src/handler.py") < order.index("src/util.py") and order[-1] == "tests/test_pay.py"


# ------------------------------------------------------------------------------- API
class BlobObjects(FakeBlob):
    """FakeBlob with content reads, as the job store uses Blob."""

    def client(self):
        base = super().client()
        store = self

        class Client(type(base)):
            async def put(self, path, body, *, access, content_type, add_random_suffix, overwrite):
                return await base.put(path, body, access=access, content_type=content_type,
                                      add_random_suffix=add_random_suffix, overwrite=overwrite)

            async def get(self, url, *, access, use_cache):
                assert access == "private"
                return SimpleNamespace(content=store.paths[url.removeprefix("https://blob/")], status_code=200)
        return Client()


@pytest.fixture
def api_jobs(monkeypatch):
    """The demo endpoints with the model review allowed, an audit that needs three legs."""
    legs: list[int] = []

    async def three_legs(reference, settings, *, ai, tmark_text=None, skipped=None):
        leg = review_budget.current_leg()
        legs.append(leg.job.state["leg"])
        await leg.checkpoint(progress={"stage": "deep_review", "files_read": len(legs) * 10, "files_total": 30})
        if len(legs) < 3:
            raise LegSuspended("leg_time")
        return {"ai": {"review": "completed", "files_read": 30, "files_total": 30}, "decision": "needs_fixes"}
    monkeypatch.setattr(demo_flow, "run_demo_audit", three_legs)
    monkeypatch.setattr(rate_limit, "_memory", MemoryStore())
    monkeypatch.setattr(audit_jobs, "_memory", MemoryObjects())
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setattr(api, "settings", Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k",
                                                  deep_review_limit_store="memory"))
    with TestClient(api.app, client=PEER) as client:
        yield client, legs


def stream(client, path, body):
    with client.stream("POST", path, json=body, headers={"Accept": "application/x-ndjson"}) as response:
        return [json.loads(line) for line in response.iter_lines() if line]


def test_a_job_takes_one_allowance_slot_however_many_legs_it_runs(api_jobs):
    client, legs = api_jobs
    first = stream(client, "/api/v1/demo/audit", {"reference": "https://github.com/o/r", "model_review_consent": True})
    job = next(e for e in first if e["type"] == "job")
    assert first[-1]["type"] == "continue" and first[-1]["job_id"] == job["job_id"] and job["leg"] == 1
    second = stream(client, "/api/v1/demo/audit/continue", {"job_id": job["job_id"]})
    resumed = next(e for e in second if e["type"] == "job")
    assert resumed["leg"] == 2 and resumed["progress"]["files_read"] == 10 and second[-1]["type"] == "continue"
    third = stream(client, "/api/v1/demo/audit/continue", {"job_id": job["job_id"]})
    assert third[-1]["type"] == "result" and third[-1]["data"]["job"]["legs"] == 3
    assert third[-1]["data"]["ai"]["allowance"]["left_this_hour"] == 4
    # A reload after the end: the same result, no fourth leg, no second slot.
    again = client.post("/api/v1/demo/audit/continue", json={"job_id": job["job_id"]}).json()
    assert again == third[-1]["data"] and legs == [1, 2, 3]
    assert len(rate_limit._memory.paths) == 3  # client-hour, hour and day: one slot each, once


def test_the_plain_api_answers_202_while_a_job_is_unfinished_and_cancel_ends_it(api_jobs):
    client, legs = api_jobs
    response = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r", "model_review_consent": True})
    assert response.status_code == 202 and response.json()["type"] == "continue"
    job_id = response.json()["job_id"]
    assert client.post("/api/v1/demo/audit/cancel", json={"job_id": job_id}).json()["status"] == "cancelled"
    after = client.post("/api/v1/demo/audit/continue", json={"job_id": job_id})
    assert after.status_code == 202 and after.json()["type"] == "cancelled" and legs == [1]
    assert client.post("/api/v1/demo/audit/continue", json={"job_id": "nope-nope-nope"}).status_code == 422
    gone = client.post("/api/v1/demo/audit/continue", json={"job_id": "20200101-" + "a" * 24})
    assert gone.status_code == 410 and "Run it again" in gone.json()["detail"]


def test_the_job_self_check_runs_on_the_store_only_on_previews(api_jobs, monkeypatch):
    client, _ = api_jobs
    api._self_check_last[0] = 0.0
    assert client.post("/api/v1/ops/job-check").status_code == 404
    monkeypatch.setenv("VERCEL_ENV", "preview")
    out = client.post("/api/v1/ops/job-check").json()
    assert out["ok"] is True and out["double_continue"] == ["busy", "claimed"] and out["left_after_delete"] == 0


def test_every_leg_fits_the_function_limit():
    config = json.loads((ROOT / "vercel.json").read_text())
    limit = config["functions"]["app.py"]["maxDuration"]
    settings = Settings(_env_file=None)
    assert audit_jobs.FUNCTION_MAX_SECONDS == limit
    # The last model call starts at the leg's end at the latest and is cut LEG_MARGIN before it;
    # the report and the store writes need the rest.
    assert settings.demo_leg_seconds + 30 <= limit <= api.DEMO_REQUEST_SECONDS + 10
    assert audit_jobs.LEASE_SECONDS > limit and audit_jobs.STALE_SECONDS > settings.deep_review_call_timeout_seconds
