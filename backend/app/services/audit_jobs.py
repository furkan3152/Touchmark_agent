"""Audits that outlive one request: a job, advanced by request legs, kept in Vercel Blob.

A serverless function may run 300 s (vercel.json, and the project's plan). A full model
review of a 100+ file repository takes longer, and nothing should cut it short except a spend
cap (services/review_budget.py). So the public demo runs an audit as a job:

- the first request creates the job (and claims the one model-review allowance slot the job
  will ever use), pins the commit and runs the audit as far as the request may;
- the review and the verifier save their place after every model turn and every verdict; when
  the request nears its limit they stop, and the stream ends with a ``continue`` event that
  carries the job id;
- the page opens the next leg at once (and after a reload, from the id kept in
  sessionStorage); each leg re-reads the pinned commit, checks it is byte-for-byte the source
  the job started on, and continues from the saved state;
- the leg that finishes stores the result; continuing a finished job returns it again.

Store layout, in the same private Blob store as the allowance (one prefix per creation day,
so whole days expire together):

    touchmark-jobs/20261101/<token>/s/000000      state snapshots, gzip JSON, create-only
    touchmark-jobs/20261101/<token>/s/000001
    touchmark-jobs/20261101/<token>/result        the finished result, create-only
    touchmark-jobs/20261101/<token>/cancel        written by Cancel

Every object is written once with a create-only put and never changed, so no reader sees a
stale copy. The newest snapshot is the state. Writing snapshot n+1 is the only way to change a
job, and the store refuses it when n+1 exists: two legs of one job can never both proceed
(a double continue, a retry after a dropped connection, two tabs). The loser stops before it
spends anything more. A leg holds the job with a lease it renews at each checkpoint; a lease
not renewed for ``STALE_SECONDS``, or older than the function limit, belongs to a request that
is gone, and the next continue takes the job over.

Nothing runs between legs: a job nobody continues stops after its current leg, and expires
after ``demo_job_ttl_hours`` (day prefixes older than that are deleted).
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from .review_budget import Budget, Leg, LegSuspended, ReviewCancelled, Spend, leg_scope

logger = logging.getLogger("touchmark.audit_jobs")

ROOT = "touchmark-jobs"
JOB_ID = re.compile(r"^(\d{8})-([A-Za-z0-9_-]{24})$")
#: vercel.json gives app.py this long; no leg can be alive after it.
FUNCTION_MAX_SECONDS = 300.0
LEASE_SECONDS = FUNCTION_MAX_SECONDS + 30.0
#: A live leg checkpoints after every model turn and before every retry; one call may take
#: deep_review_call_timeout_seconds (120 s). A lease quiet for longer than this is abandoned.
STALE_SECONDS = 180.0
#: Snapshots kept per job when older ones are pruned (every fourth write).
KEEP_SNAPSHOTS = 3


class StoreError(RuntimeError):
    """The job store did not answer as expected."""


class MemoryObjects:
    """Process memory, for local runs and tests. Thread-safe: legs run on worker threads."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self._lock = threading.Lock()

    async def listing(self, prefix: str) -> dict[str, str]:
        with self._lock:
            return {p: p for p in self.objects if p.startswith(prefix)}

    async def put_new(self, path: str, data: bytes) -> bool:
        with self._lock:
            if path in self.objects:
                return False
            self.objects[path] = data
            return True

    async def read(self, url: str) -> bytes | None:
        with self._lock:
            return self.objects.get(url)

    async def delete(self, urls: list[str]) -> None:
        with self._lock:
            for url in urls:
                self.objects.pop(url, None)

    async def delete_prefix(self, prefix: str) -> None:
        with self._lock:
            for path in [p for p in self.objects if p.startswith(prefix)]:
                del self.objects[path]


_memory = MemoryObjects()


def job_store_from_settings(settings):
    """The allowance's store: Vercel Blob when configured, process memory off serverless, else none."""
    from .rate_limit import BlobStore, limiter_from_settings
    store = limiter_from_settings(settings).store
    if isinstance(store, BlobStore):
        return store
    return _memory if store is not None else None


def _encode(value: dict) -> bytes:
    return gzip.compress(json.dumps(value, separators=(",", ":"), default=str).encode(), mtime=0)


def _decode(data: bytes) -> dict:
    return json.loads(gzip.decompress(data).decode())


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%d")


class JobHandle:
    """A job held by this leg. Every change is a create-only write of the next snapshot."""

    def __init__(self, store, job_id: str, state: dict, seq: int, owner: str, clock=time.time) -> None:
        self.store, self.job_id, self.state, self.seq, self.owner = store, job_id, state, seq, owner
        self.clock = clock
        self.lost = False
        self._cancel_checked = 0.0
        self._cancelled = False
        self._written: list[str] = []

    @property
    def prefix(self) -> str:
        return job_prefix(self.job_id)

    async def _write(self, state: dict) -> bool:
        path = f"{self.prefix}s/{self.seq + 1:06d}"
        try:
            ok = await self.store.put_new(path, _encode(state))
        except Exception as exc:  # noqa: BLE001 - a store that cannot be written ends the leg
            raise StoreError(type(exc).__name__) from exc
        if not ok:
            return False
        self.seq += 1
        self.state = state
        self._written.append(path)
        if self.seq % 4 == 0:  # every fourth write: each store call costs time on a leg
            await self._prune()
        return True

    async def _prune(self) -> None:
        try:
            listing = await self.store.listing(f"{self.prefix}s/")
            old = sorted(listing)[:-KEEP_SNAPSHOTS]
            if old:
                await self.store.delete([listing[p] for p in old])
        except Exception:  # noqa: BLE001 - pruning is housekeeping
            pass

    def _next(self, **changes) -> dict:
        state = dict(self.state)
        state.update({k: v for k, v in changes.items() if v is not None})
        now = self.clock()
        if state.get("status") == "running":
            state["lease"] = {**(state.get("lease") or {}), "owner": self.owner, "renewed_at": now}
        state["updated_at"] = now
        return state

    async def checkpoint(self, *, spend: dict | None = None, review: dict | None = None,
                         verification: dict | None = None, progress: dict | None = None, pin: dict | None = None) -> None:
        if self.lost:
            raise LegSuspended("lease_lost")
        try:
            ok = await self._write(self._next(spend=spend, review=review, verification=verification,
                                              progress=progress, pin=pin))
        except StoreError as exc:
            logger.warning("job checkpoint failed: %s", exc)
            raise LegSuspended("store_unavailable") from exc
        if not ok:
            self.lost = True  # another leg wrote first: it holds the job now
            raise LegSuspended("lease_lost")

    async def heartbeat(self, *, spend: dict | None = None) -> None:
        await self.checkpoint(spend=spend)

    async def cancel_requested(self) -> bool:
        """Checked before each model call (at most every two seconds)."""
        if self._cancelled:
            return True
        now = time.monotonic()
        if now - self._cancel_checked < 2.0:
            return False
        self._cancel_checked = now
        try:
            self._cancelled = bool(await self.store.listing(f"{self.prefix}cancel"))
        except Exception:  # noqa: BLE001 - an unreadable marker is no cancel; the next check retries
            return False
        return self._cancelled

    async def finish(self, status: str, **fields) -> bool:
        """Release the job: suspended (waits for a continue), completed, failed or cancelled."""
        if self.lost:
            return False
        state = self._next(status=status, **fields)
        state["lease"] = None
        try:
            return await self._write(state)
        except StoreError:
            return False

    async def store_result(self, result: dict) -> None:
        try:
            await self.store.put_new(f"{self.prefix}result", _encode(result))
        except Exception as exc:  # noqa: BLE001
            raise StoreError(type(exc).__name__) from exc


def job_prefix(job_id: str) -> str:
    match = JOB_ID.match(job_id or "")
    if not match:
        raise ValueError("Not a job id.")
    return f"{ROOT}/{match.group(1)}/{match.group(2)}/"


class JobManager:
    def __init__(self, store, settings, clock=time.time) -> None:
        self.store, self.settings, self.clock = store, settings, clock

    def _ttl(self) -> float:
        return float(self.settings.demo_job_ttl_hours) * 3600

    async def create(self, request: dict) -> JobHandle:
        now = self.clock()
        job_id = f"{_day(now)}-{secrets.token_urlsafe(18)}"
        owner = secrets.token_hex(8)
        state = {"v": 1, "job_id": job_id, "status": "running", "created_at": now, "updated_at": now,
                 "expires_at": now + self._ttl(), "leg": 1, "legs_started": [now],
                 "lease": {"owner": owner, "started_at": now, "renewed_at": now},
                 "request": request, "pin": {}, "review": None, "verification": None, "spend": {},
                 "progress": {"stage": "queued"}, "error": ""}
        try:
            ok = await self.store.put_new(f"{job_prefix(job_id)}s/{0:06d}", _encode(state))
        except Exception as exc:  # noqa: BLE001
            raise StoreError(type(exc).__name__) from exc
        if not ok:  # a 144-bit id collided: astronomically unlikely, still refused
            raise StoreError("job id collision")
        await self._maybe_cleanup(now)
        return JobHandle(self.store, job_id, state, 0, owner, self.clock)

    async def load(self, job_id: str) -> tuple[dict, int] | None:
        prefix = job_prefix(job_id)
        for _ in range(3):
            try:
                listing = await self.store.listing(f"{prefix}s/")
            except Exception as exc:  # noqa: BLE001
                raise StoreError(type(exc).__name__) from exc
            if not listing:
                return None
            latest = max(listing)
            try:
                data = await self.store.read(listing[latest])
            except Exception as exc:  # noqa: BLE001
                raise StoreError(type(exc).__name__) from exc
            if data is not None:  # None: pruned between the listing and the read; list again
                return _decode(data), int(latest.rsplit("/", 1)[1])
        return None

    async def result(self, job_id: str) -> dict | None:
        prefix = job_prefix(job_id)
        listing = await self.store.listing(f"{prefix}result")
        url = listing.get(f"{prefix}result")
        data = await self.store.read(url) if url else None
        return _decode(data) if data else None

    def _lease_alive(self, state: dict, now: float) -> bool:
        lease = state.get("lease") or {}
        if state.get("status") != "running" or not lease:
            return False
        return (now - float(lease.get("renewed_at", 0)) < STALE_SECONDS
                and now - float(lease.get("started_at", 0)) < LEASE_SECONDS)

    async def claim(self, job_id: str) -> tuple[str, JobHandle | None, dict]:
        """("claimed", handle, state) to run the next leg, or why not: completed (with the stored
        result), busy (another leg holds it), cancelled, failed, expired, missing."""
        loaded = await self.load(job_id)
        if loaded is None:
            return "missing", None, {}
        state, seq = loaded
        now = self.clock()
        if now > float(state.get("expires_at", 0)):
            await self._delete(job_id)
            return "expired", None, state
        status = state.get("status")
        if status == "completed":
            result = await self.result(job_id)
            return ("completed", None, {"state": state, "result": result}) if result else ("failed", None, state)
        if status in ("cancelled", "failed"):
            return status, None, state
        if self._lease_alive(state, now):
            renewed = float((state.get("lease") or {}).get("renewed_at", now))
            return "busy", None, {**state, "retry_after": max(3, min(15, int(STALE_SECONDS - (now - renewed))))}
        owner = secrets.token_hex(8)
        handle = JobHandle(self.store, job_id, state, seq, owner, self.clock)
        if await handle.cancel_requested():
            await handle.finish("cancelled")
            return "cancelled", None, handle.state
        claimed = dict(state, status="running", leg=int(state.get("leg", 0)) + 1,
                       legs_started=[*(state.get("legs_started") or []), now][-200:],
                       lease={"owner": owner, "started_at": now, "renewed_at": now}, updated_at=now)
        try:
            ok = await handle._write(claimed)
        except StoreError:
            raise
        if not ok:
            return "busy", None, {**state, "retry_after": 3}
        return "claimed", handle, handle.state

    async def cancel(self, job_id: str) -> str:
        """Mark the job cancelled. A running leg stops before its next model call."""
        loaded = await self.load(job_id)
        if loaded is None:
            return "missing"
        state, seq = loaded
        if state.get("status") in ("completed", "cancelled", "failed"):
            return state["status"]
        try:
            await self.store.put_new(f"{job_prefix(job_id)}cancel", b"")
        except Exception as exc:  # noqa: BLE001
            raise StoreError(type(exc).__name__) from exc
        if not self._lease_alive(state, self.clock()):
            # Nobody is running it: record the end now (a leg that wins the race sees the marker).
            handle = JobHandle(self.store, job_id, state, seq, secrets.token_hex(8), self.clock)
            await handle.finish("cancelled")
        return "cancelled"

    async def _delete(self, job_id: str) -> None:
        try:
            await self.store.delete_prefix(job_prefix(job_id))
        except Exception:  # noqa: BLE001
            pass

    async def _maybe_cleanup(self, now: float) -> None:
        """Delete whole creation days older than the TTL allows (the first job of each hour does it)."""
        if datetime.fromtimestamp(now, timezone.utc).minute > 4 and secrets.randbelow(20):
            return
        await self.cleanup(now)

    async def cleanup(self, now: float | None = None) -> list[str]:
        now = self.clock() if now is None else now
        oldest_kept = datetime.fromtimestamp(now - self._ttl(), timezone.utc).date()
        swept = []
        for back in range(1, 8):
            day = oldest_kept - timedelta(days=back)
            prefix = f"{ROOT}/{day.strftime('%Y%m%d')}/"
            try:
                await self.store.delete_prefix(prefix)
                swept.append(prefix)
            except Exception:  # noqa: BLE001 - housekeeping; the next sweep retries
                break
        return swept


def manager_from_settings(settings) -> JobManager | None:
    store = job_store_from_settings(settings)
    return JobManager(store, settings) if store is not None else None


def describe(state: dict, now: float | None = None) -> dict:
    """What the page is told about a job: id, leg, overall elapsed seconds and progress."""
    now = time.time() if now is None else now
    return {"job_id": state.get("job_id", ""), "leg": int(state.get("leg", 0)), "job_status": state.get("status", ""),
            "elapsed": round(max(0.0, now - float(state.get("created_at", now))), 1),
            "progress": state.get("progress") or {}, "reference": (state.get("request") or {}).get("reference", ""),
            "consent": bool((state.get("request") or {}).get("consent"))}


async def run_leg(handle: JobHandle, settings, *, started: float, abandoned: threading.Event | None = None,
                  audit=None) -> dict:
    """Advance the job as far as this request may. Returns the event that ends the stream:
    result, continue, busy, cancelled or error. ``started`` is the request's time.monotonic()."""
    from .rate_limit import limiter_from_settings
    if audit is None:
        from .demo_flow import run_demo_audit as audit
    request = handle.state.get("request") or {}
    spend = Spend.from_dict(handle.state.get("spend"))
    budget = Budget.from_settings(settings, spend=spend, store=limiter_from_settings(settings).store)
    leg = Leg(budget=budget, deadline=started + float(settings.demo_leg_seconds), job=handle,
              abandoned=abandoned or threading.Event(), review_state=handle.state.get("review"),
              verification_state=handle.state.get("verification"), pin=dict(handle.state.get("pin") or {}))
    info = lambda: describe(handle.state, handle.clock())  # noqa: E731
    try:
        return await _advance(handle, settings, request, budget, leg, info, audit)
    finally:
        _log_spend(str(handle.state.get("status", "")), budget, int(handle.state.get("leg", 0)))


async def _advance(handle: JobHandle, settings, request: dict, budget: Budget, leg: Leg, info, audit) -> dict:
    try:
        with leg_scope(leg):
            out = await audit(request["reference"], settings, ai=bool(request.get("ai")),
                              tmark_text=request.get("tmark"), skipped=request.get("skipped"))
    except LegSuspended as exc:
        if exc.reason == "lease_lost":
            return {"type": "busy", **info(), "retry_after": 3}
        await handle.finish("suspended", spend=budget.spend.to_dict())
        return {"type": "continue", **info(), "reason": exc.reason,
                "retry_after": 5 if exc.reason == "store_unavailable" else 0}
    except ReviewCancelled:
        await handle.finish("cancelled", spend=budget.spend.to_dict())
        return {"type": "cancelled", **info()}
    except ValueError as exc:
        await handle.finish("failed", error=str(exc)[:500], spend=budget.spend.to_dict())
        return {"type": "error", "status": 422, "detail": str(exc), **info()}
    except Exception as exc:  # noqa: BLE001 - reported to the client, not hidden
        logger.warning("audit leg failed: %s", type(exc).__name__)
        await handle.finish("failed", error=type(exc).__name__, spend=budget.spend.to_dict())
        return {"type": "error", "status": 500, "detail": "The audit stopped on an internal error. Try again.", **info()}
    if await handle.cancel_requested():
        await handle.finish("cancelled", spend=budget.spend.to_dict())
        return {"type": "cancelled", **info()}
    if request.get("allowance") is not None:
        out["ai"]["allowance"] = request["allowance"]
    legs = int(handle.state.get("leg", 1))
    out["job"] = {"id": handle.job_id, "legs": legs,
                  "elapsed": round(handle.clock() - float(handle.state.get("created_at", handle.clock())), 1)}
    try:
        await handle.store_result(out)
    except StoreError:
        return {"type": "result", "data": out}  # the result is here; only a reload could not fetch it again
    await handle.finish("completed", spend=budget.spend.to_dict(), progress={"stage": "done"})
    return {"type": "result", "data": out}


def _log_spend(outcome: str, budget: Budget, leg: int) -> None:
    """Measured spend goes to the server log (and the job state), never to a public response.
    The job id is left out: it is the job's only credential (continue, cancel)."""
    if not budget.spend.calls and not budget.spend.cut_calls:
        return
    s = budget.summary()
    logger.info("audit leg %s (leg %d): %d model calls, %d tokens, %.4f USD; stopped by %s",
                outcome, leg, s["calls"], s["tokens"], s["cost_usd"], s["stopped_by"] or "nothing")


def is_serverless(settings) -> bool:
    return bool(settings.stateless_studio or os.environ.get("VERCEL") == "1")


class _RehearsalClient:
    """A model client that costs nothing: each call reads the next file and finishes its pass,
    reporting usage as a real response does. Used only by ``self_check``."""

    def __init__(self, files: list[str], delay: float = 0.4) -> None:
        from types import SimpleNamespace
        self.files, self.delay, self.calls = list(files), delay, 0
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        import asyncio
        from types import SimpleNamespace
        await asyncio.sleep(self.delay)
        n, self.calls = self.calls, self.calls + 1
        blocks = []
        if n == 0:
            blocks.append(SimpleNamespace(type="tool_use", id=f"t{n}a", name="describe_operating_model", input={
                "purpose": "self-check", "triggers": "self-check", "example_run": "self-check",
                "trust_boundaries": [], "assets_at_risk": []}))
        if n < len(self.files):
            blocks.append(SimpleNamespace(type="tool_use", id=f"t{n}b", name="read_source",
                                          input={"path": self.files[n], "start_line": 1, "end_line": 5}))
        blocks.append(SimpleNamespace(type="tool_use", id=f"t{n}c", name="finish", input={"summary": "ok"}))
        return SimpleNamespace(content=blocks, stop_reason="tool_use", usage=SimpleNamespace(
            input_tokens=1000, output_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0))


async def self_check(store, settings) -> dict:
    """Exercise the job machinery on the real store with a model client that costs nothing:
    a first leg that stops at its time limit, two continues at once (exactly one may run), a
    second leg that resumes and finishes, an idempotent continue of the finished job, a
    cancelled job, and the deletion of both. Answers booleans and counts only."""
    import asyncio
    from ..models import AgentArtifact, SourceKind
    from .deep_review import DeepReviewer
    from .review_budget import MIN_CALL_SECONDS
    out: dict = {}
    manager = JobManager(store, settings)
    files = {f"src/m{i}.py": f"x{i} = {i}\n" for i in range(6)}
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="self-check", code_files=files)
    client = _RehearsalClient(sorted(files))
    reviewer = DeepReviewer(client, model="self-check", passes=1, files_per_pass=2, fallbacks=False)
    ids: list[str] = []
    started = time.monotonic()
    try:
        handle = await manager.create({"reference": "self-check", "ai": False})
        ids.append(handle.job_id)
        leg1 = Leg(budget=Budget(), deadline=time.monotonic() + MIN_CALL_SECONDS + 1.3, job=handle)
        try:
            with leg_scope(leg1):
                await reviewer.review(artifact, [])
            out["leg1_suspended"] = False
        except LegSuspended:
            out["leg1_suspended"] = await handle.finish("suspended", spend=leg1.budget.spend.to_dict())
        out["leg1_files_read"] = (handle.state.get("progress") or {}).get("files_read")
        out["leg1_calls"] = Spend.from_dict(handle.state.get("spend")).calls
        claims = await asyncio.gather(manager.claim(handle.job_id), manager.claim(handle.job_id))
        out["double_continue"] = sorted(c[0] for c in claims)
        winner = next((c[1] for c in claims if c[0] == "claimed"), None)
        if winner is not None:
            leg2 = Leg(budget=Budget(spend=Spend.from_dict(winner.state.get("spend"))), deadline=None, job=winner,
                       review_state=winner.state.get("review"), pin=winner.state.get("pin") or {})
            with leg_scope(leg2):
                review = await reviewer.review(artifact, [])
            out["resumed_status"] = review.status
            out["resumed_files_read"] = len(review.files_read)
            out["total_calls"] = leg2.budget.spend.calls
            out["model_calls_made"] = client.calls
            await winner.store_result({"self_check": True, "files_read": len(review.files_read)})
            out["finished"] = await winner.finish("completed", spend=leg2.budget.spend.to_dict())
        again = await manager.claim(handle.job_id)
        out["continue_after_finish"] = again[0]
        out["result_returned"] = bool(again[0] == "completed" and (again[2].get("result") or {}).get("self_check"))
        other = await manager.create({"reference": "self-check", "ai": False})
        ids.append(other.job_id)
        await other.finish("suspended")
        out["cancel"] = await manager.cancel(other.job_id)
        out["continue_after_cancel"] = (await manager.claim(other.job_id))[0]
    except Exception as exc:  # noqa: BLE001 - reported by class, the check never raises
        out.setdefault("errors", []).append(type(exc).__name__)
    finally:
        for job_id in ids:
            await manager._delete(job_id)
        try:
            out["left_after_delete"] = sum([len(await store.listing(job_prefix(j))) for j in ids])
        except Exception as exc:  # noqa: BLE001
            out.setdefault("errors", []).append(type(exc).__name__)
    out["seconds"] = round(time.monotonic() - started, 1)
    out["ok"] = (out.get("leg1_suspended") is True and out.get("double_continue") == ["busy", "claimed"]
                 and out.get("resumed_status") == "completed" and out.get("resumed_files_read") == len(files)
                 and out.get("total_calls") == out.get("model_calls_made")
                 and out.get("continue_after_finish") == "completed" and out.get("result_returned") is True
                 and out.get("cancel") == "cancelled" and out.get("continue_after_cancel") == "cancelled"
                 and out.get("left_after_delete") == 0 and not out.get("errors"))
    return out
