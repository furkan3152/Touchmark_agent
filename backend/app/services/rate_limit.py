"""Durable allowance for the paid model review on stateless serverless.

The public demo runs on Vercel functions: each invocation may be a fresh process, so a
counter in memory is not a limit. The allowance is kept in Vercel Blob instead (the private
store the project already has, ``BLOB_READ_WRITE_TOKEN``), as numbered slots:

    touchmark-limits/deep-review/20261031/day/0007
    touchmark-limits/deep-review/20261031/h14/all/0031
    touchmark-limits/deep-review/20261031/h14/c/<hashed client>/02

A slot is claimed with a create-only write (``x-allow-overwrite: 0``), which the store
refuses when the slot exists, so two concurrent requests can never both take the last one:
the ceiling holds exactly, and a race costs a retry, not an over-spend. The count read
before claiming only picks where to start; a stale listing makes the claim fail and move on.

Three allowances are claimed in order, the narrowest first: per client per hour, overall per
hour, overall per day (``DEEP_REVIEW_DAILY_LIMIT``, a hard ceiling). Clients are identified by
the address Vercel reports, HMAC-hashed: no raw address is stored.

Fail closed: when the store cannot be reached, is not configured on a serverless deployment,
or answers with anything unexpected, the model review is refused and the audit runs on the
deterministic rules, saying why. The limiter never fails the audit itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

logger = logging.getLogger("touchmark.rate_limit")

PREFIX = "touchmark-limits/deep-review"
#: Each store call is bounded; a slow store counts as unavailable.
STORE_TIMEOUT_SECONDS = 6.0
#: Create-only attempts per allowance before giving up (a burst of concurrent claims).
MAX_ATTEMPTS = 12


class StoreUnavailable(RuntimeError):
    """The counter store could not answer; the caller fails closed."""


class CounterStore(Protocol):
    async def count(self, prefix: str) -> int: ...
    async def claim(self, path: str) -> bool: ...
    async def delete(self, paths: list[str]) -> None: ...
    async def delete_prefix(self, prefix: str) -> None: ...


class MemoryStore:
    """One process (local development, a single persistent worker, tests)."""

    def __init__(self) -> None:
        self.paths: set[str] = set()
        # A thread lock: audits run on worker threads, each with its own event loop.
        self._lock = threading.Lock()

    async def count(self, prefix: str) -> int:
        return sum(1 for p in list(self.paths) if p.startswith(prefix))

    async def claim(self, path: str) -> bool:
        with self._lock:
            if path in self.paths:
                return False
            self.paths.add(path)
            return True

    async def delete(self, paths: list[str]) -> None:
        with self._lock:
            self.paths.difference_update(paths)

    async def delete_prefix(self, prefix: str) -> None:
        # In place and under the lock: a claim on another thread is never lost to a rebind.
        with self._lock:
            self.paths.difference_update([p for p in self.paths if p.startswith(prefix)])


class BlobStore:
    """Vercel Blob (private store). Slots are empty files; only their names carry data."""

    def __init__(self, token: str, client_factory=None) -> None:
        self.token = token
        self._factory = client_factory

    def _client(self):
        if self._factory is not None:
            return self._factory()
        from vercel.blob import AsyncBlobClient
        return AsyncBlobClient(token=self.token)

    async def count(self, prefix: str) -> int:
        total, cursor = 0, None
        async with self._client() as client:
            for _ in range(5):  # at most 5,000 slots are counted; every ceiling is far below
                page = await client.list_objects(prefix=prefix, limit=1000, cursor=cursor)
                total += len(page.blobs)
                if not page.has_more or not page.cursor:
                    break
                cursor = page.cursor
        return total

    async def claim(self, path: str) -> bool:
        from vercel.blob import BlobError
        async with self._client() as client:
            try:
                await client.put(path, b"", access="private", content_type="text/plain",
                                 add_random_suffix=False, overwrite=False)
            except BlobError as exc:
                if "already exists" in str(exc).lower():
                    return False
                raise
        return True

    async def delete(self, paths: list[str]) -> None:
        if paths:
            async with self._client() as client:
                await client.delete(paths)

    async def delete_prefix(self, prefix: str) -> None:
        async with self._client() as client:
            for _ in range(20):  # 20,000 objects at most per sweep
                page = await client.list_objects(prefix=prefix, limit=1000)
                if not page.blobs:
                    break
                await client.delete([b.url for b in page.blobs])
                if not page.has_more:
                    break

    # Objects with content (audit job state, services/audit_jobs.py). Each is written once and
    # never changed, so no reader can see a stale copy of it.
    async def listing(self, prefix: str) -> dict[str, str]:
        """{pathname: url} under ``prefix`` (at most 5,000)."""
        out, cursor = {}, None
        async with self._client() as client:
            for _ in range(5):
                page = await client.list_objects(prefix=prefix, limit=1000, cursor=cursor)
                out.update({b.pathname: b.url for b in page.blobs})
                if not page.has_more or not page.cursor:
                    break
                cursor = page.cursor
        return out

    async def put_new(self, path: str, data: bytes) -> bool:
        """Create-only write with content: False when the path exists."""
        from vercel.blob import BlobError
        async with self._client() as client:
            try:
                await client.put(path, data, access="private", content_type="application/octet-stream",
                                 add_random_suffix=False, overwrite=False)
            except BlobError as exc:
                if "already exists" in str(exc).lower():
                    return False
                raise
        return True

    async def read(self, url: str) -> bytes | None:
        from vercel.blob import BlobNotFoundError
        async with self._client() as client:
            try:
                got = await client.get(url, access="private", use_cache=False)
            except BlobNotFoundError:
                return None
        return got.content if getattr(got, "status_code", 200) == 200 else None


@dataclass
class Decision:
    allowed: bool
    #: "allowed", "client_hour", "hour", "day", "store_unavailable", "not_configured"
    reason: str
    limits: dict = field(default_factory=dict)
    #: Slots still free after this claim, per allowance (known only when one was claimed).
    left: dict = field(default_factory=dict)

    @property
    def message(self) -> str:
        return {
            "allowed": "",
            "client_hour": f"This connection used its {self.limits.get('client_hour')} model reviews for this hour.",
            "hour": f"The deployment used its {self.limits.get('hour')} model reviews for this hour.",
            "day": f"The deployment reached its daily ceiling of {self.limits.get('day')} model reviews.",
            "store_unavailable": "The model-review allowance could not be checked, so the model review was not run.",
            "not_configured": "No durable allowance store is configured on this deployment, so the model review is off.",
        }[self.reason]


class DeepReviewLimiter:
    def __init__(self, store: CounterStore | None, *, client_hour: int = 5, hour: int = 60, day: int = 200,
                 salt: bytes = b"", clock=None) -> None:
        self.store = store
        self.limits = {"client_hour": max(0, client_hour), "hour": max(0, hour), "day": max(0, day)}
        self.salt = salt or secrets.token_bytes(32)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def client_key(self, client: str) -> str:
        """The hashed client identity used in slot names; the address itself is never stored."""
        return hmac.new(self.salt, (client or "unknown").encode(), hashlib.sha256).hexdigest()[:24]

    def _paths(self, client: str) -> list[tuple[str, str, int]]:
        now = self.clock()
        day, hour = now.strftime("%Y%m%d"), now.strftime("%H")
        return [("client_hour", f"{PREFIX}/{day}/h{hour}/c/{self.client_key(client)}/", self.limits["client_hour"]),
                ("hour", f"{PREFIX}/{day}/h{hour}/all/", self.limits["hour"]),
                ("day", f"{PREFIX}/{day}/day/", self.limits["day"])]

    async def _bounded(self, awaitable):
        try:
            return await asyncio.wait_for(awaitable, timeout=STORE_TIMEOUT_SECONDS)
        except StoreUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - any store failure means: do not spend
            raise StoreUnavailable(f"{type(exc).__name__}") from exc

    async def _claim_one(self, prefix: str, limit: int) -> str | None:
        """The slot path claimed under ``prefix``, or None when all ``limit`` slots are taken."""
        if limit <= 0:
            return None
        width = len(str(max(limit - 1, 1)))
        n, tried, wrapped = await self._bounded(self.store.count(prefix)), 0, False
        while tried < MAX_ATTEMPTS:
            if n >= limit:
                if wrapped:
                    return None
                # Every slot from the count up is taken; a refunded claim may have left a hole below.
                n, wrapped = 0, True
            tried += 1
            if await self._bounded(self.store.claim(f"{prefix}{n:0{width}d}")):
                return f"{prefix}{n:0{width}d}"
            # Someone else took it: jump to what the store holds now rather than one step on.
            recount = await self._bounded(self.store.count(prefix))
            n = n + 1 if wrapped else max(n + 1, recount)
            if n >= limit and recount >= limit:
                return None
        return None

    async def acquire(self, client: str) -> Decision:
        if self.store is None:
            return Decision(False, "not_configured", self.limits)
        claimed: list[str] = []
        left: dict[str, int] = {}
        try:
            for name, prefix, limit in self._paths(client):
                path = await self._claim_one(prefix, limit)
                if path is None:
                    await self._refund(claimed)
                    return Decision(False, name, self.limits, left={**left, name: 0})
                claimed.append(path)
                # Slot n taken means at least n + 1 are used (a refund can leave a hole below).
                left[name] = max(0, limit - int(path.rsplit("/", 1)[1]) - 1)
            if not claimed[-1].rsplit("/", 1)[1].strip("0"):
                await self._cleanup()  # the first review of a day clears days long past
            return Decision(True, "allowed", self.limits, left=left)
        except StoreUnavailable as exc:
            logger.warning("deep-review allowance store unavailable: %s", exc)
            await self._refund(claimed)
            return Decision(False, "store_unavailable", self.limits)

    async def remaining(self, client: str) -> dict[str, int]:
        """Free slots per allowance for this client, without claiming any (three listings).
        Raises StoreUnavailable when the store cannot answer."""
        if self.store is None:
            raise StoreUnavailable("not_configured")
        names, prefixes, limits = zip(*self._paths(client))
        counts = await self._bounded(asyncio.gather(*(self.store.count(p) for p in prefixes)))
        return {name: max(0, limit - count) for name, limit, count in zip(names, limits, counts)}

    def describe(self, left: dict[str, int]) -> dict:
        """What a visitor can be told about the allowance: reviews left this hour and today,
        whether it is used up, by which ceiling, and when that ceiling resets (UTC)."""
        now = self.clock()
        next_hour = (now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)).isoformat()
        next_day = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).isoformat()
        hourly = [left[k] for k in ("client_hour", "hour") if k in left]
        reason = next((k for k in ("client_hour", "hour", "day") if left.get(k) == 0), "")
        return {"left_this_hour": min(hourly) if hourly else None, "left_today": left.get("day"),
                "used_up": bool(reason), "reason": reason,
                "resets_at": next_day if reason == "day" else next_hour if reason else ""}

    async def _refund(self, claimed: list[str]) -> None:
        """Give back slots claimed before a later allowance refused (best effort)."""
        if claimed:
            try:
                await self._bounded(self.store.delete(claimed))
            except StoreUnavailable:
                pass

    async def _cleanup(self) -> None:
        now = self.clock()
        for days in (2, 3):
            try:
                await self._bounded(self.store.delete_prefix(f"{PREFIX}/{(now - timedelta(days=days)).strftime('%Y%m%d')}/"))
            except StoreUnavailable:
                return


async def _winners(claims) -> int:
    results = await claims
    if any(isinstance(r, BaseException) for r in results):
        raise next(r for r in results if isinstance(r, BaseException))
    return sum(1 for r in results if r is True)


async def self_check(store: CounterStore, *, prefix: str = f"{PREFIX.rsplit('/', 1)[0]}/self-check/") -> dict:
    """Exercise the store the way the limiter does, on a throwaway path: a create-only claim, the
    same claim again (it must be refused as already existing), a listing, then a delete. Returns
    booleans and exception class names only, never a token, URL or stored value."""
    path = f"{prefix}{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(4)}"
    out: dict = {"path_prefix": prefix}

    async def step(name: str, awaitable):
        try:
            out[name] = await asyncio.wait_for(awaitable, timeout=STORE_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 - reported by class, the check never raises
            out[name] = None
            out.setdefault("errors", {})[name] = type(exc).__name__
    await step("first_claim", store.claim(path))
    await step("second_claim", store.claim(path))
    await step("listed", store.count(path))
    await step("deleted", store.delete([path]))
    await step("listed_after_delete", store.count(path))
    # Three claims of one fresh slot at once: exactly one may win, or the ceiling could be overspent.
    race = f"{path}-race"
    await step("race_winners", _winners(asyncio.gather(*(store.claim(race) for _ in range(3)), return_exceptions=True)))
    await step("race_cleanup", store.delete([race]))
    out["ok"] = (out.get("first_claim") is True and out.get("second_claim") is False
                 and out.get("listed") == 1 and out.get("listed_after_delete") == 0 and out.get("race_winners") == 1)
    out.pop("race_cleanup", None)
    out.pop("deleted", None)
    return out


_memory = MemoryStore()
#: One key per process for the memory store, so a client hashes the same on every request.
_PROCESS_SALT = secrets.token_bytes(32)


def limiter_from_settings(settings) -> DeepReviewLimiter:
    """Blob when a token is configured; process memory only where a process is long-lived;
    nothing (model review off) on a serverless deployment without a durable store."""
    mode = (settings.deep_review_limit_store or "auto").lower()
    token = settings.blob_read_write_token
    serverless = settings.stateless_studio or os.environ.get("VERCEL") == "1"
    if mode == "none":
        store = None
    elif mode == "blob" or (mode == "auto" and token):
        store = BlobStore(token) if token else None
    elif mode == "memory" or (mode == "auto" and not serverless):
        store = _memory
    else:
        store = None
    salt = (settings.deep_review_rate_salt.encode() if settings.deep_review_rate_salt
            else hashlib.sha256(b"touchmark.deep-review-limit.v1|" + token.encode()).digest() if token else _PROCESS_SALT)
    return DeepReviewLimiter(store, client_hour=settings.deep_review_client_hourly_limit,
                             hour=settings.deep_review_hourly_limit, day=settings.deep_review_daily_limit,
                             salt=salt)


def store_kind(settings) -> str:
    """For status reporting: which store the allowance uses."""
    store = limiter_from_settings(settings).store
    return "vercel_blob" if isinstance(store, BlobStore) else "memory" if isinstance(store, MemoryStore) else "none"

