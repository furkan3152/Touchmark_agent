"""What may stop a model review: money, never the clock.

A review reads the agent until every source file is read. The only things that end it early
are spend caps, measured from what Anthropic reports for each response (``usage``), not
estimated:

- per audit: the tokens the model processed (input, cache writes, cache reads and output),
  their cost at the configured prices, and the number of files the review may open;
- across the deployment: a daily token budget, claimed in chunks of ``CHUNK_TOKENS`` with the
  same create-only slots as the review allowance (services/rate_limit.py), so concurrent
  audits can never overspend it.

A model request still has a network timeout, because a hung provider call must not hang an
audit: a request that takes longer than ``call_timeout`` is abandoned and retried with backoff,
and only when every retry fails does the review stop, as unavailable, keeping its findings.

On serverless, one request ("leg") cannot hold a long review. The leg (``Leg``) tells the
reviewer and the verifier how long the current request may still start model calls; when it
runs out they save where they are and raise ``LegSuspended``, and the next request continues
from there (services/audit_jobs.py). The leg is a property of the request, not of the audit.
"""

from __future__ import annotations

import asyncio
import contextvars
import math
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields

#: Token fields of an Anthropic response's ``usage``, all counted towards the caps.
TOKEN_FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
#: The daily budget is claimed in chunks this large (one create-only slot each).
CHUNK_TOKENS = 1_000_000
#: A model call is started only with this much of the leg left; less would likely be cut off.
MIN_CALL_SECONDS = 45.0
#: Seconds kept between the end of a call's timeout and the end of the leg.
LEG_MARGIN_SECONDS = 5.0
#: What a first call is assumed to cost before any response has reported usage.
FIRST_CALL_ESTIMATE = 60_000

#: Why a review stopped before it read everything (shown in the report).
STOP_REASONS = {
    "token_cap": "the per-audit token cap",
    "cost_cap": "the per-audit cost cap",
    "file_cap": "the per-audit file cap",
    "daily_budget": "the deployment's daily token budget",
    "daily_budget_unavailable": "the daily token budget could not be checked",
}


class LegSuspended(Exception):
    """This request must stop now; the review's place is saved and the next leg continues.
    ``reason``: leg_time (the request is near its limit), client_gone, lease_lost."""

    def __init__(self, reason: str = "leg_time"):
        super().__init__(reason)
        self.reason = reason


class ReviewCancelled(Exception):
    """The visitor cancelled the audit; nothing more is spent."""


class ProviderUnavailable(Exception):
    """Every attempt at one model call failed (timeouts, overload, connection errors)."""


@dataclass
class Spend:
    """Measured usage of one audit, across every leg, reviewer and verifier together."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    #: Calls that returned usage, and calls cut off before a response arrived.
    calls: int = 0
    cut_calls: int = 0
    #: Tokens charged for cut-off calls (no usage came back): the input of the previous call.
    estimated_tokens: int = 0
    #: Daily-budget tokens this audit holds (claimed chunks).
    reserved_tokens: int = 0
    #: Consecutive failed attempts at the call in progress (kept across legs).
    failures: int = 0
    last_call_tokens: int = 0

    def tokens(self) -> int:
        return sum(getattr(self, k) for k in TOKEN_FIELDS) + self.estimated_tokens

    def cost(self, prices: dict) -> float:
        return round((self.input_tokens * prices["input"] + self.output_tokens * prices["output"]
                      + self.cache_creation_input_tokens * prices["cache_write"]
                      + self.cache_read_input_tokens * prices["cache_read"]
                      + self.estimated_tokens * prices["input"]) / 1_000_000, 4)

    def add(self, usage) -> int:
        counted = {k: int(getattr(usage, k, 0) or (usage.get(k, 0) if isinstance(usage, dict) else 0) or 0)
                   for k in TOKEN_FIELDS}
        for key, value in counted.items():
            setattr(self, key, getattr(self, key) + value)
        self.calls += 1
        total = sum(counted.values())
        self.last_call_tokens = total
        return total

    def charge_cut_call(self) -> None:
        """A call abandoned before it answered may still be billed: charge the input it sent."""
        self.cut_calls += 1
        self.estimated_tokens += self.last_call_tokens or FIRST_CALL_ESTIMATE

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict | None) -> "Spend":
        names = {f.name for f in fields(cls)}
        return cls(**{k: int(v) for k, v in (data or {}).items() if k in names})


class DailyTokenBudget:
    """The deployment-wide daily token budget, as create-only chunk slots in the allowance store:

        touchmark-limits/deep-review/20261101/tokens/0041

    An audit claims a chunk before its spend can pass what it already holds. Chunks are never
    given back (a crashed leg's chunk stays spent), so the budget can only be under-used."""

    def __init__(self, store, budget_tokens: int, clock=None) -> None:
        from datetime import datetime, timezone
        self.store, self.budget = store, max(0, int(budget_tokens))
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def chunks(self) -> int:
        return self.budget // CHUNK_TOKENS

    async def reserve(self, spend: Spend, need: int) -> str:
        """Hold at least ``need`` tokens. "" when held, else daily_budget(_unavailable)."""
        if self.store is None or spend.reserved_tokens >= need:
            return ""
        from .rate_limit import PREFIX, DeepReviewLimiter, StoreUnavailable
        limiter = DeepReviewLimiter(self.store, salt=b"daily-tokens", clock=self.clock)
        prefix = f"{PREFIX}/{self.clock().strftime('%Y%m%d')}/tokens/"
        try:
            while spend.reserved_tokens < need:
                if await limiter._claim_one(prefix, self.chunks) is None:
                    return "daily_budget"
                spend.reserved_tokens += CHUNK_TOKENS
        except StoreUnavailable:
            return "daily_budget_unavailable"
        return ""


def _transient(exc: BaseException) -> bool:
    """Errors worth retrying: timeouts, dropped connections, overload and server errors."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, ConnectionError)):
        return True
    try:
        import anthropic
    except ImportError:  # pragma: no cover - the reviewer is not built without the SDK
        return False
    if isinstance(exc, (anthropic.APITimeoutError, anthropic.APIConnectionError, anthropic.RateLimitError,
                        anthropic.InternalServerError)):
        return True
    return isinstance(exc, anthropic.APIStatusError) and getattr(exc, "status_code", 0) in (408, 409, 429, 500,
                                                                                           502, 503, 504, 529)


class Budget:
    """The caps and the per-call timeout/retry policy for one audit."""

    def __init__(self, *, max_tokens: int = 60_000_000, max_cost: float = 30.0, max_files: int = 400,
                 prices: dict | None = None, spend: Spend | None = None, daily: DailyTokenBudget | None = None,
                 call_timeout: float = 120.0, retries: int = 2, sleep=asyncio.sleep) -> None:
        self.max_tokens, self.max_cost, self.max_files = int(max_tokens), float(max_cost), int(max_files)
        self.prices = prices or {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.2}
        self.spend = spend or Spend()
        self.daily = daily
        self.call_timeout, self.retries = float(call_timeout), int(retries)
        self._sleep = sleep
        #: Set once a cap ends the review: later calls (the verifier) stop at once for the same reason.
        self.stopped = ""

    @classmethod
    def from_settings(cls, settings, *, spend: Spend | None = None, store=None) -> "Budget":
        daily = DailyTokenBudget(store, settings.deep_review_daily_token_budget) if store is not None else None
        return cls(max_tokens=settings.deep_review_max_tokens_per_audit,
                   max_cost=settings.deep_review_max_cost_usd_per_audit,
                   max_files=settings.deep_review_max_files_per_audit,
                   prices={"input": settings.deep_review_price_input_per_mtok,
                           "output": settings.deep_review_price_output_per_mtok,
                           "cache_write": settings.deep_review_price_cache_write_per_mtok,
                           "cache_read": settings.deep_review_price_cache_read_per_mtok},
                   spend=spend, daily=daily, call_timeout=settings.deep_review_call_timeout_seconds,
                   retries=settings.deep_review_call_retries)

    def caps(self) -> dict:
        return {"tokens": self.max_tokens, "cost_usd": self.max_cost, "files": self.max_files,
                "daily_tokens": self.daily.budget if self.daily is not None else None}

    def summary(self) -> dict:
        s = self.spend
        return {"tokens": s.tokens(), "input_tokens": s.input_tokens, "output_tokens": s.output_tokens,
                "cache_read_input_tokens": s.cache_read_input_tokens,
                "cache_creation_input_tokens": s.cache_creation_input_tokens,
                "estimated_tokens": s.estimated_tokens, "calls": s.calls, "cut_calls": s.cut_calls,
                "cost_usd": s.cost(self.prices), "caps": self.caps(), "stopped_by": self.stopped}

    def _estimate(self) -> int:
        return self.spend.last_call_tokens or FIRST_CALL_ESTIMATE

    async def admit(self, leg: "Leg | None") -> str:
        """Before each model call: the leg may stop the request (raises LegSuspended or
        ReviewCancelled); a cap ends the review (returns its reason). "" lets the call go."""
        if leg is not None:
            await leg.check()
            if leg.time_left() < MIN_CALL_SECONDS:
                raise LegSuspended("leg_time")
        if self.stopped:
            return self.stopped
        estimate = self._estimate()
        reason = ""
        if self.spend.tokens() + estimate > self.max_tokens:
            reason = "token_cap"
        elif self.spend.cost(self.prices) + estimate * self.prices["input"] / 1_000_000 > self.max_cost:
            reason = "cost_cap"
        elif self.daily is not None:
            reason = await self.daily.reserve(self.spend, self.spend.tokens() + estimate)
        self.stopped = reason
        return reason

    async def call(self, make, leg: "Leg | None" = None):
        """``make()`` returns the request coroutine. Retries transient failures; records usage."""
        while True:
            budget = self.call_timeout
            cut_by_leg = False
            if leg is not None and leg.deadline is not None:
                left = leg.time_left() - LEG_MARGIN_SECONDS
                if left < MIN_CALL_SECONDS - LEG_MARGIN_SECONDS:
                    raise LegSuspended("leg_time")
                if left < budget:
                    budget, cut_by_leg = left, True
            try:
                response = await asyncio.wait_for(make(), timeout=budget)
            except Exception as exc:  # noqa: BLE001 - sorted into retry, leg end or failure below
                if not _transient(exc):
                    raise
                timed_out = isinstance(exc, (asyncio.TimeoutError, TimeoutError))
                if timed_out:
                    self.spend.charge_cut_call()
                    if cut_by_leg:
                        raise LegSuspended("leg_time") from exc  # the leg ended, not the provider
                self.spend.failures += 1
                if self.spend.failures > self.retries:
                    self.spend.failures = 0
                    raise ProviderUnavailable(type(exc).__name__) from exc
                if leg is not None:
                    await leg.heartbeat()
                await self._sleep(min(2 ** self.spend.failures, 10))
                continue
            self.spend.failures = 0
            self.spend.add(getattr(response, "usage", None) or {})
            return response


@dataclass
class Leg:
    """The request an audit is running in. ``deadline`` is a time.monotonic() value by which
    model calls stop being started (None: no request limit, as in the CLI)."""
    budget: Budget
    deadline: float | None = None
    job: object | None = None  # audit_jobs.JobHandle: checkpoint(), cancel_requested(), heartbeat()
    abandoned: threading.Event = field(default_factory=threading.Event)
    review_state: dict | None = None
    verification_state: dict | None = None
    pin: dict = field(default_factory=dict)

    def time_left(self) -> float:
        return math.inf if self.deadline is None else self.deadline - time.monotonic()

    async def check(self) -> None:
        if self.abandoned.is_set():
            raise LegSuspended("client_gone")
        if self.job is not None and await self.job.cancel_requested():
            raise ReviewCancelled()

    async def checkpoint(self, **sections) -> None:
        if "review" in sections:
            self.review_state = sections["review"]
        if "verification" in sections:
            self.verification_state = sections["verification"]
        if self.job is not None:
            await self.job.checkpoint(spend=self.budget.spend.to_dict(), **sections)

    async def pin_source(self, revision: str, source_sha256: str, files: int) -> None:
        """The first leg records the exact source it reviews; every later leg must see the same
        bytes, or its saved review would describe other code (raises ValueError)."""
        current = {"revision": revision, "source_sha256": source_sha256, "files": files}
        if not self.pin:
            self.pin = current
            if self.job is not None:
                await self.job.checkpoint(pin=current, spend=self.budget.spend.to_dict())
            return
        if self.pin.get("source_sha256") != source_sha256 or self.pin.get("revision") != revision:
            raise ValueError("The repository's source differs from what the earlier part of this audit read, so "
                             "the audit cannot be continued. Run it again.")

    async def heartbeat(self) -> None:
        if self.job is not None:
            await self.job.heartbeat(spend=self.budget.spend.to_dict())


_leg: contextvars.ContextVar[Leg | None] = contextvars.ContextVar("touchmark_leg", default=None)


def current_leg() -> Leg | None:
    return _leg.get()


@contextmanager
def leg_scope(leg: Leg | None):
    token = _leg.set(leg)
    try:
        yield leg
    finally:
        _leg.reset(token)
