"""Opt-in enforcement SDK. Call authorize immediately before the real tool invocation.

The action is reserved atomically. Failed tools still consume their reservation.
The host must keep this database and approval key outside the agent's authority.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class RuntimePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    agent_id: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    network: Literal["testnet", "mainnet"] = "testnet"
    asset: str = Field(min_length=1, max_length=128)
    allowed_tools: list[str] = Field(max_length=30)
    allowed_destinations: list[str] = Field(max_length=50)
    max_per_action: int = Field(ge=0, le=2**63-1, strict=True)
    max_total: int = Field(ge=0, le=2**63-1, strict=True)
    max_depth: int = Field(default=1, ge=0, le=10)
    expires_at: int = Field(gt=0)
    require_approval: bool = True


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    nonce: str = Field(min_length=16, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    network: Literal["testnet", "mainnet"]
    tool: str = Field(min_length=1, max_length=100)
    asset: str = Field(min_length=1, max_length=128)
    destination: str = Field(min_length=1, max_length=128)
    amount: int = Field(ge=0, le=2**63-1, strict=True)
    depth: int = Field(default=0, ge=0, le=100)
    expires_at: int = Field(gt=0)


def digest(value: BaseModel) -> str:
    return hashlib.sha256(json.dumps(value.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def approval_token(policy: RuntimePolicy, action: Action, key: bytes) -> str:
    if len(key) < 32:
        raise ValueError("Use at least 32 bytes for the approval signing key.")
    return hmac.new(key, f"{digest(policy)}:{digest(action)}".encode(), hashlib.sha256).hexdigest()


def evaluate(policy: RuntimePolicy, action: Action, *, spent: int = 0, paused: bool = False, now: int | None = None) -> list[str]:
    now = int(time.time()) if now is None else now
    failures = []
    for failed, reason in [
        (paused, "emergency_stop"),
        (now >= policy.expires_at or now >= action.expires_at, "expired"),
        (action.expires_at > policy.expires_at, "action_outlives_policy"),
        (action.agent_id != policy.agent_id, "agent_mismatch"),
        (action.version != policy.version, "version_mismatch"),
        (action.network != policy.network, "network_mismatch"),
        (action.asset != policy.asset, "asset_mismatch"),
        (action.tool not in policy.allowed_tools, "tool_denied"),
        (action.destination not in policy.allowed_destinations, "destination_denied"),
        (action.amount > policy.max_per_action, "per_action_limit"),
        (spent + action.amount > policy.max_total, "cumulative_limit"),
        (action.depth > policy.max_depth, "delegation_depth"),
    ]:
        if failed:
            failures.append(reason)
    return failures


class PolicyGateway:
    def __init__(self, database: str | Path, approval_key: bytes):
        if len(approval_key) < 32:
            raise ValueError("Approval key must contain at least 32 bytes.")
        self.database, self.key = str(database), approval_key
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS reservations (
                    agent TEXT NOT NULL, nonce TEXT NOT NULL, amount INTEGER NOT NULL,
                    action_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
                    PRIMARY KEY(agent, nonce));
                CREATE TABLE IF NOT EXISTS stops (agent TEXT PRIMARY KEY, paused INTEGER NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=5, isolation_level="IMMEDIATE")
        try:
            with db:
                yield db
        finally:
            db.close()

    def pause(self, agent_id: str, paused: bool = True):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO stops VALUES (?, ?)", (agent_id, int(paused)))

    def authorize(self, policy: RuntimePolicy, action: Action, approval: str = "", *, now: int | None = None) -> dict:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Budget and replay scope is agent-wide: changing policy or source version
            # cannot silently reset spent funds or make an old nonce valid again.
            spent = db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE agent=?", (policy.agent_id,)).fetchone()[0]
            paused = db.execute("SELECT paused FROM stops WHERE agent=?", (policy.agent_id,)).fetchone()
            failures = evaluate(policy, action, spent=spent, paused=bool(paused and paused[0]), now=now)
            if policy.require_approval and not hmac.compare_digest(approval_token(policy, action, self.key), approval):
                failures.append("approval_missing_or_invalid")
            if db.execute("SELECT 1 FROM reservations WHERE agent=? AND nonce=?", (policy.agent_id, action.nonce)).fetchone():
                failures.append("replay")
            if failures:
                return {"allowed": False, "reasons": failures, "reserved": False}
            db.execute("INSERT INTO reservations VALUES (?,?,?,?,?)", (policy.agent_id, action.nonce, action.amount, digest(action), digest(policy)))
            return {"allowed": True, "reasons": [], "reserved": True, "action_hash": digest(action), "spent": spent + action.amount}
