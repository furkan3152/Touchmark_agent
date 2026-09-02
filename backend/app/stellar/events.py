"""RPC olaylarını kalıcı cursor ve tekilleştirme ile SQLite'a işler.

Stellar RPC olay geçmişi kalıcı bir indeks değildir. Bu sınıf, uygulamanın
işlediği cursor'u ve ham olayları yerel veritabanında saklar; yeniden başlatmada
aynı olayın iki kez uygulanmasını engeller.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from stellar_sdk import scval

from .rpc import StellarRpc


class StellarEventStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        self.path = path
        self._init_schema()
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS cursors (
                    stream TEXT PRIMARY KEY,
                    cursor TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    stream TEXT NOT NULL,
                    ledger INTEGER,
                    contract_id TEXT,
                    topic_json TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    observed_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_stream_ledger
                    ON events(stream, ledger);
                """
            )

    def cursor(self, stream: str) -> str:
        with self._connect() as db:
            row = db.execute("SELECT cursor FROM cursors WHERE stream = ?", (stream,)).fetchone()
        return str(row["cursor"]) if row else ""

    def ingest_page(
        self,
        stream: str,
        events: list[dict],
        cursor: str,
        allowed_contract_ids: set[str] | None = None,
    ) -> int:
        inserted = 0
        with self._connect() as db:
            for event in events:
                contract_id = str(event.get("contractId") or "")
                if allowed_contract_ids is not None and contract_id not in allowed_contract_ids:
                    continue
                if event.get("inSuccessfulContractCall") is not True:
                    continue
                if event.get("type") not in (None, "contract"):
                    continue
                event_id = str(event.get("id") or event.get("pagingToken") or "")
                if not event_id:
                    continue
                result = db.execute(
                    """
                    INSERT OR IGNORE INTO events(
                        event_id, stream, ledger, contract_id, topic_json,
                        value_json, raw_json, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        stream,
                        event.get("ledger"),
                        contract_id,
                        json.dumps(event.get("topic", []), sort_keys=True),
                        json.dumps(event.get("value", {}), sort_keys=True),
                        json.dumps(event, sort_keys=True),
                        time.time(),
                    ),
                )
                inserted += int(result.rowcount > 0)
            if cursor:
                db.execute(
                    """
                    INSERT INTO cursors(stream, cursor, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(stream) DO UPDATE SET
                        cursor=excluded.cursor, updated_at=excluded.updated_at
                    """,
                    (stream, cursor, time.time()),
                )
        return inserted

    def confirmed_responses(self, contract_id: str, limit: int = 20) -> list[dict]:
        """Başarılı registry `responded` eventlerini decode ederek döndürür."""
        if not contract_id:
            return []
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT event_id, ledger, raw_json FROM events
                WHERE contract_id = ? ORDER BY ledger DESC, event_id DESC LIMIT ?
                """,
                (contract_id, max(1, min(limit * 4, 400))),
            ).fetchall()
        out: list[dict] = []
        for row in rows:
            try:
                raw = json.loads(row["raw_json"])
                topics = [_decode_scval(value) for value in raw.get("topic", [])]
                if "responded" not in topics:
                    continue
                value = _decode_scval(raw.get("value"))
                out.append(
                    {
                        "event_id": row["event_id"],
                        "ledger": row["ledger"],
                        "tx_hash": str(raw.get("txHash") or ""),
                        "paging_token": str(raw.get("pagingToken") or ""),
                        "topics": _json_safe(topics),
                        "value": _json_safe(value),
                        "confirmed": True,
                    }
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if len(out) >= limit:
                break
        return out

    def find_response(
        self,
        contract_id: str,
        request_id: str,
        report_hash: str,
    ) -> dict | None:
        """Beklenen request ve report hash'ini aynı confirmed eventte arar."""
        request_id = request_id.removeprefix("0x").lower()
        report_hash = report_hash.removeprefix("0x").lower()
        for event in self.confirmed_responses(contract_id, limit=100):
            if not _contains_hex(event.get("topics"), request_id):
                continue
            if not _contains_hex(event.get("value"), report_hash):
                continue
            return event
        return None

    def status(self) -> dict:
        with self._connect() as db:
            events = db.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            cursors = db.execute("SELECT COUNT(*) AS n FROM cursors").fetchone()["n"]
        return {"database_configured": True, "events": events, "streams": cursors}


class StellarEventIngester:
    def __init__(self, rpc: StellarRpc, store: StellarEventStore) -> None:
        self.rpc = rpc
        self.store = store

    async def sync(self, stream: str, contract_ids: list[str], start_ledger: int) -> dict:
        cursor = self.store.cursor(stream)
        params: dict = {
            "startLedger": start_ledger,
            "filters": [{"type": "contract", "contractIds": contract_ids}],
            "pagination": {"limit": 100},
        }
        if cursor:
            params.pop("startLedger", None)
            params["pagination"]["cursor"] = cursor
        page = await self.rpc.get_events(params)
        events = page.get("events") or []
        candidate = page.get("cursor") or (events[-1].get("pagingToken") if events else "")
        next_cursor = str(candidate) if candidate else cursor
        inserted = self.store.ingest_page(stream, events, next_cursor, set(contract_ids))
        return {"received": len(events), "inserted": inserted, "cursor": next_cursor}


def _decode_scval(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return scval.to_native(value)
    except (ValueError, TypeError):
        return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(_json_safe(key)): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "address"):
        return str(value.address)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _contains_hex(value: Any, needle: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_hex(k, needle) or _contains_hex(v, needle) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_hex(item, needle) for item in value)
    return isinstance(value, str) and value.removeprefix("0x").lower() == needle
