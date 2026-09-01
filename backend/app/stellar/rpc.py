"""Salt-okunur Stellar RPC istemcisi; işlem imzalama veya yayınlama yapmaz."""

from __future__ import annotations

import itertools
from typing import Any

import httpx

from ..config import Settings


class StellarRpcError(RuntimeError):
    pass


class StellarRpc:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.url = settings.rpc_url
        self._ids = itertools.count(1)

    @property
    def available(self) -> bool:
        return bool(self.url)

    async def call(self, method: str, params: dict | None = None) -> Any:
        if not self.url:
            raise StellarRpcError("Stellar RPC kapalı")
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": method,
            "params": params or {},
        }
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                response = await client.post(self.url, json=payload)
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise StellarRpcError(f"RPC isteği başarısız: {exc}") from exc
        if data.get("error"):
            err = data["error"]
            raise StellarRpcError(f"RPC {method}: {err.get('code')} {err.get('message')}")
        if "result" not in data:
            raise StellarRpcError(f"RPC {method}: result yok")
        return data["result"]

    async def health(self) -> dict:
        if not self.available:
            return {"reachable": False, "error": "RPC kapalı"}
        try:
            health = await self.call("getHealth")
            ledger = await self.call("getLatestLedger")
            return {
                "reachable": health.get("status") == "healthy",
                "status": health.get("status"),
                "latest_ledger": ledger.get("sequence"),
                "protocol_version": ledger.get("protocolVersion"),
            }
        except StellarRpcError as exc:
            return {"reachable": False, "error": str(exc)}

    async def get_events(self, params: dict) -> dict:
        result = await self.call("getEvents", params)
        if not isinstance(result, dict):
            raise StellarRpcError("getEvents sözlük döndürmedi")
        return result

    async def get_transaction(self, tx_hash: str) -> dict:
        result = await self.call("getTransaction", {"hash": tx_hash})
        if not isinstance(result, dict):
            raise StellarRpcError("getTransaction sözlük döndürmedi")
        return result
