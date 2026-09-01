"""Stellar account/contract kimliği; kanıt yoksa mock kimlik üretmez."""

from __future__ import annotations

import httpx
from stellar_sdk.strkey import StrKey

from ..config import Settings
from ..models import OnchainActivity


def is_valid_stellar_address(value: str, *, account_only: bool = False) -> bool:
    """StrKey sürümü ve checksum'u dahil G/C adres doğrulaması."""
    try:
        if value.startswith("G"):
            StrKey.decode_ed25519_public_key(value)
            return True
        if not account_only and value.startswith("C"):
            StrKey.decode_contract(value)
            return True
    except (ValueError, TypeError):
        return False
    return False


class IdentityReader:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def resolve(self, address: str) -> dict:
        return {
            "source": "custom-soroban-registry" if self.settings.agent_registry_contract_id else "unresolved",
            "agent_uri": "",
            "card": {},
            "evidence": (
                "Registry contract configured; contract read adapter is not yet implemented."
                if self.settings.agent_registry_contract_id
                else "No registry contract configured."
            ),
        }

    async def onchain_activity(self, address: str) -> OnchainActivity:
        if not is_valid_stellar_address(address, account_only=True) or not self.settings.horizon_url:
            return OnchainActivity(address=address, data_source="none")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                response = await client.get(f"{self.settings.horizon_url}/accounts/{address}")
                response.raise_for_status()
                account = response.json()
        except (httpx.HTTPError, ValueError):
            return OnchainActivity(address=address, data_source="none")
        native = next(
            (b for b in account.get("balances", []) if b.get("asset_type") == "native"),
            {},
        )
        return OnchainActivity(
            address=address,
            data_source="horizon_account",
            balance_xlm=float(native.get("balance", 0) or 0),
            # Account sequence işlem sayısı değildir; davranış metriği uydurulmaz.
            tx_count=0,
        )
