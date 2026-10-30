"""OFAC sanctions list scanner (no key needed).

Chainalysis / TRM / Elliptic require a commercial key. The US Treasury's OFAC
publishes the SDN list for free in machine-readable form, and the list contains
crypto addresses as `Digital Currency Address - ETH 0x…`. This module downloads
the list, extracts the crypto addresses and puts them in a local set; a match is
CONFIRMED evidence because it comes from the primary source.

OFAC lists only directly designated addresses and does no indirect exposure
analysis such as "2 hops from a mixer". No match means "not on the sanctions list",
not "clean"; the auditor reports it as a check of limited scope, not as `low` risk.

The list is ~5.6 MB and changes at most once a day. It is written with the extracted
addresses to `data/sanctions/ofac-sdn.json` and not downloaded again within
`max_age_hours`. Without a network the expired cache is still used (with a warning).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

#: OFAC's machine-readable SDN export (redirects with a 302 to a signed S3 URL).
SDN_CSV_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"

#: The `Digital Currency Address - ETH 0xabc…` pattern. Captures the chain code and address.
ADDRESS_RE = re.compile(
    r"Digital Currency Address\s*-\s*([A-Z0-9]{2,6})\s+([a-zA-Z0-9]{20,120})"
)

#: Chain codes that use hex addresses; used to normalise OFAC entries.
HEX_CHAINS = frozenset({"ETH", "USDT", "USDC", "ETC", "BNB", "ARB", "BSC"})

CACHE_NAME = "ofac-sdn.json"
DEFAULT_MAX_AGE_HOURS = 24.0


def normalise(address: str) -> str:
    """Normalise an address for lookup.

    Hex addresses (`0x…`, mixed-case checksum) are lower-cased; an upper-case `0X`
    prefix also counts as hex. Other chains (BTC/TRX/XMR/XLM) use base58 or base32,
    so they are case-sensitive and left untouched.
    """
    return address.lower() if address[:2].lower() == "0x" else address


def extract_addresses(csv_text: str) -> dict[str, list[str]]:
    """Extract a chain → address list from the SDN CSV text.

    Hex addresses are lower-cased (OFAC uses mixed-case checksums); other chains
    (BTC, TRX, XMR) are case-sensitive and kept as they are.
    """
    out: dict[str, set[str]] = {}
    for chain, address in ADDRESS_RE.findall(csv_text):
        key = chain.upper()
        value = normalise(address) if key in HEX_CHAINS else address
        out.setdefault(key, set()).add(value)
    return {k: sorted(v) for k, v in sorted(out.items())}


class OfacSanctionsList:
    """Download and cache the SDN list and look up addresses."""

    def __init__(self, data_dir: Path, max_age_hours: float = DEFAULT_MAX_AGE_HOURS) -> None:
        self.cache_path = Path(data_dir) / "sanctions" / CACHE_NAME
        self.max_age_hours = max_age_hours

    # ---------------------------------------------------------------- cache
    def load_cache(self) -> dict | None:
        if not self.cache_path.exists():
            return None
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def save_cache(self, payload: dict) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8"
        )

    def is_fresh(self, cache: dict | None) -> bool:
        if not cache:
            return False
        age_h = (time.time() - float(cache.get("fetched_at", 0))) / 3600.0
        return age_h < self.max_age_hours

    # ------------------------------------------------------------- download
    async def refresh(self, force: bool = False) -> dict:
        """Download the list if needed; always return usable data.

        On a network error it falls back to the expired cache and marks `stale=True`:
        screening with old data beats not screening, but it must be visible.
        """
        cache = self.load_cache()
        if not force and self.is_fresh(cache):
            return cache

        try:
            async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
                resp = await client.get(SDN_CSV_URL)
                resp.raise_for_status()
                csv_text = resp.text
        except Exception as exc:
            if cache:
                return {**cache, "stale": True, "error": str(exc)}
            raise

        chains = extract_addresses(csv_text)
        payload = {
            "source": SDN_CSV_URL,
            "publisher": "US Treasury OFAC (SDN)",
            "fetched_at": time.time(),
            "total_addresses": sum(len(v) for v in chains.values()),
            "chains": chains,
        }
        self.save_cache(payload)
        return payload

    # --------------------------------------------------------------- lookup
    def lookup_cached(self, address: str) -> dict:
        """Look the address up in the cache only; makes no network call.

        This is the version used on the audit path. Downloading 5.6 MB in the middle
        of an audit would block it for seconds and make the result depend on the
        network. Without a cache it returns `available=False` and the auditor reports
        a coverage gap.
        """
        cache = self.load_cache()
        if not cache:
            return {"available": False, "listed": False, "chains": []}

        chains: dict[str, list[str]] = cache.get("chains", {})
        needle = normalise(address)
        hits = [chain for chain, addresses in chains.items() if needle in addresses]

        return {
            "available": True,
            "listed": bool(hits),
            "chains": sorted(hits),
            "total_addresses": cache.get("total_addresses", 0),
            "fetched_at": cache.get("fetched_at"),
            "stale": not self.is_fresh(cache),
            "publisher": cache.get("publisher", "US Treasury OFAC (SDN)"),
        }
