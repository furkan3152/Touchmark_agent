"""On-chain authority facts for an agent account, read from Horizon.

On Stellar, who can move funds is public: signers, weights and thresholds live on
the ledger. That lets an audit verify an agent's real blast radius instead of
trusting its code or its documentation:

* whether the agent key alone can pay (medium threshold) or administer the account
  (high threshold), or needs a co-signer, which is an enforced, on-chain control;
* trustline limits and issuer exposure;
* SEP-29 `config.memo_required` on payment destinations hard-coded in source, where a
  payment without a memo is lost;
* the SEP-1 identity binding: the account listed in its home domain's stellar.toml.

Reads are GET requests with fixed hosts (Horizon) and, for SEP-1, the home domain
after the SSRF guard. Only public addresses leave the server; never source code.
"""

from __future__ import annotations

import asyncio
import base64
import re
import tomllib

import httpx
from stellar_sdk import StrKey

from ..ingestion.guards import guard_remote_url
from .networks import NETWORKS

MAX_LIMIT = "922337203685.4775807"
_G_ADDRESS = re.compile(r"\bG[A-Z2-7]{55}\b")
#: Files whose addresses are not payment destinations: tests, smoke scripts, fixtures, mocks
#: and deny/block lists (addresses the agent must *refuse* to pay).
_NON_DESTINATION_FILE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|mocks?|examples?|e2e)(?:/|$)|"
    r"(?:test|spec|smoke|fixture|mock|example)[^/]*\.\w+$|(?:black|deny|block)[-_]?list", re.I)
_DENY_CONTEXT = re.compile(r"black[-_ ]?list|deny[-_ ]?list|block[-_ ]?list|sanction|scam|blocked|"
                           r"e\.g\.|example|usage|new Error\(|raise \w*Error\(", re.I)
#: CODE:ISSUER asset notation names an issuer, not a payment destination.
_ASSET_ISSUER = re.compile(r"\b[A-Za-z0-9]{1,12}:(G[A-Z2-7]{55})\b|"
                           r"Asset\(\s*[\"'][A-Za-z0-9]{1,12}[\"']\s*,\s*[\"'](G[A-Z2-7]{55})[\"']")
_PUBLIC_MARKERS = re.compile(r"Public Global Stellar Network|PUBLIC_NETWORK_PASSPHRASE|Networks\.PUBLIC|"
                             r"\bpubnet\b|\bmainnet\b|horizon\.stellar\.org", re.I)
_TESTNET_MARKERS = re.compile(r"Test SDF Network|TESTNET_NETWORK_PASSPHRASE|Networks\.TESTNET|\btestnet\b", re.I)


def code_networks(code_files: dict[str, str]) -> set[str]:
    """Networks the code refers to (mainnet / testnet), from passphrases, constants and hosts."""
    found: set[str] = set()
    for text in code_files.values():
        if _PUBLIC_MARKERS.search(text):
            found.add("mainnet")
        if _TESTNET_MARKERS.search(text):
            found.add("testnet")
    return found


_MEMO_CALL = re.compile(r"\.(?:add_text_memo|add_id_memo|add_hash_memo|add_return_hash_memo|add_memo)\s*\(|Memo\w*\(")


def _account_view(account: dict, agent_key: str = "") -> dict:
    thresholds = account.get("thresholds", {})
    low, med, high = (int(thresholds.get(k, 0)) for k in ("low_threshold", "med_threshold", "high_threshold"))
    signers = [{"key": s.get("key"), "weight": int(s.get("weight", 0)), "type": s.get("type")}
               for s in account.get("signers", []) if int(s.get("weight", 0)) > 0]
    need_pay, need_admin = max(med, 1), max(high, 1)
    flags = account.get("flags", {})
    trustlines = [b for b in account.get("balances", []) if b.get("asset_type") != "native"]
    data = account.get("data", {})
    view = {
        "status": "found",
        "address": account.get("account_id"),
        "thresholds": {"low": low, "medium": med, "high": high},
        "signers": signers,
        "single_key_can_pay": any(s["weight"] >= need_pay for s in signers),
        "single_key_can_administer": any(s["weight"] >= need_admin for s in signers),
        "multisig_required_for_payments": not any(s["weight"] >= need_pay for s in signers),
        "flags": {k: bool(flags.get(k)) for k in ("auth_required", "auth_revocable", "auth_immutable", "auth_clawback_enabled")},
        "home_domain": account.get("home_domain") or "",
        "memo_required": data.get("config.memo_required") == base64.b64encode(b"1").decode(),
        "trustlines": [{"asset": f"{b.get('asset_code')}:{b.get('asset_issuer')}", "limit": b.get("limit"),
                        "unlimited": b.get("limit") == MAX_LIMIT, "authorized": b.get("is_authorized", True)}
                       for b in trustlines],
        "native_balance": next((b.get("balance") for b in account.get("balances", [])
                                if b.get("asset_type") == "native"), "0"),
    }
    if agent_key:
        weight = next((s["weight"] for s in signers if s["key"] == agent_key), 0)
        view["agent_key"] = {"key": agent_key, "weight": weight, "is_signer": weight > 0,
                             "can_pay_alone": weight >= need_pay, "can_administer_alone": weight >= need_admin}
    return view


class AuthorityReader:
    def __init__(self, network: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 8.0):
        profile = NETWORKS.get(network)
        if not profile or not profile.horizon_url:
            raise ValueError("On-chain verification needs testnet or mainnet.")
        self.horizon, self.network = profile.horizon_url, network
        self.transport, self.timeout = transport, timeout

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, transport=self.transport,
                                 headers={"Accept": "application/json"})

    async def account(self, client: httpx.AsyncClient, address: str) -> dict | None:
        response = await client.get(f"{self.horizon}/accounts/{address}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    async def stellar_toml(self, client: httpx.AsyncClient, domain: str) -> dict:
        url = guard_remote_url(f"https://{domain}/.well-known/stellar.toml")
        async with client.stream("GET", url) as response:
            if response.status_code != 200:
                return {"status": f"http_{response.status_code}"}
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 65_536:
                    return {"status": "too_large"}
        try:
            return {"status": "found", "toml": tomllib.loads(body.decode("utf-8"))}
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return {"status": "invalid"}

    async def collect(self, address: str = "", *, agent_key: str = "", code_files: dict[str, str] | None = None,
                      fetch_toml: bool = True) -> dict:
        facts: dict = {"network": self.network, "source": "horizon", "account": {"status": "not_supplied"},
                       "destinations": []}
        async with await self._client() as client:
            if address and StrKey.is_valid_ed25519_public_key(address):
                try:
                    account = await self.account(client, address)
                    facts["account"] = _account_view(account, agent_key) if account else {"status": "not_found", "address": address}
                except (httpx.HTTPError, ValueError):
                    facts["account"] = {"status": "unavailable", "address": address}
                domain = facts["account"].get("home_domain")
                if fetch_toml and domain:
                    try:
                        toml = await self.stellar_toml(client, domain)
                    except (httpx.HTTPError, ValueError):
                        toml = {"status": "unavailable"}
                    listed = toml.get("toml", {}).get("ACCOUNTS", []) if toml.get("status") == "found" else []
                    facts["sep1"] = {"domain": domain, "status": toml["status"],
                                     "account_listed": address in listed if isinstance(listed, list) else False}
            networks = code_networks(code_files or {})
            facts["code_networks"] = sorted(networks)
            if networks and self.network not in networks:
                # Checking pubnet destinations on testnet (or the reverse) reports false absences.
                facts["destinations_skipped"] = (f"code targets {', '.join(sorted(networks))}; "
                                                 f"destinations are not checked on {self.network}")
            else:
                facts["destinations"] = await self._destinations(client, code_files or {}, exclude=address)
        return facts

    async def _destinations(self, client, code_files: dict[str, str], *, exclude: str) -> list[dict]:
        """Hard-coded payment destinations: do they exist, and do they require a memo (SEP-29)?"""
        found: dict[str, str] = {}
        for path, text in sorted(code_files.items()):
            if _NON_DESTINATION_FILE.search(path):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if _DENY_CONTEXT.search(line):
                    continue
                issuers = {a or b for a, b in _ASSET_ISSUER.findall(line)}
                for match in _G_ADDRESS.findall(line):
                    if match in issuers:
                        continue
                    if match != exclude and StrKey.is_valid_ed25519_public_key(match):
                        found.setdefault(match, f"{path}:{number}")
        uses_memo = any(_MEMO_CALL.search(text) for text in code_files.values())
        results = []

        async def check(address: str, where: str) -> dict:
            try:
                account = await self.account(client, address)
            except (httpx.HTTPError, ValueError):
                return {"address": address, "location": where, "status": "unavailable"}
            if account is None:
                return {"address": address, "location": where, "status": "not_found"}
            view = _account_view(account)
            return {"address": address, "location": where, "status": "found",
                    "memo_required": view["memo_required"], "code_attaches_memo": uses_memo}

        for item in await asyncio.gather(*(check(a, w) for a, w in list(found.items())[:10])):
            results.append(item)
        return results


#: Committed seeds whose accounts are looked up, at most.
MAX_SEED_KEYS = 20


async def seed_exposure(public_keys: list[str], *, transport: httpx.AsyncBaseTransport | None = None,
                        timeout: float = 8.0) -> dict:
    """What a committed secret seed controls, by the public key derived from it in process.

    For each key, on mainnet and on testnet: whether its account exists and holds a balance,
    and how many other accounts list it as a signer (Horizon ``/accounts?signer=``). Only the
    G... public key is sent. Testnet is reset from time to time, so a key absent there may
    have held testnet funds before."""
    from datetime import datetime, timezone
    keys = [k for k in dict.fromkeys(public_keys) if StrKey.is_valid_ed25519_public_key(k)][:MAX_SEED_KEYS]
    out: dict = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "keys": {}}
    for network in ("mainnet", "testnet"):
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport,
                                     headers={"Accept": "application/json"}) as client:
            for key in keys:
                out["keys"].setdefault(key, {})[network] = await _key_exposure(client, NETWORKS[network].horizon_url, key)
    return out


async def _key_exposure(client: httpx.AsyncClient, horizon: str, key: str) -> dict:
    try:
        response = await client.get(f"{horizon}/accounts/{key}")
        own = None if response.status_code == 404 else response.raise_for_status().json()
        response = await client.get(f"{horizon}/accounts", params={"signer": key, "limit": 200})
        records = response.raise_for_status().json().get("_embedded", {}).get("records", [])
    except (httpx.HTTPError, ValueError, AttributeError):
        return {"status": "unavailable"}
    signs_for = [r.get("account_id") for r in records if r.get("account_id") != key]
    return {"status": "found" if own is not None or signs_for else "not_found",
            "exists": own is not None,
            "balances": [{"asset": "XLM" if b.get("asset_type") == "native" else f"{b.get('asset_code')}:{b.get('asset_issuer')}",
                          "balance": b.get("balance")} for b in (own or {}).get("balances", [])][:10],
            "signs_for": len(signs_for)}
