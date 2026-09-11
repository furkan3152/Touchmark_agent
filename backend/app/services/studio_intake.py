"""Public, fixed-destination read-only intake. Never accepts signing credentials."""
from typing import Literal
import json
import re

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from stellar_sdk import Address, xdr

from ..stellar.identity import is_valid_stellar_address
from ..stellar.networks import NETWORKS


class GitHubRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository: str = Field(max_length=240)

    @field_validator("repository")
    @classmethod
    def github_only(cls, value: str) -> str:
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_-][A-Za-z0-9_.-]*/?", value):
            raise ValueError("Use a public repository URL: https://github.com/owner/repository")
        return value.rstrip("/").removesuffix(".git")


async def import_github_bundle(request: GitHubRequest) -> dict:
    from .studio import ReviewRequest
    path = request.repository.removeprefix("https://github.com/")
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, trust_env=False) as client:
        async with client.stream("GET", f"https://api.github.com/repos/{path}/contents/agent-audit.json", headers={
            "Accept": "application/vnd.github.raw+json", "User-Agent": "AgentVeritas-Stellar",
        }) as response:
            if response.status_code == 404:
                raise ValueError("No public agent-audit.json found at the repository root. Upload files instead or add the template to your repository.")
            if response.status_code != 200:
                raise ValueError("GitHub import unavailable or rate-limited. Upload your bundle directly.")
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 131072:
                    raise ValueError("GitHub bundle exceeds 128 KiB. Use a smaller bundle.")
    try:
        bundle = ReviewRequest.model_validate(json.loads(raw)).model_dump(mode="json")
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid agent-audit.json. Use the downloadable bundle template and respect the upload limits.") from exc
    return {"bundle": bundle, "source": request.repository, "executed": False}


class AddressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(min_length=56, max_length=56)
    network: Literal["testnet", "mainnet"] = "testnet"

    @field_validator("address")
    @classmethod
    def public_address(cls, value: str) -> str:
        if not is_valid_stellar_address(value):
            raise ValueError("Use a public G-account or C-contract address, never a secret key.")
        return value


async def identify_address(request: AddressRequest) -> dict:
    # Explicit public read-only networks, independent of operator signing config.
    net = NETWORKS[request.network]
    contract = request.address.startswith("C")
    result = {
        "address": request.address, "network": request.network,
        "kind": "contract" if contract else "account",
        "ledger_presence": "unavailable", "owner_verified": False,
        "agent_verified": False, "requires_source": True,
        "explorer_url": net.explorer_contract(request.address) if contract else net.explorer_account(request.address),
        "note": "An address identifies an account or contract, not an agent's behavior. Add source to audit it.",
    }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            if not contract:
                response = await client.get(f"{net.horizon_url}/accounts/{request.address}")
                if response.status_code == 404:
                    result["ledger_presence"] = "not_found"
                else:
                    response.raise_for_status()
                    data = response.json()
                    if data.get("account_id") == request.address:
                        result["ledger_presence"] = "found"
            else:
                key = xdr.LedgerKey(
                    xdr.LedgerEntryType.CONTRACT_DATA,
                    contract_data=xdr.LedgerKeyContractData(
                        Address(request.address).to_xdr_sc_address(),
                        xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
                        xdr.ContractDataDurability.PERSISTENT,
                    ),
                ).to_xdr()
                response = await client.post(net.rpc_url, json={
                    "jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries", "params": {"keys": [key]},
                })
                response.raise_for_status()
                payload = response.json()
                if not payload.get("error") and isinstance(payload.get("result", {}).get("entries"), list):
                    entries = payload["result"]["entries"]
                    if not entries:
                        result["ledger_presence"] = "not_found"
                    elif len(entries) == 1 and entries[0].get("key") == key:
                        entry = xdr.LedgerEntryData.from_xdr(entries[0]["xdr"])
                        if (entry.type == xdr.LedgerEntryType.CONTRACT_DATA
                            and entry.contract_data.contract == Address(request.address).to_xdr_sc_address()
                            and entry.contract_data.key.type == xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE
                            and entry.contract_data.val.type == xdr.SCValType.SCV_CONTRACT_INSTANCE):
                            result["ledger_presence"] = "found"
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        pass
    return result
