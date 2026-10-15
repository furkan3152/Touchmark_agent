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


async def _github_json(client, endpoint: str, *, limit: int = 1_000_000, missing_ok: bool = False):
    async with client.stream("GET", "https://api.github.com/" + endpoint, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "AgentVeritas-Stellar",
    }) as response:
        if response.status_code == 404 and missing_ok:
            return None
        if response.status_code != 200:
            raise ValueError("GitHub is unavailable or rate-limited. Upload your project files instead.")
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            raw.extend(chunk)
            if len(raw) > limit:
                raise ValueError("Repository metadata exceeds the bounded import limit. Upload a focused project folder.")
    return json.loads(raw)


async def import_github_bundle(request: GitHubRequest) -> dict:
    """Resolve one commit, inspect its tree and fetch bounded blobs. No clone or execution."""
    import asyncio
    import base64
    from hashlib import sha1
    from pathlib import PurePosixPath
    from .discovery import discover_project, safe_source_path
    from .studio import ReviewRequest
    from .blueprint import parse_blueprint
    path = request.repository.removeprefix("https://github.com/")
    async with asyncio.timeout(25), httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        commit = await _github_json(client, f"repos/{path}/commits/HEAD")
        revision = commit.get("sha", "")
        if not re.fullmatch(r"[a-f0-9]{40}", revision):
            raise ValueError("GitHub did not return an immutable commit.")
        tree = await _github_json(client, f"repos/{path}/git/trees/{revision}?recursive=1")
        entries = tree.get("tree", [])
        declaration = next((x for x in entries if x.get('path') == 'veritas.json'), None)
        if declaration and (declaration.get('type') != 'blob' or declaration.get('mode') not in {'100644', '100755'}):
            raise ValueError('veritas.json must be a regular source file. Symbolic links are not followed.')
        candidates = [x for x in entries if x.get("type") == "blob" and x.get("mode") in {"100644", "100755"}
                      and safe_source_path(x.get("path", ""))]
        def rank(item):
            name = PurePosixPath(item["path"]).name
            priority = -1 if item['path'] == 'veritas.json' else 0 if name in {"package.json", "pyproject.toml", "requirements.txt"} else 1 if PurePosixPath(name).suffix in {".py", ".ts", ".js", ".mjs"} else 2
            return (priority, item["path"].count("/"), item["path"])
        files, omitted, omitted_reasons, total = {}, [], [], 0
        declared_paths = None
        for item in sorted(candidates, key=rank):
            name, size = item["path"], item.get("size", 0)
            if declared_paths is not None and name not in declared_paths:
                omitted.append(name)
                omitted_reasons.append({'file': name, 'reason': 'Outside declared Blueprint scope.'})
                continue
            if name == 'agent-audit.json':
                # A bundle is a useful upload format, but never substitutes its embedded
                # source for the actual repository contents at this commit.
                omitted.append(name)
                continue
            if len(files) >= 12 or size > 32000 or total + size > 64000:
                omitted.append(name)
                continue
            blob_id = item.get("sha", "")
            if not re.fullmatch(r"[a-f0-9]{40}", blob_id):
                raise ValueError("Invalid repository blob reference.")
            blob = await _github_json(client, f"repos/{path}/git/blobs/{blob_id}", limit=60000)
            if blob.get("encoding") != "base64":
                omitted.append(name)
                continue
            raw = base64.b64decode(re.sub(r"\s+", "", blob.get("content", "")), validate=True)
            if len(raw) != size or sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() != blob_id:
                raise ValueError("GitHub blob integrity check failed.")
            try:
                content = raw.decode('utf-8')
            except UnicodeError:
                omitted.append(name)
                continue
            try:
                ReviewRequest(name='Repository source', purpose='Inspect the selected repository source.',
                              files={**files, name: content})
            except ValueError:
                omitted.append(name)
                omitted_reasons.append({'file': name, 'reason': 'Source syntax, path or cumulative analysis complexity limit.'})
                continue
            files[name] = content
            total += len(raw)
            if name == 'veritas.json':
                try:
                    declared_paths = {c.path for c in parse_blueprint(content).components}
                except ValueError:
                    # Keep invalid evidence visible; discovery blocks execution.
                    declared_paths = set()
        if any(x['path'] == 'veritas.json' for x in candidates) and 'veritas.json' not in files:
            raise ValueError('Repository Blueprint could not be imported within the source limits. Upload a smaller, valid veritas.json; automatic fallback is disabled.')
    if not files:
        raise ValueError("No supported source files were found. Upload a focused source folder.")
    discovery = discover_project(files)
    manifest = discovery['blueprint'].get('manifest', {})
    bundle = ReviewRequest(name=manifest.get('name', path.split('/')[-1][:100]),
        purpose=manifest.get('purpose', "Review this project's actual agent behavior and security boundaries."),
        files=files, dependencies=discovery['dependencies'], source_reference=request.repository,
        source_revision=revision).model_dump(mode="json")
    return {"bundle": bundle, "source": request.repository, "revision": revision,
            "discovery": discovery, "executed": False,
            "import_scope": {"complete": not omitted and not tree.get('truncated') and len(files) == len(entries),
                "tree_truncated": bool(tree.get('truncated')), "files_imported": len(files),
                "selection": "blueprint" if declared_paths is not None else "provisional_discovery",
                "declared_scope_complete": bool(declared_paths) and declared_paths.issubset(files) if declared_paths is not None else None,
                "eligible_files_omitted": len(omitted), "omitted_paths": omitted[:50], "omitted_reasons": omitted_reasons[:50],
                "note": "Bounded source selection, not the entire repository. Hidden files, credentials, symlinks, binaries and dependencies are excluded."}}


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
