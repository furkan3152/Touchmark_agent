"""Resolve any agent reference to the evidence behind it, then audit what was found.

An agent can be handed to us as:

  * a registry agent id (64 hex)  -> AgentVeritas AgentRegistry record on Soroban
  * a C... contract address        -> the deployed WASM, its spec and SEP-46 metadata
  * a G... account                 -> ledger authority (signers, thresholds, home domain)
  * a GitHub URL (optionally pinned to a commit)
  * an agent card URL (.json) or an endpoint URL

Each step records what was *proven* and how: a card is trusted only if its bytes
hash to the registry's meta_hash; an endpoint only if it hashes to end_hash; a
contract's source only if a GitHub build attestation names the same WASM hash.
Anything weaker is reported as declared, not proven, and the audit says so.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import httpx
from stellar_sdk import StrKey

from ..config import Settings
from ..ingestion.guards import guard_remote_url
from ..stellar.soroban_reader import READ_ERRORS, LedgerUnavailable, SorobanReader

MAX_CARD_BYTES = 256_000
MAX_ARCHIVE_BYTES = 60_000_000
MAX_EXTRACTED_BYTES = 200_000_000
_GITHUB = re.compile(r"^(?:https://github\.com/|github:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?"
                     r"(?:/(?:tree|commit|blob)/([A-Za-z0-9_./-]+))?/?$")
_SHA = re.compile(r"^[a-f0-9]{40}$")


def classify(reference: str) -> str:
    ref = reference.strip()
    if re.fullmatch(r"(?:0x)?[a-fA-F0-9]{64}", ref):
        return "registry_agent"
    if StrKey.is_valid_contract(ref):
        return "contract"
    if StrKey.is_valid_ed25519_public_key(ref):
        return "account"
    if _GITHUB.match(ref):
        return "repository"
    if ref.startswith("ipfs://") or re.match(r"^https://", ref) and (ref.endswith(".json") or "/.well-known/" in ref):
        return "card"
    if ref.startswith("https://"):
        return "endpoint"
    raise ValueError("Unrecognised agent reference: use an agent id, a G.../C... address, a GitHub URL, "
                     "an agent card URL or an https endpoint.")


def parse_github(url: str) -> tuple[str, str, str]:
    m = _GITHUB.match(url.strip())
    if not m:
        raise ValueError("not a GitHub repository reference")
    owner, repo, ref = m.group(1), m.group(2), (m.group(3) or "")
    return owner, repo, ref.split("/")[0] if ref else ""


def github_subpath(url: str) -> str:
    """The folder a `/tree/<ref>/<path>` link points at ("" for the repository root)."""
    m = _GITHUB.match(url.strip())
    parts = (m.group(3) or "").split("/")[1:] if m else []
    if any(p in {"", ".", ".."} for p in parts):
        return ""
    return "/".join(parts)


def _card_fields(card: dict) -> dict:
    """Pull source, endpoint and wallet out of the common agent-card shapes."""
    source = card.get("source") if isinstance(card.get("source"), dict) else {}
    repo = (source.get("repository") or source.get("repo") or source.get("url") or card.get("repository")
            or card.get("source_repo") or card.get("code") or "")
    commit = source.get("commit") or source.get("revision") or card.get("commit") or card.get("revision") or ""
    endpoint = card.get("endpoint") or card.get("url") or ""
    wallet = card.get("wallet") or card.get("stellar_address") or card.get("agentWallet") or ""
    for item in card.get("endpoints") or card.get("services") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("type") or "").lower()
        value = str(item.get("endpoint") or item.get("url") or "")
        if not endpoint and name in {"a2a", "mcp", "http", "https", "api"} and value.startswith("https://"):
            endpoint = value
        if not wallet and ("wallet" in name or value.startswith("stellar:")):
            candidate = value.rsplit(":", 1)[-1]
            if StrKey.is_valid_ed25519_public_key(candidate) or StrKey.is_valid_contract(candidate):
                wallet = candidate
    return {"name": str(card.get("name", ""))[:100], "description": str(card.get("description", ""))[:2000],
            "repository": str(repo), "commit": str(commit), "endpoint": str(endpoint), "wallet": str(wallet),
            "skills": [str(s.get("name", s) if isinstance(s, dict) else s)[:80] for s in (card.get("skills") or [])][:30]}


class AgentResolver:
    def __init__(self, settings: Settings, network: str = "testnet", *,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.settings, self.network, self._transport = settings, network, transport
        self.reader = SorobanReader(network, transport=transport)

    async def _get(self, url: str, *, limit: int, headers: dict | None = None) -> bytes:
        if not url.startswith(("https://api.github.com/", "https://codeload.github.com/")):
            url = guard_remote_url(url)
        async with httpx.AsyncClient(timeout=30, follow_redirects=False, transport=self._transport) as client:
            async with client.stream("GET", url, headers=headers or {"User-Agent": "AgentVeritas-Stellar"}) as response:
                if response.status_code != 200:
                    raise ValueError(f"HTTP {response.status_code}")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise ValueError("response exceeds the size limit")
        return bytes(body)

    async def _fetch_card(self, uri: str) -> bytes:
        if uri.startswith("ipfs://"):
            uri = f"{self.settings.ipfs_gateway.rstrip('/')}/{uri[7:]}"
        if not uri.startswith("https://"):
            raise ValueError("card URI is not fetchable over https or ipfs")
        return await self._get(uri, limit=MAX_CARD_BYTES)

    async def build_attestation(self, owner: str, repo: str, wasm_hash: str) -> dict:
        """GitHub artifact attestation for this exact WASM hash, if the build published one."""
        try:
            raw = await self._get(f"https://api.github.com/repos/{owner}/{repo}/attestations/sha256:{wasm_hash}",
                                  limit=2_000_000, headers={"Accept": "application/vnd.github+json",
                                                            "User-Agent": "AgentVeritas-Stellar"})
        except (ValueError, httpx.HTTPError) as exc:
            return {"status": "not_found", "detail": str(exc)[:120]}
        try:
            for item in json.loads(raw).get("attestations", []):
                envelope = item.get("bundle", {}).get("dsseEnvelope", {})
                statement = json.loads(base64.b64decode(envelope.get("payload", "")))
                subjects = [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]
                if wasm_hash not in subjects:
                    continue
                deps = statement.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
                commit = next((d.get("digest", {}).get("gitCommit") for d in deps if d.get("digest", {}).get("gitCommit")), "")
                workflow = statement.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {}).get("workflow", {})
                return {"status": "attested", "commit": commit, "workflow": workflow.get("path", ""),
                        "repository": workflow.get("repository", f"https://github.com/{owner}/{repo}")}
        except (ValueError, TypeError, AttributeError):
            return {"status": "unreadable"}
        return {"status": "not_found"}

    async def resolve(self, reference: str) -> dict:
        kind = classify(reference)
        ref = reference.strip().removeprefix("0x").lower() if kind == "registry_agent" else reference.strip()
        out: dict = {"reference": reference.strip(), "kind": kind, "network": self.network, "steps": [],
                     "source": {"repository": "", "revision": "", "binding": "none", "verified": False},
                     "wallet": "", "contract": None, "registry": None, "card": None, "endpoint": "",
                     "endpoint_bound": False}

        def step(check: str, result: str, evidence: str = "") -> None:
            out["steps"].append({"check": check, "result": result, "evidence": evidence[:400]})

        card_bytes: bytes | None = None
        if kind == "registry_agent":
            registry = self.settings.agent_registry_contract_id
            if not registry:
                step("registry", "unavailable", "No AgentRegistry contract is configured for this deployment.")
                return out
            try:
                record = await self.reader.registry_agent(registry, ref)
            except LedgerUnavailable as exc:
                step("registry", "unavailable", str(exc))
                return out
            out["registry"] = record
            if record["status"] != "found":
                step("registry", "not_found", f"No agent {ref} in registry {registry}.")
                return out
            step("registry", "found", f"owner {record['owner']}, version {record['version']}, active={record['active']}")
            if not record["active"]:
                step("registry_active", "inactive", "The owner deactivated this agent.")
            try:
                card_bytes = await self._fetch_card(record["meta_uri"])
            except (ValueError, httpx.HTTPError) as exc:
                step("card", "unavailable", f"{record['meta_uri']}: {exc}")
            if card_bytes is not None:
                digest = hashlib.sha256(card_bytes).hexdigest()
                if digest != record["meta_hash"]:
                    step("card_hash", "mismatch", f"card sha256 {digest} != registry meta_hash {record['meta_hash']}")
                    card_bytes = None  # never use a card the registry does not commit to
                else:
                    step("card_hash", "verified", f"sha256 {digest} matches the registry record")
        elif kind == "card":
            try:
                card_bytes = await self._fetch_card(ref)
                step("card", "fetched", f"sha256 {hashlib.sha256(card_bytes).hexdigest()} (not bound to any registry record)")
            except (ValueError, httpx.HTTPError) as exc:
                step("card", "unavailable", str(exc))
        if card_bytes is not None:
            try:
                card = json.loads(card_bytes)
                fields = _card_fields(card if isinstance(card, dict) else {})
            except ValueError:
                fields = None
                step("card_parse", "invalid", "the card is not JSON")
            if fields:
                out["card"] = fields
                bound = kind == "registry_agent"
                if fields["repository"]:
                    out["source"].update(repository=fields["repository"], revision=fields["commit"],
                                         binding="registry_card" if bound else "unbound_card",
                                         verified=bound and bool(_SHA.match(fields["commit"])))
                if fields["wallet"]:
                    out["wallet"] = fields["wallet"]
                if fields["endpoint"]:
                    out["endpoint"] = fields["endpoint"]
                    if bound:
                        e_hash = hashlib.sha256(fields["endpoint"].encode()).hexdigest()
                        out["endpoint_bound"] = e_hash == out["registry"]["end_hash"]
                        step("endpoint_hash", "verified" if out["endpoint_bound"] else "mismatch",
                             f"sha256(endpoint) {'matches' if out['endpoint_bound'] else 'differs from'} registry end_hash")
        if kind == "contract" or (out["wallet"] and StrKey.is_valid_contract(out["wallet"])):
            contract_id = ref if kind == "contract" else out["wallet"]
            try:
                facts = await self.reader.contract(contract_id)
            except LedgerUnavailable as exc:
                step("contract", "unavailable", str(exc))
                facts = None
            except READ_ERRORS as exc:
                # An executable or entry this reader cannot decode is reported, never a server error.
                error = f"{type(exc).__name__}: {exc}"[:200]
                step("contract", "unreadable", error)
                facts = {"status": "unreadable", "contract_id": contract_id, "network": self.network, "error": error}
            if facts:
                out["contract"] = facts
                ref = facts.get("external_ref") or {}
                if ref:
                    step("executable_ref", ref.get("status", ""),
                         f"owner {ref.get('owner')}, tag {ref.get('tag')!r}, wasm {ref.get('resolved_wasm_hash', '-')}")
                if facts["status"] == "not_found":
                    step("contract", "not_found", contract_id)
                elif facts.get("executable") == "stellar_asset":
                    step("contract", "stellar_asset", "a Stellar Asset Contract (token), not agent code")
                elif facts.get("executable") == "unknown":
                    step("contract", "unknown_executable", "the executable type is not one this reader knows")
                elif facts.get("wasm_hash"):
                    step("contract_code", "verified" if facts.get("wasm_hash_verified") else facts.get("code", "unverified"),
                         f"wasm {facts.get('wasm_hash')}, "
                         f"{len(facts.get('functions', [])) + facts.get('functions_omitted', 0)} functions")
                    graph = (facts.get("profile") or {}).get("callgraph") or {}
                    if facts.get("profile_error") or graph.get("status") == "undecoded":
                        step("contract_callgraph", "undecoded", facts.get("profile_error") or graph.get("error", ""))
                    declared = facts.get("meta", {}).get("source_repo", "")
                    if declared and not out["source"]["repository"]:
                        try:
                            owner, repo, rev = parse_github(declared)
                        except ValueError:
                            step("source_repo", "unrecognised", declared)
                        else:
                            att = await self.build_attestation(owner, repo, facts["wasm_hash"])
                            if att.get("status") == "attested" and _SHA.match(att.get("commit", "")):
                                out["source"].update(repository=f"https://github.com/{owner}/{repo}", revision=att["commit"],
                                                     binding="attested_build", verified=True)
                                step("build_attestation", "verified",
                                     f"GitHub attestation: wasm {facts['wasm_hash'][:12]}… built from {att['commit'][:12]} by {att.get('workflow')}")
                            else:
                                out["source"].update(repository=f"https://github.com/{owner}/{repo}", revision=rev,
                                                     binding="wasm_metadata", verified=False)
                                step("build_attestation", "missing",
                                     "source_repo is declared in WASM metadata, but no build attestation ties this WASM to a commit")
        if kind == "account" or (out["wallet"] and StrKey.is_valid_ed25519_public_key(out["wallet"])):
            account_id = ref if kind == "account" else out["wallet"]
            out["wallet"] = account_id
            from ..stellar.authority import AuthorityReader, _account_view
            reader = AuthorityReader(self.network, transport=self._transport)
            try:
                async with await reader._client() as client:
                    raw = await reader.account(client, account_id)
            except (httpx.HTTPError, ValueError) as exc:
                step("account", "unavailable", str(exc))
            else:
                if raw is None:
                    step("account", "not_found", f"{account_id} does not exist on {self.network}")
                else:
                    view = _account_view(raw)
                    out["account"] = {k: view.get(k) for k in ("home_domain", "thresholds", "signers", "memo_required")}
                    step("account", "found", f"{len(view.get('signers', []))} signer(s), thresholds {view.get('thresholds')}, "
                                             f"home_domain={view.get('home_domain') or 'none'}")
        if kind == "repository":
            owner, repo, rev = parse_github(ref)
            out["source"].update(repository=f"https://github.com/{owner}/{repo}", revision=rev,
                                 binding="user_supplied", verified=False)
            if github_subpath(ref):
                out["source"]["path"] = github_subpath(ref)
        if kind == "endpoint":
            out["endpoint"] = ref
        if out["source"]["repository"] and not _SHA.match(out["source"]["revision"] or ""):
            pinned = await self._pin_commit(out["source"]["repository"], out["source"]["revision"])
            if pinned:
                step("source_pin", "pinned", f"{out['source']['revision'] or 'default branch'} -> {pinned}")
                out["source"]["revision"] = pinned
                if out["source"]["binding"] == "registry_card":
                    out["source"]["verified"] = False  # the card named a branch, not a commit
        return out

    async def _pin_commit(self, repository: str, ref: str) -> str:
        """Resolve a branch, tag or HEAD to a commit with git's smart-HTTP ref list (no API, no rate limit)."""
        try:
            owner, repo, _ = parse_github(repository)
            raw = await self._get(f"https://github.com/{owner}/{repo}.git/info/refs?service=git-upload-pack",
                                  limit=5_000_000, headers={"User-Agent": "git/2.43.0"})
        except (ValueError, httpx.HTTPError):
            return ""
        wanted = {"HEAD"} if not ref else {f"refs/heads/{ref}", f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}"}
        found: dict[str, str] = {}
        offset = 0
        while offset + 4 <= len(raw):  # pkt-line: 4 hex digits of length, 0000 = flush
            try:
                length = int(raw[offset:offset + 4], 16)
            except ValueError:
                break
            if length == 0:
                offset += 4
                continue
            body = raw[offset + 4:offset + length].decode("utf-8", "replace").rstrip("\n")
            offset += length
            parts = body.split("\x00")[0].split(" ")
            if len(parts) == 2 and _SHA.match(parts[0]):
                found[parts[1]] = parts[0]
        for name in (f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}", f"refs/tags/{ref}", "HEAD"):
            if name in wanted and name in found:
                return found[name]
        return ""

    async def download(self, repository: str, revision: str, into: Path) -> Path:
        """Fetch one commit and extract it safely (no symlinks, bounded size).

        codeload.github.com serves the commit as a zip; where it is unavailable, a shallow
        `git fetch` of that single commit is used. Neither runs any repository code.
        """
        owner, repo, _ = parse_github(repository)
        if not _SHA.match(revision):
            raise ValueError("source must be pinned to a commit")
        try:
            data = await self._get(f"https://codeload.github.com/{owner}/{repo}/zip/{revision}", limit=MAX_ARCHIVE_BYTES)
        except (ValueError, httpx.HTTPError):
            return await self._git_fetch(owner, repo, revision, into)
        total = 0
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                path = PurePosixPath(info.filename)
                if info.is_dir() or path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
                    continue
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue  # symlink
                total += info.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise ValueError("repository exceeds the extraction limit")
                target = into.joinpath(*path.parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
        return into

    async def _git_fetch(self, owner: str, repo: str, revision: str, into: Path) -> Path:
        import asyncio
        import shutil
        git = shutil.which("git")
        if not git:
            raise ValueError("the source archive is unavailable and git is not installed")
        env = {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(into),
               "PATH": "/usr/bin:/bin", **{k: v for k, v in __import__("os").environ.items()
                                            if k.lower() in {"https_proxy", "http_proxy", "no_proxy", "git_ssl_cainfo",
                                                             "ssl_cert_file", "git_config_count"} or k.startswith("GIT_CONFIG_")}}
        url = f"https://github.com/{owner}/{repo}.git"
        commands = [[git, "init", "-q", str(into)],
                    [git, "-C", str(into), "-c", "core.symlinks=false", "fetch", "-q", "--depth", "1", url, revision],
                    [git, "-C", str(into), "-c", "core.symlinks=false", "-c", "advice.detachedHead=false",
                     "checkout", "-q", "FETCH_HEAD"]]
        for cmd in commands:
            proc = await asyncio.create_subprocess_exec(*cmd, env=env, stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE)
            try:
                _, err = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                proc.kill()
                raise ValueError("fetching the repository timed out")
            if proc.returncode != 0:
                raise ValueError("git could not fetch the pinned commit: " + err.decode(errors="replace")[:200])
        shutil.rmtree(into / ".git", ignore_errors=True)
        total = sum(p.stat().st_size for p in into.rglob("*") if p.is_file() and not p.is_symlink())
        if total > MAX_EXTRACTED_BYTES:
            raise ValueError("repository exceeds the extraction limit")
        for link in [p for p in into.rglob("*") if p.is_symlink()]:
            link.unlink()
        return into


async def audit_reference(reference: str, settings: Settings, *, network: str = "testnet", deep: bool = True,
                          purpose: str = "", transport: httpx.AsyncBaseTransport | None = None,
                          deadline: float | None = None) -> dict:
    """Resolve, then audit the source if any is bound; otherwise audit the on-chain evidence."""
    from .repo_audit import audit_repository, audit_onchain

    resolver = AgentResolver(settings, network, transport=transport)
    resolution = await resolver.resolve(reference)
    card = resolution.get("card") or {}
    name = card.get("name") or resolution["reference"][:60]
    purpose = purpose or card.get("description") or "Agent resolved from an on-chain or registry reference."
    wallet = resolution.get("wallet", "")
    stellar_address = wallet if StrKey.is_valid_ed25519_public_key(wallet) else ""
    source = resolution["source"]
    onchain_identity = resolution["kind"] in {"registry_agent", "contract"}
    if source["repository"] and not _SHA.match(source.get("revision") or ""):
        if resolution["kind"] == "repository":
            raise ValueError("The repository's commit could not be resolved; nothing was audited.")
        resolution["steps"].append({"check": "source_fetch", "result": "unavailable",
                                    "evidence": "the bound source could not be pinned to a commit; only on-chain evidence was reviewed"})
    if source["repository"] and _SHA.match(source.get("revision") or ""):
        with tempfile.TemporaryDirectory(prefix="veritas-src-") as tmp:
            try:
                root = await resolver.download(source["repository"], source["revision"], Path(tmp))
            except ValueError as exc:
                if resolution["kind"] == "repository":
                    raise ValueError(f"The repository could not be fetched: {exc}") from exc
                resolution["steps"].append({"check": "source_fetch", "result": "unavailable", "evidence": str(exc)[:300]})
                root = None
            if root is not None and source.get("path"):
                # A link to one folder of a repository audits that folder only.
                sub = (root / source["path"]).resolve()
                if not sub.is_dir() or not sub.is_relative_to(root.resolve()):
                    raise ValueError(f"The folder {source['path']} does not exist in the repository.")
                root = sub
            if root is not None:
                resolution["steps"].append({"check": "source_fetch", "result": "fetched",
                                            "evidence": f"{source['repository']} @ {source['revision']}"
                                                        + (f" /{source['path']}" if source.get("path") else "")})
                result = await audit_repository(root, name=name, purpose=purpose, settings=settings,
                                                network=network, stellar_address=stellar_address, deep=deep,
                                                source_reference=source["repository"], revision=source["revision"],
                                                contract_facts=resolution.get("contract"),
                                                source_binding={**source, "onchain": onchain_identity},
                                                deadline=deadline)
                return await _finish(resolution, result)
    result = await audit_onchain(resolution, name=name, purpose=purpose, settings=settings, network=network,
                                 stellar_address=stellar_address, deep=deep)
    return await _finish(resolution, result)


async def _finish(resolution: dict, result: dict) -> dict:
    # The resolution is part of the report: re-commit the canonical bytes.
    from ..reporting.generator import canonical_json
    result["report"]["resolution"] = resolution
    result["report_json"] = canonical_json(result["report"])
    result["report_sha256"] = hashlib.sha256(result["report_json"].encode()).hexdigest()
    return result
