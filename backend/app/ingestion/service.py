"""Ingestion: 4 yükleme yolunu tek AgentArtifact'e normalize eder.

1) onchain_address  — Stellar agent contract veya cüzdan adresi
2) repo             — GitHub / IPFS URI / yerel dizin / zip
3) endpoint         — MCP / A2A / HTTP endpoint (black-box)
4) wizard           — template + kullanıcı girdisi
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, model_validator

from ..config import Settings
from ..models import AgentArtifact, OnchainActivity, SourceKind, ToolSpec
from ..stellar.identity import IdentityReader
from ..stellar.identity import is_valid_stellar_address
from ..stellar.ownership import verify_owner
from .guards import (
    MAX_REMOTE_BYTES,
    IngestGuardError,
    guard_cid,
    guard_remote_url,
    is_within,
    resolve_ingest_path,
)
from .templates import TEMPLATES

STELLAR_ADDRESS_RE = re.compile(r"^[GC][A-Z2-7]{55}$")
CODE_SUFFIXES = {".py", ".ts", ".js", ".tsx", ".jsx", ".sol", ".rs", ".go", ".json", ".yaml", ".yml", ".toml", ".lock", ".md", ".txt"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "dist", "build", ".next"}
#: Denetim yüzeyine hiçbir koşulda alınmayacak dizinler. `keystore` operatörün
#: özel anahtarını, `sanctions` 5.6 MB'lık OFAC önbelleğini tutar; ikisi de
#: denetlenen ajanın kodu değildir.
SECRET_DIRS = {"keystore", "sanctions", ".ssh", ".gnupg", ".aws", ".config"}
#: Ad bazlı sır dosyaları — uzantı filtresi bunları yakalamıyor.
SECRET_FILENAMES = {"signer.json", "state.json", ".env", ".env.local", "id_rsa", "credentials"}
MAX_FILE_BYTES = 200_000
MAX_FILES = 60


class IngestRequest(BaseModel):
    kind: Literal["onchain_address", "repo", "endpoint", "wizard", "upload"]

    # onchain
    address: str = ""
    agent_contract_id: str = ""

    # repo
    repo_url: str = ""
    local_path: str = ""
    zip_base64: str = ""

    # endpoint
    endpoint_url: str = ""
    endpoint_protocol: str = "http"
    auth_header: str = ""

    # wizard
    template: str = ""
    name: str = ""
    description: str = ""
    system_prompt: str = ""
    capabilities: list[str] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)

    # ortak
    agent_wallet: str = ""
    owner: str = ""
    owner_signature: str = ""
    human_oversight: bool | None = None
    discloses_ai: bool | None = None
    privacy_mode: bool = False
    domain: str = ""

    @model_validator(mode="after")
    def _check(self) -> "IngestRequest":
        if self.kind == "onchain_address" and not (self.address or self.agent_contract_id):
            raise ValueError("address veya agent_contract_id gerekli")
        if self.kind == "onchain_address":
            reference = self.address or self.agent_contract_id
            if not is_valid_stellar_address(reference):
                raise ValueError("geçersiz Stellar StrKey/checksum; G... veya C... bekleniyor")
        if self.agent_wallet and not is_valid_stellar_address(self.agent_wallet, account_only=True):
            raise ValueError("agent_wallet geçerli bir G-account olmalı")
        if self.kind in ("repo", "upload") and not (self.repo_url or self.local_path or self.zip_base64):
            raise ValueError("repo_url, local_path veya zip_base64 gerekli")
        if self.kind == "endpoint" and not self.endpoint_url:
            raise ValueError("endpoint_url gerekli")
        if self.kind == "wizard" and not (self.template or self.system_prompt):
            raise ValueError("template veya system_prompt gerekli")
        return self


class IngestionService:
    def __init__(self, settings: Settings, identity: IdentityReader | None = None) -> None:
        self.settings = settings
        self.identity = identity or IdentityReader(settings)

    async def ingest(self, req: IngestRequest) -> AgentArtifact:
        if req.kind == "onchain_address":
            artifact = await self._from_onchain(req)
        elif req.kind in ("repo", "upload"):
            artifact = await self._from_repo(req)
        elif req.kind == "endpoint":
            artifact = await self._from_endpoint(req)
        else:
            artifact = self._from_wizard(req)

        # ortak alanların üzerine kullanıcı girdisi
        if req.agent_wallet:
            artifact.agent_wallet = req.agent_wallet
        if req.owner:
            artifact.owner = req.owner
        # Sahiplik: imza gerçekten kurtarılır. Boş string veya çöp imza artık
        # "doğrulandı" sayılmaz; nedeni artefakta yazılır.
        ownership = verify_owner(
            agent_ref=artifact.agent_wallet or artifact.agent_contract_id or artifact.name,
            owner=req.owner,
            signature=req.owner_signature,
            network_passphrase=self.settings.network_passphrase,
        )
        artifact.owner_verified = ownership.verified
        artifact.owner_verification_note = ownership.evidence

        if req.human_oversight is not None:
            artifact.human_oversight = req.human_oversight
        if req.discloses_ai is not None:
            artifact.discloses_ai = req.discloses_ai
        artifact.privacy_mode = req.privacy_mode
        if req.domain:
            artifact.domain = req.domain

        # cüzdan varsa zincir davranışını ekle
        if artifact.agent_wallet and not artifact.onchain.address:
            artifact.onchain = await self.identity.onchain_activity(artifact.agent_wallet)
        return artifact

    # ----------------------------------------------------------------- onchain
    async def _from_onchain(self, req: IngestRequest) -> AgentArtifact:
        reference = req.address or req.agent_contract_id
        if not STELLAR_ADDRESS_RE.match(reference) or not is_valid_stellar_address(reference):
            raise ValueError("geçersiz Stellar adresi; G... account veya C... contract bekleniyor")
        address = reference if reference.startswith("G") else ""
        contract_id = reference if reference.startswith("C") else req.agent_contract_id
        resolved = await self.identity.resolve(reference)
        card: dict[str, Any] = resolved.get("card") or {}
        activity = await self.identity.onchain_activity(address) if address else OnchainActivity()

        tools = [
            ToolSpec(
                name=str(skill),
                description=f"declared skill from agent card: {skill}",
                scopes=self._scopes_for_skill(str(skill)),
                requires_signature="trad" in str(skill) or "pay" in str(skill),
            )
            for skill in card.get("skills", [])
        ]
        return AgentArtifact(
            source_kind=SourceKind.ONCHAIN_ADDRESS,
            source_ref=reference,
            name=card.get("name", f"stellar-agent-{reference[-6:]}"),
            description=card.get("description", ""),
            declared_capabilities=[str(s) for s in card.get("skills", [])],
            system_prompt=card.get("systemPrompt", ""),
            tools=tools,
            agent_wallet=address,
            agent_contract_id=contract_id or self._card_agent_id(card),
            owner=card.get("owner", ""),
            discloses_ai=True,
            onchain=activity,
            raw_metadata={
                "identity_source": resolved.get("source"),
                "identity_evidence": resolved.get("evidence", ""),
                "agent_card": card,
            },
        )

    @staticmethod
    def _card_agent_id(card: dict) -> str:
        regs = card.get("registrations") or []
        return str(regs[0].get("agentId")) if regs and isinstance(regs[0], dict) else ""

    @staticmethod
    def _scopes_for_skill(skill: str) -> list[str]:
        s = skill.lower()
        if any(k in s for k in ("trad", "swap", "pay", "transfer", "rebalanc", "deposit", "withdraw")):
            return ["write:wallet", "sign:tx"]
        if any(k in s for k in ("web", "research", "search", "scan")):
            return ["read:web"]
        return ["read:market"]

    # -------------------------------------------------------------------- repo
    async def _from_repo(self, req: IngestRequest) -> AgentArtifact:
        files: dict[str, str] = {}
        ref = req.repo_url or req.local_path or "uploaded.zip"

        if req.zip_base64:
            files = self._read_zip_b64(req.zip_base64)
        elif req.local_path:
            if not self.settings.allow_local_path_ingest:
                raise IngestGuardError(
                    "yerel dizin denetimi kapalı (ALLOW_LOCAL_PATH_INGEST=false); "
                    "repo_url veya zip yükleyin"
                )
            root = self.settings.ingest_root_path
            target = resolve_ingest_path(req.local_path, root)
            files = self._read_dir(target)
            ref = str(target)
        elif req.repo_url:
            files = await self._read_remote(req.repo_url)

        if not files:
            raise ValueError(f"kaynak okunamadı veya boş: {ref}")

        manifest = self._parse_manifest(files)
        prompt = manifest.get("system_prompt") or self._find_prompt(files)
        tools = self._parse_tools(files, manifest)
        deps = self._parse_deps(files)

        return AgentArtifact(
            source_kind=SourceKind.REPO if req.repo_url or req.local_path else SourceKind.UPLOAD,
            source_ref=ref,
            name=manifest.get("name") or Path(ref).name or "repo-agent",
            description=manifest.get("description", ""),
            declared_capabilities=manifest.get("capabilities", []),
            system_prompt=prompt,
            tools=tools,
            code_files=files,
            dependencies=deps,
            agent_wallet=manifest.get("agent_wallet", ""),
            human_oversight=bool(manifest.get("human_oversight", False)),
            discloses_ai=bool(manifest.get("discloses_ai", False)),
            domain=manifest.get("domain", "general"),
            raw_metadata={"manifest": manifest, "file_count": len(files)},
        )

    def _read_dir(self, root: Path) -> dict[str, str]:
        """Kök altındaki kod dosyalarını okur.

        `root` çağrıdan önce `resolve_ingest_path` ile doğrulanmıştır; burada
        ek olarak **dosya bazlı** iki filtre uygulanır:

        * `SECRET_DIRS` / `SECRET_FILENAMES` — kök içinde olsa dahi sır taşıyan
          yollar denetim yüzeyine alınmaz. `data/keystore/attestor.json`
          operatörün özel anahtarıdır, denetlenen ajanın kodu değildir.
        * symlink kaçışı — kök içindeki bir bağ dışarıyı gösteriyorsa atlanır.
        """
        if not root.exists():
            raise ValueError(f"dizin bulunamadı: {root}")
        out: dict[str, str] = {}
        skipped_secrets: list[str] = []

        for path in sorted(root.rglob("*")):
            if len(out) >= MAX_FILES:
                break
            if path.is_dir():
                continue
            parts = path.parts
            if any(part in SKIP_DIRS for part in parts):
                continue
            if any(part in SECRET_DIRS for part in parts) or path.name in SECRET_FILENAMES:
                skipped_secrets.append(path.name)
                continue
            if path.suffix.lower() not in CODE_SUFFIXES:
                continue
            # Symlink kökün dışını gösteriyorsa okumak kaçış olur.
            if path.is_symlink() and not is_within(path, root):
                skipped_secrets.append(f"{path.name} (symlink)")
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                out[str(path.relative_to(root))] = path.read_text(errors="replace")
            except OSError:
                continue

        self._last_skipped_secrets = skipped_secrets
        return out

    def _read_zip_b64(self, b64: str) -> dict[str, str]:
        """Base64 zip'i okur.

        Zip girdisi tamamen denetlenen tarafın kontrolündedir, bu yüzden üç
        kontrol gerekir: yol kaçışı (`../`, absolute), sır dosyaları ve toplam
        açılmış boyut (zip bomb).
        """
        import base64

        try:
            raw = base64.b64decode(b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise IngestGuardError(f"zip_base64 çözümlenemedi: {exc}") from exc
        limit = min(MAX_REMOTE_BYTES, self.settings.max_ingest_bytes)
        if len(raw) > limit:
            raise IngestGuardError(
                f"zip çok büyük: {len(raw)} bayt (üst sınır {limit})"
            )

        out: dict[str, str] = {}
        total = 0
        try:
            zf_ctx = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile as exc:
            raise IngestGuardError(f"geçersiz zip: {exc}") from exc

        with zf_ctx as zf:
            for info in zf.infolist():
                if len(out) >= MAX_FILES or info.is_dir():
                    continue
                name = info.filename
                parts = Path(name).parts
                # Yol kaçışı: `../etc/passwd` veya `/etc/passwd`.
                if ".." in parts or Path(name).is_absolute() or name.startswith("/"):
                    continue
                if any(part in SKIP_DIRS or part in SECRET_DIRS for part in parts):
                    continue
                if Path(name).name in SECRET_FILENAMES:
                    continue
                if Path(name).suffix.lower() not in CODE_SUFFIXES:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                total += info.file_size
                if total > limit:
                    break
                out[name] = zf.read(info).decode("utf-8", errors="replace")
        return out

    async def _read_remote(self, url: str) -> dict[str, str]:
        """GitHub repo veya IPFS URI'den içerik çeker; erişim yoksa hata verir.

        URL denetlenen tarafın verdiği veridir, bu yüzden GitHub/IPFS dışındaki
        her hedef `guard_remote_url` üzerinden geçer: yalnızca http/https ve
        yalnızca genel internet adresleri. Aksi hâlde bu uç bir SSRF aracıdır —
        `http://169.254.169.254/…` ile bulut metadata'sı veya `http://127.0.0.1:8000`
        ile kendi API'si çekilebilirdi.
        """
        if url.startswith("ipfs://") or "/ipfs/" in url:
            cid = guard_cid(url.split("ipfs://")[-1].split("/ipfs/")[-1])
            target = f"{self.settings.ipfs_gateway.rstrip('/')}/{cid}"
            return self._maybe_zip(await self._fetch(target, timeout=30.0), "ipfs_payload")

        m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", url)
        if m:
            owner, repo = m.group(1), m.group(2).removesuffix(".git")
            for branch in ("main", "master"):
                try:
                    content = await self._fetch(
                        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}",
                        timeout=60.0,
                    )
                except httpx.HTTPStatusError:
                    continue
                return self._maybe_zip(content, f"{repo}-{branch}")
            raise ValueError(f"GitHub reposu indirilemedi: {url}")

        safe_url = guard_remote_url(url)
        return self._maybe_zip(await self._fetch(safe_url, timeout=30.0), "remote_payload")

    async def _fetch(self, url: str, *, timeout: float) -> bytes:
        """Streaming GET; her yönlendirme ve toplam boyut fail-closed doğrulanır."""
        limit = min(MAX_REMOTE_BYTES, self.settings.max_ingest_bytes)
        url = guard_remote_url(url)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for _ in range(4):  # en fazla 4 yönlendirme
                async with client.stream("GET", url) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if not location:
                            break
                        url = guard_remote_url(str(httpx.URL(url).join(location)))
                        continue
                    resp.raise_for_status()
                    declared = int(resp.headers.get("content-length", "0") or 0)
                    if declared > limit:
                        raise IngestGuardError(
                            f"uzak içerik çok büyük: {declared} bayt (üst sınır {limit})"
                        )
                    chunks: list[bytes] = []
                    received = 0
                    async for chunk in resp.aiter_bytes():
                        received += len(chunk)
                        if received > limit:
                            raise IngestGuardError(
                                f"uzak içerik çok büyük: >{limit} bayt"
                            )
                        chunks.append(chunk)
                    return b"".join(chunks)
        raise IngestGuardError(f"çok fazla yönlendirme: {url}")

    def _maybe_zip(self, content: bytes, label: str) -> dict[str, str]:
        if content[:2] == b"PK":
            import base64

            return self._read_zip_b64(base64.b64encode(content).decode())
        return {f"{label}.txt": content.decode("utf-8", errors="replace")[:MAX_FILE_BYTES]}

    @staticmethod
    def _parse_manifest(files: dict[str, str]) -> dict:
        for name, content in files.items():
            base = Path(name).name.lower()
            if base in ("agent.json", "agentveritas.json", "agent-card.json", "manifest.json"):
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        return data
                except json.JSONDecodeError:
                    continue
        return {}

    @staticmethod
    def _find_prompt(files: dict[str, str]) -> str:
        for name, content in files.items():
            base = Path(name).name.lower()
            if base in ("system_prompt.txt", "system_prompt.md", "prompt.txt", "prompt.md"):
                return content
        # kod içinde gömülü SYSTEM_PROMPT
        pattern = re.compile(
            r"(?:SYSTEM_PROMPT|system_prompt|systemPrompt)\s*[:=]\s*(?:\(\s*)?[\"']{1,3}(.+?)[\"']{1,3}",
            re.DOTALL,
        )
        for content in files.values():
            m = pattern.search(content)
            if m:
                return m.group(1).strip()
        return ""

    @staticmethod
    def _parse_tools(files: dict[str, str], manifest: dict) -> list[ToolSpec]:
        tools: list[ToolSpec] = []
        for item in manifest.get("tools", []) or []:
            if isinstance(item, dict):
                tools.append(
                    ToolSpec(
                        name=str(item.get("name", "unnamed")),
                        description=str(item.get("description", "")),
                        scopes=[str(s) for s in item.get("scopes", [])],
                        requires_signature=bool(item.get("requires_signature", False)),
                        spend_limit_usdc=item.get("spend_limit_usdc"),
                        network_access=bool(item.get("network_access", False)),
                    )
                )
            elif isinstance(item, str):
                tools.append(ToolSpec(name=item))
        if tools:
            return tools

        for name, content in files.items():
            if Path(name).name.lower() in ("tools.json", "skills.json"):
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    continue
                items = data if isinstance(data, list) else data.get("tools", [])
                for item in items:
                    if isinstance(item, dict):
                        tools.append(
                            ToolSpec(
                                name=str(item.get("name", "unnamed")),
                                description=str(item.get("description", "")),
                                scopes=[str(s) for s in item.get("scopes", [])],
                                requires_signature=bool(item.get("requires_signature", False)),
                                spend_limit_usdc=item.get("spend_limit_usdc"),
                                network_access=bool(item.get("network_access", False)),
                            )
                        )
        if tools:
            return tools

        # son çare: kod içindeki tool tanımlarını yakala
        decl = re.compile(r"@tool\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)|def\s+(tool_\w+)")
        seen: set[str] = set()
        for content in files.values():
            for m in decl.finditer(content):
                fname = m.group(1) or m.group(2)
                if fname and fname not in seen:
                    seen.add(fname)
                    tools.append(ToolSpec(name=fname, description="discovered from code"))
        return tools

    @staticmethod
    def _parse_deps(files: dict[str, str]) -> list[str]:
        deps: list[str] = []
        for name, content in files.items():
            base = Path(name).name.lower()
            if base == "requirements.txt":
                deps += [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.startswith("#")]
            elif base == "package.json":
                try:
                    data = json.loads(content)
                    for section in ("dependencies", "devDependencies"):
                        for pkg, ver in (data.get(section) or {}).items():
                            deps.append(f"{pkg}@{ver}")
                except json.JSONDecodeError:
                    continue
        return deps

    # ---------------------------------------------------------------- endpoint
    async def _from_endpoint(self, req: IngestRequest) -> AgentArtifact:
        meta: dict[str, Any] = {}
        tools: list[ToolSpec] = []
        capabilities: list[str] = []
        reachable = False
        latency_ms = None

        headers = {"Authorization": req.auth_header} if req.auth_header else {}
        discovery_paths = ["/.well-known/agent.json", "/.well-known/agent-card.json", "/agent.json", "/"]
        # Endpoint denetimi canlı probe yapar; hedef iç ağ olamaz (SSRF).
        base = guard_remote_url(req.endpoint_url).rstrip("/")

        # Yönlendirmeler burada reddedilir. Aksi hâlde genel bir endpoint'in
        # redirect'i yeniden doğrulanmadan iç ağa dönebilir ve auth başlığı sızabilir.
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            for path in discovery_paths:
                try:
                    import time as _t

                    t0 = _t.perf_counter()
                    resp = await client.get(base + path, headers=headers)
                    latency_ms = int((_t.perf_counter() - t0) * 1000)
                    if resp.is_redirect:
                        continue
                    if len(resp.content) > self.settings.max_ingest_bytes:
                        continue
                    if resp.status_code < 500:
                        reachable = True
                    if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                        data = resp.json()
                        if isinstance(data, dict):
                            meta = data
                            break
                except Exception:
                    continue

        for item in meta.get("tools", meta.get("skills", [])) or []:
            if isinstance(item, dict):
                tools.append(
                    ToolSpec(
                        name=str(item.get("name", "unnamed")),
                        description=str(item.get("description", "")),
                        scopes=[str(s) for s in item.get("scopes", [])],
                        network_access=True,
                    )
                )
                capabilities.append(str(item.get("name", "")))
            elif isinstance(item, str):
                tools.append(ToolSpec(name=item, network_access=True))
                capabilities.append(item)

        return AgentArtifact(
            source_kind=SourceKind.ENDPOINT,
            source_ref=req.endpoint_url,
            name=meta.get("name", f"endpoint-agent"),
            description=meta.get("description", "Black-box endpoint agent."),
            declared_capabilities=[c for c in capabilities if c],
            system_prompt=meta.get("systemPrompt", meta.get("instructions", "")),
            tools=tools,
            endpoint_url=req.endpoint_url,
            endpoint_protocol=req.endpoint_protocol,
            agent_wallet=meta.get("wallet", ""),
            raw_metadata={
                "endpoint_metadata": meta,
                "reachable": reachable,
                "discovery_latency_ms": latency_ms,
                "auth_provided": bool(req.auth_header),
            },
        )

    # ------------------------------------------------------------------ wizard
    def _from_wizard(self, req: IngestRequest) -> AgentArtifact:
        tpl = TEMPLATES.get(req.template, {})
        if req.template and not tpl:
            raise ValueError(f"bilinmeyen template: {req.template}")

        tools = req.tools or list(tpl.get("tools", []))
        return AgentArtifact(
            source_kind=SourceKind.WIZARD,
            source_ref=req.template or "custom",
            name=req.name or tpl.get("name", "wizard-agent"),
            description=req.description or tpl.get("description", ""),
            declared_capabilities=req.capabilities or tpl.get("declared_capabilities", []),
            system_prompt=req.system_prompt or tpl.get("system_prompt", ""),
            tools=tools,
            human_oversight=bool(tpl.get("human_oversight", False)),
            discloses_ai=bool(tpl.get("discloses_ai", False)),
            domain=tpl.get("domain", "general"),
            raw_metadata={"template": req.template},
        )
