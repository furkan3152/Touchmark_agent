"""Audit a whole agent repository, not a 12-file bundle.

The Studio route accepts a small bundle so it can stay free and fast. Real agents are
repositories with many files in several languages. This service:

1. selects the files that define the agent (tool registration, signing, payments,
   secrets, network and process calls rank first; tests, builds and vendored code are
   skipped) within an explicit budget, and records what was left out;
2. reads agent instructions (SKILL.md, AGENTS.md, prompt files) and dependencies;
3. runs the same pipeline as every other route: code reconciliation, rule auditors,
   optional on-chain authority and the grounded deep review, then one decision.

Nothing in the repository is imported or executed.
"""

from __future__ import annotations

import json
import re
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from stellar_sdk import StrKey

from ..config import Settings
from ..models import AgentArtifact, AuditTier, SourceKind, ToolSpec
from ..reporting.generator import canonical_json, report_to_dict
from ..swarm.provenance import _is_manifest
from .lockfiles import Lockset

SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".rs", ".go", ".sol")
#: Code generators ship the agent as templates (server.py.hbs, tools.ts.tmpl). A template
#: whose stem is a source file is reviewed like source.
TEMPLATE_SUFFIXES = (".hbs", ".handlebars", ".j2", ".jinja", ".jinja2", ".tmpl", ".mustache", ".ejs")
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "uv.lock",
             "Pipfile.lock", "go.sum", "bun.lock", "bun.lockb")
#: Deeper paths are not source anyone reads: real repositories stay far below this, and
#: path handling costs grow with depth (a hostile tree of ~1,000-level branches stalls it).
MAX_PATH_DEPTH = 64
#: Files that deploy a server as several instances (serverless functions, edge workers), where
#: in-memory state such as an MPP replay store is not shared between requests.
DEPLOYMENT_MARKERS = {"vercel.json", "wrangler.toml", "serverless.yml", "serverless.yaml", "netlify.toml"}
INSTRUCTION_NAMES = {"skill.md", "agents.md", "claude.md", "system_prompt.md", "prompt.md", "instructions.md"}
#: The root README states what the agent promises its users; deep review checks the code against it.
README_NAMES = {"readme.md", "readme"}
#: Tool registrations in MCP servers and agent frameworks.
_TOOL_PATTERNS = (
    re.compile(r"""\.(?:tool|registerTool|addTool)\(\s*["'`]([\w.:-]{2,64})["'`]"""),
    re.compile(r"""\bname\s*:\s*["'`]([\w.:-]{2,64})["'`]\s*,\s*(?:title\s*:[^\n]*\n\s*)?description\s*:"""),
    re.compile(r"""@\w+\.tool\([^)]*\)\s*\n\s*(?:async\s+)?def\s+(\w+)"""),
    re.compile(r"""\bTool\(\s*name\s*=\s*["']([\w.:-]{2,64})["']"""),
)
SKIP_DIRS = {"node_modules", "dist", "build", "out", ".git", "target", "vendor", "__pycache__", "coverage",
             ".next", ".turbo", ".venv", "venv", "test", "tests", "__tests__", "spec", "fixtures", "e2e",
             "examples", "example", "docs", "benchmarks", ".github"}
SIGNALS = re.compile(
    r"stellar|soroban|Keypair|fromSecret|from_secret|sign\(|signTransaction|submitTransaction|submit_transaction|"
    r"server\.tool|registerTool|@tool|tool\(|process\.env|os\.environ|fetch\(|axios|httpx|requests\.|exec\(|"
    r"spawn\(|child_process|subprocess|payment|transfer|trustline|setOptions|set_options|secret|mnemonic|seed|"
    r"anthropic|openai|messages\.create|mcp|policy|limit|allowlist|approve", re.I)


#: Files that decide who may do what. They are kept first when a repository exceeds the budget.
SECURITY_PATH = re.compile(r"(?:^|[/_.-])(?:auth\w*|router|routes?|middleware|guards?|netguard|polic(?:y|ies)|"
                           r"permissions?|admin|webhooks?|sessions?|keys|approvals?|x402|paymaster|signer|wallet)"
                           r"(?:[/_.-]|$)", re.I)
#: Time kept for independent verification when a request deadline bounds the audit.
VERIFY_RESERVE_SECONDS = 50.0
#: An owner claim: the repository names the Stellar account its credential belongs to.
#: touchmark.json is the current name; agentveritas.json is still read for older repositories.
OWNERSHIP_FILES = ("touchmark.json", ".well-known/touchmark.json", "agentveritas.json", ".well-known/agentveritas.json")
#: The Veritas Blueprint project map; still read for older repositories. .tmark replaces it.
BLUEPRINT_FILE = "veritas.json"
#: The one declaration file: identity, owner, authority, limits and tools (services/tmark.py).
TMARK_FILE = ".tmark"
DECLARATION_BYTES = 64_000
LICENSE_NAMES = {"license", "license.md", "license.txt", "licence", "licence.md", "copying"}


def ownership_claim(record: dict) -> dict:
    """Parse agentveritas.json: {"stellar_owner": "G..."}. Committing this file shows that
    whoever controls the repository names that account; the account's signature, required
    when the agent is registered, shows its key holder agrees."""
    if not record:
        return {}
    try:
        owner = str(json.loads(record["text"]).get("stellar_owner", "")).strip()
    except (ValueError, AttributeError):
        return {"path": record["path"], "error": "not valid JSON with a stellar_owner field"}
    from stellar_sdk import StrKey
    if not StrKey.is_valid_ed25519_public_key(owner):
        return {"path": record["path"], "error": "stellar_owner is not a valid G... account"}
    return {"path": record["path"], "stellar_owner": owner}


class _DeclaredTool(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=600)
    scopes: list[str] = Field(default_factory=list, max_length=20)
    requires_signature: bool = False
    network_access: bool = False
    spend_limit_usdc: float | None = Field(default=None, ge=0)
    spend_limit: dict[str, str] | None = None

    @field_validator("spend_limit", mode="before")
    @classmethod
    def _cap(cls, value):
        """A cap in any asset, in the .tmark Money shape; anything else is not a cap."""
        from .tmark import Money, cap
        try:
            return cap(Money.model_validate(value)) if value is not None else None
        except ValidationError:
            return None


class _Declaration(BaseModel):
    """The optional self-declaration in agentveritas.json, next to stellar_owner.

    A declaration states intent; it never closes a risk on its own. Declared tools are
    reconciled with what the source can do (swarm/capabilities.py), and a declared
    spending limit counts only when the source bounds every payment amount.
    """
    model_config = ConfigDict(extra="ignore")
    name: str = Field(default="", max_length=100)
    description: str = Field(default="", max_length=2_000)
    purpose: str = Field(default="", max_length=2_000)
    domain: str = Field(default="", max_length=40)
    capabilities: list[str] = Field(default_factory=list, max_length=40)
    tools: list[_DeclaredTool] = Field(default_factory=list, max_length=60)
    forbidden_goals: list[str] = Field(default_factory=list, max_length=30)
    human_oversight: bool = False
    discloses_ai: bool = False
    agent_wallet: str = Field(default="", max_length=56)
    agent_contract_id: str = Field(default="", max_length=56)


def declarations(selection: dict) -> dict:
    """What the repository declares about itself (agentveritas.json, veritas.json).

    Returns the parsed fields plus a record of which files were read, for the report."""
    out: dict = {"files": [], "errors": []}
    tmark_record = selection.get("tmark") or {}
    if tmark_record:
        # .tmark is the single source of truth: when it is present, older files are not read,
        # and when it has any error nothing in it is used.
        from . import tmark
        parsed, errors = tmark.parse(tmark_record["text"])
        out["files"].append(tmark_record["path"])
        out["tmark"] = {"status": "valid" if parsed else "invalid", "errors": errors}
        if parsed:
            out["tmark"]["parsed"] = parsed
            out["declaration"] = _Declaration.model_validate(tmark.to_declaration(parsed))
        return out
    record = selection.get("ownership") or {}
    if record:
        try:
            raw = json.loads(record["text"])
            if not isinstance(raw, dict):
                raise ValueError("not a JSON object")
            decl = _Declaration.model_validate({k: v for k, v in raw.items() if v is not None})
            out["files"].append(record["path"])
            out["declaration"] = decl
        except (ValueError, ValidationError) as exc:
            out["errors"].append(f"{record['path']}: {str(exc).splitlines()[0][:200]}")
    blueprint = selection.get("blueprint") or {}
    if blueprint:
        from .blueprint import parse_blueprint
        try:
            parsed = parse_blueprint(blueprint["text"])
            out["files"].append(blueprint["path"])
            out["blueprint"] = parsed
        except ValueError as exc:
            out["errors"].append(f"{blueprint['path']}: {exc}")
    return out


_SEED = re.compile(rb"\bS[A-Z2-7]{55}\b")
#: Committed keys are searched in tests, examples and docs too: a key is public once pushed,
#: whichever folder holds it. Only generated and vendored folders are skipped.
_COMMITTED_SKIP = SKIP_DIRS - {"test", "tests", "__tests__", "spec", "e2e", "examples", "example", "fixtures", "docs"}


def committed_seeds(root: Path, selected: set[str], limit: int = 20,
                    keys: dict[str, list[str]] | None = None) -> list[str]:
    """Valid Stellar secret seeds in committed files the source selection leaves out
    (key files, notes, .env copies). Locations only; the seed itself never leaves here.
    ``keys`` collects the public keys derived from them, by location (one line can hold
    several), for seed triage."""
    from stellar_sdk import Keypair, StrKey
    found: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if (not path.is_file() or path.is_symlink() or rel.as_posix() in selected
                or any(p.lower() in _COMMITTED_SKIP for p in rel.parts[:-1]) or path.stat().st_size > 400_000):
            continue
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            continue
        for match in _SEED.finditer(data):
            seed = match.group(0).decode()
            if StrKey.is_valid_ed25519_secret_seed(seed):  # placeholders fail the checksum
                line = data[:match.start()].count(b"\n") + 1
                found.append(f"{rel.as_posix()}:{line} (S{seed[1:5]}…redacted)")
                if keys is not None:
                    keys.setdefault(f"{rel.as_posix()}:{line}", []).append(Keypair.from_secret(seed).public_key)
                if len(found) >= limit:
                    return found
    return found


def committed_credentials(root: Path, selected: set[str], limit: int = 20) -> list[str]:
    """API keys, tokens and private keys in committed files outside the source selection.
    Redacted locations only."""
    from ..swarm.hardening import find_credentials
    found: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if (not path.is_file() or path.is_symlink() or rel.as_posix() in selected
                or any(p.lower() in _COMMITTED_SKIP for p in rel.parts[:-1])
                or path.stat().st_size > 400_000 or path.suffix.lower() in {".lock", ".svg", ".png", ".jpg", ".woff2", ".map"}):
            continue
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            continue
        found += find_credentials(rel.as_posix(), data)
        if len(found) >= limit:
            return found[:limit]
    return found


def _is_repository_record(rel: Path) -> bool:
    posix = rel.as_posix().lower()
    return ((len(rel.parts) == 1 and rel.name.lower() in LICENSE_NAMES)
            or (posix.startswith(".github/workflows/") and posix.endswith((".yml", ".yaml")))
            or posix == ".gitlab-ci.yml"
            or re.fullmatch(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml", rel.name.lower()) is not None)


#: Build, code-generation, release and smoke-test scripts: developer tooling, not the agent.
#: They run on a developer's machine, not when the agent acts, so they are not its authority.
_DEV_TOOLING = re.compile(r"^(?:build(?:[-_.][\w-]+)?|smoke[-_]?tests?(?:[-_][\w-]+)?|generate[-_][\w-]+|gen[-_]types|"
                          r"codegen[\w-]*|test|tests|release|publish|bump[-_]?version|postinstall)"
                          r"\.(?:[cm]?[jt]s|py)$", re.I)


def _skipped(rel: Path) -> bool:
    parts = [p.lower() for p in rel.parts[:-1]]
    name = rel.name.lower()
    # In a tools/ directory under src/ (src/tools, packages/x/src/tools) a name like
    # build_transaction.ts is an agent tool; a repository's own tools/ holds build scripts.
    agent_tools = len(parts) >= 2 and parts[-1] in {"tools", "tool"} and "src" in parts[:-1]
    tooling = bool(_DEV_TOOLING.match(name)) and not agent_tools
    return (any(p in SKIP_DIRS or p.startswith(".") for p in parts) or tooling
            or name.endswith((".d.ts", ".min.js", ".test.ts", ".spec.ts", ".test.js", ".spec.js", "_test.py", ".map"))
            or name.startswith("test_"))


def _is_source(name: str) -> bool:
    name = name.lower()
    if name.endswith(TEMPLATE_SUFFIXES):
        name = name.rsplit(".", 1)[0]
    return name.endswith(SOURCE_SUFFIXES)


def _lockfiles(root: Path) -> dict[str, str]:
    found = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if path.is_file() and not path.is_symlink() and path.name in LOCKFILES and not _skipped(rel):
            found[rel.as_posix()] = sha256(path.read_bytes()).hexdigest()
    return found


def select_repository(root: Path, *, max_files: int = 1_500, max_bytes: int = 12_000_000,
                      max_file_bytes: int = 400_000) -> tuple[dict[str, str], dict]:
    """Choose the agent-defining source within a budget. Returns (files, manifest)."""
    root = root.resolve()
    candidates, instructions, manifests, skipped, oversized = [], {}, {}, 0, []
    ownership: dict = {}
    blueprint: dict = {}
    tmark_record: dict = {}
    markers: list[str] = []
    prefix = len(str(root)) + 1
    for path in sorted(root.rglob("*")):
        if str(path).count("/", prefix) >= MAX_PATH_DEPTH or not path.is_file() or path.is_symlink():
            continue
        rel = Path(str(path)[prefix:])
        if path.name in DEPLOYMENT_MARKERS and not _skipped(rel):
            markers.append(rel.as_posix())
        if rel.as_posix() in OWNERSHIP_FILES and path.stat().st_size <= DECLARATION_BYTES:
            # The first name in OWNERSHIP_FILES wins when a repository has both.
            rank = OWNERSHIP_FILES.index(rel.as_posix())
            if not ownership or rank < OWNERSHIP_FILES.index(ownership["path"]):
                ownership = {"path": rel.as_posix(), "text": path.read_text(errors="replace")}
            continue
        if rel.as_posix() == TMARK_FILE:
            tmark_record = {"path": TMARK_FILE, "text": path.read_text(errors="replace")[:DECLARATION_BYTES + 1]}
            continue
        if rel.as_posix() == BLUEPRINT_FILE and path.stat().st_size <= DECLARATION_BYTES:
            blueprint = {"path": BLUEPRINT_FILE, "text": path.read_text(errors="replace")}
            continue
        if _is_repository_record(rel) and path.stat().st_size <= 64_000:
            # License and CI definitions are provenance evidence, not source.
            manifests[rel.as_posix()] = path.read_text(errors="replace")
            continue
        if rel.name.lower() in README_NAMES and len(rel.parts) == 1:
            instructions[rel.as_posix()] = path.read_text(errors="replace")[:6_000]
            continue
        if rel.name.lower() in INSTRUCTION_NAMES and not _skipped(rel):
            instructions[rel.as_posix()] = path.read_text(errors="replace")[:20_000]
            continue
        manifest_file = _is_manifest(rel.as_posix())
        if not (_is_source(rel.name) or manifest_file):
            continue
        if _skipped(rel):
            skipped += 1
            continue
        size = path.stat().st_size
        if size > max_file_bytes:
            oversized.append(rel.as_posix())
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if manifest_file and not _is_source(rel.name):
            # Manifests and Dockerfiles declare version ranges and base images. They are
            # small and reviewed outside the source budget.
            if len(rel.parts) <= 3 and size <= 64_000:
                manifests[rel.as_posix()] = text
            continue
        score = (len(SIGNALS.findall(text)) + (5 if rel.parts[0] in {"src", "lib", "app", "agent", "server"} else 0)
                 + (40 if SECURITY_PATH.search(rel.as_posix()) else 0))
        candidates.append((score, rel.as_posix(), text))
    candidates.sort(key=lambda c: (-c[0], c[1]))
    files, used, left_out = {}, 0, []
    for score, rel, text in candidates:
        size = len(text.encode())
        if len(files) >= max_files or used + size > max_bytes:
            left_out.append(rel)
            continue
        files[rel], used = text, used + size
    source_count = len(files)
    files.update(manifests)
    manifest = {"source_files_selected": source_count, "manifest_files": sorted(manifests), "source_bytes_selected": used,
                "source_files_not_selected": left_out[:500], "files_skipped_as_tests_or_builds": skipped,
                "files_too_large": oversized[:50], "instruction_files": sorted(instructions),
                "complete": not left_out and not oversized,
                "budget": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes}}
    seed_keys: dict[str, list[str]] = {}
    return files, {"manifest": manifest, "instructions": instructions, "ownership": ownership, "blueprint": blueprint,
                   "tmark": tmark_record, "deployment_markers": markers[:50],
                   "committed_seeds": committed_seeds(root, set(files), keys=seed_keys),
                   "committed_seed_keys": seed_keys,
                   "committed_credentials": committed_credentials(root, set(files))}


def registered_tools(files: dict[str, str]) -> list[ToolSpec]:
    """Tools the source registers with an MCP server or agent framework.

    They are recorded with origin "registered": named by the code, not declared by a
    submitter, and granting nothing, so capability reconciliation still adds what the
    code can do as "observed" tools.
    """
    found: dict[str, str] = {}
    for path, text in sorted(files.items()):
        if _is_manifest(path):
            continue
        for pattern in _TOOL_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                found.setdefault(match.group(1), f"{path}:{line}")
    return [ToolSpec(name=name, origin="registered", description=f"Registered in source at {where}")
            for name, where in list(found.items())[:60]]


def _dependencies(root: Path, lockset: Lockset | None = None) -> list[str]:
    """Direct dependencies, at the exact version the lockfile resolves when there is one."""
    lockset = lockset or _read_lockset(root)
    deps: list[str] = []
    package = root / "package.json"
    if package.is_file():
        locked = {name: dep["version"] for name, dep in
                  ((lockset.importers.get("") or {}).get("deps") or {}).items() if dep.get("version")}
        try:
            data = json.loads(package.read_text(errors="replace"))
            for section in ("dependencies", "peerDependencies"):
                listed = data.get(section) if isinstance(data, dict) else None
                deps += [f"{k}@{locked.get(k) or v}" for k, v in sorted((listed if isinstance(listed, dict) else {}).items())]
        except (ValueError, OSError, RecursionError):
            pass
    for name in ("requirements.txt",):
        req = root / name
        if req.is_file():
            deps += [line.strip() for line in req.read_text(errors="replace").splitlines()
                     if line.strip() and not line.startswith("#")]
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        deps += [f"{crate}=={version}" for crate, version in
                 re.findall(r"^([A-Za-z0-9_-]+)\s*=\s*\"([^\"]+)\"", cargo.read_text(errors="replace"), re.M)]
    return deps[:200]


def _read_lockset(root: Path) -> Lockset:
    """Installed versions; a repository whose lockfiles cannot be read at all is audited
    without them (version rules then see ranges only), never failed."""
    try:
        return Lockset.read(root)
    except Exception:  # noqa: BLE001 - lockfiles are repository input; read_repository already skips bad files
        return Lockset()


#: The resolver's purpose when nothing better is known (agent_resolver.audit_reference).
GENERIC_PURPOSE = "Agent resolved from"


def _tools(decl: "_Declaration", files: dict[str, str]) -> list[ToolSpec]:
    """Declared tools, then tools the source registers that the declaration leaves out."""
    tools = [ToolSpec(**t.model_dump(), origin="declared") for t in decl.tools]
    named = {t.name for t in tools}
    return tools + [t for t in registered_tools(files) if t.name not in named]


def _declaration_record(declared: dict, root: Path) -> dict:
    """For the report: which declarations were read, and blueprint components that do not exist."""
    record: dict = {"files": declared["files"], "errors": declared["errors"]}
    if "tmark" in declared:
        record["tmark"] = {"status": declared["tmark"]["status"], "errors": declared["tmark"]["errors"]}
    decl = declared.get("declaration")
    if decl is not None:
        record["tools_declared"] = [t.name for t in decl.tools]
        record["fields"] = sorted(k for k, v in decl.model_dump().items() if v not in ("", [], False))
    blueprint = declared.get("blueprint")
    if blueprint is not None:
        record["blueprint_missing_files"] = [c.path for c in blueprint.components
                                             if not (root / c.path).is_file()][:20]
    return record


def _tmark_metadata(declared: dict, selection: dict) -> dict:
    """What the auditors need to compare the declaration with the code."""
    info = declared.get("tmark")
    if info is None:
        legacy = [p for p in ((selection.get("ownership") or {}).get("path"), (selection.get("blueprint") or {}).get("path")) if p]
        return {"status": "legacy" if legacy else "missing", "files": legacy}
    out = {"status": info["status"], "errors": info["errors"]}
    if info.get("parsed") is not None:
        out["declared"] = info["parsed"].model_dump(by_alias=False, exclude={"schema_url"})
        out["entrypoints"] = out["declared"]["entrypoints"]
    return out


async def audit_repository(root: str | Path, *, name: str, purpose: str, settings: Settings,
                           forbidden_goals: list[str] | None = None, network: str = "testnet",
                           stellar_address: str = "", agent_signing_key: str = "",
                           deep: bool = True, source_reference: str = "", revision: str = "",
                           contract_facts: dict | None = None, source_binding: dict | None = None,
                           deadline: float | None = None) -> dict:
    """``deadline`` (a ``time.monotonic()`` value) bounds the model review and verification,
    for callers with a request time limit; the deterministic analysis always runs in full."""
    from .deep_review import reviewer_from_settings

    root = Path(root)
    files, selection = select_repository(root)
    if not files:
        raise ValueError("No supported source files were found in the repository.")
    instructions = "\n\n".join(f"[{path}]\n{text}" for path, text in selection["instructions"].items())
    declared = declarations(selection)
    decl: _Declaration = declared.get("declaration") or _Declaration()
    blueprint = declared.get("blueprint")
    # The repository's own statement of purpose replaces a generic one from the caller.
    stated = decl.purpose or decl.description or (blueprint.purpose if blueprint else "")
    if stated and (not purpose or purpose.startswith(GENERIC_PURPOSE)):
        purpose = stated
    goals = forbidden_goals or [g for g in decl.forbidden_goals if g.strip()]
    description = purpose + ("\nForbidden goals: " + "; ".join(goals) if goals else "")
    if not stellar_address and StrKey.is_valid_ed25519_public_key(decl.agent_wallet):
        stellar_address = decl.agent_wallet
    declared_contract = decl.agent_contract_id if StrKey.is_valid_contract(decl.agent_contract_id) else ""
    if declared_contract and not contract_facts:
        contract_facts = await _contract_facts(settings, network, declared_contract)
    chain = await _chain_facts(settings, network, stellar_address, agent_signing_key, files)
    lockset = _read_lockset(root)
    if contract_facts:
        chain["contract"] = contract_facts
    tm = (declared.get("tmark") or {}).get("parsed")
    owner = (tm.owner.stellar_account if tm is not None and tm.owner else
             "" if declared.get("tmark") else ownership_claim(selection.get("ownership") or {}).get("stellar_owner", ""))
    exposure = await _seed_exposure(
        settings, seed_public_keys({**files, "<system prompt>": instructions[:12_000]}, selection.get("committed_seed_keys") or {}),
        {"agent": {stellar_address, agent_signing_key}, "owner": {owner}}, deadline)
    if source_binding:
        chain["source_binding"] = source_binding
    artifact = AgentArtifact(
        source_kind=SourceKind.REPO,
        source_ref=f"repo:{source_reference or root.name}@{revision}",
        name=name, description=description, system_prompt=instructions[:12_000],
        code_files=files, tools=_tools(decl, files), dependencies=_dependencies(root, lockset), chain_authority=chain,
        lockfiles=_lockfiles(root),
        declared_capabilities=decl.capabilities, human_oversight=decl.human_oversight,
        discloses_ai=decl.discloses_ai, domain=decl.domain or "general",
        raw_metadata={"source_not_selected": (selection["manifest"]["source_files_not_selected"]
                                              + selection["manifest"]["files_too_large"]),
                      "committed_seeds": selection.get("committed_seeds", []),
                      "deployment_markers": selection.get("deployment_markers", []),
                      "committed_credentials": selection.get("committed_credentials", []),
                      "tmark": _tmark_metadata(declared, selection),
                      "resolved_versions": lockset.to_json(),
                      **({"seed_exposure": exposure} if exposure else {})},
        agent_wallet=stellar_address if stellar_address.startswith("G") else "",
        agent_contract_id=(contract_facts or {}).get("contract_id", "") or declared_contract,
        owner_verification_note="Not checked during repository review.",
    )
    reviewer = reviewer_from_settings(settings) if deep else None
    if reviewer is not None:
        reviewer.max_turns = max(reviewer.max_turns, 40)
        reviewer.timeout_seconds = max(reviewer.timeout_seconds, 900.0)
    if (declared.get("tmark") or {}).get("status"):
        claim = ({"path": TMARK_FILE, "stellar_owner": tm.owner.stellar_account} if tm is not None and tm.owner
                 else {"path": TMARK_FILE, "error": "the .tmark is invalid" if tm is None else "the .tmark names no owner"})
    else:
        claim = ownership_claim(selection.get("ownership") or {})
    payload_extra = {"repository": {"reference": source_reference, "revision": revision,
                                    **({"ownership_claim": claim} if claim else {}),
                                    "declarations": _declaration_record(declared, root),
                                    "source_sha256": sha256(canonical_json(files).encode()).hexdigest(),
                                    **selection["manifest"]}}
    notes = [] if selection["manifest"]["complete"] else [
        "Repository selection was budget-limited; unselected files were not reviewed. "
        "See repository.source_files_not_selected."]
    from .finding_verifier import verifier_from_settings
    verifier = verifier_from_settings(settings) if deep else None
    if deadline is not None:
        # The review stops early enough to leave the verifier time to re-check what it found.
        if reviewer is not None:
            reviewer.deadline = deadline - (VERIFY_RESERVE_SECONDS if verifier is not None else 0)
        if verifier is not None:
            verifier.deadline = deadline
    return await _run_and_package(artifact, settings, reviewer, name, purpose, goals, payload_extra, notes,
                                  verifier=verifier)


async def audit_onchain(resolution: dict, *, name: str, purpose: str, settings: Settings, network: str = "testnet",
                        stellar_address: str = "", deep: bool = False) -> dict:
    """Audit an agent known only by on-chain identity: what the ledger proves, nothing more.

    Without source the review cannot pass; the report states exactly what was verified
    (registry record, card hash, endpoint hash, contract code, account authority).
    """
    del deep  # the deep review reads source; there is none
    contract = resolution.get("contract") or {}
    chain = await _chain_facts(settings, network, stellar_address, "", {})
    if contract:
        chain["contract"] = contract
    chain["source_binding"] = {**resolution.get("source", {}), "onchain": True}
    card = resolution.get("card") or {}
    tools = [ToolSpec(name=f["name"], origin="registered", description="Contract function: " + ", ".join(
                 f"{i['name']}: {i['type']}" for i in f["inputs"])[:300])
             for f in contract.get("functions", []) if not f["name"].startswith("__")][:60]
    tools += [ToolSpec(name=s, origin="registered", description="Skill declared in the agent card") for s in card.get("skills", [])]
    artifact = AgentArtifact(
        source_kind=SourceKind.ONCHAIN_ADDRESS, source_ref=resolution.get("reference", ""), name=name,
        description=purpose, tools=tools[:60], chain_authority=chain,
        agent_wallet=stellar_address, agent_contract_id=contract.get("contract_id", ""),
        owner_verification_note="Ownership is shown by the registry record owner when one was found.",
    )
    return await _run_and_package(artifact, settings, None, name, purpose, [], {}, [
        "No source code is bound to this agent; only on-chain evidence was reviewed. See resolution.steps."])


async def _contract_facts(settings: Settings, network: str, contract_id: str) -> dict | None:
    """The declared C... agent account, read as agent_resolver reads a contract reference."""
    if not settings.enable_onchain_verification:
        return None
    from ..stellar.soroban_reader import SorobanReader
    try:
        return await SorobanReader(network).contract(contract_id)
    except Exception:  # an unreadable ledger entry must not fail the source review
        return {"status": "unavailable", "contract_id": contract_id, "network": network}


_SEED_TEXT = re.compile(r"\bS[A-Z2-7]{55}\b")


def seed_public_keys(sources: dict[str, str], committed: dict[str, list[str]]) -> dict[str, list[str]]:
    """{G...: [path:line, ...]} for every valid secret seed in the reviewed text and in the
    committed files outside it. The public key is derived here; the seed goes nowhere."""
    from stellar_sdk import Keypair
    keys: dict[str, list[str]] = {}
    for name, text in sources.items():
        for m in _SEED_TEXT.finditer(text):
            if StrKey.is_valid_ed25519_secret_seed(m.group(0)):
                where = f"{name}:{text.count(chr(10), 0, m.start()) + 1}"
                keys.setdefault(Keypair.from_secret(m.group(0)).public_key, []).append(where)
    for where, found in committed.items():
        for public_key in [found] if isinstance(found, str) else found:
            keys.setdefault(public_key, []).append(where)
    return keys


async def _seed_exposure(settings: Settings, keys: dict[str, list[str]], declared: dict[str, set[str]],
                        deadline: float | None = None) -> dict | None:
    """Seed triage input for stellar_native: which declared key each seed is, and, when ledger
    reads are enabled, what its account holds on mainnet and testnet. With reads disabled or
    Horizon unavailable the seed keeps its path-based severity, so a rules-only run is stable.
    Under a request ``deadline`` the lookup takes at most a quarter of the time left."""
    if not keys:
        return None
    record: dict = {"status": "not_checked", "keys": [
        {"public_key": key, "locations": where,
         "declared": next((role for role, values in declared.items() if key in values), "")}
        for key, where in keys.items()]}
    if settings.enable_onchain_verification:
        from ..stellar.authority import SEED_LOOKUP_SECONDS, seed_exposure
        budget = SEED_LOOKUP_SECONDS if deadline is None else min(SEED_LOOKUP_SECONDS, (deadline - time.monotonic()) / 4)
        try:
            looked = await seed_exposure(list(keys), budget=budget)
        except Exception:  # the lookup is evidence, never a reason to fail the review
            record["status"] = "unavailable"
        else:
            record.update(status="checked", checked_at=looked["checked_at"])
            for item in record["keys"]:
                item.update(looked["keys"].get(item["public_key"]) or {})
    return record


async def _chain_facts(settings: Settings, network: str, stellar_address: str, agent_signing_key: str,
                       files: dict[str, str]) -> dict:
    if not settings.enable_onchain_verification or not (stellar_address or files):
        return {}
    from ..stellar.authority import AuthorityReader
    try:
        return await AuthorityReader(network).collect(stellar_address, agent_key=agent_signing_key, code_files=files)
    except Exception:
        return {"network": network, "status": "unavailable"}


async def _run_and_package(artifact: AgentArtifact, settings: Settings, reviewer, name: str, purpose: str,
                           goals: list[str], payload_extra: dict, notes: list[str], verifier=None) -> dict:
    from ..swarm.orchestrator import AuditSwarm
    from ..reporting.english import english_report
    from ..swarm.policy import actionable_risks, finding_set_commitment
    isolated = settings.model_copy(update={
        "stellar_network": "offline", "llm_provider": "", "llm_api_key": "", "pinata_jwt": "",
        "enable_active_agent_probes": False, "enable_audit_escrow": False, "enable_ofac_screening": False})
    report = await AuditSwarm(isolated).run(artifact, uuid4().hex, AuditTier.DEEP, deep_reviewer=reviewer,
                                             finding_verifier=verifier)
    english_report(report)
    report.finding_set_hash = finding_set_commitment(report.findings)
    payload = report_to_dict(report, artifact)
    payload.update(payload_extra)
    payload["subject"] = {"name": name, "purpose": purpose, "forbidden_goals": goals}
    payload["review_decision"] = report.decision
    payload["priority_finding_ids"] = [f.id for f in actionable_risks(report.findings)]
    payload["judge_notes"].extend(notes)
    if verifier is not None:
        # A second model re-checked each risk from source before the decision. It annotates
        # every finding; a rule finding it refutes with a quoted line was lowered one level
        # (swarm/orchestrator.py, _apply_disputes).
        verification = report.verification
        by_id = {v["finding_id"]: v for v in verification["results"]}
        for f in payload["findings"]:
            if f["id"] in by_id:
                v = by_id[f["id"]]
                f["verification"] = {k: v[k] for k in ("verdict", "reviewed_severity", "file", "line", "quote",
                                                       "reason", "quote_verified", "note")}
        payload["verification"] = verification["summary"]
    encoded = canonical_json(payload)
    return {"decision": report.decision, "report": payload, "report_json": encoded,
            "report_sha256": sha256(encoded.encode()).hexdigest()}
