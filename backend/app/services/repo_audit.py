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
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ..config import Settings
from ..models import AgentArtifact, AuditTier, SourceKind, ToolSpec
from ..reporting.generator import canonical_json, report_to_dict
from ..swarm.provenance import _is_manifest

SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".rs", ".go", ".sol")
#: Code generators ship the agent as templates (server.py.hbs, tools.ts.tmpl). A template
#: whose stem is a source file is reviewed like source.
TEMPLATE_SUFFIXES = (".hbs", ".handlebars", ".j2", ".jinja", ".jinja2", ".tmpl", ".mustache", ".ejs")
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "uv.lock",
             "Pipfile.lock", "go.sum", "bun.lock", "bun.lockb")
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


def _skipped(rel: Path) -> bool:
    parts = [p.lower() for p in rel.parts[:-1]]
    name = rel.name.lower()
    return (any(p in SKIP_DIRS or p.startswith(".") for p in parts)
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


def select_repository(root: Path, *, max_files: int = 120, max_bytes: int = 900_000,
                      max_file_bytes: int = 120_000) -> tuple[dict[str, str], dict]:
    """Choose the agent-defining source within a budget. Returns (files, manifest)."""
    root = root.resolve()
    candidates, instructions, manifests, skipped, oversized = [], {}, {}, 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
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
        score = len(SIGNALS.findall(text)) + (5 if rel.parts[0] in {"src", "lib", "app", "agent", "server"} else 0)
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
                "source_files_not_selected": left_out[:200], "files_skipped_as_tests_or_builds": skipped,
                "files_too_large": oversized[:50], "instruction_files": sorted(instructions),
                "complete": not left_out and not oversized,
                "budget": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes}}
    return files, {"manifest": manifest, "instructions": instructions}


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


def _dependencies(root: Path) -> list[str]:
    """Direct dependencies, at the exact version the lockfile resolves when there is one."""
    deps: list[str] = []
    package = root / "package.json"
    if package.is_file():
        locked: dict[str, str] = {}
        lock = root / "package-lock.json"
        if lock.is_file():
            try:
                for key, meta in (json.loads(lock.read_text()).get("packages") or {}).items():
                    if key.startswith("node_modules/") and key.count("node_modules/") == 1 and isinstance(meta, dict):
                        locked[key[len("node_modules/"):]] = str(meta.get("version", ""))
            except (ValueError, OSError):
                locked = {}
        try:
            data = json.loads(package.read_text())
            for section in ("dependencies", "peerDependencies"):
                deps += [f"{k}@{locked.get(k) or v}" for k, v in sorted((data.get(section) or {}).items())]
        except (ValueError, OSError):
            pass
    for name in ("requirements.txt",):
        req = root / name
        if req.is_file():
            deps += [line.strip() for line in req.read_text().splitlines() if line.strip() and not line.startswith("#")]
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        deps += [f"{crate}=={version}" for crate, version in
                 re.findall(r"^([A-Za-z0-9_-]+)\s*=\s*\"([^\"]+)\"", cargo.read_text(), re.M)]
    return deps[:200]


async def audit_repository(root: str | Path, *, name: str, purpose: str, settings: Settings,
                           forbidden_goals: list[str] | None = None, network: str = "testnet",
                           stellar_address: str = "", agent_signing_key: str = "",
                           deep: bool = True, source_reference: str = "", revision: str = "",
                           contract_facts: dict | None = None, source_binding: dict | None = None) -> dict:
    from .deep_review import reviewer_from_settings

    root = Path(root)
    files, selection = select_repository(root)
    if not files:
        raise ValueError("No supported source files were found in the repository.")
    instructions = "\n\n".join(f"[{path}]\n{text}" for path, text in selection["instructions"].items())
    goals = forbidden_goals or []
    description = purpose + ("\nForbidden goals: " + "; ".join(goals) if goals else "")
    chain = await _chain_facts(settings, network, stellar_address, agent_signing_key, files)
    if contract_facts:
        chain["contract"] = contract_facts
    if source_binding:
        chain["source_binding"] = source_binding
    artifact = AgentArtifact(
        source_kind=SourceKind.REPO,
        source_ref=f"repo:{source_reference or root.name}@{revision}",
        name=name, description=description, system_prompt=instructions[:12_000],
        code_files=files, tools=registered_tools(files), dependencies=_dependencies(root), chain_authority=chain, lockfiles=_lockfiles(root),
        agent_wallet=stellar_address if stellar_address.startswith("G") else "",
        agent_contract_id=(contract_facts or {}).get("contract_id", ""),
        owner_verification_note="Not checked during repository review.",
    )
    reviewer = reviewer_from_settings(settings) if deep else None
    if reviewer is not None:
        reviewer.max_turns = max(reviewer.max_turns, 40)
        reviewer.timeout_seconds = max(reviewer.timeout_seconds, 900.0)
    payload_extra = {"repository": {"reference": source_reference, "revision": revision,
                                    "source_sha256": sha256(canonical_json(files).encode()).hexdigest(),
                                    **selection["manifest"]}}
    notes = [] if selection["manifest"]["complete"] else [
        "Repository selection was budget-limited; unselected files were not reviewed. "
        "See repository.source_files_not_selected."]
    return await _run_and_package(artifact, settings, reviewer, name, purpose, goals, payload_extra, notes)


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
                           goals: list[str], payload_extra: dict, notes: list[str]) -> dict:
    from ..swarm.orchestrator import AuditSwarm
    from ..reporting.english import english_finding
    from ..swarm.policy import actionable_risks, finding_set_commitment
    isolated = settings.model_copy(update={
        "stellar_network": "offline", "llm_provider": "", "llm_api_key": "", "pinata_jwt": "",
        "enable_active_agent_probes": False, "enable_audit_escrow": False, "enable_ofac_screening": False})
    report = await AuditSwarm(isolated).run(artifact, uuid4().hex, AuditTier.DEEP, deep_reviewer=reviewer)
    report.findings = [english_finding(f) for f in report.findings]
    report.finding_set_hash = finding_set_commitment(report.findings)
    payload = report_to_dict(report, artifact)
    payload.update(payload_extra)
    payload["subject"] = {"name": name, "purpose": purpose, "forbidden_goals": goals}
    payload["review_decision"] = report.decision
    payload["priority_finding_ids"] = [f.id for f in actionable_risks(report.findings)]
    payload["judge_notes"].extend(notes)
    encoded = canonical_json(payload)
    return {"decision": report.decision, "report": payload, "report_json": encoded,
            "report_sha256": sha256(encoded.encode()).hexdigest()}
