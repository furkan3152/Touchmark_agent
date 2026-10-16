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
from ..models import AgentArtifact, AuditTier, SourceKind
from ..reporting.generator import canonical_json, report_to_dict

SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".rs", ".go", ".sol")
INSTRUCTION_NAMES = {"skill.md", "agents.md", "claude.md", "system_prompt.md", "prompt.md", "instructions.md"}
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


def select_repository(root: Path, *, max_files: int = 120, max_bytes: int = 900_000,
                      max_file_bytes: int = 120_000) -> tuple[dict[str, str], dict]:
    """Choose the agent-defining source within a budget. Returns (files, manifest)."""
    root = root.resolve()
    candidates, instructions, skipped, oversized = [], {}, 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        if rel.name.lower() in INSTRUCTION_NAMES and not _skipped(rel):
            instructions[rel.as_posix()] = path.read_text(errors="replace")[:20_000]
            continue
        if not rel.name.lower().endswith(SOURCE_SUFFIXES):
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
    manifest = {"source_files_selected": len(files), "source_bytes_selected": used,
                "source_files_not_selected": left_out[:200], "files_skipped_as_tests_or_builds": skipped,
                "files_too_large": oversized[:50], "instruction_files": sorted(instructions),
                "complete": not left_out and not oversized,
                "budget": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes}}
    return files, {"manifest": manifest, "instructions": instructions}


def _dependencies(root: Path) -> list[str]:
    deps: list[str] = []
    package = root / "package.json"
    if package.is_file():
        try:
            data = json.loads(package.read_text())
            for section in ("dependencies", "peerDependencies"):
                deps += [f"{k}@{v}" for k, v in sorted((data.get(section) or {}).items())]
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
                           deep: bool = True, source_reference: str = "", revision: str = "") -> dict:
    from ..swarm.orchestrator import AuditSwarm
    from .deep_review import reviewer_from_settings

    root = Path(root)
    files, selection = select_repository(root)
    if not files:
        raise ValueError("No supported source files were found in the repository.")
    instructions = "\n\n".join(f"[{path}]\n{text}" for path, text in selection["instructions"].items())
    goals = forbidden_goals or []
    description = purpose + ("\nForbidden goals: " + "; ".join(goals) if goals else "")
    chain: dict = {}
    if settings.enable_onchain_verification and (stellar_address or files):
        from ..stellar.authority import AuthorityReader
        try:
            chain = await AuthorityReader(network).collect(stellar_address, agent_key=agent_signing_key, code_files=files)
        except Exception:
            chain = {"network": network, "status": "unavailable"}
    artifact = AgentArtifact(
        source_kind=SourceKind.REPO,
        source_ref=f"repo:{source_reference or root.name}@{revision}",
        name=name, description=description, system_prompt=instructions[:12_000],
        code_files=files, dependencies=_dependencies(root), chain_authority=chain,
        agent_wallet=stellar_address if stellar_address.startswith("G") else "",
        owner_verification_note="Not checked during repository review.",
    )
    isolated = settings.model_copy(update={
        "stellar_network": "offline", "llm_provider": "", "llm_api_key": "", "pinata_jwt": "",
        "enable_active_agent_probes": False, "enable_audit_escrow": False, "enable_ofac_screening": False})
    reviewer = reviewer_from_settings(settings) if deep else None
    if reviewer is not None:
        reviewer.max_turns = max(reviewer.max_turns, 40)
        reviewer.timeout_seconds = max(reviewer.timeout_seconds, 900.0)
    report = await AuditSwarm(isolated).run(artifact, uuid4().hex, AuditTier.DEEP, deep_reviewer=reviewer)
    from ..reporting.english import english_finding
    from ..swarm.policy import actionable_risks, finding_set_commitment
    report.findings = [english_finding(f) for f in report.findings]
    report.finding_set_hash = finding_set_commitment(report.findings)
    payload = report_to_dict(report, artifact)
    payload["repository"] = {"reference": source_reference, "revision": revision,
                             "source_sha256": sha256(canonical_json(files).encode()).hexdigest(),
                             **selection["manifest"]}
    payload["subject"] = {"name": name, "purpose": purpose, "forbidden_goals": goals}
    payload["review_decision"] = report.decision
    payload["priority_finding_ids"] = [f.id for f in actionable_risks(report.findings)]
    if not selection["manifest"]["complete"]:
        payload["judge_notes"].append("Repository selection was budget-limited; unselected files were not reviewed. "
                                      "See repository.source_files_not_selected.")
    encoded = canonical_json(payload)
    return {"decision": report.decision, "report": payload, "report_json": encoded,
            "report_sha256": sha256(encoded.encode()).hexdigest()}
