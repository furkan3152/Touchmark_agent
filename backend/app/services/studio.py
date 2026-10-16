"""Stateless source review. No uploaded program is imported or executed."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import PurePosixPath
from uuid import uuid4
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config import Settings
from .assurance import ArchitectureManifest, build_assurance
from ..models import AgentArtifact, AuditTier, EvidenceGrade, Severity, SourceKind, ToolSpec
from ..reporting.generator import canonical_json, report_to_dict
from ..swarm import AuditSwarm
from ..stellar.identity import is_valid_stellar_address


def instruction_literals(files: dict[str, str]) -> list[dict]:
    """Locate bounded literal model instructions without importing source.

    These are candidate instructions, not proof of the live instruction hierarchy.
    Dynamic strings and framework-specific construction remain unresolved.
    """
    found = []
    for path, content in sorted(files.items()):
        if not path.endswith('.py'): continue
        try: tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError): continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call): continue
            values = []
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'decide', 'judge'} and node.args:
                values.append(node.args[0])
            values.extend(k.value for k in node.keywords if k.arg in {'system', 'system_prompt', 'instructions'})
            for value in values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and 20 <= len(value.value) <= 2000:
                    found.append({'file': path, 'line': value.lineno, 'text': value.value,
                        'evidence': 'source_literal_candidate', 'runtime_verified': False})
                    if len(found) == 6: return found
    return found


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_assistance: bool = False
    external_processing_consent: bool = False
    architecture: ArchitectureManifest = Field(default_factory=ArchitectureManifest)
    name: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=12, max_length=2000)
    system_prompt: str = Field(default="", max_length=12000)
    files: dict[str, str] = Field(default_factory=dict, max_length=12)
    tools: list[ToolSpec] = Field(default_factory=list, max_length=20)
    dependencies: list[str] = Field(default_factory=list, max_length=100)
    stellar_address: str = Field(default="", max_length=56)
    network: Literal["testnet", "mainnet"] = "testnet"
    source_revision: str = Field(default="", pattern=r"^(?:[a-f0-9]{40})?$")
    source_reference: str = Field(default="", max_length=240)

    @model_validator(mode="after")
    def bound_source(self) -> "ReviewRequest":
        if not self.name.strip() or len(self.purpose.strip()) < 12:
            raise ValueError("Provide an agent name and a meaningful purpose (at least 12 characters).")
        if self.stellar_address and not is_valid_stellar_address(self.stellar_address):
            raise ValueError("Use a public Stellar G-account or C-contract address, never a secret key.")
        if self.source_reference:
            from .studio_intake import GitHubRequest
            GitHubRequest(repository=self.source_reference)
        if not self.files and not self.system_prompt.strip() and not self.stellar_address:
            raise ValueError("Provide source files or a system prompt to review.")
        total = 0
        nodes = 0
        seen: set[str] = set()
        for name, content in self.files.items():
            from .discovery import safe_source_path
            path = PurePosixPath(name)
            if (
                not safe_source_path(name) or len(name) > 160 or not name or path.is_absolute() or "\\" in name
                or any(part.startswith(".") for part in path.parts)
                or ":" in name or name.lower() in seen
                or path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".json", ".md", ".txt", ".toml", ".yaml", ".yml"}
            ):
                raise ValueError("Use relative source filenames; hidden files and credentials are not accepted.")
            seen.add(name.lower())
            size = len(content.encode("utf-8"))
            total += size
            if size > 32_000 or total > 64_000:
                raise ValueError("Source limit: 32 KB per file and 64 KB per review.")
            if path.suffix.lower() == ".py":
                try:
                    tree = ast.parse(content)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    raise ValueError("Python source must be syntactically valid before review.") from exc
                pending = [(tree, 0)]
                while pending:
                    node, depth = pending.pop()
                    nodes += 1
                    if nodes > 5000 or depth > 50:
                        raise ValueError("Python source exceeds the bounded analysis complexity limit.")
                    pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        return self


async def review_source(request: ReviewRequest, settings: Settings) -> dict:
    if request.ai_assistance:
        if not request.external_processing_consent:
            raise ValueError("Explicit consent is required to send source to the configured AI provider.")
        if not settings.enable_public_ai_review or not settings.llm_enabled:
            raise ValueError("AI review is unavailable. Run a static review or ask the operator to enable the provider.")
    # Copy explicit settings, then disable every external integration. Server .env
    # cannot silently turn a free source review into an external upload or probe.
    isolated = settings.model_copy(update={
        "stellar_network": "offline", "stellar_rpc_url": "", "stellar_horizon_url": "",
        "llm_provider": "", "llm_api_key": "", "pinata_jwt": "",
        "screening_provider": "none", "screening_api_key": "",
        "enable_ofac_screening": False, "enable_active_agent_probes": False,
        "enable_audit_escrow": False,
    })
    embedded_instructions = instruction_literals(request.files) if not request.system_prompt.strip() else []
    candidate_prompt = request.system_prompt or '\n\n'.join(item['text'] for item in embedded_instructions)
    artifact = AgentArtifact(
        source_kind=SourceKind.UPLOAD if request.files or request.system_prompt else SourceKind.ONCHAIN_ADDRESS,
        source_ref=f"studio:{request.network}:{request.source_reference or request.stellar_address or 'submitted-bundle'}:{request.source_revision}",
        name=request.name, description=request.purpose,
        architecture=request.architecture.model_dump(),
        system_prompt=candidate_prompt, code_files=request.files,
        tools=request.tools, dependencies=request.dependencies,
        agent_wallet=request.stellar_address if request.stellar_address.startswith("G") else "",
        agent_contract_id=request.stellar_address if request.stellar_address.startswith("C") else "",
        owner_verification_note="Not checked during source review.",
    )
    report = await AuditSwarm(isolated).run(artifact, uuid4().hex, AuditTier.DEEP)
    from ..reporting.english import english_finding
    from ..swarm.policy import finding_set_commitment
    report.findings = [english_finding(f) for f in report.findings]
    report.finding_set_hash = finding_set_commitment(report.findings)
    payload = report_to_dict(report, artifact)
    payload["judge_notes"] = [
        "Rule-based source assessment; no runtime attacks were executed.",
        "Scores summarize observed findings and do not establish safety or complete coverage.",
        "Use priority findings, explicit limitations and the control inventory to plan further validation.",
    ]
    payload['instruction_evidence'] = embedded_instructions
    if embedded_instructions:
        payload['judge_notes'].append('Literal model instructions were located in source. Their use and the complete runtime hierarchy remain unverified.')
    from ..reporting.english import ATTACK_LABELS
    for auditor in payload["auditors"]:
        auditor["notes"] = f"Static {auditor['dimension']} analysis. See findings and coverage for evidence and limitations."
        for scenario in auditor["scenarios"]:
            sid = scenario["scenario_id"]
            if sid.startswith("A-") and sid[2:].isdigit() and 1 <= int(sid[2:]) <= len(ATTACK_LABELS):
                scenario["name"] = ATTACK_LABELS[int(sid[2:]) - 1][0]
            else:
                scenario["name"] = f"{auditor['dimension'].replace('_', ' ').title()} check {sid}"
            scenario["reason"] = "Recognized static signal present; enforcement unverified." if scenario["passed"] else "Expected static signal not established; further evidence required."
    from .discovery import discover_project
    payload["discovery"] = discover_project(request.files)
    payload["assurance"] = build_assurance(artifact, report.findings)
    payload["subject"] = {
        "stellar_address": request.stellar_address, "network": request.network,
        "source_reference": request.source_reference, "source_revision": request.source_revision, "association_verified": False,
    }
    scope = {
        "analysis": "static rules and bounded source-path analysis",
        "runtime_executed": False, "onchain_confirmed": False,
        "owner_verified": False, "persisted": False, "external_processors": [],
        "limits": [
            "Source review does not execute the agent or establish production safety.",
            "Python paths use bounded intraprocedural analysis; other languages use heuristics.",
            "Named controls are not proof of authorization, budget enforcement or replay protection.",
            "Seven rule-based dimensions are not seven independent human auditors.",
            "No sanctions clearance, legal certification or chain-state verification is performed.",
            "Source is processed on this server in memory; download the report before leaving.",
        ],
    }
    payload["ai_review"] = {"status": "not_requested", "observations": []}
    if request.ai_assistance:
        import asyncio
        from .ai_review import second_opinion
        try:
            payload["ai_review"] = await asyncio.wait_for(second_opinion(request, settings), timeout=25)
        except asyncio.TimeoutError:
            payload["ai_review"] = {"status": "unavailable", "observations": [], "note": "AI review timed out."}
        scope["external_processors"] = [f"{settings.llm_provider}:{settings.llm_model}"]
        scope["limits"].append("Source was sent to the configured AI provider with consent; redaction is best effort.")
        payload["result"]["external_processors"] = scope["external_processors"]
        payload["result"]["deterministic"] = False
    payload["review_scope"] = scope
    # Missing ownership is an explicit scope boundary in this route, not a code
    # defect. Heuristic signals remain in the report for investigation.
    actionable = [
        f for f in report.findings
        if f.severity.rank >= Severity.HIGH.rank
        and f.evidence_grade is EvidenceGrade.CONFIRMED
        and f.id != "compliance-owner-unverified"
    ]
    if not request.files and not request.system_prompt:
        actionable = []
    decision = "needs_fixes" if actionable else "needs_evidence"
    payload["review_decision"] = decision
    payload["priority_finding_ids"] = [f.id for f in actionable]
    encoded = canonical_json(payload)
    return {
        "mode": "source_review", "decision": decision, "scope": scope,
        "priority_finding_ids": payload["priority_finding_ids"],
        "report": payload, "report_json": encoded,
        "report_sha256": sha256(encoded.encode()).hexdigest(),
    }
