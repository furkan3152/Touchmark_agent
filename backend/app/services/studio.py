"""Stateless source review. No uploaded program is imported or executed."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import PurePosixPath
from uuid import uuid4
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config import Settings
from ..models import AgentArtifact, AuditTier, EvidenceGrade, Severity, SourceKind, ToolSpec
from ..reporting.generator import canonical_json, report_to_dict
from ..swarm import AuditSwarm
from ..stellar.identity import is_valid_stellar_address


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=12, max_length=2000)
    system_prompt: str = Field(default="", max_length=12000)
    files: dict[str, str] = Field(default_factory=dict, max_length=12)
    tools: list[ToolSpec] = Field(default_factory=list, max_length=20)
    dependencies: list[str] = Field(default_factory=list, max_length=100)
    stellar_address: str = Field(default="", max_length=56)
    network: Literal["testnet", "mainnet"] = "testnet"
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
            path = PurePosixPath(name)
            if (
                len(name) > 160 or not name or path.is_absolute() or "\\" in name
                or any(part.startswith(".") for part in path.parts)
                or ":" in name or name.lower() in seen
                or path.suffix.lower() not in {".py", ".js", ".ts", ".rs", ".go", ".json", ".md", ".txt", ".toml", ".yaml", ".yml"}
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
    # Copy explicit settings, then disable every external integration. Server .env
    # cannot silently turn a free source review into an external upload or probe.
    isolated = settings.model_copy(update={
        "stellar_network": "offline", "stellar_rpc_url": "", "stellar_horizon_url": "",
        "llm_provider": "", "llm_api_key": "", "pinata_jwt": "",
        "screening_provider": "none", "screening_api_key": "",
        "enable_ofac_screening": False, "enable_active_agent_probes": False,
        "enable_audit_escrow": False,
    })
    artifact = AgentArtifact(
        source_kind=SourceKind.UPLOAD if request.files or request.system_prompt else SourceKind.ONCHAIN_ADDRESS,
        source_ref=f"studio:{request.network}:{request.source_reference or request.stellar_address or 'submitted-bundle'}",
        name=request.name, description=request.purpose,
        system_prompt=request.system_prompt, code_files=request.files,
        tools=request.tools, dependencies=request.dependencies,
        agent_wallet=request.stellar_address if request.stellar_address.startswith("G") else "",
        agent_contract_id=request.stellar_address if request.stellar_address.startswith("C") else "",
        owner_verification_note="Not checked during source review.",
    )
    report = await AuditSwarm(isolated).run(artifact, uuid4().hex, AuditTier.DEEP)
    payload = report_to_dict(report, artifact)
    payload["subject"] = {
        "stellar_address": request.stellar_address, "network": request.network,
        "source_reference": request.source_reference, "association_verified": False,
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
