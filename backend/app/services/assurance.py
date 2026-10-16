"""A bounded control catalogue. Evidence presence never means control effectiveness."""
from __future__ import annotations

import re
from pydantic import BaseModel, ConfigDict, Field
from ..models import AgentArtifact


class ArchitectureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # These are declarations, deliberately kept separate from observed evidence.
    framework: str = Field(default="", max_length=120)
    model: str = Field(default="", max_length=120)
    mcp_servers: list[str] = Field(default_factory=list, max_length=30)
    delegates: list[str] = Field(default_factory=list, max_length=30)
    memory_stores: list[str] = Field(default_factory=list, max_length=30)
    allowed_domains: list[str] = Field(default_factory=list, max_length=50)
    controls: dict[str, bool] = Field(default_factory=dict, max_length=40)

    @classmethod
    def catalogue(cls):
        return [{"id": row[0], "name": row[1], "evidence_needed": row[3]} for row in CONTROLS]


# id, name, source indicators (discovery ONLY), next evidence to obtain
CONTROLS = [
    ("intent", "Intent & instruction hierarchy", r"system_prompt|system_instruction|role.*system", "System instructions, prohibited actions, and adversarial goal-conflict tests."),
    ("injection", "Prompt & tool-output injection", r"untrusted|prompt.injection|sanitize", "Malicious tool-output tests with observed tool calls and denied actions."),
    ("authorization", "Identity & authorization", r"require_auth|authorize|verify_signature|permission", "Negative authorization tests, signer policy, and version-bound ownership proof."),
    ("tools", "Tool permissions", r"tool|function_call", "Tool schemas, least-privilege allowlists, and execution-time permission checks."),
    ("mcp", "MCP servers & tool integrity", r"\bmcp\b|modelcontextprotocol", "Pinned MCP server/tool definitions, authentication, and tool-change rejection tests."),
    ("delegation", "Delegation & agent-to-agent trust", r"delegate|subagent|a2a|handoff", "Delegation chain, attenuation of scopes, depth limits, and confused-deputy tests."),
    ("memory", "Memory & RAG isolation", r"vector|embedding|retriev|memory", "Tenant-bound reads/writes, provenance labels, poisoning tests, and deletion evidence."),
    ("privacy", "Privacy & data exfiltration", r"redact|pii|personal.data|privacy", "Data classification, output redaction, retention policy, and exfiltration tests."),
    ("secrets", "Credentials & signing keys", r"secret|api_key|private_key|seed|keypair", "Secret-manager configuration and evidence that logs and tools cannot extract keys."),
    ("network", "Network & SSRF boundaries", r"requests\.|httpx\.|fetch\(|https?://", "Egress allowlist and private-address, redirect, and DNS-rebinding negative tests."),
    ("sandbox", "Code execution & sandboxing", r"exec\(|eval\(|subprocess|sandbox|container", "Isolated runtime configuration, resource quotas, and escape-resistance tests."),
    ("supply_chain", "Dependencies & build provenance", r"import |require\(|dependencies|lockfile", "Pinned lockfile, SBOM, vulnerability scan, and reproducible build provenance."),
    ("spending", "Spending & economic authority", r"transfer|payment|spend|balance|budget", "Integer-denominated asset limits and cumulative-budget concurrency tests."),
    ("approval", "Human approval & intent binding", r"approval|human_in|confirm|reviewer", "Approval bound to exact action hash, recipient, amount, expiry, and policy version."),
    ("replay", "Replay & idempotency", r"nonce|idempoten|sequence|replay", "Duplicate, concurrent, expired, and cross-network action rejection evidence."),
    ("resilience", "Failures & resource limits", r"timeout|retry|backoff|max_steps|rate_limit", "Timeout, retry storm, recursion, token budget, and dependency failure tests."),
    ("observability", "Trace integrity & accountability", r"audit_log|trace_id|telemetry|logging", "Redacted, tenant-bound, append-only action traces with integrity verification."),
    ("shutdown", "Emergency stop & revocation", r"kill_switch|emergency|revok|circuit_breaker|paused", "Kill-switch propagation test and proof that already queued actions are stopped."),
    ("stellar_auth", "Soroban invocation authorization", r"require_auth|soroban|invoke_contract", "Simulation, scoped invocation auth tree, network binding, and ledger readback."),
    ("stellar_assets", "Asset & trustline controls", r"trustline|issuer|clawback|sac|asset", "Exact asset issuer/contract, decimals, authorization and clawback policy evidence."),
    ("stellar_storage", "Contract TTL & restoration", r"extend_ttl|restore|persistent\(|archiv", "TTL renewal, restoration, and expired-state denial tests."),
    ("settlement", "Payment & report settlement", r"escrow|settle|refund|rep_hash", "Funded escrow, delivery commitment, evaluator acceptance, and timeout refund evidence."),
    ("credential", "Report lifecycle & revocation", r"certificate|credential|attestation|report_hash", "Version-bound report hash, issuer, expiry, revocation and changed-version tests."),
    ("compliance", "Policy & restricted-use boundaries", r"sanction|ofac|compliance|restricted", "Applicable policy review and timestamped screening evidence; no legal clearance inferred."),
]


def build_assurance(artifact: AgentArtifact, findings: list) -> dict:
    rows = []
    for control_id, name, pattern, needed in CONTROLS:
        refs = []
        for path, content in sorted(artifact.code_files.items()):
            for number, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line, re.I):
                    refs.append({"file": path, "line": number})
                    if len(refs) >= 4:
                        break
            if len(refs) >= 4:
                break
        if control_id == "intent" and artifact.system_prompt:
            refs.append({"file": "system_prompt", "line": 1})
        if control_id == "tools" and artifact.tools:
            refs.append({"file": "tool_manifest", "line": 1})
        rows.append({"id": control_id, "name": name,
                     "status": "needs_validation" if refs else "not_provided",
                     "source_references": refs, "evidence_needed": needed,
                     "runtime_verified": False})
    reviewed = sum(bool(row["source_references"]) for row in rows)
    blockers = [f.id for f in findings if f.severity.value in {"critical", "high"}
                and f.evidence_grade.value == "confirmed"]
    return {"schema": "agentveritas.assurance.v1", "controls": rows,
            "total": len(rows), "surfaces_located": reviewed, "runtime_verified": 0,
            "release_gate": "blocked" if blockers else "insufficient_evidence",
            "blocking_finding_ids": blockers,
            "method": "Source indicators locate review surfaces. They do not validate defenses.",
            "limitations": ["No finite audit proves all possible agent behavior.",
                            "Hidden services, model weights, runtime configuration and future changes are outside submitted source."]}
