"""Explicit insecure configuration findings, separate from missing-evidence checks."""
from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity


def architecture_findings(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    manifest = artifact.architecture
    if not manifest:
        return []
    controls = manifest.get("controls", {})
    checks = [
        (bool(manifest.get("mcp_servers")) and controls.get("mcp_authentication") is False,
         "mcp-auth", "MCP authentication explicitly disabled", "Require authenticated, allowlisted MCP servers and pin tool definitions."),
        (bool(manifest.get("delegates")) and controls.get("delegation_scope_attenuation") is False,
         "delegation", "Delegates can inherit excessive authority", "Attenuate scopes and budgets at every delegation; deny escalation and cap depth."),
        (bool(manifest.get("memory_stores")) and controls.get("memory_tenant_isolation") is False,
         "memory", "Memory tenant isolation explicitly disabled", "Enforce tenant identifiers in every storage query and test cross-tenant access."),
        ("*" in manifest.get("allowed_domains", []),
         "egress", "Unrestricted network egress declared", "Allow only required destinations and block private, metadata and redirected addresses."),
        (controls.get("human_approval") is False and any(t.requires_signature for t in artifact.tools),
         "approval", "Signing tools lack declared human approval", "Bind approval to exact amount, recipient, asset, network and expiring action digest."),
    ]
    return [Finding(id=f"security-architecture-{slug}", dimension=Dimension.SECURITY,
                    severity=Severity.HIGH, title=title,
                    detail="The submitted architecture explicitly declares this configuration. Deployment behavior is unverified.",
                    evidence=f"architecture declaration: {slug}", evidence_grade=EvidenceGrade.CONFIRMED,
                    remediation=fix, auditor=auditor, confidence=0.85)
            for triggered, slug, title, fix in checks if triggered]
