"""Stellar denetim politikası, commitment'ler ve kanıt güvencesi."""

from __future__ import annotations

import hashlib
import json

from ..models import AgentArtifact, AssuranceLevel, EvidenceGrade, Finding

AUDIT_SCHEMA_VERSION = "agentveritas.audit.v2"
AUDIT_POLICY_VERSION = "agentveritas.stellar.policy.2026-08-31.4"


def audit_surface_coverage(artifact: AgentArtifact) -> dict[str, object]:
    """Expose which independent evidence surfaces a deep audit inspected."""
    implementation = any(
        name.lower().endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".sol"))
        for name in artifact.code_files
    )
    surfaces = {
        "behavioral_contract": bool(artifact.system_prompt.strip()),
        "tool_permissions": bool(artifact.tools),
        "implementation": implementation,
        "supply_chain": bool(artifact.dependencies),
        "runtime_endpoint": bool(artifact.endpoint_url),
        "identity": bool(artifact.owner_verified),
        "chain_history": bool(
            (artifact.agent_wallet or artifact.agent_contract_id)
            and artifact.onchain.data_source in ("indexer", "rpc")
        ),
    }
    core = ("behavioral_contract", "tool_permissions", "implementation")
    core_present = sum(bool(surfaces[name]) for name in core)
    present = sum(bool(value) for value in surfaces.values())
    return {
        "surfaces": surfaces,
        "present": present,
        "total": len(surfaces),
        "ratio": round(present / len(surfaces), 3),
        "deep_core_present": core_present,
        "deep_core_total": len(core),
        "deep_core_complete": core_present == len(core),
        "gaps": [name for name, available in surfaces.items() if not available],
    }


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def artifact_commitment(artifact: AgentArtifact) -> str:
    """Denetlenen girdiyi yerel kimlik ve ham metadata'dan bağımsız bağlar."""
    artifact_payload = artifact.model_dump(
        mode="json", exclude={"id", "created_at", "raw_metadata"}
    )
    payload = {"policy": AUDIT_POLICY_VERSION, "artifact": artifact_payload}
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def finding_set_commitment(findings: list[Finding]) -> str:
    """Tüm finding içeriğini commit eder; hassas metni rapora açık etmez."""
    payload = {
        "policy": AUDIT_POLICY_VERSION,
        "findings": [
            finding.model_dump(mode="json")
            for finding in sorted(findings, key=lambda item: item.id)
        ],
    }
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def evidence_summary(findings: list[Finding]) -> dict[str, int]:
    summary = {grade.value: 0 for grade in EvidenceGrade}
    for finding in findings:
        summary[finding.evidence_grade.value] += 1
    return summary


def assurance_level(artifact: AgentArtifact, findings: list[Finding]) -> AssuranceLevel:
    """Badge'den ayrı olarak kimlik ve Stellar ledger kanıtını derecelendirir."""
    if artifact.onchain.data_source == "simulated" or any(
        finding.evidence_grade is EvidenceGrade.SIMULATED for finding in findings
    ):
        return AssuranceLevel.SIMULATED
    if not artifact.owner_verified:
        return AssuranceLevel.PARTIAL
    if (artifact.agent_wallet or artifact.agent_contract_id) and artifact.onchain.data_source not in {
        "indexer",
        "rpc",
    }:
        return AssuranceLevel.PARTIAL
    return AssuranceLevel.VERIFIED
