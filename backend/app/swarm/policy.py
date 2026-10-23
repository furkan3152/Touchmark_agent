"""Stellar denetim politikası, commitment'ler ve kanıt güvencesi."""

from __future__ import annotations

import hashlib
import json
import re

from ..models import AgentArtifact, AssuranceLevel, EvidenceGrade, Finding, FindingKind, Severity
from ..stellar.chain_identity import chain_identity

AUDIT_SCHEMA_VERSION = "agentveritas.audit.v2"
AUDIT_POLICY_VERSION = "agentveritas.stellar.policy.2026-10-23.1"


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
        mode="json", exclude={"id", "created_at", "raw_metadata", "code_profile", "chain_authority"}
    )
    payload = {"policy": AUDIT_POLICY_VERSION, "artifact": artifact_payload}
    # The deployed code and authority that were read bind the credential too (not the read
    # ledger, balances or TTLs: an unchanged agent keeps its commitment).
    identity = chain_identity(artifact.chain_authority)
    if identity:
        payload["chain_identity"] = "sha256:" + hashlib.sha256(_canonical(identity)).hexdigest()
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


# --------------------------------------------------------------------------- risk vs. evidence
#: Rules that report missing supporting evidence rather than an observed defect.
#: They lower assurance and can prevent a pass, but never the risk score. A rule
#: belongs here only when it fires on the *absence* of documentation, metadata or
#: prompt wording; anything derived from code, tools or chain data stays a risk.
EVIDENCE_GAP_RULES = frozenset({
    "compliance-no-ai-disclosure", "compliance-owner-unverified", "compliance-no-record-keeping",
    "compliance-wallet-screening-unavailable", "compliance-privacy-mode-off",
    "economic-no-wallet", "economic-no-chain-data",
    "intent-no-declared-intent", "intent-no-system-prompt", "intent-thin-system-prompt",
    "intent-no-planning-structure", "intent-no-uncertainty-guard", "intent-no-scope-boundary",
    "intent-scenario-failures", "intent-tmark-invalid", "intent-tmark-legacy",
    "provenance-missing-lockfile", "provenance-no-release-pipeline", "provenance-license-missing",
    "provenance-sbom-missing",
    "reliability-no-endpoint", "reliability-no-error-handling", "reliability-no-cost-controls",
    "security-no-auditable-surface", "security-no-isolation", "security-all-tools-networked",
    "security-source-analysis-incomplete", "compliance-pii-without-safeguards",
    "stellar_native-rules-incomplete-advisories", "stellar_native-rules-incomplete-rpc-semantics",
    "security-rules-incomplete-network-binding", "security-rules-incomplete-web-auth",
    "stellar_native-onchain-account-missing", "stellar_native-onchain-agent-key-undeclared",
    "stellar_native-onchain-identity-unbound", "stellar_native-onchain-source-unbound",
    "stellar_native-onchain-contract-code-unavailable", "stellar_native-onchain-contract-code-unresolved",
    "stellar_native-dep-advisory-table-stale",
})
#: Autonomy without a human approval step. Operators may run agents unattended on
#: purpose, so these are warnings: a small score penalty, never a failing decision.
#: The authority limits themselves (spend caps, allowlists, bounds) remain risks.
WARNING_RULES = frozenset({"compliance-no-human-oversight", "intent-full-autonomy-over-funds"})
#: Gaps that make a pass impossible: the reviewed scope itself is incomplete.
BLOCKING_GAPS = frozenset({"security-source-analysis-incomplete", "security-no-auditable-surface",
                           "security-controls-unverifiable", "stellar_native-onchain-source-unbound",
                           "stellar_native-onchain-contract-code-unresolved",
                           # A rule family that failed on this source (BaseAuditor.contained).
                           "stellar_native-rules-incomplete-advisories", "stellar_native-rules-incomplete-rpc-semantics",
                           "security-rules-incomplete-network-binding", "security-rules-incomplete-web-auth"})

#: Rules that assert a control is absent. They are only evidence when the analyser can
#: see controls in the language that holds the capability (Python data flow today).
ABSENCE_OF_CONTROL_RULES = frozenset({
    "economic-no-spend-policy", "compliance-no-human-oversight", "intent-full-autonomy-over-funds",
    "security-unbounded-spend", "security-path-controls-not-enforced",
})
#: Rules that compare the code with a declaration; without any declaration they are gaps.
DECLARATION_RULES = frozenset({"security-undeclared-capability", "intent-undeclared-financial-capability"})
_STATIC_ATTACK = re.compile(r"^security-a-\d+$")

#: Lowest score a passing review can have. The judge caps every report with an
#: actionable risk below this value, and the credential contract enforces it.
PASS_SCORE = 65.0


def classify_finding(finding: Finding) -> Finding:
    """Attach the policy kind. Static attack hypotheses were never executed."""
    if finding.kind is FindingKind.EVIDENCE_GAP:
        return finding  # a rule that already established it is a gap stays one
    gap = finding.id in EVIDENCE_GAP_RULES or bool(_STATIC_ATTACK.match(finding.id))
    if gap:
        kind = FindingKind.EVIDENCE_GAP
    elif finding.id in WARNING_RULES:
        kind = FindingKind.WARNING
    else:
        kind = FindingKind.RISK
    return finding if finding.kind is kind else finding.model_copy(update={"kind": kind})


#: Model-review categories where a working way around a payment or security control, or to
#: funds, accounts or other users' data, is claimed. Conditional exposures (an SSRF, a path,
#: a value that may hold a key) are left to their severity: on agents judged safe by hand,
#: confirmed medium findings of that kind were real but not disqualifying.
BYPASS_CATEGORIES = re.compile(
    r"-ai-(?:control-bypass|unauthorized-payment|foreign-transaction-signing|economic-loss|replay-or-idempotency|"
    r"account-takeover|cross-user-access|code-execution)-\d+$")


#: Rule findings that show a payment accepted, settled or sponsored without the check that
#: makes it a payment: x402 and MPP server rules, settlement and hash-proof binding, fee
#: sponsorship paths, an MPP release whose server accepts unsigned hash credentials, a
#: received payment matched by asset code alone, and a queued transaction counted as paid.
#: Matched by pattern, so each rule's stable-id suffix is covered.
PAYMENT_BYPASS_RULES = re.compile(
    r"^security-(?:x402|mpp|path-sponsor)-|^stellar_native-dep-mpp-unsigned-hash-push-|"
    r"^security-asset-checked-by-code-only$|^stellar_native-rpc-send-treated-as-final-|"
    r"(?:^|-)(?:x402-settle-unchecked|x402-verify-without-settle|x402-requirements-from-payer|tx-hash-proof-unbound)"
    r"(?:-[0-9a-f]{8})?$")


def payment_bypass(finding: Finding) -> bool:
    return bool(BYPASS_CATEGORIES.search(finding.id) or PAYMENT_BYPASS_RULES.search(finding.id))


def actionable_risks(findings: list[Finding]) -> list[Finding]:
    """High or critical risks backed by source, configuration or live evidence, and medium
    bypasses the independent verifier confirmed at the quoted line: a confirmed way around a
    payment or security control rules out a pass, whatever severity the review gave it."""
    return [
        f for f in findings
        if f.is_risk and f.evidence_grade is not EvidenceGrade.SIMULATED
        and (f.severity.rank >= Severity.HIGH.rank
             or (f.severity is Severity.MEDIUM and f.verified == "confirmed" and payment_bypass(f)))
    ]


def unverified_bypasses(findings: list[Finding]) -> list[Finding]:
    """Medium payment bypasses that no verifier checked (it did not run, or could not decide).
    Unchecked, they can be neither credited nor dismissed, so they hold a pass back."""
    return [f for f in findings if f.is_risk and f.severity is Severity.MEDIUM
            and f.evidence_grade is not EvidenceGrade.SIMULATED
            and f.verified in {"", "unverifiable"} and payment_bypass(f)]


def warnings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind is FindingKind.WARNING]


def review_decision(findings: list[Finding], coverage: dict, score: float) -> str:
    """One decision rule shared by the Studio, official audits and credentials.

    needs_fixes    an actionable risk exists, or accumulated risks pushed the score below a pass
    needs_evidence no actionable risk, but prompt, tools and implementation were not all reviewed,
                   or a medium payment bypass was never verified
    pass           no actionable risk with the full core surface reviewed
    """
    if actionable_risks(findings) or score < PASS_SCORE:
        return "needs_fixes" if any(f.is_risk for f in findings) else "needs_evidence"
    if (not coverage.get("deep_core_complete") or any(f.id in BLOCKING_GAPS for f in findings)
            or unverified_bypasses(findings)):
        return "needs_evidence"
    return "pass"
