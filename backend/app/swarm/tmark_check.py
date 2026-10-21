"""Compare what a repository's .tmark declares with what its code does.

A declaration never closes a risk. It turns a vague question ("is this safe?") into
specific claims (testnet only, recipients from an allowlist, a human approves each
payment) that the code either keeps or breaks; a broken claim is reported as such.
"""

from __future__ import annotations

import re

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity

#: Signing against the public network: its passphrase, or the SDK constants for it.
_MAINNET = re.compile(r"Public Global Stellar Network ; September 2015|Networks\.PUBLIC\b|"
                      r"Network\.PUBLIC_NETWORK_PASSPHRASE|PUBLIC_NETWORK_PASSPHRASE|horizon\.stellar\.org|"
                      r"mainnet\.sorobanrpc|soroban-rpc\.mainnet")
_CODE = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".rs")
#: What the code can do, against what .tmark says the agent signs.
_SIGNS_FOR = {"payment": "payments", "contract_invocation": "contract_calls", "account_control": "account_changes",
              "foreign_tx_signing": "foreign_transactions"}


def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: str, remediation: str,
             auditor: str, grade: EvidenceGrade = EvidenceGrade.CONFIRMED, confidence: float = 0.85) -> Finding:
    return Finding(id=fid, dimension=Dimension.INTENT, severity=severity, title=title, detail=detail,
                   evidence=evidence, evidence_grade=grade, remediation=remediation,
                   references=[".tmark v1 (docs/TMARK.md)"], auditor=auditor, confidence=confidence)


def tmark_findings(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    info = artifact.raw_metadata.get("tmark") or {}
    status = info.get("status")
    if status == "invalid":
        return [_finding(
            "intent-tmark-invalid", Severity.MEDIUM, "The .tmark file is not valid, so nothing in it was used",
            "A .tmark is read only when every field is valid; a half-read declaration could hide a limit or an "
            "authority the agent has. Fix the errors listed and audit again.",
            "; ".join(info.get("errors", [])[:8]),
            "Validate the file against https://touchmark-stellar.vercel.app/schemas/tmark-v1.json (or "
            "python scripts/tmark.py check) and fix each listed field.", auditor)]
    if status == "legacy":
        return [_finding(
            "intent-tmark-legacy", Severity.LOW, "The repository uses an older declaration file",
            "touchmark.json, agentveritas.json and veritas.json are still read, but they are free-form; .tmark "
            "has one checked structure, and only it can declare limits and approvals that the audit verifies.",
            "files: " + ", ".join(info.get("files", [])),
            "Replace the old file with a .tmark (python scripts/tmark.py init) and delete the old one.",
            auditor, grade=EvidenceGrade.INFERRED, confidence=0.9)]
    declared = info.get("declared")
    if status != "valid" or not declared:
        return []

    out: list[Finding] = []
    profile = artifact.code_profile or {}
    caps = profile.get("capabilities", {})
    controls = profile.get("controls", {})
    authority, limits = declared["authority"], declared.get("limits") or {}

    # Network: a testnet-only agent must not carry the public network's passphrase.
    if declared["agent"]["network"] == "testnet":
        hits = [f"{name}:{text.count(chr(10), 0, m.start()) + 1}" for name, text in artifact.code_files.items()
                if name.endswith(_CODE) for m in [_MAINNET.search(text)] if m]
        if hits:
            out.append(_finding(
                "intent-tmark-network-mismatch", Severity.HIGH, "Declared testnet only, but the code can use the public network",
                "The .tmark says the agent runs on testnet, and the code contains the public network passphrase or "
                "mainnet endpoints. A configuration switch, or input that picks the network, moves real funds.",
                "; ".join(hits[:5]),
                "Remove mainnet constants, or declare network mainnet/both and the limits that apply there.", auditor))

    # Authority: what the code can sign, against what is declared.
    holds = any(c in caps for c in ("key_custody", "stellar_signing", "tx_submission"))
    missing = sorted({sign for cap, sign in _SIGNS_FOR.items() if cap in caps} - set(authority["signs"]))
    if (holds and not authority["holds_keys"]) or missing:
        where = "; ".join(loc for cap in ("key_custody", "stellar_signing", *_SIGNS_FOR) for loc in caps.get(cap, [])[:1])
        out.append(_finding(
            "intent-tmark-authority-mismatch", Severity.HIGH, "The code has more Stellar authority than the .tmark declares",
            ("The .tmark says the agent holds no key, but the code loads one or signs. " if holds and not authority["holds_keys"] else "")
            + (f"The code can also sign: {', '.join(missing)}, which authority.signs does not list." if missing else ""),
            where, "Declare every authority the code has, or remove the code paths that use it.", auditor))

    # Limits: each declared control must exist in the code that pays.
    moves = any(c in caps for c in ("payment", "tx_submission", "contract_invocation"))
    broken = []
    if moves and limits.get("recipients") == "allowlist" and not controls.get("allowlist"):
        broken.append("recipients: allowlist (no recipient allowlist is enforced in code)")
    if moves and limits.get("per_payment") and not controls.get("amount_cap"):
        broken.append(f"per_payment {limits['per_payment']['amount']} {limits['per_payment']['asset']} (no amount cap in code)")
    if moves and limits.get("human_approval") in {"always", "above_limit"} and not controls.get("approval"):
        broken.append(f"human_approval: {limits['human_approval']} (no approval gate in code)")
    if moves and limits.get("per_day"):
        cumulative = re.compile(r"spent|daily|per_?day|budget|remaining|allowance|window", re.I)
        pay_files = {loc.split(":")[0] for cap in ("payment", "tx_submission") for loc in caps.get(cap, [])}
        if not any(cumulative.search(artifact.code_files.get(f, "")) for f in pay_files):
            broken.append(f"per_day {limits['per_day']['amount']} {limits['per_day']['asset']} (no running total near the payment code)")
    if broken:
        out.append(_finding(
            "intent-tmark-limit-not-enforced", Severity.HIGH, "A limit the .tmark declares is not enforced by the code",
            "Users read the .tmark to decide how far to trust the agent. Each limit listed here is promised there but "
            "missing where the agent pays, so it does not hold.",
            "; ".join(broken), "Enforce each declared limit in the code that builds or signs the payment, and test it.",
            auditor, grade=EvidenceGrade.INFERRED, confidence=0.8))
    return out
