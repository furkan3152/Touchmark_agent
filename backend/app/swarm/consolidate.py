"""One finding per defect, at the severity the evidence supports.

Compared with hand audits of 23 Stellar agents, the critical and high findings were the
least reliable layer. Their noise came from three sources: the same defect reported twice
(a model challenge pass repeating an earlier pass, or the model restating a rule finding),
absence notes ("no spend policy") restating a concrete finding, and severities one level
above the hand audit. This module removes the first two after verification; the third is
handled where verification is applied (orchestrator._apply_verification).
"""

from __future__ import annotations

import re

from ..models import Finding, FindingKind, Severity

_LOC = re.compile(r"([\w./@-]+\.[A-Za-z0-9]+):(\d+)")
#: Concrete findings that show a payment can go where it should not. When one exists, the
#: absence notes below restate it.
_CONCRETE_SPEND = re.compile(
    r"^security-path-(?:untrusted-to-financial-sink|x402-payment-unbounded|external-transaction-signed|"
    r"control-not-blocking)$|^security-declared-limit-not-enforced$|^intent-tmark-limit-not-enforced$|"
    r"-ai-(?:unauthorized-payment|control-bypass|economic-loss|foreign-transaction-signing)-\d+$")
#: Checklist notes that restate a missing spend control. In two hand-checked rounds over 23
#: agents, 102 of them were labelled: 66 generic, 23 duplicate, 10 false, 1 overstated, 2 true.
_ABSENCE = {"economic-no-spend-policy", "security-unbounded-spend", "compliance-no-human-oversight",
            "intent-full-autonomy-over-funds"}
#: The model-review categories that describe the same defect as a data-flow rule.
_RULE_TWINS = {
    "security-path-untrusted-to-financial-sink": {"unauthorized-payment", "control-bypass", "economic-loss"},
    "security-path-x402-payment-unbounded": {"unauthorized-payment", "economic-loss"},
    "security-path-external-transaction-signed": {"foreign-transaction-signing"},
    "security-path-key-signs-arbitrary-bytes": {"foreign-transaction-signing"},
    "security-path-untrusted-to-command": {"code-execution"},
    "security-path-untrusted-to-network": {"ssrf"},
    "security-path-untrusted-to-file": {"path-traversal"},
    "security-path-secret-to-model": {"secret-exposure"},
    "security-path-secret-via-model": {"secret-exposure"},
    "security-path-secret-to-exfiltration": {"secret-exposure"},
    "security-path-untrusted-account-control": {"account-takeover", "control-bypass"},
}


def _category(fid: str) -> str:
    """security-ai-control-bypass-3 -> control-bypass; rule ids are their own category."""
    m = re.search(r"-ai-([a-z-]+?)-\d+$", fid)
    return m.group(1) if m else fid


def _locations(f: Finding) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in _LOC.finditer(f.evidence or "")]


def _same_place(a: Finding, b: Finding, slack: int = 3) -> bool:
    la, lb = _locations(a), _locations(b)
    return bool(la and lb) and la[0][0] == lb[0][0] and abs(la[0][1] - lb[0][1]) <= slack


def merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """A model finding at the same place and of the same kind as one already kept is the
    same defect reported again: it is folded into the kept one, never dropped silently.
    Rule findings are never folded into each other, and a rule finding absorbs a model
    finding at its own location (corroborated by two independent methods)."""
    kept: list[Finding] = []
    for f in findings:
        if not f.is_risk or "-ai-" not in f.id:
            kept.append(f)
            continue
        # The same line and kind for two model findings (a later pass repeating an earlier
        # one); for a rule finding, a nearby line and the matching kind of defect.
        twin = next((k for k in kept if k.is_risk and (
            (_same_place(k, f, 0) and _category(k.id) == _category(f.id)) if "-ai-" in k.id
            else (_same_place(k, f) and _category(f.id) in _RULE_TWINS.get(k.id, set())))), None)
        if twin is None:
            kept.append(f)
            continue
        merged = twin.model_copy(update={
            "severity": max(twin.severity, f.severity, key=lambda s: s.rank) if "-ai-" in twin.id else twin.severity,
            "detail": twin.detail + f" Also reported as {f.id}: {f.title}.",
            "confidence": max(twin.confidence, f.confidence) if "-ai-" in twin.id else min(1.0, twin.confidence + 0.05),
            "verified": twin.verified or f.verified,
        })
        kept[kept.index(twin)] = merged
    return kept


def fold_absence_notes(findings: list[Finding]) -> list[Finding]:
    """'No spend policy', 'no declared limit', 'no human oversight' and 'full autonomy'
    restate a concrete payment finding when one exists: they become low checklist warnings
    that point to it, so the concrete defect carries the severity. Without a concrete
    finding they stay as they are."""
    concrete = [f for f in findings if f.is_risk and _CONCRETE_SPEND.search(f.id)
                and f.severity.rank >= Severity.MEDIUM.rank]
    if not concrete:
        return findings
    lead = max(concrete, key=lambda f: f.severity.rank)
    return [f.model_copy(update={"kind": FindingKind.WARNING, "severity": Severity.LOW,
                                 "detail": f.detail + f" The concrete defect is reported as {lead.id}."})
            if f.id in _ABSENCE and f.kind is not FindingKind.EVIDENCE_GAP else f for f in findings]


def consolidate(findings: list[Finding]) -> list[Finding]:
    return fold_absence_notes(merge_duplicates(findings))
