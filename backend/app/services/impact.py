"""Severity from stated impact facts, not from a reviewer's impression.

A model review names four facts about each defect: who can trigger it, what is at risk,
what must already be true, and where it applies. The severity follows from them by a
fixed table, so two reviews that agree on the facts agree on the severity, and a
reader can check the reasoning ("anyone -> funds -> no precondition -> critical").

Against hand audits of 23 Stellar agents, impression-based severities ran a level high
half the time; the facts behind them were usually right.
"""

from __future__ import annotations

from ..models import Severity

TRIGGERS = {
    "anyone": "any outside party: an open endpoint, a paid server the agent calls, content it reads",
    "agent_user": "anyone who can send the agent a request or a prompt",
    "authenticated_user": "a user holding an account, key or token the operator grants",
    "operator": "only the operator or developer, through their own configuration or command line",
    "no_attacker": "nobody: the defect does harm in normal use",
}
ASSETS = {
    "funds_or_keys": "funds move, a key or seed leaks, or the agent signs something it should not",
    "paid_service": "a paid resource is obtained without paying, or payment is taken without delivery",
    "other_users": "another user's data, account or session",
    "availability": "the agent or a contract stops working for others",
    "correctness": "wrong results or a broken feature, without loss to others",
}
PRECONDITIONS = {
    "none": "works in the agent's normal operation",
    "realistic": "needs a common setting, timing or user action",
    "unlikely": "needs an unusual setting, a compromised party or rare timing",
}
REACH = {
    "default": "the shipped default path",
    "optional": "an optional setting or mode",
    "example_or_test": "example, template, test or demo code",
    "not_wired": "code nothing calls",
}

_BASE = {"funds_or_keys": 4, "paid_service": 3, "other_users": 3, "availability": 2, "correctness": 2}
_TRIGGER = {"anyone": 0, "agent_user": 0, "authenticated_user": -1, "operator": -2, "no_attacker": -1}
_PRECONDITION = {"none": 0, "realistic": -1, "unlikely": -2}
_LEVELS = [Severity.LOW, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severity(trigger: str, asset: str, precondition: str, reach: str) -> Severity:
    """The severity the facts support. Unknown values raise KeyError."""
    if reach in {"example_or_test", "not_wired"}:
        return Severity.LOW  # latent: nothing in the shipped agent reaches it
    score = _BASE[asset] + _TRIGGER[trigger] + _PRECONDITION[precondition] - (1 if reach == "optional" else 0)
    if asset == "funds_or_keys" and trigger == "no_attacker":
        score = max(score, 3)  # losing money in normal use (paying twice on a retry) is high
    return _LEVELS[max(0, min(4, score))]


def explain(trigger: str, asset: str, precondition: str, reach: str) -> str:
    return (f"Severity from impact: triggered by {trigger.replace('_', ' ')}, puts {asset.replace('_', ' ')} at "
            f"risk, preconditions {precondition}, reached in {reach.replace('_', ' ')} code.")


def schema_properties() -> dict:
    return {
        "triggered_by": {"type": "string", "enum": list(TRIGGERS),
                         "description": "; ".join(f"{k}: {v}" for k, v in TRIGGERS.items())},
        "at_risk": {"type": "string", "enum": list(ASSETS),
                    "description": "; ".join(f"{k}: {v}" for k, v in ASSETS.items())},
        "preconditions": {"type": "string", "enum": list(PRECONDITIONS),
                          "description": "; ".join(f"{k}: {v}" for k, v in PRECONDITIONS.items())},
        "reached_in": {"type": "string", "enum": list(REACH),
                       "description": "; ".join(f"{k}: {v}" for k, v in REACH.items())},
    }
