"""Prompt text scanning helpers: word-boundary and negation aware.

Auditors look for policy signals in the prompt text. A plain substring search gives
two false negatives: ``limit`` inside ``"trust unlimited issuers"`` counts as a
spending policy, and ``private`` inside ``"ask for their private key"`` counts as
evidence of execution protection.

Rules:

1. Word boundary: searching for ``limit`` does not match ``unlimited``.
2. Anti-signal: phrases such as ``no limit``, ``unlimited`` or ``there are no spending
   limits`` do not just cancel the signal, they count as evidence the other way.
3. Multi-word phrases match regardless of the amount of whitespace between words.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Phrases that announce the absence of a policy. When present there is no need to
#: look for signals: the agent says outright that it runs without limits.
#: The last two are Turkish ("limitless", "unlimited") so Turkish prompts are covered.
NEGATION_PATTERNS = (
    r"\bunlimited\b",
    r"\bno\s+(?:spend(?:ing)?|budget|daily|transfer)?\s*limits?\b",
    r"\bthere\s+is\s+no\s+\w*\s*limit\b",
    r"\bthere\s+are\s+no\s+\w*\s*limits?\b",
    r"\bwithout\s+(?:any\s+)?limits?\b",
    r"\bno\s+cap\b",
    r"\bignore\s+(?:any\s+)?(?:policy|policies|limits?|rules?)\b",
    r"\bat\s+all\s+costs\b",
    r"\bfull\s+wallet\s+balance\b",
    r"\bmax_?uint\b",
    r"\blimitsiz\b",
    r"\bsınırsız\b",
)

_NEGATION_RE = re.compile("|".join(NEGATION_PATTERNS), re.IGNORECASE)


def _phrase_pattern(phrase: str) -> str:
    """Turn a multi-word phrase into a word-bounded regex with flexible whitespace."""
    parts = [re.escape(p) for p in phrase.split()]
    return r"\b" + r"\s+".join(parts) + r"\b"


def has_negation(text: str) -> bool:
    """Does the text explicitly announce that there is no policy?"""
    return bool(_NEGATION_RE.search(text or ""))


def negations_found(text: str) -> list[str]:
    """Return the anti-signals found (written into the finding as evidence)."""
    return sorted({m.group(0).strip().lower() for m in _NEGATION_RE.finditer(text or "")})


def find_signals(text: str, signals: tuple[str, ...]) -> list[str]:
    """Signal search that respects word boundaries.

    The ``limit`` signal does not match inside ``unlimited``; that was the costliest
    mistake of a naive ``in`` search.
    """
    text = text or ""
    return [s for s in signals if re.search(_phrase_pattern(s), text, re.IGNORECASE)]


@dataclass(frozen=True)
class SignalScan:
    """Scan result for one signal family."""

    matched: list[str]
    negations: list[str]

    @property
    def present(self) -> bool:
        """Is the signal *validly* present?

        With an anti-signal the signal does not count: "trust unlimited issuers" is
        not evidence of a spending policy.
        """
        return bool(self.matched) and not self.negations

    @property
    def explicitly_absent(self) -> bool:
        """Is the absence of a policy explicitly announced? (calls for a heavier penalty)"""
        return bool(self.negations)

    def reason(self, found: str, missing: str) -> str:
        if self.negations:
            return f"policy explicitly rejected: {', '.join(self.negations)}"
        return f"{found}: {', '.join(self.matched)}" if self.matched else missing


def scan(text: str, signals: tuple[str, ...]) -> SignalScan:
    """Scan a signal family, aware of negation."""
    return SignalScan(matched=find_signals(text, signals), negations=negations_found(text))
