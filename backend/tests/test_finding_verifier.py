"""Independent finding verification: quotes are checked, reasoning is withheld, failures never remove findings."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from backend.app.models import Dimension, Finding, Severity
from backend.app.services.finding_verifier import FindingVerifier, claim_locations, selectable

FILES = {"src/pay.ts": "export async function pay(args) {\n  const to = args.to;\n  tx.sign(keypair);\n  return submit(tx);\n}\n"}


def call(name, **args):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}_{id(args)}", name=name, input=args)


def reply(*blocks, stop="tool_use"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5,
                                                 cache_read_input_tokens=0, cache_creation_input_tokens=0))


class Scripted:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn


def finding(**kw):
    base = dict(id="security-path-untrusted-to-financial-sink", dimension=Dimension.SECURITY, severity=Severity.CRITICAL,
                title="External input reaches a Stellar transaction boundary",
                detail="SECRET REASONING: the model controls the destination.", evidence="src/pay.ts:3 `tx.sign(keypair);`")
    return Finding(**{**base, **kw})


def run(turns, f=None):
    client = Scripted(turns)
    verifier = FindingVerifier(client, model="m", fallbacks=False)
    result = asyncio.run(verifier.verify([f or finding()], FILES))
    return result, client


def test_confirmation_with_a_real_quote_is_kept_and_reasoning_is_withheld():
    result, client = run([
        reply(call("read_source", path="src/pay.ts", start_line=1, end_line=5)),
        reply(call("submit_verdict", verdict="confirmed", reviewed_severity="critical", file="src/pay.ts", line=3,
                   evidence_quote="tx.sign(keypair);", reason="destination comes from args")),
    ])
    v = result.results[0]
    assert v.verdict == "confirmed" and v.quote_verified and v.reviewed_severity == "critical"
    first = client.requests[0]["messages"][0]["content"]
    assert "src/pay.ts:3" in first and "SECRET REASONING" not in first
    assert result.summary()["agreement"] == 1.0


def test_a_verdict_with_an_invented_quote_becomes_unverifiable():
    result, _ = run([reply(call("submit_verdict", verdict="refuted", reviewed_severity="none", file="src/pay.ts",
                                line=3, evidence_quote="if (!ALLOWLIST.has(to)) throw", reason="allowlisted"))])
    v = result.results[0]
    assert v.verdict == "unverifiable" and not v.quote_verified and "rejected" in v.note


def test_provider_failure_leaves_the_finding_unverified():
    result, _ = run([RuntimeError("down")])
    assert result.results[0].verdict == "unverifiable" and "failed" in result.results[0].note


def test_selection_and_locations():
    gap = finding(id="g", severity=Severity.HIGH, kind="evidence_gap")
    low = finding(id="l", severity=Severity.LOW)
    assert [f.id for f in selectable([gap, low, finding()])] == ["security-path-untrusted-to-financial-sink"]
    assert claim_locations("a/b.ts:12 `x`; c.py:3 y") == [("a/b.ts", 12), ("c.py", 3)]


def test_confirmed_at_a_lower_severity_is_partial_and_nearby_quotes_count():
    result, _ = run([reply(call("submit_verdict", verdict="confirmed", reviewed_severity="medium", file="src/pay.ts",
                                line=1, evidence_quote="tx.sign(keypair);", reason="real but bounded elsewhere"))])
    v = result.results[0]
    assert v.verdict == "partial" and v.quote_verified and v.line == 3 and "lower severity" in v.note


def test_stellar_reference_is_available():
    result, client = run([
        reply(call("stellar_reference", topic=sorted(__import__("backend.app.stellar.knowledge", fromlist=["TOPICS"]).TOPICS)[0])),
        reply(call("submit_verdict", verdict="unverifiable", reviewed_severity="none", file="", line=0,
                   evidence_quote="", reason="not decidable")),
    ])
    assert client.requests[1]["messages"][2]["content"][0]["content"] != "Unknown tool."
