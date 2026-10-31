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


def test_a_passed_deadline_leaves_findings_unverified_without_calling_the_model():
    import time
    client = Scripted([])
    verifier = FindingVerifier(client, model="m", fallbacks=False)
    verifier.deadline = time.monotonic() - 1
    result = asyncio.run(verifier.verify([finding()], FILES))
    assert result.results[0].note == "timeout" and not client.requests


# ------------------------------------------------------- partial claims and unchecked weight
TERNARY = {"src/classic.ts": ("export class Classic {\n  constructor(serverUrl) {\n"
                              "    const network = serverUrl.includes('testnet')\n      ? 'testnet'\n"
                              "      : serverUrl.includes('futurenet')\n        ? 'futurenet'\n        : 'public';\n"
                              "    this.config = CONFIG[network];\n  }\n}\n")}


def network_finding():
    return finding(id="security-network-fallback-mainnet-b49a9b3a", severity=Severity.MEDIUM,
                   title="An unrecognised network value signs for mainnet",
                   evidence="src/classic.ts:3 `const network = serverUrl.includes('testnet')`")


def test_a_quote_of_a_statement_spread_over_several_lines_is_found():
    client = Scripted([reply(call("submit_verdict", verdict="partial", reviewed_severity="low", file="src/classic.ts",
                                  line=3, evidence_quote="const network = serverUrl.includes('testnet') ? 'testnet' : "
                                                         "serverUrl.includes('futurenet') ? 'futurenet' : 'public';",
                                  reason="right for classic.ts, wrong for core.ts"))])
    result = asyncio.run(FindingVerifier(client, model="m", fallbacks=False).verify([network_finding()], TERNARY))
    v = result.results[0]
    assert v.verdict == "partial" and v.quote_verified and v.line == 3


def test_reasoning_that_confirms_part_of_a_claim_is_partial_even_when_the_quote_is_off():
    client = Scripted([reply(call("submit_verdict", verdict="partial", reviewed_severity="low", file="src/classic.ts",
                                  line=3, evidence_quote="const net = pickNetwork(serverUrl)",
                                  reason="The claim is right for classic.ts but wrong for core.ts."))])
    result = asyncio.run(FindingVerifier(client, model="m", fallbacks=False).verify([network_finding()], TERNARY))
    v = result.results[0]
    assert v.verdict == "partial" and not v.quote_verified and "recorded as partial" in v.note


def _scored(verdict: dict):
    from backend.app.models import AuditorVerdict
    from backend.app.swarm.orchestrator import AuditSwarm
    f = network_finding()
    base = AuditorVerdict(auditor="security", dimension=Dimension.SECURITY, score=50.0, findings=[f])
    out = AuditSwarm._apply_disputes([base], {"results": [{"finding_id": f.id, **verdict}]})[0].findings[0]
    return f, out


def test_an_unquoted_partial_is_recorded_but_changes_no_severity():
    before, after = _scored({"verdict": "partial", "quote_verified": False, "reviewed_severity": "low",
                             "quote": "x", "reason": "partly"})
    assert after.verified == "partial" and after.severity is before.severity and after.penalty == before.penalty


def test_an_unverifiable_claim_does_not_count_at_full_weight():
    before, after = _scored({"verdict": "unverifiable", "quote_verified": False, "reviewed_severity": "",
                             "note": "", "reason": "the file is not in the bundle"})
    assert after.verified == "unverifiable" and after.is_risk and after.penalty < before.penalty
    # A check that did not finish (timeout, provider error) is not a verdict: full weight.
    _, timed_out = _scored({"verdict": "unverifiable", "quote_verified": False, "note": "timeout"})
    assert timed_out.penalty == before.penalty
