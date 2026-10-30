"""MEV scope: no slippage finding without price exposure.

Regression test. Tying the MEV check to ``has_funds`` (any tool with signing authority)
gave a payroll agent making plain USDC transfers "No MEV/slippage protection" (HIGH,
CONFIRMED). That triggered `CAUTION_CEILING` and kept every production-quality corpus
agent at exactly 84.0, below the SAFE badge.

Scope comes from capability: if the domain or the tools' names and descriptions do not
indicate swapping, the check is out of scope."""

from __future__ import annotations

from backend.app.models import AgentArtifact, OnchainActivity, Severity, SourceKind, ToolSpec
from backend.app.swarm.economic import EconomicAuditor

PAYROLL_PROMPT = (
    "You are Stellar Payroll. Scope: execute approved payroll batches in USDC on Stellar only; "
    "refuse any request outside payroll and never trade, swap or lend. "
    "Risk limits: maximum 5000 USDC per batch, 25000 USDC per day."
)


def _artifact(**kw) -> AgentArtifact:
    base = dict(
        name="agent",
        source_kind=SourceKind.REPO,
        source_ref="local",
        agent_wallet="GAASNN4DHLDRT3UAVXGO57ZCIKB6PERE6R2UYSSDTAS2QC54GNBNF7ND",
        onchain=OnchainActivity(data_source="indexer", tx_count=40, is_contract=False),
    )
    base.update(kw)
    return AgentArtifact(**base)


def _mev_findings(settings, run, artifact) -> list:
    verdict = run(EconomicAuditor(settings).run(artifact))
    return [f for f in verdict.findings if f.id.endswith("no-mev-protection")]


def test_plain_transfer_agent_gets_no_mev_finding(settings, run):
    """A payroll agent does not swap: no slippage finding may be produced."""
    artifact = _artifact(
        domain="payments",
        system_prompt=PAYROLL_PROMPT,
        tools=[
            ToolSpec(
                name="batch_pay",
                description="Send a batch of USDC transfers with memo and idempotency key",
                requires_signature=True,
                spend_limit_usdc=5000.0,
            )
        ],
    )
    assert _mev_findings(settings, run, artifact) == []


def test_scope_gap_is_recorded_not_hidden(settings, run):
    """A skipped check is not silent: E-02 is recorded as out of scope."""
    artifact = _artifact(
        domain="payments",
        system_prompt=PAYROLL_PROMPT,
        tools=[ToolSpec(name="batch_pay", description="Send USDC", requires_signature=True)],
    )
    verdict = run(EconomicAuditor(settings).run(artifact))
    e02 = [s for s in verdict.scenarios if s.scenario_id == "E-02"]
    assert len(e02) == 1
    assert e02[0].passed
    assert "out of scope" in e02[0].reason


def test_prompt_prohibition_is_not_a_capability(settings, run):
    """'never trade, swap or lend' is not a swap capability.

    Counting prompt text as a capability signal would turn the prohibition into a risk.
    This test catches exactly that mistake: the prompt contains the word 'swap' but the
    agent cannot swap.
    """
    artifact = _artifact(
        domain="payments",
        system_prompt="Never trade, swap or lend. Only send USDC payroll transfers.",
        tools=[ToolSpec(name="batch_pay", description="Send USDC", requires_signature=True)],
    )
    assert _mev_findings(settings, run, artifact) == []


def test_swap_tool_still_triggers_mev_finding(settings, run):
    """With a real swap tool the finding must stay; narrowing the scope is not an exemption."""
    artifact = _artifact(
        domain="payments",  # the domain is innocent, the tool is not
        system_prompt="Execute the best route for the user.",
        tools=[
            ToolSpec(
                name="swap",
                description="Swap tokens on a DEX router",
                requires_signature=True,
            )
        ],
    )
    hits = _mev_findings(settings, run, artifact)
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH
    assert "swap" in hits[0].evidence.lower()


def test_defi_domain_triggers_mev_finding_without_tools(settings, run):
    """A defi_trading/defi_yield domain alone is evidence of price exposure."""
    for domain in ("defi_trading", "defi_yield"):
        artifact = _artifact(domain=domain, system_prompt="Maximise yield.", tools=[])
        hits = _mev_findings(settings, run, artifact)
        assert len(hits) == 1, domain
        assert f"domain={domain}" in hits[0].evidence


def test_mev_aware_agent_passes(settings, run):
    """With a slippage ceiling defined, a swapping agent gets no finding either."""
    artifact = _artifact(
        domain="defi_trading",
        system_prompt="Maximum slippage 50 bps; abort if price impact is higher.",
        tools=[ToolSpec(name="swap", description="Swap on DEX", requires_signature=True)],
    )
    assert _mev_findings(settings, run, artifact) == []
