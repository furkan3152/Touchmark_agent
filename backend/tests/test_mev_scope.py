"""MEV scope discipline — no slippage finding is generated if there is no price exposure.

This is a regression test. Previously, the MEV check was tied to the ``has_funds``
condition (is there a tool with signing authority). Result: a payroll agent making plain USDC transfers
was receiving "No MEV/slippage protection" (HIGH, CONFIRMED). Because the finding was verified HIGH,
the `CAUTION_CEILING` was triggered, and the agent could not get the SAFE badge —
meaning a false positive directly lowered the badge. This was why every production-quality
agent in the corpus scan stopped exactly at 84.0.

Now, scope is derived from **capability**: if the domain or the name/description of the tools
does not indicate swapping, the check is out of scope."""

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
    """Bordro ajanı takas yapmıyor: slippage bulgusu üretilmemeli."""
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
    """Kontrol atlandığında sessiz kalınmaz: E-02 kapsam dışı olarak yazılır."""
    artifact = _artifact(
        domain="payments",
        system_prompt=PAYROLL_PROMPT,
        tools=[ToolSpec(name="batch_pay", description="Send USDC", requires_signature=True)],
    )
    verdict = run(EconomicAuditor(settings).run(artifact))
    e02 = [s for s in verdict.scenarios if s.scenario_id == "E-02"]
    assert len(e02) == 1
    assert e02[0].passed
    assert "kapsam dışı" in e02[0].reason


def test_prompt_prohibition_is_not_a_capability(settings, run):
    """'never trade, swap or lend' bir takas yeteneği değildir.

    Prompt metnini yetenek sinyali saymak, yasağı riske çevirirdi. Bu test
    tam olarak o hatayı yakalar: prompt 'swap' kelimesini içeriyor ama ajan
    takas yapamıyor.
    """
    artifact = _artifact(
        domain="payments",
        system_prompt="Never trade, swap or lend. Only send USDC payroll transfers.",
        tools=[ToolSpec(name="batch_pay", description="Send USDC", requires_signature=True)],
    )
    assert _mev_findings(settings, run, artifact) == []


def test_swap_tool_still_triggers_mev_finding(settings, run):
    """Gerçek takas aracı varsa bulgu korunmalı — kapsam daraltma bir muafiyet değil."""
    artifact = _artifact(
        domain="payments",  # alan masum, araç değil
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
    """defi_trading/defi_yield alanı tek başına fiyat maruziyeti kanıtıdır."""
    for domain in ("defi_trading", "defi_yield"):
        artifact = _artifact(domain=domain, system_prompt="Maximise yield.", tools=[])
        hits = _mev_findings(settings, run, artifact)
        assert len(hits) == 1, domain
        assert f"domain={domain}" in hits[0].evidence


def test_mev_aware_agent_passes(settings, run):
    """Slippage tavanı tanımlıysa takas ajanı da bulgu almaz."""
    artifact = _artifact(
        domain="defi_trading",
        system_prompt="Maximum slippage 50 bps; abort if price impact is higher.",
        tools=[ToolSpec(name="swap", description="Swap on DEX", requires_signature=True)],
    )
    assert _mev_findings(settings, run, artifact) == []
