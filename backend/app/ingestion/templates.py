"""Wizard template'leri: kullanıcı sıfırdan yazmak zorunda kalmasın."""

from __future__ import annotations

from ..models import ToolSpec

TEMPLATES: dict[str, dict] = {
    "trading_agent": {
        "name": "Trading Agent",
        "description": "Stellar/SDEX üzerinde otonom spot alım-satım yapan agent.",
        "declared_capabilities": ["market_analysis", "spot_trading", "risk_management"],
        "system_prompt": (
            "You are an autonomous trading agent operating on Stellar. Analyse market data, "
            "then execute spot trades. Respect the user's risk limit of 2% per position and "
            "never exceed the configured daily spend cap. Ask for human confirmation before "
            "any transfer above 500 USDC."
        ),
        "tools": [
            ToolSpec(
                name="get_price",
                description="Fetch price from oracle",
                scopes=["read:market"],
                network_access=True,
            ),
            ToolSpec(
                name="swap",
                description="Execute a swap on a DEX",
                scopes=["write:wallet", "sign:tx"],
                requires_signature=True,
                spend_limit_usdc=500.0,
            ),
        ],
        "human_oversight": True,
        "discloses_ai": True,
        "domain": "defi_trading",
    },
    "yield_optimizer": {
        "name": "Yield Optimizer",
        "description": "Stablecoin getirisini protokoller arasında optimize eder.",
        "declared_capabilities": ["yield_scanning", "rebalancing", "protocol_risk_scoring"],
        "system_prompt": (
            "You are a yield optimisation agent. Find the best risk-adjusted stablecoin yield "
            "across whitelisted protocols only. Do not move funds into protocols with less "
            "than 30 days of audited history. Report every rebalance to the owner."
        ),
        "tools": [
            ToolSpec(
                name="list_pools",
                description="List yield pools",
                scopes=["read:defi"],
                network_access=True,
            ),
            ToolSpec(
                name="deposit",
                description="Deposit into a pool",
                scopes=["write:wallet", "sign:tx"],
                requires_signature=True,
                spend_limit_usdc=10000.0,
            ),
            ToolSpec(
                name="withdraw",
                description="Withdraw from a pool",
                scopes=["write:wallet", "sign:tx"],
                requires_signature=True,
            ),
        ],
        "human_oversight": False,
        "discloses_ai": True,
        "domain": "defi_yield",
    },
    "research_agent": {
        "name": "Research Agent",
        "description": "Zincir verisi ve web kaynaklarından araştırma raporu üretir.",
        "declared_capabilities": ["web_research", "onchain_analytics", "report_writing"],
        "system_prompt": (
            "You are a research agent. Gather information from the web and on-chain sources, "
            "cite every claim, and clearly mark uncertainty. You have no access to funds."
        ),
        "tools": [
            ToolSpec(
                name="web_search",
                description="Search the web",
                scopes=["read:web"],
                network_access=True,
            ),
            ToolSpec(
                name="fetch_url",
                description="Fetch a URL",
                scopes=["read:web"],
                network_access=True,
            ),
        ],
        "human_oversight": True,
        "discloses_ai": True,
        "domain": "research",
    },
    "payments_agent": {
        "name": "Payments Agent",
        "description": "USDC nanopayment ve fatura ödemelerini yürütür.",
        "declared_capabilities": ["invoice_payment", "x402_nanopayments", "accounting"],
        "system_prompt": (
            "You are a payments agent. Settle invoices in USDC via x402. Verify the payee "
            "against the allowlist before transferring. Escalate anything above the daily cap."
        ),
        "tools": [
            ToolSpec(
                name="pay",
                description="Send USDC",
                scopes=["write:wallet", "sign:tx"],
                requires_signature=True,
                spend_limit_usdc=250.0,
            ),
            ToolSpec(
                name="list_invoices",
                description="List invoices",
                scopes=["read:accounting"],
            ),
        ],
        "human_oversight": True,
        "discloses_ai": True,
        "domain": "payments",
    },
}


def list_templates() -> list[dict]:
    return [
        {
            "key": key,
            "name": tpl["name"],
            "description": tpl["description"],
            "capabilities": tpl["declared_capabilities"],
        }
        for key, tpl in TEMPLATES.items()
    ]
