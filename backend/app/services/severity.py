"""Severity from stated facts, not from the model's feel.

Two runs on the same agent rated one shell injection critical and then high, and a testnet
token with no value high. The review therefore no longer picks a severity: for each defect it
states four facts, and the severity follows from them by a fixed table, so the same facts give
the same severity on every run and every agent.

* what is at risk (``asset``): funds, keys, account control, the host (code execution) -> critical;
  funds locked or delayed -> high; the operator's own provider spend (model or API bills, quotas),
  availability, data exposure, correctness -> medium; nothing -> low. A read-only agent whose chat quota
  can be raced was rated critical as "funds"; the operator paying more for a model is not value taken
  from an account, so it has its own, lower, asset;
* who can trigger it (``trigger``): anyone, including content the agent reads, or any user -> as is;
  a counterparty the agent talks to (payment server, RPC, facilitator) -> one level lower; only the
  operator -> two lower; nobody yet (no caller, not wired) -> low;
* which network (``network``): testnet only -> at most medium (testnet value is not real);
* where the code is (``location``): example or quickstart -> one lower and at most high;
  tests and developer tools -> low.
"""
from __future__ import annotations

LEVELS = ["low", "medium", "high", "critical"]

ASSETS = {
    "funds": "critical", "keys_or_secrets": "critical", "account_control": "critical",
    "host_code_execution": "critical", "funds_locked_or_delayed": "high",
    "operator_spend": "medium", "service_availability": "medium", "data_exposure": "medium", "correctness": "medium",
    "none": "low",
}
TRIGGERS = {"anyone": 0, "any_user": 0, "counterparty": -1, "operator_only": -2, "nobody_yet": None}
NETWORKS = ["mainnet_or_configurable", "testnet_only", "not_applicable"]
LOCATIONS = ["shipped", "example_or_quickstart", "test_or_dev_tool"]

FACTOR_SCHEMA = {
    "asset": {"type": "string", "enum": sorted(ASSETS),
              "description": "What an exploit or failure costs: funds = on-chain value or users' money taken or lost "
                             "(not the operator's own model or API bills); operator_spend = higher model, API or "
                             "provider bills, quotas or rate limits bypassed; keys_or_secrets = a "
                             "key, seed or credential exposed; account_control = signers, thresholds, merge, "
                             "contract admin or upgrade; host_code_execution = commands or code run on the host; "
                             "funds_locked_or_delayed = value stuck or settlement blocked; service_availability; "
                             "data_exposure = non-secret data leaked; correctness = wrong behaviour without loss; "
                             "none."},
    "trigger": {"type": "string", "enum": sorted(TRIGGERS),
                "description": "Who can make it happen: anyone = an unauthenticated caller or any content the agent "
                               "reads (web, memo, email, tool result, prompt injection); any_user = any "
                               "authenticated user or customer; counterparty = a server, RPC, facilitator or "
                               "payment challenge the agent talks to; operator_only = only the operator or admin; "
                               "nobody_yet = no caller, not wired up, mocked."},
    "network": {"type": "string", "enum": NETWORKS,
                "description": "testnet_only only when the code is fixed to testnet; mainnet_or_configurable when "
                               "mainnet is used or a setting can select it; not_applicable when no chain is involved."},
    "location": {"type": "string", "enum": LOCATIONS,
                 "description": "shipped = code the agent or library runs; example_or_quickstart = examples, demos or "
                                "quickstarts a user is told to run; test_or_dev_tool = tests, fixtures, build or "
                                "maintenance scripts."},
}


def compute(asset: str, trigger: str, network: str, location: str) -> str:
    """The severity the stated facts give (unknown values fall back to the most cautious reading)."""
    level = LEVELS.index(ASSETS.get(asset, "critical"))
    shift = TRIGGERS.get(trigger, 0)
    if shift is None or location == "test_or_dev_tool":
        return "low"
    level += shift
    if network == "testnet_only":
        level = min(level, LEVELS.index("medium"))
    if location == "example_or_quickstart":
        level = min(level - 1, LEVELS.index("high"))
    return LEVELS[max(0, min(level, len(LEVELS) - 1))]


def basis(args: dict) -> str:
    return (f"Severity basis: at risk {args.get('asset', '?')}, triggered by {args.get('trigger', '?')}, "
            f"network {args.get('network', '?')}, code {args.get('location', '?')}.")
