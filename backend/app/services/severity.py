"""Severity from stated facts, not from the model's feel.

Two runs on the same agent rated one shell injection critical and then high, and a testnet
token with no value high. The review therefore no longer picks a severity: for each defect it
states four facts, and the severity follows from them by a fixed table, so the same facts give
the same severity on every run and every agent.

* what is at risk (``asset``): funds, keys, account control, the host (code execution) -> critical;
  funds locked or delayed -> high; the operator's own provider spend (model or API bills, quotas),
  availability, data exposure, correctness -> medium; nothing -> low. A read-only agent whose chat quota
  can be raced was rated critical as "funds"; the operator paying more for a model is not value taken
  from an account, so it has its own, lower, asset. Likewise an API key for a search or model provider
  (``service_credential``) is high, not the critical of a signing key;
* who can trigger it (``trigger``): anyone, including content the agent reads, or any user -> as is;
  a counterparty the agent talks to (payment server, RPC, facilitator) -> one level lower; only the
  operator -> two lower; nobody yet (no caller, not wired) -> low;
* which network (``network``): testnet only -> at most medium (testnet value is not real);
* where the code is (``location``): example or quickstart -> one lower and at most high;
  tests and developer tools -> low.
"""
from __future__ import annotations

import re

from .file_map import AUTHORITY_KINDS as _MAP_AUTHORITY_KINDS

LEVELS = ["low", "medium", "high", "critical"]

ASSETS = {
    "funds": "critical", "keys_or_secrets": "critical", "account_control": "critical", "service_credential": "high",
    "paid_service_not_delivered": "medium",
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
                             "Stellar or wallet signing key, seed, or a credential that controls funds or the host, "
                             "exposed; service_credential = an API key or token for a third-party service (search, "
                             "model provider, analytics) exposed; account_control = a Stellar "
                             "account's signers, thresholds or merge, or a contract's admin or upgrade (a web login, "
                             "an application user account or an email that can be claimed is data_exposure); "
                             "host_code_execution = commands or code the service itself runs on its host (text a "
                             "person might copy and paste is not); "
                             "funds_locked_or_delayed = value stuck or settlement blocked; paid_service_not_delivered = a payer is "
                             "charged but the paid service fails or is not delivered, with no refund (the payer's own "
                             "payment for a failed call, not value someone takes); service_availability; "
                             "data_exposure = non-secret data leaked; correctness = wrong behaviour without loss; "
                             "none."},
    "trigger": {"type": "string", "enum": sorted(TRIGGERS),
                "description": "Who can make it happen: anyone = an unauthenticated caller or any content the agent "
                               "reads (web, memo, email, tool result, prompt injection); any_user = any "
                               "authenticated user or customer; counterparty = a server, RPC, facilitator, "
                               "payment challenge or seller listing the agent talks to; operator_only = only the operator or admin, "
                               "including the person at the keyboard of a single-user desktop or command-line app "
                               "(its own buttons and flags); "
                               "nobody_yet = no caller, not wired up, mocked, or code that cannot run: it does not "
                               "compile, or the function the path depends on is a stub or raises NotImplementedError."},
    "network": {"type": "string", "enum": NETWORKS,
                "description": "testnet_only only when the code is fixed to testnet; mainnet_or_configurable when "
                               "mainnet is used or a setting can select it; not_applicable when no chain is involved."},
    "location": {"type": "string", "enum": LOCATIONS,
                 "description": "shipped = code the agent or library runs; example_or_quickstart = examples, demos or "
                                "quickstarts a user is told to run; test_or_dev_tool = tests, fixtures, mocks and mock "
                                "modes, seeded demo data, build or maintenance scripts."},
}


#: An agent that can do any of these holds Stellar authority.
#: Stellar authority: the file map's authority kinds (services/file_map.py) without the two that
#: are not authority over Stellar funds or accounts by themselves. A secret may be an API key and
#: a shell is not a Stellar key; findings about those keep their own assets (service_credential).
AUTHORITY_KINDS = frozenset(_MAP_AUTHORITY_KINDS - {"holds_or_loads_secret", "executes_code"})
#: Claims that need Stellar authority somewhere in the agent, and what each falls to without it.
AUTHORITY_ASSETS = {"funds": "correctness", "funds_locked_or_delayed": "correctness",
                    "account_control": "data_exposure", "keys_or_secrets": "service_credential"}
_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|e2e|mocks?|__mocks__)/|\.(?:test|spec)\.\w+$|"
                        r"(?:^|/)test_[^/]*$|_test\.\w+$|(?:^|/)tests?\.rs$|(?:^|/)mock[-_.][^/]*$", re.I)
_EXAMPLE_PATH = re.compile(r"(?:^|/)(?:examples?|demos?|samples?|quickstarts?)/", re.I)
#: Front-end view code: components, pages and views rendered in a browser.
_UI_PATH = re.compile(r"\.(?:tsx|jsx|vue|svelte)$|(?:^|/)(?:components|pages|views)/[^/]+\.(?:js|ts)$", re.I)


def ground(args: dict, card: dict | None, agent_kinds: set | None = None) -> tuple[dict, list[str]]:
    """Hold a model's stated severity facts to positive evidence. On never-audited agents most critical findings
    were a UI component, a web login or a demo mock rated as a loss of funds. A claim of funds, keys or account
    control is lowered only when the evidence shows it cannot hold: the agent has no Stellar authority at all, or
    the cited file is front-end view code with no authority capability of its own. A capability the file map did
    not record is never taken as proof of absence (the map misses some, and real defects sat in such files).
    Code under test, mock or example paths is not shipped code whatever the model says."""
    out, notes = dict(args), []
    path = str(args.get("file") or "")
    asset = out.get("asset")
    kinds = {c.get("kind") for c in (card or {}).get("capabilities", []) if isinstance(c, dict)}
    if asset in AUTHORITY_ASSETS and (card or {}).get("role") != "contract":
        # Code that authenticates callers may gate a system outside what was audited (a middleware folder of a
        # payment platform), so a claim made there is kept even when the audited code holds no authority.
        if agent_kinds is not None and not set(agent_kinds) & AUTHORITY_KINDS \
                and "authenticates_callers" not in kinds:
            out["asset"] = AUTHORITY_ASSETS[asset]
            notes.append(f"the agent holds no Stellar authority, so {asset} is rated as {out['asset']}")
        elif _UI_PATH.search(path) and not kinds & AUTHORITY_KINDS:
            out["asset"] = AUTHORITY_ASSETS[asset]
            notes.append(f"{path} is front-end view code with no authority of its own, so {asset} is rated as "
                         f"{out['asset']}")
    if out.get("location") == "shipped" or out.get("location") not in LOCATIONS:
        if _TEST_PATH.search(path):
            out["location"] = "test_or_dev_tool"
            notes.append(f"{path} is test or mock code")
        elif _EXAMPLE_PATH.search(path):
            out["location"] = "example_or_quickstart"
            notes.append(f"{path} is example code")
    return out, notes


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
