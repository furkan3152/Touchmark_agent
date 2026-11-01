"""The check ledger: the same questions asked of every agent, each answered from the code.

A free-form review finds what the model happens to look at, so two runs on the same agent
can differ and a quiet report says little about what was checked. The ledger fixes the
questions. Which checks apply follows from what the agent can do (the rules' capability
profile and the file map, services/file_map.py), never from the model's choice. Each review
pass takes one group of checks and must answer every check in it:

* holds: the code enforces it; the answer quotes the enforcing line;
* fails: the code does not; the answer quotes the defective line and becomes a finding;
* not_applicable: the agent does not do what the check is about (the reason says why);
* cannot_determine: the code that decides it is not in the submitted files.

holds and fails need a verbatim quote that is checked against the source. A ledger answer
never removes or lowers a finding; "holds" is evidence for the developer of what is in
place, "fails" adds a finding like any other review finding and goes through the same
independent verification. The report lists every applicable check with its answer, so a
developer sees what was checked, what is protected and what is not, in the same order on
every run.
"""
from __future__ import annotations

from dataclasses import dataclass

VERDICTS = ["holds", "fails", "not_applicable", "cannot_determine"]

#: Rule-profile capability names (swarm/codeflow.py) -> file-map kinds.
RULE_KINDS = {
    "key_custody": "holds_or_loads_secret", "secret_material": "holds_or_loads_secret",
    "hardcoded_secret": "holds_or_loads_secret", "stellar_signing": "signs_transactions",
    "foreign_tx_signing": "builds_from_external_xdr", "delegated_signing": "signs_transactions",
    "tx_submission": "submits_transactions", "tx_relay": "submits_transactions", "payment": "moves_value",
    "account_control": "changes_account_authority", "contract_invocation": "invokes_contract",
    "trustline": "changes_account_authority", "code_execution": "executes_code", "process_spawn": "executes_code",
    "network_fetch": "calls_network", "file_access": "reads_writes_files", "llm_call": "calls_llm",
}

VALUE = {"moves_value", "submits_transactions", "invokes_contract"}
SIGN = {"signs_transactions", "signs_raw_bytes", "builds_from_external_xdr", "submits_transactions"}
CHAIN = SIGN | VALUE | {"changes_account_authority"}
PRIVILEGED = CHAIN | {"holds_or_loads_secret", "executes_code"}


@dataclass(frozen=True)
class Check:
    id: str
    group: str
    title: str
    question: str
    category: str                      # deep_review.CATEGORIES key a failing answer is filed under
    needs: frozenset = frozenset()     # applies when the agent has any of these kinds (empty: always)


def _c(id, group, title, question, category, needs=()):
    return Check(id, group, title, question, category, frozenset(needs))


CATALOG: tuple[Check, ...] = (
    # ---- value movement -------------------------------------------------------------------
    _c("V1", "value", "Per-action amount bound",
       "Is every amount the agent pays, transfers, swaps or approves bounded by a code-enforced maximum "
       "before signing, on every path that moves value (each tool, route and retry)?", "unauthorized_payment", VALUE),
    _c("V2", "value", "Cumulative budget",
       "Is there a cumulative (per day, per session or per caller) limit that many small requests cannot "
       "exceed, stored somewhere that survives restarts and is shared by every instance?", "economic_loss", VALUE),
    _c("V3", "value", "Atomic budget accounting",
       "Are budget or balance checks and their recording atomic, so two concurrent requests cannot both pass "
       "before either is counted, and is spend recorded before (not after) the payment is sent?",
       "economic_loss", VALUE),
    _c("V4", "value", "Recipient binding",
       "Is the destination of every payment or transfer fixed by the operator, checked against an allowlist, "
       "or bound to the authenticated caller, rather than chosen by tool input, fetched content or a memo?",
       "unauthorized_payment", VALUE),
    _c("V5", "value", "Asset identity and units",
       "Are assets identified by code AND issuer (or contract id), and are amounts parsed one way with the "
       "right unit (stroops vs decimal; no float, hex, exponent or negative surprises) both where they are "
       "checked and where they are signed?", "stellar_protocol_misuse", VALUE),
    _c("V6", "value", "Replay and double payment",
       "Can a request, a retry after a timeout, or a resubmitted proof cause the same payment or action "
       "twice? Look for idempotency keys, sequence handling and retry logic.", "replay_or_idempotency", VALUE),
    _c("V7", "value", "Incoming payment verification",
       "Where the agent accepts payment (paywall, x402, MPP, order), does it check the destination is its "
       "own account, the asset with issuer, the amount, the memo or order binding and finality, and refuse "
       "a proof used twice?", "unauthorized_payment", {"verifies_incoming_payment"}),
    _c("V8", "value", "Slippage and quoted prices",
       "For swaps, path payments and AMM deposits: are minimum received / maximum sent set by code and not "
       "zero or taken from a quote the requester controls; is any price computed from fields the payer chooses?",
       "economic_loss", {"moves_value", "invokes_contract"}),
    # ---- signing, network, submission -----------------------------------------------------
    _c("S1", "signing", "Externally supplied transactions",
       "Before signing a transaction, XDR, auth entry or simulation result that came from outside (a "
       "client, a server, a payment challenge, a remote API), does the code inspect its operations, "
       "destination, amount, asset, invoked contract and function?", "foreign_transaction_signing",
       {"builds_from_external_xdr", "signs_transactions"}),
    _c("S2", "signing", "Raw byte signing",
       "Does the agent key ever sign bytes, a hash, a nonce or a 'message' the requester supplies (which "
       "can be a transaction hash or Soroban auth payload)?", "foreign_transaction_signing",
       {"signs_raw_bytes", "signs_transactions"}),
    _c("S3", "signing", "Network and endpoint pinning",
       "Are the network passphrase and the Horizon / Soroban RPC / facilitator URLs fixed by operator "
       "configuration on every path that signs or submits, and never chosen by the requester? Does the "
       "configured network actually reach the signing path?", "stellar_protocol_misuse", CHAIN),
    _c("S4", "signing", "Expiry and fees",
       "Do signed transactions carry a bounded timeout (not 0 / infinite), and are fees, fee bumps and any "
       "sponsorship bounded rather than set from input?", "stellar_protocol_misuse", SIGN),
    _c("S5", "signing", "Submission outcome",
       "After submitting, does the code check the real result (final status, result codes, response body), "
       "and avoid errors after the send that make a caller retry and pay again?", "reliability_failure",
       {"submits_transactions"}),
    _c("S6", "signing", "Account authority changes",
       "Are signer, threshold, trustline, account-merge or contract-admin changes impossible from untrusted "
       "input, or gated by an enforced control?", "account_takeover", {"changes_account_authority"}),
    _c("S7", "signing", "Soroban contract checks",
       "In contracts the agent ships or calls: does every state-changing function require_auth the right "
       "address, are per-user records in persistent (not instance) storage, and are TTLs extended for entries "
       "it depends on?", "stellar_protocol_misuse", {"invokes_contract"}),
    # ---- access, secrets, entry points ----------------------------------------------------
    _c("A1", "access", "Caller authentication",
       "Does every route, tool, webhook or command that reaches signing, payment, approval or secrets "
       "require an authenticated caller (including example servers a user is told to run)?",
       "control_bypass", PRIVILEGED),
    _c("A2", "access", "Secret handling",
       "Are keys and secrets kept out of tool results, model context, logs, error messages, URLs and "
       "committed files (.env copies, key files, notes)?", "secret_exposure", {"holds_or_loads_secret"}),
    _c("A3", "access", "Tenant isolation",
       "Can one user or caller act on keys, funds, sessions or records that belong to another user or to "
       "a shared treasury? Is state shared across users of the same process keyed by the caller?",
       "cross_user_access", {"stores_shared_state", "moves_value", "holds_or_loads_secret"}),
    _c("A4", "access", "Approvals fail closed",
       "Where an approval, confirmation or policy gate exists, does it deny on timeout, error, a missing "
       "reviewer or a flag the requester or model can set?", "control_bypass", PRIVILEGED),
    _c("A5", "access", "Code, command and query execution",
       "Is any shell command, eval, SQL, template or deserialization built from model output, tool input or "
       "fetched data?", "code_execution", {"executes_code", "reads_writes_files"}),
    _c("A6", "access", "Outbound requests and file paths",
       "Can the requester steer outbound URLs (SSRF, internal addresses) or file paths (traversal) the "
       "agent fetches, reads or writes?", "ssrf", {"calls_network", "reads_writes_files"}),
    # ---- the model and the agent's behaviour ----------------------------------------------
    _c("M1", "model", "Instructions in data",
       "Can text the agent reads (web pages, documents, memos, tool results, other agents' messages) choose "
       "the action, recipient, amount or asset of a privileged call without a code check between them?",
       "prompt_injection", {"calls_llm"}),
    _c("M2", "model", "Controls outside the prompt",
       "Is every safety rule that matters for funds or keys enforced in code, rather than only stated in the "
       "system prompt or tool description (so a reworded, translated or role-played request cannot pass)? "
       "Are keyword filters robust to synonyms, other languages and encodings?", "prompt_injection",
       {"calls_llm"} | PRIVILEGED),
    _c("M3", "model", "Persistent memory and loaded instructions",
       "Can untrusted content write memory, notes or vector stores that later prompts read, and are tools, "
       "skills, prompts or MCP server lists loaded at run time from a URL or third party?", "prompt_injection",
       {"calls_llm", "stores_shared_state"}),
    _c("M4", "model", "Stated purpose versus behaviour",
       "Does the code do what the README, .tmark declaration and tool descriptions say, and nothing with "
       "keys or funds that they do not mention (including claims of limits or on-chain enforcement)?",
       "intent_mismatch"),
    _c("M5", "model", "Core function works",
       "Does the agent's core path actually work as shipped: real SDK and API calls with the right types and "
       "units, imports that exist, configuration that is read where it is used, errors that are not swallowed?",
       "functional_defect"),
)

BY_ID = {c.id: c for c in CATALOG}
GROUPS = ("value", "signing", "access", "model")
GROUP_TITLES = {"value": "Value movement", "signing": "Signing, network and submission",
                "access": "Access, secrets and entry points", "model": "Model behaviour and intent"}


def agent_kinds(rule_capabilities: dict | None, map_kinds: set[str] | None) -> set[str]:
    kinds = set(map_kinds or ())
    for name, locs in (rule_capabilities or {}).items():
        if locs and name in RULE_KINDS:
            kinds.add(RULE_KINDS[name])
    return kinds


def applicable(kinds: set[str]) -> list[Check]:
    return [c for c in CATALOG if not c.needs or c.needs & kinds]


def plan(kinds: set[str]) -> list[tuple[str, list[Check]]]:
    """(group, checks) for each group with at least one applicable check, in fixed order."""
    checks = applicable(kinds)
    return [(g, [c for c in checks if c.group == g]) for g in GROUPS if any(c.group == g for c in checks)]


def instruction(group: str, checks: list[Check], files: list[str], prior: str) -> str:
    rows = "\n".join(f"- {c.id} ({c.title}): {c.question}" for c in checks)
    focus = ", ".join(files[:40]) or "the files in read_first"
    return (f"Check-ledger pass: {GROUP_TITLES[group]}. Answer EVERY check below with answer_check, one call "
            f"per check, after reading the code that decides it.\n{rows}\n\n"
            f"Start with these files (the file map shows they hold the relevant capabilities): {focus}. Search "
            "for sibling paths that do the same thing and judge all of them.\n"
            "Verdicts: holds = the code enforces it (quote the enforcing line); fails = it does not on at least "
            "one reachable path (quote the defective line and give severity, title, attack scenario and "
            "remediation; if an earlier pass already recorded this defect put its id in existing_finding_id "
            "instead of a new title); not_applicable = the agent does not do this (say why); cannot_determine = "
            "the deciding code is not in the submitted files. Comments, prompts and docs are never a control.\n"
            f"Earlier passes recorded:\n{prior}\n"
            "Skip describe_operating_model. You may also record_finding for other real defects you meet. "
            "When every check is answered, call finish.")


@dataclass
class Answer:
    check_id: str
    verdict: str
    file: str = ""
    line: int = 0
    quote: str = ""
    reason: str = ""
    finding_id: str = ""
    quote_verified: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def report(answers: dict[str, dict], kinds: set[str], planned: list[str]) -> dict:
    """The ledger section of the report: every applicable check, answered or not."""
    rows = []
    for check in applicable(kinds):
        answer = answers.get(check.id)
        rows.append({"id": check.id, "group": check.group, "title": check.title, "question": check.question,
                     **({k: v for k, v in answer.items() if k != "check_id"} if answer
                        else {"verdict": "unanswered" if check.group in planned else "not_run"})})
    counts = {v: sum(1 for r in rows if r["verdict"] == v)
              for v in (*VERDICTS, "unanswered", "not_run")}
    answered = sum(counts[v] for v in VERDICTS)
    return {"version": 1, "checks": rows, "counts": counts, "applicable": len(rows),
            "answered": answered, "complete": bool(rows) and answered == len(rows),
            "agent_kinds": sorted(kinds)}
