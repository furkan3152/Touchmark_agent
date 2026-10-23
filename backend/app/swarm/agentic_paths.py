"""Stellar deep-tier static source-to-sink analysis for autonomous agents.

Python uses bounded AST propagation; other languages produce inferred signals.
CONFIRMED describes visible static evidence, never a successfully executed exploit.
This implementation uses Stellar/Soroban transaction sinks.
"""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass
from functools import lru_cache

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity
from ..services.lockfiles import Lockset, below, spec_admits
from ..stellar.canonical import NETWORK_MARKERS
from .consolidate import stable_id


_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_ASSIGN_RE = re.compile(rf"\b(?P<var>{_IDENT})\s*(?::[^=]+)?=\s*(?P<rhs>.+)")
_FUNCTION_RE = re.compile(
    rf"(?:async\s+)?def\s+{_IDENT}\s*\((?P<py>[^)]*)\)|"
    rf"(?:async\s+)?function\s+{_IDENT}\s*\((?P<js>[^)]*)\)",
    re.I,
)
_SOURCE_RE = re.compile(
    r"request\.(?:json|body|form|args)|req\.(?:body|query|params)|"
    r"event\.(?:body|data)|webhook|input\s*\(|stdin|argv|"
    r"messages?\s*\[|user[_-]?(?:input|message)|response\.(?:text|json)|resp\.text",
    re.I,
)
_SOURCE_NAMES = {
    "input", "user_input", "prompt", "payload", "query", "message", "messages",
    "command", "cmd", "code", "request", "webhook",
}
#: A secret passed through a masking, hashing or public-key step on the same line is not leaked.
_SANITISED_RE = re.compile(r"mask|redact|hash|digest|fingerprint|public_?key|publicKey|\.length\b|\blen\(", re.I)
_COMMAND_SINK_RE = re.compile(
    # `exec(` as a function, not a method: RegExp.exec / db.exec are not code execution.
    r"(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(|os\.system\s*\(|subprocess\.(?:run|call|popen)\s*\(|"
    r"child_process\.(?:exec|execSync|spawn)\s*\(|\b(?:execSync|spawnSync|execFile)\s*\(|\bCommand::new\s*\(",
    re.I,
)
# Stellar Classic transaction submission and Soroban invocation/authorization
# are explicit sinks here; EVM writeContract/sendRawTransaction are not.
_FINANCIAL_SINK_RE = re.compile(
    r"\.(?:transfer|send_transaction|sign_transaction|submit_transaction|"
    r"invoke_contract|invoke_host_function|authorize_entry|sign_auth_entry)\s*\(|"
    r"\b(?:submit_transaction|invoke_contract|token\.transfer)\s*\(",
    re.I,
)
_CONTROL_RE = re.compile(
    r"authori[sz]|authenticat|verify_signature|require_auth|allowlist|whitelist|validate|"
    r"schema|sanitize|spend_limit|max_(?:amount|spend)|daily_(?:cap|limit)|"
    r"human_(?:approval|oversight)|idempoten|sequence|nonce|replay|policyerror|require\s*\(",
    re.I,
)
_SECRET_NAME_RE = re.compile(
    r"(?:private[_-]?key|secret|seed(?:_phrase)?|mnemonic|api[_-]?key|access[_-]?token)",
    re.I,
)
_SECRET_SOURCE_RE = re.compile(
    r"os\.(?:environ|getenv)|process\.env|std::env|private[_-]?key|mnemonic|seed[_-]?phrase|"
    r"(?:sk|pk|xprv)-[A-Za-z0-9_-]{8,}|S[A-Z2-7]{55}",
    re.I,
)
_EXFIL_SINK_RE = re.compile(
    r"\bprint\s*\(|console\.log\s*\(|log(?:ger|ging)?\.(?:debug|info|warning|error)\s*\(|"
    r"requests?\.(?:post|put|get)\s*\(|fetch\s*\(|httpx?\.",
    re.I,
)
_IMPLEMENTATION_SUFFIXES = (
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".sol",
)
_SIGNING_SCOPES = {"sign:tx", "write:wallet", "wallet", "transfer", "spend"}


@dataclass(frozen=True)
class _Hit:
    file: str
    line: int
    variable: str
    text: str
    grade: EvidenceGrade = EvidenceGrade.INFERRED

    def evidence(self) -> str:
        return f"{self.file}:{self.line} `{' '.join(self.text.strip().split())[:180]}`"


def _names(text: str) -> set[str]:
    return set(re.findall(_IDENT, text))


def _function_params(line: str) -> set[str]:
    match = _FUNCTION_RE.search(line)
    if not match:
        return set()
    raw = match.group("py") or match.group("js") or ""
    params = set()
    for item in raw.split(","):
        name_match = re.search(_IDENT, item.strip())
        if name_match and name_match.group(0).lower() in _SOURCE_NAMES:
            params.add(name_match.group(0))
    return params


def _scan_file(filename: str, content: str, external_entrypoints: set[str] | None = None) -> tuple[list[_Hit], list[_Hit], list[_Hit]]:
    tainted: set[str] = set()
    secrets: set[str] = set()
    commands: list[_Hit] = []
    financial: list[_Hit] = []
    exfil: list[_Hit] = []

    for number, line in enumerate(content.splitlines(), 1):
        params = _function_params(line)
        if _FUNCTION_RE.search(line):
            tainted = params
        assignment = _ASSIGN_RE.search(line)
        if assignment:
            variable = assignment.group("var")
            rhs = assignment.group("rhs")
            if _SOURCE_RE.search(rhs) or _names(rhs) & tainted:
                tainted.add(variable)
            if _SECRET_NAME_RE.search(variable) and _SECRET_SOURCE_RE.search(rhs):
                secrets.add(variable)

        referenced_taint = sorted(_names(line) & tainted)
        if referenced_taint and _COMMAND_SINK_RE.search(line):
            commands.append(_Hit(filename, number, referenced_taint[0], line))
        if referenced_taint and _FINANCIAL_SINK_RE.search(line):
            financial.append(_Hit(filename, number, referenced_taint[0], line))

        referenced_secrets = sorted(_names(line) & secrets)
        if referenced_secrets and _EXFIL_SINK_RE.search(line) and not _SANITISED_RE.search(line):
            if not assignment or assignment.group("var") not in referenced_secrets:
                exfil.append(_Hit(filename, number, referenced_secrets[0], line))
    return commands[:5], financial[:5], exfil[:5]


# Severities follow hand audits of 23 Stellar agents: where a rule's real findings were rated
# a level lower by hand in both comparison rounds (payment, signing, command and secret paths:
# high), the rule says so. Request URLs stay high: hand audits rated them lower on local
# desktop tools, but a server-side fetch tool reaches internal and cloud-metadata hosts, and
# the verifier may lower it where the context is local. The model review and the
# confirmed-bypass rule still raise a finding that is critical in context.
_PATH_RULES = {
    # category: (finding id, severity for direct input, title, detail, remediation, references)
    "command": ("security-path-untrusted-to-command", Severity.HIGH,
        "External input reaches a process or code-execution boundary",
        "Input-derived data appears in an eval, exec or process call. Inspect whether an attacker controls executable content or arguments. A static path alone does not prove arbitrary code execution.",
        "Remove dynamic execution. Otherwise use an isolated worker without network access or Stellar signing keys, with allowlisted commands and arguments.",
        ["OWASP LLM05 Improper Output Handling", "CWE-78"]),
    "financial": ("security-path-untrusted-to-financial-sink", Severity.HIGH,
        "External input reaches a Stellar transaction boundary",
        "A static input-to-transaction path is visible: the recipient or an unbounded amount of a signed Stellar operation comes from untrusted input. Authorization names and comments do not prove enforcement. This is not proof of a successful exploit.",
        "Enforce typed inputs, recipient allowlists, fail-closed spending limits, replay protection and explicit approval before signing. Test each boundary with rejected requests.",
        ["Soroban authorization", "OWASP LLM06 Excessive Agency"]),
    "foreign_signing": ("security-path-external-transaction-signed", Severity.HIGH,
        "An externally supplied transaction is signed with the agent key",
        "A transaction envelope parsed from request or model input is signed or submitted without inspecting its operations. Whoever supplies the envelope chooses what the agent key authorizes.",
        "Never sign arbitrary envelopes. Build transactions server-side, or decode and allowlist every operation, source, destination and amount before signing.",
        ["Stellar transaction signing", "OWASP LLM06 Excessive Agency"]),
    "account_control": ("security-path-untrusted-account-control", Severity.CRITICAL,
        "Untrusted input changes account authority",
        "Signer, threshold, trustline or merge operations are built from untrusted input and signed. A prompt injection or forged request can add a signer or merge the account.",
        "Remove account-administration tools from the agent, or require an out-of-band human approval and fixed parameters for each change.",
        ["Stellar set_options", "OWASP LLM06 Excessive Agency"]),
    "endpoint": ("security-path-untrusted-ledger-endpoint", Severity.CRITICAL,
        "Input chooses the Stellar RPC or Horizon server the agent trusts",
        "The URL of the RPC or Horizon server comes from a tool argument, flag or request field. That server returns the simulation, authorization entries, sequence numbers and quotes the agent then signs, so a malicious server chooses what the agent's key authorizes. Checks on the user's request do not cover what the server returns.",
        "Take RPC, Horizon and network passphrase from operator configuration only; if overrides are needed, allowlist them. Inspect the authorization tree before signing.",
        ["Stellar RPC simulation", "OWASP LLM06 Excessive Agency"]),
    "signing_oracle": ("security-path-key-signs-arbitrary-bytes", Severity.CRITICAL,
        "The agent key signs whatever bytes the requester supplies",
        "Raw data from a tool argument or request is signed with the agent's keypair. A Stellar transaction is authorized by a signature over its hash, and a Soroban authorization entry by a signature over its payload hash, so a requester who chooses the bytes can get any transaction or contract call signed as this account.",
        "Never expose raw signing. Sign only transactions the server builds and inspects; for login or proof of control use SEP-10/SEP-45 or SEP-53 message signing, which prefixes the message so it cannot be a transaction.",
        ["Stellar transaction signatures", "SEP-53", "OWASP LLM06 Excessive Agency"]),
    "asset_route": ("security-path-untrusted-conversion-route", Severity.HIGH,
        "Input chooses the assets or route of a path payment",
        "A signed path payment takes its send asset, destination asset or path from a tool argument or request. The conversion then runs through whatever assets and liquidity pools the requester names, including a look-alike token or a thin pool they control, and the value lost in the trade goes to them.",
        "Fix the assets (code and issuer) and allowed paths in configuration, and require a minimum received amount computed from an independent price.",
        ["Stellar path payments", "OWASP LLM06 Excessive Agency"]),
    "sql": ("security-path-untrusted-to-sql", Severity.HIGH,
        "Input is written into a SQL statement",
        "A SQL statement is built by string formatting with a value from a tool argument, request or model output. The requester can rewrite the query: read other users' records, or change balances, approvals and spending totals that controls depend on.",
        "Pass values as bound parameters (cursor.execute(sql, params), $1 placeholders, tagged sql templates); never format them into the statement.",
        ["CWE-89", "OWASP LLM05 Improper Output Handling"]),
    "ssrf": ("security-path-untrusted-to-network", Severity.HIGH,
        "Untrusted input chooses a server-side request URL",
        "A URL derived from model or request input is fetched without a fixed host. The agent can be steered to internal services, cloud metadata endpoints or attacker hosts.",
        "Allowlist hosts and schemes, resolve and pin addresses, block private ranges and do not return raw responses to the model.",
        ["CWE-918", "OWASP LLM06 Excessive Agency"]),
    "path_traversal": ("security-path-untrusted-to-file", Severity.HIGH,
        "Untrusted input chooses a file path",
        "A file path derived from model or request input is opened without a containment check. Relative segments such as ../ can reach configuration and key files.",
        "Resolve the path and require it to stay inside a fixed directory (Path.resolve().is_relative_to(base)); allowlist extensions.",
        ["CWE-22"]),
    "secret_via_model": ("security-path-secret-handled-by-model", Severity.HIGH,
        "The model is asked to handle secret keys",
        "A model-callable tool takes secret key material as an argument. Keys pass through the model's context, client transcripts and provider logs, and any key the model has seen can be replayed into other calls.",
        "Keep keys out of tool arguments: sign with a key held by the server or an external signer, and pass only public keys or unsigned XDR through the model.",
        ["OWASP LLM02 Sensitive Information Disclosure", "CWE-522"]),
    "x402_unbounded": ("security-path-x402-payment-unbounded", Severity.HIGH,
        "Paid requests pay whatever the server asks",
        "An x402/MPP client wrapper signs the payment a 402 response requests, with no maximum amount or requirement selector. A malicious or compromised paid endpoint chooses the recipient, asset and amount.",
        "Configure a maximum per payment and an allowlist of payees and assets in the wrapper (or a requirements selector that enforces them), and track spend across calls.",
        ["OWASP LLM06 Excessive Agency", "x402 client payment policy"]),
    "secret_to_model": ("security-path-secret-to-model", Severity.HIGH,
        "Secret material is sent to the language model",
        "A secret value is placed into a model request. It leaves the trust boundary to the model provider and can be extracted from the conversation by prompt injection.",
        "Keep keys out of prompts and tool results. Sign in a separate component the model cannot read, and rotate any key that was sent.",
        ["OWASP LLM02 Sensitive Information Disclosure"]),
    "secret_exfiltration": ("security-path-secret-to-exfiltration", Severity.CRITICAL,
        "A signing secret reaches a logging or network boundary",
        "A variable derived from secret material appears in a logging or network call. Confirm the sink semantics and remove secret material from the output path.",
        "Keep Stellar keys in an external signer. Remove secret logging, redact diagnostics, and rotate credentials if they were exposed.",
        ["OWASP LLM02 Sensitive Information Disclosure", "CWE-532"]),
}


def _evidence(flows) -> str:
    return "; ".join(f"{flow.location.render()} [{', '.join(sorted(flow.labels - {'secret'})) or 'secret'} -> {flow.function}]"
                     for flow in flows[:5])


# --------------------------------------------------------------------------- payment SDKs
#: @x402/core caps every payment by default from this release ($1 on the assets a scheme
#: recognizes; other assets are refused), and @x402/stellar recognizes Stellar USDC from the
#: same release. Checked in the published 2.22.0 and 2.23.0 packages: spendControls and
#: findDefaultAsset first appear in 2.23.0.
X402_DEFAULT_CAP = "2.23.0"
#: @x402/fetch and @x402/axios X.Y.Z depend on @x402/core ~X.Y.0, so their version names
#: the core a wrapper uses when the core is not a direct dependency.
_X402_WRAPPERS = ("@x402/fetch", "@x402/axios")
#: First @stellar/mpp release whose server throws at start-up without a replay store. Before
#: it, the charge server checks used challenges and transaction hashes only `if (store)`
#: (0.2.0 to 0.4.0); the channel server tracks vouchers in the store from 0.4.0.
MPP_STORE_REQUIRED = {"charge": "0.5.0", "channel": "0.4.0"}
#: The fee-bump ceiling @stellar/mpp uses when none is given (DEFAULT_MAX_FEE_BUMP_STROOPS).
MPP_DEFAULT_FEE_BUMP = 10_000_000
#: Example, test and development code: item severities drop one level there.
_NON_PRODUCTION = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|examples?|dev|demo)/", re.I)
#: Code that names a network. A package that only names testnet moves test money.
_MAINNET_CODE = re.compile(r"\bSTELLAR_PUBNET\b|\bUSDC_SAC_MAINNET\b|\bXLM_SAC_MAINNET\b|\bNetworks\.PUBLIC\b|"
                           r"[\"'](?:pubnet|mainnet)[\"']|" + "|".join(map(re.escape, NETWORK_MARKERS["mainnet"])))
_TESTNET_CODE = re.compile(r"\bSTELLAR_TESTNET\b|\bUSDC_SAC_TESTNET\b|\bXLM_SAC_TESTNET\b|\bNetworks\.TESTNET\b|"
                           r"[\"']testnet[\"']|" + "|".join(map(re.escape, NETWORK_MARKERS["testnet"])))
#: Test files beside the code they test (`server.test.ts`): none of it is deployed.
_TEST_FILE = re.compile(r"[._-](?:test|spec)s?\.[cm]?[jt]sx?$")
#: Configuration a deployment reads; `#` lines in them are comments.
_CONFIG_FILES = (".json", ".yml", ".yaml", ".toml", ".env")
#: Deployment descriptors that run several instances of a server (each with its own memory).
_MULTI_INSTANCE_FILES = re.compile(r"(?:^|/)(?:vercel\.json|wrangler\.toml|serverless\.ya?ml|netlify\.toml)$")
#: A serverless entry point: counts only in the server's own module. Leading blanks are
#: [ \t] here and below: a \s crosses blank lines and backtracks quadratically on them.
_LAMBDA_HANDLER = re.compile(r"^[ \t]*export\s+(?:const|async\s+function|function)\s+handler\b|\bexports\.handler\s*=", re.M)
#: One `key: value` line of a YAML file (list items `- key: value` too); compose services and
#: Kubernetes workloads with `replicas` above one run several instances.
_YAML_KEY = re.compile(r"^(?P<indent>[ \t]*)(?P<dash>-[ \t]+)?(?P<key>[\w.-]+):(?:[ \t]+(?P<value>.*))?$")

#: fact kind -> (finding id, severity, title, detail, remediation, references, lower on testnet)
_FACT_RULES = {
    "x402_spend_controls_disabled": (
        "security-x402-spend-controls-disabled", Severity.HIGH,
        "x402 spend controls are switched off",
        "The x402 client is configured with spendControls: false (or maxAmountPerPayment: false). From @x402/core "
        "2.23.0 the client refuses payments above $1 and in unknown assets by default; this switch removes that, so "
        "a paid endpoint chooses the amount and asset the agent pays.",
        "Keep spendControls on; raise maxAmountPerPayment to the largest payment the agent should make, and list "
        "extra assets with their own per-asset caps.",
        ["x402 client spend controls", "OWASP LLM06 Excessive Agency"], False),
    "x402_any_asset": (
        "security-x402-any-asset-uncapped", Severity.MEDIUM,
        "x402 client pays in any asset, uncapped",
        "allowedAssets: true lets the client pay in any asset a 402 response names. The dollar cap applies only to "
        "assets a scheme recognizes, so a payment in any other token has no ceiling.",
        "List the extra assets the agent may pay in, each with an atomic maxAmountPerPayment.",
        ["x402 client spend controls"], False),
    "mpp_replay_store": (
        "security-mpp-replay-store-missing", Severity.HIGH,
        "MPP server accepts the same payment more than once",
        "The @stellar/mpp server records used challenges and transaction hashes only in its store. Without a shared, "
        "persistent store, one on-chain payment can be presented again for further paid requests.",
        "Pass a persistent store shared by every instance (and upgrade @stellar/mpp: from 0.5.0 the server refuses "
        "to start without one).",
        ["MPP charge replay protection", "CWE-294 Authentication Bypass by Capture-replay"], True),
    "mpp_unsigned_push": (
        "security-mpp-unsigned-push-enabled", Severity.HIGH,
        "MPP server accepts unsigned payment hashes",
        "allowUnsignedPush: true accepts a transaction hash as payment without a signature from the payer. Anyone who "
        "sees a payment on chain can present its hash as their own.",
        "Leave allowUnsignedPush off so push credentials are signed by the payer.",
        ["MPP charge push mode"], True),
    "mpp_channel_state_unchecked": (
        "security-mpp-channel-state-unchecked", Severity.MEDIUM,
        "MPP channel server does not check the channel on chain",
        "checkOnChainState: false stops the server from noticing that a payment channel was closed on chain. Vouchers "
        "accepted after the close cannot be settled, so the service is delivered unpaid.",
        "Leave checkOnChainState on (the default from @stellar/mpp 0.5.0).",
        ["MPP payment channels"], False),
    "mpp_fee_budget": (
        "security-mpp-fee-budget-unbounded", Severity.MEDIUM,
        "MPP server sponsors fees without a budget",
        "The server fee-bumps settlement transactions with its own key, with a ceiling above the SDK default or no "
        "per-funder fee budget. Payers who make it settle often spend the sponsor's XLM on fees.",
        "Keep maxFeeBumpStroops at or below 10,000,000 stroops and set a feeBudget when a fee-bump signer is configured.",
        ["MPP fee sponsorship", "CWE-770 Allocation of Resources Without Limits or Throttling"], False),
    "mpp_unpinned_channel": (
        "security-mpp-unpinned-channel", Severity.HIGH,
        "MPP client signs for any payment channel",
        "allowUnpinnedChannel: true makes the client sign vouchers for whatever channel contract the server names, "
        "not one the operator chose.",
        "Pass allowedChannels with the channel contracts the agent may pay into.",
        ["MPP payment channels", "OWASP LLM06 Excessive Agency"], True),
    "cli_auto_sign": (
        "security-cli-auto-sign", Severity.LOW,
        "Agent runs stellar contract invoke with --auto-sign",
        "The command signs every Soroban authorization entry the invocation needs, including non-root ones the CLI "
        "would otherwise ask about, so a contract call can authorize sub-invocations (transfers from the identity) "
        "nobody reviewed.",
        "Drop --auto-sign and review the authorization entries, or restrict the contract and function the tool may invoke.",
        ["Stellar CLI contract invoke", "Soroban authorization"], False),
    "x402_requirements_from_payer": (
        "security-x402-requirements-from-payer", Severity.CRITICAL,
        "The payer chooses the payment requirements the server verifies",
        "The requirements passed to the facilitator's verify or settle call come from the payer's own payload or "
        "request body (for example payload.accepted). The facilitator then checks the payment against terms the payer "
        "wrote: any amount, asset, network or payee passes.",
        "Build the requirements on the server for the route being paid, and compare payload.accepted with them "
        "(findMatchingRequirements or a deep equality) before verifying or settling.",
        ["x402 resource server", "CWE-807 Reliance on Untrusted Inputs in a Security Decision"], False),
    "x402_settle_unchecked": (
        "security-x402-settle-unchecked", Severity.HIGH,
        "The paid resource is served without checking that settlement succeeded",
        "The handler settles the payment and then serves the response, but no branch reads the settlement's "
        "success. A facilitator answers HTTP 200 with success: false when the transfer failed (and with a "
        "transaction while it is still pending), so a failed payment still gets the resource.",
        "Serve only when settle() returned success: true; answer 402 otherwise. The HTTP status and the "
        "transaction hash are not proof of payment.",
        ["x402 facilitator settle response", "CWE-754 Improper Check for Unusual or Exceptional Conditions"], False),
    "x402_verify_without_settle": (
        "security-x402-verify-without-settle", Severity.HIGH,
        "A payment is verified but never settled before serving",
        "The handler verifies a payment the client signed and then serves the resource, but nothing in it settles or "
        "submits the payment. A signed payload that is never submitted, or whose payer lacks the funds, gets the "
        "resource for free, and the same payload can be presented again.",
        "Settle (or submit) the payment and check its success before serving, or settle in a hook that runs once "
        "the response succeeds and refuse further use of the payload.",
        ["x402 resource server", "CWE-841 Improper Enforcement of Behavioral Workflow"], False),
    "tx_hash_proof": (
        "security-tx-hash-proof-unbound", Severity.HIGH,
        "A transaction hash proves payment without being bound to this request",
        "The server accepts a transaction hash the requester supplies as proof of payment and looks it up on "
        "chain. Unless the hash is recorded as used, tied to the payer or to a challenge the server issued, and "
        "recent, anyone can present someone else's payment, or an old one, for a paid response.",
        "Record used hashes (a unique insert), require a memo or challenge id the server issued for this request, "
        "check the source is the authenticated payer, and reject transactions older than the challenge.",
        ["CWE-294 Authentication Bypass by Capture-replay", "x402 payment verification"], False),
    "sponsor_rebuild": (
        "security-path-sponsor-signs-foreign-ops", Severity.HIGH,
        "The fee sponsor signs operations a client chose",
        "The server rebuilds a client's transaction with its own account as the source and signs it, copying the "
        "client's operations without checking that their credentials are Address credentials and that neither the "
        "envelope nor the operation names the sponsor as source. A client can then make the sponsor's account the "
        "source of a payment or an authorization the sponsor's signature satisfies.",
        "Before signing, require one invokeHostFunction operation with no sub-invocations, Address credentials only, "
        "an operation source that is unset (or the payer, never the sponsor) and an envelope source equal to a fixed "
        "placeholder or the payer.",
        ["Stellar fee sponsorship", "Soroban authorization", "OWASP LLM06 Excessive Agency"], False),
    "sponsor_fee": (
        "security-path-sponsor-fee-from-client", Severity.MEDIUM,
        "The client sets the fee the sponsor pays",
        "The rebuilt transaction takes its fee (or its Soroban resource data) from the client's envelope. "
        "assembleTransaction adds the minimum resource fee on top of the incoming fee, so the client chooses how "
        "much of the sponsor's XLM each transaction burns.",
        "Use a constant base fee, simulate the rebuilt transaction and cap the total fee before signing.",
        ["Stellar fee sponsorship", "CWE-770 Allocation of Resources Without Limits or Throttling"], False),
    "fee_bump_unbounded": (
        "security-path-fee-bump-unbounded", Severity.MEDIUM,
        "A fee bump pays whatever fee the input names",
        "The server wraps a transaction it did not build in a fee bump paid from its own account, with the fee taken "
        "from a tool argument or request and no ceiling. The outer signature only covers fees, so the exposure is the "
        "sponsor's XLM, at the rate the caller chooses.",
        "Cap the fee-bump fee with a constant (or derive it from the network's fee stats with a ceiling), and fee-bump "
        "only transactions whose operations the server checked.",
        ["Stellar fee-bump transactions", "CWE-770 Allocation of Resources Without Limits or Throttling"], False),
    "auth_expiration": (
        "security-auth-expiration-wide", Severity.LOW,
        "Signed authorizations stay valid longer than needed",
        "A signed Soroban authorization entry can be submitted by whoever holds it until its expiration ledger. "
        "Here that ledger is far ahead, comes from the paying server's timeout with no ceiling, or is computed "
        "from the clock instead of the ledger, so a held or leaked entry stays usable long after the agent "
        "decided to pay.",
        "Expire entries a few minutes ahead (latest ledger + 12 to 100), and cap any timeout the counterparty "
        "names with Math.min against a constant.",
        ["Soroban authorization", "x402 Stellar exact scheme"], False),
    "x402_stellar_not_default": (
        "security-x402-stellar-usdc-not-default", Severity.INFO,
        "x402 refuses Stellar USDC payments (fails closed)",
        "@x402/core 2.23.0 or later accepts only assets a scheme recognizes, and the installed @x402/stellar predates "
        "2.23.0, which first recognizes Stellar USDC. Payments on Stellar are refused rather than uncapped.",
        "Upgrade @x402/stellar to the same release as @x402/core.",
        ["x402 client spend controls"], False),
}


@dataclass(frozen=True)
class _FactHit:
    """One place a fact rule fires. Hits of one rule in one file become one finding."""
    kind: str
    location: object
    severity: Severity
    note: str = ""
    grade: EvidenceGrade = EvidenceGrade.CONFIRMED
    confidence: float = 0.9


def _fact_findings(hits: list[_FactHit], auditor: str) -> list[Finding]:
    """One finding per rule and file, at the worst severity, with every place as evidence.
    Two servers or switches in one module are one defect, and lines with the same text would
    otherwise give two findings the same id."""
    groups: dict[tuple[str, str], list[_FactHit]] = {}
    for hit in hits:
        groups.setdefault((hit.kind, hit.location.file), []).append(hit)
    findings = []
    for (kind, file), group in groups.items():
        group.sort(key=lambda h: h.location.line)
        worst = max(group, key=lambda h: h.severity.rank)
        rule, _, title, detail, remediation, refs, _ = _FACT_RULES[kind]
        findings.append(Finding(
            id=stable_id(rule, file, group[0].location.text), dimension=Dimension.SECURITY,
            severity=worst.severity, title=title, detail=detail,
            evidence="; ".join(h.location.render() + (f" ({h.note})" if h.note else "") for h in group[:5]),
            evidence_grade=worst.grade, remediation=remediation, references=refs, auditor=auditor,
            confidence=max(h.confidence for h in group)))
    return findings


def _sponsor_gaps(fact) -> list[str]:
    gaps = [label for label, ok in (("R1 credential type", fact.get("credential_type")),
                                    ("R2 source pin", fact.get("source_pin"))) if not ok]
    if fact.get("facilitator") and not fact.get("single_invocation"):
        gaps.append("R4 single invocation")
    if fact.get("foreign_fee"):
        gaps.append("R3 client-chosen fee")
    return gaps


def _sponsor_hits(profile, by_category: dict) -> tuple[list[_FactHit], dict]:
    """Fee sponsors and relayers (R1-R4, fee bumps). Where the signing site is already a
    foreign-signing flow, the gaps are returned as notes for that finding instead. A sponsor
    with R1 and R2 in place signed nothing the client chose (jsflow drops those flows)."""
    hits: list[_FactHit] = []
    notes: dict = {}
    # The same defect as a foreign-signing or untrusted-transaction flow at the signing site.
    signed = {f.location for c in ("foreign_signing", "financial") for f in by_category.get(c, [])}
    for fact in profile.facts_of("sponsor_rebuild"):
        gaps = _sponsor_gaps(fact)
        if not gaps:
            continue
        if fact.location in signed:
            notes[fact.location] = "sponsor rebuild without " + ", ".join(gaps)
            continue
        confidence = 0.95 if fact.get("warned") else 0.85  # the guide's check, left as a comment
        if any(g.startswith(("R1", "R2", "R4")) for g in gaps):
            severity = Severity.HIGH if any(g.startswith(("R1", "R2")) for g in gaps) else Severity.MEDIUM
            hits.append(_FactHit("sponsor_rebuild", fact.location, severity, confidence=confidence,
                                 note="missing " + ", ".join(g for g in gaps if not g.startswith("R3"))))
        if "R3 client-chosen fee" in gaps:
            hits.append(_FactHit("sponsor_fee", fact.location, Severity.MEDIUM))
    for fact in profile.facts_of("fee_bump_unbounded"):
        severity, extra = _adjusted("fee_bump_unbounded", Severity.MEDIUM, fact.location.file, False)
        hits.append(_FactHit("fee_bump_unbounded", fact.location, severity, "; ".join([fact.detail] + extra)))
    return hits, notes


_WEB_AUTH = {
    "sep10": ("security-sep10-challenge-unchecked", "A SEP-10 challenge is signed without being checked",
              "The agent asks an anchor's WEB_AUTH_ENDPOINT for a challenge and signs the transaction it gets back "
              "with its own key, but never checks that it is a challenge: sequence number 0 (so it can never be "
              "submitted) and a first ManageData operation '<home domain> auth' sourced by the agent. A malicious or "
              "compromised anchor can send a real payment or account change instead and submit the signature.",
              "Read the challenge with WebAuth.readChallengeTx (stellar_sdk read_challenge_transaction), which checks "
              "the sequence number, the server signature and every operation, before signing it.",
              ["SEP-10 Stellar Web Authentication"]),
    "sep45": ("security-sep45-entries-unchecked", "SEP-45 authorization entries are signed without the client checks",
              "The agent signs the authorization entries a contract web-auth server returns without checking that each "
              "calls web_auth_verify on the WEB_AUTH_CONTRACT_ID from stellar.toml and has no sub-invocations. A "
              "server can return an entry that authorizes a transfer from the agent's account.",
              "Before signing, check every entry: contract address equals WEB_AUTH_CONTRACT_ID, function name is "
              "web_auth_verify, sub-invocations are empty, and the arguments name this client and home domain.",
              ["SEP-45 Stellar Web Authentication for Contract Accounts"]),
}


def _web_auth_findings(artifact: AgentArtifact, findings: list[Finding], by_category: dict, auditor: str) -> list[Finding]:
    """SEP-10 challenges and SEP-45 entries signed unchecked. Where the signing site is already
    a foreign-signing flow, the check that is missing joins that finding instead."""
    from .auth_rules import web_auth_hits
    signed = {(f.location.file, f.location.line) for f in by_category.get("foreign_signing", [])}
    out = list(findings)
    existing = next((f for f in out if f.id == "security-path-external-transaction-signed"), None)
    for kind, file, line, text, severity, note in web_auth_hits(artifact.code_files):
        rule, title, detail, remediation, refs = _WEB_AUTH[kind]
        # Folded only into a finding at least as severe (an unresolved caller origin is LOW).
        if (file, line) in signed and existing is not None and existing.severity.rank >= severity.rank:
            sep = {"sep10": "SEP-10 challenge", "sep45": "SEP-45 authorization entry"}[kind]
            out = [f.model_copy(update={"detail": f.detail + f" At {file}:{line} it is a {sep}: {note}."})
                   if f.id == "security-path-external-transaction-signed" else f for f in out]
            continue
        out.append(Finding(
            id=stable_id(rule, file, text), dimension=Dimension.SECURITY, severity=severity, title=title,
            detail=detail, evidence=f"{file}:{line} `{' '.join(text.split())[:160]}` ({note})",
            evidence_grade=EvidenceGrade.CONFIRMED, remediation=remediation, references=refs, auditor=auditor,
            confidence=0.85))
    return out


#: Interop, round-trip and smoke harnesses (item 13 drops them one level, like test code).
_HARNESS = re.compile(r"(?:^|/)interop/|roundtrip|round_trip|smoke", re.I)


def _auth_hits(profile) -> tuple[list[_FactHit], dict]:
    """Expiration findings, and per blind-tree signing site the expiration note that joins its
    signing finding instead (one finding per defect)."""
    trees = {f.location for f in profile.facts_of("auth_tree_unchecked")}
    notes = {loc: "" for loc in trees}
    hits = []
    for fact in profile.facts_of("auth_expiration"):
        if fact.location in trees:
            notes[fact.location] = fact.detail
            continue
        severity, extra = _adjusted("auth_expiration", Severity(fact.get("severity", "low")), fact.location.file, False)
        if not extra and _HARNESS.search(fact.location.file):
            severity, extra = severity.downgrade(1), ["interop or round-trip harness"]
        hits.append(_FactHit("auth_expiration", fact.location, severity, "; ".join([fact.detail] + extra),
                             grade=EvidenceGrade.INFERRED, confidence=0.8))
    return hits, notes


def _fold_scheme_trees(artifact: AgentArtifact, profile, by_category: dict, x402_flows: list, findings: list[Finding],
                       tree_notes: dict) -> list[Finding]:
    """An x402 client scheme (createPaymentPayload) that signs a blind tree, in a package whose
    wrapper is already reported as paying whatever a 402 asks: the paid endpoint choosing the
    asset contract is that finding's defect, so the tree and expiry notes join it and no
    signing finding opens for the scheme (one finding per defect)."""
    from .network_rules import _MANIFESTS, _package_of
    x402 = next((f for f in findings if f.id == _PATH_RULES["x402_unbounded"][0]), None)
    if x402 is None:
        return findings
    roots = {n.rpartition("/")[0] for n in artifact.code_files if n.rsplit("/", 1)[-1] in _MANIFESTS}
    paid = {_package_of(f.location.file, roots) for f in x402_flows if f.location.render() in x402.evidence}
    sites = [f.location for f in profile.facts_of("auth_tree_unchecked")
             if f.get("scheme") == "x402" and _package_of(f.location.file, roots) in paid]
    if not sites:
        return findings
    for category in ("foreign_signing", "financial"):
        if category in by_category:
            by_category[category] = [f for f in by_category[category] if f.location not in sites]
    note = (" The registered x402 scheme also signs the authorization entries of the asset contract the 402 names "
            "without comparing their root contract, function and sub-invocations, so that contract can add a transfer "
            "from the payer to the tree (" + "; ".join(
                f"{loc.file}:{loc.line}" + (f", and {tree_notes[loc]}" if tree_notes.get(loc) else "") for loc in sites[:3])
            + ").")
    for loc in sites:
        tree_notes.pop(loc, None)
    folded = x402.model_copy(update={"detail": x402.detail + note, "evidence": x402.evidence + "; " + "; ".join(
        f"{loc.render()} [authorization tree unchecked]" for loc in sites[:3])})
    return [folded if f is x402 else f for f in findings]


def _grouped(facts) -> dict[str, list]:
    out: dict[str, list] = {}
    for fact in facts:
        out.setdefault(fact.location.file, []).append(fact)
    return out


def _seller_findings(profile, auditor: str) -> list[Finding]:
    """Hand-written x402 sellers (S1-S4): one finding per rule and file."""
    findings: list[Finding] = []
    settles = profile.facts_of("x402_settle_call")
    for kind in ("x402_requirements_from_payer", "x402_settle_unchecked", "x402_verify_without_settle"):
        for file, facts in _grouped(profile.facts_of(kind)).items():
            rule, severity, title, detail, remediation, refs, _ = _FACT_RULES[kind]
            evidence = [f"{f.location.render()} [{f.detail}]" for f in facts[:3]]
            if kind == "x402_settle_unchecked":
                near = [f for f in settles if f.location.file == file] or settles
                evidence += [f"settled at {f.location.render()}" for f in near[:2]]
                if any(f.get("moves_funds") for f in facts):
                    severity = Severity.CRITICAL
            if kind == "x402_verify_without_settle":
                evidence = [f"{f.location.render()} [{f.detail}; served at line {f.get('delivery')}]" for f in facts[:3]]
            findings.append(Finding(
                id=stable_id(rule, file, facts[0].location.text), dimension=Dimension.SECURITY, severity=severity,
                title=title, detail=detail, evidence="; ".join(evidence), evidence_grade=EvidenceGrade.CONFIRMED,
                remediation=remediation, references=refs, auditor=auditor, confidence=0.9))
    for file, facts in _grouped(profile.facts_of("tx_hash_proof")).items():
        worst = None
        for fact in facts:
            missing = [name for name, ok in (("used-hash store", fact.get("store")), ("payer or challenge binding",
                       fact.get("payer") or fact.get("challenge")), ("age check", fact.get("age"))) if not ok]
            bound = fact.get("payer") or fact.get("challenge")
            if not fact.get("store") or (not bound and not fact.get("age")):
                # Without a store one payment is redeemed again and again; without binding or an
                # age limit every past payment to the merchant is a free pass.
                severity = Severity.HIGH
            elif not bound:
                severity = Severity.MEDIUM
            elif not fact.get("age"):
                severity = Severity.LOW
            else:
                continue
            if worst is None or severity.rank > worst[0].rank:
                worst = (severity, fact, missing)
        if worst:
            severity, fact, missing = worst
            rule, _, title, detail, remediation, refs, _ = _FACT_RULES["tx_hash_proof"]
            findings.append(Finding(
                id=stable_id(rule, file, fact.location.text), dimension=Dimension.SECURITY, severity=severity,
                title=title, detail=detail, evidence=f"{fact.location.render()} [missing: {', '.join(missing)}]",
                evidence_grade=EvidenceGrade.CONFIRMED, remediation=remediation, references=refs, auditor=auditor,
                confidence=0.85))
    return findings


def _installed(lockset: Lockset, package: str, near: str) -> tuple[list[str], str | None, bool]:
    """(installed versions, declared range, direct dependency) nearest to ``near``."""
    found = lockset.resolve(package, near)
    if found is None:
        return [], None, False
    return list(found.versions), found.spec, found.spec is not None


def _x402_core(lockset: Lockset, near: str) -> tuple[list[str], str | None, str]:
    """The @x402/core versions a client near ``near`` runs on: the core itself when declared,
    else the wrapper's lockstep version, else every copy the lockfile installs."""
    versions, spec, direct = _installed(lockset, "@x402/core", near)
    if direct and versions:
        return versions, spec, "@x402/core"
    for wrapper in _X402_WRAPPERS:
        w_versions, w_spec, _ = _installed(lockset, wrapper, near)
        if w_versions:
            return w_versions, w_spec, wrapper
        spec = spec or w_spec
    return versions, spec, "@x402/core"


def _x402_cap(lockset: Lockset, near: str) -> tuple[str, str]:
    """('capped' | 'uncapped' | 'depends', why) for x402 clients near ``near``."""
    versions, spec, source = _x402_core(lockset, near)
    if versions:
        old = [v for v in versions if below(v, X402_DEFAULT_CAP) is True]
        new = [v for v in versions if below(v, X402_DEFAULT_CAP) is False]
        listed = f"{source} {', '.join(versions)} installed"
        if new and not old:
            return "capped", listed
        if old and not new:
            return "uncapped", f"{listed}; no default cap before {X402_DEFAULT_CAP}"
        return "depends", f"{listed}; only some copies cap payments by default"
    if spec:
        before, after = spec_admits(spec, None, X402_DEFAULT_CAP), spec_admits(spec, X402_DEFAULT_CAP, None)
        if before and after:
            return "depends", f"no lockfile; {source} {spec} admits releases before and after {X402_DEFAULT_CAP}: the cap depends on install date"
        if before is True and after is False:
            return "uncapped", f"{source} {spec}; no default cap before {X402_DEFAULT_CAP}"
        if after is True and before is False:
            return "capped", f"{source} {spec}"
    return "depends", f"installed @x402/core version unknown; payments are capped by default only from {X402_DEFAULT_CAP}"


def _package_root(lockset: Lockset, near: str) -> str:
    roots = [r for r in lockset.importers if r == "" or near == r or near.startswith(r + "/")]
    return max(roots, key=len) if roots else ""


def _testnet_only(artifact: AgentArtifact, lockset: Lockset, near: str, named: str = "") -> bool:
    """Only testnet is named in the package that holds ``near``, so only test money moves.
    Names count in code (not in its comments) and in configuration files, outside tests and
    examples; a network-keyed map counts too, since it can select either network."""
    from .tmark_check import network_hits
    if named and (_MAINNET_CODE.search(named) or _MAINNET_CODE.search(f"'{named}'")):
        return False
    root = _package_root(lockset, near)
    package = {f: t for f, t in artifact.code_files.items() if (not root or f.startswith(root + "/"))
               and not _NON_PRODUCTION.search(f) and not _TEST_FILE.search(f)}
    code = {f: t for f, t in package.items() if not f.endswith(_CONFIG_FILES)}
    config = [t for f, t in package.items() if f.endswith(_CONFIG_FILES)]

    def named_in(pattern: re.Pattern) -> bool:
        return bool(network_hits(code, pattern, skip_keyed=False)) or any(
            pattern.search(line) for t in config for line in t.splitlines() if not line.lstrip().startswith("#"))
    return named_in(_TESTNET_CODE) and not named_in(_MAINNET_CODE)


def _multi_instance(artifact: AgentArtifact, lockset: Lockset, near: str) -> str:
    """A deployment marker that runs several copies of the server in ``near``: a descriptor
    in its package and in a directory that holds it, a Lambda-style handler exported by its
    own module, or replicas above one at its package root."""
    root = _package_root(lockset, near)
    inside = lambda f: not root or f.startswith(root + "/")  # noqa: E731
    for path in list(artifact.raw_metadata.get("deployment_markers") or []) + list(artifact.code_files):
        folder = path.rpartition("/")[0]
        if _MULTI_INSTANCE_FILES.search(path) and inside(path) and (not folder or near.startswith(folder + "/")):
            return path
    if _LAMBDA_HANDLER.search(artifact.code_files.get(near, "")):
        return near
    for path, text in artifact.code_files.items():
        if inside(path) and path.endswith((".yml", ".yaml")) and _replicated(path, text, near):
            return path
    return ""


def _replicated(path: str, text: str, near: str) -> bool:
    """A compose service or Kubernetes workload in ``path`` with replicas above one that runs
    the server in ``near``: its command names the server's module, or (with no command of its
    own) it is built from a directory that holds the module. Another service's replicas (a
    worker, a database) say nothing about the server."""
    stem = posixpath.splitext(near.rsplit("/", 1)[-1])[0]
    names = re.compile(r"(?<![\w.-])" + re.escape(stem) + r"(?:\.[cm]?[jt]sx?)?(?![\w-])")
    folder = path.rpartition("/")[0]

    def builds_server(context: str | None) -> bool:
        if context is None:
            return False
        root = posixpath.normpath(posixpath.join(folder, context))
        return root in {"", "."} or near.startswith(root + "/")
    return any(replicas and (any(names.search(c) for c in commands) or (not commands and builds_server(build)))
               for replicas, build, commands in _yaml_workloads(text))


@lru_cache(maxsize=256)
def _yaml_workloads(text: str) -> tuple:
    """(replicas above one, build context, command lines) per compose service, or per YAML
    document outside `services:` (a Kubernetes workload). One pass over the lines."""
    groups: dict[tuple, list] = {}
    stack: list[tuple[int, str]] = []
    doc = 0
    for line in text.splitlines():
        if line.startswith("---"):
            doc, stack = doc + 1, []
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _YAML_KEY.match(line)
        if m is not None:
            indent = len(m.group("indent")) + len(m.group("dash") or "")
            while stack and stack[-1][0] >= indent:
                stack.pop()
        service = stack[1][1] if len(stack) > 1 and stack[0][1] == "services" else None
        group = groups.setdefault((doc, service), [False, None, []])
        if m is None:  # a list item: `- node` / `- dist/server.js` under command or args
            if stack and stack[-1][1] in {"command", "entrypoint", "args"}:
                group[2].append(line)
            continue
        key, value = m.group("key"), (m.group("value") or "").split(" #")[0].strip().strip("\"'")
        if key == "replicas" and value.isdigit() and int(value) > 1:
            group[0] = True
        elif key in {"build", "context"} and value:
            group[1] = value
        elif key in {"command", "entrypoint", "args"}:
            group[2].append(value)
        stack.append((indent, key))
    return tuple((replicas, build, tuple(commands)) for replicas, build, commands in groups.values())


def _adjusted(kind: str, severity: Severity, file: str, testnet: bool) -> tuple[Severity, list[str]]:
    notes = []
    if testnet and _FACT_RULES[kind][6]:
        severity, notes = severity.downgrade(1), notes + ["only testnet is named in this package"]
    if _NON_PRODUCTION.search(file):
        severity, notes = severity.downgrade(1), notes + ["example or test code"]
    return severity, notes


def _payment_sdk_findings(artifact: AgentArtifact, profile, lockset: Lockset, by_category: dict,
                          auditor: str) -> tuple[list[Finding], list[_FactHit], list]:
    """Version-aware x402 and MPP rules. Returns the findings, the fact hits, and the x402
    clients whose installed release caps each payment by default (amount caps for the
    control rules)."""
    findings: list[Finding] = []
    hits: list[_FactHit] = []
    default_caps = []
    # Wrapped clients whose spend controls are switched off: the client value carries the
    # switch to the wrap (jsflow), or the switch sits in the wrap's own module.
    switched_off = {f.location for f in profile.facts_of("x402_controls_off")}
    disabled_files = {f.location.file for f in profile.facts_of("x402_spend_controls_disabled")}

    # (A) x402 payers: whether the wrapped fetch pays whatever a 402 asks depends on the release
    # of @x402/core. Clients from other x402 libraries keep the plain path rule.
    other_clients = {f.location for f in profile.facts_of("x402_other_client")}
    kept, notes, others = [], {}, []
    for flow in by_category.pop("x402_unbounded", []):
        if flow.location in other_clients:
            others.append(flow)
            continue
        state, why = _x402_cap(lockset, flow.location.file)
        off = flow.location in switched_off or flow.location.file in disabled_files
        if state == "capped" or (off and state != "uncapped"):
            # Capped by default, or reported below as a switched-off cap.
            if state == "capped" and not off:
                default_caps.append(flow.location)
                stellar, _, _ = _installed(lockset, "@x402/stellar", flow.location.file)
                if stellar and all(below(v, X402_DEFAULT_CAP) is True for v in stellar):
                    hits.append(_FactHit("x402_stellar_not_default", flow.location, Severity.INFO,
                                         f"@x402/stellar {', '.join(stellar)} installed"))
            continue
        severity = Severity.HIGH if state == "uncapped" else Severity.MEDIUM
        if _NON_PRODUCTION.search(flow.location.file):
            severity = severity.downgrade(1)
        kept.append((flow, severity, state))
        notes[flow.location] = why
    if kept or others:
        fid, high, title, detail, remediation, refs = _PATH_RULES["x402_unbounded"]
        kept.sort(key=lambda item: -item[1].rank)
        entries = [(severity, f"{flow.location.render()} [{notes[flow.location]}]") for flow, severity, _ in kept]
        entries += [(high, _evidence([flow])) for flow in others]
        entries.sort(key=lambda item: -item[0].rank)
        findings.append(Finding(
            id=fid, dimension=Dimension.SECURITY, severity=entries[0][0], title=title,
            detail=detail + (" Whether the installed x402 release caps payments by default could not be "
                             "established for every client." if any(s == "depends" for _, _, s in kept) else ""),
            evidence="; ".join(text for _, text in entries[:5]),
            evidence_grade=EvidenceGrade.CONFIRMED if others or kept[0][2] == "uncapped" else EvidenceGrade.INFERRED,
            remediation=remediation, references=refs, auditor=auditor, confidence=0.95))

    # (B) x402 switches. Before 2.23.0 they switch nothing off; (A) reports that client.
    abort_hooks = {f.location.file for f in profile.facts_of("x402_abort_hook")}
    for kind in ("x402_spend_controls_disabled", "x402_any_asset"):
        for fact in profile.facts_of(kind):
            file = fact.location.file
            cap_state = _x402_cap(lockset, file)[0]
            if cap_state == "uncapped":
                continue
            if kind == "x402_spend_controls_disabled" and fact.get("browser"):
                # A browser paywall or wallet-signed client: the person approves each payment
                # in the wallet prompt, after the amount is shown. Unattended clients still fire.
                continue
            severity = _FACT_RULES[kind][1]
            if kind == "x402_spend_controls_disabled" and file in abort_hooks:
                severity = Severity.MEDIUM  # a registered hook can still refuse a payment
            severity, extra = _adjusted(kind, severity, file, False)
            # Confirmed only on a resolved release that has the switch (2.23.0 or later).
            hits.append(_FactHit(kind, fact.location, severity, "; ".join(
                extra + ([] if cap_state == "capped" else ["installed @x402/core release not resolved"])),
                grade=EvidenceGrade.CONFIRMED if cap_state == "capped" else EvidenceGrade.INFERRED))

    # (C) MPP servers, and (D) client switches.
    for fact in profile.facts_of("mpp_server"):
        file, mode = fact.location.file, fact.get("mode")
        versions, spec, _ = _installed(lockset, "@stellar/mpp", file)
        boundary = MPP_STORE_REQUIRED.get(mode, "0.0.0")
        if versions:
            optional = all(below(v, boundary) is True for v in versions)
            installed = f"@stellar/mpp {', '.join(versions)} installed"
        else:
            optional = bool(spec) and spec_admits(spec, None, boundary) is True and spec_admits(spec, boundary, None) is False
            installed = f"@stellar/mpp {spec}"
        testnet = _testnet_only(artifact, lockset, file, fact.get("network") or "")
        store = fact.get("store")
        if store == "none" and optional:
            severity, extra = _adjusted("mpp_replay_store", Severity.HIGH, file, testnet)
            hits.append(_FactHit("mpp_replay_store", fact.location, severity,
                                 "; ".join([f"no store; {installed}: replay checks run only with a store"] + extra)))
        elif store == "memory":
            marker = _multi_instance(artifact, lockset, file)
            severity, extra = _adjusted("mpp_replay_store", Severity.HIGH if marker else Severity.LOW, file,
                                        testnet and bool(marker))
            hits.append(_FactHit(
                "mpp_replay_store", fact.location, severity,
                "; ".join([f"Store.memory() with several instances ({marker})" if marker else
                           "Store.memory(): replay records are lost on restart"] + extra)))
        if fact.get("max_fee_bump", 0) > MPP_DEFAULT_FEE_BUMP or (
                mode == "channel" and fact.get("fee_bump_signer") and not fact.get("fee_budget")):
            severity, extra = _adjusted("mpp_fee_budget", Severity.MEDIUM, file, testnet)
            hits.append(_FactHit("mpp_fee_budget", fact.location, severity, "; ".join(extra)))
    for kind in ("mpp_unsigned_push", "mpp_channel_state_unchecked", "mpp_unpinned_channel"):
        for fact in profile.facts_of(kind):
            file = fact.location.file
            severity, extra = _adjusted(kind, _FACT_RULES[kind][1], file, _testnet_only(artifact, lockset, file))
            hits.append(_FactHit(kind, fact.location, severity, "; ".join(extra)))
    for fact in profile.facts_of("cli_auto_sign"):
        severity, extra = _adjusted("cli_auto_sign", Severity.MEDIUM if fact.get("direct") else Severity.LOW,
                                    fact.location.file, False)
        hits.append(_FactHit("cli_auto_sign", fact.location, severity, "; ".join(
            (["the command takes tool or request arguments"] if fact.get("direct") else []) + extra)))
    return findings, hits, default_caps


def analyse_agentic_paths(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    from .codeflow import analyse_code

    from .capabilities import declared_entrypoints
    entrypoints = declared_entrypoints(artifact)
    profile = analyse_code(artifact.code_files, entrypoints)
    findings: list[Finding] = []

    by_category: dict[str, list] = {}
    for flow in profile.flows:
        by_category.setdefault(flow.category, []).append(flow)
    lockset = Lockset(artifact.raw_metadata.get("resolved_versions"))
    x402_flows = list(by_category.get("x402_unbounded", []))
    payment_findings, payment_hits, default_caps = _payment_sdk_findings(artifact, profile, lockset, by_category, auditor)
    sponsor_hits, sponsor_notes = _sponsor_hits(profile, by_category)
    auth_hits, tree_notes = _auth_hits(profile)
    payment_findings = _fold_scheme_trees(artifact, profile, by_category, x402_flows, payment_findings, tree_notes)
    findings += payment_findings + _fact_findings(payment_hits + sponsor_hits + auth_hits, auditor) + _seller_findings(profile, auditor)
    amount_caps = list(profile.controls.get("amount_cap", [])) + default_caps
    # A sponsor that accepts only Address credentials and pins both sources inspected the
    # client's transaction (its signing flows were already dropped in jsflow).
    inspected = [f.location for f in profile.facts_of("sponsor_rebuild")
                 if not [g for g in _sponsor_gaps(f) if not g.startswith("R3")]]
    for category, (fid, severity, title, detail, remediation, refs) in _PATH_RULES.items():
        flows = by_category.get(category, [])
        # A value merely derived from an object that holds a secret (a receipt, a form's other
        # fields) is not reported: on unseen agents every such report was a false alarm.
        if not flows:
            continue
        direct = [f for f in flows if f.direct or category.startswith("secret")]
        if category == "endpoint":
            # A skill's commands are run by the model, so their flags are the model's choice.
            # Only a skill's own SKILL.md makes the model the one running its commands (AGENTS.md
            # guides coding assistants), and only for the scripts in that skill's folder: an SDK
            # elsewhere in the repository is called by its integrators, not by the model.
            skill_dirs = [m.group(1) for m in re.finditer(r"^\[((?:[^\]\n]*/)?)skill\.md\]$",
                                                          artifact.system_prompt or "", re.I | re.M)]
            direct = [f for f in flows if f.direct or ("caller" in f.labels
                      and any(f.location.file.startswith(d) for d in skill_dirs))]
            if not any(profile.has(cap) for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation")):
                severity = Severity.MEDIUM  # nothing is signed against what that server returns
        if category == "path_traversal" and not direct:
            # A file path from a public function with no caller in the source: on unseen agents
            # these were all dead code or operator-chosen paths (env, argv, own templates).
            continue
        if category in {"secret_via_model", "secret_to_model"} and all("fresh" in f.labels for f in flows):
            # A key generated in this call and handed back (create_account): not yet funded or
            # used by anyone, so exposing it is a handling flaw, not a theft path.
            severity = severity.downgrade(2)
        chosen = direct or flows
        confirmed = bool(direct)
        attached = {loc: note for loc, note in sponsor_notes.items() if any(f.location == loc for f in flows)}
        if attached and (category == "foreign_signing" or not any(
                f.location in attached for f in by_category.get("foreign_signing", []))) and category in {"foreign_signing", "financial"}:
            # One finding per defect: a sponsor's rebuild gaps are evidence for the signing flow.
            chosen = sorted(chosen, key=lambda f: f.location not in attached)
            detail = detail + " The signer is a fee sponsor that rebuilds the client's transaction: " + "; ".join(
                f"{loc.file}:{loc.line} {note}" for loc, note in attached.items()) + "."
        trees = [loc for loc in tree_notes if any(f.location == loc for f in flows)]
        if trees and category in {"foreign_signing", "financial"}:
            # One finding per defect: a blind authorization tree is evidence for the signing flow.
            chosen = sorted(chosen, key=lambda f: f.location not in trees)
            detail = detail + " The signed authorization entries come from simulating a contract that the request, the " \
                "model or a 402 response names, and nothing compares their root contract, function and sub-invocations " \
                "with what was meant: that contract can add a transfer from the signer to the tree (" + "; ".join(
                    f"{loc.file}:{loc.line}" + (f", and {tree_notes[loc]}" if tree_notes[loc] else "") for loc in trees[:3]) + ")."
        findings.append(Finding(
            id=fid, dimension=Dimension.SECURITY,
            # A file path its caller chooses is the caller's own business unless input from
            # outside reaches it; that case is confirmed above.
            # A library that exposes raw signing to its integrators is an API choice until
            # outside input is shown to reach it.
            # Unresolved origins were false in 23 of 31 hand-checked cases on real agents: kept
            # visible as an API to review, at low.
            severity=severity if confirmed else Severity.LOW,
            title=title,
            detail=detail if confirmed else detail + " The value enters through a public function whose callers are not in the submitted source, so the input origin is unresolved.",
            evidence=_evidence(chosen),
            evidence_grade=EvidenceGrade.CONFIRMED if confirmed else EvidenceGrade.INFERRED,
            remediation=remediation, references=refs, auditor=auditor,
            confidence=0.97 if confirmed else 0.75,
        ))

    findings = _web_auth_findings(artifact, findings, by_category, auditor)

    if profile.nonblocking_controls:
        findings.append(Finding(
            id="security-path-control-not-blocking", dimension=Dimension.SECURITY,
            severity=Severity.HIGH,
            title="A spending limit check does not stop the action",
            detail="A comparison against a cap or limit only logs a warning; execution continues to the signed operation. The control exists in name but is not enforced.",
            evidence="; ".join(loc.render() for loc in profile.nonblocking_controls[:5]),
            evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Raise or return when the limit is exceeded, before any transaction is built or signed, and cover the rejection with a test.",
            references=["CWE-693 Protection Mechanism Failure"], auditor=auditor, confidence=0.95,
        ))

    forgeable = profile.forgeable_approvals or profile.unresolved_approvals
    if forgeable:
        moves_funds = any(profile.has(cap) for cap in ("stellar_signing", "tx_submission", "payment", "contract_invocation",
                                                       "foreign_tx_signing", "account_control"))
        severity = Severity.CRITICAL if moves_funds else Severity.HIGH
        # A flag only an unseen caller sets is the integrator's API until outside input reaches it.
        resolved = bool(profile.forgeable_approvals)
        findings.append(Finding(
            id="security-path-forgeable-approval", dimension=Dimension.SECURITY,
            severity=severity if resolved else Severity.LOW,
            title="The approval gate checks a value the requester supplies",
            detail="The code refuses to act unless an approval flag is set, but that flag is a tool argument, request "
                   "field or fetched value. Whoever can talk to the agent can set it: a request the model refuses "
                   "when asked plainly passes when reworded so the model fills in the flag. The gate is not an approval.",
            evidence="; ".join(loc.render() for loc in forgeable[:5]),
            evidence_grade=EvidenceGrade.CONFIRMED if resolved else EvidenceGrade.INFERRED,
            remediation="Take approval from outside the model's reach: a signed approval record, a wallet prompt the "
                        "human answers, or an operator decision stored server-side and bound to the exact recipient and amount.",
            references=["CWE-807 Reliance on Untrusted Inputs in a Security Decision", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.93,
        ))

    # Non-Python sources keep lexical candidates; they are never reported as confirmed data flow.
    lexical_command: list[_Hit] = []
    lexical_financial: list[_Hit] = []
    lexical_exfil: list[_Hit] = []
    analysed = set(profile.analysed_files)
    for filename, content in artifact.code_files.items():
        if filename in analysed or filename.lower().endswith(".py") or not filename.lower().endswith(_IMPLEMENTATION_SUFFIXES):
            continue
        commands, financial, exfil = _scan_file(filename, content)
        lexical_command += commands
        lexical_financial += financial
        lexical_exfil += exfil
    known = {f.id for f in findings}
    for hits, fid in ((lexical_command, "security-path-untrusted-to-command"),
                      (lexical_financial, "security-path-untrusted-to-financial-sink"),
                      (lexical_exfil, "security-path-secret-to-exfiltration")):
        if hits and fid not in known:
            rule = next(r for r in _PATH_RULES.values() if r[0] == fid)
            findings.append(Finding(
                id=fid, dimension=Dimension.SECURITY, severity=rule[1].downgrade(1), title=rule[2],
                detail=rule[3] + " Detected lexically in non-Python source; data flow is not resolved.",
                evidence="; ".join(hit.evidence() for hit in hits), evidence_grade=EvidenceGrade.INFERRED,
                remediation=rule[4], references=rule[5], auditor=auditor, confidence=0.6))

    executable = {name for name in artifact.code_files if name.lower().endswith(_IMPLEMENTATION_SUFFIXES)}
    signing = any(tool.requires_signature or set(tool.scopes) & _SIGNING_SCOPES for tool in artifact.tools) or any(
        profile.has(cap) for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation"))
    enforced = bool(amount_caps or inspected) or any(profile.controls.get(kind) for kind in ("allowlist", "approval", "transaction_inspection"))
    if signing and executable and not enforced:
        findings.append(Finding(
            id="security-path-controls-not-enforced", dimension=Dimension.SECURITY,
            severity=Severity.HIGH,
            title="No enforced Stellar spending control in source",
            detail="The agent can sign or move funds, but no fail-closed recipient allowlist, amount cap, approval gate or transaction inspection was found in the source. Prompt statements are not enforceable controls.",
            evidence="files with signing or payment authority=" + (", ".join(sorted({
                loc.file for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation", "payment")
                for loc in profile.capabilities.get(cap, [])})) or ", ".join(sorted(executable)[:10])),
            evidence_grade=EvidenceGrade.INFERRED,
            remediation="Enforce recipient allowlists, amount caps and approval in code that raises before signing; add negative tests.",
            references=["Soroban authorization", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.82,
        ))

    # A payment rule the instructions state but the code does not enforce: the model is the
    # only control, and a reworded, role-played or indirect request gets past a model.
    moving = {f.id for f in findings} & {"security-path-untrusted-to-financial-sink", "security-path-forgeable-approval",
                                         "security-path-external-transaction-signed", "security-path-x402-payment-unbounded"}
    moving |= {f.id for f in findings if f.id.startswith(("security-x402-spend-controls-disabled-",
                                                         "security-x402-any-asset-uncapped-"))}
    rules = _prompt_payment_rules(artifact)
    if moving and rules:
        findings.append(Finding(
            id="security-policy-only-in-prompt", dimension=Dimension.SECURITY, severity=Severity.HIGH,
            title="A payment rule is stated to the model but not enforced in code",
            detail="The instructions tell the model what it may pay, but the payment path does not check it. The model "
                   "is then the only control: a plain request may be refused while the same request reworded, "
                   "role-played, translated, split up or planted in content the agent reads is carried out.",
            evidence="; ".join(rules[:3]), evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Enforce each stated rule in the code that builds or signs the transaction (allowlist, caps, "
                        "approval bound to recipient and amount), and test it with reworded and indirect requests.",
            references=["OWASP LLM01 Prompt Injection", "OWASP LLM06 Excessive Agency"], auditor=auditor, confidence=0.9,
        ))

    # A per-payment cap with no running total: many small requests each pass it.
    pay_files = {loc.file for cap in ("stellar_signing", "tx_submission", "payment", "contract_invocation")
                 for loc in profile.capabilities.get(cap, [])}
    if amount_caps and pay_files and not any(
            _CUMULATIVE.search(artifact.code_files.get(f, "")) for f in pay_files):
        findings.append(Finding(
            id="security-per-call-cap-only", dimension=Dimension.SECURITY, severity=Severity.MEDIUM,
            title="Payments are capped per call, with no total or rate limit",
            detail="Each payment is checked against a maximum, but nothing tracks how much has been sent. Splitting a "
                   "large request into many calls that each stay under the cap moves any amount.",
            evidence="caps at " + "; ".join(loc.render() for loc in amount_caps[:3])
                     + " · no running total in " + ", ".join(sorted(pay_files)[:5]),
            evidence_grade=EvidenceGrade.INFERRED,
            remediation="Keep a persistent spent-amount per period (and per user for shared funds), reject when it "
                        "would exceed the budget, and rate-limit payment calls.",
            references=["CWE-770 Allocation of Resources Without Limits or Throttling"], auditor=auditor, confidence=0.7,
        ))
    return findings


_PAY_WORDS = re.compile(r"\b(?:pay\w*|send\w*|transfer\w*|withdraw\w*|spend\w*|xlm|usdc|funds?|payments?|recipients?)\b", re.I)
_RULE_WORDS = re.compile(r"\b(?:never|do not|don't|must not|must only|only (?:send|pay|transfer)|at most|no more than|"
                         r"maximum|max(?:imum)? of|limit(?:ed)? to|cap(?:ped)?|without (?:approval|confirmation)|"
                         r"(?:ask|require)s? (?:for )?(?:approval|confirmation)|refuse)\b", re.I)
_CUMULATIVE = re.compile(r"spent|total_?(?:spent|paid|sent|amount)|daily|per_?(?:day|hour|period)|cumulative|budget|"
                         r"quota|remaining|allowance|rate_?limit|window_?(?:start|total)|spend_?tracker|ledger", re.I)


_DEVELOPER_GUIDES = {"agents.md", "claude.md", "contributing.md", ".cursorrules", "copilot-instructions.md"}


def _prompt_payment_rules(artifact: AgentArtifact) -> list[str]:
    """Sentences in the agent's instructions that state a payment rule, with their file."""
    found: list[str] = []
    for block in re.split(r"\n(?=\[[^\]\n]+\]\n)", artifact.system_prompt or ""):
        head = re.match(r"\[([^\]\n]+)\]\n", block)
        where = head.group(1) if head else "instructions"
        if where.lower().startswith("readme") or where.lower().rsplit("/", 1)[-1] in _DEVELOPER_GUIDES:
            # A README describes the project to people, and AGENTS.md / CLAUDE.md guide the coding
            # assistants that work on the repository; neither instructs the agent at run time.
            continue
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", block[head.end():] if head else block):
            sentence = sentence.strip(" -*#>")
            if 12 <= len(sentence) <= 300 and _PAY_WORDS.search(sentence) and _RULE_WORDS.search(sentence):
                found.append(f"{where}: \"{sentence}\"")
    # Approval and limit rules first: they are what a reworded request gets past.
    found.sort(key=lambda rule: not _GATE_WORDS.search(rule))
    return found[:5]


_GATE_WORDS = re.compile(r"approv|confirm|prompt|limit|cap\b|max|at most|no more than|only (?:pay|send|transfer)", re.I)
