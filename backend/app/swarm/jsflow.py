"""Project-wide JavaScript / TypeScript data-flow analysis.

Counterpart of `codeflow.py` for .js/.mjs/.cjs/.jsx/.ts/.tsx sources. Files are
parsed with tree-sitter (never executed). The analysis writes into the same
`CodeProfile` with the same labels, sinks, controls and flow categories, so every
rule that reads a profile treats both languages alike.

What it resolves
  * ESM and CommonJS imports between project files (named, default, namespace,
    `require` and destructured `require`), and library aliases
    (`import { exec } from "child_process"` -> child_process.exec).
  * Functions, arrow functions, class methods, object-literal methods, and
    closures: a nested function starts from the state it captured.
  * Calls between project functions, with argument labels propagated to
    parameters and return labels propagated back, to a fixed point.

Where untrusted input enters
  model    handlers registered as LLM tools: MCP `server.tool` / `registerTool`,
           `setRequestHandler(CallToolRequestSchema, ...)`, AI-SDK `tool({execute})`,
           LangChain `DynamicStructuredTool({func})`, tool objects that pair an
           input schema with `execute`, and model responses.
  external HTTP routes (Express/Fastify/Hono/Next.js), bot handlers, request
           bodies, `process.argv`, fetched network responses.
  chain    Horizon / RPC transaction, payment and event reads.
  caller   parameters of exported or public functions nothing in the project calls.

Controls count only when they fail closed (code after them runs only if the
check passed): allowlists (`ALLOW.has(x)`, `includes`, `in`), upper bounds
(`if (amount > MAX) throw`), value binding, approval checks, path containment,
transaction inspection, and zod schema constraints on tool input (`z.enum`,
`z.literal`, numeric `.max()` / `.lte()` / `.lt()`).
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field

from .codeflow import DIRECT, UNTRUSTED, CodeProfile, Flow, Location  # noqa: F401  (re-exported types)
from .codeflow import CLI_AUTO_SIGN as _CLI_AUTO_SIGN, _HUMAN_DECISION, _LOOKUP, _NOT_HUMAN

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
_RESOLVE_SUFFIXES = ("", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".mts", ".cts",
                     "/index.ts", "/index.tsx", "/index.js", "/index.mjs")

_SECRET_ENV = re.compile(r"secret|seed|private|mnemonic|sign(?:er|ing)|api[_-]?key|token|password|credential|(?:^|_)key$", re.I)
_SEED_LITERAL = re.compile(r"\bS[A-Z2-7]{55}\b")
_REQUEST_KEY = re.compile(r"(?:^|\.)(?:req|request|c\.req|ctx\.req|ctx\.request|event)\.(?:body|query|params|headers|cookies|url|path)\b")
_REQUEST_CALL = re.compile(r"(?:^|\.)(?:req|request|c\.req|ctx\.req)\.(?:json|text|formData|arrayBuffer|blob|param|query|header)$")
_LLM_CALL = re.compile(r"\.messages\.(?:create|stream)$|\.chat\.completions\.create$|\.completions\.create$|\.responses\.create$|"
                       r"^(?:generateText|generateObject|streamText|streamObject)$|\.generateContent$|"
                       r"(?:llm|model|chain|agent|chat|executor)\.(?:invoke|call|predict|run|stream)$")
_HTTP_CALL = re.compile(r"^(?:fetch|axios|got|ky|undici\.request|undici\.fetch|node-fetch|request)$|"
                        r"^(?:axios|got|ky|superagent|needle)\.(?:get|post|put|patch|delete|head|request)$|"
                        r"^(?:http|https)\.(?:request|get)$")
# An address classifier: an IP block list or a private/loopback/link-local range check.
_ADDRESS_FILTER = re.compile(r"\bnew\s+BlockList\b|\.addSubnet\(|\bis(?:Private|Public|Loopback|LinkLocal|Reserved)"
                             r"(?:Address|Ip|IP|Destination)?\s*\(|ipaddr\.(?:parse|process)\b|\.range\(\)|"
                             r"\bprivate-ip\b|\bis-ip-private\b")
_PINNED_AGENT = re.compile(r"lookup|RequestFilteringAgent|ssrf", re.I)
#: Built-in globals. `JSON.parse` is never a project method that happens to be named `parse`.
_JS_GLOBALS = frozenset({
    "JSON", "Object", "Math", "Array", "Promise", "Number", "String", "Boolean", "Date", "RegExp", "Error",
    "Buffer", "console", "process", "Reflect", "Proxy", "crypto", "URL", "URLSearchParams", "Intl", "BigInt",
    "Symbol", "Map", "Set", "WeakMap", "WeakSet", "window", "document", "globalThis", "self", "navigator",
    "localStorage", "sessionStorage", "Atomics", "TextEncoder", "TextDecoder", "Headers", "Response", "Request",
    "performance", "structuredClone", "AbortSignal", "ArrayBuffer", "Uint8Array", "DataView", "Iterator"})
_CHAIN_READ = re.compile(r"\.(?:transactions|payments|operations|effects|trades|claimableBalances)\b.*\.call$|"
                         r"\.(?:getEvents|getTransaction|getTransactions|getLedgerEntries|getContractData)$")
_LEDGER_ENDPOINT = re.compile(r"(?:^|\.)(?:rpc|SorobanRpc|Horizon|StellarSdk)\.Server$|^Server$", re.I)
_COMMAND_SINK = re.compile(r"^(?:eval|Function)$|^child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$|"
                           r"^vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)$|^(?:execa|shelljs\.exec|zx)$")
_SHELL_ALWAYS = re.compile(r"\.(?:exec|execSync)$")
#: node-serialize style loaders that run functions embedded in the data.
_DESERIALIZE = re.compile(r"(?:^|\.)unserialize$|^funcster\.deepDeserialize$")
_SQL_TEXT = re.compile(r"\b(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where\s|drop\s+table)\b", re.I | re.S)
_SQL_CALL = {"query", "execute", "raw", "exec", "run", "all", "get", "prepare", "$queryRawUnsafe", "$executeRawUnsafe", "unsafe"}
_FILE_SINK = re.compile(r"^(?:fs|fs/promises|fs\.promises|fsp|node:fs|node:fs/promises)\.(?:readFile|readFileSync|writeFile|"
                        r"writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|"
                        r"readdir|readdirSync|open|openSync|copyFile|rename)$")
_LOG_SINK = re.compile(r"^console\.\w+$|(?:^|\.)(?:log|logger|logging|winston|pino)\.(?:debug|info|warn|warning|error|fatal|trace|log)$")
_PAYMENT_OPS = {"payment", "pathPaymentStrictSend", "pathPaymentStrictReceive", "createAccount",
                "createClaimableBalance", "clawback"}
_TRUSTLINE_OPS = {"changeTrust", "allowTrust", "setTrustLineFlags"}
_ACCOUNT_OPS = {"setOptions", "accountMerge", "manageData",
                "revokeSponsorship", "revokeAccountSponsorship", "revokeTrustlineSponsorship",
                "beginSponsoringFutureReserves"}
_INVOKE_OPS = {"invokeContractFunction", "invokeHostFunction", "createCustomContract", "uploadContractWasm"}
_FOREIGN_TX = re.compile(r"(?:^|\.)(?:TransactionBuilder\.fromXDR|TransactionEnvelope\.fromXDR|Transaction|FeeBumpTransaction|"
                         r"fromXDR|txFromXDR)$")
_SUBMIT = re.compile(r"\.(?:submitTransaction|sendTransaction|submitAsyncTransaction)$")
_SOROBAN_SINK = re.compile(r"(?:^|\.)(?:invoke|invoke_contract|invokeContract|invokeContractFunction|callContract)$|^token\.transfer$")
_WALLET_PROMPT = re.compile(r"freighter|wallets?[-_]?kit|WalletsKit|walletKit|@creit|albedo|xbull|lobstr|rabet|hana|"
                            r"walletConnect|^browserwallet\.", re.I)
#: Functions whose output has a fixed structure or is a one-way hash of the input.
_STRUCTURING = re.compile(r"^(?:stringify|canonicali[sz]e\w*|serialize\w*|digest|hash\w*|sha\d+|keccak\w*|createHash|toXDR|"
                          r"encodeStructured\w*|hashMessage)$", re.I)
#: Functions whose output hides a secret (masking, redaction, one-way hashing).
_MASKING = re.compile(r"^(?:mask|redact|obfuscate|truncate|fingerprint|sha256|hash)\w*$", re.I)
#: Values that are the user's browser wallet: Wallet Standard features and injected providers.
_BROWSER_WALLET = re.compile(r"^\w+\.features\[[^\]]+\]|^(?:window\.)?(?:ethereum|solana|phantom\.solana|freighterApi)\b")
#: React hooks that hand out the connected browser wallet's functions.
_WALLET_HOOK = re.compile(r"^use(?:\w*Wallet\w*|Freighter|Stellar\w*|Albedo|Kit)$")
_SIGN_FOREIGN = re.compile(r"(?:^|\.)(?:signTransaction|signAuthEntry|signXdr|signAndSubmit|signAndSend\w*|signAndSendTransaction)$")
_AUTHORIZE = re.compile(r"(?:^|\.)(?:authorizeEntry|authorizeInvocation)$")
_APPROVAL_CALL = re.compile(r"approv|authori[sz]|verify|confirm|permi(?:t|ssion)|allowed|isAllowed|checkAuth|requireAuth", re.I)
_SECRET_ARG = re.compile(r"secret|^seed$|seed_?phrase|mnemonic|private_?key|privateKey|signing_?key|signingKey|^sk$", re.I)
#: x402 / MPP client wrappers that pay whatever a 402 response asks unless given a ceiling.
_X402_PAYER = re.compile(r"(?:^|\.)(?:wrapFetchWithPayment\w*|withPaymentInterceptor|wrapAxiosWithPayment\w*|"
                         r"createPayingFetch|createPaymentFetch)$")
#: Lower-level x402 / MPP client calls that sign a payment payload with the agent's key. The
#: code around them decides what is paid, so they record the capability, not a flow.
_X402_SIGNER = re.compile(r"(?:^|\.)(?:createPaymentPayload|createPaymentHeader|createEd25519Signer|"
                          r"signPaymentPayload|createStellarSigner)$")
#: Client options that cap a payment by value, and those that hold a policy or selector
#: function (a ceiling only when the function bounds the amount).
_X402_VALUE_LIMITS = {"maxValue", "maxAmount", "maxPaymentAmount", "maxAmountRequired", "budget", "maxPrice", "spendLimit"}
_X402_POLICY_KEYS = {"policy", "policies", "paymentRequirementsSelector", "selector"}
#: x402Client methods that take a function deciding which requirement is paid. One that
#: compares the requirement's amount is a ceiling; one that filters networks is not.
_X402_DECIDERS = {"registerPolicy", "onBeforePaymentCreation"}
#: Fields of a payment requirement that hold the amount it asks for (x402 v2, v1).
_REQUIREMENT_AMOUNT = {"amount", "maxAmountRequired"}
#: Literal options that turn an SDK safeguard off: (package the file imports, option, the
#: value that disables it, fact kind). Verified against the published packages: x402
#: spendControls from @x402/core 2.23.0; MPP allowUnsignedPush, allowUnpinnedChannel and
#: feeBudget from @stellar/mpp 0.7.0; checkOnChainState defaults to true from 0.5.0.
_SAFEGUARD_SWITCHES = (
    ("@x402/", "spendControls", "false", "x402_spend_controls_disabled"),
    ("@x402/", "maxAmountPerPayment", "false", "x402_spend_controls_disabled"),
    ("@x402/", "allowedAssets", "true", "x402_any_asset"),
    ("@stellar/mpp", "allowUnsignedPush", "true", "mpp_unsigned_push"),
    ("@stellar/mpp", "checkOnChainState", "false", "mpp_channel_state_unchecked"),
    ("@stellar/mpp", "allowUnpinnedChannel", "true", "mpp_unpinned_channel"),
)
#: @stellar/mpp server methods: `stellar(...)`, `stellar.charge(...)` or `charge(...)` from
#: the charge entry point, and the same with `channel` from the channel entry point.
_MPP_SERVER = re.compile(r"^@stellar/mpp/(?P<mode>charge|channel)/server\.(?:stellar|stellar\.(?:charge|channel)|charge|channel)$")
# ---- x402 / MPP sellers (resource servers that take payment by hand)
#: Request headers that carry a payment from the payer (x402 v2 PAYMENT-SIGNATURE, v1
#: X-PAYMENT, and the X-PAYMENT-SIGNATURE / X-PAYMENT-TX variants hand-written sellers use).
_PAYMENT_HEADER = re.compile(r"^(?:payment-signature|x-payment|x-payment-signature|x-payment-tx)$", re.I)
#: A constant naming that header (`HEADERS.paymentSignature`, `X_PAYMENT_HEADER`).
_PAYMENT_HEADER_CONST = re.compile(r"(?:^|\.)(?:payment_?signature|x_?payment)(?:_?header)?$", re.I)
#: SDK decoders whose result is the payer's payload.
_PAYMENT_DECODERS = {"decodePaymentSignatureHeader", "decodePaymentHeader", "decodeXPaymentHeader", "decodePayment"}
#: Facilitator calls: settle(payload, requirements) moves the money, verify(...) only checks it.
_SETTLE_SINK = {"settle", "settlePayment"}
_VERIFY_SINK = {"verify", "verifyPayment"}
#: UI component libraries: a module importing one runs in front of a person.
_UI_PACKAGES = ("react", "react-dom", "preact", "vue", "svelte", "solid-js")
#: Wallet SDKs whose signer is the user's wallet, which shows each transaction for approval
#: (Freighter, Stellar Wallets Kit and xBull, Albedo, LOBSTR, WalletConnect).
_WALLET_PACKAGES = re.compile(r"^(?:@stellar/freighter-api|@creit\.tech/(?:stellar-wallets-kit|xbull-wallet-connect)|"
                              r"@albedo-link/intent|@lobstrco/signer-extension-api|@walletconnect/)")
#: Verification of a client-signed envelope (not of a transaction hash, which S4 covers).
_ENVELOPE_VERIFY = re.compile(r"^verify(?:Envelope\w*|SignedXdr|TransactionXdr|Xdr)$")
#: Receivers of a generic `verify` that is a payment verification, not a JWT or signature one.
_PAYMENT_VERIFIER = re.compile(r"facilit|x402|payment|resource|verifier|paywall", re.I)
#: Calls into an x402 library (`@x402/core/server`, the v1 `x402` package, `@coinbase/x402`).
_X402_LIB = re.compile(r"^(?:@x402/|x402(?:/|\.|$)|@coinbase/x402)")
#: A facilitator URL: a literal, constant or template ending in /verify or /settle.
_FACILITATOR_PATH = re.compile(r"/(?P<op>verify|settle)/?[\"'`]?\s*$")
#: Calls that bind payer-chosen requirements to the server's own (S1 sanitizers).
_REQUIREMENT_MATCHERS = re.compile(r"^(?:findMatchingRequirements|findMatchingPaymentRequirements|isDeepStrictEqual|"
                                   r"deepEqual|deepStrictEqual|isEqual|equals|requirementsMatch\w*|matchesRequirements)$")
#: Settlement-result fields that say whether money moved; `ok`, `status` and the transaction
#: hash do not (a settlement_pending response carries a transaction with success: false).
_SETTLE_SUCCESS = {"success", "isSuccess"}
#: Response senders: the paid resource reaches the payer through one of these.
_RESPONDERS = re.compile(r"^(?:res|response|reply|c|ctx|h)\.(?:\w+\.)*(?:json|send|end|write|text|html|body|sendFile|stream|pipe)$|"
                         r"^(?:NextResponse|Response)\.json$|^(?:Response|NextResponse)$")
#: Upstream proxies: the paid request is forwarded to the service behind the paywall.
_PROXIES = re.compile(r"(?:^|\.)(?:proxy|proxyRequest|forward|forwardRequest|web)$", re.I)
#: Assertion helpers: `assert(settlement.success)` is a check like an if.
_ASSERTION = re.compile(r"^(?:assert\w*|invariant|ensure\w*|require\w*)$")
#: Calls that look a transaction up by hash (S4 sinks).
_TX_LOOKUP = re.compile(r"(?:^|\.)getTransaction$|\.transactions\.transaction$")
_TX_LOOKUP_URL = re.compile(r"/transactions/\$\{|[\"']getTransaction[\"']")
# ---- fee sponsors and relayers (rebuild or fee-bump a client's transaction)
#: Calls that load the account a builder uses as its source.
_LOAD_ACCOUNT = {"loadAccount", "getAccount"}
#: Labels of values taken from a client's envelope.
_FOREIGN = frozenset({"foreign_tx", "foreign_ops"})
#: A fee chosen by whoever calls: a tool or request argument, or the client's own envelope
#: (not a fee read from the network's fee stats, which no caller chooses).
_FEE_INPUT = frozenset({"model", "external"}) | _FOREIGN
#: Array methods whose callback judges each entry (`op.auth.every((e) => ...)`).
_PREDICATES = {"every", "some", "find", "findIndex", "filter", "forEach"}
#: What a sponsor that signs a rebuilt client operation has checked; once R1 and R2 hold, the
#: client's operation is authorized by the client alone and these labels no longer apply.
_SPONSORED = frozenset({"invoke_untrusted", "foreign_tx", "foreign_ops", "foreign_source", "foreign_fee"})
#: The Stellar fee-payer guide leaves the source check as this comment.
_SPONSOR_WARNING = re.compile(r"SECURITY:\s*Verify the (?:transaction|operation) source is not the fee[- ]?payer", re.I)
#: A replay store that lives in one process: `Store.memory()` from mppx or @stellar/mpp.
_MEMORY_STORE = re.compile(r"^(?:mppx(?:/\w+)?|@stellar/mpp(?:/[\w/]+)?)\.Store\.memory$")
_SAFE_URL_PREFIX = re.compile(r"^https?://[^/{}\s$]+(?:/|$)")
from .codeflow import AMOUNT_NAME, HANDLER_NAME, RECEIVED_NAME  # noqa: E402
from .auth_rules import (auth_tree_index as _auth_tree_index, js_call as _auth_call,  # noqa: E402
                         mark_payment_requirements as _mark_payment_requirements)
_NAME_SOURCES = {"userinput", "prompt", "payload", "command", "cmd", "code", "webhook", "query", "message", "body",
                 "request", "req", "event", "ctx"}
_TOOL_REGISTER = re.compile(r"(?:^|\.)(?:tool|registerTool|addTool|defineTool|createTool)$")
_HTTP_ROUTE = re.compile(r"(?:^|\.)(?:get|post|put|patch|delete|all|options|head)$")
_BOT_HANDLER = re.compile(r"(?:^|\.)(?:on|command|hears|action|callbackQuery|onText|message)$")
#: A first handler parameter with one of these names is the framework's object, not model input.
_CONTEXT_PARAMS = {"agent", "kit", "agentKit", "runtime", "ctx", "context", "client", "wallet", "server", "deps",
                   "env", "config", "app", "sdk", "stellar"}
_HANDLER_KEYS = {"execute", "handler", "func", "run", "call", "invoke"}
_SCHEMA_KEYS = {"inputSchema", "parameters", "schema", "argsSchema", "input_schema"}
_NEXT_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_JUMPS = {"throw_statement", "return_statement", "continue_statement", "break_statement"}


def _parsers():
    global _PARSERS
    if _PARSERS is None:
        import tree_sitter_javascript as tsj
        import tree_sitter_typescript as tst
        from tree_sitter import Language, Parser
        _PARSERS = {"js": Parser(Language(tsj.language())), "ts": Parser(Language(tst.language_typescript())),
                    "tsx": Parser(Language(tst.language_tsx()))}
    return _PARSERS


_PARSERS = None


def available() -> bool:
    try:
        _parsers()
        return True
    except ImportError:
        return False


def is_js(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(JS_SUFFIXES) and not lower.endswith((".d.ts", ".min.js"))


def _txt(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _unwrap(node):
    while node is not None and node.type in {"parenthesized_expression", "await_expression", "as_expression",
                                             "non_null_expression", "satisfies_expression", "type_assertion"}:
        named = [c for c in node.named_children if c.type not in {"type_annotation", "type_identifier", "predefined_type",
                                                                  "generic_type", "object_type", "union_type"}]
        if not named:
            return None
        node = named[0]
    return node


def _dotted(node) -> str:
    """a.b().c -> a.b.c ; this.x -> this.x ; new X() -> X."""
    parts: list[str] = []
    node = _unwrap(node)
    while node is not None:
        t = node.type
        if t in {"identifier", "property_identifier", "shorthand_property_identifier", "this", "super",
                 "private_property_identifier", "type_identifier"}:
            parts.append(_txt(node))
            break
        if t == "member_expression":
            prop = node.child_by_field_name("property")
            parts.append(_txt(prop))
            node = _unwrap(node.child_by_field_name("object"))
        elif t == "call_expression":
            node = _unwrap(node.child_by_field_name("function"))
        elif t == "new_expression":
            node = _unwrap(node.child_by_field_name("constructor"))
        elif t == "subscript_expression":
            node = _unwrap(node.child_by_field_name("object"))
        else:
            break
    return ".".join(reversed(parts))


def _string_value(node) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return "".join(_txt(c) for c in node.named_children if c.type in {"string_fragment", "escape_sequence"})
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.named_children):
        return "".join(_txt(c) for c in node.named_children)
    return None


def _args(call) -> list:
    args = call.child_by_field_name("arguments")
    return [] if args is None else [a for a in args.named_children if a.type != "comment"]


def _props(obj) -> dict:
    """Object literal -> {key: value node} (shorthand keys map to their identifier)."""
    out: dict = {}
    obj = _unwrap(obj)
    if obj is None or obj.type != "object":
        return out
    for child in obj.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            name = _string_value(key) if key is not None and key.type == "string" else _txt(key)
            out[name] = child.child_by_field_name("value")
        elif child.type == "shorthand_property_identifier":
            out[_txt(child)] = child
        elif child.type == "method_definition":
            out[_txt(child.child_by_field_name("name"))] = child
    return out


def _param_names(fn_node) -> set[str]:
    """Names a function's parameters bind (destructured ones too; types and defaults not)."""
    params = fn_node.child_by_field_name("parameters") or fn_node.child_by_field_name("parameter")
    names: set[str] = set()
    stack = [params]
    while stack:
        n = stack.pop()
        if n is None or n.type == "type_annotation":
            continue
        if n.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.add(_txt(n))
        elif n.type in {"required_parameter", "optional_parameter"}:
            stack.append(n.child_by_field_name("pattern"))
        elif n.type in {"assignment_pattern", "object_assignment_pattern"}:
            stack.append(n.child_by_field_name("left"))
        elif n.type == "pair_pattern":
            stack.append(n.child_by_field_name("value"))
        else:
            stack.extend(n.named_children)
    return names


def _returns_abort(node) -> bool:
    """A hook branch that refuses the payment: it throws, or returns `{ abort: true }`."""
    node = _unwrap(node)
    if node is not None and node.type == "statement_block":
        stmts = [c for c in node.named_children if c.type != "comment"]
        node = stmts[-1] if stmts else None
    if node is not None and node.type == "return_statement":
        node = _unwrap(node.named_children[0]) if node.named_children else None
    elif node is not None and node.type == "throw_statement":
        return True
    value = _unwrap(_props(node).get("abort")) if node is not None and node.type == "object" else None
    return value is not None and value.type == "true"


def _amount_ceiling(fn_node, hook: bool, resolve=None) -> bool:
    """An x402 policy, selector or hook that refuses requirements above a ceiling. A policy
    or selector keeps requirements through a predicate (filter, find, every) whose truth puts
    the requirement's `.amount` (or `.maxAmountRequired`) at or below a bound; a hook refuses
    (`return { abort: true }` or throw) where the amount exceeds one. Sorting by price,
    dropping zero amounts, filtering networks, or logging a large payment caps nothing.
    ``resolve`` maps a named callback (`reqs.filter(isCheap)`) to its function node."""
    params: set[str] = set()
    stack = [fn_node]
    while stack:
        n = stack.pop()
        if _is_function(n):
            params |= _param_names(n)
        stack.extend(n.named_children)

    def reads(side) -> bool:
        todo = [side]
        while todo:
            m = _unwrap(todo.pop())
            if m is None or _is_function(m):
                continue
            if m.type == "member_expression" and _txt(m.child_by_field_name("property")) in _REQUIREMENT_AMOUNT:
                root = m
                while root is not None and root.type in {"member_expression", "subscript_expression"}:
                    root = _unwrap(root.child_by_field_name("object"))
                if root is not None and root.type == "identifier" and _txt(root) in params:
                    return True
            if m.type == "identifier" and _txt(m) in params & _REQUIREMENT_AMOUNT:
                return True  # ({ amount }) => amount <= MAX
            todo.extend(m.named_children)
        return False

    def bounds(expr, holds: bool) -> bool:
        """`expr` being true (holds) or false puts the amount at or below a bound."""
        expr = _unwrap(expr)
        if expr is None:
            return False
        if expr.type == "unary_expression" and _txt(expr.child_by_field_name("operator")) == "!":
            return bounds(expr.child_by_field_name("argument"), not holds)
        if expr.type != "binary_expression":
            return False
        op = _txt(expr.child_by_field_name("operator"))
        left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
        if op in {"&&", "||"}:
            # a && b holds: both do; a || b fails: both fail. Otherwise each side must bound.
            either = (op == "&&") == holds
            return (bounds(left, holds) or bounds(right, holds)) if either else (bounds(left, holds) and bounds(right, holds))
        if op not in {"<", "<=", ">", ">="}:
            return False
        low, high = (left, right) if (op in {"<", "<="}) == holds else (right, left)
        return reads(low) and not reads(high)

    def verdict(callback) -> bool:
        """A predicate callback whose truth bounds the amount."""
        callback = _unwrap(callback)
        if callback is not None and not _is_function(callback) and resolve is not None:
            callback = resolve(callback)
        if not _is_function(callback):
            return False
        body = callback.child_by_field_name("body")
        if body is not None and body.type != "statement_block":
            return bounds(body, True)
        returns = [r for r in _own_nodes(body) if r.type == "return_statement" and r.named_children]
        return bool(returns) and all(bounds(r.named_children[0], True) for r in returns)

    nodes = list(_own_nodes(fn_node.child_by_field_name("body")))
    if not hook:
        for n in nodes:
            fn = _unwrap(n.child_by_field_name("function")) if n.type == "call_expression" else None
            if fn is not None and fn.type == "member_expression" and _args(n) \
                    and _txt(fn.child_by_field_name("property")) in {"filter", "find", "findLast", "every"} and verdict(_args(n)[0]):
                return True
        return False
    for n in nodes:
        if n.type != "if_statement":
            continue
        cond = n.child_by_field_name("condition")
        alternative = n.child_by_field_name("alternative")
        alt = alternative.named_children[0] if alternative is not None and alternative.named_children else None
        if _returns_abort(n.child_by_field_name("consequence")) and bounds(cond, False):
            return True  # if (amount > MAX) return { abort: true }
        if alt is not None and _returns_abort(alt) and bounds(cond, True):
            return True  # if (amount <= MAX) { ... } else throw
    return False


def _own_nodes(node):
    """Nodes of a function body, not of the functions nested in it."""
    stack = [node] if node is not None else []
    while stack:
        n = stack.pop()
        yield n
        stack.extend(c for c in n.named_children if not _is_function(c))


def _number(node) -> int | float:
    """A JS number literal's value: 1_000, 1e9, 0x5F5E100, 0o17, 0b1, 100n, 50.5 (0 if unreadable)."""
    text = _txt(node).replace("_", "")
    text = text[:-1] if text.endswith("n") else text
    try:
        return int(text, 0)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return 0


def _controls_off(config: dict) -> bool:
    """x402 client config with `spendControls: false` or `{ maxAmountPerPayment: false }`."""
    value = _unwrap(config.get("spendControls"))
    if value is None:
        return False
    inner = _unwrap(_props(value).get("maxAmountPerPayment")) if value.type == "object" else value
    return inner is not None and inner.type == "false"


_FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition",
                   "generator_function_declaration", "generator_function", "function"}


def _is_function(node) -> bool:
    return node is not None and node.type in _FUNCTION_TYPES


def _rejects(node) -> str:
    """How a branch refuses the request: "throw" (it stops every caller too), "return" (it
    stops this function), or "" (it carries on: a log, a metric, `continue` past an entry)."""
    node = _unwrap(node)
    if node is not None and node.type == "statement_block":
        stmts = [c for c in node.named_children if c.type != "comment"]
        node = stmts[-1] if stmts else None
    if node is None:
        return ""
    if node.type == "throw_statement":
        return "throw"
    if node.type == "return_statement":
        return "return"
    if node.type == "expression_statement" and node.named_children:
        inner = _unwrap(node.named_children[0])
        if inner is not None and inner.type == "call_expression" and _dotted(inner) == "process.exit":
            return "throw"
    return ""


def _terminates(node) -> bool:
    if node is None:
        return False
    if node.type in _JUMPS:
        return True
    if node.type == "statement_block":
        stmts = [c for c in node.named_children if c.type != "comment"]
        return bool(stmts) and _terminates(stmts[-1])
    if node.type == "expression_statement":
        inner = _unwrap(node.named_children[0]) if node.named_children else None
        # process.exit(...) / res.status(4xx).json(...) followed by nothing still continues; only exit stops.
        return inner is not None and inner.type == "call_expression" and _dotted(inner) in {"process.exit"}
    return False


@dataclass
class _JsFunction:
    key: str
    module: str
    node: object
    cls: str | None
    params: list  # (name | None, pattern node)
    parent: str | None = None
    name: str = ""


@dataclass
class _Module:
    path: str
    root: object
    lines: list[str]
    text: str = ""
    imports: dict[str, str] = field(default_factory=dict)
    exports: dict[str, str] = field(default_factory=dict)
    constants: set[str] = field(default_factory=set)
    classes: dict[str, set[str]] = field(default_factory=dict)
    objects: dict[str, dict[str, str]] = field(default_factory=dict)  # const obj -> {prop: function key}


class JsProject:
    MAX_ROUNDS = 12

    def __init__(self, files: dict[str, str], profile: CodeProfile, entrypoints: dict[str, set[str]] | None = None):
        self.profile = profile
        self.modules: dict[str, _Module] = {}
        self.functions: dict[str, _JsFunction] = {}
        self.by_node: dict[tuple, str] = {}
        self.local_functions: dict[str | None, dict[str, str]] = {}
        self.entry: dict[str, list[set[str]]] = {}
        #: Per parameter, the labels of each property when every caller passed an object
        #: literal (None once any caller passed something else).
        self.entry_props: dict[str, list[dict[str, set[str]] | None | bool]] = {}
        self.returns: dict[str, set[str]] = {}
        self.captured: dict[str, dict[str, set[str]]] = {}
        self.called: set[str] = set()
        self.model_entries: set[str] = set()
        self.constraints: dict[str, dict[str, str]] = {}  # function key -> {prop: enum|max}
        self.tool_schemas: dict[str, set[str]] = {}  # model entry -> argument names in its schema
        self.schemas: dict[str, dict[str, dict[str, str]]] = {}  # module -> schema const -> constraints
        self.class_attrs: dict[str, dict[str, set[str]]] = {}
        self.wallet_names: dict[str, set[str]] = {}
        #: Who calls each project function, and what it calls (seller and sponsor checks
        #: look one or two calls away).
        self.callers: dict[str, set[str]] = {}
        self.callees: dict[str, set[str]] = {}
        #: Per function, what it checks about a client's envelope (fee sponsors, item 12): checks
        #: that stop the function when they fail, the subset that throw (they stop its callers
        #: too), checks in the boolean it returns (they hold where a caller gates on that value),
        #: and checks enclosing a call to it (`if (valid) await signFor(tx)`).
        self.sponsor_checks: dict[str, set[str]] = {}
        self.sponsor_throws: dict[str, set[str]] = {}
        self.sponsor_returns: dict[str, set[str]] = {}
        self.sponsor_enclosed: dict[str, set[str]] = {}
        #: Seller facts gathered while recording: settle calls per module, transaction-hash
        #: lookups, the proof checks each function makes, and route paths of handlers.
        self.settle_sinks: dict[str, dict[Location, None]] = {}
        self.tx_lookups: list[tuple[str | None, str, Location]] = []
        self.proof_checks: dict[str, set[str]] = {}
        self.proof_throws: dict[str, set[str]] = {}
        self.route_paths: dict[str, str] = {}
        #: Per route registration, the receiver it is registered on and the project functions
        #: it runs; per receiver (`module|app`), its `use` middlewares. A payment one step of a
        #: request verifies may be settled by another.
        self.routes: list[tuple[str, set[str]]] = []
        self.route_uses: dict[str, set[str]] = {}
        self._route_index: dict[str, tuple[list[int], list[str]]] | None = None
        self._receiver_routes: dict[str, list[int]] = {}
        self._settle_text: dict = {}
        self._proof_text: dict[str, tuple[bool, bool]] = {}
        self._field_settled: dict[tuple[str, str], bool] = {}
        self._declared: dict[tuple, dict[str, str]] = {}
        self._validators: dict[str, set[int]] = {}
        self._seller_scope: dict[str, bool] = {}
        self._owners: dict[str, list[str]] | None = None
        self.declared_entry = entrypoints or {}
        self._propagated = False
        parsers = _parsers()
        for path, content in sorted(files.items()):
            if not is_js(path):
                continue
            lower = path.lower()
            parser = parsers["tsx" if lower.endswith(".tsx") else "ts" if lower.endswith((".ts", ".mts", ".cts")) else "js"]
            try:
                tree = parser.parse(content.encode("utf-8", "replace"))
            except (ValueError, RecursionError):
                self.profile.unparsed.append(path)
                continue
            root = tree.root_node
            if root.has_error and self._error_share(root) > 0.02:
                # Too much of the file did not parse; leave it to lexical and AI review.
                self.profile.unparsed.append(path)
                continue
            self.modules[path] = _Module(path, root, content.splitlines(), content)
        # Workspace packages: `import { x } from "@scope/pkg"` resolves to the package's source.
        self.packages: dict[str, str] = {}
        for path, content in files.items():
            if path.rsplit("/", 1)[-1] == "package.json":
                try:
                    name = json.loads(content).get("name")
                except ValueError:
                    continue
                if isinstance(name, str) and name:
                    self.packages[name] = posixpath.dirname(path)
        for module in self.modules.values():
            self._index(module)
        for module in self.modules.values():
            self._entrypoints(module)
        _mark_payment_requirements(self)

    @staticmethod
    def _error_share(root) -> float:
        bad = 0
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "ERROR" or node.is_missing:
                bad += max(1, node.end_byte - node.start_byte)
                continue
            if node.has_error:
                stack.extend(node.children)
        return bad / max(1, root.end_byte - root.start_byte)

    @property
    def analysed(self) -> list[str]:
        return sorted(self.modules)

    # --------------------------------------------------------------- indexing
    def _resolve_path(self, current: str, source: str) -> str | None:
        if not source.startswith("."):
            return self._resolve_package(source)
        base = posixpath.normpath(posixpath.join(posixpath.dirname(current), source))
        stem = re.sub(r"\.(?:js|mjs|cjs|jsx)$", "", base)
        for candidate in [base, *(stem + s for s in _RESOLVE_SUFFIXES)]:
            if candidate in self.modules:
                return candidate
        return None

    def _resolve_package(self, source: str) -> str | None:
        parts = source.split("/")
        for n in (2, 1):
            name = "/".join(parts[:n])
            root = self.packages.get(name)
            if root is None:
                continue
            rest = "/".join(parts[n:])
            bases = [posixpath.join(root, rest), posixpath.join(root, "src", rest)] if rest else \
                    [posixpath.join(root, "src", "index"), posixpath.join(root, "index"), posixpath.join(root, "src")]
            for base in bases:
                base = base.lstrip("./") if base.startswith("./") else base
                for candidate in (base, *(base + s for s in _RESOLVE_SUFFIXES[1:])):
                    if candidate in self.modules:
                        return candidate
        return None

    def _import_target(self, module: _Module, source: str, name: str | None) -> str:
        resolved = self._resolve_path(module.path, source)
        if resolved:
            return f"module:{resolved}" if name is None else f"{resolved}:{name}"
        pkg = source.replace("node:", "")
        return f"lib:{pkg}" if name is None or name == "default" else f"lib:{pkg}.{name}"

    def _add_function(self, module: _Module, node, name: str, cls: str | None, parent: str | None) -> str:
        nk = (module.path, node.start_byte, node.end_byte)
        if nk in self.by_node:
            return self.by_node[nk]
        key = f"{module.path}:{(cls + '.') if cls else ''}{name}"
        if key in self.functions:
            # Several anonymous functions on one line (`a.filter((x) => x.some((y) => …))`)
            # need distinct keys; a reused key would make a function its own parent.
            base, n = f"{key}@{node.start_point[0] + 1}", 1
            key = base
            while key in self.functions:
                n += 1
                key = f"{base}#{n}"
        params_node = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        params: list = []
        if params_node is not None:
            items = [params_node] if params_node.type == "identifier" else params_node.named_children
            for p in items:
                if p.type in {"comment"}:
                    continue
                pattern = p.child_by_field_name("pattern") if p.type in {"required_parameter", "optional_parameter"} else p
                if pattern is not None and pattern.type == "this":
                    continue
                if pattern is not None and pattern.type == "assignment_pattern":
                    pattern = pattern.child_by_field_name("left")
                if pattern is not None and pattern.type == "rest_pattern":
                    pattern = pattern.named_children[0] if pattern.named_children else pattern
                pname = _txt(pattern) if pattern is not None and pattern.type == "identifier" else None
                params.append((pname, pattern))
        self.functions[key] = _JsFunction(key, module.path, node, cls, params, parent, name)
        self.by_node[nk] = key
        self.entry[key] = [set() for _ in params]
        self.entry_props[key] = [False for _ in params]  # False: no call seen yet
        self.returns[key] = set()
        if parent is not None or cls is None:
            self.local_functions.setdefault(parent if parent else f"module:{module.path}", {}).setdefault(name, key)
        return key

    def _index(self, module: _Module) -> None:
        root = module.root
        for stmt in root.named_children:
            self._index_statement(module, stmt, exported=False)
        # Every remaining function node (callbacks, nested helpers) gets a key and a parent.
        self._index_nested(module, root, None)

    def _index_statement(self, module: _Module, stmt, exported: bool) -> None:
        t = stmt.type
        if t == "export_statement":
            decl = stmt.child_by_field_name("declaration")
            value = stmt.child_by_field_name("value")
            if decl is not None:
                self._index_statement(module, decl, exported=True)
                name = decl.child_by_field_name("name")
                if name is not None:
                    module.exports[_txt(name)] = _txt(name)
                for d in decl.named_children:
                    if d.type == "variable_declarator" and d.child_by_field_name("name") is not None:
                        n = _txt(d.child_by_field_name("name"))
                        module.exports[n] = n
                if any(c.type == "default" for c in stmt.children) and name is not None:
                    module.exports["default"] = _txt(name)
            elif value is not None:
                if _is_function(value):
                    self._add_function(module, value, "default", None, None)
                    module.exports["default"] = "default"
                elif value.type == "identifier":
                    module.exports["default"] = _txt(value)
                elif value.type == "object":
                    self._index_object(module, "default", value)
                    module.exports["default"] = "default"
            for clause in stmt.named_children:
                if clause.type == "export_clause":
                    for spec in clause.named_children:
                        local = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias")
                        if local is not None:
                            module.exports[_txt(alias or local)] = _txt(local)
            source = stmt.child_by_field_name("source")
            if source is not None:  # export { x } from "./y"
                for clause in stmt.named_children:
                    if clause.type == "export_clause":
                        for spec in clause.named_children:
                            local = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias")
                            module.imports[_txt(alias or local)] = self._import_target(module, _string_value(source) or "", _txt(local))
                            module.exports[_txt(alias or local)] = _txt(alias or local)
            return
        if t == "import_statement":
            source = _string_value(stmt.child_by_field_name("source")) or ""
            for clause in stmt.named_children:
                if clause.type != "import_clause":
                    continue
                for part in clause.named_children:
                    if part.type == "identifier":
                        module.imports[_txt(part)] = self._import_target(module, source, "default")
                    elif part.type == "namespace_import":
                        ident = next((c for c in part.named_children if c.type == "identifier"), None)
                        if ident is not None:
                            module.imports[_txt(ident)] = self._import_target(module, source, None)
                    elif part.type == "named_imports":
                        for spec in part.named_children:
                            name = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias")
                            if name is not None:
                                module.imports[_txt(alias or name)] = self._import_target(module, source, _txt(name))
            return
        if t in {"function_declaration", "generator_function_declaration"}:
            name = stmt.child_by_field_name("name")
            self._add_function(module, stmt, _txt(name) or "anonymous", None, None)
            return
        if t in {"class_declaration", "abstract_class_declaration"}:
            self._index_class(module, _txt(stmt.child_by_field_name("name")), stmt)
            return
        if t in {"lexical_declaration", "variable_declaration"}:
            for d in stmt.named_children:
                if d.type != "variable_declarator":
                    continue
                name_node = d.child_by_field_name("name")
                value = _unwrap(d.child_by_field_name("value"))
                if name_node is None:
                    continue
                if name_node.type == "object_pattern" and value is not None and value.type == "call_expression" \
                        and _dotted(value.child_by_field_name("function")) == "require":
                    source = _string_value(_args(value)[0]) if _args(value) else ""
                    for prop in name_node.named_children:
                        if prop.type == "shorthand_property_identifier_pattern":
                            module.imports[_txt(prop)] = self._import_target(module, source or "", _txt(prop))
                        elif prop.type == "pair_pattern":
                            module.imports[_txt(prop.child_by_field_name("value"))] = self._import_target(
                                module, source or "", _txt(prop.child_by_field_name("key")))
                    continue
                if name_node.type != "identifier":
                    continue
                name = _txt(name_node)
                if value is None:
                    continue
                if value.type == "call_expression" and _dotted(value.child_by_field_name("function")) == "require":
                    source = _string_value(_args(value)[0]) if _args(value) else ""
                    module.imports[name] = self._import_target(module, source or "", None)
                elif _is_function(value):
                    self._add_function(module, value, name, None, None)
                elif value.type in {"class", "class_expression"}:
                    self._index_class(module, name, value)
                elif value.type == "object":
                    self._index_object(module, name, value)
                    if self._constant(value):
                        module.constants.add(name)
                    self._index_schema_object(module, name, value)
                elif self._constant(value):
                    module.constants.add(name)
                elif value.type == "call_expression":
                    shape = self._zod_shape(value)
                    if shape is not None:
                        self.schemas.setdefault(module.path, {})[name] = shape
            return
        if t == "expression_statement" and stmt.named_children:
            expr = stmt.named_children[0]
            if expr.type == "assignment_expression":
                left = _dotted(expr.child_by_field_name("left"))
                right = _unwrap(expr.child_by_field_name("right"))
                if left == "module.exports" and right is not None:
                    if right.type == "object":
                        for prop, value in _props(right).items():
                            if _is_function(value):
                                self._add_function(module, value, prop, None, None)
                            module.exports[prop] = _txt(value) if value is not None and value.type in {
                                "identifier", "shorthand_property_identifier"} else prop
                    elif right.type == "identifier":
                        module.exports["default"] = _txt(right)
                    elif _is_function(right):
                        self._add_function(module, right, "default", None, None)
                        module.exports["default"] = "default"
                elif left.startswith(("exports.", "module.exports.")) and right is not None:
                    prop = left.rsplit(".", 1)[-1]
                    if _is_function(right):
                        self._add_function(module, right, prop, None, None)
                    module.exports[prop] = _txt(right) if right.type == "identifier" else prop

    def _index_class(self, module: _Module, name: str, node) -> None:
        body = node.child_by_field_name("body")
        methods: set[str] = set()
        for item in (body.named_children if body is not None else []):
            if item.type == "method_definition":
                mname = _txt(item.child_by_field_name("name"))
                self._add_function(module, item, mname, name, None)
                methods.add(mname)
            elif item.type in {"public_field_definition", "field_definition"}:
                value = item.child_by_field_name("value")
                if _is_function(value):
                    mname = _txt(item.child_by_field_name("name") or item.child_by_field_name("property"))
                    self._add_function(module, value, mname, name, None)
                    methods.add(mname)
        module.classes[name] = methods
        self._owners = None

    def _index_object(self, module: _Module, name: str, obj) -> None:
        table: dict[str, str] = {}
        for prop, value in _props(obj).items():
            if _is_function(value):
                table[prop] = self._add_function(module, value, f"{name}.{prop}", None, None)
        module.objects[name] = table

    def _index_nested(self, module: _Module, node, parent: str | None) -> None:
        for child in node.named_children:
            current = parent
            if _is_function(child):
                key = self.by_node.get((module.path, child.start_byte, child.end_byte))
                if key is None:
                    name = child.child_by_field_name("name")
                    holder = node if node.type == "variable_declarator" else None
                    if name is None and holder is not None and (holder.child_by_field_name("name") or node).type == "identifier":
                        # `const safePath = (p) => …` inside a function is callable by that name.
                        name = holder.child_by_field_name("name")
                    label = _txt(name) if name is not None else f"<anonymous@{child.start_point[0] + 1}>"
                    key = self._add_function(module, child, label, None, parent)
                elif parent is not None and self.functions[key].parent is None and self.functions[key].cls is None:
                    self.functions[key].parent = parent
                current = key
            self._index_nested(module, child, current)

    def _constant(self, node) -> bool:
        node = _unwrap(node)
        if node is None:
            return False
        t = node.type
        if t in {"string", "number", "true", "false", "null", "regex"}:
            return True
        if t == "template_string":
            return not any(c.type == "template_substitution" for c in node.named_children)
        if t == "member_expression" and _dotted(node).startswith("process.env."):
            return True
        if t in {"array"}:
            return all(self._constant(c) for c in node.named_children if c.type != "comment")
        if t == "object":
            return all(self._constant(v) for v in _props(node).values() if v is not None)
        if t == "new_expression" and _dotted(node.child_by_field_name("constructor")) in {"Set", "Map"}:
            return all(self._constant(a) for a in _args(node))
        if t == "call_expression" and _dotted(node.child_by_field_name("function")) in {"Object.freeze", "new Set"}:
            return all(self._constant(a) for a in _args(node))
        if t == "binary_expression":
            return all(self._constant(c) for c in node.named_children)
        return False

    # ----------------------------------------------------------------- zod
    def _zod_constraint(self, node) -> str | None:
        """Constraint a zod chain puts on one property: enum (fixed values) or max (numeric bound)."""
        text = _txt(node)
        if not re.match(r"^\s*z\s*\.", text):
            return None
        if re.search(r"\bz\s*\.\s*(?:enum|literal|nativeEnum)\s*\(", text):
            return "enum"
        numeric = re.search(r"\bz\s*\.\s*(?:number|bigint|coerce\s*\.\s*number|coerce\s*\.\s*bigint)\s*\(", text)
        if numeric and re.search(r"\.\s*(?:max|lte|lt)\s*\(", text):
            return "max"
        if re.search(r"\.\s*refine\s*\(", text) and re.search(r"<=?\s*[A-Z_0-9]", text):
            return "max"
        return None

    def _zod_shape(self, node) -> dict[str, str] | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "call_expression":
            label = _dotted(node.child_by_field_name("function"))
            if label.startswith("z.") or label.endswith(".object"):
                args = _args(node)
                inner = node
                while inner is not None and inner.type == "call_expression" and _dotted(inner.child_by_field_name("function")) not in {"z.object", "z.strictObject"}:
                    fn = inner.child_by_field_name("function")
                    inner = _unwrap(fn.child_by_field_name("object")) if fn is not None and fn.type == "member_expression" else None
                if inner is not None and inner.type == "call_expression" and _args(inner):
                    return self._shape_from_object(_args(inner)[0])
                if args and _unwrap(args[0]) is not None and _unwrap(args[0]).type == "object":
                    return self._shape_from_object(args[0])
        if node.type == "object":
            return self._shape_from_object(node)
        return None

    def _shape_from_object(self, obj) -> dict[str, str]:
        out = {}
        for prop, value in _props(obj).items():
            c = self._zod_constraint(value) if value is not None else None
            if c:
                out[prop] = c
        return out

    def _index_schema_object(self, module: _Module, name: str, obj) -> None:
        shape = self._shape_from_object(obj)
        if shape:
            self.schemas.setdefault(module.path, {})[name] = shape

    def _schema_for(self, module: _Module, node) -> dict[str, str]:
        node = _unwrap(node)
        if node is None:
            return {}
        if node.type == "identifier":
            name = _txt(node)
            if name in self.schemas.get(module.path, {}):
                return self.schemas[module.path][name]
            target = module.imports.get(name, "")
            if ":" in target and not target.startswith(("lib:", "module:")):
                mod, sym = target.rsplit(":", 1)
                return self.schemas.get(mod, {}).get(sym, {})
            return {}
        if node.type == "member_expression":
            return {}
        return self._zod_shape(node) or {}

    # ------------------------------------------------------------- entrypoints
    def _mark_entry(self, key: str, label: str, reason: str, constraints: dict[str, str] | None = None,
                    schema_names: set[str] | None = None) -> None:
        if label == "model":
            self.model_entries.add(key)
            if schema_names:
                self.tool_schemas.setdefault(key, set()).update(schema_names)
        # A tool handler's model input is its first parameter; later ones are the framework's
        # context (MCP `extra`, AI-SDK options) or operator configuration (agent kits). Some kits
        # pass the agent first, `(agent, input)`: then the input is the second parameter.
        entry = self.entry[key]
        if label == "model":
            names = [name for name, _ in self.functions[key].params]
            first = 1 if len(names) > 1 and names[0] in _CONTEXT_PARAMS and names[1] not in _CONTEXT_PARAMS else 0
            entry = entry[first:first + 1]
        for params in entry:
            params.add(label)
        if constraints:
            self.constraints.setdefault(key, {}).update(constraints)
        fn = self.functions[key]
        self.profile.entrypoints.setdefault(f"{fn.module}:{fn.name}", reason)

    def _function_arg(self, node, path: str) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if _is_function(node):
            return self.by_node.get((path, node.start_byte, node.end_byte))
        return None

    def _entrypoints(self, module: _Module) -> None:
        stack = [module.root]
        while stack:
            node = stack.pop()
            stack.extend(node.named_children)
            if node.type == "call_expression" or node.type == "new_expression":
                callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
                label = _dotted(callee)
                args = _args(node)
                short = label.rsplit(".", 1)[-1]
                # MCP / agent frameworks: register a handler as an LLM tool.
                if _TOOL_REGISTER.search(label) or short in {"DynamicStructuredTool", "DynamicTool", "StructuredTool", "FunctionTool"}:
                    schema: dict[str, str] = {}
                    arg_names: set[str] = set()
                    for a in args:
                        if _unwrap(a) is not None and _unwrap(a).type == "object":
                            props = _props(a)
                            for key in _SCHEMA_KEYS:
                                if key in props:
                                    schema.update(self._schema_for(module, props[key]))
                            if not any(k in props for k in _SCHEMA_KEYS | _HANDLER_KEYS | {"description", "name", "title"}):
                                schema.update(self._shape_from_object(a))
                                arg_names.update(props)
                            for key_name in _SCHEMA_KEYS:
                                inner = _unwrap(props.get(key_name))
                                if inner is not None and inner.type == "object":
                                    arg_names.update(_props(inner))
                            for hk in _HANDLER_KEYS:
                                fk = self._function_arg(props.get(hk), module.path)
                                if fk:
                                    self._mark_entry(fk, "model", "LLM tool handler", schema, arg_names)
                        elif _unwrap(a) is not None and _unwrap(a).type == "identifier":
                            schema.update(self._schema_for(module, a))
                    for a in args:
                        fk = self._function_arg(a, module.path)
                        if fk:
                            self._mark_entry(fk, "model", "LLM tool handler", schema, arg_names)
                    continue
                if short == "setRequestHandler" and args and "CallTool" in _txt(args[0]):
                    for a in args[1:]:
                        fk = self._function_arg(a, module.path)
                        if fk:
                            self._mark_entry(fk, "model", "MCP CallTool handler")
                    continue
                # HTTP routes.
                first = _string_value(args[0]) if args else None
                receiver = label.rpartition(".")[0]
                if receiver and (short == "use" or _HTTP_ROUTE.search(label) and first is not None and first.startswith("/")):
                    members = {k for k in (self._middleware_key(module, a) for a in args) if k}
                    if short == "use":
                        self.route_uses.setdefault(f"{module.path}|{receiver}", set()).update(members)
                    elif members:
                        self.routes.append((f"{module.path}|{receiver}", members))
                if _HTTP_ROUTE.search(label) and first is not None and first.startswith("/") or \
                        short == "route" and first is not None and first.startswith("/"):
                    for a in args[1:]:
                        fk = self._function_arg(a, module.path)
                        if fk:
                            self._mark_entry(fk, "external", "HTTP route")
                            self.route_paths[fk] = first
                    continue
                if short == "use" and args and any(self._function_arg(a, module.path) for a in args) and re.search(r"^(?:app|router|server)\b", label):
                    for a in args:
                        fk = self._function_arg(a, module.path)
                        if fk:
                            self._mark_entry(fk, "external", "HTTP middleware")
                    continue
                # Chat bots: any user can send the message.
                if _BOT_HANDLER.search(label) and re.search(r"^(?:bot|client|telegraf|discord|slack|app)\b", label, re.I):
                    for a in args:
                        fk = self._function_arg(a, module.path)
                        if fk:
                            self._mark_entry(fk, "external", "chat bot handler")
                    continue
            # Tool objects pairing an input schema with an execute method (agent kits).
            if node.type == "object":
                props = _props(node)
                handler = next((props[k] for k in ("execute", "handler", "run") if k in props), None)
                schema_key = next((k for k in _SCHEMA_KEYS if k in props), None)
                if handler is not None and schema_key and ("name" in props or "description" in props):
                    fk = self._function_arg(handler, module.path)
                    if fk:
                        self._mark_entry(fk, "model", "LLM tool object", self._schema_for(module, props[schema_key]))
        # Next.js route handlers and API routes.
        path = module.path.lower()
        if re.search(r"(?:^|/)app/.*route\.(?:ts|js|mjs)$", path) or re.search(r"(?:^|/)pages/api/", path):
            for name, local in module.exports.items():
                if name in _NEXT_METHODS or (name == "default" and "pages/api/" in path):
                    key = self.local_functions.get(f"module:{module.path}", {}).get(local)
                    if key:
                        self._mark_entry(key, "external", "Next.js route handler")
        for name in self.declared_entry.get(module.path, set()):
            key = self.local_functions.get(f"module:{module.path}", {}).get(name)
            if key:
                self._mark_entry(key, "external", "declared entrypoint")

    # ----------------------------------------------------------------- resolve
    def resolve(self, module: _Module, callee, fn: _JsFunction | None, local_types: dict[str, str]) -> str | None:
        callee = _unwrap(callee)
        if callee is None:
            return None
        if _is_function(callee):
            return self.by_node.get((module.path, callee.start_byte, callee.end_byte))
        if callee.type == "identifier":
            name = _txt(callee)
            scope, seen = fn, set()
            while scope is not None and scope.key not in seen:
                seen.add(scope.key)
                key = self.local_functions.get(scope.key, {}).get(name)
                if key:
                    return key
                scope = self.functions.get(scope.parent) if scope.parent else None
            key = self.local_functions.get(f"module:{module.path}", {}).get(name)
            if key:
                return key
            if name in module.classes:
                ctor = f"{module.path}:{name}.constructor"
                return ctor if ctor in self.functions else None
            return self._imported(module, name)
        if callee.type == "member_expression":
            obj = _unwrap(callee.child_by_field_name("object"))
            prop = _txt(callee.child_by_field_name("property"))
            if obj is not None and obj.type == "this" and fn is not None and fn.cls:
                key = f"{fn.module}:{fn.cls}.{prop}"
                return key if key in self.functions else None
            if obj is not None and obj.type == "identifier":
                name = _txt(obj)
                if name in module.objects and prop in module.objects[name]:
                    return module.objects[name][prop]
                cls = local_types.get(name)
                if cls:
                    key = f"{cls}.{prop}"
                    if key in self.functions:
                        return key
                target = module.imports.get(name, "")
                if target.startswith("module:"):
                    return self._exported(target[7:], prop)
                if ":" in target and not target.startswith("lib:"):
                    mod, sym = target.rsplit(":", 1)
                    other = self.modules.get(mod)
                    local = other.exports.get(sym, sym) if other else sym
                    if other and local in other.objects and prop in other.objects[local]:
                        return other.objects[local][prop]
                if target.startswith("lib:") or (not target and name in _JS_GLOBALS):
                    return None
            owners = self._method_owners().get(prop, [])
            if len(owners) == 1 and prop not in {"constructor", "call", "apply", "bind", "then", "catch", "finally",
                                                 "get", "set", "has", "push", "map", "filter", "forEach", "toString"}:
                return f"{owners[0]}.{prop}"
        return None

    def _method_owners(self) -> dict[str, list[str]]:
        """Method name -> classes defining it (classes are fixed once modules are indexed)."""
        if self._owners is None:
            self._owners = {}
            for m in self.modules.values():
                for c, methods in m.classes.items():
                    for method in methods:
                        self._owners.setdefault(method, []).append(f"{m.path}:{c}")
        return self._owners

    def imported_value(self, module: _Module, name: str) -> set[str]:
        """Labels of a module-level value another project module exports under ``name``."""
        target = module.imports.get(name, "")
        if not target or target.startswith(("lib:", "module:")):
            return set()
        mod, sym = target.rsplit(":", 1)
        other = self.modules.get(mod)
        values = getattr(self, "globals", {})  # complete once every module's state is known
        return set(values.get(mod, {}).get(other.exports.get(sym, sym), set())) if other is not None else set()

    def _imported(self, module: _Module, name: str) -> str | None:
        target = module.imports.get(name, "")
        if not target or target.startswith(("lib:", "module:")):
            return None
        mod, sym = target.rsplit(":", 1)
        return self._exported(mod, sym)

    def _exported(self, mod: str, sym: str, depth: int = 0) -> str | None:
        other = self.modules.get(mod)
        if other is None or depth > 4:
            return None
        local = other.exports.get(sym, sym)
        key = self.local_functions.get(f"module:{mod}", {}).get(local)
        if key:
            return key
        if local in other.classes:
            ctor = f"{mod}:{local}.constructor"
            return ctor if ctor in self.functions else None
        target = other.imports.get(local, "")
        if target and not target.startswith(("lib:", "module:")):
            m2, s2 = target.rsplit(":", 1)
            return self._exported(m2, s2, depth + 1)
        return None

    def class_of(self, module: _Module, ctor) -> str | None:
        name = _dotted(ctor)
        if name in module.classes:
            return f"{module.path}:{name}"
        target = module.imports.get(name, "")
        if target and not target.startswith(("lib:", "module:")):
            mod, sym = target.rsplit(":", 1)
            other = self.modules.get(mod)
            local = other.exports.get(sym, sym) if other else sym
            if other and local in other.classes:
                return f"{mod}:{local}"
        return None

    # ---------------------------------------------------------------- analysis
    def run(self) -> None:
        for key, fn in self.functions.items():
            for module in [self.modules[fn.module]]:
                pass
        # Pass 0: which functions are referenced anywhere (called, passed, exported).
        for module in self.modules.values():
            stack = [module.root]
            while stack:
                node = stack.pop()
                stack.extend(node.named_children)
                if node.type in {"call_expression", "new_expression"}:
                    callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
                    key = self.resolve(module, callee, None, {})
                    if key:
                        self.called.add(key)
                    for a in _args(node):
                        fk = self._function_arg(a, module.path) or (self.resolve(module, a, None, {}) if _unwrap(a) is not None and _unwrap(a).type in {"identifier", "member_expression"} else None)
                        if fk:
                            self.called.add(fk)
        exported = {self.local_functions.get(f"module:{m.path}", {}).get(local)
                    for m in self.modules.values() for local in m.exports.values()}
        for key, fn in self.functions.items():
            public = fn.parent is None and (key in exported or fn.cls is not None) and not fn.name.startswith(("_", "#"))
            if key not in self.called and public and not any(self.entry[key]) and fn.name != "constructor":
                for i, (pname, pattern) in enumerate(fn.params):
                    named = (pname or "").lower().replace("_", "") in _NAME_SOURCES
                    label = "external" if named and HANDLER_NAME.search(fn.name or "") else "caller"
                    self.entry[key][i].add(label)
                if fn.params:
                    self.profile.entrypoints.setdefault(f"{fn.module}:{fn.name}", "public function with no caller in project")
        self.globals = {path: self._module_state(m) for path, m in self.modules.items()}
        changed, rounds = True, 0
        while changed and rounds < self.MAX_ROUNDS:
            changed, rounds = False, rounds + 1
            for key in list(self.functions):
                before = ([set(p) for p in self.entry[key]], set(self.returns[key]),
                          {k: set(v) for k, v in self.captured.get(key, {}).items()})
                self._analyse(key, record=False)
                after = ([set(p) for p in self.entry[key]], set(self.returns[key]),
                         {k: set(v) for k, v in self.captured.get(key, {}).items()})
                changed |= before != after
            changed |= self._propagated
            self._propagated = False
        for path, module in self.modules.items():
            _JsInterp(self, module, None, record=True).block(module.root.named_children, dict(self.globals[path]))
        for key in self.functions:
            self._analyse(key, record=True)
        for module in self.modules.values():
            self._scan_payment_settings(module)
        self._tx_proof_facts()
        for locations in self.settle_sinks.values():
            for location in locations:
                self.profile.add_fact("x402_settle_call", location)

    # ------------------------------------------------------------ SDK settings
    def _module_label(self, module: _Module, callee) -> str:
        """A call's label with the module's library imports expanded."""
        label = _dotted(callee)
        head, _, rest = label.partition(".")
        target = module.imports.get(head, "")
        if target.startswith("lib:"):
            return target[4:].strip(".") + ("." + rest if rest else "")
        return label

    @staticmethod
    def imports_package(module: _Module, prefix: str) -> bool:
        return any(t.startswith("lib:" + prefix) for t in module.imports.values())

    def browser_client(self, module: _Module) -> bool:
        """Code that runs in the user's browser or pays through the user's wallet: a
        `"use client"` module, one under a browser/ directory, a UI component module (React,
        Preact, Vue, Svelte), or one that imports a wallet (Freighter, Stellar Wallets Kit).
        The person holding the wallet sees the amount and approves each payment."""
        first = next((c for c in module.root.named_children if c.type != "comment"), None)
        if first is not None and first.type == "expression_statement" and _string_value(
                first.named_children[0] if first.named_children else None) == "use client":
            return True
        if re.search(r"(?:^|/)browser/", module.path):
            return True
        for target in module.imports.values():
            package = target[4:] if target.startswith("lib:") else ""
            if any(package == ui or package.startswith((ui + ".", ui + "/")) for ui in _UI_PACKAGES) \
                    or _WALLET_PACKAGES.match(package):
                return True
        return False

    def seller_scope(self, module: _Module) -> bool:
        """The module takes x402 or MPP payments: it imports a payment SDK or reads a payment header."""
        if module.path not in self._seller_scope:
            self._seller_scope[module.path] = any(self.imports_package(module, p) for p in ("@x402/", "@stellar/mpp", "mppx")) \
                or bool(re.search(r"payment-signature|x-payment|paymentSignature|X_PAYMENT", module.text, re.I))
        return self._seller_scope[module.path]

    def _options_object(self, module: _Module, node):
        """An options argument: an object literal, or a module constant bound to one."""
        node = _unwrap(node)
        if node is not None and node.type == "identifier":
            name = _txt(node)
            for stmt in module.root.named_children:
                decl = stmt.child_by_field_name("declaration") if stmt.type == "export_statement" else stmt
                if decl is None or decl.type not in {"lexical_declaration", "variable_declaration"}:
                    continue
                for d in decl.named_children:
                    if d.type == "variable_declarator" and _txt(d.child_by_field_name("name")) == name:
                        node = _unwrap(d.child_by_field_name("value"))
        return node if node is not None and node.type == "object" else None

    def _scan_payment_settings(self, module: _Module) -> None:
        """Literal switches that turn an x402 or MPP safeguard off, and how each @stellar/mpp
        server is configured. Whether they matter depends on the installed version, which
        agentic_paths reads from the lockfile."""
        stack = [module.root]
        while stack:
            node = stack.pop()
            stack.extend(node.named_children)
            if node.type == "pair":
                key = node.child_by_field_name("key")
                name = _string_value(key) if key is not None and key.type == "string" else _txt(key)
                value = _unwrap(node.child_by_field_name("value"))
                for package, option, off, kind in _SAFEGUARD_SWITCHES:
                    if name == option and value is not None and value.type == off and self.imports_package(module, package):
                        extra = {"browser": self.browser_client(module)} if package == "@x402/" else {}
                        self.profile.add_fact(kind, self.location(module, node), f"{option}: {off}", **extra)
                continue
            if node.type != "call_expression":
                continue
            label = self._module_label(module, node.child_by_field_name("function"))
            args = _args(node)
            first = _unwrap(args[0]) if args else None
            if label.endswith(".setSpendControls") and first is not None and first.type == "false" \
                    and self.imports_package(module, "@x402/"):
                self.profile.add_fact("x402_spend_controls_disabled", self.location(module, node), "setSpendControls(false)",
                                      browser=self.browser_client(module))
            mode = _MPP_SERVER.match(label)
            options = self._options_object(module, args[0]) if mode and args else None
            if options is None:
                continue
            props = _props(options)
            if "store" not in props and any(c.type == "spread_element" for c in options.named_children):
                continue  # the store may come in through the spread
            store = _unwrap(props.get("store"))
            store_kind = "none" if store is None else "memory" if store.type == "call_expression" and _MEMORY_STORE.match(
                self._module_label(module, store.child_by_field_name("function"))) else "other"
            fee_cap = _unwrap(props.get("maxFeeBumpStroops"))
            fee_cap_value = _number(fee_cap) if fee_cap is not None and fee_cap.type == "number" else 0
            fee_payer = _props(props.get("feePayer")) if props.get("feePayer") is not None else {}
            network = _unwrap(props.get("network"))
            self.profile.add_fact(
                "mpp_server", self.location(module, node), f"@stellar/mpp {mode.group('mode')} server",
                mode=mode.group("mode"), store=store_kind, max_fee_bump=fee_cap_value,
                fee_bump_signer="feeBumpSigner" in fee_payer or "feeBumpSigner" in props, fee_budget="feeBudget" in props,
                network=(_string_value(network) or _txt(network)) if network is not None else "")

    def _module_state(self, module: _Module) -> dict[str, set[str]]:
        state: dict[str, set[str]] = {}
        _JsInterp(self, module, None, record=False).block(module.root.named_children, state)
        return state

    def _analyse(self, key: str, *, record: bool) -> None:
        fn = self.functions[key]
        module = self.modules[fn.module]
        state = {k: set(v) for k, v in self.globals.get(fn.module, {}).items()}
        for name, tags in self.captured.get(key, {}).items():
            state[name] = state.get(name, set()) | tags
        interp = _JsInterp(self, module, fn, record=record)
        for (pname, pattern), props in zip(fn.params, self.entry_props.get(key, [])):
            # Only when callers are known: an entry point (tool handler, route, public API)
            # receives arbitrary objects, so its parameters stay whole.
            if pname and isinstance(props, dict) and not any(self.entry[key][i] & {"model", "external", "caller"}
                                                             for i in range(len(fn.params)) if key in self.model_entries):
                interp.literal_params[pname] = props
        constraints = self.constraints.get(key, {})
        for (pname, pattern), tags in zip(fn.params, self.entry[key]):
            interp.bind(pattern, set(tags), state, source_key=pname, constraints=constraints)
        if record and key in self.model_entries:
            names = set()
            for pname, pattern in fn.params:
                if pname:
                    names.add(pname)
                elif pattern is not None and pattern.type == "object_pattern":
                    names |= {_txt(c.child_by_field_name("key") or c.child_by_field_name("left") or c)
                              for c in pattern.named_children}
            names |= set(self.tool_schemas.get(key, ()))
            secret_names = sorted(n for n in names if _SECRET_ARG.search(n))
            if secret_names:
                loc = fn.node
                self.flow("secret_via_model", module, fn, loc, {"model", "secret"},
                          "tool arguments carry secret keys: " + ", ".join(secret_names))
        if constraints and record:
            # Schema constraints are enforced before the handler runs (the SDK rejects the call).
            if "enum" in constraints.values():
                self.control("allowlist", module, fn.node)
            if "max" in constraints.values():
                self.control("amount_cap", module, fn.node)
        body = fn.node.child_by_field_name("body")
        if body is None:
            return
        if body.type == "statement_block":
            interp.block(body.named_children, state)
        else:  # concise arrow body
            interp.returned |= interp.tags(body, state)
            interp.check_return(body, interp.returned)
            interp.sponsor_returns |= interp._sponsor_guards(body, state)  # (tx) => tx.source === P
        self.returns[key] |= interp.returned
        self.sponsor_checks.setdefault(key, set()).update(interp.sponsor_checks)
        self.sponsor_throws.setdefault(key, set()).update(interp.sponsor_throws)
        self.sponsor_returns.setdefault(key, set()).update(interp.sponsor_returns)
        if record:
            self.proof_checks.setdefault(key, set()).update(interp.proof_checks)
            self.proof_throws.setdefault(key, set()).update(interp.proof_throws)
            self._seller_facts(fn, module, interp)

    # ----------------------------------------------------------------- sellers
    #: Settlement in a module or function. Name suffixes are bounded (\w{0,64}): an unbounded
    #: \w* after a short literal backtracks quadratically on one long word that repeats it.
    _SETTLES = re.compile(r"(?i:settle)\w{0,64}\s*\(|\.(?:submitTransaction|sendTransaction|submitAsyncTransaction)\s*\(|"
                          r"\.on\(\s*[\"'](?:finish|close)[\"']")
    _MOVES_FUNDS = re.compile(r"Operation\.(?:payment|pathPayment\w{0,64}|createAccount)\s*\(|\.transfer\s*\(|"
                              r"invokeContract\w{0,64}\s*\(")

    def _settles(self, path: str, text: str) -> bool:
        """Settlement text in a module or function (searched once per key)."""
        if path not in self._settle_text:
            self._settle_text[path] = bool(self._SETTLES.search(text))
        return self._settle_text[path]

    def _middleware_key(self, module: _Module, node) -> str | None:
        """The project function a route registration argument stands for: a function literal,
        a named function, or the factory a call such as `paywall()` runs."""
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "call_expression":
            node = node.child_by_field_name("function")
        return self.resolve(module, node, None, {}) if _unwrap(node) is not None else None

    def _settled_downstream(self, fn: _JsFunction, interp: "_JsInterp") -> bool:
        """A verifying middleware whose payment is settled by another step of the request:
        every route chain that runs it (`app.get(path, paywall(), settleFirst(), handler)`, with
        the receiver's `use` middlewares) has a member that settles or submits; or, outside any
        known chain, a module that reads the request field it sets (`req.paymentXdr`) settles."""
        mine = set()
        key = fn.key
        while key is not None and key not in mine:
            mine.add(key)
            key = self.functions[key].parent if key in self.functions else None
        if self._route_index is None:
            index: dict[str, tuple[list[int], list[str]]] = {}
            for i, (receiver, members) in enumerate(self.routes):
                self._receiver_routes.setdefault(receiver, []).append(i)
                for k in members:
                    index.setdefault(k, ([], []))[0].append(i)
            for receiver, members in self.route_uses.items():
                for k in members:
                    index.setdefault(k, ([], []))[1].append(receiver)
            self._route_index = index
        routes = {i for k in mine for i in self._route_index.get(k, ([], []))[0]}
        receivers = {r for k in mine for r in self._route_index.get(k, ([], []))[1]}
        if routes or receivers:
            # The verifier's own module settles nothing (checked first), so any settling step
            # is another one. A route runs its receiver's `use` middlewares too.
            return all(self._route_settles(i) for i in routes) and all(self._receiver_settles(r) for r in receivers)
        for field_name in interp.request_fields:
            if (field_name, fn.module) not in self._field_settled:
                needle = re.compile(r"\." + re.escape(field_name) + r"\b")
                self._field_settled[(field_name, fn.module)] = any(
                    path != fn.module and self._settles("module:" + path, other.text) and needle.search(other.text)
                    for path, other in self.modules.items())
            if self._field_settled[(field_name, fn.module)]:
                return True
        return False

    def _step_settles(self, keys) -> bool:
        """A project function among ``keys`` settles or submits (its text searched once)."""
        for k in keys:
            if k in self.functions and k not in self._settle_text:
                self._settle_text[k] = bool(self._SETTLES.search(_txt(self.functions[k].node)))
            if self._settle_text.get(k):
                return True
        return False

    def _uses_settle(self, receiver: str) -> bool:
        if ("uses", receiver) not in self._settle_text:
            self._settle_text[("uses", receiver)] = self._step_settles(self.route_uses.get(receiver, ()))
        return self._settle_text[("uses", receiver)]

    def _route_settles(self, i: int) -> bool:
        if ("route", i) not in self._settle_text:
            receiver, members = self.routes[i]
            self._settle_text[("route", i)] = self._step_settles(members) or self._uses_settle(receiver)
        return self._settle_text[("route", i)]

    def _receiver_settles(self, receiver: str) -> bool:
        """Every request through the receiver's `use` middlewares reaches a settling step."""
        if ("receiver", receiver) not in self._settle_text:
            routes = self._receiver_routes.get(receiver, [])
            self._settle_text[("receiver", receiver)] = self._uses_settle(receiver) or (
                bool(routes) and all(self._route_settles(i) for i in routes))
        return self._settle_text[("receiver", receiver)]

    def _seller_facts(self, fn: _JsFunction, module: _Module, interp: "_JsInterp") -> None:
        """S1-S3 for one handler. A facilitator (it answers with the verification or settlement
        itself, or serves /verify and /settle) is not a resource server."""
        if interp.relay or not self.seller_scope(module):
            return
        route = self.route_paths.get(fn.key, "")
        if re.search(r"/(?:verify|settle)\b", route) or re.search(r"(?:^|/)(?:verify|settle)(?:/|$)|facilitator", module.path.lower()):
            return
        if interp.payer_requirements and interp.resource_after_sink:
            self.profile.add_fact("x402_requirements_from_payer", self.location(module, interp.payer_requirements[0]), fn.name)
        if interp.unchecked_deliveries:
            self.profile.add_fact("x402_settle_unchecked", self.location(module, interp.unchecked_deliveries[0]), fn.name,
                                  moves_funds=bool(self._MOVES_FUNDS.search(_txt(fn.node))))
        # Settlement anywhere in the module (a finish hook, a later middleware) may be the deferred one.
        if interp.verified_deliveries and not self._settles("module:" + module.path, module.text) \
                and not self._settled_downstream(fn, interp):
            delivery = self.location(module, interp.verified_deliveries[0])
            self.profile.add_fact("x402_verify_without_settle", self.location(module, interp.client_verified[0]), fn.name,
                                  delivery=delivery.line)

    #: A record of used proofs: a replay guard, a used-hash lookup or a unique insert (suffixes
    #: bounded as in _SETTLES).
    _PROOF_STORE = re.compile(r"\breplay\w*\s*\.|\b(?:used|seen|spent|redeemed|claimed|processed|consumed)\w*\s*(?:\.|\()|"
                              r"\bis\w{0,64}(?:Used|Seen|Spent|Redeemed|Processed)\s*\(|"
                              r"\b(?:record|mark|save|insert)\w{0,64}Payment\w{0,64}\s*\(|"
                              r"\.claim\s*\(|\bUNIQUE\b|ON CONFLICT|\.(?:setnx|setNX|sadd|sAdd)\s*\(")

    #: The server answers 402 Payment Required (a payer that reads a 402 does not match).
    _SENDS_402 = re.compile(r"\.(?:status|code)\(\s*402\s*\)|status:\s*402\b|,\s*402\s*\)|sendStatus\(\s*402\s*\)")

    def related(self, key: str | None) -> set[str]:
        """Functions whose checks guard what ``key`` does: its callers and the helpers they
        and it call, two calls away each way (``key`` itself excluded)."""
        if key is None:
            return set()

        def reach(start: set[str], graph: dict[str, set[str]]) -> set[str]:
            seen, frontier = set(start), set(start)
            for _ in range(2):
                frontier = {n for k in frontier for n in graph.get(k, ()) if n not in seen}
                seen |= frontier
            return seen
        return reach(reach({key}, self.callers), self.callees) - {key}

    def guard_scope(self, key: str | None) -> tuple[set[str], set[str]]:
        """(callers of ``key``, two calls up; helpers those callers and ``key`` call, two calls
        down). A failed check stops a caller before it calls ``key``; a helper's check stops
        anything only when it throws, or when the caller gates on what it returns."""
        if key is None:
            return set(), set()

        def reach(start: set[str], graph: dict[str, set[str]]) -> set[str]:
            seen, frontier = set(start), set(start)
            for _ in range(2):
                frontier = {n for k in frontier for n in graph.get(k, ()) if n not in seen}
                seen |= frontier
            return seen
        up = reach({key}, self.callers)
        return up - {key}, reach(up, self.callees) - up

    def _scope(self, key: str | None, hops: int = 2) -> list[str]:
        scope, frontier = [key] if key else [], [key] if key else []
        for _ in range(hops):
            frontier = [c for k in frontier for c in sorted(self.callers.get(k, ())) if c in self.functions and c not in scope]
            scope += frontier
        return scope

    def declarations(self, module: _Module, scope) -> dict[str, str]:
        """`const name = ...` initializers declared in a function (not in functions nested in
        it) or a module, by name: built once per scope, so looking a name up per call stays
        linear in the module."""
        key = (module.path, scope.start_byte, scope.end_byte)
        if key not in self._declared:
            found: dict[str, str] = {}
            stack = [scope]
            while stack:
                n = stack.pop()
                if n.type == "variable_declarator":
                    value = n.child_by_field_name("value")
                    found.setdefault(_txt(n.child_by_field_name("name")), _txt(value) if value is not None else "")
                if n is scope or not _is_function(n):
                    stack.extend(reversed(n.named_children))
            self._declared[key] = found
        return self._declared[key]

    def success_validator(self, key: str) -> set[int]:
        """Parameters a project function throws on unless their settlement succeeded:
        `function ensureSettled(s) { if (!s.success) throw ... }` or `assert(s.success)`.
        Calling it is a check like an `if` (a return would not stop the caller)."""
        if key not in self._validators:
            fn = self.functions[key]
            index = {name: i for i, (name, _) in enumerate(fn.params) if name}
            # ({ success }) => ...: the destructured field itself.
            fields = {_txt(c): i for i, (_, pattern) in enumerate(fn.params)
                      if pattern is not None and pattern.type == "object_pattern"
                      for c in pattern.named_children if c.type == "shorthand_property_identifier_pattern"}

            def reads(node) -> set[int]:
                out, stack = set(), [node]
                while stack:
                    n = stack.pop()
                    if n is None or _is_function(n):
                        continue
                    if n.type == "member_expression" and _txt(n.child_by_field_name("property")) in _SETTLE_SUCCESS:
                        root = _unwrap(n.child_by_field_name("object"))
                        if root is not None and root.type == "identifier" and _txt(root) in index:
                            out.add(index[_txt(root)])
                    elif n.type == "identifier" and _txt(n) in _SETTLE_SUCCESS and _txt(n) in fields:
                        out.add(fields[_txt(n)])
                    stack.extend(n.named_children)
                return out

            def throws(node) -> bool:
                node = _unwrap(node)
                if node is not None and node.type == "statement_block":
                    stmts = [c for c in node.named_children if c.type != "comment"]
                    node = stmts[-1] if stmts else None
                return node is not None and node.type == "throw_statement"

            found: set[int] = set()
            body = fn.node.child_by_field_name("body")
            stack = [body] if body is not None and body.type == "statement_block" else []
            while stack:
                n = stack.pop()
                if n is None or _is_function(n):
                    continue
                if n.type == "if_statement" and throws(n.child_by_field_name("consequence")):
                    found |= reads(n.child_by_field_name("condition"))
                elif n.type == "call_expression" and _ASSERTION.match(_dotted(n.child_by_field_name("function")).rsplit(".", 1)[-1]):
                    found |= reads(n.child_by_field_name("arguments"))
                stack.extend(n.named_children)
            self._validators[key] = found
        return self._validators[key]

    def _proof_text_facts(self, key: str) -> tuple[bool, bool]:
        """(answers 402, records used proofs) for one function's text, searched once."""
        if key not in self._proof_text:
            text = _txt(self.functions[key].node)
            self._proof_text[key] = (bool(self._SENDS_402.search(text)), bool(self._PROOF_STORE.search(text)))
        return self._proof_text[key]

    def _tx_proof_facts(self) -> None:
        """S4: a transaction hash the requester supplies is looked up and the result gates a
        paid response. Records which checks the lookup, its callers and the helpers they call
        (a throwing `assertBound(tx, challenge)`) make."""
        helpers: dict[str | None, list[str]] = {}
        for key, path, location in self.tx_lookups:
            scope = self._scope(key)
            if not any(self._proof_text_facts(k)[0] for k in scope):
                continue  # not a paywall: an explorer, a payer checking its own payment, a reporting tool
            if key not in helpers:
                helpers[key] = sorted(k for k in self.related(key) - set(scope) if k in self.functions)
            # The lookup and its callers stop the request by returning; a helper they call only
            # by throwing (a cache sweep's TTL comparison checks no proof).
            checks = set().union(set(), *(self.proof_checks.get(k, set()) for k in scope),
                                 *(self.proof_throws.get(k, set()) for k in helpers[key]))
            self.profile.add_fact("tx_hash_proof", location, path,
                                  store=any(self._proof_text_facts(k)[1] for k in scope + helpers[key]),
                                  payer="payer" in checks, challenge="challenge" in checks, age="age" in checks)

    def propagate_props(self, key: str, literal_props: list[dict[str, set[str]] | None]) -> None:
        slots = self.entry_props[key]
        for i, props in enumerate(literal_props[:len(slots)]):
            current = slots[i]
            if props is None:
                if current is not None:
                    slots[i] = None
                    self._propagated = True
            elif current is False:
                slots[i] = {k: set(v) for k, v in props.items()}
                self._propagated = True
            elif isinstance(current, dict):
                for prop, tags in props.items():
                    bucket = current.setdefault(prop, set())
                    if not tags <= bucket:
                        bucket |= tags
                        self._propagated = True

    def propagate(self, key: str, args: list[set[str]]) -> None:
        entry = self.entry[key]
        for i, tags in enumerate(args):
            if i < len(entry):
                if not tags <= entry[i]:
                    entry[i] |= tags
                    self._propagated = True
            elif entry:
                last = entry[-1]
                if not tags <= last:
                    last |= tags
                    self._propagated = True

    def capture(self, key: str, state: dict[str, set[str]]) -> None:
        bucket = self.captured.setdefault(key, {})
        for name, tags in state.items():
            if "." in name:
                continue
            current = bucket.setdefault(name, set())
            if not tags <= current:
                current |= tags
                self._propagated = True

    # ---------------------------------------------------------------- recording
    def location(self, module: _Module, node) -> Location:
        line = node.start_point[0] + 1
        text = module.lines[line - 1] if 0 < line <= len(module.lines) else ""
        return Location(module.path, line, text)

    def capability(self, name: str, module: _Module, node) -> None:
        self.profile.add_capability(name, self.location(module, node))

    def control(self, name: str, module: _Module, node) -> None:
        self.profile.add_control(name, self.location(module, node))

    def flow(self, category: str, module: _Module, fn: _JsFunction | None, node, labels: set[str], detail: str = "") -> None:
        loc = self.location(module, node)
        self.profile.add_flow(Flow(category, loc, frozenset(labels & (UNTRUSTED | {"secret"})), fn.name if fn else "<module>", detail))


class _JsInterp:
    def __init__(self, project: JsProject, module: _Module, fn: _JsFunction | None, *, record: bool):
        self.p, self.module, self.fn, self.record = project, module, fn, record
        self.returned: set[str] = set()
        self.local_types: dict[str, str] = {}
        self.aliases: dict[str, str] = {}
        self.approved = False
        self.literal_params: dict[str, dict[str, set[str]]] = {}
        #: Seller state for this function: settle calls whose success nothing branched on,
        #: verifications of a client-signed payload, and what was delivered after them.
        self.unchecked_settles: list = []
        #: A settlement result reached this function (a call returned one, or it came in with
        #: the state): only then can a variable in the state hold one.
        self.settle_seen = False
        self._state_seen = False
        self.client_verified: list = []
        self.unchecked_deliveries: list = []
        self.verified_deliveries: list = []
        self.payer_requirements: list = []
        self.sink_seen = False
        self.resource_after_sink: list = []
        self.relay = False
        self.requirements_bound = False
        #: Request fields this function sets from the payer's payment (`req.paymentXdr = xdr`):
        #: a later step of the request that reads one may settle it.
        self.request_fields: set[str] = set()
        #: Checks a transaction-hash proof passed (S4): store, payer, challenge, age.
        self.proof_checks: set[str] = set()
        self.proof_throws: set[str] = set()
        #: How the branch whose condition is being assumed refuses: "throw", "return" or "".
        self._rejecting = ""
        #: Checks made on a client's envelope so far (fee sponsors, R1/R2/R4): see
        #: JsProject.sponsor_checks. ``_enclosing`` holds the checks of the conditions around
        #: the statement being read, and ``_verdicts`` the variables holding a validator's result.
        self.sponsor_checks: set[str] = set()
        self.sponsor_throws: set[str] = set()
        self.sponsor_returns: set[str] = set()
        self._enclosing: list[set[str]] = []
        self._verdicts: dict[str, str] = {}
        #: Outbound requests after an unchecked settlement: a delivery only if the settlement
        #: is still unchecked when the handler ends (an audit hook before the check is not).
        self._pending_upstream: set[tuple[int, int]] = set()
        self._conditional = 0
        self._adjust: dict[tuple, tuple[set[str], set[str]]] = {}

    # ------------------------------------------------------------------ labels
    def canonical(self, callee) -> str:
        label = _dotted(callee)
        head, _, rest = label.partition(".")
        callee = _unwrap(callee)
        if callee is not None and callee.type == "identifier" and head in self.aliases:
            return self.aliases[head]
        if callee is not None and head in self.p.wallet_names.get(self.module.path, set()):
            return "browserwallet." + label
        target = self.module.imports.get(head, "")
        if target.startswith("lib:"):
            expanded = target[4:].strip(".")
            return expanded + ("." + rest if rest else "")
        return label

    def _model_entry(self) -> bool:
        """Inside a tool handler the model calls. Elsewhere a model-tainted object (a stored
        record looked up by a model-chosen id) does not mean the model supplied its fields."""
        return self.fn is not None and self.fn.key in self.p.model_entries

    def _cap(self, name: str, node) -> None:
        if self.record:
            self.p.capability(name, self.module, node)

    def _flow(self, category: str, node, labels: set[str], detail: str = "") -> None:
        if self.record:
            self.p.flow(category, self.module, self.fn, node, labels, detail)

    def _control(self, kind: str, node) -> None:
        # A condition that only chooses a value (`a ? b : c`) stops nothing; it is not a control.
        if self.record and not getattr(self, "_choosing", False):
            self.p.control(kind, self.module, node)

    # ------------------------------------------------------------------ values
    def tags(self, node, state: dict[str, set[str]]) -> set[str]:
        node = _unwrap(node)
        if node is None:
            return set()
        t = node.type
        if t in {"string", "template_string"} and t == "string":
            value = _txt(node)
            if _SEED_LITERAL.search(value):
                self._cap("secret_material", node)
                self._cap("hardcoded_secret", node)
                return {"secret"}
            return set()
        if t in {"number", "true", "false", "null", "undefined", "regex", "this", "super"}:
            return set()
        if t in {"identifier", "shorthand_property_identifier"}:
            return set(state.get(_txt(node), set()))
        if _is_function(node):
            key = self.p.by_node.get((self.module.path, node.start_byte, node.end_byte))
            if key:
                self.p.capture(key, state)
            return set()
        if t == "template_string":
            found: set[str] = set()
            head = self._url_head(node)
            head_tags = self.tags(head, state) if head is not None and head.type != "string_fragment" else set()
            if head is not None and (head.type == "string_fragment" and _txt(head).strip() or (
                    head.type != "string_fragment" and (_txt(head) in self.module.constants
                                                         or re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", _txt(head))))):
                found.add("structured")  # a fixed prefix: the text cannot be an arbitrary hash
            if (head is not None and head.type == "string_fragment" and _SAFE_URL_PREFIX.match(_txt(head))) or \
                    (head is not None and head.type != "string_fragment" and not head_tags & UNTRUSTED
                     and _dotted(head) and re.search(r"url|host|base|api|endpoint|server|horizon|rpc|origin", _dotted(head), re.I)):
                found.add("host_fixed")
            for child in node.named_children:
                if child.type == "template_substitution":
                    for inner in child.named_children:
                        found |= self.tags(inner, state)
                elif child.type == "string_fragment" and _SEED_LITERAL.search(_txt(child)):
                    self._cap("secret_material", node)
                    self._cap("hardcoded_secret", node)
                    found.add("secret")
            return found
        if t == "member_expression":
            return self.member(node, state)
        if t == "subscript_expression":
            obj = _unwrap(node.child_by_field_name("object"))
            index = node.child_by_field_name("index")
            if obj is not None and obj.type == "identifier" and _txt(obj) in self.module.constants:
                self.tags(index, state)
                self._control("allowlist", node)
                return set()
            label = _dotted(obj)
            if label == "process.argv" and _txt(_unwrap(index)) in {"0", "1"}:
                return set()  # the node binary and the script path, not arguments
            if label == "process.env":
                env = _string_value(index) or ""
                if env and _SECRET_ENV.search(env):
                    self._cap("secret_material", node)
                    return {"secret"}
                return set()
            container, key = self.tags(obj, state), self.tags(index, state)
            if key & UNTRUSTED and not container & UNTRUSTED:
                key = key | {"stored_record"}
            if self._names_payment_header(index) and container & {"external", "model"}:
                key = key | {"payment_header"}  # headers['x-payment']: the payer's payload
            return container | key
        if t in {"call_expression", "new_expression"}:
            found = self.call(node, state)
            fn = _unwrap(node.child_by_field_name("function")) if t == "call_expression" else None
            name = _dotted(fn) if fn is not None else ""
            if _HUMAN_DECISION.search(name.rsplit(".", 1)[-1]) and not _NOT_HUMAN.search(name):
                found = found | {"human_decision"}
            if (fn is not None and fn.type == "member_expression" and _LOOKUP.match(name.rsplit(".", 1)[-1])
                    and not self.tags(fn.child_by_field_name("object"), state) & UNTRUSTED):
                found = found | {"stored_record"}
            return found
        if t == "assignment_expression":
            value = self.tags(node.child_by_field_name("right"), state)
            self.assign(node.child_by_field_name("left"), value, state, node.child_by_field_name("right"))
            return value
        if t == "augmented_assignment_expression":
            value = self.tags(node.child_by_field_name("right"), state) | self.tags(node.child_by_field_name("left"), state)
            self.assign(node.child_by_field_name("left"), value, state, None)
            return value
        if t == "ternary_expression":
            # `inside(base, p) ? p : null` checks like an if statement: each branch runs only
            # when its side of the condition holds.
            cond = node.child_by_field_name("condition")
            self.tags(cond, state)
            self._settle_checked(cond, state)
            when_true = {k: set(v) for k, v in state.items()}
            # It controls a value only when it passes that value on (`a <= MAX ? a : MAX`);
            # choosing between constants (`step >= 1 ? "on" : "off"`) controls nothing.
            outcomes = (self._names_in(node.child_by_field_name("consequence"))
                        | self._names_in(node.child_by_field_name("alternative")))
            self._choosing = not (self._names_in(cond) & outcomes)
            self.assume(cond, True, when_true, node=node)
            when_false = {k: set(v) for k, v in state.items()}
            self.assume(cond, False, when_false, node=node)
            self._choosing = False
            return (self.tags(node.child_by_field_name("consequence"), when_true)
                    | self.tags(node.child_by_field_name("alternative"), when_false))
        if t in {"binary_expression"}:
            op = _txt(node.child_by_field_name("operator"))
            left = self.tags(node.child_by_field_name("left"), state)
            if op in {"&&", "||"}:
                # `s.success && next()`. In a chain `a && b && c` the nested level already checked
                # `a`; only its last operand is new here, so the chain is walked once in all.
                checked = _unwrap(node.child_by_field_name("left"))
                if checked is not None and checked.type == "binary_expression" \
                        and _txt(checked.child_by_field_name("operator")) in {"&&", "||"}:
                    checked = checked.child_by_field_name("right")
                self._settle_checked(checked, state)
            right = self.tags(node.child_by_field_name("right"), state)
            if op in {"===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"}:
                return set()
            if op == "+" and (self._fixed_host(node) or ("host_fixed" in left and not left & UNTRUSTED)):
                return left | right | {"host_fixed"}
            return left | right
        if t == "unary_expression":
            op = _txt(node.child_by_field_name("operator"))
            inner = self.tags(node.child_by_field_name("argument"), state)
            return set() if op in {"!", "typeof", "void"} else inner
        if t == "object":
            found = set()
            for prop, value in _props(node).items():
                if value is not None and value.type != "method_definition":
                    found |= self.tags(value, state)
            for child in node.named_children:
                if child.type == "spread_element":
                    found |= self.tags(child.named_children[0] if child.named_children else None, state)
            return found
        found = set()
        for child in node.named_children:
            if child.type in {"type_annotation", "type_arguments", "comment"}:
                continue
            found |= self.tags(child, state)
        return found

    def member(self, node, state) -> set[str]:
        obj = _unwrap(node.child_by_field_name("object"))
        prop = _txt(node.child_by_field_name("property"))
        key = _dotted(node)
        if key in state:
            return set(state[key])
        if obj is not None and obj.type == "identifier" and _txt(obj) in self.literal_params \
                and key.count(".") == 1:
            # Every caller passed an object literal: a property nobody passes is undefined.
            return set(self.literal_params[_txt(obj)].get(prop, set()))
        if obj is not None and obj.type == "this" and self.fn is not None and self.fn.cls:
            stored = self.p.class_attrs.get(f"{self.fn.module}:{self.fn.cls}", {}).get(prop)
            if stored is not None:
                return set(stored)
        if key.startswith("process.env."):
            if _SECRET_ENV.search(prop):
                self._cap("secret_material", node)
                return {"secret"}
            return set()
        if key == "process.argv" or key.startswith("process.argv."):
            # Whoever starts the process chooses argv: the operator, or an agent driving a CLI skill.
            return {"caller"}
        base = self.tags(obj, state)
        if "model" in base and _SECRET_ARG.search(prop) and "signer" not in base and self._model_entry():
            # A secret read out of model-supplied arguments: the key passed through the model.
            self._flow("secret_via_model", node, {"model", "secret"}, f"tool argument `{prop}` carries a secret key")
            return base | {"secret"}
        if "signer" in base:
            return {"secret"} if prop in {"secret", "rawSecretKey", "_secretKey", "secretKey"} else set()
        if prop == "operations" and "foreign_tx" in base:
            # The operations of a foreign envelope stay foreign wherever they are rebuilt.
            base = base | {"foreign_ops"}
        if "secret" in base and not _SECRET_ENV.search(prop):
            # A config or signer object that holds a secret also holds public fields
            # (address, network, url). Reading one of those is not reading the secret.
            base = (base - {"secret"}) | {"secret_possible"}
        if _REQUEST_KEY.search(key):
            base.add("external")
            if re.search(r"\.body\b", key):
                base.add("request_body")
        if obj is not None and obj.type == "identifier" and _txt(obj) in self.module.constants:
            return set()
        return base

    # ------------------------------------------------------------------ calls
    def call(self, node, state) -> set[str]:
        out = self._call(node, state)
        callee = node.child_by_field_name("constructor" if node.type == "new_expression" else "function")
        if _STRUCTURING.match(self.canonical(callee).rsplit(".", 1)[-1]):
            # A hash, JSON encoding or canonical form fixes the shape of what is later signed:
            # the requester can no longer make it equal a transaction hash.
            out = out | {"structured"}
        add, strip = self._adjust.pop((node.start_byte, node.end_byte), (set(), set()))
        out = (out - strip) | add
        self.settle_seen = self.settle_seen or "settle_result" in out
        return out

    def _call(self, node, state) -> set[str]:
        is_new = node.type == "new_expression"
        callee = node.child_by_field_name("constructor" if is_new else "function")
        label = self.canonical(callee)
        short = label.rsplit(".", 1)[-1]
        callee_u = _unwrap(callee)
        receiver_node = callee_u.child_by_field_name("object") if callee_u is not None and callee_u.type == "member_expression" else None
        receiver = self.tags(receiver_node, state) if receiver_node is not None else set()
        arg_nodes = _args(node)
        args = []
        for a in arg_nodes:
            if a.type == "spread_element":
                args.append(self.tags(a.named_children[0] if a.named_children else None, state))
            else:
                args.append(self.tags(a, state))
        every = set().union(*args) if args else set()
        self._seller(node, label, short, callee_u, receiver_node, receiver, arg_nodes, args, state, is_new)
        sponsored = self._sponsor(node, label, short, callee_u, receiver, arg_nodes, args, is_new, state)
        tree_inspected = _auth_call(self, node, label, short, receiver_node, receiver, arg_nodes, args, state, is_new)
        if sponsored:
            # A sponsor that checked the client's envelope signs only its own fee payment.
            receiver = receiver - sponsored
            target = _unwrap(receiver_node)
            if target is not None and _dotted(target) in state:
                state[_dotted(target)] = state[_dotted(target)] - sponsored

        # Callbacks receive what the call works on (promise values, iterated items).
        for a in arg_nodes:
            fk = self.p._function_arg(a, self.module.path)
            if fk and not label.endswith(("tool", "registerTool")):
                self.p.propagate(fk, [every | receiver] * max(1, len(self.p.entry[fk])))
                self.p.called.add(fk)
                if self.fn is not None:
                    self.p.callees.setdefault(self.fn.key, set()).add(fk)

        if _MASKING.match(short):
            # maskSecret(s) -> "SABC…WXYZ": what it prints is not the secret.
            return every - {"secret", "secret_possible"}
        key = self.p.resolve(self.module, callee, self.fn, self.local_types)
        if key:
            self.p.callers.setdefault(key, set()).add(self.fn.key if self.fn else f"module:{self.module.path}")
            if self.fn is not None:
                self.p.callees.setdefault(self.fn.key, set()).add(key)
            if self._enclosing:
                self.p.sponsor_enclosed.setdefault(key, set()).update(*self._enclosing)
        if key and _SIGN_FOREIGN.search(label) and not _WALLET_PROMPT.search(label):
            # A thin project wrapper named signTransaction / signAndSubmit still signs the
            # envelope it is given; judge the call site as well as the wrapper body. Only
            # when the first argument is the envelope (not a keypair or a method name).
            xdr = args[0] if args else set()
            first = _unwrap(arg_nodes[0]) if arg_nodes else None
            envelope = first is not None and "signer" not in xdr and (
                "foreign_tx" in xdr or re.search(r"xdr|envelope|\btx\b|transaction", _txt(first), re.I))
            if envelope and xdr & UNTRUSTED and "tx_built" not in xdr and not self.approved:
                self._cap("foreign_tx_signing", node)
                self._flow("foreign_signing", node, xdr, "an externally supplied transaction is signed")
        if key and key in self.p.functions and not _is_function(_unwrap(callee)) or (key and _is_function(_unwrap(callee))):
            self.p.propagate(key, args)
            literal = []
            for a in arg_nodes:
                a_u = _unwrap(a)
                if a_u is not None and a_u.type == "object" and not any(c.type == "spread_element" for c in a_u.named_children):
                    literal.append({prop: self.tags(v, state) for prop, v in _props(a_u).items()
                                    if v is not None and v.type != "method_definition"})
                else:
                    literal.append(None)
            self.p.propagate_props(key, literal)
            out = set(self.p.returns[key])
            if self.p.functions[key].name == "constructor":
                out = set(every)
            return out
        if is_new:
            cls = self.p.class_of(self.module, callee)
            if cls:
                ctor = f"{cls}.constructor"
                if ctor in self.p.functions:
                    self.p.propagate(ctor, args)
                return set(every)

        if label in {"Math.min"} and any(self._is_bound_value(a) for a in arg_nodes):
            return every | {"bounded"}

        # Fixed tables.
        if short in {"get"} and receiver_node is not None and _unwrap(receiver_node).type == "identifier" \
                and _txt(_unwrap(receiver_node)) in self.module.constants:
            self._control("allowlist", node)
            return set()

        # ---- sources
        if label.endswith("Keypair.fromSecret") or short in {"fromSecret", "fromRawEd25519Seed"} and "Keypair" in label:
            self._cap("key_custody", node)
            if args and "model" in args[0]:
                # Wherever it happens: a key the model supplied becomes the signing key.
                self._flow("secret_via_model", node, {"model", "secret"}, "a model-supplied value is used as a signing key")
            return {"signer"}
        if label.endswith("Keypair.random"):
            return {"signer", "fresh"}
        if short == "secret" and "signer" in receiver:
            # A key generated right here (Keypair.random) is not yet anyone's funded account.
            return {"secret", "fresh"} if "fresh" in receiver else {"secret"}
        if short in {"publicKey", "accountId", "toString"} and "signer" in receiver:
            # The server's own account: what it loads from this key is a sponsor's source account.
            return {"sponsor_key"} if short == "publicKey" else set()
        if _REQUEST_CALL.search(label):
            return receiver | {"external"} | ({"request_body"} if short in {"json", "text", "formData", "arrayBuffer", "blob"} else set())
        if _LLM_CALL.search(label) or _LLM_CALL.search("." + label):
            self._cap("llm_call", node)
            # The client object holds the provider API key; only the request content reaches the model.
            if "secret" in every:
                self._flow("secret_to_model", node, every, "secret material is placed in a model request")
            return {"model"}
        if _X402_SIGNER.search(label):
            self._cap("payment", node)
            self._cap("stellar_signing", node)
            return every | receiver
        if self.p.imports_package(self.module, "@x402/") and (
                (short in _X402_DECIDERS | {"setSpendControls"} and receiver_node is not None)
                or (is_new and short == "x402Client") or label.endswith("x402Client.fromConfig")):
            # A client whose policy, hook or selector compares the requirement's amount (or
            # whose config names a ceiling) does not pay whatever the server asks; one whose
            # spend controls are switched off carries that to the fetch it wraps.
            config = _props(arg_nodes[0]) if label.endswith("fromConfig") and arg_nodes else {}
            if label.endswith("fromConfig"):
                capped = self._config_caps(arg_nodes[0] if arg_nodes else None)
            else:
                # registerPolicy(fn) and new x402Client(selector) take a policy; the hook refuses.
                hook = short == "onBeforePaymentCreation"
                capped = short != "setSpendControls" and any(self._ceiling(a, hook) for a in arg_nodes)
                if hook and self.record and any(self._aborts(a) for a in arg_nodes):
                    self.p.profile.add_fact("x402_abort_hook", self.p.location(self.module, node), "a hook can refuse a payment")
            first = _unwrap(arg_nodes[0]) if arg_nodes else None
            off = _controls_off(config) or (short == "setSpendControls" and first is not None and first.type == "false")
            labels = ({"x402_capped"} if capped else set()) | ({"x402_off"} if off else set())
            target = _unwrap(receiver_node)
            if labels and target is not None and target.type == "identifier":
                # `client.onBeforePaymentCreation(...)` as a statement of its own configures `client`.
                state[_txt(target)] = state.get(_txt(target), set()) | labels
            return receiver | every | labels
        if _X402_PAYER.search(label):
            # The wrapped fetch signs whatever payment a 402 response requests. Without a
            # ceiling or selector, the paid server chooses recipient, asset and amount.
            self._cap("payment", node)
            self._cap("stellar_signing", node)
            capped = any(self._config_caps(a) or any(self._config_caps(v) for v in _props(a).values()) for a in arg_nodes)
            # A client configured in another module (`import { client } from "./client"`).
            client = every | set().union(*(self.p.imported_value(self.module, _txt(a)) for a in map(_unwrap, arg_nodes)
                                           if a is not None and a.type == "identifier" and _txt(a) not in state))
            if not capped and not self.approved and "x402_capped" not in client:
                self._flow("x402_unbounded", node, {"external"}, "402 responses decide the payment; no maximum or selector is set")
                if self.record and not label.startswith("@x402/"):
                    # Another x402 client library: the @x402/core release logic does not apply.
                    self.p.profile.add_fact("x402_other_client", self.p.location(self.module, node), label)
            if self.record and ("x402_off" in client or any(_controls_off(_props(a)) for a in arg_nodes)):
                # The client (from any module) or this wrap's own config switches spend controls off.
                self.p.profile.add_fact("x402_controls_off", self.p.location(self.module, node), "spend controls switched off")
            return every | receiver
        if is_new and short == "Server" and _LEDGER_ENDPOINT.search(label) and arg_nodes:
            # The RPC or Horizon server decides what the agent signs (simulation, auth entries, quotes).
            endpoint = self.tags(arg_nodes[0], state)
            if endpoint & UNTRUSTED and not self._fixed_host(arg_nodes[0]):
                self._flow("endpoint", node, endpoint, "the ledger RPC or Horizon URL comes from input")
            return set()
        if _HTTP_CALL.search(label):
            self._cap("network_fetch", node)
            url = arg_nodes[0] if arg_nodes else None
            if url is not None:
                url_u = _unwrap(url)
                if url_u is not None and url_u.type == "object":
                    url = _props(url_u).get("url") or _props(url_u).get("baseURL")
            url_tags = self.tags(url, state) if url is not None else set()
            host_tags = self.tags(self._url_head(url), state) if url is not None else set()
            untrusted_host = bool(host_tags & (UNTRUSTED - {"caller"})) and not self._fixed_host(url) \
                and "host_fixed" not in url_tags and not self._pinned_destination(arg_nodes[1:])
            if untrusted_host:
                self._flow("ssrf", node, url_tags, "request URL is not fixed to an allowed host")
            # An API key in an Authorization header to a fixed host is normal use; a secret in
            # the URL or body, or any secret sent to a host chosen by untrusted input, leaks it.
            body_tags = set()
            for a in arg_nodes[1:]:
                for prop, value in _props(a).items():
                    if prop not in {"headers", "auth"}:
                        body_tags |= self.tags(value, state)
            if "secret" in url_tags or "secret" in body_tags or ("secret" in every and untrusted_host):
                self._flow("secret_exfiltration", node, every, "secret material is sent over the network")
            return {"external"}
        if short in {"json", "text", "arrayBuffer", "blob"} and "external" in receiver:
            return receiver
        if _CHAIN_READ.search(label) or _CHAIN_READ.search("." + label):
            return every | receiver | {"chain"}

        # ---- sinks
        if _DESERIALIZE.search(label):
            data = args[0] if args else set()
            if data & UNTRUSTED:
                self._cap("code_execution", node)
                self._flow("command", node, data, "untrusted data is deserialized by a loader that runs embedded code")
            return data
        if short in _SQL_CALL and callee_u is not None and callee_u.type == "member_expression" and arg_nodes:
            query = _unwrap(arg_nodes[0])
            built = query is not None and (query.type == "binary_expression" or (
                query.type == "template_string" and any(c.type == "template_substitution" for c in query.named_children)))
            if built and _SQL_TEXT.search(_txt(query)) and args and args[0] & UNTRUSTED:
                self._flow("sql", node, args[0], "a SQL statement is built from untrusted input")
        if (short == "setNetworkPassphrase" and args and args[0] & UNTRUSTED) or (
                short == "TransactionBuilder" and is_new and len(arg_nodes) > 1
                and self.tags(_props(arg_nodes[1]).get("networkPassphrase"), state) & UNTRUSTED):
            self._flow("endpoint", node, every, "the network passphrase comes from input")
        if _COMMAND_SINK.search(label) or (is_new and short == "Function"):
            shell = bool(_SHELL_ALWAYS.search(label)) or any("shell" in _props(a) for a in arg_nodes if _unwrap(a) is not None and _unwrap(a).type == "object")
            # The command and its argument list; an options object (cwd, env, stdio) is not code.
            command = set()
            for a, tags in zip(arg_nodes, args):
                a_u = _unwrap(a)
                if a_u is not None and a_u.type == "object" or _is_function(a_u):
                    continue
                command |= tags
            # `execFileSync("stellar", ["keys", "secret", name])`: no shell and a fixed program, so
            # input is one argument to that program and cannot start another command.
            program = _unwrap(arg_nodes[0]) if arg_nodes else None
            fixed = (not shell and not is_new and short != "eval" and program is not None and program.type == "string"
                     and len(arg_nodes) > 1 and _unwrap(arg_nodes[1]) is not None and _unwrap(arg_nodes[1]).type == "array")
            # spawn/execFile(program, args) with no shell: input that is only in the argument list
            # cannot start another program; the program itself must not come from input.
            fixed = fixed or (not shell and not is_new and short in {"spawn", "spawnSync", "execFile", "execFileSync"}
                              and len(args) > 1 and not args[0] & UNTRUSTED)
            # Running one fixed program is not arbitrary code execution.
            self._cap("process_spawn" if fixed else "code_execution", node)
            if command & UNTRUSTED and not fixed:
                self._flow("command", node, command, "shell command" if shell else "argument list, no shell")
            if self.record and _CLI_AUTO_SIGN.search(" ".join(_txt(a) for a in arg_nodes)):
                self.p.profile.add_fact("cli_auto_sign", self.p.location(self.module, node),
                                        "stellar contract invoke --auto-sign", direct=bool(command & DIRECT))
            return set()
        if _FILE_SINK.search(label):
            self._cap("file_access", node)
            target = args[0] if args else set()
            if target & UNTRUSTED:
                self._flow("path_traversal", node, target, "file path is derived from untrusted input")
            return target if "read" in short.lower() else set()
        if label in {"path.join", "path.resolve", "path.normalize", "join", "resolve"} and label.startswith(("path", "join", "resolve")):
            return every
        if _LOG_SINK.search(label):
            if "secret" in every and "fresh" in every:
                self._flow("secret_possible", node, every, "a newly generated secret is printed")
            elif "secret" in every:
                self._flow("secret_exfiltration", node, every, "secret material is written to output")
            elif "secret_possible" in every:
                self._flow("secret_possible", node, every, "return value of a secret-bearing object is written to output")
            return set()
        if short == "TransactionBuilder" and is_new:
            return every | {"tx_built"}
        if _FOREIGN_TX.search(label) and (label.endswith("fromXDR") or is_new):
            out = every | receiver
            if every & UNTRUSTED:
                out.add("foreign_tx")
            return out
        if label.startswith(("Operation.", "StellarSdk.Operation.", "Op.")) or (short in _PAYMENT_OPS | _ACCOUNT_OPS | _TRUSTLINE_OPS | _INVOKE_OPS and "Operation" in label):
            if short in _PAYMENT_OPS:
                self._cap("payment", node)
                return self._payment_markers(arg_nodes, state, short.startswith("pathPayment"))
            if short in _TRUSTLINE_OPS:
                # Which assets the account holds, not who controls it.
                self._cap("trustline", node)
                return set()
            if short in _ACCOUNT_OPS:
                self._cap("account_control", node)
                return ({"acct_untrusted"} | (every & UNTRUSTED)) if every & UNTRUSTED else set()
            if short in _INVOKE_OPS:
                self._cap("contract_invocation", node)
                if every & UNTRUSTED and not self.approved:
                    return {"invoke_untrusted"} | (every & UNTRUSTED)
                return set()
        if short == "addOperation" and receiver_node is not None:
            return receiver | every
        if short in {"build", "setTimeout", "addMemo", "setTimebounds", "setNetworkPassphrase", "toXDR", "toEnvelope"} and receiver:
            return receiver | (every - {"signer"})
        if short in {"signDecorated", "signPayloadDecorated"} and "signer" in receiver and args \
                and args[0] & UNTRUSTED and not args[0] & {"tx_built", "signer", "structured"} and not self.approved:
            self._flow("signing_oracle", node, args[0], "the agent key signs bytes chosen by the requester")
        if short == "sign" and callee_u is not None and callee_u.type == "member_expression":
            # keypair.sign(data): raw bytes the requester picks can be a transaction hash or a
            # Soroban authorization payload.
            if "signer" in receiver and args and args[0] & UNTRUSTED and not args[0] & {"tx_built", "signer", "structured"} \
                    and not self.approved:
                self._flow("signing_oracle", node, args[0], "the agent key signs bytes chosen by the requester")
            if "signer" in every | receiver:
                self._cap("stellar_signing", node)
                self._check_signed(node, receiver)
                target = _unwrap(receiver_node)
                if target is not None and target.type in {"identifier", "member_expression"}:
                    state[_dotted(target)] = state.get(_dotted(target), set()) | {"agent_signed"}
                # wallet.sign(xdr, { keypair }): the first argument is what gets signed.
                subject = args[0] if args else set()
                if "signer" not in receiver and "signer" not in subject and subject & UNTRUSTED \
                        and "tx_built" not in subject and not self.approved:
                    self._cap("foreign_tx_signing", node)
                    self._flow("foreign_signing", node, subject, "an externally supplied transaction is signed")
            return receiver
        if _AUTHORIZE.search(label):
            self._cap("stellar_signing", node)
            self._cap("contract_invocation", node)
            tree = _auth_tree_index(label)  # authorizeInvocation(signer, validUntil, invocation)
            entry = args[tree] if len(args) > tree else set()
            if entry & (UNTRUSTED | {"foreign_tx"}) and not self.approved and not tree_inspected:
                self._cap("foreign_tx_signing", node)
                self._flow("foreign_signing", node, entry, "an authorization entry derived from external input is signed")
            return entry
        # A signer object the caller hands in (an EIP-1193 provider, a Wallet Standard
        # account, an integrator's signer) and that carries no key from this code: whoever
        # supplied it decides what it signs. The project itself holds no signing authority.
        delegated = receiver_node is not None and receiver == {"caller"}
        if delegated and (_SIGN_FOREIGN.search(label) or _SUBMIT.search("." + label)):
            self._cap("delegated_signing", node)
            return (args[0] if args else set()) | {"human_approved"}
        if _SIGN_FOREIGN.search(label):
            xdr = args[0] if args else set()
            if _WALLET_PROMPT.search(label) or (receiver_node is not None and _WALLET_PROMPT.search(_dotted(receiver_node))):
                # A browser wallet (Freighter, Wallets Kit) shows the transaction to its owner,
                # who approves or rejects it: a human approval step, not agent authority.
                return xdr | {"human_approved"}
            if "tx_built" in xdr and "foreign_tx" not in xdr:
                self._cap("stellar_signing", node)
                self._check_signed(node, xdr)
                return xdr
            if xdr & UNTRUSTED and not self.approved:
                self._cap("foreign_tx_signing", node)
                self._flow("foreign_signing", node, xdr, "an externally supplied transaction is signed")
            return xdr
        if _SUBMIT.search("." + label):
            # Relaying an envelope someone else signed (a browser wallet) is not agent authority.
            relay = ("foreign_tx" in every or "human_approved" in every) and "agent_signed" not in every
            self._cap("tx_relay" if relay else "tx_submission", node)
            self._check_signed(node, every - {"foreign_tx"} if relay else every)
            if every & UNTRUSTED and not every & {"tx_built", "foreign_tx"} and not self.approved:
                self._flow("financial", node, every, "an untrusted transaction envelope is submitted")
            return {"chain"}
        if short in {"simulateTransaction", "prepareTransaction", "assembleTransaction"}:
            return every | receiver
        if _SOROBAN_SINK.search(label) and not label.startswith(("Operation.", "Op.")):
            self._cap("contract_invocation", node)
            if every & UNTRUSTED and not self.approved:
                self._flow("financial", node, every, "untrusted values reach a contract invocation")
            return every | receiver
        if short == "call" and receiver and receiver & {"contract_ref"}:
            # Contract.call builds an InvokeHostFunction operation; it does nothing until the
            # agent signs or submits it (checked there), or it is returned unsigned.
            self._cap("contract_invocation", node)
            if every & UNTRUSTED and not self.approved:
                return (every | receiver | {"invoke_untrusted"}) - {"contract_ref"}
            return (every | receiver) - {"contract_ref"}
        if short == "Contract" and is_new:
            return every | {"contract_ref"}

        if short in {"push", "unshift", "add", "set", "append"} and receiver_node is not None \
                and _unwrap(receiver_node) is not None and _unwrap(receiver_node).type == "identifier":
            name = _txt(_unwrap(receiver_node))
            state[name] = state.get(name, set()) | every
        if short in {"then", "map", "filter", "forEach", "reduce", "find", "flatMap", "catch", "finally"}:
            outs = set()
            for a in arg_nodes:
                fk = self.p._function_arg(a, self.module.path)
                if fk:
                    outs |= self.p.returns.get(fk, set())
            return receiver | outs | every
        out = every | (receiver - {"signer", "contract_ref"})
        if "secret" in receiver and "secret" not in every:
            out = (out - {"secret"}) | {"secret_possible"}
        return out

    def _function_node(self, node):
        """A function literal, or the project function a name stands for."""
        node = _unwrap(node)
        if node is None or _is_function(node):
            return node
        if node.type in {"identifier", "member_expression"}:
            key = self.p.resolve(self.module, node, self.fn, self.local_types)
            return self.p.functions[key].node if key in self.p.functions else None
        return None

    def _ceiling(self, node, hook: bool) -> bool:
        fn = self._function_node(node)
        return fn is not None and _amount_ceiling(fn, hook, self._function_node)

    def _aborts(self, node) -> bool:
        """A payment-creation hook that can refuse: some branch returns `{ abort: true }` or throws."""
        fn = self._function_node(node)
        if fn is None:
            return False
        body = fn.child_by_field_name("body")
        if body is not None and body.type != "statement_block":
            return _returns_abort(body)
        return any(n.type in {"return_statement", "throw_statement"} and _returns_abort(n) for n in _own_nodes(body))

    def _config_caps(self, config) -> bool:
        """x402 client options with a ceiling: a numeric limit, or a policy or selector that
        keeps only requirements at or below an amount (`policies: []` or a network filter caps
        nothing)."""
        props = _props(config)
        if set(props) & _X402_VALUE_LIMITS:
            return True
        for key in _X402_POLICY_KEYS & set(props):
            value = _unwrap(props[key])
            items = [c for c in value.named_children if c.type != "comment"] if value is not None and value.type == "array" else [value]
            if any(self._ceiling(item, False) for item in items):
                return True
        return False

    def _is_bound_value(self, node) -> bool:
        node = _unwrap(node)
        return node is not None and (node.type == "number" or node.type == "identifier" and _txt(node) in self.module.constants)

    @staticmethod
    def _url_head(url):
        url = _unwrap(url)
        if url is None:
            return None
        if url.type == "template_string":
            for child in url.named_children:
                if child.type == "template_substitution":
                    return child.named_children[0] if child.named_children else None
                return child
            return None
        if url.type == "binary_expression" and _txt(url.child_by_field_name("operator")) == "+":
            return _JsInterp._url_head(url.child_by_field_name("left"))
        if url.type == "new_expression" and _dotted(url.child_by_field_name("constructor")) == "URL":
            args = _args(url)
            if len(args) >= 2:
                return args[1]  # new URL(path, base): the base decides the host
            return args[0] if args else None
        return url

    def _pinned_destination(self, option_nodes) -> bool:
        """The connection is pinned to an address the code checked: a `lookup` (or an agent or
        dispatcher built with one) in a module, or a module it imports, that classifies
        addresses as private or public. Resolving once, checking, then connecting to that
        address is the standard SSRF control and also defeats DNS rebinding."""
        pinned = False
        for a in option_nodes:
            for prop, value in _props(_unwrap(a)).items():
                if prop == "lookup" or (prop in {"agent", "dispatcher", "httpAgent", "httpsAgent"}
                                        and _PINNED_AGENT.search(_txt(value))):
                    pinned = True
        if not pinned:
            return False
        sources = [self.module.path] + [target.split(":", 1)[0] for target in self.module.imports.values()
                                        if not target.startswith(("lib:", "module:"))] + \
                  [target[7:] for target in self.module.imports.values() if target.startswith("module:")]
        return any(_ADDRESS_FILTER.search("\n".join(self.p.modules[path].lines))
                   for path in dict.fromkeys(sources) if path in self.p.modules)

    @staticmethod
    def _fixed_host(url) -> bool:
        url = _unwrap(url)
        if url is None:
            return False
        if url.type == "template_string":
            first = url.named_children[0] if url.named_children else None
            return first is not None and first.type == "string_fragment" and bool(_SAFE_URL_PREFIX.match(_txt(first)))
        if url.type == "binary_expression":
            return _JsInterp._fixed_host(url.child_by_field_name("left"))
        value = _string_value(url)
        return value is not None and bool(_SAFE_URL_PREFIX.match(value))

    def _payment_markers(self, arg_nodes, state, path_payment: bool = False) -> set[str]:
        out: set[str] = set()
        if not arg_nodes:
            return out
        props = _props(arg_nodes[0])
        dest = props.get("destination")
        amount = next((props[k] for k in ("amount", "sendAmount", "destAmount", "startingBalance", "sendMax") if k in props), None)
        dest_tags = self.tags(dest, state)
        amount_tags = self.tags(amount, state)
        if self.approved:
            return out
        if dest_tags & UNTRUSTED:
            out |= {"pay_dest_untrusted"} | (dest_tags & UNTRUSTED)
        if path_payment and any(self.tags(props.get(k), state) & UNTRUSTED for k in ("sendAsset", "destAsset", "path")):
            out.add("pay_route_untrusted")
        if amount is not None and amount_tags & UNTRUSTED and "bounded" not in amount_tags:
            if self.record:
                self.p.profile.unbounded_amounts.append(self.p.location(self.module, arg_nodes[0]))
                if amount_tags & DIRECT:
                    self.p.profile.unbounded_direct_amounts.append(self.p.location(self.module, arg_nodes[0]))
            out |= {"pay_amount_untrusted"} | (amount_tags & UNTRUSTED)
        return out

    def _check_signed(self, node, tx_tags: set[str]) -> None:
        if "human_approved" in tx_tags:
            return
        if "foreign_tx" in tx_tags:
            self._cap("foreign_tx_signing", node)
            self._flow("foreign_signing", node, tx_tags, "an externally supplied transaction is signed or submitted")
        if self.approved:
            return
        detail = []
        if "pay_dest_untrusted" in tx_tags:
            detail.append("payment destination")
        if "pay_amount_untrusted" in tx_tags:
            detail.append("unbounded payment amount")
        if detail:
            self._flow("financial", node, tx_tags, "untrusted " + " and ".join(detail))
        if "acct_untrusted" in tx_tags:
            self._flow("account_control", node, tx_tags, "untrusted input changes account authority settings")
        if "invoke_untrusted" in tx_tags:
            self._flow("financial", node, tx_tags, "untrusted values reach a contract invocation")
        if "pay_route_untrusted" in tx_tags:
            self._flow("asset_route", node, tx_tags, "the assets or path of a path payment come from input")

    # ----------------------------------------------------------------- sellers
    def _reports_result(self, body, state) -> bool:
        """A response body that is the verification or settlement itself, in any spelling:
        the result (`res.json(s)`), the facilitator's own reply (`res.json(await r.json())`),
        its encoding, or an object of its fields (`{ success: s.success, transaction:
        s.transaction }`, with booleans or null beside them). A body with anything else in it
        (`{ quote: 42, tx: s.transaction }`) serves a resource."""
        result = {"settle_result", "verify_result"}
        node = _unwrap(body)
        while node is not None and node.type == "call_expression":
            fn = _unwrap(node.child_by_field_name("function"))
            if _dotted(fn) == "JSON.stringify" and _args(node):
                node = _unwrap(_args(node)[0])
            elif fn is not None and fn.type == "member_expression" and not _args(node) \
                    and _txt(fn.child_by_field_name("property")) in {"json", "text"}:
                node = _unwrap(fn.child_by_field_name("object"))  # the facilitator reply's body
            else:
                return False
        if node is None:
            return False
        if node.type in {"identifier", "member_expression", "shorthand_property_identifier"}:
            return bool(self.tags(node, state) & result)
        if node.type == "object":
            values = [v for v in _props(node).values() if v is not None]
            values += [c.named_children[0] for c in node.named_children if c.type == "spread_element" and c.named_children]
            return bool(values) and any(self._reports_result(v, state) for v in values) and all(
                _unwrap(v) is not None and (_unwrap(v).type in {"true", "false", "null", "undefined"}
                                            or self._reports_result(v, state)) for v in values)
        return False

    @staticmethod
    def _binds_payer(sides: list[set[str]]) -> bool:
        """Values compared or matched: one the payer chose against one the server holds."""
        payer = {"payment_header", "request_body"}
        return any(t & payer for t in sides) and not all(t & payer for t in sides)

    @staticmethod
    def _names_payment_header(arg) -> bool:
        arg = _unwrap(arg)
        if arg is None:
            return False
        value = _string_value(arg)
        if value is not None:
            return bool(_PAYMENT_HEADER.match(value))
        return arg.type in {"identifier", "member_expression"} and bool(_PAYMENT_HEADER_CONST.search(_dotted(arg)))

    @staticmethod
    def _refusal(callee_u, arg_nodes) -> bool:
        """A response with a 4xx/5xx status: the payer is turned away, nothing is delivered."""
        if callee_u is not None and re.search(r"\.(?:status|code)\(\s*[45]\d\d\s*\)", _txt(callee_u)):
            return True
        for a in arg_nodes[1:2]:
            a_u = _unwrap(a)
            if a_u is not None and a_u.type == "number" and _txt(a_u)[:1] in "45" and len(_txt(a_u)) == 3:
                return True
            status = _unwrap(_props(a_u).get("status")) if a_u is not None and a_u.type == "object" else None
            if status is not None and status.type == "number" and _txt(status)[:1] in "45":
                return True
        return False

    def _responds(self, label: str, callee_u, receiver: set[str]) -> bool:
        """The call sends the handler's response: a global Response, or a send method on a
        response object the handler (or the function around it) received as a parameter
        (`res.json`, `reply.send`, `c.json`). Reading the facilitator's own HTTP response
        (`response.json()` after a fetch) sends nothing."""
        if re.match(r"^(?:NextResponse|Response)(?:\.json)?$", label):
            return True
        if not _RESPONDERS.search(label) or receiver & {"settle_result", "verify_result"}:
            return False
        root = callee_u
        while root is not None and root.type in {"member_expression", "call_expression"}:
            root = _unwrap(root.child_by_field_name("object" if root.type == "member_expression" else "function"))
        if root is None or root.type != "identifier":
            return False
        params, fn = set(), self.fn
        while fn is not None:
            params |= _param_names(fn.node)
            fn = self.p.functions.get(fn.parent) if fn.parent else None
        return _txt(root) in params

    def _declared_text(self, name: str) -> str:
        """The initializer of `const name = ...` in this function or at module level."""
        for scope in ([self.fn.node] if self.fn is not None else []) + [self.module.root]:
            declared = self.p.declarations(self.module, scope)
            if name in declared:
                return declared[name]
        return name

    def _json_body(self, options) -> dict:
        """`{ body: JSON.stringify({...}) }` (or a plain object body) -> the body's properties."""
        body = _unwrap(_props(options).get("body") or _props(options).get("data")) if options is not None else None
        if body is not None and body.type == "call_expression" and _dotted(body.child_by_field_name("function")) == "JSON.stringify":
            body = _unwrap(_args(body)[0]) if _args(body) else None
        return _props(body) if body is not None and body.type == "object" else {}

    def _seller(self, node, label, short, callee_u, receiver_node, receiver, arg_nodes, args, state, is_new) -> None:
        """x402 / MPP seller sources, sinks and deliveries at one call (spec item 08)."""
        add: set[str] = set()
        strip: set[str] = set()
        every = set().union(*args) if args else set()
        if _X402_LIB.match(label) and (is_new or short == "useFacilitator"):
            add.add("x402_lib")  # new HTTPFacilitatorClient(...), new x402ResourceServer(...), useFacilitator()
        if short in _PAYMENT_DECODERS or (any(self._names_payment_header(a) for a in arg_nodes)
                                          and (every | receiver) & {"external", "model"}):
            add.add("payment_header")
        if _REQUIREMENT_MATCHERS.match(short) and not is_new:
            strip |= {"payment_header", "request_body"}  # the server's own requirements come back
            if self._binds_payer(args):
                add.add("requirements_match")  # its result gating the path binds the requirements
        scope = self.p.seller_scope(self.module)
        op, payload, requirements = None, set(), set()
        http = bool(_HTTP_CALL.search(label)) and bool(arg_nodes)
        if scope and http:
            url = _unwrap(arg_nodes[0])
            text = self._declared_text(_txt(url)) if url is not None and url.type == "identifier" else _txt(url)
            found = _FACILITATOR_PATH.search(text)  # a literal, a template, or a constant holding one
            if found:
                op = found.group("op")
                body = self._json_body(_unwrap(arg_nodes[1]) if len(arg_nodes) > 1 else None)
                payload = self.tags(body.get("paymentPayload"), state) if body.get("paymentPayload") is not None else set()
                requirements = self.tags(body.get("paymentRequirements"), state) if body.get("paymentRequirements") is not None else set()
        elif scope and len(arg_nodes) >= 2 and short in _SETTLE_SINK and (_X402_LIB.match(label) or (
                receiver_node is not None and ("payment_header" in args[0] or "x402_lib" in receiver))):
            # A facilitator or resource server settles a payer's payload: the payload came from
            # the payment header, or the settle belongs to an x402 library object. A receiver's
            # name says nothing (`paymentChannel.settle(id, amount)` closes the project's channel).
            op, payload, requirements = "settle", args[0], args[1]
        elif scope and receiver_node is not None and len(arg_nodes) >= 2 and short in _VERIFY_SINK \
                and _PAYMENT_VERIFIER.search(_txt(receiver_node)) and "payment_header" in args[0]:
            op, payload, requirements = "verify", args[0], args[1]
        elif scope and _ENVELOPE_VERIFY.match(short) and args and "payment_header" in args[0]:
            op, payload = "verify", args[0]
        if op == "settle":
            add.add("settle_result")
            self.unchecked_settles.append(node)
            if self.record:
                self.p.settle_sinks.setdefault(self.module.path, {})[self.p.location(self.module, node)] = None
        elif op == "verify":
            add.add("verify_result")
            if "payment_header" in payload:
                self.client_verified.append(node)
        if op and requirements & {"payment_header", "request_body"} and not self.requirements_bound:
            self.payer_requirements.append(node)
        self.sink_seen = self.sink_seen or bool(op)
        if _ASSERTION.match(short) and re.search(r"\b(?:success|isSuccess)\b", " ".join(_txt(a) for a in arg_nodes)):
            self._settle_checked(node, state)  # assert(settlement.success)
        elif (self.unchecked_settles or self._settle_held(state)) and not is_new and any("settle_result" in a for a in args):
            # `ensureSettled(s)`: a project function that throws unless the settlement succeeded
            # (awaited when it is async: an un-awaited rejection does not stop the handler).
            key = self.p.resolve(self.module, callee_u, self.fn, self.local_types)
            checked = self.p.success_validator(key) if key in self.p.functions else set()
            asynchronous = key in self.p.functions and any(c.type == "async" for c in self.p.functions[key].node.children)
            if any(i < len(args) and "settle_result" in args[i] for i in checked) and (
                    not asynchronous or (node.parent is not None and node.parent.type == "await_expression")):
                self._clear_settles(state)
        # Transaction-hash proofs (S4): a hash the requester supplies is looked up on chain.
        hashed = (_TX_LOOKUP.search(label) and args and args[0] & {"external", "model"}) or (
            http and not op and _TX_LOOKUP_URL.search(" ".join(_txt(a) for a in arg_nodes)) and every & {"external", "model"})
        if hashed and self.record:
            self.p.tx_lookups.append((self.fn.key if self.fn else None, self.module.path, self.p.location(self.module, node)))
        # Deliveries: the paid resource, the next middleware, or an upstream service.
        delivered = resource = upstream = False
        if callee_u is not None and callee_u.type == "identifier" and _txt(callee_u) == "next" and not is_new:
            delivered = resource = not arg_nodes  # next(err) hands an error on; it serves nothing
        elif self._responds(label, callee_u, receiver) and not self._refusal(callee_u, arg_nodes):
            answer = args[0] & {"settle_result", "verify_result"} if args else set()
            if answer and self._reports_result(arg_nodes[0], state):
                self.relay = True  # a facilitator answers with the verification or settlement itself
            else:
                delivered, resource = True, not answer
        elif (http and not op and not hashed) or (_PROXIES.search(label) and not is_new):
            delivered = resource = True
            upstream = http and not _PROXIES.search(label)
        if resource and self.sink_seen:
            self.resource_after_sink.append(node)
        if delivered and scope:
            if self.unchecked_settles or self._settle_held(state):
                self.unchecked_deliveries.append(node)
                if upstream:
                    self._pending_upstream.add((node.start_byte, node.end_byte))
            if self.client_verified:
                self.verified_deliveries.append(node)
        if add or strip:
            self._adjust[(node.start_byte, node.end_byte)] = (add, strip)

    def _sponsor(self, node, label, short, callee_u, receiver, arg_nodes, args, is_new, state) -> set[str]:
        """Fee sponsors (spec item 12): a builder sourced by the server's own account that
        carries a foreign transaction's operations, and fee bumps of foreign envelopes.
        Returns the labels a sponsor that checked the client's envelope no longer signs for."""
        add: set[str] = set()
        every = set().union(*args) if args else set()
        if (short in _LOAD_ACCOUNT and "sponsor_key" in every) or (is_new and short == "Account" and args and "sponsor_key" in args[0]):
            add.add("sponsor_account")
        if is_new and short == "TransactionBuilder" and args and "sponsor_account" in args[0]:
            add.add("sponsor_built")
            if len(arg_nodes) > 1 and self.tags(_props(arg_nodes[1]).get("fee"), state) & _FOREIGN:
                add.add("foreign_fee")  # `fee: clientTx.fee`: the client sets what the sponsor pays
        if short == "setSorobanData" and "sponsor_built" in receiver and every & _FOREIGN:
            add.add("foreign_fee")  # resource fee copied from the client's envelope
        if short == "operations" and "foreign_tx" in receiver:
            add.add("foreign_ops")
        if "Operation" in label.split(".")[:-1] or label.startswith(("Operation.", "Op.")):
            add |= every & {"foreign_ops"}
            source = _props(arg_nodes[0]).get("source") if arg_nodes else None
            if source is not None and self._chain_tags(source, state) & _FOREIGN:
                add.add("foreign_source")  # the client's operation source is copied into the rebuild
        if _ASSERTION.match(short):
            for a in arg_nodes:
                guards = self._sponsor_guards(a, state)  # assert(tx.source === PLACEHOLDER)
                self.sponsor_checks |= guards
                self.sponsor_throws |= guards
        if short == "address" and callee_u is not None and callee_u.type == "member_expression" \
                and self._credentials_call(callee_u.child_by_field_name("object"), state):
            # js-xdr union accessors throw for another arm: credentials().address() rejects
            # SourceAccount (and delegated) credentials.
            self.sponsor_checks.add("credential_type")
            self.sponsor_throws.add("credential_type")
        strip: set[str] = set()
        if short == "buildFeeBumpTransaction" and len(args) >= 3:
            fee, inner = args[1], args[2]
            # A transaction the server built and stored itself (looked up by id) is not foreign.
            foreign_inner = bool(inner & _FOREIGN) or (bool(inner & UNTRUSTED) and not inner & {"stored_record", "tx_built"})
            if foreign_inner and fee & _FEE_INPUT and "bounded" not in fee and not self.approved and self.record:
                self.p.profile.add_fact("fee_bump_unbounded", self.p.location(self.module, node),
                                        "the fee of a foreign inner transaction comes from input")
            # The outer envelope is the server's own; its signature covers the fee, not the
            # inner operations (those are authorized by the inner signatures). Where the inner
            # came from (a caller, a request) stays on the value, so evidence names it.
            add.add("tx_built")
            strip |= _FOREIGN
        sponsored: set[str] = set()
        if short == "sign" and {"sponsor_built", "foreign_ops"} <= receiver and "signer" in every:
            # Checks that fail closed before this point here, around this call, in the callers
            # around it, and in the throwing helpers they call.
            key = self.fn.key if self.fn else None
            checks = set(self.sponsor_checks).union(*self._enclosing, self.p.sponsor_enclosed.get(key, set()))
            up, down = self.p.guard_scope(key)
            for k in up:
                checks |= self.p.sponsor_checks.get(k, set()) | self.p.sponsor_enclosed.get(k, set())
            for k in down:
                checks |= self.p.sponsor_throws.get(k, set())
            credential = "credential_type" in checks
            # R2: the envelope's source is pinned, and the operation's source is too unless the
            # rebuild leaves it out.
            source_pin = "tx_source" in checks and ("op_source" in checks or "foreign_source" not in receiver)
            if self.record:
                self.p.profile.add_fact(
                    "sponsor_rebuild", self.p.location(self.module, node), "the sponsor signs a rebuilt foreign operation",
                    function=self.fn.name if self.fn else "<module>", foreign_fee="foreign_fee" in receiver,
                    warned=bool(self.fn is not None and _SPONSOR_WARNING.search(_txt(self.fn.node))),
                    facilitator=self._facilitator(), credential_type=credential, source_pin=source_pin,
                    single_invocation="single_invocation" in checks)
            if credential and source_pin:
                sponsored = set(_SPONSORED)
        if add or strip:
            current = self._adjust.get((node.start_byte, node.end_byte), (set(), set()))
            self._adjust[(node.start_byte, node.end_byte)] = (current[0] | add, current[1] | strip)
        return sponsored

    def _facilitator(self) -> bool:
        """An x402 facilitator settles payers' transactions (R4 applies to it)."""
        name = f"{self.module.path} {self.fn.name if self.fn else ''}"
        route = self.p.route_paths.get(self.fn.key, "") if self.fn else ""
        return self.p.imports_package(self.module, "@x402/") or bool(re.search(r"facilitat", name, re.I)) \
            or bool(re.search(r"/(?:settle|verify)\b", route))

    # ------------------------------------------------------------ sponsor guards
    def _chain_tags(self, node, state) -> set[str]:
        """Labels of the value an access chain starts from (`op.auth[0]`, `e.credentials()`),
        read without evaluating any call again: calls along the chain hand their receiver's
        labels on."""
        node = _unwrap(node)
        if node is None:
            return set()
        if node.type == "identifier":
            return set(state.get(_txt(node), set()))
        if node.type == "call_expression":
            fn = _unwrap(node.child_by_field_name("function"))
            return self._chain_tags(fn.child_by_field_name("object"), state) \
                if fn is not None and fn.type == "member_expression" else set()
        if node.type in {"member_expression", "subscript_expression"}:
            key = _dotted(node) if node.type == "member_expression" else ""
            if key and key in state:
                return set(state[key])
            base = self._chain_tags(node.child_by_field_name("object"), state)
            if node.type == "member_expression" and _txt(node.child_by_field_name("property")) == "operations" \
                    and "foreign_tx" in base:
                base.add("foreign_ops")
            return base
        return set()

    def _credentials_call(self, node, state) -> bool:
        """`<foreign entry>.credentials()`."""
        node = _unwrap(node)
        if node is None or node.type != "call_expression":
            return False
        fn = _unwrap(node.child_by_field_name("function"))
        return fn is not None and fn.type == "member_expression" \
            and _txt(fn.child_by_field_name("property")) == "credentials" and bool(self._chain_tags(node, state) & _FOREIGN)

    def _credential_switch(self, node, state) -> bool:
        """`<foreign entry>.credentials().switch()` (or its `.name` / `.value`)."""
        node = _unwrap(node)
        while node is not None and node.type == "member_expression" and _txt(node.child_by_field_name("property")) in {"name", "value"}:
            node = _unwrap(node.child_by_field_name("object"))
        if node is None or node.type != "call_expression":
            return False
        fn = _unwrap(node.child_by_field_name("function"))
        return fn is not None and fn.type == "member_expression" and _txt(fn.child_by_field_name("property")) == "switch" \
            and self._credentials_call(fn.child_by_field_name("object"), state)

    def _guard_operand(self, side, other, op: str, state) -> set[str]:
        side = _unwrap(side)
        if side is None:
            return set()
        found: set[str] = set()
        equality = op in {"===", "!==", "==", "!="}
        prop = _txt(side.child_by_field_name("property")) if side.type == "member_expression" else ""
        if equality and self._credential_switch(side, state):
            found.add("credential_type")
        if equality and prop == "source" and not self._chain_tags(other, state) & _FOREIGN:
            # Compared with a placeholder, the payer, the sponsor, or undefined.
            tags = self._chain_tags(side.child_by_field_name("object"), state)
            found |= {"op_source"} if "foreign_ops" in tags else {"tx_source"} if "foreign_tx" in tags else set()
        if prop == "length":
            obj = _unwrap(side.child_by_field_name("object"))
            inner = _unwrap(obj.child_by_field_name("function")) if obj is not None and obj.type == "call_expression" else None
            if obj is not None and obj.type == "member_expression" and _txt(obj.child_by_field_name("property")) == "operations" \
                    and "foreign_tx" in self._chain_tags(obj.child_by_field_name("object"), state):
                found.add("single_invocation")
            elif inner is not None and inner.type == "member_expression" \
                    and _txt(inner.child_by_field_name("property")) == "subInvocations" and self._chain_tags(obj, state) & _FOREIGN:
                found.add("single_invocation")
        return found

    def _sponsor_guards(self, node, state, rejects: bool = False) -> set[str]:
        """What a condition, assertion or returned expression checks about a client's envelope
        before a fee sponsor signs it: R1 `credential_type` (an auth entry's
        credentials().switch() is compared), R2 `tx_source` / `op_source` (the envelope's or an
        operation's source is compared, or the operation's required absent), R4
        `single_invocation` (operations.length or subInvocations() is compared). Only values
        from the client's envelope count; comments and look-alike names do not. ``rejects``:
        the expression being true refuses the request (`if (C) throw`); otherwise true means
        valid (an assertion, a validator's return value). A comparison counts only where its
        truth decides the expression's (through !, &&, ||, a predicate callback, a validator's
        result): one inside a logged object, a ternary or a metric's argument decides nothing."""
        found: set[str] = set()
        # (node, scope, sign): sign is True or False while the node's truthiness decides the
        # expression's (through !, &&, || and parentheses), None elsewhere.
        stack = [(_unwrap(node), state, True)]
        while stack:
            sub, scope, sign = stack.pop()
            if sub is None or _is_function(sub):
                continue
            child_sign = None
            children = None
            if sub.type == "parenthesized_expression":
                child_sign = sign
            elif sub.type == "unary_expression" and _txt(sub.child_by_field_name("operator")) == "!":
                child_sign = None if sign is None else not sign
            elif sub.type == "binary_expression":
                op = _txt(sub.child_by_field_name("operator"))
                if op in {"&&", "||"}:
                    child_sign = sign
                if op in {"===", "!==", "==", "!=", "<", ">", "<=", ">="} and sign is not None:
                    left, right = sub.child_by_field_name("left"), sub.child_by_field_name("right")
                    found |= self._guard_operand(left, right, op, scope) | self._guard_operand(right, left, op, scope)
                    # `op.auth.filter((e) => ...).length > 0`, `findIndex(...) !== -1`: the
                    # predicate's verdict is what is compared.
                    children = []
                    for side in (left, right):
                        side_u = _unwrap(side)
                        if side_u is not None and side_u.type == "member_expression" \
                                and _txt(side_u.child_by_field_name("property")) == "length":
                            side_u = _unwrap(side_u.child_by_field_name("object"))
                        children.append((side_u, scope, True if side_u is not None and side_u.type == "call_expression" else None))
            elif sub.type == "call_expression":
                fn = _unwrap(sub.child_by_field_name("function"))
                method = _txt(fn.child_by_field_name("property")) if fn is not None and fn.type == "member_expression" else ""
                args = [_unwrap(a) for a in _args(sub)]
                tags = self._chain_tags(fn.child_by_field_name("object"), scope) if method else set()
                if method in _PREDICATES and tags & _FOREIGN:
                    # `op.auth.every((e) => e.credentials().switch() === ...)`: each entry is foreign.
                    for a in args:
                        if _is_function(a):
                            inner = dict(scope)
                            inner.update({name: set(tags) for name in _param_names(a)})
                            # The callback's truth is the verdict, except forEach's.
                            stack.append((_unwrap(a.child_by_field_name("body")), inner,
                                          sign if method != "forEach" else None))
                elif method in {"includes", "has"} and args and self._credential_switch(args[0], scope):
                    found.add("credential_type")
                elif sign is not None:
                    # `if (!isSponsorable(tx)) throw`: the validator's checks hold here.
                    found |= self._verdict(self.p.resolve(self.module, fn, self.fn, self.local_types))
            elif sub.type == "identifier" and sign is not None and _txt(sub) in self._verdicts:
                found |= self._verdict(self._verdicts[_txt(sub)])  # const ok = validate(tx); if (!ok) throw
            elif sub.type == "member_expression" and _txt(sub.child_by_field_name("property")) == "source" \
                    and sign is not None and sign == rejects \
                    and "foreign_ops" in self._chain_tags(sub.child_by_field_name("object"), scope):
                # `if (op.source) throw` or `assert(!op.source)`: the operation must name no
                # source. `if (!op.source) throw` and `op.source || x` require none of that.
                found.add("op_source")
            stack.extend(children if children is not None else ((c, scope, child_sign) for c in sub.named_children))
        return found

    def _verdict(self, key: str | None) -> set[str]:
        """What a project validator checked, where its result gates the path: the boolean it
        returns, and the checks that end it early."""
        if not key or key not in self.p.functions or (self.fn is not None and key == self.fn.key):
            return set()
        return self.p.sponsor_returns.get(key, set()) | self.p.sponsor_checks.get(key, set())

    def _settle_held(self, state) -> bool:
        """A variable holds a settlement result nothing has checked yet. One enters the state
        with it (parameters, captured or module values: looked at once) or from a call."""
        if not self._state_seen:
            self._state_seen = True
            self.settle_seen = self.settle_seen or any("settle_result" in tags for tags in state.values())
        return self.settle_seen and any("settle_result" in tags for tags in state.values())

    def _settle_checked(self, cond, state) -> None:
        """A branch condition that reads a settlement's success clears every pending settle."""
        if not self.unchecked_settles and not self._settle_held(state):
            return  # nothing to clear: most conditions, in most files
        stack = [cond]
        while stack:
            sub = stack.pop()
            if sub is None or _is_function(sub):
                continue
            stack.extend(sub.named_children)
            if sub.type == "member_expression" and _txt(sub.child_by_field_name("property")) in _SETTLE_SUCCESS:
                held = _dotted(_unwrap(sub.child_by_field_name("object")))
                seen = state.get(held) or state.get(held.split(".")[0], set())
            elif sub.type == "identifier" and _txt(sub) in _SETTLE_SUCCESS:
                seen = state.get(_txt(sub), set())
            elif sub.type == "call_expression" and sub is not cond and any(
                    "settle_result" in state.get(_dotted(a), set()) for a in _args(sub)
                    if _unwrap(a) is not None and _unwrap(a).type in {"identifier", "member_expression"}):
                seen = {"settle_result"}  # `if (!isSettled(s))`: a helper judges the settlement
            else:
                continue
            if "settle_result" in seen or self.unchecked_settles:
                self._clear_settles(state)
                return

    def _clear_settles(self, state) -> None:
        """A check of the settlement's success: nothing settled so far is pending."""
        self.unchecked_settles.clear()
        # Requests sent before the check (an audit or log hook) served nothing yet.
        self.unchecked_deliveries = [n for n in self.unchecked_deliveries
                                     if (n.start_byte, n.end_byte) not in self._pending_upstream]
        self._pending_upstream.clear()
        for name in [n for n, tags in state.items() if "settle_result" in tags]:
            state[name] = state[name] - {"settle_result"}  # sets may be shared with module state

    def _proof_check(self, text: str, sides) -> None:
        """Record what a fail-closed comparison checks about a transaction-hash proof (and,
        apart, the checks whose failure throws: they stop a caller too)."""
        if self._conditional:
            return
        found = set()
        if re.search(r"memo|challenge|nonce|request_?id|requestId|invoice|order_?id|orderId|reference", text, re.I):
            found.add("challenge")
        if re.search(r"(?:^|[.\[\s(!])(?:from|source|source_?account|sourceAccount|payer|sender)\b", text) and \
                not any(tags & {"payment_header", "request_body"} for tags in sides):
            found.add("payer")
        if re.search(r"created_?at|createdAt|close_?time|closeTime|timestamp|\bage(?:_?ms|_?seconds|_?secs?)?\b|max_?age|maxAge|"
                     r"txTime|Date\.now", text, re.I):
            found.add("age")
        self.proof_checks |= found
        if self._rejecting == "throw":
            self.proof_throws |= found

    def _optional_guard(self, cond) -> bool:
        """`if (options.expectedMemo && ...)` where no caller passes expectedMemo: what the
        branch checks never runs."""
        if self.fn is None:
            return False
        params = {name: i for i, (name, _) in enumerate(self.fn.params) if name}
        stack = [_unwrap(cond)]
        while stack:
            sub = stack.pop()
            if sub is None:
                continue
            if sub.type == "binary_expression" and _txt(sub.child_by_field_name("operator")) == "&&":
                stack += [_unwrap(sub.child_by_field_name("left")), _unwrap(sub.child_by_field_name("right"))]
            elif sub.type == "member_expression":
                obj = _unwrap(sub.child_by_field_name("object"))
                if obj is not None and obj.type == "identifier" and _txt(obj) in params:
                    passed = self.p.entry_props.get(self.fn.key, [])[params[_txt(obj)]:params[_txt(obj)] + 1]
                    if passed and isinstance(passed[0], dict) and _txt(sub.child_by_field_name("property")) not in passed[0]:
                        return True
        return False

    # ------------------------------------------------------------------ guards
    def assume(self, cond, truth: bool, state, *, node) -> None:
        """Record what holds after a fail-closed check.

        `if (C) throw` lets later code run only when C is false (truth=False); the body
        of `if (C) { ... }` runs only when C is true (truth=True).
        """
        cond = _unwrap(cond)
        if cond is None:
            return
        t = cond.type
        if t == "unary_expression" and _txt(cond.child_by_field_name("operator")) == "!":
            self.assume(cond.child_by_field_name("argument"), not truth, state, node=node)
            return
        if t == "binary_expression":
            op = _txt(cond.child_by_field_name("operator"))
            left, right = cond.child_by_field_name("left"), cond.child_by_field_name("right")
            if (op == "&&" and truth) or (op == "||" and not truth):
                self.assume(left, truth, state, node=node)
                self.assume(right, truth, state, node=node)
                return
            if op in {"&&", "||"}:
                # One of the two holds: a value is clean only if both branches clean it.
                branches = []
                self._conditional += 1
                for side in (left, right):
                    copy = {k: set(v) for k, v in state.items()}
                    self.assume(side, truth, copy, node=node)
                    branches.append(copy)
                self._conditional -= 1
                for name in set(branches[0]) | set(branches[1]):
                    state[name] = branches[0].get(name, set()) | branches[1].get(name, set())
                return
            if op in {"<", "<=", ">", ">="}:
                self._proof_check(_txt(cond), [])
                upper_left = (op in {"<", "<="}) == truth  # left <= right holds
                value, bound = (left, right) if upper_left else (right, left)
                names = {n for n in self._compared(value)
                         if not n.isupper() and n not in self.module.constants and not n.startswith("Number.")}
                if names and not self._non_positive(bound):
                    for name in names:
                        state[name] = state.get(name, set()) | {"bounded"}
                    if any(AMOUNT_NAME.search(n) for n in names) and not any(
                            RECEIVED_NAME.search(n) for n in self._compared(bound)):
                        # A retry counter, a rating range or a price check is a bound, but not a spending cap.
                        self._control("amount_cap", node)
                return
            if (op in {"!==", "!="} and not truth) or (op in {"===", "=="} and truth):
                sides = [self.tags(left, state), self.tags(right, state)]
                self._proof_check(_txt(cond), sides)
                if self._binds_payer(sides):
                    self.requirements_bound = True  # a payer-chosen field equals the server's value
                for side, other in ((left, right), (right, left)):
                    other_u = _unwrap(other)
                    if other_u is None or other_u.type in {"null", "undefined"} or _txt(other_u) == "undefined":
                        continue
                    side_u = _unwrap(side)
                    if side_u is not None and side_u.type in {"identifier", "member_expression"}:
                        # Equal to a trusted value, or to one the function's own caller chose.
                        if self.approved or not self.tags(other, state) & (UNTRUSTED - {"caller"}):
                            self._checked(side, state)
                            self._control("value_binding", node)
                return
            if op == "in" and truth and not re.search(r"block|deny|ban|black", _txt(right), re.I):
                self._checked(left, state)
                self._control("allowlist", node)
                return
            return
        if t in {"call_expression"} and truth:
            fn = cond.child_by_field_name("function")
            short = _dotted(fn).rsplit(".", 1)[-1]
            receiver = _unwrap(fn.child_by_field_name("object")) if fn is not None and fn.type == "member_expression" else None
            args = _args(cond)
            if _REQUIREMENT_MATCHERS.match(short) and self._binds_payer([self.tags(a, state) for a in args]):
                # `if (!isDeepStrictEqual(p.accepted, ROUTES.quote)) return 402`: past the check the
                # payer's requirements are the server's (findMatchingRequirements, deep equality).
                self.requirements_bound = True
                return
            if short in {"includes", "has", "hasOwnProperty"} and receiver is not None and args:
                if not re.search(r"block|deny|ban|reject|black", _dotted(receiver), re.I):
                    self._checked(args[0], state)
                    self._control("allowlist", node)
                return
            if short == "hasOwn" and len(args) >= 2 and not re.search(r"block|deny|ban|black", _txt(args[0]), re.I):
                self._checked(args[1], state)
                self._control("allowlist", node)
                return
            if _APPROVAL_CALL.search(short):
                self.approved = True
                self._control("approval", node)
                return
        if t in {"identifier", "member_expression"} and truth and "requirements_match" in self.tags(cond, state):
            self.requirements_bound = True  # `const m = findMatchingRequirements(...); if (!m) return 402`
            return
        if t in {"identifier", "member_expression"} and truth:
            ident = _txt(cond.child_by_field_name("property")) if t == "member_expression" else _txt(cond)
            if not ident.isupper() and re.search(r"approv|confirm", ident, re.I):
                found = self.tags(cond, state)
                if found & UNTRUSTED and not found & {"human_decision", "stored_record"}:
                    # `if (!args.approved) throw`: the requester supplies the approval itself.
                    if self.record:
                        where = (self.p.profile.forgeable_approvals if found & DIRECT
                                 else self.p.profile.unresolved_approvals)
                        where.append(self.p.location(self.module, node))
                    return
                self.approved = True
                self._control("approval", node)
                return
        # Checks that count in either polarity.
        stack = [cond]
        while stack:
            sub = stack.pop()
            if _is_function(sub):
                continue
            stack.extend(sub.named_children)
            if sub.type == "call_expression":
                fn = sub.child_by_field_name("function")
                short = _dotted(fn).rsplit(".", 1)[-1]
                receiver = _unwrap(fn.child_by_field_name("object")) if fn is not None and fn.type == "member_expression" else None
                if short in {"startsWith", "isRelativeTo"} and receiver is not None:
                    for name in self._names_in(receiver) | {n for a in _args(sub) for n in self._names_in(a)}:
                        state[name] = state.get(name, set()) - UNTRUSTED
                    self._control("path_containment", node)
                elif short in {"gt", "isGreaterThan", "greaterThan", "gte", "isGreaterThanOrEqualTo"} and receiver is not None and not truth:
                    compared = self._compared(receiver)
                    for name in compared:
                        state[name] = state.get(name, set()) | {"bounded"}
                    if any(AMOUNT_NAME.search(n) for n in compared):
                        self._control("amount_cap", node)
            elif sub.type == "member_expression" and _txt(sub.child_by_field_name("property")) == "operations":
                for name in self._names_in(sub):
                    state[name] = state.get(name, set()) - {"foreign_tx"}
                self._control("transaction_inspection", node)

    def _non_positive(self, bound) -> bool:
        bound = _unwrap(bound)
        if bound is None or bound.type != "number":
            return False
        try:
            return float(_txt(bound).replace("_", "").rstrip("n")) <= 0
        except ValueError:
            return False

    def _checked(self, node, state) -> None:
        node = _unwrap(node)
        if node is None:
            return
        if node.type in {"call_expression", "new_expression"} and len(_args(node)) == 1:
            return self._checked(_args(node)[0], state)
        key = _dotted(node) if node.type in {"identifier", "member_expression"} else ""
        if key:
            state[key] = (state.get(key, self.tags(node, state)) - UNTRUSTED) | {"checked"}

    def _names_in(self, node) -> set[str]:
        out = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            if n.type == "identifier":
                out.add(_txt(n))
            stack.extend(n.named_children)
        return out

    def _compared(self, side) -> set[str]:
        side = _unwrap(side)
        if side is None:
            return set()
        if side.type in {"identifier", "member_expression"}:
            return {_dotted(side)}
        if side.type == "binary_expression" and _txt(side.child_by_field_name("operator")) == "+":
            # `spent + price > MAX`: a running total plus this payment, both bounded.
            return self._compared(side.child_by_field_name("left")) | self._compared(side.child_by_field_name("right"))
        if side.type in {"call_expression", "new_expression"}:
            args = _args(side)
            if len(args) == 1:
                return self._compared(args[0])
            fn = side.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression" and not args:
                return self._compared(fn.child_by_field_name("object"))  # amount.toNumber()
        return set()

    def _nonblocking(self, stmt) -> bool:
        cond = stmt.child_by_field_name("condition")
        consequence = stmt.child_by_field_name("consequence")
        text = _txt(cond)
        if not re.search(r">", text) or _terminates(consequence):
            return False
        warns = bool(re.search(r"\b(?:console|logger|log)\.\w+\s*\(", _txt(consequence)))
        return warns and bool(re.search(r"max|cap|limit|budget|threshold", text, re.I))

    # -------------------------------------------------------------- statements
    def assign(self, target, value: set[str], state, value_node) -> None:
        target = _unwrap(target)
        if target is None:
            return
        if target.type == "identifier":
            name = _txt(target)
            state[name] = set(value)
            v = _unwrap(value_node)
            if v is not None and v.type in {"identifier", "member_expression"} and not self.p.resolve(self.module, v, self.fn, self.local_types):
                self.aliases[name] = self.canonical(v)
            else:
                self.aliases.pop(name, None)
        elif target.type == "member_expression":
            state[_dotted(target)] = set(value)
            obj = _unwrap(target.child_by_field_name("object"))
            if obj is not None and obj.type == "identifier" and value & {"payment_header", "verify_result"}:
                self.request_fields.add(_txt(target.child_by_field_name("property")))
            if obj is not None and obj.type == "this" and self.fn is not None and self.fn.cls:
                attrs = self.p.class_attrs.setdefault(f"{self.fn.module}:{self.fn.cls}", {})
                current = attrs.setdefault(_txt(target.child_by_field_name("property")), set())
                if not value <= current:
                    current |= value
                    self.p._propagated = True
        elif target.type in {"object_pattern", "array_pattern"}:
            self.bind(target, value, state)

    def bind(self, pattern, value: set[str], state, source_key: str | None = None,
             constraints: dict[str, str] | None = None) -> None:
        pattern = _unwrap(pattern) if pattern is not None and pattern.type != "object_pattern" else pattern
        if pattern is None:
            return
        constraints = constraints or {}
        if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
            name = _txt(pattern)
            if pattern.type == "shorthand_property_identifier_pattern" and source_key:
                value = set(state.get(f"{source_key}.{name}", value))
            state[name] = set(value)
            for prop, kind in constraints.items():
                base = state.get(f"{name}.{prop}", set(value))
                state[f"{name}.{prop}"] = (base - UNTRUSTED) | {"checked"} if kind == "enum" else base | {"bounded"}
            return
        if pattern.type == "object_pattern":
            for prop in pattern.named_children:
                if prop.type == "shorthand_property_identifier_pattern":
                    name = _txt(prop)
                    tags = set(state.get(f"{source_key}.{name}", value)) if source_key else set(value)
                    if "model" in tags and _SECRET_ARG.search(name) and "signer" not in tags and self._model_entry():
                        self._flow("secret_via_model", prop, {"model", "secret"}, f"tool argument `{name}` carries a secret key")
                        tags |= {"secret"}
                    kind = constraints.get(name)
                    state[name] = (tags - UNTRUSTED) | {"checked"} if kind == "enum" else tags | {"bounded"} if kind == "max" else tags
                elif prop.type == "pair_pattern":
                    key = _txt(prop.child_by_field_name("key"))
                    inner = prop.child_by_field_name("value")
                    tags = set(state.get(f"{source_key}.{key}", value)) if source_key else set(value)
                    kind = constraints.get(key)
                    tags = (tags - UNTRUSTED) | {"checked"} if kind == "enum" else tags | {"bounded"} if kind == "max" else tags
                    self.bind(inner, tags, state)
                elif prop.type == "object_assignment_pattern":
                    left = prop.child_by_field_name("left")
                    name = _txt(left)
                    tags = set(state.get(f"{source_key}.{name}", value)) if source_key else set(value)
                    kind = constraints.get(name)
                    state[name] = (tags - UNTRUSTED) | {"checked"} if kind == "enum" else tags | {"bounded"} if kind == "max" else tags
                elif prop.type == "rest_pattern":
                    for inner in prop.named_children:
                        self.bind(inner, value, state)
            return
        if pattern.type == "array_pattern":
            for inner in pattern.named_children:
                self.bind(inner, value, state)
            return
        if pattern.type == "assignment_pattern":
            self.bind(pattern.child_by_field_name("left"), value, state, source_key, constraints)
            return
        if pattern.type == "rest_pattern":
            for inner in pattern.named_children:
                self.bind(inner, value, state)

    def check_return(self, node, value: set[str]) -> None:
        if self.fn is not None and self.fn.key in self.p.model_entries and "secret" in value:
            self._flow("secret_to_model", node, value, "a tool result returned to the model contains secret material")

    def block(self, statements, state) -> None:
        for stmt in statements:
            self.statement(stmt, state)

    def statement(self, stmt, state) -> None:
        t = stmt.type
        if t in {"comment", "empty_statement", "import_statement", "class_declaration", "abstract_class_declaration",
                 "interface_declaration", "type_alias_declaration", "enum_declaration", "ambient_declaration",
                 "module", "internal_module"}:
            return
        if t in {"function_declaration", "generator_function_declaration"}:
            key = self.p.by_node.get((self.module.path, stmt.start_byte, stmt.end_byte))
            if key:
                self.p.capture(key, state)
            return
        if t == "export_statement":
            decl = stmt.child_by_field_name("declaration")
            if decl is not None:
                self.statement(decl, state)
            value = stmt.child_by_field_name("value")
            if value is not None:
                self.tags(value, state)
            return
        if t in {"lexical_declaration", "variable_declaration"}:
            for d in stmt.named_children:
                if d.type != "variable_declarator":
                    continue
                name = d.child_by_field_name("name")
                value_node = d.child_by_field_name("value")
                if value_node is None:
                    continue
                value = self.tags(value_node, state)
                v = _unwrap(value_node)
                if v is not None and v.type == "new_expression" and name is not None and name.type == "identifier":
                    cls = self.p.class_of(self.module, v.child_by_field_name("constructor"))
                    if cls:
                        self.local_types[_txt(name)] = cls
                if name is not None and name.type == "object_pattern":
                    src = _dotted(v) if v is not None and v.type in {"identifier", "member_expression"} else None
                    self.bind(name, value, state, source_key=src)
                    if v is not None and v.type == "call_expression" and _WALLET_HOOK.match(
                            _dotted(v.child_by_field_name("function")).rsplit(".", 1)[-1]):
                        for prop in name.named_children:
                            if prop.type == "shorthand_property_identifier_pattern":
                                self.aliases[_txt(prop)] = "browserwallet." + _txt(prop)
                                # Callbacks defined in the component use the same function.
                                self.p.wallet_names.setdefault(self.module.path, set()).add(_txt(prop))
                else:
                    if name is not None and name.type == "identifier" and v is not None and v.type == "call_expression":
                        verdict = self.p.resolve(self.module, v.child_by_field_name("function"), self.fn, self.local_types)
                        if verdict in self.p.functions:
                            self._verdicts[_txt(name)] = verdict
                        else:
                            self._verdicts.pop(_txt(name), None)
                    if name is not None and name.type == "identifier" and v is not None and _BROWSER_WALLET.search(_txt(v)):
                        # A Wallet Standard feature or an injected provider: the user's wallet
                        # shows the transaction and asks for approval.
                        self.p.wallet_names.setdefault(self.module.path, set()).add(_txt(name))
                    self.assign(name, value, state, value_node)
            return
        if t == "expression_statement":
            for child in stmt.named_children:
                self.tags(child, state)
            return
        if t == "if_statement":
            cond = stmt.child_by_field_name("condition")
            consequence = stmt.child_by_field_name("consequence")
            alternative = stmt.child_by_field_name("alternative")
            self.tags(cond, state)
            self._settle_checked(cond, state)
            # A sponsor check counts when it fails closed: the branch for a bad envelope rejects,
            # or the check encloses what follows (`if (ok) { tx.sign(k) }`). A branch that logs
            # or counts a metric rejects nothing.
            alt_body = alternative.named_children[0] if alternative is not None and alternative.type == "else_clause" \
                and alternative.named_children else alternative
            stops = _rejects(consequence)
            inside: set[str] = set()
            if stops:
                guards = self._sponsor_guards(cond, state, rejects=True)
                self.sponsor_checks |= guards
                self.sponsor_throws |= guards if stops == "throw" else set()
            elif alt_body is not None and _rejects(alt_body):
                guards = self._sponsor_guards(cond, state, rejects=False)
                self.sponsor_checks |= guards
                self.sponsor_throws |= guards if _rejects(alt_body) == "throw" else set()
            else:
                inside = self._sponsor_guards(cond, state, rejects=False)
            if self._nonblocking(stmt) and self.record:
                self.p.profile.nonblocking_controls.append(self.p.location(self.module, stmt))
            if _terminates(consequence) and alternative is None:
                self.statement(consequence, {k: set(v) for k, v in state.items()})
                self._rejecting = _rejects(consequence)
                self.assume(cond, False, state, node=stmt)
                self._rejecting = ""
                return
            branches = []
            optional = self._optional_guard(cond)
            for i, body in enumerate((consequence, alternative)):
                branch = {k: set(v) for k, v in state.items()}
                saved = self.approved
                if i == 0:
                    self.assume(cond, True, branch, node=stmt)
                    self._conditional += optional
                    self._enclosing.append(inside)
                if body is not None:
                    inner = body.named_children[0] if body.type == "else_clause" and body.named_children else body
                    self.statement(inner, branch)
                if i == 0:
                    self.approved = saved
                    self._conditional -= optional
                    self._enclosing.pop()
                branches.append(branch)
            for key in set(branches[0]) | set(branches[1]):
                state[key] = branches[0].get(key, set()) | branches[1].get(key, set())
            return
        if t == "statement_block":
            self.block(stmt.named_children, state)
            return
        if t in {"for_in_statement", "for_statement", "while_statement", "do_statement"}:
            branch = {k: set(v) for k, v in state.items()}
            if t == "for_in_statement":
                left = stmt.child_by_field_name("left")
                right = stmt.child_by_field_name("right")
                value = self.tags(right, state)
                if left is not None:
                    target = left
                    if left.type in {"lexical_declaration", "variable_declaration"}:
                        decl = next((c for c in left.named_children if c.type == "variable_declarator"), None)
                        target = decl.child_by_field_name("name") if decl is not None else None
                    self.bind(target, value, branch)
            elif t == "for_statement":
                init = stmt.child_by_field_name("initializer")
                if init is not None:
                    self.statement(init, branch)
            else:
                self.tags(stmt.child_by_field_name("condition"), state)
            body = stmt.child_by_field_name("body")
            for _ in range(2):
                if body is not None:
                    self.statement(body, branch)
            for key, value in branch.items():
                state[key] = state.get(key, set()) | value
            return
        if t == "try_statement":
            body = stmt.child_by_field_name("body")
            if body is not None:
                self.statement(body, state)
            handler = stmt.child_by_field_name("handler")
            if handler is not None:
                hbody = handler.child_by_field_name("body")
                if hbody is not None:
                    self.statement(hbody, state)
            final = stmt.child_by_field_name("finalizer")
            if final is not None:
                fbody = final.child_by_field_name("body") or (final.named_children[0] if final.named_children else None)
                if fbody is not None:
                    self.statement(fbody, state)
            return
        if t == "switch_statement":
            self.tags(stmt.child_by_field_name("value"), state)
            body = stmt.child_by_field_name("body")
            ends = [_rejects(s) for case in (body.named_children if body is not None else [])
                    for s in case.named_children[-1:]]
            if self._credential_switch(stmt.child_by_field_name("value"), state) and any(ends):
                # switch (e.credentials().switch()) { case address: ...; default: throw }
                self.sponsor_checks.add("credential_type")
                if "throw" in ends:
                    self.sponsor_throws.add("credential_type")
            for case in (body.named_children if body is not None else []):
                branch = {k: set(v) for k, v in state.items()}
                for s in case.named_children:
                    if s.type.endswith("statement") or s.type in {"lexical_declaration", "variable_declaration"}:
                        self.statement(s, branch)
                for key, value in branch.items():
                    state[key] = state.get(key, set()) | value
            return
        if t == "return_statement":
            value = set()
            for child in stmt.named_children:
                value |= self.tags(child, state)
                self.sponsor_returns |= self._sponsor_guards(child, state)  # `return tx.source === PLACEHOLDER`
            self.returned |= value
            self.check_return(stmt, value)
            return
        if t == "throw_statement":
            for child in stmt.named_children:
                self.tags(child, state)
            return
        if t == "labeled_statement":
            body = stmt.child_by_field_name("body")
            if body is not None:
                self.statement(body, state)
            return
        for child in stmt.named_children:
            if child.type.endswith("statement") or child.type in {"statement_block"}:
                self.statement(child, state)
            else:
                self.tags(child, state)



def analyse_js(files: dict[str, str], profile: CodeProfile, entrypoints: dict[str, set[str]] | None = None) -> list[str]:
    """Analyse JS/TS files into `profile`. Returns the files analysed with data flow."""
    if not any(is_js(p) for p in files) or not available():
        return []
    project = JsProject(files, profile, entrypoints)
    project.run()
    return project.analysed
