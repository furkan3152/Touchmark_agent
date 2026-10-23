"""Soroban authorization entries the agent signs, and how long its signatures stay valid.

Signing a Soroban authorization entry signs its whole invocation tree: the root call and every
sub-invocation the simulated contract added. When the contract is one a request, the model or
a 402 response names, that contract chooses the tree, and an uninspected tree can carry a
transfer from the signer to anyone. The data-flow parsers (jsflow, codeflow) call the hooks
here at each call; this module adds two labels (``sim_auth`` on simulation output,
``contract_untrusted`` on a contract chosen by input), the tree-inspection sanitizer, the
expiration classifier, and the SEP-10 and SEP-45 challenge checks. A blind tree is reported
under the existing signing ids; only the expiration and the web-auth challenges have ids of
their own.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from ..models import Severity
from .codeflow import DIRECT, UNTRUSTED

#: The SDK default validity of a signed authorization entry: signAuthEntries signs until the
#: latest ledger + 100 (js-stellar-sdk contract/assembled_transaction.js).
DEFAULT_OFFSET = 100
#: Offsets up to here are the default with some slack (about 10 minutes at 5 s a ledger);
#: up to an hour (720 ledgers) is LOW, longer is MEDIUM.
SLACK_OFFSET, HOUR_OFFSET = 120, 720
#: A validity taken from the paying server's requirements or challenge.
_COUNTERPARTY = re.compile(r"max_?[Tt]imeout_?[Ss]econds|maxTimeoutSeconds|\bpaymentRequirements\b|\brequirements?\b"
                           r"|\baccepted\b|\bmethodDetails\b|\bchallenge\b")
#: A ceiling on it.
_CLAMP = re.compile(r"\bMath\.min\s*\(|(?<![\w.])min\s*\(|\.min\s*\(|\bclamp\b|\.clamp\s*\(|\bcmp::min\b")
#: Wall-clock values: not a ledger number.
_WALL_CLOCK = re.compile(r"\bDate\.now\s*\(|\bnew\s+Date\b|\btime\.time\s*\(|\bdatetime\b|\bSystemTime::now\b|\bUtc::now\b")
_OFFSET = re.compile(r"\+\s*(?P<a>\d[\d_]*)(?![\w.])|(?<![\w.])(?P<b>\d[\d_]*)\s*\+")
#: Code that walks an authorization tree: sub-invocations, and the root's contract and function.
_TREE_PARTS = (re.compile(r"subInvocations|sub_invocations"), re.compile(r"contractAddress|contract_address|contractId\s*\("),
               re.compile(r"functionName|function_name"))


@dataclass(frozen=True)
class Expiry:
    severity: Severity
    note: str


def classify_expiration(expr: str, resolve, depth: int = 3) -> Expiry | None:
    """How long a signature stays valid, from the expression that sets its expiration ledger.
    ``resolve(name)`` returns a local variable's initializer or a helper's body (one hop)."""
    text = _expand(expr, resolve, depth)
    if _WALL_CLOCK.search(text):
        return Expiry(Severity.LOW, "the expiration is computed from the clock, not from a ledger number")
    if _COUNTERPARTY.search(text):
        if _CLAMP.search(text):
            return None
        return Expiry(Severity.LOW, "the paying server's maxTimeoutSeconds decides how long the signature stays "
                                    "valid, with no ceiling")
    offsets = [int((m.group("a") or m.group("b")).replace("_", "")) for m in _OFFSET.finditer(text)]
    if not offsets or not re.search(r"ledger|sequence|seq\b|latest", text, re.I):
        return None
    offset = max(offsets)
    if offset > HOUR_OFFSET:
        return Expiry(Severity.MEDIUM, f"signatures stay valid for {offset} ledgers (about {offset * 5 // 3600} h or "
                                       f"more), against {DEFAULT_OFFSET} by default")
    if offset > SLACK_OFFSET:
        return Expiry(Severity.LOW, f"signatures stay valid for {offset} ledgers, against {DEFAULT_OFFSET} by default")
    return None


def _expand(expr: str, resolve, depth: int) -> str:
    """The expression with each name it uses followed by what that name stands for."""
    seen: set[str] = set()
    out, frontier = expr, [expr]
    for _ in range(depth):
        nxt = []
        for part in frontier:
            for name in dict.fromkeys(re.findall(r"[A-Za-z_$][\w$]*", part)):
                if name in seen:
                    continue
                seen.add(name)
                value = resolve(name)
                if value:
                    if re.fullmatch(r"\s*\d[\d_]*\s*", value):
                        out = re.sub(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", value.strip(), out)
                    else:
                        out += f" ⟨{value}⟩"
                    nxt.append(value)
        frontier = nxt
    return out


def inspects_tree(texts) -> bool:
    """Some code compares sub-invocations, the root contract and the function name: the
    sanitizer of item 13 (a full walk, or `subInvocations().length === 0` with the root pinned)."""
    return any(all(p.search(t) for p in _TREE_PARTS) for t in texts)


# --------------------------------------------------------------------------- JavaScript hook
#: Contract clients built from a contract id: the simulation they run is for that contract.
_ASSEMBLED = re.compile(r"(?:^|\.)AssembledTransaction\.(?:build|buildWithOp|fromJSON|fromXDR)$|(?:^|\.)Client\.from\w*$")
_SIMULATES = {"simulateTransaction", "prepareTransaction", "assembleTransaction", "simulate"}


def js_call(interp, node, label: str, short: str, receiver_node, receiver: set[str], arg_nodes, args, state,
            is_new: bool) -> bool:
    """Labels and sinks for one JS call. Returns True when the authorization tree signed here
    is inspected (the existing authorizeEntry sink then stays quiet)."""
    from . import jsflow as J
    add: set[str] = set()
    every = set().union(*args) if args else set()
    if is_new and short == "Contract" and args and args[0] & DIRECT:
        add.add("contract_untrusted")
    contract_option = None
    if _ASSEMBLED.search(label) or (is_new and short == "Client"):
        contract_option = J._props(arg_nodes[0]).get("contractId") if arg_nodes else None
        add.add("sim_auth")  # build() simulates unless told not to
    if short == "invokeContractFunction" and arg_nodes:
        contract_option = J._props(arg_nodes[0]).get("contract")
    if contract_option is not None and interp.tags(contract_option, state) & DIRECT:
        add.add("contract_untrusted")
    if short in _SIMULATES:
        add.add("sim_auth")
    inspected = False
    if J._AUTHORIZE.search(label):
        entry = args[0] if args else set()
        inspected = _sink(interp, node, entry, arg_nodes[2] if len(arg_nodes) > 2 else None)
    elif short == "signAuthEntries" and receiver_node is not None:
        options = J._props(arg_nodes[0]) if arg_nodes else {}
        for key in ("authorizeEntry", "signAuthEntry"):
            fk = interp.p._function_arg(options.get(key), interp.module.path)
            if fk:  # the callback's entry parameter is one of the receiver's entries
                interp.p.propagate(fk, [receiver | every] * max(1, len(interp.p.entry[fk])))
        inspected = _sink(interp, node, receiver, options.get("expiration"))
    if add:
        current = interp._adjust.get((node.start_byte, node.end_byte), (set(), set()))
        interp._adjust[(node.start_byte, node.end_byte)] = (current[0] | add, current[1])
    return inspected


def _js_inspected(interp) -> bool:
    cache = interp.p.__dict__.setdefault("_tree_inspected", {})
    path = interp.module.path
    if path not in cache:
        modules = [path] + [t.split(":", 1)[0] for t in interp.module.imports.values() if not t.startswith(("lib:", "module:"))] \
            + [t[7:] for t in interp.module.imports.values() if t.startswith("module:")]
        cache[path] = inspects_tree("\n".join(interp.p.modules[m].lines) for m in dict.fromkeys(modules) if m in interp.p.modules)
    return cache[path]


def _js_resolver(interp):
    """Local initializers in the function (and its parents), module constants, then the body
    of a project helper with that name."""
    from . import jsflow as J
    scopes = []
    fn = interp.fn
    while fn is not None:
        scopes.append(fn.node)
        fn = interp.p.functions.get(fn.parent) if fn.parent else None
    scopes.append(interp.module.root)

    def resolve(name: str) -> str | None:
        for scope in scopes:
            stack = [scope]
            while stack:
                n = stack.pop()
                if n.type == "variable_declarator":
                    target = n.child_by_field_name("name")
                    value = n.child_by_field_name("value")
                    if target is not None and value is not None:
                        if target.type == "identifier" and J._txt(target) == name:
                            return J._txt(value)
                        named = re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", J._txt(target))
                        if target.type == "object_pattern" and named:
                            return f"{J._txt(value)}.{name}"  # const { maxTimeoutSeconds } = requirements
                if n is scope or not J._is_function(n):
                    stack.extend(n.named_children)
        for key, fn in interp.p.functions.items():
            if key.rsplit(":", 1)[-1].rsplit(".", 1)[-1] == name:
                return J._txt(fn.node)[:2000]
        return None
    return resolve


def _sink(interp, node, entry: set[str], expiry_node) -> bool:
    from . import jsflow as J
    inspected = _js_inspected(interp)
    location = interp.p.location(interp.module, node)
    blind = {"sim_auth", "contract_untrusted"} <= entry and not inspected and not interp.approved
    if inspected:
        interp._control("transaction_inspection", node)
    if blind and interp.record:
        interp._cap("stellar_signing", node)
        interp._cap("foreign_tx_signing", node)
        interp._flow("foreign_signing", node, entry,
                     "an authorization tree simulated for a contract the input chooses is signed without inspecting it")
        interp.p.profile.add_fact("auth_tree_unchecked", location, "simulated for a contract chosen by input")
    if expiry_node is not None and interp.record:
        found = classify_expiration(J._txt(expiry_node), _js_resolver(interp))
        if found:
            interp.p.profile.add_fact("auth_expiration", location, found.note, severity=found.severity.value)
    return inspected and bool(entry & (UNTRUSTED | {"foreign_tx"}))


def mark_payment_requirements(project) -> None:
    """x402 client schemes (`createPaymentPayload(x402Version, requirements)` in a class): the
    requirements are the paid server's 402 response, so they are external input."""
    for key, fn in project.functions.items():
        if fn.cls and fn.name == "createPaymentPayload":
            for i, (name, _) in enumerate(fn.params):
                if name and re.search(r"requirement", name, re.I):
                    project.entry[key][i].add("external")
                    project.profile.entrypoints.setdefault(f"{fn.module}:{fn.name}", "x402 requirements from a 402 response")


# --------------------------------------------------------------------------- Python hook
_PY_SIMULATES = {"simulate_transaction", "prepare_transaction"}


def py_call(interp, node: ast.Call, state) -> tuple[set[str], bool]:
    """Labels for one Python call, and the authorize_entry sink. Returns (labels to add,
    whether the authorization tree signed here is inspected)."""
    from .codeflow import _dotted
    short = _dotted(node.func).rsplit(".", 1)[-1]
    add: set[str] = set()
    if short in {"append_invoke_contract_function_op", "invoke_contract_function"}:
        contract = next((k.value for k in node.keywords if k.arg == "contract_id"), node.args[0] if node.args else None)
        if contract is not None and interp.tags(contract, state) & DIRECT:
            add.add("contract_untrusted")
    if short in _PY_SIMULATES:
        add.add("sim_auth")
    if short not in {"authorize_entry", "sign_auth_entries"}:
        return add, False
    entry = interp.tags(node.args[0], state) if node.args else set()
    texts = [interp.p.files.get(interp.p.module_of[interp.module], "")]
    inspected = inspects_tree(texts)
    location = interp.p.location(interp.module, node)
    if inspected:
        interp._control("transaction_inspection", node)
    if interp.record and {"sim_auth", "contract_untrusted"} <= entry and not inspected and not interp.approved:
        interp.p.profile.add_fact("auth_tree_unchecked", location, "simulated for a contract chosen by input")
    expiry = next((k.value for k in node.keywords if k.arg in {"valid_until_ledger_sequence", "valid_until_ledger_seq"}),
                  node.args[2] if len(node.args) > 2 else None)
    if expiry is not None and interp.record:
        found = classify_expiration(ast.unparse(expiry), _py_resolver(interp))
        if found:
            interp.p.profile.add_fact("auth_expiration", location, found.note, severity=found.severity.value)
    return add, inspected and bool(entry & UNTRUSTED)


def _py_resolver(interp):
    fn = interp.fn.node if interp.fn is not None else None
    assigns: dict[str, str] = {}
    for n in ast.walk(fn) if fn is not None else []:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            assigns.setdefault(n.targets[0].id, ast.unparse(n.value))
    functions = {f.node.name: f.node for f in interp.p.functions.values()}

    def resolve(name: str) -> str | None:
        if name in assigns:
            return assigns[name]
        if name in functions:
            return ast.unparse(functions[name])[:2000]
        return None
    return resolve


# --------------------------------------------------------------------------- Rust
_RUST_FIELD = re.compile(r"\bsignature_expiration_ledger\s*(?::(?!:)|=(?!=))|\bsignature_expiration_ledger\s*(?=,|\n\s*})")


def _rhs(code: str, start: int) -> str:
    """The expression from ``start`` to the `,` `;` or closing bracket that ends it at depth 0."""
    depth = 0
    for i in range(start, min(len(code), start + 600)):
        ch = code[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return code[start:i]
            depth -= 1
        elif depth == 0 and ch in ",;":
            return code[start:i]
    return code[start:start + 600]


_RUST_TEST = re.compile(r"(?:^|/)(?:tests?|benches|examples?)/|_test\.rs$|(?:^|/)tests?\.rs$", re.I)


def rust_expiration_hits(files: dict[str, str]) -> list[tuple[str, int, str, Expiry]]:
    """`signature_expiration_ledger` set outside a contract and outside tests, from the paying
    server's timeout without a ceiling, from the clock, or a long constant offset."""
    from .stellar_native import _rust_code  # comments and literals masked, offsets kept
    hits = []
    for name, text in files.items():
        if not name.endswith(".rs") or _RUST_TEST.search(name) or "#![no_std]" in text \
                or "signature_expiration_ledger" not in text:
            continue
        code = _rust_code(text.split("#[cfg(test)]", 1)[0])
        if "signature_expiration_ledger" not in code:
            continue

        def resolve(ident: str, code=code) -> str | None:
            let = re.search(r"\blet\s+(?:mut\s+)?" + re.escape(ident) + r"\b(?:\s*:[^=;]+)?\s*=\s*([^;]+);", code)
            if let:
                return let.group(1)
            fn = re.search(r"\bfn\s+" + re.escape(ident) + r"\s*(?:<[^>]*>)?\s*\(", code)
            if fn:
                start = code.find("{", fn.end())
                return code[fn.start():start + 1500] if start >= 0 else None
            return None
        for m in _RUST_FIELD.finditer(code):
            expr = (_rhs(code, m.end()) if code[m.end() - 1] in ":=" else "signature_expiration_ledger").strip()
            if re.fullmatch(r"\d[\d_]*", expr) or expr == "0":
                continue  # an absolute ledger (a fixture) or the unsigned placeholder
            found = classify_expiration(expr, resolve)
            if found:
                line = code.count("\n", 0, m.start()) + 1
                start = code.rfind("\n", 0, m.start()) + 1
                end = m.end() + len(_rhs(code, m.end())) if code[m.end() - 1] in ":=" else m.end()
                hits.append((name, line, " ".join(text[start:end].split()), found))
                break  # one place per file: the others copy the same value on
    return hits


# --------------------------------------------------------------------------- SEP-10 / SEP-45
_JS_PY = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".mts", ".cts", ".py")
#: A request for a SEP-10 challenge: the stellar.toml WEB_AUTH_ENDPOINT, or the `account` query.
_SEP10_REQUEST = re.compile(r"WEB_AUTH_ENDPOINT|webAuthEndpoint|web_auth_endpoint|[?&]account=|"
                            r"""searchParams\.(?:set|append)\(\s*["']account["']|params\s*=\s*\{[^}]*["']account["']""")
_PARSE_TX = re.compile(r"\bnew\s+(?:[\w$]+\.)?Transaction\s*\(|\bTransactionBuilder\.fromXDR\s*\(|\bTransaction\.fromXDR\s*\(|"
                       r"\bTransactionEnvelope\.from_xdr\s*\(|\bparse_transaction_envelope_from_xdr\s*\(")
_KEY_SIGN = re.compile(r"\.\s*sign\s*\(")
#: The SDK readers that check a challenge, or the checks themselves (sequence 0 and the
#: `<home domain> auth` ManageData operation).
_SEP10_READ = re.compile(r"readChallengeTx|read_challenge_transaction|verifyChallengeTx|verify_challenge_transaction")
_SEP10_SEQUENCE = re.compile(r"""sequence\s*(?:!==?|===?|!=|==)\s*["']?0\b|\bsequence\b[^\n]{0,40}\bnot\s+0\b""")
_SEP10_OPERATION = re.compile(r"""manageData|manage_data|MANAGE_DATA""")
#: SEP-45: authorization entries from a contract web-auth server.
_SEP45_REQUEST = re.compile(r"WEB_AUTH_FOR_CONTRACTS_ENDPOINT|webAuthForContracts|web_auth_for_contracts|authorization_entries")
_SEP45_SIGN = re.compile(r"\bauthorizeEntry\s*\(|\bauthorize_entry\s*\(|\bsignAuthEntry\s*\(")
_SEP45_CHECKS = (re.compile(r"web_auth_verify"), re.compile(r"WEB_AUTH_CONTRACT_ID|webAuthContractId|web_auth_contract_id", re.I),
                 re.compile(r"subInvocations|sub_invocations"))
#: A file about web authentication at all (SEP-10 or SEP-45).
_WEB_AUTH_FILE = re.compile(r"WEB_AUTH|web_?auth|webAuth|\bsep-?(?:10|45)\b|\bSEP(?:10|45)\b", re.I)
#: Interop, round-trip and smoke harnesses: a level lower.
_HARNESS = re.compile(r"(?:^|/)(?:interop|tests?|__tests__|e2e)/|roundtrip|round_trip|smoke|\.test\.|\.spec\.|_test\.py$", re.I)


def web_auth_hits(files: dict[str, str]) -> list[tuple[str, str, int, str, Severity, str]]:
    """(kind, file, line, text, severity, note) for SEP-10 challenges and SEP-45 entries signed
    without the checks the SEPs require of the client."""
    from .network_rules import _region, _sources
    hits = []
    for src in _sources({n: t for n, t in files.items() if n.endswith(_JS_PY)}):
        code = src.code
        if not _WEB_AUTH_FILE.search(code):
            continue
        if _SEP10_REQUEST.search(code) and not _SEP10_READ.search(code) \
                and not (_SEP10_SEQUENCE.search(code) and _SEP10_OPERATION.search(code) and re.search(r"""\bauth["'`]""", code)):
            for request in _SEP10_REQUEST.finditer(code):
                start, end = _region(src, request.start())
                parsed = _PARSE_TX.search(code, request.end(), end)
                signed = _KEY_SIGN.search(code, parsed.end(), end) if parsed else None
                if signed:
                    line = src.text.count("\n", 0, signed.start()) + 1
                    severity = Severity.HIGH.downgrade(1) if _HARNESS.search(src.name) else Severity.HIGH
                    hits.append(("sep10", src.name, line, src.text.splitlines()[line - 1].strip(), severity,
                                 "the challenge is parsed and signed without checking its sequence number and operations"))
                    break
        if _SEP45_REQUEST.search(code) and _SEP45_SIGN.search(code):
            missing = [p.pattern.split("|")[0] for p in _SEP45_CHECKS if not p.search(code)]
            if missing:
                sign = _SEP45_SIGN.search(code)
                line = src.text.count("\n", 0, sign.start()) + 1
                severity = Severity.HIGH.downgrade(1) if _HARNESS.search(src.name) else Severity.HIGH
                hits.append(("sep45", src.name, line, src.text.splitlines()[line - 1].strip(), severity,
                             "nothing checks " + ", ".join(missing)))
    return hits
