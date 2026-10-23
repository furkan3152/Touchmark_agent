"""Soroban authorization entries the agent signs, and how long its signatures stay valid.

Signing a Soroban authorization entry signs its whole invocation tree: the root call and every
sub-invocation the simulated contract added. When the contract is one a request, the model or
a 402 response names, that contract chooses the tree, and an uninspected tree can carry a
transfer from the signer to anyone. The data-flow parsers (jsflow, codeflow) call the hooks
here at each call; this module adds three labels (``sim_auth`` on simulation output,
``contract_untrusted`` on a contract chosen by input, ``auth_built`` on an entry the code
builds itself with no sub-invocations), the tree-inspection sanitizer (comparisons of the
sub-invocations, the root contract and the function name in the signing function or the
helpers it calls; comments, strings and logging do not count), the expiration classifier, and
the SEP-10 and SEP-45 challenge checks. A blind tree is reported under the existing signing
ids; only the expiration and the web-auth challenges have ids of their own.
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
#: A term that reads the ledger the network is at: the latest ledger or a sequence number.
_LEDGER_TERM = re.compile(r"ledger|sequence|\bseq\b|latest", re.I)
_NAME = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*")
#: Names never inlined: language words and the clock and arithmetic helpers the classes test for.
_KEEP = frozenset({"await", "new", "this", "self", "return", "Math", "Date", "time", "datetime", "int", "len", "min",
                   "max", "u32", "u64", "as", "and", "or", "not", "if", "else", "None", "true", "false", "True", "False"})
#: Inlined text beyond this is not expanded further.
_INLINE_LIMIT = 4000
#: The parts of an authorization tree a check must compare (stellar-base and stellar_sdk names):
#: the sub-invocations, the root's contract address and its function name.
_PARTS = {"subInvocations": "sub", "sub_invocations": "sub", "contractAddress": "contract",
          "contract_address": "contract", "functionName": "function", "function_name": "function"}
_ALL_PARTS = frozenset(_PARTS.values())


@dataclass(frozen=True)
class Expiry:
    severity: Severity
    note: str


def classify_expiration(expr: str, resolve, depth: int = 3) -> Expiry | None:
    """How long a signature stays valid, from the expression that sets its expiration ledger.
    ``resolve(name)`` returns what a name stands for: a local's initializer, or the return
    expression of a helper (never a whole body). Clock and counterparty tokens are looked for
    in the expression with those inlined; an offset counts only when it is added to the term
    that reads the ledger."""
    text = _inline(expr, resolve, depth)
    ledger = bool(_LEDGER_TERM.search(text))
    if _WALL_CLOCK.search(text) and not ledger:
        return Expiry(Severity.LOW, "the expiration is computed from the clock, not from a ledger number")
    if _COUNTERPARTY.search(text):
        if _CLAMP.search(text):
            return None
        return Expiry(Severity.LOW, "the paying server's maxTimeoutSeconds decides how long the signature stays "
                                    "valid, with no ceiling")
    offsets = _ledger_offsets(text)
    offset = max(offsets) if offsets else 0
    if offset > HOUR_OFFSET:
        return Expiry(Severity.MEDIUM, f"signatures stay valid for {offset} ledgers (about {offset * 5 // 3600} h or "
                                       f"more), against {DEFAULT_OFFSET} by default")
    if offset > SLACK_OFFSET:
        return Expiry(Severity.LOW, f"signatures stay valid for {offset} ledgers, against {DEFAULT_OFFSET} by default")
    return None


def _inline(expr: str, resolve, depth: int) -> str:
    """The expression with each name replaced by `(what it stands for)`, ``depth`` levels deep.
    A name after a dot is replaced only when it is called (a helper method)."""
    seen: set[str] = set()
    text = expr
    for _ in range(depth):
        changed = False
        for name in dict.fromkeys(m.group() for m in _NAME.finditer(text)):
            if name in seen or name in _KEEP or len(text) > _INLINE_LIMIT:
                continue
            seen.add(name)
            value = resolve(name)
            if not value or not value.strip():
                continue
            value = " ".join(value.split())
            pattern = r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])|(?<=\.)" + re.escape(name) + r"(?=\s*\()"
            text = re.sub(pattern, lambda _m, v=value: f"({v})", text)
            changed = True
        if not changed:
            break
    return text


def _constant(text: str) -> int | None:
    """The value of an integer constant expression (`5_000`, `60 * 12`, `(720)`), else None."""
    text = text.strip()
    if not text or len(text) > 60 or not re.fullmatch(r"[\d_\s*+()-]+", text) or not re.search(r"\d", text):
        return None
    try:
        tree = ast.parse(text.replace("_", ""), mode="eval")
    except (SyntaxError, ValueError, RecursionError):
        return None

    def value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult, ast.Sub)):
            a, b = value(node.left), value(node.right)
            if a is None or b is None or abs(a) > 10**9 or abs(b) > 10**9:
                return None
            return a + b if isinstance(node.op, ast.Add) else a * b if isinstance(node.op, ast.Mult) else a - b
        return None
    return value(tree.body)


_OPEN, _CLOSE = "([{", ")]}"


def _left_operand(text: str, end: int) -> str:
    """The operand that ends just before ``end``: names, member chains, calls and brackets."""
    i = end
    while i > 0 and text[i - 1] == " ":
        i -= 1
    stop = i
    while i > 0:
        ch = text[i - 1]
        if ch in _CLOSE:
            depth, j = 0, i - 1
            while j >= 0:
                if text[j] in _CLOSE:
                    depth += 1
                elif text[j] in _OPEN:
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < 0:
                break
            i = j
        elif ch.isalnum() or ch in "_$.":
            i -= 1
        elif ch == " " and text[max(0, i - 6):i] == "await ":
            i -= 6
        else:
            break
    return text[i:stop]


def _right_operand(text: str, start: int) -> str:
    """The operand that starts at ``start``, up to the next operator or separator at depth 0."""
    depth, i = 0, start
    while i < len(text):
        ch = text[i]
        if ch in _OPEN:
            depth += 1
        elif ch in _CLOSE:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch in "+-,;|&?:<>=/%":
            break
        i += 1
    return text[start:i]


def _ledger_offsets(text: str) -> list[int]:
    """Constants added to a term that reads the ledger: `latest + 500`, `100 + seq`,
    `latest_ledger.saturating_add(720)`."""
    out = []
    for m in re.finditer(r"(?<![+=])\+(?![+=])", text):
        left, right = _left_operand(text, m.start()), _right_operand(text, m.end())
        for term, other in ((left, right), (right, left)):
            n = _constant(other)
            if n is not None and _LEDGER_TERM.search(term) and _constant(term) is None:
                out.append(n)
                break
    for m in re.finditer(r"\.(?:saturating|checked|wrapping)_add\s*\(", text):
        n = _constant(_right_operand(text, m.end()))
        if n is not None and _LEDGER_TERM.search(_left_operand(text, m.start())):
            out.append(n)
    return out


# --------------------------------------------------------------------------- tree inspection
def _js_ids(node, aliases: dict[str, set[str]]) -> set[str]:
    """The tree parts a JS expression reads: the part names it uses, and locals holding one."""
    found: set[str] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in {"string", "template_string", "comment", "regex"}:
            continue
        if n.type in {"property_identifier", "identifier", "shorthand_property_identifier"}:
            text = n.text.decode("utf-8", "replace")
            if text in _PARTS:
                found.add(_PARTS[text])
            elif n.type == "identifier" and text in aliases:
                found |= aliases[text]
        stack.extend(n.named_children)
    return found


#: Comparison operators, and calls that test a value against an allowlist or assert it.
_COMPARE_OPS = {"===", "!==", "==", "!=", "<", ">", "<=", ">="}
_ALLOWLIST_CALLS = {"includes", "has", "indexOf", "assert", "ok", "equal", "strictEqual", "deepEqual",
                    "deepStrictEqual", "invariant"}


def _js_compared(root) -> set[str]:
    """Tree parts that code under ``root`` compares: inside an `===`/`!==`-style comparison, a
    switch or an allowlist or assert call, directly or through a local assigned from them; a
    bare if/while test counts only for the sub-invocations (`if (subs.length) throw`).
    Comments, strings and logging do not count."""
    from . import jsflow as J
    declared, contexts, tests = [], [], []
    stack = [root]
    while stack:
        n = stack.pop()
        t = n.type
        if t == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                declared.append((J._txt(name), value))
        elif t == "binary_expression":
            op = n.child_by_field_name("operator")
            if op is not None and J._txt(op) in _COMPARE_OPS:
                contexts.append(n)
        elif t in {"if_statement", "while_statement", "do_statement"}:
            tests.append(n.child_by_field_name("condition"))
        elif t == "switch_statement":
            contexts.append(n.child_by_field_name("value"))
        elif t == "call_expression":
            callee = J._dotted(n.child_by_field_name("function"))
            if callee.rsplit(".", 1)[-1] in _ALLOWLIST_CALLS:
                contexts.append(n.child_by_field_name("arguments"))
        stack.extend(n.named_children)
    aliases: dict[str, set[str]] = {}
    for _ in range(2):  # `const fn = inv.function().contractFn(); const name = fn.functionName()`
        for name, value in declared:
            parts = _js_ids(value, aliases)
            if parts:
                aliases[name] = aliases.get(name, set()) | parts
    found: set[str] = set()
    for c in contexts:
        if c is not None:
            found |= _js_ids(c, aliases)
    for c in tests:
        if c is not None:
            found |= _js_ids(c, aliases) & {"sub"}
    return found


def _js_inspected(interp) -> bool:
    """The signing function (with the functions it sits in) and the helpers it calls, two
    calls deep, compare the sub-invocations, the root contract and the function name."""
    p = interp.p
    cache = p.__dict__.setdefault("_tree_compared", {})
    fn = interp.fn
    if fn is None:
        key = f"module:{interp.module.path}"
        scopes = [(key, interp.module.root)]
    else:
        chain = []
        while fn is not None:
            chain.append(fn.key)
            fn = p.functions.get(fn.parent) if fn.parent else None
        reach, frontier = list(chain), list(chain)
        for _ in range(2):
            frontier = [c for k in frontier for c in sorted(p.callees.get(k, ())) if c in p.functions and c not in reach]
            reach += frontier
        scopes = [(k, p.functions[k].node) for k in reach[:40]]
        key = interp.fn.key
    if key not in cache:
        memo = p.__dict__.setdefault("_tree_compared_scopes", {})
        found: set[str] = set()
        for name, scope in scopes:
            if name not in memo:
                memo[name] = _js_compared(scope)
            found |= memo[name]
        cache[key] = _ALL_PARTS <= found
    return cache[key]


def _py_ids(node: ast.AST, aliases: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr in _PARTS:
            found.add(_PARTS[n.attr])
        elif isinstance(n, ast.Name):
            if n.id in _PARTS:
                found.add(_PARTS[n.id])
            elif n.id in aliases:
                found |= aliases[n.id]
    return found


def _py_compared(fn: ast.AST) -> set[str]:
    """Python counterpart of _js_compared: comparisons (`==`, `in` an allowlist), locals
    assigned from the tree's parts that those test, and bare if/while/assert tests for the
    sub-invocations only."""
    declared, contexts, tests = [], [], []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            declared.append((n.targets[0].id, n.value))
        elif isinstance(n, ast.Compare):
            contexts.append(n)
        elif isinstance(n, (ast.If, ast.While, ast.Assert)):
            tests.append(n.test)
    aliases: dict[str, set[str]] = {}
    for _ in range(2):
        for name, value in declared:
            parts = _py_ids(value, aliases)
            if parts:
                aliases[name] = aliases.get(name, set()) | parts
    found: set[str] = set()
    for c in contexts:
        found |= _py_ids(c, aliases)
    for c in tests:
        found |= _py_ids(c, aliases) & {"sub"}
    return found


def _py_inspected(interp) -> bool:
    """The signing function and the project functions it calls, two calls deep, compare the
    sub-invocations, the root contract and the function name."""
    if interp.fn is None:
        return False
    p = interp.p
    cache = p.__dict__.setdefault("_tree_compared", {})
    if interp.fn.key not in cache:
        reach, frontier = [interp.fn.key], [interp.fn.key]
        for _ in range(2):
            nxt = []
            for k in frontier:
                fn = p.functions[k]
                for call in ast.walk(fn.node):
                    if isinstance(call, ast.Call):
                        target = p._resolve_ref(fn.module, call.func)
                        if target and target in p.functions and target not in reach:
                            reach.append(target)
                            nxt.append(target)
            frontier = nxt
        found: set[str] = set()
        for k in reach[:40]:
            found |= _py_compared(p.functions[k].node)
        cache[interp.fn.key] = _ALL_PARTS <= found
    return cache[interp.fn.key]


def _quiet_tags(interp, node, state) -> set[str]:
    """Labels of an argument evaluated ahead of the call itself, with nothing recorded (the
    call records its arguments' flows, facts and controls once)."""
    saved, interp.record = interp.record, False
    try:
        return interp.tags(node, state)
    finally:
        interp.record = saved


# --------------------------------------------------------------------------- JavaScript hook
#: Contract clients built from a contract id: the simulation they run is for that contract.
_ASSEMBLED = re.compile(r"(?:^|\.)AssembledTransaction\.(?:build|buildWithOp|fromJSON|fromXDR)$|(?:^|\.)Client\.from\w*$")
_SIMULATES = {"simulateTransaction", "prepareTransaction", "assembleTransaction", "simulate"}
#: An authorization entry the code builds itself with no sub-invocations: its tree is what the
#: code wrote, not what a simulation returned (a re-parse of the code's own XDR is allowed).
_EMPTY_SUBS = re.compile(r"\bsubInvocations\s*:\s*\[\s*\]|\bsub_invocations\s*=\s*\[\s*\]")


def auth_tree_index(label: str) -> int:
    """Which argument carries the authorization tree: the entry of authorizeEntry, the
    invocation of authorizeInvocation(signer, validUntilLedgerSeq, invocation) (stellar-base)."""
    return 2 if label.endswith("authorizeInvocation") else 0


def _built_entry(obj) -> bool:
    from . import jsflow as J
    if obj is None or not _EMPTY_SUBS.search(J._txt(obj)):
        return False
    stack = [obj]
    while stack:
        n = stack.pop()
        if n.type == "call_expression" and J._dotted(n.child_by_field_name("function")).endswith("fromXDR"):
            first = next(iter(J._args(n)), None)
            if first is None or not re.search(r"\.toXDR\(\s*\)\s*$", J._txt(first)):
                return False
        stack.extend(n.named_children)
    return True


def js_call(interp, node, label: str, short: str, receiver_node, receiver: set[str], arg_nodes, args, state,
            is_new: bool) -> bool:
    """Labels and sinks for one JS call. Returns True when the authorization tree signed here
    is inspected or was built by the code (the existing authorizeEntry sink then stays quiet)."""
    from . import jsflow as J
    add: set[str] = set()
    if is_new and short == "Contract" and args and args[0] & DIRECT:
        add.add("contract_untrusted")
    if is_new and short == "SorobanAuthorizationEntry" and arg_nodes and _built_entry(arg_nodes[0]):
        add.add("auth_built")
    if short == "invokeHostFunction" and arg_nodes:
        # Operation.invokeHostFunction({func, auth: [entry]}): the operation carries the entries.
        auth = J._unwrap(J._props(arg_nodes[0]).get("auth"))
        entries = (auth.named_children if auth.type == "array" else [auth]) if auth is not None else []
        if entries and all("auth_built" in _quiet_tags(interp, e, state) for e in entries):
            add.add("auth_built")
    contract_option = None
    if _ASSEMBLED.search(label) or (is_new and short == "Client"):
        contract_option = J._props(arg_nodes[0]).get("contractId") if arg_nodes else None
        add.add("sim_auth")  # build() simulates unless told not to
    if short == "invokeContractFunction" and arg_nodes:
        contract_option = J._props(arg_nodes[0]).get("contract")
    if contract_option is not None and _quiet_tags(interp, contract_option, state) & DIRECT:
        add.add("contract_untrusted")
    if short in _SIMULATES:
        add.add("sim_auth")
    known = False
    if J._AUTHORIZE.search(label):
        tree = auth_tree_index(label)
        expiry = 1 if tree == 2 else 2
        entry = args[tree] if len(args) > tree else set()
        known = _sink(interp, node, entry, arg_nodes[expiry] if len(arg_nodes) > expiry else None)
    elif short == "signAuthEntries" and receiver_node is not None:
        options = J._props(arg_nodes[0]) if arg_nodes else {}
        every = set().union(*args) if args else set()
        for key in ("authorizeEntry", "signAuthEntry"):
            fk = interp.p._function_arg(options.get(key), interp.module.path)
            if fk:  # the callback's entry parameter is one of the receiver's entries
                interp.p.propagate(fk, [receiver | every] * max(1, len(interp.p.entry[fk])))
        known = _sink(interp, node, receiver, options.get("expiration"))
    if add:
        current = interp._adjust.get((node.start_byte, node.end_byte), (set(), set()))
        interp._adjust[(node.start_byte, node.end_byte)] = (current[0] | add, current[1])
    return known


def _js_resolver(interp):
    """Local initializers in the function (and its parents), module constants, then the
    return expression of a project helper with that name."""
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
                            return _js_returns(value) if J._is_function(value) else J._txt(value)
                        named = re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", J._txt(target))
                        if target.type == "object_pattern" and named:
                            return f"{J._txt(value)}.{name}"  # const { maxTimeoutSeconds } = requirements
                if n is scope or not J._is_function(n):
                    stack.extend(n.named_children)
        for key, fn in interp.p.functions.items():
            if key.rsplit(":", 1)[-1].rsplit(".", 1)[-1] == name:
                return _js_returns(fn.node)
        return None
    return resolve


def _js_returns(fn_node) -> str:
    """What a JS function returns: its expression body, or its return expressions with the
    locals they use inlined one level (never the rest of the body)."""
    from . import jsflow as J
    body = fn_node.child_by_field_name("body")
    if body is None:
        return ""
    if body.type != "statement_block":
        return J._txt(body)
    returns, local = [], {}
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type == "return_statement" and n.named_children:
            returns.append(J._txt(n.named_children[0]))
        elif n.type == "variable_declarator":
            target, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if target is not None and value is not None and target.type == "identifier" and not J._is_function(value):
                local.setdefault(J._txt(target), J._txt(value))
        if n is body or not J._is_function(n):
            stack.extend(n.named_children)
    return " , ".join(_inline(r, local.get, 1) for r in returns)[:_INLINE_LIMIT]


def _sink(interp, node, entry: set[str], expiry_node) -> bool:
    from . import jsflow as J
    location = interp.p.location(interp.module, node)
    built = "auth_built" in entry
    exposed = bool(entry & (UNTRUSTED | {"foreign_tx"})) or {"sim_auth", "contract_untrusted"} <= entry
    inspected = exposed and not built and _js_inspected(interp)
    blind = {"sim_auth", "contract_untrusted"} <= entry and not inspected and not built and not interp.approved
    if inspected:
        interp._control("transaction_inspection", node)
    if blind and interp.record:
        interp._cap("stellar_signing", node)
        interp._cap("foreign_tx_signing", node)
        interp._flow("foreign_signing", node, entry,
                     "an authorization tree simulated for a contract the input chooses is signed without inspecting it")
        scheme = interp.fn is not None and bool(interp.fn.cls) and interp.fn.name == "createPaymentPayload"
        interp.p.profile.add_fact("auth_tree_unchecked", location, "simulated for a contract chosen by input",
                                  **({"scheme": "x402"} if scheme else {}))
    if expiry_node is not None and interp.record:
        found = classify_expiration(J._txt(expiry_node), _js_resolver(interp))
        if found:
            interp.p.profile.add_fact("auth_expiration", location, found.note, severity=found.severity.value)
    return (inspected or built) and bool(entry & (UNTRUSTED | {"foreign_tx"}))


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
    whether the authorization tree signed here is inspected or was built by the code)."""
    from .codeflow import _dotted
    short = _dotted(node.func).rsplit(".", 1)[-1]
    add: set[str] = set()
    if short in {"append_invoke_contract_function_op", "invoke_contract_function"}:
        contract = next((k.value for k in node.keywords if k.arg == "contract_id"), node.args[0] if node.args else None)
        if contract is not None and _quiet_tags(interp, contract, state) & DIRECT:
            add.add("contract_untrusted")
    if short == "SorobanAuthorizationEntry" and _EMPTY_SUBS.search(ast.unparse(node)) \
            and not re.search(r"from_xdr\s*\(", ast.unparse(node)):
        add.add("auth_built")
    if short in _PY_SIMULATES:
        add.add("sim_auth")
    if short not in {"authorize_entry", "sign_auth_entries"}:
        return add, False
    entry = _quiet_tags(interp, node.args[0], state) if node.args else set()
    built = "auth_built" in entry
    exposed = bool(entry & UNTRUSTED) or {"sim_auth", "contract_untrusted"} <= entry
    inspected = exposed and not built and _py_inspected(interp)
    location = interp.p.location(interp.module, node)
    if inspected:
        interp._control("transaction_inspection", node)
    if interp.record and {"sim_auth", "contract_untrusted"} <= entry and not inspected and not built and not interp.approved:
        interp.p.profile.add_fact("auth_tree_unchecked", location, "simulated for a contract chosen by input")
    expiry = next((k.value for k in node.keywords if k.arg in {"valid_until_ledger_sequence", "valid_until_ledger_seq"}),
                  node.args[2] if len(node.args) > 2 else None)
    if expiry is not None and interp.record:
        found = classify_expiration(ast.unparse(expiry), _py_resolver(interp))
        if found:
            interp.p.profile.add_fact("auth_expiration", location, found.note, severity=found.severity.value)
    return add, (inspected or built) and bool(entry & UNTRUSTED)


def _py_assigns(body) -> dict[str, str]:
    out: dict[str, str] = {}
    for n in body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            out.setdefault(n.targets[0].id, ast.unparse(n.value))
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            out.setdefault(n.target.id, ast.unparse(n.value))
    return out


def _py_own_nodes(fn: ast.AST):
    """The nodes of a function body, not those of functions defined inside it."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(n))


def _py_returns(fn: ast.AST) -> str:
    """What a Python function returns, with the locals its return expressions use inlined."""
    nodes = list(_py_own_nodes(fn))
    local = _py_assigns(nodes)
    returns = [ast.unparse(n.value) for n in nodes if isinstance(n, ast.Return) and n.value is not None]
    return " , ".join(_inline(r, local.get, 1) for r in returns)[:_INLINE_LIMIT]


def _py_resolver(interp):
    """Locals of the signing function, module constants, then a helper's return expression."""
    local = _py_assigns(_py_own_nodes(interp.fn.node)) if interp.fn is not None else {}
    tree = interp.p.trees.get(interp.module)
    module = _py_assigns(tree.body) if tree is not None else {}
    functions = {f.node.name: f.node for f in interp.p.functions.values()}

    def resolve(name: str) -> str | None:
        if name in local:
            return local[name]
        if name in module:
            return module[name]
        if name in functions:
            return _py_returns(functions[name])
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


def _rust_let(ident: str):
    return re.compile(r"\blet\s+(?:mut\s+)?" + re.escape(ident) + r"\b(?:\s*:[^=;]+)?\s*=\s*([^;]+);")


def _rust_returns(code: str, after: int) -> str | None:
    """What the Rust fn whose signature ends near ``after`` returns: its `return` expressions
    and its tail expression, with the `let` locals they use inlined one level."""
    from .network_rules import _closing
    open_at = code.find("{", after)
    if open_at < 0:
        return None
    close = _closing(code, open_at, limit=8000)
    body = code[open_at + 1:close]
    returns = [m.group(1) for m in re.finditer(r"\breturn\s+([^;]+);", body)]
    depth, last = 0, 0
    for i, ch in enumerate(body):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0 and ch == "}":
                last = i + 1
        elif depth == 0 and ch == ";":
            last = i + 1
    tail = body[last:].strip()
    if tail:
        returns.append(tail)

    def local(name: str) -> str | None:
        m = _rust_let(name).search(body)
        return m.group(1) if m else None
    return " , ".join(_inline(r, local, 1) for r in returns)[:_INLINE_LIMIT] or None


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
            let = _rust_let(ident).search(code)
            if let:
                return let.group(1)
            fn = re.search(r"\bfn\s+" + re.escape(ident) + r"\s*(?:<[^>]*>)?\s*\(", code)
            return _rust_returns(code, fn.end()) if fn else None
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
