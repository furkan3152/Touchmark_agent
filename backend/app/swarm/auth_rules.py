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
from bisect import bisect_left
from dataclasses import dataclass
from hashlib import sha1

from ..models import Severity
from .codeflow import DIRECT, UNTRUSTED, unparse

#: What ast.parse raises on source it cannot read (MemoryError: "parser stack overflowed" for
#: `a{{{...`). source_index has the same tuple; jsflow imports this module, so it is not imported.
_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)
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
#: Inlined text beyond this is not expanded further, and at most this many names are looked up.
_INLINE_LIMIT, _INLINE_NAMES = 4000, 64
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
    that reads the ledger. An expression longer than _INLINE_LIMIT is not read."""
    if len(expr) > _INLINE_LIMIT:
        return None
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
    A name after a dot is replaced only when it is called (a helper method). The text never
    grows past _INLINE_LIMIT: a substitution that would pass it is skipped, and at most
    _INLINE_NAMES names are looked up."""
    seen: set[str] = set()
    text = expr
    for _ in range(depth):
        changed = False
        for name in dict.fromkeys(m.group() for m in _NAME.finditer(text)):
            if len(text) > _INLINE_LIMIT or len(seen) >= _INLINE_NAMES:
                break
            if name in seen or name in _KEEP:
                continue
            seen.add(name)
            value = resolve(name)
            if not value or len(value) > _INLINE_LIMIT or not value.strip():
                continue
            value = " ".join(value.split())
            pattern = re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])|(?<=\.)" + re.escape(name) + r"(?=\s*\()")
            uses = sum(1 for _ in pattern.finditer(text))
            if not uses or len(text) + uses * (len(value) + 2) > _INLINE_LIMIT:
                continue
            text = pattern.sub(lambda _m, v=value: f"({v})", text)
            changed = True
        if not changed:
            break
    return text


#: Calls and casts that keep a constant a constant: `Math.ceil(3600 / 5)`, `720u32`, `100n`.
_NUMERIC_WRAPPER = re.compile(r"\b(?:Math\.(?:floor|ceil|round|trunc)|Number|BigInt|int)\s*\(")
_NUMERIC_SUFFIX = re.compile(r"(?<=\d)(?:n|_?[ui](?:8|16|32|64|128|size))\b")


def _constant(text: str) -> int | None:
    """The value of an integer constant expression (`5_000`, `60 * 12`, `(720)`, `3600 / 5`),
    else None. Division keeps its fraction until the end; the result is truncated."""
    text = _NUMERIC_SUFFIX.sub("", _NUMERIC_WRAPPER.sub("(", text.strip()))
    if not text or len(text) > 60 or not re.fullmatch(r"[\d_\s*+()/%.-]+", text) or not re.search(r"\d", text):
        return None
    try:
        tree = ast.parse(text.replace("_", ""), mode="eval")
    except _PARSE_ERRORS:
        return None

    def value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            inner = value(node.operand)
            return None if inner is None else inner if isinstance(node.op, ast.UAdd) else -inner
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)):
            a, b = value(node.left), value(node.right)
            if a is None or b is None or abs(a) > 10**9 or abs(b) > 10**9:
                return None
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and b == 0:
                return None
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Sub):
                return a - b
            if isinstance(node.op, ast.Mult):
                return a * b
            if isinstance(node.op, ast.Div):
                return a / b
            return a // b if isinstance(node.op, ast.FloorDiv) else a % b
        return None
    try:
        found = value(tree.body)
    except RecursionError:
        return None
    return int(found) if found is not None else None


_OPEN, _CLOSE = "([{", ")]}"
#: Operators that bind more loosely than + and -: they end an additive expression.
_LOOSER = frozenset(",;?:|&<>=!")
#: Python and Rust words that do the same (`a + 1 if fast else a + 5000`), and Rust casts.
_WORD_OPERATOR = re.compile(r"\b(?:if|else|and|or|not|in|is|for|lambda|return|await)\b")
_CAST = re.compile(r"\s+as\s+[ui](?:8|16|32|64|128|size)\b")
#: The longest operand read as the ledger term, and the window searched back from `.saturating_add(`.
_OPERAND_LIMIT = 300


def _left_operand(text: str, end: int) -> str:
    """The operand that ends just before ``end``: names, member chains, calls and brackets
    (at most _OPERAND_LIMIT characters back)."""
    floor = max(0, end - _OPERAND_LIMIT)
    i = end
    while i > floor and text[i - 1] == " ":
        i -= 1
    stop = i
    while i > floor:
        ch = text[i - 1]
        if ch in _CLOSE:
            depth, j = 0, i - 1
            while j >= floor:
                if text[j] in _CLOSE:
                    depth += 1
                elif text[j] in _OPEN:
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < floor:
                break
            i = j
        elif ch.isalnum() or ch in "_$.":
            i -= 1
        elif ch == " " and text[max(0, i - 6):i] == "await ":
            i -= 6
        else:
            break
    return text[i:stop]


def _blank_strings(text: str) -> str:
    """String literal contents blanked, quotes kept: a `+` inside a string is not an operator."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        quote = text[i]
        if quote in "'\"`":
            j = i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _ledger_offsets(text: str) -> list[int]:
    """The offsets added to a term that reads the ledger: each additive expression (`latest +
    500`, `100 + seq`, `latest + 3600 / 5`, `latest + 1000 - 900`) whose one ledger term is
    added to constant terms gives their sum; an expression with any other non-constant term
    gives nothing. `latest_ledger.saturating_add(720)` counts too. One pass over the text."""
    text = _CAST.sub(lambda m: " " * len(m.group()), _blank_strings(text))
    text = _WORD_OPERATOR.sub(lambda m: "," + " " * (len(m.group()) - 1), text)
    out: list[int] = []
    closes: dict[int, int] = {}
    frames: list[tuple[int, list]] = [(0, [])]
    prev = ""
    for i, ch in enumerate(text):
        if ch in _OPEN:
            frames.append((i + 1, []))
        elif ch in _CLOSE:
            if len(frames) > 1:
                start, cuts = frames.pop()
                closes[start - 1] = i
                _group_offsets(text, start, i, cuts, out)
        elif ch in "+-":
            # Binary only after an operand; not ++, --, +=, -= or ->.
            if prev and (prev.isalnum() or prev in "_$)]}.'\"`") and text[i + 1:i + 2] not in (ch, "=", ">"):
                frames[-1][1].append((i, ch))
        elif ch in "*/%":
            frames[-1][1].append((i, "*"))
        elif ch in _LOOSER:
            member = ch == "?" and text[i + 1:i + 2] == "."  # optional chaining
            path = ch == ":" and ":" in (text[i - 1:i], text[i + 1:i + 2])  # Rust `u32::MAX`
            if not (member or path):
                frames[-1][1].append((i, ","))
        if not ch.isspace():
            prev = ch
    for start, cuts in frames:
        _group_offsets(text, start, len(text), cuts, out)
    for m in re.finditer(r"\.(?:saturating|checked|wrapping)_add\s*\(", text):
        close = closes.get(m.end() - 1)
        n = _constant(text[m.end():close]) if close is not None and close - m.end() <= 60 else None
        if n is not None and n > 0 and _LEDGER_TERM.search(_left_operand(text, m.start())):
            out.append(n)
    return out


def _group_offsets(text: str, start: int, end: int, cuts: list, out: list[int]) -> None:
    """_ledger_offsets for one bracket group: its segments between looser operators, each an
    additive expression of signed terms."""
    if not any(op in "+-" for _, op in cuts):
        return
    segment: list[tuple[str, int, int, bool]] = []  # (sign, start, end, holds a * / or %)
    sign, at, product = "+", start, False
    for pos, op in cuts + [(end, ",")]:
        if op == "*":
            product = True
            continue
        segment.append((sign, at, pos, product))
        sign, at, product = op, pos + 1, False
        if op == ",":
            _segment_offset(text, segment, out)
            segment, sign = [], "+"


def _segment_offset(text: str, terms: list[tuple[str, int, int, bool]], out: list[int]) -> None:
    if len(terms) < 2:
        return
    ledger, total = None, 0
    for sign, a, b, product in terms:
        if b - a > _OPERAND_LIMIT:
            return
        term = text[a:b]
        n = _constant(term)
        if n is not None:
            total += n if sign == "+" else -n
        elif sign == "+" and not product and ledger is None and _LEDGER_TERM.search(term) and term.strip():
            ledger = term
        else:
            return  # another value: the offset is not a constant
    if ledger is not None and total > 0:
        out.append(total)


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
    return expression of a project helper with that name. Each scope's declarations are
    indexed once per project, not searched again for every name."""
    from . import jsflow as J
    scopes = []
    fn = interp.fn
    while fn is not None:
        scopes.append(fn.node)
        fn = interp.p.functions.get(fn.parent) if fn.parent else None
    scopes.append(interp.module.root)
    cache = interp.p.__dict__.setdefault("_expiry_scopes", {})
    helpers = interp.p.__dict__.get("_expiry_helpers")
    if helpers is None:
        helpers = {}
        for key, f in interp.p.functions.items():
            helpers.setdefault(key.rsplit(":", 1)[-1].rsplit(".", 1)[-1], f.node)
        interp.p.__dict__["_expiry_helpers"] = helpers

    def declarations(scope) -> tuple[dict, list]:
        """(name -> initializer node, [(destructuring pattern text, value node)]) in ``scope``,
        not inside nested functions; the first one found wins, as a search would find it."""
        key = (interp.module.path, scope.start_byte, scope.end_byte)
        if key not in cache:
            names, patterns = {}, []
            stack = [scope]
            while stack:
                n = stack.pop()
                if n.type == "variable_declarator":
                    target, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                    if target is not None and value is not None:
                        if target.type == "identifier":
                            names.setdefault(J._txt(target), value)
                        elif target.type == "object_pattern":
                            patterns.append((J._txt(target), value))
                if n is scope or not J._is_function(n):
                    stack.extend(n.named_children)
            cache[key] = (names, patterns)
        return cache[key]

    def resolve(name: str) -> str | None:
        for scope in scopes:
            names, patterns = declarations(scope)
            value = names.get(name)
            if value is not None:
                return _js_returns(value) if J._is_function(value) else J._txt(value)
            for target, value in patterns:
                if re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", target):
                    return f"{J._txt(value)}.{name}"  # const { maxTimeoutSeconds } = requirements
        helper = helpers.get(name)
        return _js_returns(helper) if helper is not None else None
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
    if short == "SorobanAuthorizationEntry":
        text = _py_text(interp, node)
        if _EMPTY_SUBS.search(text) and not re.search(r"from_xdr\s*\(", text):
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
        found = classify_expiration(_py_text(interp, expiry), _py_resolver(interp))
        if found:
            interp.p.profile.add_fact("auth_expiration", location, found.note, severity=found.severity.value)
    return add, (inspected or built) and bool(entry & UNTRUSTED)


def _py_text(interp, node: ast.AST) -> str:
    """A node's code: unparsed, or (when it is too deep to unparse) sliced from the file."""
    text = unparse(node)
    if not text:
        path = interp.p.module_of.get(interp.module)
        text = ast.get_source_segment(interp.p.files.get(path, ""), node) or "" if path else ""
    return text


def _py_assigns(body) -> dict[str, str]:
    out: dict[str, str] = {}
    for n in body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            out.setdefault(n.targets[0].id, unparse(n.value))
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            out.setdefault(n.target.id, unparse(n.value))
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
    returns = [unparse(n.value) for n in nodes if isinstance(n, ast.Return) and n.value is not None]
    return " , ".join(_inline(r, local.get, 1) for r in returns)[:_INLINE_LIMIT]


def _py_resolver(interp):
    """Locals of the signing function, module constants, then a helper's return expression.
    Module constants are unparsed only when a name asks for them."""
    local = _py_assigns(_py_own_nodes(interp.fn.node)) if interp.fn is not None else {}
    tree = interp.p.trees.get(interp.module)
    cache = interp.p.__dict__.setdefault("_expiry_modules", {})
    if id(tree) not in cache:
        nodes: dict[str, ast.AST] = {}
        for n in tree.body if tree is not None else []:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                nodes.setdefault(n.targets[0].id, n.value)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                nodes.setdefault(n.target.id, n.value)
        cache[id(tree)] = (tree, nodes)
    module = cache[id(tree)][1]
    functions = interp.p.__dict__.get("_expiry_py_helpers")
    if functions is None:
        functions = {f.node.name: f.node for f in interp.p.functions.values()}
        interp.p.__dict__["_expiry_py_helpers"] = functions

    def resolve(name: str) -> str | None:
        if name in local:
            return local[name]
        if name in module:
            return unparse(module[name])
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
#: Where a SEP-10 challenge comes from: the stellar.toml WEB_AUTH_ENDPOINT (a name or the key),
#: or a literal `/auth?account=` URL. An `account` query on any other URL is not one.
_SEP10_SOURCE = re.compile(r"WEB_AUTH_ENDPOINT|[Ww]eb_?[Aa]uth_?[Ee]ndpoint|/auth\b[^\s\"'`]{0,80}[?&]account=")
_PARSE_TX = re.compile(r"\bnew\s+(?:[\w$]+\.)?Transaction\s*\(|\bTransactionBuilder\.fromXDR\s*\(|\bTransaction\.fromXDR\s*\(|"
                       r"\bTransactionEnvelope\.from_xdr\s*\(|\bparse_transaction_envelope_from_xdr\s*\(|"
                       r"\bTransactionBuilder\.from_xdr\s*\(")
#: The SDK readers that check a challenge, or the checks themselves (sequence 0 and the
#: `<home domain> auth` ManageData operation).
_SEP10_READ = re.compile(r"readChallengeTx|read_challenge_transaction|verifyChallengeTx|verify_challenge_transaction")
_SEP10_SEQUENCE = re.compile(r"""sequence\s*(?:!==?|===?|!=|==)\s*["']?0\b|\bsequence\b[^\n]{0,40}\bnot\s+0\b""")
_SEP10_OPERATION = re.compile(r"""manageData|manage_data|MANAGE_DATA""")
#: SEP-45: the contract web-auth endpoint, and the response field that carries the entries.
_SEP45_SOURCE = re.compile(r"WEB_AUTH_FOR_CONTRACTS_ENDPOINT|webAuthForContracts\w*|web_auth_for_contracts\w*", re.I)
_SEP45_FIELD = re.compile(r"authorization_?[Ee]ntries")
_SEP45_SIGN = re.compile(r"\bauthorizeEntry\s*\(|\bauthorize_entry\s*\(|\bsignAuthEntry\s*\(")
_SEP45_CHECKS = (re.compile(r"web_auth_verify"), re.compile(r"WEB_AUTH_CONTRACT_ID|webAuthContractId|web_auth_contract_id", re.I),
                 re.compile(r"subInvocations|sub_invocations"))
#: An HTTP request: its response can carry SEP-45 entries.
_HTTP = re.compile(r"\b(?:fetch\w*|axios|got|ky|request|httpx|requests|aiohttp|session|client)\b\s*(?:\.\s*(?:get|post|request)\b)?\s*\(")
#: A file about web authentication at all (SEP-10 or SEP-45).
_WEB_AUTH_FILE = re.compile(r"WEB_AUTH|web_?auth|webAuth|\bsep-?(?:10|45)\b|\bSEP(?:10|45)\b", re.I)
#: Interop, round-trip and smoke harnesses: a level lower.
_HARNESS = re.compile(r"(?:^|/)(?:interop|tests?|__tests__|e2e)/|roundtrip|round_trip|smoke|\.test\.|\.spec\.|_test\.py$", re.I)


#: web_auth_hits per code tree (digest of the files): an audit asks more than once.
_WEB_AUTH_CACHE: dict[str, list] = {}


def web_auth_hits(files: dict[str, str]) -> list[tuple[str, str, int, str, Severity, str]]:
    """(kind, file, line, text, severity, note) for SEP-10 challenges and SEP-45 entries signed
    without the checks the SEPs require of the client. The signed value must come from the
    web-auth response by data flow inside the signing function (through locals, loops and
    callbacks); SEP-45 entries also count when that function itself makes the request. Kind
    "incomplete" names a file whose flow was not fully read (the note says which SEPs)."""
    files = {n: t for n, t in files.items() if n.endswith(_JS_PY)}
    key = sha1("\0".join(f"{k}\0{v}" for k, v in sorted(files.items())).encode("utf-8", "replace")).hexdigest()
    if key not in _WEB_AUTH_CACHE:
        if len(_WEB_AUTH_CACHE) > 16:
            _WEB_AUTH_CACHE.clear()
        _WEB_AUTH_CACHE[key] = _web_auth_hits(files)
    return list(_WEB_AUTH_CACHE[key])


def _web_auth_hits(files: dict[str, str]) -> list[tuple[str, str, int, str, Severity, str]]:
    from .network_rules import _sources
    hits = []
    for src in _sources(files):
        code = src.code
        if not _WEB_AUTH_FILE.search(code):
            continue
        severity = Severity.HIGH.downgrade(1) if _HARNESS.search(src.name) else Severity.HIGH
        sep10 = _SEP10_SOURCE.search(code) and not _SEP10_READ.search(code) \
            and not (_SEP10_SEQUENCE.search(code) and _SEP10_OPERATION.search(code) and re.search(r"""\bauth["'`]""", code))
        sep45 = _SEP45_SOURCE.search(code) or (_SEP45_FIELD.search(code) and _HTTP.search(code))
        if not (sep10 or sep45):
            continue
        flows = _py_web_auth(src) if src.python else _js_web_auth(src)
        if sep10 and flows["sep10"] is not None:
            line = src.line(flows["sep10"])
            hits.append(("sep10", src.name, line, src.line_text(line).strip(), severity,
                         "the challenge is parsed and signed without checking its sequence number and operations"))
        missing = [p.pattern.split("|")[0] for p in _SEP45_CHECKS if not p.search(code)]
        if sep45 and missing and flows["sep45"] is not None:
            line = src.line(flows["sep45"])
            hits.append(("sep45", src.name, line, src.line_text(line).strip(), severity, "nothing checks " + ", ".join(missing)))
        # A kind left unread and unreported is a gap, not a clean result.
        unread = [k.upper().replace("SEP", "SEP-") for k in sorted(flows.get("incomplete", ()))
                  if flows[k] is None and (sep10 if k == "sep10" else sep45 and missing)]
        if unread:
            hits.append(("incomplete", src.name, 1, "", Severity.LOW, " and ".join(unread)))
    return hits


#: An identifier that is not a property (`x` in `x.y`, not `y`).
_IDENT = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")


def _ids(text: str) -> set[str]:
    """The identifiers a piece of code reads: tested against a name set, so a growing taint
    never builds a pattern."""
    return set(_IDENT.findall(text))


#: JS bindings: `const x =`, `const { a, b } =`, `x =`; `for (const x of ...)`; `xs.map((x) =>`.
_JS_BIND = re.compile(r"(?:\b(?:const|let|var)\s+(?P<pat>[\w$]+|\{[^}]{0,400}\}|\[[^\]]{0,400}\])|(?<![\w$.])(?P<bare>[\w$]+))"
                      r"\s*(?::[^=;\n]{0,200})?=(?![=>])\s*")
#: network_rules._statement's window: a statement that reaches it was never closed.
_STATEMENT_WINDOW = 1200
_JS_LOOP = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+(?P<pat>[\w$]+|\{[^}]{0,400}\}|\[[^\]]{0,400}\])\s+of\b")
_JS_EACH = re.compile(r"(?P<iter>[\w$.]+)\s*\.\s*(?:map|forEach|flatMap|filter|some|every|reduce|find)\s*\(\s*(?:async\s*)?\(?\s*"
                      r"(?P<pat>[\w$]+)")
_ITERATING = re.compile(r"\.\s*(?:map|forEach|flatMap|filter|some|every|reduce|find|then)\s*\(\s*(?:async\s*)?$|"
                        r"\bPromise\.all\w*\s*\(\s*$")


def _flow_scope(src, pos: int) -> tuple[int, int]:
    """The function whose locals a value at ``pos`` can come from: the innermost function, or
    the one that holds it when it is a callback of map, forEach, then and the like."""
    scope = src.function_at(pos)
    while scope is not None:
        start = _function_start(src, scope[0])
        if start is None or not _ITERATING.search(src.skel, max(0, start - 80), start):
            break
        outer = src.function_at(start)
        if outer is None:
            break
        scope = outer
    return scope if scope is not None else (0, len(src.code))


def _function_start(src, brace: int) -> int | None:
    """Where the function whose body opens at ``brace`` starts: its parameter list (or single
    parameter) for an arrow, its `function` keyword otherwise."""
    base = max(0, brace - 300)
    head = src.skel[base:brace].rstrip()
    if head.endswith("=>"):
        before = head[:-2].rstrip()
        if before.endswith(")"):
            return src.pairs().get(base + len(before) - 1)
        name = re.search(r"[\w$]+$", before)
        return base + name.start() if name else None
    if head.endswith(")"):
        opening = src.pairs().get(base + len(head) - 1)
        keyword = re.search(r"\bfunction\b\s*\*?\s*[\w$]*\s*$", src.skel[max(0, opening - 60):opening]) if opening else None
        return max(0, opening - 60) + keyword.start() if keyword else None
    return None


def _js_bound(pattern: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_$][\w$]*", re.sub(r"\s*:\s*[\w$]+(?=\s*[,}])", "", pattern))) if pattern[:1] in "{[" \
        else {pattern}


def _js_events(src) -> list[tuple]:
    """(offset, kind, names bound, identifiers read, text read, parses a transaction) for every
    binding of a JS file in source order, read once per file and shared by every function's flow."""
    found = src.memo.get("web_auth_events")
    if found is None:
        from .network_rules import _statement
        code, found = src.code, []
        binds = list(_JS_BIND.finditer(code))
        for k, m in enumerate(binds):
            stop, _marks = _statement(src, m.end())
            if stop >= m.end() + _STATEMENT_WINDOW and k + 1 < len(binds):
                # Never closed within the window (`x=[x=[...`): it reads only up to the next binding,
                # or every such binding would read the whole window.
                stop = min(stop, max(m.end(), binds[k + 1].start()))
            found.append((m.start(), "bind", _js_bound(m.group("pat") or m.group("bare")), code[m.end():stop]))
        for m in _JS_LOOP.finditer(code):
            close = src.pairs().get(code.find("(", m.start()), m.end())
            found.append((m.start(), "loop", _js_bound(m.group("pat")), code[m.end():close]))
        for m in _JS_EACH.finditer(code):
            found.append((m.start(), "each", {m.group("pat")}, m.group("iter")))
        found = sorted(((pos, kind, names, _ids(expr), expr, kind == "bind" and bool(_PARSE_TX.search(expr)))
                        for pos, kind, names, expr in found), key=lambda e: e[0])
        src.memo["web_auth_events"] = found
    return found


#: A scope with at most this many relevant bindings is always read (real signing functions
#: read a few dozen): no padding before a login can starve it, and what such scopes cost is
#: bounded by the file's signing calls.
_SCOPE_FREE = 64
#: Binding visits one file's web-auth taint may spend on larger scopes (each scope reads its
#: relevant bindings twice), on top of a few reads of every relevant binding. Nested scopes
#: re-read their inner ones; the budget keeps a file of thousands of them linear. A scope that
#: does not fit is not read, later ones still are, and the file's analysis is incomplete (a
#: blocking gap, never a silent "untainted").
_TAINT_BUDGET = 1_000_000
_TAINT_READS = 8


class _Taint:
    """One file's web-auth taint for one source pattern: which bindings the pattern matches
    (searched once per binding, not once per scope), and the bindings that can take part in
    any scope's taint at all, found by one worklist pass over the whole file from every seed a
    scope can have. A binding outside that set never fires in a scope (a scope's taint is a
    subset of the file's), so a scope reads only the relevant bindings in its range."""

    def __init__(self, src, source: re.Pattern, seeds: set[str]):
        events = _js_events(src)
        self.events = events
        self.matched = [bool(source.search(e[4])) for e in events]
        readers: dict[str, list[int]] = {}
        for i, e in enumerate(events):
            for name in e[3]:
                readers.setdefault(name, []).append(i)
        fired = [False] * len(events)
        tainted, todo = set(seeds), list(seeds)

        def fire(i: int) -> None:
            fired[i] = True
            for name in events[i][2]:
                if name not in tainted:
                    tainted.add(name)
                    todo.append(name)
        for i, hit in enumerate(self.matched):
            if hit and not fired[i]:
                fire(i)
        while todo:
            for i in readers.get(todo.pop(), ()):
                if not fired[i]:
                    fire(i)
        self.relevant = [i for i, f in enumerate(fired) if f]
        self.offsets = [events[i][0] for i in self.relevant]
        # What any scope's taint can hold at most: a name no scope can bind needs no scope read.
        self.bound = {n for i in self.relevant for n in events[i][2]}
        self.parses = {n for i in self.relevant if events[i][5] for n in events[i][2]}
        self.budget, self.spent, self.incomplete = _TAINT_BUDGET + _TAINT_READS * len(self.relevant), 0, False

    def scope(self, start: int, end: int, seeds: set[str], module: bool = False, src=None) -> tuple[set[str], set[str]]:
        """(names derived from the seeds or the source, those bound to a parsed transaction) in
        code[start:end], in source order (two passes for loops). With ``module``, only
        bindings outside every function count. A large scope over the budget is not read and
        marks the analysis incomplete."""
        lo, hi = bisect_left(self.offsets, start), bisect_left(self.offsets, end)
        tainted, parsed = set(seeds), set()
        if not module and hi - lo > _SCOPE_FREE and self.spent + 2 * (hi - lo) > self.budget:
            self.incomplete = True
            return tainted, parsed
        self.spent += 2 * (hi - lo)
        steps = [i for i in self.relevant[lo:hi] if not module or src.function_at(self.events[i][0]) is None]
        for _ in range(2):
            for i in steps:
                _pos, _kind, names, read, _expr, parses = self.events[i]
                if self.matched[i] or not read.isdisjoint(tainted):
                    tainted |= names
                    if parses:
                        parsed |= names
        return tainted, parsed


def _js_web_auth(src) -> dict:
    """Offsets of a SEP-10 challenge signed from the web-auth response, and of SEP-45 entries
    signed from the contract web-auth response, in a JS or TS file; under "incomplete", the
    kinds whose taint left a scope unread. A signing call whose names no scope can derive
    reads no scope."""
    found: dict = {"sep10": None, "sep45": None, "incomplete": set()}
    code, cache, requests = src.code, {}, {}
    # Module-level values first: `const ENDPOINT = toml.WEB_AUTH_FOR_CONTRACTS_ENDPOINT`.
    taint10 = _Taint(src, _SEP10_SOURCE, set()) if _SEP10_SOURCE.search(code) else None
    top10 = taint10.scope(0, len(code), set(), module=True, src=src)[0] if taint10 else set()
    # Every seed a SEP-45 scope can have: the module-level values and the parameters named
    # for the entries (`authorizationEntries`), wherever they are declared.
    params45 = set(re.findall(r"[\w$]*" + _SEP45_FIELD.pattern + r"[\w$]*", code))
    top45 = set()
    if _SEP45_SOURCE.search(code):
        top45 = _Taint(src, _SEP45_SOURCE, set()).scope(0, len(code), set(), module=True, src=src)[0]
    taint45 = None

    def flow(scope, kind):
        nonlocal taint10, taint45
        key = (scope, kind)
        if key not in cache:
            head = code[max(0, scope[0] - 300):scope[0]]
            if kind == "sep10":
                taint10 = taint10 or _Taint(src, _SEP10_SOURCE, top10)
                cache[key] = taint10.scope(scope[0], scope[1], top10)
            else:
                taint45 = taint45 or _Taint(src, _SEP45_SOURCE, top45 | params45)
                params = set(re.findall(r"[\w$]*" + _SEP45_FIELD.pattern + r"[\w$]*", head))
                cache[key] = taint45.scope(scope[0], scope[1], top45 | params)
        return cache[key]
    for m in re.finditer(r"(?<![\w$.])(?P<recv>[\w$]+)\s*\.\s*sign\s*\(", code):
        taint10 = taint10 or _Taint(src, _SEP10_SOURCE, top10)
        if m.group("recv") in taint10.parses and m.group("recv") in flow(_flow_scope(src, m.start()), "sep10")[1]:
            found["sep10"] = m.start()
            break
    asks, reach45 = None, None
    for m in _SEP45_SIGN.finditer(code):
        scope = _flow_scope(src, m.start())
        if reach45 is None:
            taint45 = taint45 or _Taint(src, _SEP45_SOURCE, top45 | params45)
            reach45 = taint45.bound | top45 | params45
        signed = _ids(code[m.end():src.pairs().get(m.end() - 1, m.end())])
        if scope not in requests:  # the function itself asks the contract web-auth endpoint for entries
            if asks is None:  # where the endpoint (or a module value holding it) and the field occur: once per file
                asks = ([m.start() for m in _SEP45_SOURCE.finditer(code)] +
                        [m.start() for m in _IDENT.finditer(code) if m.group() in top45],
                        [m.start() for m in _SEP45_FIELD.finditer(code)])
                asks = (sorted(asks[0]), asks[1])
            requests[scope] = _occurs(asks[0], scope[0], scope[1]) and _occurs(asks[1], scope[0], scope[1])
        if requests[scope] or (not signed.isdisjoint(reach45) and not signed.isdisjoint(flow(scope, "sep45")[0])):
            found["sep45"] = m.start()
            break
    found["incomplete"] = {kind for kind, taint in (("sep10", taint10), ("sep45", taint45)) if taint and taint.incomplete}
    return found


def _occurs(offsets: list[int], start: int, end: int) -> bool:
    """Some offset of a sorted list falls in [start, end)."""
    i = bisect_left(offsets, start)
    return i < len(offsets) and offsets[i] < end


def _py_web_auth(src) -> dict[str, int | None]:
    """The same for a Python file, on its syntax tree: functions in source order, bindings by
    assignment, `for` targets and comprehension targets."""
    found: dict[str, int | None] = {"sep10": None, "sep45": None}
    try:
        tree = ast.parse(src.text)
    except _PARSE_ERRORS:
        return found

    def text_of(node) -> str:
        return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)) + " " + \
            " ".join(n.id if isinstance(n, ast.Name) else n.attr for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute)))

    def names_in(node) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def bindings(scope):
        """(targets, value) in source order, not inside nested functions."""
        out = []
        stack = list(ast.iter_child_nodes(scope))
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                out.append((n, {x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)}, n.value))
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                out.append((n, {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}, n.iter))
            elif isinstance(n, ast.comprehension):
                out.append((n.iter, {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}, n.iter))
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                stack.extend(ast.iter_child_nodes(n))
        return sorted(out, key=lambda b: (getattr(b[0], "lineno", 0), getattr(b[0], "col_offset", 0)))

    def called(func) -> str:
        """`a.b.c` -> `b.c`: enough for the parsers' names, without unparsing a long chain."""
        if isinstance(func, ast.Attribute):
            base = func.value.attr if isinstance(func.value, ast.Attribute) else getattr(func.value, "id", "")
            return f"{base}.{func.attr}"
        return getattr(func, "id", "")

    prepared: dict = {}

    def steps_of(scope) -> list[tuple[set[str], set[str], str, bool]]:
        """(targets, names read, text, parses a transaction) per binding, once per scope."""
        if scope not in prepared:
            prepared[scope] = [(targets, names_in(value), text_of(value),
                                any(isinstance(c, ast.Call) and _PARSE_TX.search(called(c.func) + "(") for c in ast.walk(value)))
                               for _node, targets, value in bindings(scope)]
        return prepared[scope]

    def taint(scope, seeds: set[str], source: re.Pattern) -> tuple[set[str], set[str]]:
        tainted, parsed = set(seeds), set()
        steps = steps_of(scope)
        hits = [bool(source.search(text)) for _targets, _names, text, _parses in steps]
        for _ in range(2):
            for (targets, names, _text, parses), hit in zip(steps, hits):
                if hit or names & tainted:
                    tainted |= targets
                    if parses:
                        parsed |= targets
        return tainted, parsed
    top10, _ = taint(tree, set(), _SEP10_SOURCE)
    top45, _ = taint(tree, set(), _SEP45_SOURCE)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in [*fn.args.args, *fn.args.kwonlyargs] if _SEP45_FIELD.search(a.arg)}
        t10, parsed = taint(fn, top10, _SEP10_SOURCE)
        t45, _ = taint(fn, top45 | params, _SEP45_SOURCE)
        requested = any(_SEP45_SOURCE.search(text_of(n)) or names_in(n) & top45 for n in fn.body)
        for call in _py_own_calls(fn):
            name = unparse(call.func)
            if found["sep10"] is None and isinstance(call.func, ast.Attribute) and call.func.attr == "sign" and \
                    isinstance(call.func.value, ast.Name) and call.func.value.id in parsed:
                found["sep10"] = src.line_start(call.lineno)
            if found["sep45"] is None and name.rsplit(".", 1)[-1] in {"authorize_entry", "sign_auth_entry"} and (
                    any(names_in(a) & t45 for a in [*call.args, *(k.value for k in call.keywords)])
                    or (requested and any(_SEP45_FIELD.search(text_of(n)) for n in fn.body))):
                found["sep45"] = src.line_start(call.lineno)
    return found


def _py_own_calls(fn):
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call):
            yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(n))
