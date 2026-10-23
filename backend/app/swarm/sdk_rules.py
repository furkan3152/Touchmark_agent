"""Stellar SDK semantics the code gets wrong: RPC results read as final, enums compared
with strings, fields a release does not have, removed symbols, and failures handled as if
nothing was sent.

Soroban RPC's sendTransaction only queues a transaction (PENDING); the outcome is read with
getTransaction or pollTransaction. Code that treats the send result as the outcome, compares
the Python SDK's Enum status with a string, reads a field the installed release lacks, or
releases a spending reservation when a call fails after the transaction was broadcast,
reports the wrong state of money that moved or did not. Each check is syntactic and names
the SDK release it was judged against (stellar/sdk_semantics.py).
"""

from __future__ import annotations

import ast
import posixpath
import re
from bisect import bisect_left, bisect_right

from ..models import AgentArtifact, EvidenceGrade, Finding, Severity
from ..services.lockfiles import Lockset, below, spec_admits
from ..stellar import sdk_semantics as sdk
from .consolidate import stable_id
from .jsflow import _args, _dotted, _props, _string_value, _txt, _unwrap
from .source_index import (TEST_PATH, JsFile, PyFile, SourceIndex, callee_name, drop, index_for,
                           js_function_name, js_functions_type, receiver, unparse)

#: Names of calls that free what a payment had reserved, and the things they free.
_RELEASE = re.compile(r"release|unlock|refund|rollback|roll_back|decrement|free|unreserve|revert|undo|cancel", re.I)
_RESERVED = re.compile(r"reserv|claim|budget|spend|escrow|hold|allowance|quota|credit|limit|pending|window", re.I)
#: Words that say an outcome is final.
_FINAL_WORDS = re.compile(r"confirm|success|succeed|settled|complete|paid|anchored|registered|on-?chain|landed|finali[sz]", re.I)
_TENTATIVE_WORDS = re.compile(r"pending|submit\w*|queued|sent\b|sending|broadcast\w*|in.?flight|not\s+yet|wait\w*|poll\w*", re.I)
#: What, just before a final word, makes it an instruction, a condition or a negation rather
#: than a claim: "to confirm", "failed to complete", "not successful", "check whether settled".
_NOT_A_CLAIM = re.compile(r"(?:\b(?:to|not|never|no|unable|cannot|until|whether|once|if|check|verify)|n't|\bfail\w*)"
                          r"\s+(?:[\w-]+\s+)?$", re.I)
#: Consumers of a hash that record or act on the payment as done.
_SETTLE_CALL = re.compile(r"^(?:mark\w*|settle\w*|fulfil\w*|deliver\w*|grant\w*|unlock\w*|credit\w*|record\w*|save\w*|"
                          r"store\w*|persist\w*|insert\w*|upsert\w*|anchor\w*|register\w*|complete\w*|confirm\w*|"
                          r"finali[sz]e\w*|set\w*(?:Hash|Paid|Status))$", re.I)
_PAYMENT_WORDS = re.compile(r"paid|settle|payment|deliver|grant|unlock|fulfil|access|credit|purchase|order|invoice", re.I)
_DB_WRITE = re.compile(r"(?:^|\.)(?:db|prisma|repo|store|knex|supabase|sql|model|collection|table|redis|cache|kv)\b.*"
                       r"\.(?:insert|update|set|values|create|upsert|save|put|hset|add)$", re.I)
_LOGGER = re.compile(r"^console\.\w+$|(?:^|\.)(?:log|logger|logging|winston|pino)\.(?:debug|info|warn|warning|error|log|trace|success)$")
_RESPONDER = re.compile(r"^(?:res|response|reply|c|ctx|h)\.(?:\w+\.)*(?:json|send|end|write|text)$|^NextResponse\.json$|^Response\.json$")
_TRANSPARENT = {"stringify", "String", "assign", "freeze", "toString"}
#: A wrapper around the send that is not in the project but, by its name, waits for the outcome.
_WAITS = re.compile(r"wait|confirm|poll", re.I)
#: Calls that register a callback with a framework (a tool, a route, an event): what the callback
#: returns is the outcome its caller is told. Other callees (map, then, Promise.all, retry) hand
#: it back to the enclosing function.
_REGISTERS = re.compile(r"^(?:tool|registerTool|addTool|get|post|put|patch|delete|all|use|on|once|handle|handler|route|"
                        r"action|command|middleware|setRequestHandler|addListener|subscribe|register\w*|define\w*)$")
#: Names that make a status test a success verdict, and names of a "polling finished" flag.
_SUCCESS_NAME = re.compile(r"(?i:succe|paid|confirm|settled|valid|applied)|^(?i:ok)(?![a-z])|(?<![A-Z])O[Kk](?![a-z])")
_POLL_FLAG = re.compile(r"done|finish|complete|final|resolved|ready|stop", re.I)
_PAYMENT_HEADER = re.compile(r"^(?:payment-signature|x-payment|x-payment-signature|x-payment-tx)$", re.I)
_PAYING_FETCH = re.compile(r"^wrap(?:Fetch|Axios)WithPayment\w*$")
_STELLAR_CLI = re.compile(r"\b(?:stellar|soroban)\s+(?:contract\s+invoke|tx\s+send)\b")
_BOUNDS = re.compile(r"\.(?:set_timeout|add_time_bounds|set_ledger_bounds)\(|\btime_bounds\s*=")
#: Python operation builders (TransactionBuilder.append_*_op and the operation classes).
_PY_OP_BUILDER = re.compile(r"^append_\w+_op$|^(?:Payment|ChangeTrust|PathPaymentStrict(?:Send|Receive)|CreateAccount|"
                            r"ManageSellOffer|ManageBuyOffer|CreatePassiveSellOffer|CreateClaimableBalance|Clawback|"
                            r"LiquidityPool(?:Deposit|Withdraw))$")
#: Calls that turn a BigInt into something JSON.stringify accepts.
_TO_JSON_SAFE = frozenset({"String", "Number", "toString", "toFixed", "toLocaleString", "parseInt", "parseFloat"})
#: Operation builders whose amount and limit fields are decimal strings checked against int64.
_OP_BUILDERS = frozenset({"payment", "changeTrust", "pathPaymentStrictSend", "pathPaymentStrictReceive", "createAccount",
                          "createClaimableBalance", "manageSellOffer", "manageBuyOffer", "createPassiveSellOffer",
                          "clawback", "liquidityPoolDeposit", "liquidityPoolWithdraw"})
_AMOUNT_KEYS = frozenset({"amount", "limit", "startingBalance", "starting_balance", "sendAmount", "send_amount", "destAmount",
                          "dest_amount", "sendMax", "send_max", "destMin", "dest_min"})
_STATEMENTS = frozenset({"expression_statement", "lexical_declaration", "variable_declaration", "if_statement",
                         "for_statement", "for_in_statement", "while_statement", "do_statement", "throw_statement",
                         "switch_statement", "statement_block"})


def _decimal_over_max(value: str) -> bool:
    m = re.fullmatch(r"\s*(\d+)(?:\.(\d+))?\s*", value or "")
    if not m:
        return False
    whole, frac = int(m.group(1)), (m.group(2) or "").ljust(7, "0")
    return whole * 10**7 + int(frac[:7]) > sdk.MAX_STROOPS


class _Context:
    """Per-audit state: the parsed sources and the SDK versions installed near a file."""

    def __init__(self, artifact: AgentArtifact):
        self.index: SourceIndex = index_for(artifact.code_files)
        self.locks = Lockset(artifact.raw_metadata.get("resolved_versions"))

    def version(self, package: str, near: str) -> tuple[str | None, str | None, str]:
        """(exact version or None, declared range, how it reads in evidence)."""
        found = self.locks.resolve(package, near=near)
        if found is None:
            return None, None, f"{package} version not resolved"
        exact = found.versions[0] if len(set(found.versions)) == 1 else None
        shown = (f"{package} {', '.join(sorted(set(found.versions)))}" + (f" ({found.source})" if found.source else "")
                 if found.versions else f"{package} {found.spec} (no lockfile)")
        return exact, found.spec, shown


def _skip(path: str) -> bool:
    return bool(TEST_PATH.search(path))


# =========================================================================== Python
def _py_walk(fn):
    """Nodes of a function body, not descending into nested functions or classes."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _py_scopes(py: PyFile):
    yield py.tree
    for node in ast.walk(py.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _py_name(func) -> str:
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _py_call(node) -> ast.Call | None:
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def _py_rpc_receivers(py: PyFile) -> set[str]:
    names = set()
    for node in ast.walk(py.tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            call = _py_call(node.value) if node.value is not None else None
            if call is not None and _py_name(call.func) in sdk.PY_RPC_CLASSES:
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    names.add(unparse(target))
        elif isinstance(node, ast.arg) and node.annotation is not None and \
                any(c in unparse(node.annotation) for c in sdk.PY_RPC_CLASSES):
            names.add(node.arg)
    return names


def _py_is_rpc(call: ast.Call, receivers: set[str], sdk_server: bool) -> bool:
    """A stellar_sdk SorobanServer receiver: built or typed as one, or (in a module that imports
    the class, in a project that defines no method of that name) named like one."""
    if not isinstance(call.func, ast.Attribute):
        return False
    text = unparse(call.func.value)
    if re.search(r"horizon|\beth\b|web3", text, re.I):
        return False
    return text in receivers or (sdk_server and bool(re.search(r"soroban|rpc", text, re.I)))


class _PyRules:
    def __init__(self, ctx: _Context):
        self.ctx = ctx
        self._submits: dict[int, tuple[bool, int]] = {}  # verdict, depth judged at (_judged)
        self._frames: dict[str, dict[int, tuple]] = {}
        self._locals: dict[int, dict] = {}
        self._names: dict[str, dict[str, tuple]] = {}
        self._lookups: dict[tuple, tuple | None] = {}
        self._modules: dict[str, list] | None = None
        self._methods: dict[tuple, list] = {}
        self._members: dict[int, dict[str, list]] = {}
        self._raisers: dict[int, list] | None = None
        self._commands: dict[int, dict[str, list[str]]] = {}
        self._strings: dict[int, list[str]] = {}

    # -------------------------------------------------- K2: enum compared with str, missing field
    def misread(self, py: PyFile) -> list[tuple[str, int, str, bool]]:
        """(kind of misread, line, code, on a send/poll path)."""
        receivers, sdk_server = _py_rpc_receivers(py), self._sdk_server(py)
        exact, spec, _ = self.ctx.version("stellar-sdk", py.path)
        out = []
        seen: set[int] = set()
        for fn in _py_scopes(py):
            # Each use takes the kind of the nearest assignment above it, so one name reused for a
            # contract-data read in one branch and a poll result in another is read correctly.
            assigned: dict[str, list[tuple[tuple[int, int], str | None]]] = {}
            for node in _py_walk(fn):
                if isinstance(node, ast.Assign):
                    call = _py_call(node.value)
                    kind = sdk.PY_RPC_RESULT.get(_py_name(call.func)) if call is not None else None
                    kind = kind if kind and _py_is_rpc(call, receivers, sdk_server) else None
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned.setdefault(target.id, []).append(((node.lineno, node.col_offset), kind))
            if not any(kind for places in assigned.values() for _, kind in places):
                continue

            def kind_of(name: str, at) -> str | None:
                before = [kind for pos, kind in sorted(assigned.get(name, [])) if pos < (at.lineno, at.col_offset)]
                return before[-1] if before else None

            moves = any(isinstance(n, ast.Call) and _py_name(n.func) in {"sign", "send_transaction"} for n in _py_walk(fn))
            for node in _py_walk(fn):
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name):
                    kind = kind_of(node.value.id, node)
                    if kind and sdk.py_field_missing(kind, node.attr, spec, exact) and node.lineno not in seen:
                        seen.add(node.lineno)
                        out.append(("field", node.lineno, py.snippet(node), moves and kind != "simulate"))
                elif isinstance(node, ast.Compare) and len(node.ops) == 1 and \
                        isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
                    sides = [node.left, node.comparators[0]]
                    for status, other_side in (sides, sides[::-1]):
                        if (isinstance(status, ast.Attribute) and status.attr == "status" and isinstance(status.value, ast.Name)
                                and kind_of(status.value.id, status) in sdk.PY_ENUM_FIELDS
                                and _py_strings_only(other_side) and node.lineno not in seen):
                            seen.add(node.lineno)
                            out.append(("compare", node.lineno, py.snippet(node), moves))
                            break
        return sorted(out, key=lambda m: m[1])

    def _sdk_server(self, py: PyFile) -> bool:
        """The module imports the SDK's Soroban server and the project defines none of its methods."""
        imports = any(isinstance(n, ast.ImportFrom) and (n.module or "").startswith("stellar_sdk")
                      and any(a.name in sdk.PY_RPC_CLASSES for a in n.names) for n in ast.walk(py.tree))
        own = any(name in self.ctx.index.py_defs for name in (*sdk.PY_RPC_RESULT, *sdk.PY_DURABILITY_METHODS))
        return imports and not own

    # -------------------------------------------------- K7: durability passed as a string
    def durability(self, py: PyFile) -> list[tuple[int, str]]:
        receivers, sdk_server = _py_rpc_receivers(py), self._sdk_server(py)
        out = []
        for fn in _py_scopes(py):
            for node in _py_walk(fn):
                if not (isinstance(node, ast.Call) and _py_name(node.func) in sdk.PY_DURABILITY_METHODS
                        and _py_is_rpc(node, receivers, sdk_server)):
                    continue
                arg = next((k.value for k in node.keywords if k.arg == "durability"), None)
                if arg is None and len(node.args) > 2:
                    arg = node.args[2]
                origin = _py_string_origin(arg, fn) if arg is not None else None
                if origin:
                    out.append((node.lineno, f"{py.snippet(node)} (durability {origin})"))
        return out

    # -------------------------------------------------- K9: built and signed with no time bounds
    def no_expiry(self, py: PyFile) -> list[tuple[int, str]]:
        module_sets_bounds = _BOUNDS.search(py.text)
        out = []
        for fn in _py_scopes(py):
            if fn is py.tree:
                continue
            nodes = list(_py_walk(fn))
            if not any(isinstance(n, ast.Call) and _py_name(n.func) in {"sign", "sign_transaction"} for n in nodes):
                continue
            for node in nodes:
                if not (isinstance(node, ast.Call) and _py_name(node.func) == "TransactionBuilder"):
                    continue
                methods, var = _py_chain(node, py), None
                parent = py.parents.get(node)
                if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                    var = parent.targets[0].id
                    for other in nodes:
                        if isinstance(other, ast.Call) and _py_root_name(other.func) == var:
                            methods |= _py_chain_names(other.func)
                        if isinstance(other, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "time_bounds"
                                                                  and _py_root_name(t) == var for t in other.targets):
                            methods.add("time_bounds")
                if "build" not in methods or methods & {"set_timeout", "add_time_bounds", "set_ledger_bounds", "time_bounds"}:
                    continue
                helpers = [c for c in nodes if var is not None and isinstance(c, ast.Call)
                           and any(isinstance(a, ast.Name) and a.id == var for a in c.args)]
                # The builder is handed to code that may set the bounds: this module, or a project
                # function (in any module) whose body sets them.
                if helpers and (module_sets_bounds or any(_BOUNDS.search(other.source(d)) for c in helpers
                                                          for other, d in self.ctx.index.py_defs.get(_py_name(c.func), []))):
                    continue
                out.append((node.lineno, py.snippet(node)))
        return out

    # -------------------------------------------------- K5: amount above int64 stroops
    def huge_amounts(self, py: PyFile) -> list[tuple[int, str]]:
        out = []
        for node in ast.walk(py.tree):
            call = py.parents.get(node)
            if isinstance(node, ast.keyword) and node.arg in _AMOUNT_KEYS and isinstance(call, ast.Call) and \
                    _PY_OP_BUILDER.match(_py_name(call.func)):
                for const in ast.walk(node.value):
                    if isinstance(const, ast.Constant) and isinstance(const.value, (str, int)) and \
                            not isinstance(const.value, bool) and _decimal_over_max(str(const.value)):
                        out.append((const.lineno, py.snippet(const)))
        return out

    # -------------------------------------------------- K3: reservation released after broadcast
    def release_after_send(self, py: PyFile) -> list[tuple[int, str]]:
        out = []
        if "except" not in py.text or not _RELEASE.search(py.text):
            return out
        for node in ast.walk(py.tree):
            if not isinstance(node, ast.Try) or not any(_py_broad(h.type) for h in node.handlers):
                continue
            if not (any(self._py_node_submits(py, stmt) for stmt in node.body) or self._py_catches_sent(py, node)):
                continue
            flags = {unparse(t) for stmt in node.body for n in ast.walk(stmt) if isinstance(n, (ast.Assign, ast.AugAssign))
                     for t in ([n.target] if isinstance(n, ast.AugAssign) else n.targets)
                     if isinstance(t, (ast.Name, ast.Attribute))}  # sent = True; self.sent = True
            for handler in node.handlers:
                if not _py_broad(handler.type):
                    continue
                body = [n for stmt in handler.body for n in ast.walk(stmt)]
                if any(isinstance(n, ast.Call) and _py_name(n.func) in sdk.POLL_METHODS for n in body):
                    continue
                for call in body:
                    if not isinstance(call, ast.Call):
                        continue
                    name = _py_name(call.func)
                    text = unparse(call) or py.source(call)
                    if _RELEASE.search(name) and _RESERVED.search(text) and not self._py_flag_guarded(call, handler, flags, py):
                        out.append((handler.lineno, f"{py.snippet(handler)} -> {' '.join(text.split())[:100]}"))
                        break
        return out

    @staticmethod
    def _py_flag_guarded(call, handler, flags: set[str], py: PyFile) -> bool:
        """The release runs only under a flag set in the try body, or for an exception type the
        handler tests (isinstance(e, ...), type(e), e.code)."""
        node = py.parents.get(call)
        while node is not None and node is not handler:
            if isinstance(node, ast.If):
                for n in ast.walk(node.test):
                    if isinstance(n, (ast.Name, ast.Attribute)) and unparse(n) in flags:
                        return True
                    if isinstance(n, ast.Call) and _py_name(n.func) in {"isinstance", "type", "issubclass"}:
                        return True
                    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and handler.name and \
                            n.value.id == handler.name:
                        return True
            node = py.parents.get(node)
        return False

    def _py_node_submits(self, py: PyFile, stmt) -> bool:
        return any(isinstance(n, ast.Call) and self._py_call_submits(py, n, 0) for n in ast.walk(stmt))

    def _py_call_submits(self, py: PyFile, call: ast.Call, depth: int) -> bool:
        name = _py_name(call.func)
        if name in {"send_transaction", "submit_transaction"}:
            return True
        if any(k.arg == "send" and isinstance(k.value, ast.Constant) and k.value.value == "no" for k in call.keywords):
            return False
        if re.fullmatch(r"(?:subprocess\.)?(?:run|Popen|check_output|check_call|call)|os\.system", _py_dotted(call.func) or ""):
            return self._py_cli_sends(py, call)
        if depth >= 3:
            return False
        return any(self._py_fn_submits(other, fn, depth) for other, fn in self._py_targets(py, call))

    def _py_fn_submits(self, py: PyFile, fn, depth: int) -> bool:
        return _judged(self._submits, id(fn), depth, lambda: any(
            isinstance(n, ast.Call) and self._py_call_submits(py, n, depth + 1) for n in _py_walk(fn)))

    def _py_catches_sent(self, py: PyFile, node: ast.Try) -> bool:
        """A handler names a project exception that only submitting functions raise (`except
        TxSubmittedUnconfirmed`): the body reaches one of them, whatever its receiver's type."""
        for handler in node.handlers:
            for kind in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]):
                found = self._py_lookup(py, _py_dotted(kind) or "")
                if found and found[0] == "class":
                    sites = self._py_raisers().get(id(found[2]), [])
                    names = {fn.name for _, fn in sites if fn is not None}
                    called = {(_py_name(n.func) or "").rsplit(".", 1)[-1] for stmt in node.body
                              for n in ast.walk(stmt) if isinstance(n, ast.Call)}
                    if sites and names & called and \
                            all(fn is not None and self._py_fn_submits(other, fn, 1) for other, fn in sites):
                        return True
        return False

    def _py_raisers(self) -> dict[int, list]:
        """Project exception class (by node) -> the functions that raise it (None at module
        level), from one walk of each non-test module."""
        if self._raisers is None:
            self._raisers = {}
            for py in self.ctx.index.py.values():
                if TEST_PATH.search(py.path) or "raise" not in py.text:
                    continue
                for node in ast.walk(py.tree):
                    if isinstance(node, ast.Raise) and node.exc is not None:
                        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
                        found = self._py_lookup(py, _py_dotted(exc) or "")
                        if found and found[0] == "class":
                            self._raisers.setdefault(id(found[2]), []).append((py, self._py_frame(py, node)[0]))
        return self._raisers

    def _py_targets(self, py: PyFile, call: ast.Call) -> list[tuple[PyFile, ast.AST]]:
        """The project functions a call runs, followed only when the target is exact: `f()` defined
        in the calling function or at module level here or in the project module it is imported
        from by name (`mod.f()` through an imported module), `self.m()`, `cls.m()` or `super().m()`
        in the caller's class or a project class it inherits from, and `C().m()` or `x.m()` after
        `x = C()` in the same function, C a project class. A call on anything else (a parameter, an
        attribute, a typed name) is not followed: its target may be any class with that method."""
        func = call.func
        fn, cls = self._py_frame(py, call)
        held = self._py_locals(fn) if fn is not None else {}
        if isinstance(func, ast.Name):
            if func.id in held:
                bound = held[func.id]
                return [(py, bound)] if isinstance(bound, (ast.FunctionDef, ast.AsyncFunctionDef)) else []
            found = self._py_lookup(py, func.id)
            return [found[1:]] if found and found[0] == "def" else []
        if not isinstance(func, ast.Attribute):
            return []
        recv = func.value
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"}:
            return self._py_methods(py, cls, func.attr) if cls is not None else []
        if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name) and recv.func.id == "super":
            return [m for base in self._py_bases(py, cls) for m in self._py_methods(*base, func.attr)] if cls is not None else []
        if isinstance(recv, ast.Name) and recv.id in held:
            recv = held[recv.id]  # `x = C()` in this function
            if not isinstance(recv, str):
                return []
            found = self._py_lookup(py, recv)
        elif isinstance(recv, ast.Call):  # `C().m()`
            found = self._py_lookup(py, _py_dotted(recv.func) or "")
        else:  # `mod.f()`, `pkg.mod.f()`
            found = self._py_lookup(py, f"{_py_dotted(recv)}.{func.attr}") if _py_dotted(recv) else None
            return [found[1:]] if found and found[0] == "def" else []
        return self._py_methods(found[1], found[2], func.attr) if found and found[0] == "class" else []

    def _py_frame(self, py: PyFile, node) -> tuple:
        """(function, class) a call or raise sits in, from one walk per file: no parent walk per node."""
        frames = self._frames.get(py.path)
        if frames is None:
            frames = self._frames[py.path] = {}
            stack = [(py.tree, None, None)]
            while stack:
                node_, fn, cls = stack.pop()
                if isinstance(node_, (ast.Call, ast.Raise)):
                    frames[id(node_)] = (fn, cls)
                if isinstance(node_, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = node_
                elif isinstance(node_, ast.ClassDef):
                    cls = node_
                stack.extend((child, fn, cls) for child in ast.iter_child_nodes(node_))
        return frames.get(id(node), (None, None))

    def _py_locals(self, fn) -> dict:
        """Name -> what one function binds it to, for each name it binds: the class text of `x =
        C(...)`, a nested def, or None (a parameter, any other value, or bound more than once).
        One walk per function, not descending into nested ones."""
        found = self._locals.get(id(fn))
        if found is None:
            bound: dict[str, list] = {}
            made: set[int] = set()
            for node in _py_walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    built = _py_call(node.value)
                    held = _py_dotted(built.func) if built is not None and not isinstance(node.value, ast.Await) else None
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if isinstance(target, ast.Name):
                            bound.setdefault(target.id, []).append(held)
                            made.add(id(target))
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and id(node) not in made:
                    bound.setdefault(node.id, []).append(None)
                elif isinstance(node, ast.arg):
                    bound.setdefault(node.arg, []).append(None)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound.setdefault(node.name, []).append(None if isinstance(node, ast.ClassDef) else node)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        bound.setdefault((alias.asname or alias.name).split(".")[0], []).append(None)
                elif isinstance(node, ast.ExceptHandler) and node.name:
                    bound.setdefault(node.name, []).append(None)
            found = self._locals[id(fn)] = {name: values[0] if len(values) == 1 else None for name, values in bound.items()}
        return found

    def _py_names(self, py: PyFile) -> dict[str, tuple]:
        """What a module's top-level statements bind each name to: ("def", node), ("class", node),
        ("from", module, level, name), ("module", module, level) or ("other",) (an assignment,
        or bound more than once). `import a.b` binds both `a` and the dotted name `a.b`."""
        found = self._names.get(py.path)
        if found is None:
            found = self._names[py.path] = {}

            def bind(name: str, entry: tuple) -> None:
                found[name] = entry if name not in found else ("other",)
            for node in py.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    bind(node.name, ("def", node))
                elif isinstance(node, ast.ClassDef):
                    bind(node.name, ("class", node))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.asname:
                            bind(alias.asname, ("module", alias.name, 0))
                            continue
                        bind(alias.name.split(".")[0], ("module", alias.name.split(".")[0], 0))
                        if "." in alias.name:
                            bind(alias.name, ("module", alias.name, 0))
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name != "*":
                            bind(alias.asname or alias.name, ("from", node.module or "", node.level, alias.name))
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if isinstance(target, ast.Name):
                            bind(target.id, ("other",))
        return found

    def _py_lookup(self, py: PyFile, dotted: str, depth: int = 0) -> tuple | None:
        """What a name or dotted name used in a module stands for, exactly: ("def", file, node),
        ("class", file, node) or ("module", file, None), through imports of project modules
        (re-exports included). A name the module does not bind, or binds from outside the
        project, is None."""
        key = (py.path, dotted)
        if key in self._lookups:
            return self._lookups[key]
        self._lookups[key] = None  # an import cycle reads as unknown
        found = None
        entry = self._py_names(py).get(dotted) if dotted and depth < 8 else None
        if entry is None and "." in dotted and depth < 8:
            head, _, last = dotted.rpartition(".")
            owner = self._py_lookup(py, head, depth + 1)
            found = self._py_lookup(owner[1], last, depth + 1) if owner and owner[0] == "module" else None
        elif entry is not None and entry[0] in {"def", "class"}:
            found = (entry[0], py, entry[1])
        elif entry is not None and entry[0] == "module":
            module = self._py_module(py, entry[1], entry[2])
            found = ("module", module, None) if module is not None else None
        elif entry is not None and entry[0] == "from":
            _, module, level, name = entry
            source = self._py_module(py, module, level)
            if source is not None and name in self._py_names(source):
                found = self._py_lookup(source, name, depth + 1)
            elif (sub := self._py_module(py, f"{module}.{name}" if module else name, level)) is not None:
                found = ("module", sub, None)  # `from pkg import mod`
        self._lookups[key] = found
        return found

    def _py_module(self, py: PyFile, module: str, level: int) -> PyFile | None:
        """The one non-test project file a module name stands for: relative to the importing file,
        or (absolute) the only file whose path ends with it under any source root."""
        if self._modules is None:
            self._modules = {}
            for path, other in self.ctx.index.py.items():
                if TEST_PATH.search(path):
                    continue
                stem = path[:-3]
                stem = stem[:-9] if stem.endswith("/__init__") else "" if stem == "__init__" else stem
                parts = stem.split("/")
                for i in range(len(parts)):
                    self._modules.setdefault(".".join(parts[i:]), []).append(other)
        if level:
            base = posixpath.dirname(py.path)
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            stem = posixpath.join(base, *module.split(".")) if module else base
            other = self.ctx.index.py.get(stem + ".py") or self.ctx.index.py.get(stem + "/__init__.py")
            return other if other is not None and not TEST_PATH.search(other.path) else None
        found = self._modules.get(module, [])
        return found[0] if len(found) == 1 else None

    def _py_methods(self, py: PyFile, cls: ast.ClassDef, name: str, depth: int = 0) -> list[tuple[PyFile, ast.AST]]:
        """The methods `name` of a class: its own, else those of the first project base class that has it."""
        key = (id(cls), name)
        if key not in self._methods:
            self._methods[key] = []  # an inheritance cycle reads as none
            members = self._members.get(id(cls))
            if members is None:
                members = self._members[id(cls)] = {}
                for node in cls.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        members.setdefault(node.name, []).append((py, node))
            self._methods[key] = members.get(name) or next((found for base in self._py_bases(py, cls) if depth < 8
                                                            and (found := self._py_methods(*base, name, depth + 1))), [])
        return self._methods[key]

    def _py_bases(self, py: PyFile, cls: ast.ClassDef) -> list[tuple[PyFile, ast.ClassDef]]:
        found = [self._py_lookup(py, _py_dotted(base) or "") for base in cls.bases]
        return [(other, node) for kind, other, node in filter(None, found) if kind == "class"]

    def _py_cli_sends(self, py: PyFile, call: ast.Call) -> bool:
        """`stellar contract invoke` / `tx send` run as a command: the strings of its first
        argument, of what the calling function assigns to it, and of the project function that
        builds it (`cmd = build_cmd(...)`)."""
        words: list[str] = []
        for arg in call.args[:1]:
            words += self._py_words(py, arg)
            if isinstance(arg, ast.Name):
                fn = self._py_frame(py, call)[0]
                words += self._py_commands(py, fn if fn is not None else py.tree).get(arg.id, [])
        text = " ".join(words)
        return bool(_STELLAR_CLI.search(text)) and not re.search(r"--send[= ]no\b", text)

    def _py_commands(self, py: PyFile, scope) -> dict[str, list[str]]:
        """Name -> the strings assigned to it in one function (or at module level): one walk."""
        found = self._commands.get(id(scope))
        if found is None:
            found = self._commands[id(scope)] = {}
            for node in _py_walk(scope):
                if isinstance(node, ast.Assign):
                    words = self._py_words(py, node.value)
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            found.setdefault(target.id, []).extend(words)
        return found

    def _py_words(self, py: PyFile, value) -> list[str]:
        """The strings of a value, and of the project function it calls (once per function)."""
        words = _py_strings(value)
        built = _py_call(value)
        for _, fn in self._py_targets(py, built) if built is not None else []:
            if id(fn) not in self._strings:
                self._strings[id(fn)] = _py_strings(fn)
            words += self._strings[id(fn)]
        return words


def _judged(memo: dict, key, depth: int, judge) -> bool:
    """A memoised verdict on whether code submits. A yes holds at any call depth; a no only as
    deep as it was judged, since the depth limit may have cut that judgment short (each key is
    judged at most once per depth). A cycle reads as no."""
    seen = memo.get(key)
    if seen is not None and (seen[0] or seen[1] <= depth):
        return seen[0]
    memo[key] = (False, depth)
    memo[key] = (bool(judge()), depth)
    return memo[key][0]


def _py_dotted(node) -> str | None:
    """`agent.chain` for an attribute chain of plain names."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return ".".join([node.id, *reversed(parts)]) if isinstance(node, ast.Name) else None


def _py_strings(node) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _py_strings_only(node) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return bool(node.elts) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts)
    return False


def _py_broad(handler_type) -> bool:
    if handler_type is None:
        return True
    names = [unparse(e) for e in (handler_type.elts if isinstance(handler_type, ast.Tuple) else [handler_type])]
    return any(n in {"Exception", "BaseException"} for n in names)


def _py_root_name(node) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _py_chain_names(func) -> set[str]:
    names = set()
    node = func
    while isinstance(node, (ast.Attribute, ast.Call)):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
            node = node.value
        else:
            node = node.func
    return names


def _py_chain(call: ast.Call, py: PyFile) -> set[str]:
    """Methods chained onto `TransactionBuilder(...)`: `.set_timeout(30).build()`."""
    names = set()
    node = call
    while True:
        parent = py.parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            names.add(parent.attr)
            grand = py.parents.get(parent)
            node = grand if isinstance(grand, ast.Call) and grand.func is parent else parent
        else:
            return names


def _py_string_origin(arg, fn) -> str | None:
    """Where a durability argument becomes a str: a literal, a str default or a str assignment."""
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return f"is the string {arg.value!r}"
    if not isinstance(arg, ast.Name) or isinstance(fn, ast.Module):
        return None
    params = fn.args.args + fn.args.kwonlyargs
    defaults = dict(zip([a.arg for a in fn.args.args[len(fn.args.args) - len(fn.args.defaults):]], fn.args.defaults))
    defaults.update({a.arg: d for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults) if d is not None})
    for param in params:
        if param.arg != arg.id:
            continue
        default = defaults.get(param.arg)
        if isinstance(default, ast.Constant) and isinstance(default.value, str):
            return f"defaults to the string {default.value!r} (line {default.lineno})"
        if param.annotation is not None and unparse(param.annotation) == "str":
            return f"is typed str (line {param.lineno})"
    for node in _py_walk(fn):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in node.targets) \
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return f"is assigned the string {node.value.value!r} (line {node.lineno})"
    return None


# =========================================================================== JavaScript
#: The Soroban RPC client classes of the JS SDK (rpc.Server; SorobanRpc.Server before 13.0.0;
#: SorobanServer in soroban-client).
_RPC_CLASS = r"(?:[\w$]+\.)*(?:(?:rpc|SorobanRpc)\.Server|SorobanServer)\b"
#: Where the client class is named (`new rpc.Server(`, `: rpc.Server`); the name it is bound
#: to is read from the text just before it on the same line (_BEFORE_*).
_RPC_USE = re.compile(r"(?<![\w$])(?:(?:rpc|SorobanRpc)\.Server|SorobanServer)(?![\w$])")
#: `Server` imported from the SDK's rpc entry point, or destructured from its rpc namespace.
_RPC_IMPORT = re.compile(r"""\{([^{}]{0,800})\}\s*(?:from\s*|=\s*require\(\s*)["']@stellar/stellar-sdk/"""
                         r"""(?:(?:no-axios|no-eventsource|minimal)/)?rpc["']""")
_RPC_DESTRUCTURE = re.compile(r"\{([^{}=;]{0,800})\}\s*=\s*(?:[\w$]+\.)?(?:rpc|SorobanRpc)\s*(?:[;\n]|$)")
#: How much of the line before a class use is read for the name bound to it.
_BEFORE = 160
#: `name = new `, `name: T = new `, `name: new ` (an object key), `this.name = new `. The type
#: excludes brackets and commas, so `f(url: string) { this.rpc = new ` binds rpc, not url.
_BEFORE_NEW = re.compile(r"(?<![\w$])#?([\w$]+)\s*(?:\??:[^=;\n(){},]{0,120})?[=:]\s*(?:await\s+)?new\s+(?:[\w$]+\.)*$")
#: `name: ` or `name?: ` (a typed parameter, variable or field).
_BEFORE_TYPE = re.compile(r"(?<![\w$])#?([\w$]+)\s*\??:\s*(?:[\w$]+\.)*$")
#: `function f(...): ` or `f = async (...): Promise<` (a factory typed to return the client).
_BEFORE_RETURN_TYPE = re.compile(r"(?<![\w$])([\w$]+)\s*(?:=\s*(?:async\s*)?)?\([^()]{0,120}\)\s*:\s*"
                                 r"(?:Promise\s*<\s*)?(?:[\w$]+\.)*$")
#: `return new ` or `=> new ` (a factory that builds the client).
_BEFORE_RETURNED = re.compile(r"(?:(?<![\w$])return\s+(?:await\s+)?|=>\s*\(?\s*)new\s+(?:[\w$]+\.)*$")
#: `name = ` / `name: ` before a factory call (`const rpcServer = getRpc()`, `this.rpc = await this.makeRpc()`).
_BEFORE_CALL = re.compile(r"(?<![\w$])#?([\w$]+)\s*(?:\??:[^=;\n(){},]{0,120})?[=:]\s*(?:await\s+)?(?:this\.|[\w$]+\.)?$")
#: Call sites by name, for the factory calls: `getRpc(`, `this.makeRpc(`.
_CALL_SITE = re.compile(r"(?:(?<![\w$.])|(?<=(?<![\w$.])this\.))([\w$]+)\s*\(")
#: `name = new C(`, `this.name: T = new C(` (the class a name is built as; the type excludes
#: brackets and commas, so `f(a: string, b = new C(` binds b).
_JS_BUILT = re.compile(r"(?<![\w$.])(?:this\.)?#?([\w$]+)\s*(?:\??:[^=;\n(){},]{0,120})?=\s*(?:await\s+)?new\s+"
                       r"((?:[\w$]+\.)*[\w$]+)\s*[(<]")
#: `name = maker(` (what a local fetch is made by, for the paid-request test).
_JS_MADE = re.compile(r"(?<![\w$])([\w$]+)\s*(?::[^=;\n(){},]{0,120})?=\s*(?:await\s+)?([\w$.]+)\s*\(")
#: Class declarations and expressions.
_CLASS_TYPES = frozenset({"class_declaration", "class", "abstract_class_declaration"})
#: Receivers that are another chain's client or a wallet, whatever they are bound to.
_NOT_RPC = re.compile(r"horizon|wallet|signer|provider|\beth\b|viem|ethers|web3|solana|connection", re.I)
#: How far up from a use of a send result its context is looked for, and how many names
#: derived from one result are followed; past either the use counts as unknown (no finding).
_CONTEXT_DEPTH = 200
_DERIVED_LIMIT = 256


#: How deep below its function a node may sit for its parents to be read from the function
#: down (one scan of a node's children per level); deeper, the node is not judged.
_LOCAL_DEPTH = 1000


def _ancestors(node, top) -> list | None:
    """The nodes from ``top`` (the node's function, or the file's root) down to the node's
    parent, outermost first. Read downwards because a tree-sitter parent lookup walks from the
    root, so its cost is the node's depth in the file: in a loop over nested functions that
    made the rules quadratic or cubic. None past _LOCAL_DEPTH levels."""
    chain, cur = [], top
    while cur is not None and cur != node:
        chain.append(cur)
        if len(chain) > _LOCAL_DEPTH:
            return None
        cur = cur.child_with_descendant(node)
    return chain if cur is not None else None


class _JsTree:
    """One file's calls by callee name with the function each sits in (also by the call's span),
    and each function's enclosing function, from one walk (no parent lookups)."""
    __slots__ = ("root", "calls", "order", "starts", "scope", "outer")

    def __init__(self, root):
        self.root = root
        self.calls: dict[str, list] = {}
        self.order: list = []  # every call, in source order, with its start offset
        self.starts: list[int] = []
        self.scope: dict[tuple, object] = {}
        self.outer: dict[tuple, object] = {}
        stack = [(root, None)]
        while stack:
            node, fn = stack.pop()
            if node.type == "call_expression":
                self.calls.setdefault(callee_name(node), []).append((node, fn))
                self.order.append(node)
                self.starts.append(node.start_byte)
                self.scope[(node.start_byte, node.end_byte)] = fn
            elif js_functions_type(node):
                self.outer[(node.start_byte, node.end_byte, node.type)] = fn
                fn = node
            stack.extend((child, fn) for child in reversed(node.named_children))

    def up(self, node, fn) -> list | None:
        """A node's ancestors, nearest first, up to its function (``fn``, None at top level)."""
        chain = _ancestors(node, fn if fn is not None else self.root)
        return chain[::-1] if chain is not None else None

    def enclosing(self, fn):
        """The function a function sits in (None at top level)."""
        return self.outer.get((fn.start_byte, fn.end_byte, fn.type))

    def function_name(self, fn) -> str | None:
        up = self.up(fn, self.enclosing(fn))
        return js_function_name(fn, up[0] if up else None) if up is not None else None


def _bound_names(call, up: list) -> tuple[object, set[str], list, object]:
    """(outermost expression standing for the call's result, names bound to it, the wrapper
    calls it passed through, that expression's parent), from the call's ancestors (``up``,
    nearest first)."""
    node, wrappers, i = call, [], 0
    while i < len(up):
        parent = up[i]
        if parent.type in {"await_expression", "parenthesized_expression", "as_expression", "non_null_expression"}:
            node, i = parent, i + 1
            continue
        host = up[i + 1] if i + 1 < len(up) else None
        if parent.type == "arguments" and host is not None and host.type == "call_expression" \
                and callee_name(host) not in sdk.POLL_METHODS and _args(host)[:1] == [node]:
            node, i = host, i + 2  # a wrapper: runRpc(server.sendTransaction(tx), "label")
            wrappers.append(node)
            continue
        break
    parent = up[i] if i < len(up) else None
    names: set[str] = set()
    if parent is None:
        return node, names, wrappers, None
    if parent.type == "variable_declarator" and parent.child_by_field_name("value") == node:
        target = parent.child_by_field_name("name")
        if target.type == "identifier":
            names.add(_txt(target))
        elif target.type == "object_pattern":
            for child in target.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    names.add(_txt(child))
                elif child.type == "pair_pattern":
                    value = child.child_by_field_name("value")
                    if value is not None and value.type == "identifier":
                        names.add(_txt(value))
    elif parent.type == "assignment_expression" and parent.child_by_field_name("right") == node:
        left = parent.child_by_field_name("left")
        if left.type == "identifier":
            names.add(_txt(left))
    return node, names, wrappers, parent


class _FileUses:
    """One file's identifiers, indexed in one walk so each send reads only the uses of its own
    names inside its own function (a byte range): names derived from a root (`const h =
    sent.hash`, `for (const s of sent)`) and, per name, its uses (with the function each sits
    in) and their classification by kind, all in source order. The walk carries each node's
    parent and function: a tree-sitter parent lookup costs the node's depth, so reading it for
    every identifier made nested functions cubic."""
    __slots__ = ("derived", "idents", "kinds")

    def __init__(self, root):
        self.derived: dict[str, tuple[list[int], list[str]]] = {}
        self.idents: dict[str, list] = {}
        #: name -> kind -> (starts, wheres, for "settled": index of the next entry with payment words)
        self.kinds: dict[str, dict[str, tuple[list[int], list, list[int]]]] = {}
        stack = [(root, None, None)]
        while stack:
            node, parent, fn = stack.pop()
            kind = node.type
            if kind == "variable_declarator":
                value = _unwrap(node.child_by_field_name("value"))
                target = node.child_by_field_name("name")
                if value is not None and target is not None and target.type == "identifier" and \
                        value.type in {"identifier", "member_expression"}:
                    root_name = _root_identifier(value)
                    if root_name:
                        starts, targets = self.derived.setdefault(root_name, ([], []))
                        starts.append(node.start_byte)
                        targets.append(_txt(target))
            elif kind == "for_in_statement":
                root_name, left = _root_identifier(node.child_by_field_name("right")), node.child_by_field_name("left")
                if root_name and left is not None and left.type == "identifier":
                    starts, targets = self.derived.setdefault(root_name, ([], []))
                    starts.append(node.start_byte)
                    targets.append(_txt(left))
            elif kind in {"identifier", "shorthand_property_identifier"}:
                if not (parent is not None and parent.type == "variable_declarator" and parent.child_by_field_name("name") == node):
                    self.idents.setdefault(_txt(node), []).append((node, fn))
                continue
            elif js_functions_type(node):
                fn = node
            stack.extend((child, node, fn) for child in reversed(node.named_children))


class _JsRules:
    def __init__(self, ctx: _Context):
        self.ctx = ctx
        self._memo: dict[tuple, object] = {}
        self._sent: dict[tuple, tuple[set[int], dict[int, int]]] = {}  # K3: per file and call depth (_sends_within)
        self._bound: set[str] | None = None
        self._aliases: dict[str, re.Pattern | None] = {}
        self._file_uses: dict[str, _FileUses] = {}
        self._trees: dict[str, _JsTree] = {}
        self._contexts: dict[tuple, tuple[str | None, tuple]] = {}
        self._arg_contexts: dict[tuple, tuple[str | None, tuple]] = {}
        self._caller_verdicts: dict[tuple, list | None] = {}
        self._claims: dict[tuple, bool] = {}
        self._calls_by_name: dict[str, list] | None = None

    # -------------------------------------------------- which receivers are Soroban RPC clients
    def _class_alias(self, js: JsFile) -> re.Pattern | None:
        """This file's own names for the client class: `Server` imported from the SDK's rpc
        entry point or destructured from its rpc namespace (`const { Server } = rpc`)."""
        if js.path not in self._aliases:
            names = set()
            for m in _RPC_IMPORT.finditer(js.text):
                names.update(a or "Server" for a in re.findall(r"(?<![\w$])Server(?:\s+as\s+([\w$]+))?(?![\w$])", m.group(1)))
            for m in _RPC_DESTRUCTURE.finditer(js.text):
                names.update(a or "Server" for a in re.findall(r"(?<![\w$])Server(?:\s*:\s*([\w$]+))?(?![\w$])", m.group(1)))
            self._aliases[js.path] = re.compile(r"(?<![\w$.])(?:" + "|".join(sorted(map(re.escape, names))) + r")(?![\w$])") \
                if names else None
        return self._aliases[js.path]

    def _class_uses(self, js: JsFile):
        yield from _RPC_USE.finditer(js.text)
        alias = self._class_alias(js)
        if alias is not None:
            yield from alias.finditer(js.text)

    def _is_rpc_class(self, js: JsFile, text: str) -> bool:
        alias = self._class_alias(js)
        return bool(re.fullmatch(_RPC_CLASS, text) or alias is not None and alias.fullmatch(text))

    def _rpc_bound(self) -> set[str]:
        """Names bound or typed as an RPC client anywhere in the project's Stellar files
        (`server = new rpc.Server(`, `server: rpc.Server`, `rpc: new rpc.Server(` in a clients
        object, `const rpcServer = getRpc()` for a factory that returns one), found in one pass
        over each file: a class use, then the text just before it."""
        if self._bound is not None:
            return self._bound
        bound, factories, builders = set(), set(), {}
        stellar = [js for js in self.ctx.index.js.values() if js.stellar]
        for js in stellar:
            for m in self._class_uses(js):
                before = js.text[max(0, m.start() - _BEFORE):m.start()]
                before = before[before.rfind("\n") + 1:]
                found = _BEFORE_NEW.search(before) or _BEFORE_TYPE.search(before)
                if found:
                    bound.add(found.group(1))
                elif (found := _BEFORE_RETURN_TYPE.search(before)):
                    factories.add(found.group(1))
                elif _BEFORE_RETURNED.search(before):
                    builders[js.path] = js
        for js in builders.values():  # `return new rpc.Server(url)` / `() => new rpc.Server(url)`: the function's name
            for node in SourceIndex.walk(js.root):
                if node.type != "new_expression" or not self._is_rpc_class(js, _txt(node.child_by_field_name("constructor"))):
                    continue
                parent = node.parent
                while parent is not None and parent.type in {"await_expression", "parenthesized_expression", "as_expression"}:
                    parent = parent.parent
                fn = SourceIndex.enclosing_function(node) if parent is not None and parent.type == "return_statement" \
                    else parent if js_functions_type(parent) else None
                name = js_function_name(fn) if fn is not None else None
                if name:
                    factories.add(name)
        if factories:
            for js in stellar:
                for m in _CALL_SITE.finditer(js.text):
                    if m.group(1) in factories:
                        before = js.text[max(0, m.start() - _BEFORE):m.start()]
                        found = _BEFORE_CALL.search(before[before.rfind("\n") + 1:])
                        if found:
                            bound.add(found.group(1))
        self._bound = bound
        return bound

    def _is_rpc(self, js: JsFile, recv) -> bool:
        """A Soroban RPC client of the Stellar SDK, in a file that imports the SDK: a new
        rpc.Server(...) or a name bound to one, typed as one or returned by a factory of one
        (here, or in another Stellar file of the project, as a clients module does). A name
        alone (`rpcClient`) is not enough: EVM and other JSON-RPC clients send transactions
        too. A name that says soroban counts in a Stellar file."""
        if recv is None or not js.stellar:
            return False
        text = _txt(recv)
        if _NOT_RPC.search(text):
            return False
        if re.search(r"soroban", text, re.I):
            return True
        if recv.type == "new_expression":
            return self._is_rpc_class(js, _txt(recv.child_by_field_name("constructor")))
        name = text.rsplit(".", 1)[-1].lstrip("#")
        if not (re.fullmatch(r"[\w$]+", name) and name in self._rpc_bound()):
            return False
        # Bound to an RPC client in some Stellar file, but this file builds its own of another
        # class under that name (`const client = new ethers.JsonRpcProvider(...)`): this one wins.
        local = self._js_built_as(js, name)
        return local is None or self._is_rpc_class(js, local)

    # -------------------------------------------------- uses of a send result
    def _uses(self, js: JsFile, fn, names: set[str], after: int) -> dict[str, list]:
        """Classify each use of the names in fn after a byte offset: poll, settled, returned,
        unknown, status. Reads the file's index (one walk per file) between the offset and the
        end of fn, so the cost of a send is the number of names derived from it, not the size
        of its function. `settled` holds the first two settled uses and the first that names a
        payment (what the finding shows and how it is rated); the other kinds hold their first."""
        index = self._file_uses.get(js.path)
        if index is None:
            index = self._file_uses[js.path] = _FileUses(js.root)
        end = fn.end_byte
        out = _no_uses()
        names, todo, steps = set(names), list(names), 0
        while todo:
            starts, targets = index.derived.get(todo.pop(), ((), ()))
            for i in range(bisect_right(starts, after), bisect_left(starts, end)):
                steps += 1
                if steps > _DERIVED_LIMIT:
                    out["unknown"].append((0, "too many names derived from the result"))
                    return out
                if targets[i] not in names:
                    names.add(targets[i])
                    todo.append(targets[i])
        settled, paying = [], []
        for name in names:
            for kind, (starts, wheres, pays) in self._name_uses(js, index, name).items():
                i = bisect_right(starts, after)
                if i == len(starts) or starts[i] >= end:
                    continue
                if kind != "settled":
                    out[kind].append(wheres[i])
                    continue
                settled += [(starts[j], wheres[j]) for j in range(i, min(i + 2, len(starts))) if starts[j] < end]
                if pays[i] >= 0 and starts[pays[i]] < end:
                    paying.append((starts[pays[i]], wheres[pays[i]]))
        settled.sort(key=lambda item: item[0])
        first = settled[:2]
        if paying and not any(_PAYMENT_WORDS.search(where[1]) for _, where in first):
            first.append(min(paying, key=lambda item: item[0]))
        out["settled"] = [where for _, where in first]
        return out

    def _name_uses(self, js: JsFile, index: _FileUses, name: str) -> dict:
        """kind -> (starts, wheres, next paying entry) for one name's uses in a file."""
        kinds = index.kinds.get(name)
        if kinds is None:
            kinds = {}
            for node, fn in index.idents.get(name, ()):
                kind, where = self._context_of(js, node, fn)
                if kind:
                    starts, wheres, _ = kinds.setdefault(kind, ([], [], []))
                    starts.append(node.start_byte)
                    wheres.append(where)
            for kind, (starts, wheres, pays) in kinds.items():
                following = -1
                pays.extend([-1] * len(starts))
                for j in range(len(starts) - 1, -1, -1):
                    if kind == "settled" and _PAYMENT_WORDS.search(wheres[j][1]):
                        following = j
                    pays[j] = following
            index.kinds[name] = kinds
        return kinds

    def _context_of(self, js: JsFile, node, fn) -> tuple[str | None, tuple]:
        """_context, once per identifier (fn: the function it sits in): the walk stops there,
        so the answer does not depend on which function asked."""
        key = _node_key(js, node)
        found = self._contexts.get(key)
        if found is None:
            found = self._contexts[key] = self._context(js, node, fn)
        return found

    def _context(self, js: JsFile, node, fn) -> tuple[str | None, tuple]:
        up = self._tree(js).up(node, fn)
        if up is None:
            return "unknown", ()
        # `sent.status` handed back or logged: whoever reads it sees PENDING, unless the same
        # return or log calls the outcome a success.
        holder = up[0] if up else None
        status = holder is not None and holder.type == "member_expression" and \
            holder.child_by_field_name("object") == node and _txt(holder.child_by_field_name("property")) == "status"
        return self._walk_context(js, node, up, 0, status, _CONTEXT_DEPTH)

    def _walk_context(self, js: JsFile, expr, up: list, i: int, status: bool, budget: int) -> tuple[str | None, tuple]:
        """Up from a use (``up[i]`` is its parent) to the statement that holds it, inside its
        own function."""
        for i in range(i, len(up)):
            parent = up[i]
            if js_functions_type(parent):
                return None, ()
            budget -= 1
            if budget < 0:
                return "unknown", ()
            if parent.type == "return_statement":
                claims = self._claims_final(js, parent)
                if status and not claims:
                    return "status", ()
                return ("claimed" if claims else "returned"), (js.line(parent), js.snippet(parent))
            if parent.type in _STATEMENTS:
                return None, ()
            if parent.type == "arguments":
                call = up[i + 1] if i + 1 < len(up) else None
                if call is not None and call.type == "call_expression":
                    key = (_node_key(js, call), status)
                    found = self._arg_contexts.get(key)
                    if found is None:
                        found = self._arg_contexts[key] = self._call_context(js, call, up, i + 2, status, budget)
                    return found
            if parent.type == "binary_expression" and _txt(parent.child_by_field_name("operator")) in \
                    {"===", "!==", "==", "!=", "<", ">", "<=", ">="}:
                return None, ()
            if parent.type == "assignment_expression" and parent.child_by_field_name("right") == expr:
                left = parent.child_by_field_name("left")
                if left is not None and left.type == "member_expression":
                    prop = _txt(left.child_by_field_name("property"))
                    return ("settled", (js.line(parent), js.snippet(parent))) if re.search(
                        r"hash|paid|settle|anchor|regist|confirm", prop, re.I) else (None, ())
                return None, ()
            expr = parent
        return None, ()

    def _call_context(self, js: JsFile, call, up: list, i: int, status: bool, budget: int) -> tuple[str | None, tuple]:
        """What a call does with a send result passed to it (once per call and status use;
        ``up[i]`` is the call's parent)."""
        name, dotted = callee_name(call), _dotted(call.child_by_field_name("function"))
        if name in sdk.POLL_METHODS or name in sdk.SELF_POLLING:
            return "poll", ()
        if name in _TRANSPARENT:
            return self._walk_context(js, call, up, i, status, budget)
        where = (js.line(call), js.snippet(call))
        if _LOGGER.search(dotted):
            text = " ".join(s for s in (_string_value(a) or _template_text(a) for a in _args(call)) if s)
            if _says_final(text):
                return "settled", where
            return ("status", ()) if status else (None, ())
        if _RESPONDER.search(dotted):
            claims = self._claims_final(js, call)
            return ("status", ()) if status and not claims else (("claimed" if claims else "returned"), where)
        if (_DB_WRITE.search(dotted) or _SETTLE_CALL.search(name)) and _TENTATIVE_WORDS.search(
                " ".join(_string_value(n) or "" for a in _args(call) for n in SourceIndex.walk(a)
                         if n.type in {"string", "template_string"})):
            return "unknown", where  # recorded as pending: settled later by a reconciler
        if _DB_WRITE.search(dotted):
            return "settled", where
        defs = self.ctx.index.defs(name)
        if defs and any(self._fn_polls(f, d, 0) for f, d in defs):
            return "poll", ()
        if _SETTLE_CALL.search(name):
            return "settled", where
        return ("unknown", where) if not defs else (None, ())

    def _claims_final(self, js: JsFile, node) -> bool:
        """A return or response that calls the outcome final: a success-named key set to true
        (`success: true`, `ok: true`) or a string that says confirmed or paid (not pending, not
        "to confirm" or "failed to complete")."""
        key = _node_key(js, node)
        if key not in self._claims:
            claims = False
            for n in SourceIndex.walk(node):
                if n.type == "pair" and _txt(n.child_by_field_name("value")) == "true" and \
                        _SUCCESS_NAME.search(_txt(n.child_by_field_name("key")).strip("'\"")):
                    claims = True
                elif n.type in {"string", "template_string"}:
                    claims = _says_final(_string_value(n) or _template_text(n) or "")
                if claims:
                    break
            self._claims[key] = claims
        return self._claims[key]

    def _fn_polls(self, js: JsFile, fn, depth: int) -> bool:
        """The function (nested callbacks included) reads the outcome: it calls a poll method,
        or (up to two calls deep from depth 0) a project function that does. Answered from the
        file's sorted offsets of such calls, so a function costs a lookup, not a walk."""
        return _within(self._polling_calls(js, 2 - depth), fn.start_byte, fn.end_byte)

    def _polling_calls(self, js: JsFile, level: int) -> list[int]:
        """Sorted offsets of the calls in a file that read an outcome within ``level`` calls: a
        poll method, or a call to a project function whose body has a call of level - 1."""
        key = ("polling", js.path, level)
        if key not in self._memo:
            self._memo[key] = []  # a cycle reads as not polling
            self._memo[key] = sorted(call.start_byte for name, calls in self._tree(js).calls.items()
                                     if name in sdk.POLL_METHODS or name in sdk.SELF_POLLING
                                     or (level > 0 and self._name_polls(name, level - 1)) for call, _ in calls)
        return self._memo[key]

    def _name_polls(self, name: str, level: int) -> bool:
        """A project function of this name has a polling call of the level in its body."""
        key = ("polls", name, level)
        if key not in self._memo:
            self._memo[key] = False
            self._memo[key] = any(_within(self._polling_calls(f, level), d.start_byte, d.end_byte)
                                  for f, d in self.ctx.index.defs(name))
        return self._memo[key]

    # -------------------------------------------------- K1: send result used as the outcome
    def send_as_final(self, js: JsFile) -> tuple[list[tuple[int, str]], bool]:
        """Send sites whose PENDING result is used as the outcome, and whether that outcome is
        a payment or access decision."""
        out, money = [], False
        if "sendTransaction" not in js.text:
            return out, money
        tree = self._tree(js)
        for call, fn in tree.calls.get("sendTransaction", ()):
            if fn is None or not self._is_rpc(js, receiver(call)):
                continue
            up = tree.up(call, fn)
            if up is None:
                continue
            _, names, wrappers, holder = _bound_names(call, up)
            if any(self._waits(w) for w in wrappers):
                continue
            uses = self._uses(js, fn, names, call.end_byte) if names else _no_uses()
            if holder is not None and holder.type == "return_statement":
                uses["returned"].append((js.line(holder), js.snippet(holder)))
            if _undecided(uses):
                continue
            settled = list(uses["settled"])
            if not settled and (uses["returned"] or uses["claimed"]):
                verdict = self._callers(js, fn)
                if verdict is None:
                    continue
                settled = verdict
            if not settled:
                continue
            money = money or any(_PAYMENT_WORDS.search(snippet) for _, snippet in settled)
            out.append((js.line(call), f"{js.snippet(call)} -> " + "; ".join(f"{s}" for _, s in settled[:2])))
        return out, money

    def _waits(self, wrapper) -> bool:
        """A wrapper around the send waits for the outcome: a project function that polls, or
        one from a library whose name says it waits."""
        name = callee_name(wrapper)
        defs = self.ctx.index.defs(name)
        return any(self._fn_polls(f, d, 0) for f, d in defs) if defs else bool(_WAITS.search(name))

    def _callers(self, js: JsFile, fn, depth: int = 0) -> list | None:
        """What the callers of a function returning a send result do with it: None when one
        polls or when nothing in the project calls it (once per function)."""
        key = (_node_key(js, fn), depth)
        if key not in self._caller_verdicts:
            self._caller_verdicts[key] = None  # a cycle reads as undecided
            self._caller_verdicts[key] = self._callers_of(js, fn, depth)
        return self._caller_verdicts[key]

    def _callers_of(self, js: JsFile, fn, depth: int) -> list | None:
        tree = self._tree(js)
        outer = tree.enclosing(fn)
        up = tree.up(fn, outer)
        if up is None:
            return None
        name = js_function_name(fn, up[0] if up else None)
        if not name:
            if len(up) < 2 or up[0].type != "arguments" or up[1].type != "call_expression":
                return None
            host = up[1]
            if _REGISTERS.match(callee_name(host)):
                # A tool or route handler: what it returns is the outcome its caller (a model, an
                # HTTP client) is told, unless it says the transaction is only pending.
                returns = [n for n in SourceIndex.walk(fn) if n.type == "return_statement"]
                if not any(_TENTATIVE_WORDS.search(_txt(r)) for r in returns):
                    return [(js.line(fn), "returned to the framework that called the handler")]
                return None
            # map, then, Promise.all, a retry helper: the results go back to the enclosing function.
            if outer is None or depth >= 2:
                return None
            _, names, wrappers, holder = _bound_names(host, up[2:])
            if any(self._waits(w) for w in wrappers):
                return None
            uses = self._uses(js, outer, names, host.end_byte) if names else _no_uses()
            if _undecided(uses):
                return None
            if uses["settled"]:
                return uses["settled"]
            if uses["returned"] or uses["claimed"] or (holder is not None and holder.type == "return_statement"):
                return self._callers(js, outer, depth + 1)
            return None
        settled, seen = [], False
        for other, call, caller in self._calls_named(name):
            if caller is None or caller == fn:
                continue
            seen = True
            call_up = self._tree(other).up(call, caller)
            if call_up is None:
                return None
            _, names, wrappers, _ = _bound_names(call, call_up)
            if any(self._waits(w) for w in wrappers):
                return None
            uses = self._uses(other, caller, names, call.end_byte) if names else _no_uses()
            if _undecided(uses):
                return None
            settled += [(line, f"{other.path}:{line} {snip}") for line, snip in uses["settled"]]
        return settled if seen and settled else None

    def _calls_named(self, name: str) -> list:
        """(file, call, the function it sits in) for every call by this name outside tests:
        one pass over the project."""
        if self._calls_by_name is None:
            found: dict[str, list] = {}
            for other in self.ctx.index.js.values():
                if TEST_PATH.search(other.path):
                    continue
                for callee, calls in self._tree(other).calls.items():
                    found.setdefault(callee, []).extend((other, call, fn) for call, fn in calls)
            self._calls_by_name = found
        return self._calls_by_name.get(name, [])

    def _tree(self, js: JsFile) -> _JsTree:
        tree = self._trees.get(js.path)
        if tree is None:
            tree = self._trees[js.path] = _JsTree(js.root)
        return tree

    # -------------------------------------------------- K1b: success read as "not failed"
    def not_failed_as_success(self, js: JsFile) -> list[tuple[int, str]]:
        """`x.status !== FAILED` (or NOT_FOUND) kept as the verdict on a getTransaction or
        pollTransaction result x. Each test is judged once, against the innermost function that
        binds its name to such a result (the binding it reads), in one sweep per name."""
        out = []
        if not re.search(r"getTransaction|pollTransaction", js.text):
            return out
        tree = self._tree(js)
        binders: dict[str, list[tuple[int, int, object, frozenset]]] = {}  # name -> (start, end, function, names)
        for call, fn in [c for name in ("getTransaction", "pollTransaction") for c in tree.calls.get(name, ())]:
            if fn is None or not self._is_rpc(js, receiver(call)):
                continue
            up = tree.up(call, fn)
            names = frozenset(_bound_names(call, up)[1]) if up is not None else frozenset()
            for name in names:
                binders.setdefault(name, []).append((fn.start_byte, fn.end_byte, fn, names))
        if not binders:
            return out
        failed, success = self._status_tests(js)
        compared = set()  # (name, function span) whose binding is compared with SUCCESS
        for name, spans in binders.items():
            spans.sort(key=lambda span: (span[0], -span[1]))  # functions nest: an outer one opens first
            for pos, span in _innermost(spans, success.get(name, ())):
                compared.add((name, span[0], span[1]))
        for name, spans in binders.items():
            starts, tests = failed.get(name, ((), ()))
            for k, span in _innermost(spans, starts, indexes=True):
                node, value, own = tests[k]
                lo, hi, fn, names = span
                holder = next((h for h in (tree.up(node, own) or ()) if h.type != "parenthesized_expression"), None)
                if holder is None or holder.type not in {"pair", "return_statement", "variable_declarator",
                                                         "assignment_expression"}:
                    continue
                held = _holder_name(holder, fn, tree)
                if not _SUCCESS_NAME.search(held):
                    # `finished = r.status !== NOT_FOUND` is a polling flag; a test that is not
                    # named as a verdict is fine when the same result is compared with SUCCESS.
                    if "NOT_FOUND" in value and _POLL_FLAG.search(held):
                        continue
                    if any((n, lo, hi) in compared for n in names):
                        continue
                out.append((js.line(node), js.snippet(node)))
        return out

    def _status_tests(self, js: JsFile) -> tuple[dict[str, tuple[list[int], list]], dict[str, list[int]]]:
        """(root name -> offsets and `x.status !== FAILED|NOT_FOUND` tests with the function each
        sits in, root name -> offsets where its status is compared with SUCCESS or switched on)
        in a file, in source order: one walk per file, swept against the functions binding each name."""
        key = ("status", js.path)
        if key not in self._memo:
            failed: dict[str, tuple[list[int], list]] = {}
            success: dict[str, list[int]] = {}
            stack = [(js.root, None)]
            while stack:
                node, own = stack.pop()
                stack.extend((child, node if js_functions_type(node) else own) for child in reversed(node.named_children))
                if node.type == "binary_expression":
                    op = _txt(node.child_by_field_name("operator"))
                    if op not in {"===", "==", "!==", "!="}:
                        continue
                    left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                    for status, other in ((left, right), (right, left)):
                        if other is None or other.end_byte - other.start_byte > 200 or not _is_status(status, {_root_identifier(status)}):
                            continue
                        value = _string_value(other) or _txt(other)
                        root = _root_identifier(status)
                        if op in {"!==", "!="} and re.search(r"FAILED|NOT_FOUND", value):
                            starts, tests = failed.setdefault(root, ([], []))
                            starts.append(node.start_byte)
                            tests.append((node, value, own))
                        if re.search(r"SUCCESS", value):
                            success.setdefault(root, []).append(node.start_byte)
                elif node.type == "switch_statement":
                    value = node.child_by_field_name("value")
                    if _is_status(value, {_root_identifier(value)}) and "SUCCESS" in _txt(node.child_by_field_name("body")):
                        success.setdefault(_root_identifier(value), []).append(node.start_byte)
            self._memo[key] = (failed, success)
        return self._memo[key]

    # -------------------------------------------------- K3: released or rebuilt after broadcast
    def release_after_send(self, js: JsFile) -> list[tuple[int, str]]:
        """Try blocks whose failure handler releases what was reserved although the block may
        have sent. One walk of the file finds each handler's first release that no flag or
        error test guards (in the handler's own function, outside the handlers nested in it);
        whether the block sends comes from one judgment of each call (_sends_within)."""
        out = []
        if "catch" not in js.text or not _RELEASE.search(js.text):
            return out
        tries, released, polls, assigned = [], {}, [], {}
        stack = [(js.root, -1, False)]  # node, index of the handler it sits in (-1: none), guarded
        while stack:
            node, at, guarded = stack.pop()
            kind = node.type
            if js_functions_type(node):
                at, guarded = -1, False
            elif kind == "try_statement":
                body, handler = node.child_by_field_name("body"), node.child_by_field_name("handler")
                catch = handler.child_by_field_name("body") if handler is not None else None
                if body is not None and catch is not None:
                    tries.append((handler, body, catch))
                    rest = node.child_by_field_name("finalizer")
                    stack.extend(item for item in ((rest, at, guarded), (catch, len(tries) - 1, False), (body, at, guarded))
                                 if item[0] is not None)  # the block before its handler: its flags are known there
                    continue
            elif kind == "if_statement" and at >= 0 and not guarded:
                guarded = _flag_test(_txt(node.child_by_field_name("condition")), tries[at][1], assigned)
            elif kind == "assignment_expression" and node.child_by_field_name("left").type in {"identifier", "member_expression"}:
                assigned.setdefault(_txt(node.child_by_field_name("left")), []).append(node.start_byte)  # sent = true
            elif kind == "call_expression":
                name = callee_name(node)
                if name in sdk.POLL_METHODS:
                    polls.append(node.start_byte)
                elif at >= 0 and not guarded and at not in released and _RELEASE.search(name) and _RESERVED.search(_txt(node)):
                    released[at] = node
            stack.extend((child, at, guarded) for child in reversed(node.named_children))
        for at, call in sorted(released.items()):
            handler, body, catch = tries[at]
            if not _within(polls, catch.start_byte, catch.end_byte) and self._sends_within(js, body.start_byte, body.end_byte, 0):
                out.append((js.line(handler), f"{js.snippet(handler)} -> {' '.join(_txt(call).split())[:100]}"))
        return out

    def _sends_within(self, js: JsFile, lo: int, hi: int, depth: int) -> bool:
        """Some call between two offsets of a file submits. The file's calls are judged in order
        at most once per call depth: an index skips past calls already judged not to submit."""
        tree = self._tree(js)
        sends, skip = self._sent.setdefault((js.path, depth), (set(), {}))
        j, seen = bisect_left(tree.starts, lo), []
        while j < len(tree.order) and tree.starts[j] < hi and j not in sends:
            if j in skip:
                seen.append(j)
                j = skip[j]
            elif self._call_submits(js, tree.order[j], depth):
                sends.add(j)
            else:
                seen.append(j)
                j += 1
        for k in seen:
            skip[k] = j
        return j in sends and tree.starts[j] < hi

    def _call_submits(self, js: JsFile, call, depth: int) -> bool:
        name = callee_name(call)
        if name in {"submitTransaction", "submitAsyncTransaction"} or \
                (name == "sendTransaction" and self._is_rpc(js, receiver(call))):
            return True
        if self._pays(js, call):
            return True
        if name in {"exec", "execSync", "spawn", "spawnSync", "execFile", "execa"} and \
                any(_STELLAR_CLI.search(_template_text(a) or _string_value(a) or "") for a in _args(call)):
            return True
        return depth < 2 and any(self._sends_within(other, fn.start_byte, fn.end_byte, depth + 1)
                                 for other, fn in self._js_targets(js, call))

    def _js_targets(self, js: JsFile, call) -> list[tuple[JsFile, object]]:
        """The project functions a call runs, followed only when the target is exact: `f()`
        declared in the calling function or at the top of this file or the project module it is
        imported from by name (`ns.f()` through a namespace import), `this.m()` or `super.m()` in
        the caller's class or a project class it extends, and `new C().m()` or `x.m()` after `x =
        new C()` in the same function, C a project class. A call on anything else (a parameter, a
        typed name, a field) is not followed: its target may be any class with that method."""
        fn = _unwrap(call.child_by_field_name("function"))
        if fn is None:
            return []
        scope = self._tree(js).scope.get((call.start_byte, call.end_byte))
        held = self._js_locals(js, scope) if scope is not None else {}
        if fn.type == "identifier":
            bound = held.get(_txt(fn), False)
            if bound is not False:
                return [(js, bound)] if bound is not None and not isinstance(bound, str) else []
            found = self._js_lookup(js, _txt(fn))
            return [found[1:]] if found and found[0] == "function" else []
        if fn.type != "member_expression":
            return []
        obj, name = _unwrap(fn.child_by_field_name("object")), _txt(fn.child_by_field_name("property")).lstrip("#")
        if obj is not None and obj.type in {"this", "super"}:
            cls = self._class_at(js, call)
            if cls is None:
                return []
            return self._js_methods(js, cls, name) if obj.type == "this" else \
                [m for base in self._js_bases(js, cls) for m in self._js_methods(*base, name)]
        if obj is not None and obj.type == "identifier" and _txt(obj) in held:
            built = held[_txt(obj)]  # `x = new C()` in this function
            found = self._js_lookup(js, built) if isinstance(built, str) else None
        elif obj is not None and obj.type == "new_expression":  # `new C().m()`
            found = self._js_lookup(js, _js_path(obj.child_by_field_name("constructor")))
        else:  # `ns.f()`
            found = self._js_lookup(js, f"{_js_path(obj)}.{name}") if _js_path(obj) else None
            return [found[1:]] if found and found[0] == "function" else []
        return self._js_methods(found[1], found[2], name) if found and found[0] == "class" else []

    def _js_locals(self, js: JsFile, fn) -> dict:
        """Name -> what one function binds it to, for each name it binds: the constructor of `x =
        new C(...)`, a function declared in it, or None (a parameter, any other value, or bound
        more than once). One walk per function, not descending into nested ones."""
        key = ("locals", js.path, fn.start_byte, fn.end_byte)
        found = self._memo.get(key)
        if found is None:
            bound: dict[str, list] = {}

            def unknown(node) -> None:
                for n in SourceIndex.walk(node):
                    if n.type in {"identifier", "shorthand_property_identifier_pattern"}:
                        bound.setdefault(_txt(n), []).append(None)
            params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
            if params is not None:
                unknown(params)
            stack = [fn.child_by_field_name("body")]
            while stack:
                node = stack.pop()
                if node is None:
                    continue
                if js_functions_type(node):
                    name = node.child_by_field_name("name") if node.type.endswith("function_declaration") else None
                    if name is not None:
                        bound.setdefault(_txt(name), []).append(node)
                    continue
                if node.type == "variable_declarator":
                    target = node.child_by_field_name("name")
                    if target is not None and target.type == "identifier":
                        bound.setdefault(_txt(target), []).append(_js_held(_unwrap(node.child_by_field_name("value"))))
                    elif target is not None:
                        unknown(target)
                elif node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        bound.setdefault(_txt(left), []).append(_js_held(_unwrap(node.child_by_field_name("right"))))
                elif node.type in {"for_in_statement", "catch_clause"}:
                    target = node.child_by_field_name("left") or node.child_by_field_name("parameter")
                    if target is not None:
                        unknown(target)
                elif node.type in _CLASS_TYPES and node.child_by_field_name("name") is not None:
                    bound.setdefault(_txt(node.child_by_field_name("name")), []).append(None)
                stack.extend(node.named_children)
            found = self._memo[key] = {name: values[0] if len(values) == 1 else None for name, values in bound.items()}
        return found

    def _js_names(self, js: JsFile) -> dict[str, tuple]:
        """What a file's top-level statements bind each name to: ("function", node), ("class",
        node), ("from", module, name) for a named or default import, ("module", module) for a
        namespace import or a require, ("alias", name) for `export default name`, or ("other",)
        (any other value, or bound more than once)."""
        key = ("names", js.path)
        found = self._memo.get(key)
        if found is None:
            found = self._memo[key] = {}

            def bind(name: str, entry: tuple) -> None:
                found[name] = entry if name not in found else ("other",)
            for stmt in js.root.named_children:
                if stmt.type == "import_statement":
                    source = _string_value(stmt.child_by_field_name("source")) or ""
                    for spec in SourceIndex.walk(stmt):
                        if spec.type == "import_specifier":
                            name = spec.child_by_field_name("name")
                            bind(_txt(spec.child_by_field_name("alias") or name), ("from", source, _txt(name)))
                        elif spec.type in {"import_clause", "namespace_import"}:
                            for child in spec.named_children:
                                if child.type == "identifier":
                                    bind(_txt(child), ("module", source) if spec.type == "namespace_import" else ("from", source, "default"))
                    continue
                decl, default = stmt, False
                if stmt.type == "export_statement":
                    default = any(c.type == "default" for c in stmt.children)
                    decl = stmt.child_by_field_name("declaration") or stmt.child_by_field_name("value")
                    if decl is not None and default and decl.type == "identifier":
                        bind("default", ("alias", _txt(decl)))
                        continue
                if decl is None:
                    continue
                kind = "function" if decl.type.endswith("function_declaration") else "class" if decl.type in _CLASS_TYPES else None
                if kind:
                    if decl.child_by_field_name("name") is not None:
                        bind(_txt(decl.child_by_field_name("name")), (kind, decl))
                    if default:
                        bind("default", (kind, decl))
                elif decl.type in {"lexical_declaration", "variable_declaration"}:
                    for item in decl.named_children:
                        target = item.child_by_field_name("name") if item.type == "variable_declarator" else None
                        value = _unwrap(item.child_by_field_name("value")) if target is not None else None
                        required = _string_value(_args(value)[0]) if value is not None and value.type == "call_expression" and \
                            _txt(value.child_by_field_name("function")) == "require" and _args(value) else None
                        if target is not None and target.type == "identifier":
                            bind(_txt(target), ("module", required) if required else ("function", value) if js_functions_type(value)
                                 else ("class", value) if value is not None and value.type in _CLASS_TYPES else ("other",))
                        elif target is not None and target.type == "object_pattern" and required:
                            for part in target.named_children:  # const { f, g: h } = require("./m")
                                if part.type == "shorthand_property_identifier_pattern":
                                    bind(_txt(part), ("from", required, _txt(part)))
                                elif part.type == "pair_pattern" and part.child_by_field_name("value") is not None:
                                    bind(_txt(part.child_by_field_name("value")), ("from", required, _txt(part.child_by_field_name("key"))))
        return found

    def _js_lookup(self, js: JsFile, dotted: str, depth: int = 0) -> tuple | None:
        """What a name or dotted name used in a file stands for, exactly: ("function", file, node),
        ("class", file, node) or ("module", file, None), through imports of project modules
        (re-exports included). A name the file does not bind at its top, or binds from outside
        the project, is None."""
        key = ("lookup", js.path, dotted)
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = None  # an import cycle reads as unknown
        found = None
        entry = self._js_names(js).get(dotted) if dotted and depth < 8 else None
        if entry is None and "." in dotted and depth < 8:
            head, _, last = dotted.rpartition(".")
            owner = self._js_lookup(js, head, depth + 1)
            found = self._js_lookup(owner[1], last, depth + 1) if owner and owner[0] == "module" else None
        elif entry is not None and entry[0] in {"function", "class"}:
            found = (entry[0], js, entry[1])
        elif entry is not None and entry[0] == "alias":
            found = self._js_lookup(js, entry[1], depth + 1)
        elif entry is not None and entry[0] in {"module", "from"}:
            module = self._js_module(js, entry[1])
            if module is not None:
                found = ("module", module, None) if entry[0] == "module" else self._js_lookup(module, entry[2], depth + 1)
        self._memo[key] = found
        return found

    def _js_module(self, js: JsFile, source: str) -> JsFile | None:
        """The one non-test project file an import names: a relative module (with its extension
        or index file), or for an aliased path (`@/lib/chain`) the only file whose path ends
        with the part after the alias."""
        if "stems" not in self._memo:  # module path (no extension, no /index) -> files; its shorter tails -> files
            stems: dict[str, list] = {}
            tails: dict[str, list] = {}
            for path, other in self.ctx.index.js.items():
                if TEST_PATH.search(path):
                    continue
                stem = re.sub(r"(?:/index)?\.[cm]?[jt]sx?$", "", path)
                stems.setdefault(stem, []).append(other)
                parts = stem.split("/")
                for i in range(1, len(parts)):
                    tails.setdefault("/".join(parts[i:]), []).append(other)
            self._memo["stems"], self._memo["tails"] = stems, tails
        if source.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(js.path), source))
            found = self._memo["stems"].get(re.sub(r"(?:/index)?\.[cm]?[jt]sx?$", "", base), [])
        else:
            alias = re.match(r"([@~#][\w.-]*)/(.+)", source)  # `@/x/y`, `~/x/y`, `@app/x/y`; not a package `@scope/pkg`
            tail = alias.group(2) if alias and (len(alias.group(1)) == 1 or "/" in alias.group(2)) else None
            found = self._memo["stems"].get(tail, []) + self._memo["tails"].get(tail, []) if tail else []
        return found[0] if len(found) == 1 else None

    def _js_methods(self, js: JsFile, cls, name: str, depth: int = 0) -> list[tuple[JsFile, object]]:
        """The methods `name` of a class: its own, else those of the project class it extends."""
        key = ("methods", js.path, cls.start_byte, name)
        if key not in self._memo:
            self._memo[key] = []  # an inheritance cycle reads as none
            own = [(js, f) for f in self._js_members(js, cls).get(name, [])]
            self._memo[key] = own or next((found for base in self._js_bases(js, cls) if depth < 8
                                           and (found := self._js_methods(*base, name, depth + 1))), [])
        return self._memo[key]

    def _js_members(self, js: JsFile, cls) -> dict[str, list]:
        """Method name -> its functions in a class body (methods and function-valued fields)."""
        key = ("members", js.path, cls.start_byte)
        table = self._memo.get(key)
        if table is None:
            table = self._memo[key] = {}
            body = cls.child_by_field_name("body")
            for member in body.named_children if body is not None else []:
                name = member.child_by_field_name("name") or member.child_by_field_name("property")
                value = member if member.type == "method_definition" else \
                    _unwrap(member.child_by_field_name("value")) if member.type in {"public_field_definition", "field_definition"} else None
                if name is not None and js_functions_type(value):
                    table.setdefault(_txt(name).lstrip("#"), []).append(value)
        return table

    def _js_bases(self, js: JsFile, cls) -> list[tuple[JsFile, object]]:
        heritage = next((_txt(c) for c in cls.named_children if c.type == "class_heritage"), "")
        parent = re.search(r"\bextends\s+([\w$.]+)", heritage)
        found = self._js_lookup(js, parent.group(1)) if parent else None
        return [found[1:]] if found and found[0] == "class" else []

    def _class_at(self, js: JsFile, node):
        """The class declaration a node sits in, from the file's class spans: one walk per file
        (a walk up the parents costs the node's depth at every step)."""
        key = ("class_spans", js.path)
        spans = self._memo.get(key)
        if spans is None:
            starts, ends, nodes, outer = [], [], [], []
            stack = [(js.root, -1)]
            while stack:
                n, enclosing = stack.pop()
                if n.type in _CLASS_TYPES:
                    starts.append(n.start_byte)
                    ends.append(n.end_byte)
                    nodes.append(n)
                    outer.append(enclosing)
                    enclosing = len(nodes) - 1
                stack.extend((child, enclosing) for child in reversed(n.named_children))
            spans = self._memo[key] = (starts, ends, nodes, outer)
        starts, ends, nodes, outer = spans
        pos = node.start_byte
        i = bisect_left(starts, pos) - 1  # the last class opened before the node, then its enclosing classes
        while i >= 0 and ends[i] <= pos:
            i = outer[i]
        return nodes[i] if i >= 0 else None

    def _js_built_as(self, js: JsFile, name: str) -> str | None:
        """The constructor this file first builds a name with (`new ethers.JsonRpcProvider`)."""
        key = ("built", js.path)
        if key not in self._memo:  # the first binding of every name, from one scan of the file
            built: dict[str, str] = {}
            for m in _JS_BUILT.finditer(js.text):
                built.setdefault(m.group(1), m.group(2))
            self._memo[key] = built
        return self._memo[key].get(name)

    def _pays(self, js: JsFile, call) -> bool:
        """An x402 paid request: a fetch with a payment header, or a fetch wrapped to pay."""
        name = callee_name(call)
        for arg in _args(call)[1:2]:
            headers = _unwrap(_props(arg).get("headers"))
            if headers is not None and headers.type == "object":
                for key in _props(headers):
                    if _PAYMENT_HEADER.match(key.strip("[]'\"`")) or re.search(r"payment", key, re.I) and key.startswith("["):
                        return True
        fn = _unwrap(call.child_by_field_name("function"))
        if fn is not None and fn.type == "identifier":
            key = ("made", js.path)
            if key not in self._memo:  # name -> what it is first assigned from, once per file
                made: dict[str, str] = {}
                for m in _JS_MADE.finditer(js.text):
                    made.setdefault(m.group(1), m.group(2))
                self._memo[key] = made
            maker = self._memo[key].get(name)
            if maker and _PAYING_FETCH.match(maker.rsplit(".", 1)[-1]):
                return True
            found = self._js_lookup(js, maker) if maker else None  # a project function that wraps fetch
            if found and found[0] == "function":
                key = ("pays", found[1].path, found[2].start_byte)
                if key not in self._memo:
                    self._memo[key] = any(_PAYING_FETCH.match(callee_name(c)) for c in SourceIndex.calls(found[2]))
                return self._memo[key]
        return False

    def paid_retry_loops(self, js: JsFile) -> list[tuple[int, str]]:
        """Attempt loops that repeat an x402 paid request: a request that was settled but
        failed afterwards is paid again on the next attempt."""
        out = []
        if "catch" not in js.text or not re.search(r"attempt|retr|tries", js.text, re.I):
            return out
        for node in SourceIndex.walk(js.root):
            if node.type not in {"for_statement", "while_statement", "do_statement"}:
                continue
            head = _txt(node)[: max(0, (node.child_by_field_name("body") or node).start_byte - node.start_byte)]
            if not re.search(r"attempt|retr|tries", head, re.I):
                continue
            body = node.child_by_field_name("body")
            for inner in SourceIndex.walk(body) if body is not None else []:
                if inner.type != "try_statement":
                    continue
                block, handler = inner.child_by_field_name("body"), inner.child_by_field_name("handler")
                catch = handler.child_by_field_name("body") if handler is not None else None
                if block is None or catch is None or _terminates(catch):
                    continue
                if any(self._pays(js, c) for c in SourceIndex.calls(block)):
                    out.append((js.line(node), js.snippet(node)))
                    break
        return out

    # -------------------------------------------------- K4, K5, K6, K8
    def skip_memo_check(self, js: JsFile) -> list[tuple[int, str]]:
        if "skipMemoRequiredCheck" not in js.text:
            return []
        return [(js.line(n), js.snippet(n)) for n in SourceIndex.walk(js.root)
                if n.type == "pair" and _txt(n.child_by_field_name("key")).strip("'\"") == "skipMemoRequiredCheck"
                and _txt(n.child_by_field_name("value")) == "true"]

    def huge_amounts(self, js: JsFile) -> list[tuple[int, str]]:
        out = []
        if "Operation" not in js.text:
            return out
        for call in SourceIndex.calls(js.root):
            recv = receiver(call)
            if callee_name(call) not in _OP_BUILDERS or recv is None or not _txt(recv).endswith("Operation"):
                continue  # Operation.payment(...), not stripe.payment(...)
            for arg in _args(call)[:1]:
                for key, value in _props(arg).items():
                    if key not in _AMOUNT_KEYS or value is None:
                        continue
                    for leaf in SourceIndex.walk(value):
                        text = _string_value(leaf) if leaf.type in {"string", "template_string"} else None
                        if text is not None and _decimal_over_max(text):
                            out.append((js.line(leaf), js.snippet(leaf)))
        return out

    def removed_symbols(self, js: JsFile) -> list[tuple[int, str, str]]:
        out = []
        if not any(symbol in js.text for _, symbol in sdk.JS_REMOVED_EXPORTS):
            return out
        namespaces = set()
        for node in SourceIndex.walk(js.root):
            source = None
            if node.type == "import_statement":
                source = _string_value(node.child_by_field_name("source"))
                clause = next((c for c in node.named_children if c.type == "import_clause"), None)
                if clause is None or re.match(r"import\s+type\b", _txt(node)):
                    continue  # `import type { SorobanRpc }` is erased: a compile error, not a run-time one
                for spec in SourceIndex.walk(clause):
                    if spec.type == "namespace_import":
                        namespaces |= {_txt(c) for c in spec.named_children if c.type == "identifier"}
                    if spec.type == "import_specifier" and not re.match(r"type\s", _txt(spec)):
                        imported = _txt(spec.child_by_field_name("name"))
                        if (source, imported) in sdk.JS_REMOVED_EXPORTS:
                            out.append((js.line(spec), js.snippet(node), imported))
            elif node.type == "variable_declarator":
                value = _unwrap(node.child_by_field_name("value"))
                target = node.child_by_field_name("name")
                if value is None or target is None or target.type != "object_pattern" or value.type != "call_expression":
                    continue
                if callee_name(value) not in {"require", "import"} and _txt(value.child_by_field_name("function")) != "import":
                    continue
                source = next((_string_value(a) for a in _args(value)), None)
                for child in target.named_children:
                    imported = _txt(child.child_by_field_name("key")) if child.type == "pair_pattern" else _txt(child)
                    if (source, imported) in sdk.JS_REMOVED_EXPORTS:
                        out.append((js.line(child), js.snippet(node), imported))
        for node in SourceIndex.walk(js.root):
            if node.type == "member_expression" and _txt(node.child_by_field_name("object")) in namespaces:
                prop = _txt(node.child_by_field_name("property"))
                if ("@stellar/stellar-sdk", prop) in sdk.JS_REMOVED_EXPORTS:
                    out.append((js.line(node), js.snippet(node), prop))
        return out

    def bigint_to_json(self, js: JsFile) -> list[tuple[int, str]]:
        """JSON.stringify (no replacer) of a value from scValToNative, which returns BigInt for
        every 64- and 128-bit integer: the call throws TypeError on such a value."""
        if "scValToNative" not in js.text or self.ctx.index.bigint_json_patched():
            return []
        out = []
        for call in SourceIndex.calls(js.root):
            if _dotted(call.child_by_field_name("function")) != "JSON.stringify" or len(_args(call)) != 1:
                continue
            fn = SourceIndex.enclosing_function(call) or js.root
            native = {_txt(d.child_by_field_name("name")) for d in SourceIndex.walk(fn)
                      if d.type == "variable_declarator" and d.child_by_field_name("name").type == "identifier"
                      and _unwrap(d.child_by_field_name("value")) is not None
                      and _unwrap(d.child_by_field_name("value")).type == "call_expression"
                      and callee_name(_unwrap(d.child_by_field_name("value"))) == "scValToNative"}
            arg = _args(call)[0]
            raw = [n for n in SourceIndex.walk(arg) if (n.type == "call_expression" and callee_name(n) == "scValToNative") or
                   (n.type in {"identifier", "shorthand_property_identifier"} and _txt(n) in native)]
            if any(not _converted(n, arg) for n in raw):
                out.append((js.line(call), js.snippet(call)))
        return out

    def meta_v3_only(self, js: JsFile) -> tuple[list[tuple[int, str]], bool]:
        """meta.v3() reads with no v4 branch, and whether one reads a transaction this code just
        submitted (the throw then reports a failure for a transaction that was applied)."""
        if "v3" not in js.text or \
                re.search(r"\.v4\s*\(|['\"]v4['\"]|transactionMetaV4|\.switch\(\)\s*(?:===|==)\s*4|case\s+4\s*:", js.text):
            return [], False
        places, after_send = [], False
        for call in SourceIndex.calls(js.root):
            recv = receiver(call)
            if callee_name(call) != "v3" or recv is None or not re.search(r"meta", _txt(recv), re.I):
                continue
            places.append((js.line(call), js.snippet(call)))
            fn = SourceIndex.enclosing_function(call)
            after_send = after_send or (fn is not None and any(
                re.search(r"submit|send", callee_name(c), re.I) and c.end_byte < call.start_byte for c in SourceIndex.calls(fn)))
        return sorted(places), after_send


def _js_path(node) -> str:
    """`a.b.c` for a chain of plain names, else ""."""
    parts, node = [], _unwrap(node)
    while node is not None and node.type == "member_expression":
        parts.append(_txt(node.child_by_field_name("property")))
        node = _unwrap(node.child_by_field_name("object"))
    return ".".join([_txt(node), *reversed(parts)]) if node is not None and node.type == "identifier" else ""


def _js_held(value):
    """What a binding holds, for call resolution: the constructor of `new C(...)` (as `C` or
    `ns.C`), a function, or None."""
    if value is not None and value.type == "new_expression":
        return _js_path(value.child_by_field_name("constructor")) or None
    return value if js_functions_type(value) else None


def _innermost(spans: list, offsets, indexes: bool = False):
    """(offset, or its index with ``indexes``; the innermost span holding it) for sorted offsets
    against sorted nested spans (start, end, ...), in one sweep with a stack of open spans."""
    stack, j = [], 0
    for k, pos in enumerate(offsets):
        while j < len(spans) and spans[j][0] <= pos:
            while stack and stack[-1][1] <= spans[j][0]:
                stack.pop()
            stack.append(spans[j])
            j += 1
        while stack and stack[-1][1] <= pos:
            stack.pop()
        if stack:
            yield (k if indexes else pos), stack[-1]


def _within(starts: list[int], lo: int, hi: int) -> bool:
    """Some offset of a sorted list falls in [lo, hi)."""
    i = bisect_left(starts, lo)
    return i < len(starts) and starts[i] < hi


def _no_uses() -> dict[str, list]:
    """How a send result is used: polled, settled, returned (as is, or `claimed` by a return
    or response that calls it final), unknown, or its status handed on."""
    return {"poll": [], "settled": [], "returned": [], "claimed": [], "unknown": [], "status": []}


def _undecided(uses: dict[str, list]) -> bool:
    """The result is polled, goes somewhere unknown, or only its status is handed on (the
    reader sees PENDING). A status logged or returned next to a write that marks the order
    paid, or next to a return that says it is confirmed, does not undo them."""
    return bool(uses["poll"] or uses["unknown"] or uses["status"] and not (uses["settled"] or uses["claimed"]))


def _says_final(text: str) -> bool:
    """Text that calls an outcome final: a final word that no tentative word, instruction or
    negation qualifies ("Payment confirmed", not "call getTransaction to confirm")."""
    if _TENTATIVE_WORDS.search(text):
        return False
    return any(not _NOT_A_CLAIM.search(text, max(0, m.start() - 40), m.start()) for m in _FINAL_WORDS.finditer(text))


def _node_key(js: JsFile, node) -> tuple:
    """A tree-sitter node's identity: each access returns a new wrapper object."""
    return js.path, node.start_byte, node.end_byte, node.type


def _root_identifier(node) -> str | None:
    node = _unwrap(node)
    while node is not None and node.type in {"member_expression", "subscript_expression", "call_expression"}:
        node = _unwrap(node.child_by_field_name("object") if node.type != "call_expression"
                       else node.child_by_field_name("function"))
    return _txt(node) if node is not None and node.type == "identifier" else None


def _is_status(node, names: set[str]) -> bool:
    node = _unwrap(node)
    return node is not None and node.type == "member_expression" and \
        _txt(node.child_by_field_name("property")) == "status" and _root_identifier(node) in names


def _holder_name(holder, fn, tree: _JsTree) -> str:
    """The name a status test is kept under: a key, a variable, a property, or for a returned
    test the function's own name."""
    if holder.type == "pair":
        return _txt(holder.child_by_field_name("key")).strip("'\"")
    if holder.type == "variable_declarator":
        return _txt(holder.child_by_field_name("name"))
    if holder.type == "assignment_expression":
        return _txt(holder.child_by_field_name("left")).rsplit(".", 1)[-1]
    return tree.function_name(fn) or ""


def _converted(node, scope) -> bool:
    """The value passes through String(), .toString(), Number() or similar before scope ends."""
    while node is not None and node != scope:
        parent = node.parent
        if parent is not None and parent.type == "call_expression" and callee_name(parent) in _TO_JSON_SAFE:
            return True
        if parent is not None and parent.type == "member_expression" and \
                _txt(parent.child_by_field_name("property")) in _TO_JSON_SAFE:
            return True
        node = parent
    return False


def _template_text(node) -> str | None:
    node = _unwrap(node)
    if node is not None and node.type == "template_string":
        return "".join(_txt(c) for c in node.named_children if c.type == "string_fragment")
    return None


def _flag_test(test: str, block, assigned: dict[str, list[int]]) -> bool:
    """A handler's test that keeps a release from running after a send: a name (or a prefix of
    a dotted name) assigned in the try block (`if (!sent)`, `if (!ctx.sent)`), or the error's
    class or code (`instanceof`, `e.code`)."""
    if re.search(r"instanceof|\.code\b|\.name\b|\.status\b", test):
        return True
    for m in re.finditer(r"(?<![\w$.])[\w$]+(?:\.[\w$]+)*", test):
        parts = m.group(0).split(".")
        if any(_within(assigned.get(".".join(parts[:k]), []), block.start_byte, block.end_byte) for k in range(1, len(parts) + 1)):
            return True
    return False


def _terminates(block) -> bool:
    stmts = [c for c in block.named_children if c.type != "comment"]
    return bool(stmts) and stmts[-1].type in {"throw_statement", "return_statement", "break_statement"}


# =========================================================================== findings
def _evidence(items: list[tuple[str, int, str]]) -> list[str]:
    return [f"{path}:{line} `{snippet[:170]}`" for path, line, snippet in items[:6]]


def rpc_findings(artifact: AgentArtifact, auditor) -> list[Finding]:
    """The SDK-semantics findings reported by the Stellar auditor (one per rule and file)."""
    ctx = _Context(artifact)
    py, js = _PyRules(ctx), _JsRules(ctx)
    findings: list[Finding] = []

    def add(rule: str, path: str, places: list[tuple[int, str]], severity: Severity, title: str, detail: str,
            remediation: str, refs: list[str], grade: EvidenceGrade, extra: str = "") -> None:
        severity = drop(severity, path)
        if severity is Severity.INFO or not places:
            return
        places = sorted(places)
        evidence = "; ".join(_evidence([(path, line, snip) for line, snip in places]) + ([extra] if extra else []))
        findings.append(auditor.finding(
            stable_id(rule, path, places[0][1]), severity, title, detail, evidence=evidence,
            remediation=remediation, references=refs, grade=grade, confidence=0.8 if grade is EvidenceGrade.INFERRED else 0.9))

    for path, source in ctx.index.py.items():
        if _skip(path) or not source.stellar:
            continue
        _, _, shown = ctx.version("stellar-sdk", path)
        misread = py.misread(source)
        if misread:
            moving = any(m for *_, m in misread)
            kinds = {k for k, *_ in misread}
            add("rpc-response-misread", path, [(line, snip) for _, line, snip, _ in misread],
                Severity.MEDIUM if moving else Severity.LOW,
                "A Soroban RPC result is read in a way the SDK never returns",
                ("The Python SDK's RPC results are pydantic models whose `status` is a plain Enum "
                 "(SendTransactionStatus, GetTransactionStatus): comparing it with a string is always False. "
                 if "compare" in kinds else "")
                + ("A field the installed release does not define raises AttributeError when read. "
                   if "field" in kinds else "")
                + ("On a path that signs and sends, the code then reports failure (or crashes) after the "
                   "transaction was broadcast, and a retry pays again." if moving else
                   "The read path fails or misreports every time."),
                "Compare with the enum members (GetTransactionStatus.SUCCESS) and read only the fields the "
                "response model defines (error_result_xdr on a send response).",
                ["stellar-sdk soroban_rpc response models", "Soroban RPC sendTransaction/getTransaction"],
                EvidenceGrade.CONFIRMED, shown)
        durability = py.durability(source)
        if durability:
            add("rpc-durability-as-string", path, durability, Severity.LOW,
                "Contract storage is read with a string durability",
                "get_contract_data compares durability with Durability.PERSISTENT and uses TEMPORARY for anything "
                "else, so 'persistent' passed as a string reads the temporary entry: persistent state looks missing.",
                "Pass Durability.PERSISTENT or Durability.TEMPORARY (stellar_sdk.soroban_server).",
                ["stellar-sdk SorobanServer.get_contract_data"], EvidenceGrade.CONFIRMED, shown)
        amounts = py.huge_amounts(source)
        if amounts:
            add("amount-above-int64", path, amounts, Severity.LOW,
                "An amount or limit is larger than any Stellar amount",
                f"Stellar amounts are int64 stroops: the largest is {sdk.MAX_AMOUNT}. A larger value is rejected "
                "when the operation is built, so this path always fails.",
                f"Use {sdk.MAX_AMOUNT} (or omit the limit for the maximum).", ["Stellar amount precision"],
                EvidenceGrade.CONFIRMED, shown)

    for path, source in ctx.index.js.items():
        if _skip(path):
            continue
        shown = ctx.version("@stellar/stellar-sdk", path)[2]
        settled, money = js.send_as_final(source)
        if settled:
            add("rpc-send-treated-as-final", path, settled, Severity.MEDIUM if money else Severity.LOW,
                "A transaction counts as done when it was only queued",
                "sendTransaction returns as soon as the RPC accepts the transaction (status PENDING); it can still "
                "fail or never be included. Here that result is stored, logged as confirmed or returned as the "
                "outcome, and nothing reads the final status with getTransaction or pollTransaction.",
                "Poll the hash (rpc.Server.pollTransaction or getTransaction) and act only on status SUCCESS.",
                ["Soroban RPC sendTransaction", "Soroban RPC getTransaction"], EvidenceGrade.INFERRED, shown)
        if source.stellar or "getTransaction" in source.text:
            weak = js.not_failed_as_success(source)
            if weak:
                add("rpc-outcome-not-success-checked", path, weak, Severity.MEDIUM,
                    "A transaction counts as successful because it did not fail",
                    "getTransaction and pollTransaction return NOT_FOUND while a transaction is unknown or when polling "
                    "runs out of attempts. Testing `!== FAILED` (or `!== NOT_FOUND`) treats those as success.",
                    "Accept only status === rpc.Api.GetTransactionStatus.SUCCESS.",
                    ["Soroban RPC getTransaction"], EvidenceGrade.CONFIRMED, shown)
        skips = js.skip_memo_check(source)
        if skips:
            add("memo-required-check-skipped", path, skips, Severity.MEDIUM,
                "Payments skip the SEP-29 memo-required check",
                "skipMemoRequiredCheck disables the check that refuses payments without a memo to accounts that "
                "require one (exchanges and custodians). Such a payment lands in the receiver's pooled account with "
                "nothing to credit it to.",
                "Leave the check on, or require a memo for every destination.", ["SEP-29"], EvidenceGrade.CONFIRMED, shown)
        amounts = js.huge_amounts(source)
        if amounts:
            add("amount-above-int64", path, amounts, Severity.LOW,
                "An amount or limit is larger than any Stellar amount",
                f"Stellar amounts are int64 stroops: the largest is {sdk.MAX_AMOUNT}. stellar-base rejects a larger "
                "value (isValidAmount), so the operation is never built on this path.",
                f"Use {sdk.MAX_AMOUNT}, or omit the trustline limit to get the maximum.", ["stellar-base Operation.isValidAmount"],
                EvidenceGrade.CONFIRMED, shown)
        removed = js.removed_symbols(source)
        if removed:
            exact, spec, _ = ctx.version("@stellar/stellar-sdk", path)
            first = sdk.JS_REMOVED_EXPORTS[("@stellar/stellar-sdk", removed[0][2])]
            installed = (exact is not None and below(exact, first) is False) or \
                        (exact is None and spec is not None and spec_admits(spec, None, first) is False)
            if installed:
                add("sdk-removed-symbol", path, [(line, snip) for line, snip, _ in removed], Severity.LOW,
                    f"{removed[0][2]} is imported from a release that no longer exports it",
                    f"@stellar/stellar-sdk removed {removed[0][2]} in {first} (use `rpc`). It is undefined here, so the "
                    "code that uses it throws a TypeError and never runs.",
                    "Import `rpc` from @stellar/stellar-sdk (or Server from @stellar/stellar-sdk/rpc).",
                    ["@stellar/stellar-sdk 13.0.0 changelog"], EvidenceGrade.CONFIRMED, shown)
        to_json = js.bigint_to_json(source)
        if to_json:
            add("bigint-to-json", path, to_json, Severity.LOW,
                "A contract result is serialised with JSON.stringify, which throws on BigInt",
                "scValToNative returns BigInt for i64, u64, i128 and u128 values (amounts, balances, ids). "
                "JSON.stringify without a replacer throws 'Do not know how to serialize a BigInt' on them, so the "
                "result is lost and the call reports an error.",
                "Pass a replacer that turns bigint into a string (JSON.stringify(v, (_, x) => typeof x === 'bigint' "
                "? x.toString() : x)).", ["stellar-base scValToNative"], EvidenceGrade.INFERRED, shown)
        meta, after_send = js.meta_v3_only(source)
        if meta:
            add("transaction-meta-v3-only", path, meta, Severity.MEDIUM if after_send else Severity.LOW,
                "Transaction results are read as TransactionMeta v3 only",
                "Since Protocol 23 the network returns TransactionMetaV4 (the testnet RPC returns v4 for every "
                "transaction). meta.v3() throws 'v3 not set' on a v4 result, so the code reports an error for a "
                "transaction that was applied" + (": right after submitting it, which invites a second submission."
                                                  if after_send else "."),
                "Branch on meta.switch() and read v4().sorobanMeta() (or use the parsed returnValue of getTransaction).",
                ["Stellar Protocol 23 (CAP-67)", "TransactionMetaV4"], EvidenceGrade.CONFIRMED, shown)
    return findings


def hardening_evidence(artifact: AgentArtifact) -> dict[str, list[str]]:
    """Evidence for two hardening rules: payment state released after a broadcast (retry may
    pay twice) and Python transactions built with no time bounds (never expire)."""
    ctx = _Context(artifact)
    py, js = _PyRules(ctx), _JsRules(ctx)
    released, no_expiry = [], []
    for path, source in ctx.index.py.items():
        if _skip(path):
            continue
        released += [f"{path}:{line} (released after a send: {snip[:120]})" for line, snip in py.release_after_send(source)]
        if source.stellar:
            no_expiry += [f"{path}:{line} (built without time bounds)" for line, _ in py.no_expiry(source)]
    for path, source in ctx.index.js.items():
        if _skip(path):
            continue
        released += [f"{path}:{line} (released after a send: {snip[:120]})" for line, snip in js.release_after_send(source)]
        released += [f"{path}:{line} (paid request retried)" for line, _ in js.paid_retry_loops(source)]
    return {"released": released, "no_expiry": no_expiry}
