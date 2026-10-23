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


class _PyDefs:
    """The non-test definitions of one function or method name, sorted once per project:
    module-level functions by file, methods by their class (node and name)."""
    __slots__ = ("plain", "by_owner", "by_class", "modules")

    def __init__(self, entries):
        self.plain: dict[str, list] = {}
        self.by_owner: dict[int, list] = {}
        self.by_class: dict[str, list] = {}
        self.modules: dict[str, list] = {}  # module -> its module-level functions of this name (memo)
        for py, fn in entries:
            if TEST_PATH.search(py.path):
                continue
            owner = _py_owner(py, fn)
            if owner is None:
                self.plain.setdefault(py.path, []).append((py, fn))
            elif isinstance(owner, ast.ClassDef):
                self.by_owner.setdefault(id(owner), []).append((py, fn))
                self.by_class.setdefault(owner.name, []).append((py, fn))

    def in_module(self, module: str) -> list:
        if module not in self.modules:
            self.modules[module] = [d for path, found in self.plain.items() if _module_is(path, module) for d in found]
        return self.modules[module]


class _PyRules:
    def __init__(self, ctx: _Context):
        self.ctx = ctx
        self._submits: dict[int, tuple[bool, int]] = {}  # verdict, depth judged at (_judged)
        self._set_submits: dict[tuple, tuple[bool, int]] = {}
        self._defs: dict[str, _PyDefs] = {}
        self._imported: dict[tuple, tuple[str, str | None] | None] = {}
        self._import_names: dict[str, dict[str, tuple]] = {}
        self._classes: dict[tuple, str | None] = {}
        self._frames: dict[str, dict[int, tuple]] = {}
        self._scope_classes: dict[int, dict] = {}
        self._attr_classes: dict[int, dict[str, str]] = {}
        self._standing: tuple[dict[str, set[str]], dict[str, set[str]]] | None = None

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
            if not isinstance(node, ast.Try):
                continue
            if not any(self._py_node_submits(py, stmt, 0) for stmt in node.body):
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

    def _py_node_submits(self, py: PyFile, stmt, depth: int) -> bool:
        return any(isinstance(n, ast.Call) and self._py_call_submits(py, n, depth, stmt) for n in ast.walk(stmt))

    def _py_call_submits(self, py: PyFile, call: ast.Call, depth: int, scope) -> bool:
        name = _py_name(call.func)
        if name in {"send_transaction", "submit_transaction"}:
            return True
        if any(k.arg == "send" and isinstance(k.value, ast.Constant) and k.value.value == "no" for k in call.keywords):
            return False
        dotted = unparse(call.func)
        if re.fullmatch(r"(?:subprocess\.)?(?:run|Popen|check_output|check_call|call)|os\.system", dotted):
            return self._py_cli_sends(call, scope)
        if depth >= 3:
            return False
        shared, targets = self._py_targets(py, call)
        if shared is None:
            return any(self._py_fn_submits(other, fn, depth) for other, fn in targets)
        # What a Protocol's method stands for: judged once per method, not once per call.
        return _judged(self._set_submits, shared, depth, lambda: any(self._py_fn_submits(other, fn, depth) for other, fn in targets))

    def _py_fn_submits(self, py: PyFile, fn, depth: int) -> bool:
        return _judged(self._submits, id(fn), depth, lambda: any(
            isinstance(n, ast.Call) and self._py_call_submits(py, n, depth + 1, fn) for n in _py_walk(fn)))

    def _py_defs(self, name: str) -> _PyDefs:
        if name not in self._defs:
            self._defs[name] = _PyDefs(self.ctx.index.py_defs.get(name, []))
        return self._defs[name]

    def _py_targets(self, py: PyFile, call: ast.Call, standing: bool = True) -> tuple[tuple | None, list[tuple[PyFile, ast.AST]]]:
        """(a key when the list is shared by every call of the method, the project functions a
        call runs), resolved through its receiver: `self.m()` in the caller's class, `f()`
        defined in the module or imported by name, `mod.f()` / `pkg.mod.f()` from an imported
        module, `obj.m()` where obj is annotated or built as a project class (here, inline as
        `C().m()`, or as a module-level instance imported from another module), a Protocol's
        stub standing for the classes that stand for the Protocol (_py_standing_for; with
        `standing` false, the stub itself). A method called on anything else (`cur.execute()`)
        is not followed: its name may belong to another class."""
        name = _py_name(call.func)
        if name not in self.ctx.index.py_defs:
            return None, []
        defs = self._py_defs(name)
        func = call.func
        if isinstance(func, ast.Name):
            local = defs.plain.get(py.path)
            if local:
                return None, local
            source = self._py_imported(py, name)
            return None, defs.in_module(source[0]) if source else []
        if not isinstance(func, ast.Attribute):
            return None, []
        recv, kind = func.value, None
        fn, cls = self._py_frame(py, call)
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"}:
            if cls is None:
                return None, []
            own = defs.by_owner.get(id(cls))
            if own:
                return None, own
            bases = sorted(b for b in {_py_annotation_class(b) for b in cls.bases} if b)  # inherited from a project class
            return None, [d for b in bases for d in defs.by_class.get(b, [])]
        if isinstance(recv, ast.Name):
            source = self._py_imported(py, recv.id)
            if source and source[1] is None:  # `import pkg.mod as m` / `from pkg import mod`
                return None, defs.in_module(source[0])
            key = (py.path, id(fn), recv.id)
            if key not in self._classes:
                self._classes[key] = self._py_class_of_name(py, fn, cls, recv.id) or (
                    self._py_module_instance(*source) if source else None)  # `from agent.chain import client`
            kind = self._classes[key]
        elif isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id == "self":
            kind = self._py_attr_classes(cls).get(recv.attr) if cls is not None else None
        elif isinstance(recv, ast.Attribute):
            dotted = _py_dotted(recv)  # `agent.chain.submit()` after `import agent.chain`
            if dotted and self._py_imported(py, dotted) == (dotted, None):
                return None, defs.in_module(dotted)
        elif isinstance(recv, ast.Call) and isinstance(recv.func, (ast.Name, ast.Attribute)) and \
                _py_name(recv.func)[:1].isupper():
            kind = _py_name(recv.func)  # `StellarClient().pay(env)`
        if not kind:
            return None, []
        own = defs.by_class.get(kind, [])
        if standing and own and all(_py_stub(d) for _, d in own):
            # A Protocol or an abstract base: the methods of the classes that stand for it.
            return ("standing", kind, name), [d for c in sorted(self._py_standing_for(kind))
                                              for d in defs.by_class.get(c, []) if not _py_stub(d[1])]
        return None, own

    def _py_frame(self, py: PyFile, call: ast.Call) -> tuple:
        """(function, class) a call sits in, from one walk per file: no parent walk per call."""
        frames = self._frames.get(py.path)
        if frames is None:
            frames = self._frames[py.path] = {}
            stack = [(py.tree, None, None)]
            while stack:
                node, fn, cls = stack.pop()
                if isinstance(node, ast.Call):
                    frames[id(node)] = (fn, cls)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = node
                elif isinstance(node, ast.ClassDef):
                    cls = node
                stack.extend((child, fn, cls) for child in ast.iter_child_nodes(node))
        return frames.get(id(call), (None, None))

    def _py_class_of_name(self, py: PyFile, fn, cls, name: str) -> str | None:
        """The class a local name holds in the calling function, else at module level."""
        for scope in ([fn] if fn is not None else []) + [py.tree]:
            found = self._py_scope_classes(scope).get(name)
            if isinstance(found, tuple):  # `client = self.a or self.b`
                found = next((c for attr in found if cls is not None and (c := self._py_attr_classes(cls).get(attr))), None)
            if found:
                return found
        return None

    def _py_scope_classes(self, scope) -> dict:
        """name -> the class it holds in one function (a parameter annotation, else its last
        `name: C = ...` or `name = C(...)`; `name = self.a or self.b` gives the attributes) or
        at module level (the first such statement): once per scope, not once per name."""
        found = self._scope_classes.get(id(scope))
        if found is None:
            found = self._scope_classes[id(scope)] = {}
            module = isinstance(scope, ast.Module)
            nodes = scope.body if module else sorted(
                (n for n in _py_walk(scope) if isinstance(n, (ast.Assign, ast.AnnAssign))), key=lambda n: (n.lineno, n.col_offset))
            for node in nodes:
                held = None
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    held, targets = _py_annotation_class(node.annotation), [node.target.id]
                elif isinstance(node, ast.Assign):
                    targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                    held = _py_built_class(node.value) or (None if module else _py_self_attrs(node.value))
                if held:
                    for target in targets:
                        if module:
                            found.setdefault(target, held)
                        else:
                            found[target] = held
            if not module:
                for arg in [*scope.args.args, *scope.args.kwonlyargs, *scope.args.posonlyargs]:
                    if arg.annotation is not None and (held := _py_annotation_class(arg.annotation)):
                        found[arg.arg] = held
        return found

    def _py_attr_classes(self, cls: ast.ClassDef) -> dict[str, str]:
        """attr -> the class `self.attr` holds: `attr: C` in the class body, `self.attr = C(...)`
        or `self.attr = param` with param annotated in a method; once per class."""
        found = self._attr_classes.get(id(cls))
        if found is None:
            found = self._attr_classes[id(cls)] = {}
            for node in cls.body:
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and \
                        (held := _py_annotation_class(node.annotation)):
                    found.setdefault(node.target.id, held)
            for method in cls.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = {a.arg: a.annotation for a in [*method.args.args, *method.args.kwonlyargs] if a.annotation is not None}
                local: dict[str, str] = {}
                for node in sorted((n for n in _py_walk(method) if isinstance(n, (ast.Assign, ast.AnnAssign))),
                                   key=lambda n: (n.lineno, n.col_offset)):
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if not (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self"):
                            continue
                        if isinstance(node, ast.AnnAssign):
                            held = _py_annotation_class(node.annotation)
                        elif isinstance(node.value, ast.Name) and node.value.id in params:
                            held = _py_annotation_class(params[node.value.id])
                        else:
                            held = _py_built_class(node.value)
                        if held:
                            local[target.attr] = held
                for attr, held in local.items():
                    found.setdefault(attr, held)
        return found

    def _py_standing_for(self, protocol: str) -> set[str]:
        """The project classes a Protocol or abstract base stands for: its subclasses, and the
        classes the project builds where it is expected (returned by a function annotated to
        return it, assigned to a name annotated with it, or passed for a parameter annotated
        with it), with their subclasses. A class that only shares a method name is not one."""
        if self._standing is None:
            self._standing = self._py_expected()
        subclasses, expected = self._standing
        found: set[str] = set()
        todo = list(subclasses.get(protocol, set()) | expected.get(protocol, set()))
        while todo:
            name = todo.pop()
            if name not in found and name != protocol:
                found.add(name)
                todo.extend(subclasses.get(name, ()))
        return found

    def _py_expected(self) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """(base -> its subclasses, annotated class -> the classes built for it) over the
        project's non-test modules, in one walk per module. A class passed for an annotated
        parameter counts only when the call resolves to its function (_py_targets): a project
        name index would merge every function of that name."""
        subclasses: dict[str, set[str]] = {}
        expected: dict[str, set[str]] = {}
        classes: set[str] = set()
        for py in self.ctx.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for node in ast.walk(py.tree):
                if isinstance(node, ast.ClassDef):
                    classes.add(node.name)
                    for base in node.bases:
                        if (name := _py_annotation_class(base)):
                            subclasses.setdefault(name, set()).add(node.name)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    wanted = _py_annotation_class(node.returns) if node.returns is not None else None
                    if wanted:
                        for ret in _py_walk(node):
                            if isinstance(ret, ast.Return) and ret.value is not None:
                                built = _py_built_class(ret.value) or (
                                    self._py_scope_classes(node).get(ret.value.id) if isinstance(ret.value, ast.Name) else None)
                                if isinstance(built, str):
                                    expected.setdefault(wanted, set()).add(built)
                    args = node.args
                    for arg, default in [*zip(args.args[len(args.args) - len(args.defaults):], args.defaults),
                                         *zip(args.kwonlyargs, args.kw_defaults)]:
                        if default is not None and arg.annotation is not None and (built := _py_built_class(default)) \
                                and (wanted := _py_annotation_class(arg.annotation)):
                            expected.setdefault(wanted, set()).add(built)
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    if (built := _py_built_class(node.value)) and (wanted := _py_annotation_class(node.annotation)):
                        expected.setdefault(wanted, set()).add(built)
                elif isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
                    table = None
                    for at, value in [*enumerate(node.args), *((k.arg, k.value) for k in node.keywords if k.arg)]:
                        built = _py_built_class(value)
                        if built is None and isinstance(value, ast.Name):
                            fn, _ = self._py_frame(py, node)
                            built = self._py_scope_classes(fn if fn is not None else py.tree).get(value.id)
                        if isinstance(built, str):
                            table = self._py_param_classes(py, node) if table is None else table
                            if (wanted := table.get(at)):
                                expected.setdefault(wanted, set()).add(built)
        return subclasses, {wanted: built & classes for wanted, built in expected.items()}

    def _py_param_classes(self, py: PyFile, call: ast.Call) -> dict[int | str, str]:
        """position or keyword -> the class its parameter is annotated with, in the functions
        the call resolves to (_py_targets, the Protocol's stub itself); a parameter they do not
        all annotate with the same class is left out, as is any call that does not resolve."""
        tables = []
        for other, fn in self._py_targets(py, call, standing=False)[1]:
            table: dict[int | str, str] = {}
            positional = [*fn.args.posonlyargs, *fn.args.args]
            if isinstance(_py_owner(other, fn), ast.ClassDef):
                positional = positional[1:]  # self
            for i, arg in enumerate(positional):
                if arg.annotation is not None and (wanted := _py_annotation_class(arg.annotation)):
                    table[i] = table[arg.arg] = wanted
            for arg in fn.args.kwonlyargs:
                if arg.annotation is not None and (wanted := _py_annotation_class(arg.annotation)):
                    table[arg.arg] = wanted
            tables.append(table)
        if not tables:
            return {}
        return {at: wanted for at, wanted in tables[0].items() if all(t.get(at) == wanted for t in tables[1:])}

    def _py_imported(self, py: PyFile, name: str) -> tuple[str, str | None] | None:
        """(module, imported name) a local name comes from: `from a.b import name` -> ("a.b",
        "name"); `import a.b as name`, `import a.b` (for the name `a.b`), or `from a import b`
        where a/b.py is a project module -> ("a.b", None). Once per file and name, from one
        index of the file's imports (the first statement that binds the name)."""
        key = (py.path, name)
        if key not in self._imported:
            names = self._import_names.get(py.path)
            if names is None:
                names = self._import_names[py.path] = {}
                for node in py.tree.body:
                    if isinstance(node, ast.Import) or (isinstance(node, ast.ImportFrom) and node.module):
                        bound = {alias.asname or alias.name: (node, alias) for alias in node.names}  # the last alias wins
                        for local, entry in bound.items():
                            names.setdefault(local, entry)
            found, entry = None, names.get(name)
            if entry and isinstance(entry[0], ast.ImportFrom):
                node, alias = entry
                dotted = f"{node.module}.{alias.name}"
                module = any(_module_is(path, dotted) for path in self.ctx.index.py)
                found = (dotted, None) if module else (node.module, alias.name)
            elif entry:
                found = (entry[1].name, None)
            self._imported[key] = found
        return self._imported[key]

    def _py_module_instance(self, module: str, name: str | None) -> str | None:
        """The class of a module-level instance another module imports by name: `client =
        StellarClient()` or `client: StellarClient = ...` in that module."""
        key = ("instance", module, name)
        if key not in self._classes:
            found = None
            for path, other in self.ctx.index.py.items():
                if name is None or not _module_is(path, module) or TEST_PATH.search(path):
                    continue
                for node in other.tree.body:
                    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
                        found = _py_annotation_class(node.annotation)
                    elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                        built = _py_call(node.value)
                        if built is not None and isinstance(built.func, (ast.Name, ast.Attribute)) and \
                                _py_name(built.func)[:1].isupper():
                            found = _py_name(built.func)
            self._classes[key] = found
        return self._classes[key]

    def _py_cli_sends(self, call: ast.Call, scope) -> bool:
        words: list[str] = []
        for arg in call.args[:1]:
            words += _py_strings(arg)
            if isinstance(arg, ast.Name):
                for node in ast.walk(scope):
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in node.targets):
                        words += _py_strings(node.value)
                        built = _py_call(node.value)
                        for _, fn in self.ctx.index.py_defs.get(_py_name(built.func) if built else "", []):
                            words += _py_strings(fn)
        text = " ".join(words)
        return bool(_STELLAR_CLI.search(text)) and not re.search(r"--send[= ]no\b", text)


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


def _py_owner(py: PyFile, fn: ast.AST):
    """What a function belongs to: its class (a method), None (a module-level function), or
    False (a function nested in another, which no call from outside reaches by name)."""
    parent = py.parents.get(fn)
    return parent if isinstance(parent, ast.ClassDef) else None if isinstance(parent, ast.Module) else False


def _module_is(path: str, dotted: str) -> bool:
    """The file is the module `a.b` (a/b.py or a/b/__init__.py, under any source root)."""
    stem = path[:-3] if path.endswith(".py") else path
    stem = stem[:-9] if stem.endswith("/__init__") else stem
    return ("/" + stem).endswith("/" + dotted.replace(".", "/"))


def _py_annotation_class(node) -> str | None:
    """`C`, `mod.C`, `Optional[C]`, `C | None` -> C (the first class named, left to right; no
    recursion, so a long union cannot overflow the stack)."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Subscript):
            stack.append(node.slice)
        elif isinstance(node, ast.BinOp):
            stack.extend((node.right, node.left))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.fullmatch(r"[\w.]+", node.value):
                return node.value.rsplit(".", 1)[-1]
        elif isinstance(node, (ast.Name, ast.Attribute)):
            return node.id if isinstance(node, ast.Name) else node.attr
    return None


def _py_built_class(value) -> str | None:
    """`C(...)` or `mod.C(...)` (a capitalised callee) -> C."""
    built = _py_call(value)
    if built is not None and isinstance(built.func, (ast.Name, ast.Attribute)) and _py_name(built.func)[:1].isupper():
        return _py_name(built.func)
    return None


def _py_self_attrs(value) -> tuple[str, ...] | None:
    """`self.a`, `self.a or self.b`, `self.a if x else self.b` -> the attribute names, in order."""
    attrs, stack = [], [value]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            attrs.append(node.attr)
        elif isinstance(node, ast.BoolOp):
            stack.extend(reversed(node.values))
        elif isinstance(node, ast.IfExp):
            stack.extend((node.orelse, node.body))
    return tuple(attrs) or None


def _py_stub(fn: ast.AST) -> bool:
    """A Protocol or abstract method: a docstring, `...`, `pass` or `raise NotImplementedError`."""
    body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]
    return all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is ...)
               or (isinstance(s, ast.Raise) and "NotImplementedError" in unparse(s)) for s in body)


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
#: brackets and commas, so `f(a: string, b = new C(` binds b) and `name: C` (typed as).
_JS_BUILT = re.compile(r"(?<![\w$.])(?:this\.)?#?([\w$]+)\s*(?:\??:[^=;\n(){},]{0,120})?=\s*(?:await\s+)?new\s+"
                       r"((?:[\w$]+\.)*[\w$]+)\s*[(<]")
_JS_TYPED = re.compile(r"(?<![\w$.])#?([\w$]+)\s*\??:\s*(?:[\w$]+\.)*([A-Z][\w$]*)\b(?!\s*[.<\[])")
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
    """One file's calls by callee name with the function each sits in, and each function's
    enclosing function, from one walk (no parent lookups)."""
    __slots__ = ("root", "calls", "outer")

    def __init__(self, root):
        self.root = root
        self.calls: dict[str, list] = {}
        self.outer: dict[tuple, object] = {}
        stack = [(root, None)]
        while stack:
            node, fn = stack.pop()
            if node.type == "call_expression":
                self.calls.setdefault(callee_name(node), []).append((node, fn))
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


class _JsDefs:
    """The non-test functions of one name, sorted once per project: plain functions and object
    literal properties by file, methods by class name and by class node."""
    __slots__ = ("plain", "literal", "not_class", "by_class", "by_class_node")

    def __init__(self, entries, class_at):
        self.plain: dict[str, list] = {}
        self.literal: dict[str, list] = {}
        self.not_class: dict[str, list] = {}
        self.by_class: dict[str, list] = {}
        self.by_class_node: dict[tuple, list] = {}
        for js, fn in entries:
            cls = class_at(js, fn)
            owner = _js_owner(fn, cls)
            if owner is None:
                self.plain.setdefault(js.path, []).append((js, fn))
            elif owner is True:
                self.literal.setdefault(js.path, []).append((js, fn))
            if not isinstance(owner, str):
                self.not_class.setdefault(js.path, []).append((js, fn))
            else:
                self.by_class.setdefault(owner, []).append((js, fn))
            if cls is not None:
                self.by_class_node.setdefault((js.path, cls.start_byte), []).append((js, fn))


class _JsRules:
    def __init__(self, ctx: _Context):
        self.ctx = ctx
        self._defs: dict[str, _JsDefs | None] = {}
        self._memo: dict[tuple, object] = {}
        self._sends: dict[tuple, tuple[bool, int]] = {}
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
        out = []
        if "catch" not in js.text or not _RELEASE.search(js.text):
            return out
        for node in SourceIndex.walk(js.root):
            if node.type != "try_statement":
                continue
            body, handler = node.child_by_field_name("body"), node.child_by_field_name("handler")
            if body is None or handler is None or not self._submits(js, body, 0):
                continue
            catch = handler.child_by_field_name("body")
            if catch is None or any(callee_name(c) in sdk.POLL_METHODS for c in SourceIndex.calls(catch)):
                continue
            flags = {_txt(a.child_by_field_name("left")) for a in SourceIndex.walk(body)
                     if a.type == "assignment_expression" and a.child_by_field_name("left").type in
                     {"identifier", "member_expression"}}  # transmitted = true; this.transmitted = true
            for call in SourceIndex.calls(catch, include_nested=False):
                name = callee_name(call)
                if _RELEASE.search(name) and _RESERVED.search(_txt(call)) and not _guarded(call, catch, flags):
                    out.append((js.line(handler), f"{js.snippet(handler)} -> {' '.join(_txt(call).split())[:100]}"))
                    break
        return out

    def _submits(self, js: JsFile, node, depth: int) -> bool:
        for call in SourceIndex.calls(node):
            name = callee_name(call)
            if name in {"submitTransaction", "submitAsyncTransaction"} or \
                    (name == "sendTransaction" and self._is_rpc(js, receiver(call))):
                return True
            if self._pays(js, call):
                return True
            if name in {"exec", "execSync", "spawn", "spawnSync", "execFile", "execa"} and \
                    any(_STELLAR_CLI.search(_template_text(a) or _string_value(a) or "") for a in _args(call)):
                return True
            if depth < 2:
                for other, fn in self._js_targets(js, call):
                    if _judged(self._sends, _node_key(other, fn), depth, lambda: self._submits(other, fn, depth + 1)):
                        return True
        return False

    def _js_targets(self, js: JsFile, call) -> list[tuple[JsFile, object]]:
        """The project functions a call runs, resolved through its receiver: `f()` defined in
        this file or imported by name, `this.m()` in the caller's class, `mod.f()` on an
        imported module, `obj.m()` where obj is built or typed as a project class (here, inline
        as `new C().m()`, or as an instance another module exports) or is an object literal of
        this file. A method called on anything else (`db.execute()`) is not followed: its name
        may belong to another class."""
        name = callee_name(call)
        defs = self._js_defs(name)
        fn = _unwrap(call.child_by_field_name("function"))
        if defs is None or fn is None:
            return []
        if fn.type == "identifier":
            local = defs.plain.get(js.path)
            if local:
                return local
            return [d for path, found in defs.plain.items() if path != js.path for d in found] \
                if _txt(fn) in _js_imports(js) else []
        if fn.type != "member_expression":
            return []
        obj = _unwrap(fn.child_by_field_name("object"))
        if obj is not None and obj.type == "this":
            cls = self._class_at(js, call)
            if cls is None:
                return []
            own = defs.by_class_node.get((js.path, cls.start_byte), [])
            if own:
                return own
            heritage = next((_txt(c) for c in cls.named_children if c.type == "class_heritage"), "")
            parent = re.search(r"\bextends\s+(?:[\w$]+\.)*([\w$]+)", heritage)  # inherited from a project class
            return defs.by_class.get(parent.group(1), []) if parent else []
        if obj is not None and obj.type == "identifier" and _js_imports(js).get(_txt(obj)) in {"namespace", "default"}:
            return [d for path, found in defs.not_class.items() if path != js.path for d in found]
        if obj is not None and obj.type == "new_expression":  # `new StellarService().pay(tx)`
            ctor = obj.child_by_field_name("constructor")
            return defs.by_class.get(_txt(ctor).rsplit(".", 1)[-1], []) if ctor is not None else []
        holder = _js_holder(obj)
        if not holder:
            return []
        kind = self._js_class_of(js, holder)
        if kind is None and obj.type == "identifier" and _js_imports(js).get(holder) == "named":
            kind = next((k for other in self._js_modules(js, holder) if (k := self._js_class_of(other, holder))), None)
        if kind:
            return defs.by_class.get(kind, [])
        literal = self._js_literal_of(js, holder)
        if literal is not None:
            return [(f, d) for f, d in defs.literal.get(js.path, []) if literal[0] <= d.start_byte < literal[1]]
        return []

    def _js_defs(self, name: str) -> _JsDefs | None:
        if name not in self._defs:
            found = [(f, d) for f, d in self.ctx.index.defs(name) if not TEST_PATH.search(f.path)]
            self._defs[name] = _JsDefs(found, self._class_at) if found else None
        return self._defs[name]

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

    def _js_class_of(self, js: JsFile, name: str) -> str | None:
        """The class a name holds in this file: `name = new C(...)`, `this.name = new C(...)`,
        else `name: C` (a parameter, a variable or a field). The file is read once for every
        name (the first binding of each), not once per name."""
        key = ("classes", js.path)
        if key not in self._memo:
            built: dict[str, str] = {}
            typed: dict[str, str] = {}
            for m in _JS_BUILT.finditer(js.text):
                built.setdefault(m.group(1), m.group(2))  # the constructor as written: `rpc.Server`
            for m in _JS_TYPED.finditer(js.text):
                typed.setdefault(m.group(1), m.group(2))
            self._memo[key] = (built, typed)
        built, typed = self._memo[key]
        found = built.get(name)
        return found.rsplit(".", 1)[-1] if found else typed.get(name)

    def _js_built_as(self, js: JsFile, name: str) -> str | None:
        """The constructor this file first builds a name with (`new ethers.JsonRpcProvider`)."""
        self._js_class_of(js, name)
        return self._memo[("classes", js.path)][0].get(name)

    def _js_literal_of(self, js: JsFile, name: str) -> tuple[int, int] | None:
        key = ("literal", js.path)
        if key not in self._memo:  # name -> range of the object literal it is declared with, once per file
            found: dict[str, tuple[int, int] | None] = {}
            for node in SourceIndex.walk(js.root):
                if node.type == "variable_declarator":
                    target = _txt(node.child_by_field_name("name"))
                    if target not in found:
                        value = _unwrap(node.child_by_field_name("value"))
                        found[target] = (value.start_byte, value.end_byte) if value is not None and value.type == "object" else None
            self._memo[key] = found
        return self._memo[key].get(name)

    def _js_modules(self, js: JsFile, name: str) -> list[JsFile]:
        """The project files a named import may come from: the relative module it names
        (with its extension or index file), or for an aliased path (`@/lib/chain`) the files
        named like its last segment."""
        key = ("module", js.path, name)
        if key not in self._memo:
            if "stems" not in self._memo:  # module path (no extension, no /index) -> files; last segment -> files
                stems: dict[str, list] = {}
                lasts: dict[str, list] = {}
                for path, other in self.ctx.index.js.items():
                    stem = re.sub(r"(?:/index)?\.[cm]?[jt]sx?$", "", path)
                    stems.setdefault(stem, []).append(other)
                    lasts.setdefault(stem.rsplit("/", 1)[-1], []).append(other)
                self._memo["stems"], self._memo["lasts"] = stems, lasts
            source = _js_import_sources(js).get(name) or ""
            found = []
            if source.startswith("."):
                base = posixpath.normpath(posixpath.join(posixpath.dirname(js.path), source))
                found = self._memo["stems"].get(re.sub(r"(?:/index)?\.[cm]?[jt]sx?$", "", base), [])
            elif not source.startswith(("@stellar/", "node:")) and "/" in source:
                found = self._memo["lasts"].get(source.rstrip("/").rsplit("/", 1)[-1], [])
            self._memo[key] = [other for other in found if other is not js]
        return self._memo[key]

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
                    made.setdefault(m.group(1), m.group(2).rsplit(".", 1)[-1])
                self._memo[key] = made
            maker = self._memo[key].get(name)
            if maker:
                if _PAYING_FETCH.match(maker):
                    return True
                key = ("pays", maker)
                if key not in self._memo:
                    self._memo[key] = any(_PAYING_FETCH.match(callee_name(c)) for f, d in self.ctx.index.defs(maker)
                                          for c in SourceIndex.calls(d))
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


def _js_holder(obj) -> str:
    """The name a receiver is held under: `client` or `this.client` -> client."""
    if obj is not None and obj.type == "identifier":
        return _txt(obj)
    if obj is not None and obj.type == "member_expression":
        base = _unwrap(obj.child_by_field_name("object"))
        if base is not None and base.type == "this":
            return _txt(obj.child_by_field_name("property"))
    return ""


def _js_owner(fn, cls) -> str | bool | None:
    """What a function belongs to (cls: the class it sits in): the name of its class (a method),
    True (a property of an object literal), or None (a function declared on its own)."""
    parent = fn.parent
    if fn.type == "method_definition" or (parent is not None and parent.type in {"public_field_definition", "field_definition"}):
        if cls is not None:
            name = cls.child_by_field_name("name")
            return _txt(name) if name is not None else True
        return True  # a method of an object literal
    if parent is not None and parent.type == "pair":
        return True
    return None


def _js_imports(js: JsFile) -> dict[str, str]:
    """Local name -> how it is imported: "named", "default" or "namespace" (ES imports and
    `const { f } = require(...)`); once per file."""
    found = getattr(js, "_imports", None)
    if found is None:
        found = {}
        for node in SourceIndex.walk(js.root):
            if node.type == "import_statement":
                for spec in SourceIndex.walk(node):
                    if spec.type == "import_specifier":
                        alias = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                        found[_txt(alias)] = "named"
                    elif spec.type == "namespace_import":
                        found.update({_txt(c): "namespace" for c in spec.named_children if c.type == "identifier"})
                    elif spec.type == "import_clause":
                        found.update({_txt(c): "default" for c in spec.named_children if c.type == "identifier"})
            elif node.type == "variable_declarator" and _txt(node.child_by_field_name("value")).startswith("require("):
                target = node.child_by_field_name("name")
                if target is not None and target.type == "identifier":
                    found[_txt(target)] = "default"
                elif target is not None:
                    found.update({_txt(n): "named" for n in SourceIndex.walk(target)
                                  if n.type in {"shorthand_property_identifier_pattern", "identifier"}})
        js._imports = found
    return found


def _js_import_sources(js: JsFile) -> dict[str, str]:
    """Local name -> the module it is imported from (ES imports and `const { f } = require()`);
    once per file."""
    found = getattr(js, "_import_sources", None)
    if found is None:
        found = {}
        for node in SourceIndex.walk(js.root):
            if node.type == "import_statement":
                source = _string_value(node.child_by_field_name("source")) or ""
                for spec in SourceIndex.walk(node):
                    if spec.type == "import_specifier":
                        alias = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                        found[_txt(alias)] = source
                    elif spec.type in {"namespace_import", "import_clause"}:
                        found.update({_txt(c): source for c in spec.named_children if c.type == "identifier"})
            elif node.type == "variable_declarator" and _txt(node.child_by_field_name("value")).startswith("require("):
                value = node.child_by_field_name("value")
                source = next((_string_value(a) for a in _args(value)), None) or ""
                target = node.child_by_field_name("name")
                if target is not None:
                    found.update({_txt(n): source for n in SourceIndex.walk(target)
                                  if n.type in {"shorthand_property_identifier_pattern", "identifier"}})
        js._import_sources = found
    return found


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


def _guarded(call, scope, flags: set[str]) -> bool:
    """The release only runs when a flag set in the try block says nothing was sent, or
    for an error class the code tests explicitly."""
    node = call.parent
    while node is not None and node != scope:
        if node.type == "if_statement":
            test = _txt(node.child_by_field_name("condition"))
            if any(re.search(r"(?<![\w$.])" + re.escape(f) + r"(?![\w$])", test) for f in flags) or \
                    re.search(r"instanceof|\.code\b|\.name\b|\.status\b", test):
                return True
        node = node.parent
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
