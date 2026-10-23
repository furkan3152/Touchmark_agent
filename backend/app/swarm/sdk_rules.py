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
import re

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
        self._submits: dict[int, bool] = {}

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
        for other, fn in self._py_targets(py, call):
            key = id(fn)
            if key not in self._submits:
                self._submits[key] = False  # cycles count as not submitting
                self._submits[key] = any(isinstance(n, ast.Call) and self._py_call_submits(other, n, depth + 1, fn)
                                         for n in _py_walk(fn))
            if self._submits[key]:
                return True
        return False

    def _py_targets(self, py: PyFile, call: ast.Call) -> list[tuple[PyFile, ast.AST]]:
        """The project functions a call runs, resolved through its receiver: `self.m()` in the
        caller's class, `f()` defined in the module or imported by name, `mod.f()` from an
        imported module, `obj.m()` where obj is annotated or built as a project class (a
        Protocol's stub stands for the classes that implement the method). A method called on
        anything else (`cur.execute()`) is not followed: its name may belong to another class."""
        name = _py_name(call.func)
        defs = [(f, d) for f, d in self.ctx.index.py_defs.get(name, []) if not TEST_PATH.search(f.path)]
        if not defs:
            return []
        func = call.func
        if isinstance(func, ast.Name):
            local = [(f, d) for f, d in defs if f is py and _py_owner(f, d) is None]
            source = self._py_imported(py, name)
            return local or [(f, d) for f, d in defs if source and _py_owner(f, d) is None and _module_is(f.path, source[0])]
        if not isinstance(func, ast.Attribute):
            return []
        recv = func.value
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"}:
            cls = _py_enclosing_class(py, call)
            if cls is None:
                return []
            own = [(f, d) for f, d in defs if _py_owner(f, d) is cls]
            bases = {_py_annotation_class(b) for b in cls.bases}  # inherited from a project class
            return own or [(f, d) for f, d in defs if isinstance(_py_owner(f, d), ast.ClassDef)
                           and _py_owner(f, d).name in bases]
        if isinstance(recv, ast.Name):
            source = self._py_imported(py, recv.id)
            if source and source[1] is None:  # `import pkg.mod as m` / `from pkg import mod`
                return [(f, d) for f, d in defs if _py_owner(f, d) is None and _module_is(f.path, source[0])]
            kind = _py_class_of_name(py, call, recv.id)
        elif isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id == "self":
            kind = _py_class_of_attribute(py, call, recv.attr)
        else:
            kind = None
        if not kind:
            return []
        own = [(f, d) for f, d in defs if isinstance(_py_owner(f, d), ast.ClassDef) and _py_owner(f, d).name == kind]
        if own and all(_py_stub(d) for _, d in own):
            # A Protocol or an abstract base: the project classes that implement the method.
            return [(f, d) for f, d in defs if isinstance(_py_owner(f, d), ast.ClassDef) and not _py_stub(d)]
        return own

    def _py_imported(self, py: PyFile, name: str) -> tuple[str, str | None] | None:
        """(module, imported name) a local name comes from: `from a.b import name` -> ("a.b",
        "name"); `import a.b as name`, or `from a import b` where a/b.py is a project module ->
        ("a.b", None)."""
        for node in py.tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if (alias.asname or alias.name) == name:
                        dotted = f"{node.module}.{alias.name}"
                        module = any(_module_is(path, dotted) for path in self.ctx.index.py)
                        return (dotted, None) if module else (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname == name or (alias.asname is None and alias.name == name):
                        return alias.name, None
        return None

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


def _py_owner(py: PyFile, fn: ast.AST):
    """What a function belongs to: its class (a method), None (a module-level function), or
    False (a function nested in another, which no call from outside reaches by name)."""
    parent = py.parents.get(fn)
    return parent if isinstance(parent, ast.ClassDef) else None if isinstance(parent, ast.Module) else False


def _py_enclosing_class(py: PyFile, node) -> ast.ClassDef | None:
    parent = py.parents.get(node)
    while parent is not None and not isinstance(parent, ast.ClassDef):
        parent = py.parents.get(parent)
    return parent


def _module_is(path: str, dotted: str) -> bool:
    """The file is the module `a.b` (a/b.py or a/b/__init__.py, under any source root)."""
    stem = path[:-3] if path.endswith(".py") else path
    stem = stem[:-9] if stem.endswith("/__init__") else stem
    return ("/" + stem).endswith("/" + dotted.replace(".", "/"))


def _py_annotation_class(node) -> str | None:
    """`C`, `mod.C`, `Optional[C]`, `C | None` -> C."""
    if isinstance(node, ast.Subscript):
        return _py_annotation_class(node.slice)
    if isinstance(node, ast.BinOp):
        return _py_annotation_class(node.left) or _py_annotation_class(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.rsplit(".", 1)[-1] if re.fullmatch(r"[\w.]+", node.value) else None
    if isinstance(node, (ast.Name, ast.Attribute)):
        return node.id if isinstance(node, ast.Name) else node.attr
    return None


def _py_class_of_name(py: PyFile, call: ast.Call, name: str) -> str | None:
    """The class a local name holds: a parameter annotation, `name: C = ...`, or `name = C(...)`
    in the calling function (or at module level)."""
    fn = py.parents.get(call)
    while fn is not None and not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        fn = py.parents.get(fn)
    for scope in ([fn] if fn is not None else []) + [py.tree]:
        if scope is not py.tree:
            for arg in [*scope.args.args, *scope.args.kwonlyargs, *scope.args.posonlyargs]:
                if arg.arg == name and arg.annotation is not None:
                    return _py_annotation_class(arg.annotation)
        for node in (_py_walk(scope) if scope is not py.tree else scope.body):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
                return _py_annotation_class(node.annotation)
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                built = _py_call(node.value)
                if built is not None and isinstance(built.func, (ast.Name, ast.Attribute)) and \
                        _py_name(built.func)[:1].isupper():
                    return _py_name(built.func)
    return None


def _py_class_of_attribute(py: PyFile, call: ast.Call, attr: str) -> str | None:
    """The class `self.attr` holds: `self.attr = C(...)`, `self.attr = param` with param
    annotated, or `attr: C` in the class body."""
    cls = _py_enclosing_class(py, call)
    if cls is None:
        return None
    for node in cls.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == attr:
            return _py_annotation_class(node.annotation)
    for method in cls.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg: a.annotation for a in [*method.args.args, *method.args.kwonlyargs] if a.annotation is not None}
        for node in _py_walk(method):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and any(
                    isinstance(t, ast.Attribute) and t.attr == attr and isinstance(t.value, ast.Name) and t.value.id == "self"
                    for t in (node.targets if isinstance(node, ast.Assign) else [node.target])):
                if isinstance(node, ast.AnnAssign):
                    return _py_annotation_class(node.annotation)
                built = _py_call(node.value)
                if built is not None and _py_name(built.func)[:1].isupper():
                    return _py_name(built.func)
                if isinstance(node.value, ast.Name) and node.value.id in params:
                    return _py_annotation_class(params[node.value.id])
    return None


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
#: Receivers that are another chain's client or a wallet, whatever they are bound to.
_NOT_RPC = re.compile(r"horizon|wallet|signer|provider|\beth\b|viem|ethers|web3|solana|connection", re.I)


def _bound_names(call) -> tuple[object, set[str], list]:
    """(outermost expression standing for the call's result, names bound to it, the wrapper
    calls it passed through)."""
    node, wrappers = call, []
    while True:
        parent = node.parent
        if parent is None:
            return node, set(), wrappers
        if parent.type in {"await_expression", "parenthesized_expression", "as_expression", "non_null_expression"}:
            node = parent
            continue
        if parent.type == "arguments" and parent.parent is not None and parent.parent.type == "call_expression" \
                and callee_name(parent.parent) not in sdk.POLL_METHODS and _args(parent.parent)[:1] == [node]:
            node = parent.parent  # a wrapper: runRpc(server.sendTransaction(tx), "label")
            wrappers.append(node)
            continue
        break
    parent = node.parent
    names: set[str] = set()
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
    return node, names, wrappers


class _JsRules:
    def __init__(self, ctx: _Context):
        self.ctx = ctx
        self._polls: dict[int, bool] = {}
        self._sends: dict[int, bool] = {}
        self._rpc_names: dict[str, bool] = {}

    def _is_rpc(self, js: JsFile, recv) -> bool:
        """A Soroban RPC client of the Stellar SDK, in a file that imports the SDK: a new
        rpc.Server(...) or a name bound to one or typed as one (here, or in another Stellar
        file of the project, as a clients module does). A name alone (`rpcClient`) is not
        enough: EVM and other JSON-RPC clients send transactions too. A name that says soroban
        counts in a Stellar file."""
        if recv is None or not js.stellar:
            return False
        text = _txt(recv)
        if _NOT_RPC.search(text):
            return False
        if re.match(r"new\s+" + _RPC_CLASS + r"\s*\(", text) or re.search(r"soroban", text, re.I):
            return True
        name = text.rsplit(".", 1)[-1].lstrip("#")
        if not re.fullmatch(r"[\w$]+", name):
            return False
        if name not in self._rpc_names:
            bound = re.compile(r"(?<![\w$])#?" + re.escape(name) + r"\s*(?:\??:[^=;\n]+)?[=:]\s*(?:await\s+)?new\s+" + _RPC_CLASS
                               + r"\s*\(|(?<![\w$])#?" + re.escape(name) + r"\s*\??:\s*" + _RPC_CLASS)
            self._rpc_names[name] = any(other.stellar and bound.search(other.text) for other in self.ctx.index.js.values())
        return self._rpc_names[name]

    # -------------------------------------------------- uses of a send result
    def _uses(self, js: JsFile, fn, names: set[str], after: int) -> dict[str, list]:
        """Classify each use of the names in fn after a byte offset: poll, settled, returned."""
        out: dict[str, list] = _no_uses()
        names = set(names)
        for node in SourceIndex.walk(fn):
            if node.type == "variable_declarator" and node.start_byte > after:
                value = _unwrap(node.child_by_field_name("value"))
                target = node.child_by_field_name("name")
                if value is not None and target is not None and target.type == "identifier" and \
                        value.type in {"identifier", "member_expression"} and _root_identifier(value) in names:
                    names.add(_txt(target))  # const h = sent.hash
            elif node.type == "for_in_statement" and node.start_byte > after and \
                    _root_identifier(node.child_by_field_name("right")) in names:
                left = node.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    names.add(_txt(left))  # for (const s of sent)
        for node in SourceIndex.walk(fn):
            if node.type not in {"identifier", "shorthand_property_identifier"} or _txt(node) not in names \
                    or node.start_byte <= after:
                continue
            parent = node.parent
            if parent.type in {"variable_declarator"} and parent.child_by_field_name("name") == node:
                continue
            kind, where = self._context(js, node, fn)
            if kind:
                out[kind].append(where)
        return out

    def _context(self, js: JsFile, node, fn) -> tuple[str | None, tuple]:
        # `sent.status` handed back or logged: whoever reads it sees PENDING, nothing claims success.
        holder = node.parent
        status = holder is not None and holder.type == "member_expression" and \
            holder.child_by_field_name("object") == node and _txt(holder.child_by_field_name("property")) == "status"
        expr = node
        while expr.parent is not None and expr.parent != fn and not js_functions_type(expr.parent):
            parent = expr.parent
            if parent.type == "return_statement":
                return ("status", ()) if status else ("returned", (js.line(parent), js.snippet(parent)))
            if parent.type in _STATEMENTS:
                return None, ()
            if parent.type == "arguments" and parent.parent is not None and parent.parent.type == "call_expression":
                call = parent.parent
                name, dotted = callee_name(call), _dotted(call.child_by_field_name("function"))
                if name in sdk.POLL_METHODS or name in sdk.SELF_POLLING:
                    return "poll", ()
                if name in _TRANSPARENT:
                    expr = call
                    continue
                where = (js.line(call), js.snippet(call))
                if _LOGGER.search(dotted):
                    if status:
                        return "status", ()
                    text = " ".join(s for s in (_string_value(a) or _template_text(a) for a in _args(call)) if s)
                    final = _FINAL_WORDS.search(text) and not _TENTATIVE_WORDS.search(text)
                    return ("settled", where) if final else (None, ())
                if _RESPONDER.search(dotted):
                    return ("status", ()) if status else ("returned", where)
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

    def _fn_polls(self, js: JsFile, fn, depth: int) -> bool:
        key = _node_key(js, fn)
        if key in self._polls:
            return self._polls[key]
        self._polls[key] = False
        found = False
        for call in SourceIndex.calls(fn):
            name = callee_name(call)
            if name in sdk.POLL_METHODS or name in sdk.SELF_POLLING:
                found = True
                break
            if depth < 2 and any(self._fn_polls(f, d, depth + 1) for f, d in self.ctx.index.defs(name)
                                 if d != fn):
                found = True
                break
        self._polls[key] = found
        return found

    # -------------------------------------------------- K1: send result used as the outcome
    def send_as_final(self, js: JsFile) -> tuple[list[tuple[int, str]], bool]:
        """Send sites whose PENDING result is used as the outcome, and whether that outcome is
        a payment or access decision."""
        out, money = [], False
        if "sendTransaction" not in js.text:
            return out, money
        for call in SourceIndex.calls(js.root):
            if callee_name(call) != "sendTransaction" or not self._is_rpc(js, receiver(call)):
                continue
            fn = SourceIndex.enclosing_function(call)
            if fn is None:
                continue
            expr, names, wrappers = _bound_names(call)
            if any(self._waits(w) for w in wrappers):
                continue
            uses = self._uses(js, fn, names, call.end_byte) if names else _no_uses()
            if expr.parent is not None and expr.parent.type == "return_statement":
                uses["returned"].append((js.line(expr.parent), js.snippet(expr.parent)))
            if uses["poll"] or uses["unknown"] or uses["status"]:
                continue
            settled = list(uses["settled"])
            if not settled and uses["returned"]:
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
        polls or when nothing in the project calls it."""
        name = js_function_name(fn)
        if not name:
            if fn.parent is None or fn.parent.type != "arguments" or fn.parent.parent is None:
                return None
            host = fn.parent.parent
            if _REGISTERS.match(callee_name(host)):
                # A tool or route handler: what it returns is the outcome its caller (a model, an
                # HTTP client) is told, unless it says the transaction is only pending.
                returns = [n for n in SourceIndex.walk(fn) if n.type == "return_statement"]
                if not any(_TENTATIVE_WORDS.search(_txt(r)) for r in returns):
                    return [(js.line(fn), "returned to the framework that called the handler")]
                return None
            # map, then, Promise.all, a retry helper: the results go back to the enclosing function.
            outer = SourceIndex.enclosing_function(host)
            if outer is None or depth >= 2:
                return None
            expr, names, wrappers = _bound_names(host)
            if any(self._waits(w) for w in wrappers):
                return None
            uses = self._uses(js, outer, names, host.end_byte) if names else \
                _no_uses()
            if uses["poll"] or uses["unknown"] or uses["status"]:
                return None
            if uses["settled"]:
                return uses["settled"]
            if uses["returned"] or (expr.parent is not None and expr.parent.type == "return_statement"):
                return self._callers(js, outer, depth + 1)
            return None
        settled, seen = [], False
        for other in self.ctx.index.js.values():
            if TEST_PATH.search(other.path):
                continue
            for call in SourceIndex.calls(other.root):
                if callee_name(call) != name:
                    continue
                caller = SourceIndex.enclosing_function(call)
                if caller is None or caller == fn:
                    continue
                seen = True
                expr, names, wrappers = _bound_names(call)
                if any(self._waits(w) for w in wrappers):
                    return None
                uses = self._uses(other, caller, names, call.end_byte) if names else \
                    _no_uses()
                if uses["poll"] or uses["unknown"] or uses["status"]:
                    return None
                settled += [(line, f"{other.path}:{line} {snip}") for line, snip in uses["settled"]]
        return settled if seen and settled else None

    # -------------------------------------------------- K1b: success read as "not failed"
    def not_failed_as_success(self, js: JsFile) -> list[tuple[int, str]]:
        out = []
        if not re.search(r"getTransaction|pollTransaction", js.text):
            return out
        for call in SourceIndex.calls(js.root):
            if callee_name(call) not in {"getTransaction", "pollTransaction"} or not self._is_rpc(js, receiver(call)):
                continue
            fn = SourceIndex.enclosing_function(call)
            _, names, _ = _bound_names(call)
            if fn is None or not names:
                continue
            checks_success = None
            for node in SourceIndex.walk(fn):
                if node.type != "binary_expression" or _txt(node.child_by_field_name("operator")) not in {"!==", "!="}:
                    continue
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                for status, other in ((left, right), (right, left)):
                    value = _string_value(other) or _txt(other)
                    if not (_is_status(status, names) and re.search(r"FAILED|NOT_FOUND", value)):
                        continue
                    holder = node.parent
                    while holder is not None and holder.type == "parenthesized_expression":
                        holder = holder.parent
                    if holder is None or holder.type not in {"pair", "return_statement", "variable_declarator",
                                                             "assignment_expression"}:
                        continue
                    name = _holder_name(holder, fn)
                    if not _SUCCESS_NAME.search(name):
                        # `finished = r.status !== NOT_FOUND` is a polling flag; a test that is not
                        # named as a verdict is fine when the same result is compared with SUCCESS.
                        if "NOT_FOUND" in value and _POLL_FLAG.search(name):
                            continue
                        if checks_success is None:
                            checks_success = _compares_success(fn, names)
                        if checks_success:
                            continue
                    out.append((js.line(node), js.snippet(node)))
        return out

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
                    key = _node_key(other, fn)
                    if key not in self._sends:
                        self._sends[key] = False
                        self._sends[key] = self._submits(other, fn, depth + 1)
                    if self._sends[key]:
                        return True
        return False

    def _js_targets(self, js: JsFile, call) -> list[tuple[JsFile, object]]:
        """The project functions a call runs, resolved through its receiver: `f()` defined in
        this file or imported by name, `this.m()` in the caller's class, `mod.f()` on an
        imported module, `obj.m()` where obj is built or typed as a project class or is an
        object literal of this file. A method called on anything else (`db.execute()`) is not
        followed: its name may belong to another class."""
        defs = [(f, d) for f, d in self.ctx.index.defs(callee_name(call)) if not TEST_PATH.search(f.path)]
        fn = _unwrap(call.child_by_field_name("function"))
        if not defs or fn is None:
            return []
        if fn.type == "identifier":
            plain = [(f, d) for f, d in defs if _js_owner(d) is None]
            local = [(f, d) for f, d in plain if f is js]
            return local or ([(f, d) for f, d in plain if f is not js] if _txt(fn) in _js_imports(js) else [])
        if fn.type != "member_expression":
            return []
        obj = _unwrap(fn.child_by_field_name("object"))
        if obj is not None and obj.type == "this":
            cls = _js_class(call)
            if cls is None:
                return []
            own = [(f, d) for f, d in defs if f is js and _js_class(d) == cls]
            parent = re.search(r"\bextends\s+(?:[\w$]+\.)*([\w$]+)", _txt(cls)[:300])  # inherited from a project class
            return own or [(f, d) for f, d in defs if parent and _js_owner(d) == parent.group(1)]
        if obj is not None and obj.type == "identifier" and _js_imports(js).get(_txt(obj)) in {"namespace", "default"}:
            return [(f, d) for f, d in defs if f is not js and not isinstance(_js_owner(d), str)]
        holder = _js_holder(obj)
        if not holder:
            return []
        kind = _js_class_of(js, holder)
        if kind:
            return [(f, d) for f, d in defs if _js_owner(d) == kind]
        literal = _js_literal_of(js, holder)
        if literal is not None:
            return [(f, d) for f, d in defs if f is js and literal[0] <= d.start_byte < literal[1]]
        return []

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
            assigned = re.search(r"\b" + re.escape(name) + r"\s*(?::[^=;\n]+)?=\s*(?:await\s+)?([\w$.]+)\s*\(", js.text)
            if assigned:
                maker = assigned.group(1).rsplit(".", 1)[-1]
                if _PAYING_FETCH.match(maker):
                    return True
                return any(_PAYING_FETCH.match(callee_name(c)) for f, d in self.ctx.index.defs(maker)
                           for c in SourceIndex.calls(d))
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


def _js_class(node):
    """The class declaration a node sits in."""
    n = node.parent
    while n is not None and n.type not in {"class_declaration", "class", "abstract_class_declaration"}:
        n = n.parent
    return n


def _js_owner(fn) -> str | bool | None:
    """What a function belongs to: the name of its class (a method), True (a property of an
    object literal), or None (a function declared on its own)."""
    parent = fn.parent
    if fn.type == "method_definition" or (parent is not None and parent.type in {"public_field_definition", "field_definition"}):
        cls = _js_class(fn)
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


def _js_class_of(js: JsFile, name: str) -> str | None:
    """The class a name holds in this file: `name = new C(...)`, `this.name = new C(...)`, or
    `name: C` (a parameter, a variable or a field)."""
    n = re.escape(name)
    built = re.search(r"(?<![\w$.])(?:this\.)?#?" + n + r"\s*(?:\??:[^=;\n]+)?=\s*(?:await\s+)?new\s+(?:[\w$]+\.)*([\w$]+)\s*[(<]",
                      js.text)
    if built:
        return built.group(1)
    typed = re.search(r"(?<![\w$.])#?" + n + r"\s*\??:\s*(?:[\w$]+\.)*([A-Z][\w$]*)\b(?!\s*[.<\[])", js.text)
    return typed.group(1) if typed else None


def _js_literal_of(js: JsFile, name: str) -> tuple[int, int] | None:
    """The byte range of the object literal a name is declared with in this file."""
    for node in SourceIndex.walk(js.root):
        if node.type == "variable_declarator" and _txt(node.child_by_field_name("name")) == name:
            value = _unwrap(node.child_by_field_name("value"))
            if value is not None and value.type == "object":
                return value.start_byte, value.end_byte
            return None
    return None


def _no_uses() -> dict[str, list]:
    """How a send result is used: polled, settled, returned, unknown, or its status handed on."""
    return {"poll": [], "settled": [], "returned": [], "unknown": [], "status": []}


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


def _holder_name(holder, fn) -> str:
    """The name a status test is kept under: a key, a variable, a property, or for a returned
    test the function's own name."""
    if holder.type == "pair":
        return _txt(holder.child_by_field_name("key")).strip("'\"")
    if holder.type == "variable_declarator":
        return _txt(holder.child_by_field_name("name"))
    if holder.type == "assignment_expression":
        return _txt(holder.child_by_field_name("left")).rsplit(".", 1)[-1]
    return js_function_name(fn) or ""


def _compares_success(fn, names: set[str]) -> bool:
    """The function compares the result's status with SUCCESS (or switches on it)."""
    for node in SourceIndex.walk(fn):
        if node.type == "binary_expression" and _txt(node.child_by_field_name("operator")) in {"===", "==", "!==", "!="}:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            for status, other in ((left, right), (right, left)):
                if _is_status(status, names) and re.search(r"SUCCESS", _string_value(other) or _txt(other)):
                    return True
        elif node.type == "switch_statement" and _is_status(node.child_by_field_name("value"), names) and \
                "SUCCESS" in _txt(node.child_by_field_name("body")):
            return True
    return False


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
