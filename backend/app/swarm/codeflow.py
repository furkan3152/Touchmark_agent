"""Project-wide Python data-flow analysis for agent source.

The analyser parses every submitted Python file (it never imports or executes
them), resolves calls between files and propagates taint labels from untrusted
sources to security-relevant sinks. It also inventories what the code is able
to do, independently of what the submitter declared.

Labels
  model    value chosen by an LLM: arguments of registered tool handlers and
           model responses. Reachable by prompt injection.
  external value from an HTTP request, CLI input or a fetched network response.
  chain    ledger data such as memos and payment records; anyone can write it.
  caller   parameter of a public function that nothing in the project calls.
           The caller is unknown, so the value is treated as unvalidated.
  secret   secret material (secret seeds, API keys, signer environment values).
  signer   a Stellar keypair able to sign.

The analysis is context-insensitive and bounded. A reported path is static
evidence that a value can reach a sink, not proof of a successful exploit.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field

UNTRUSTED = frozenset({"model", "external", "chain", "caller"})
DIRECT = frozenset({"model", "external", "chain"})

_SECRET_ENV = re.compile(r"secret|seed|private|mnemonic|sign(?:er|ing)|api[_-]?key|token|password|credential|(?:^|_)key$", re.I)
_SEED_LITERAL = re.compile(r"\bS[A-Z2-7]{55}\b")
_REQUEST_SOURCE = re.compile(
    r"(?:^|\.)(?:request|req)\.(?:json|body|form|args|values|data|get_json|query|params)|"
    r"(?:^|\.)(?:input|sys\.stdin\.read|sys\.stdin\.readline)$|^sys\.argv"
)
_LLM_CALL = re.compile(
    r"\.messages\.create$|\.messages\.stream$|\.completions\.create$|\.responses\.create$|"
    r"\.generate_content$|\.chat\.complete$|(?:llm|model|chain|agent|chat)\.(?:invoke|ainvoke|predict|run)$"
)
_HTTP_CALL = re.compile(
    r"^(?:requests|httpx|aiohttp|urllib3)\.(?:get|post|put|patch|delete|head|request|options)$|"
    r"^(?:urllib\.request\.)?urlopen$|^urllib\.request\.urlopen$|"
    r"\.(?:session|client|http)\.(?:get|post|put|patch|delete|request)$"
)
_CHAIN_READ = re.compile(
    r"\.(?:transactions|payments|operations|effects|trades|offers|claimable_balances)\b.*\.call$|"
    r"\.(?:get_events|get_transaction|get_transactions|get_ledger_entries)$|"
    r"\.(?:stream|cursor)\b.*\.(?:call|stream)$"
)
_COMMAND_SINK = re.compile(
    r"^(?:eval|exec|compile|__import__)$|^os\.(?:system|popen|exec\w*|spawn\w*)$|"
    r"^subprocess\.\w+$|^asyncio\.create_subprocess_\w+$|^pty\.spawn$"
)
_STRUCTURING = re.compile(r"^(?:dumps|canonicali[sz]e\w*|serialize\w*|digest|hexdigest|hash\w*|sha\d+|keccak\w*|to_xdr|hash_message)$", re.I)
#: Loaders that run code embedded in the data they read.
_DESERIALIZE = re.compile(r"^(?:c?pickle|dill|marshal|cloudpickle)\.loads?$|^jsonpickle\.decode$|^yaml\.(?:load|load_all|unsafe_load|full_load)$|"
                          r"^(?:torch|joblib)\.load$|^shelve\.open$")
#: A query string with SQL in it; a database call whose query embeds input is SQL injection.
_SQL_TEXT = re.compile(r"\b(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where\s|drop\s+table)\b", re.I | re.S)
_SQL_CALL = {"execute", "executemany", "executescript", "raw", "fetch", "fetchrow", "fetchval", "query"}
_FILE_SINK = re.compile(r"^(?:open|io\.open|os\.remove|os\.unlink|os\.rename|shutil\.\w+)$")
_PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "rename"}
_LOG_SINK = re.compile(r"^print$|(?:^|\.)(?:log|logger|logging)\.(?:debug|info|warning|warn|error|critical|exception)$")
_PAYMENT_OPS = {
    "append_payment_op", "append_path_payment_strict_send_op", "append_path_payment_strict_receive_op",
    "append_create_account_op", "append_create_claimable_balance_op", "append_clawback_op",
}
_ACCOUNT_OPS = {
    "append_set_options_op", "append_account_merge_op", "append_manage_data_op",
    "append_revoke_sponsorship_op", "append_begin_sponsoring_future_reserves_op",
}
#: Trustline changes decide which assets the account holds; they change no signer or threshold.
_TRUSTLINE_OPS = {"append_change_trust_op", "append_allow_trust_op", "append_set_trust_line_flags_op"}
_FOREIGN_TX = re.compile(r"(?:TransactionEnvelope\.from_xdr|from_xdr_object|parse_transaction_envelope_from_xdr|"
                         r"FeeBumpTransactionEnvelope\.from_xdr)$")
_SUBMIT = re.compile(r"\.(?:submit_transaction|send_transaction)$")
_SOROBAN_SINK = re.compile(r"\.(?:invoke|invoke_contract|authorize_entry|sign_auth_entries?)$|^token\.transfer$")
#: `stellar contract invoke ... --auto-sign`: the CLI signs non-root Soroban authorization
#: entries without asking (stellar-cli FULL_HELP_DOCS.md).
CLI_AUTO_SIGN = re.compile(r"\bcontract\b[\s\S]{0,80}\binvoke\b[\s\S]{0,400}--auto-sign\b")
#: Calls that ask a person and return their decision (an operator console, a wallet prompt).
#: A decision they return is not something the requester can set.
_HUMAN_DECISION = re.compile(r"approv|confirm|consent|prompt_?(?:user|human|operator)|ask_?(?:user|human|operator|owner)|"
                             r"human|operator|review|sign_?off", re.I)
#: Reading a record from the agent's own store: the requester picks the key, not the content.
_LOOKUP = re.compile(r"^(?:get|find\w*|lookup|load\w*|fetch_?(?:one|record|approval)\w*|read|select|query|first)$", re.I)
_NOT_HUMAN = re.compile(r"llm|model|chat|complet|generat|agent|openai|anthropic|claude|gpt", re.I)
_APPROVAL_CALL = re.compile(r"approv|authori[sz]|verify|confirm|permi(?:t|ssion)|allowed|check_auth|require_auth", re.I)
_HANDLER_DECORATOR = re.compile(r"(?:^|\.)(?:tool|function_tool|mcp_tool)$|(?:^|\.)tool\(|\.tool$")
_ROUTE_DECORATOR = re.compile(r"\.(?:get|post|put|patch|delete|route|websocket|api_route)$")
_SAFE_URL_PREFIX = re.compile(r"^https?://[^/{}\s]+(?:/|$)")
_NAME_SOURCES = {"user_input", "prompt", "payload", "command", "cmd", "code", "webhook", "query", "message"}
#: Only a function that looks like a handler takes its input from outside by parameter name:
#: `on_message(message)` does, a wallet's own `sign_message(message)` primitive does not.
HANDLER_NAME = re.compile(r"^(?:on|handle|handler|process|dispatch|receive|route|webhook|listen|callback|controller|"
                          r"endpoint|serve|run|execute|invoke|call|main|chat|ask|reply|respond)(?:[_A-Z]|$)|"
                          r"(?:handler|hook|route|controller|endpoint|listener|callback)$", re.I)
#: Names of values a spending cap compares: money, not counters, ratings or lengths.
AMOUNT_NAME = re.compile(r"amount|value|price|cost|units|spend|spent|total|budget|sum|fee|usdc|xlm|stroop|balance|"
                         r"limit|qty|quantity|max|cap\b|pay|charge|\bsize", re.I)
#: A bound that is the money received: `required <= paid` checks a price was met, not a spending cap.
RECEIVED_NAME = re.compile(r"paid|received|incoming|actual|deposit", re.I)


@dataclass(frozen=True)
class Location:
    file: str
    line: int
    text: str

    def render(self) -> str:
        return f"{self.file}:{self.line} `{' '.join(self.text.split())[:160]}`"


@dataclass(frozen=True)
class Flow:
    category: str
    location: Location
    labels: frozenset[str]
    function: str
    detail: str = ""

    @property
    def direct(self) -> bool:
        return bool(self.labels & DIRECT)


@dataclass(frozen=True)
class Fact:
    """Something the code configures or does at one place whose risk depends on more than
    the code: a payment SDK option (its meaning depends on the installed version), a
    settlement call, a sponsored rebuild. agentic_paths turns facts into findings once the
    lockfile and network are known. ``attrs`` holds sorted (key, value) pairs."""
    kind: str
    location: Location
    detail: str = ""
    attrs: tuple = ()

    def get(self, key: str, default=None):
        return dict(self.attrs).get(key, default)


@dataclass
class CodeProfile:
    capabilities: dict[str, list[Location]] = field(default_factory=dict)
    flows: list[Flow] = field(default_factory=list)
    controls: dict[str, list[Location]] = field(default_factory=dict)
    nonblocking_controls: list[Location] = field(default_factory=list)
    #: Approval gates that test a value the model, the caller or fetched content supplies.
    #: Whoever can ask the agent can set it, so the gate approves nothing.
    forgeable_approvals: list[Location] = field(default_factory=list)
    #: The same, where only a caller the source does not show supplies the flag.
    unresolved_approvals: list[Location] = field(default_factory=list)
    entrypoints: dict[str, str] = field(default_factory=dict)
    unparsed: list[str] = field(default_factory=list)
    unbounded_amounts: list[Location] = field(default_factory=list)
    #: The subset whose amount comes from the model, a request or chain data, not only from
    #: a caller the source does not show.
    unbounded_direct_amounts: list[Location] = field(default_factory=list)
    #: Files covered by data-flow analysis (Python or JS/TS). Authority found in any
    #: other file can only be judged by reading it.
    analysed_files: list[str] = field(default_factory=list)
    #: Version-, network- or path-dependent facts for the rules in agentic_paths.
    facts: list[Fact] = field(default_factory=list)
    error: str = ""

    def has(self, capability: str) -> bool:
        return bool(self.capabilities.get(capability))

    def add_fact(self, kind: str, location: Location, detail: str = "", **attrs) -> None:
        fact = Fact(kind, location, detail, tuple(sorted(attrs.items())))
        if not any(f.kind == kind and f.location == location for f in self.facts):
            self.facts.append(fact)

    def facts_of(self, kind: str) -> list[Fact]:
        return [f for f in self.facts if f.kind == kind]

    def summary(self) -> dict:
        return {
            "capabilities": {k: [loc.render() for loc in v[:3]] for k, v in sorted(self.capabilities.items())},
            "controls": {k: [loc.render() for loc in v[:3]] for k, v in sorted(self.controls.items())},
            "entrypoints": dict(sorted(self.entrypoints.items())),
            "flows": [{"category": f.category, "labels": sorted(f.labels), "function": f.function,
                       "location": f.location.render()} for f in self.flows],
            "nonblocking_controls": [loc.render() for loc in self.nonblocking_controls[:5]],
            "forgeable_approvals": [loc.render() for loc in self.forgeable_approvals[:5]],
            "unbounded_amounts": [loc.render() for loc in self.unbounded_amounts[:5]],
            "unbounded_direct_amounts": [loc.render() for loc in self.unbounded_direct_amounts[:5]],
            "unparsed_files": sorted(self.unparsed),
            "analysed_files": sorted(self.analysed_files),
            "facts": [{"kind": f.kind, "location": f.location.render(), "detail": f.detail} for f in self.facts[:40]],
            "error": self.error,
        }


@dataclass
class _Function:
    key: str
    module: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    cls: str | None
    params: list[str]


def _dotted(node: ast.AST | None) -> str:
    """Name of a call target through attribute and call chains: a.b().c -> a.b.c."""
    parts: list[str] = []
    while node is not None:
        if isinstance(node, ast.Name):
            parts.append(node.id)
            break
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            break
    return ".".join(reversed(parts))


def _module_name(path: str) -> str:
    stem = path[:-3] if path.endswith(".py") else path
    parts = [p for p in stem.replace("\\", "/").split("/") if p]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_env_lookup(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        return _dotted(node.value) == "os.environ"
    if isinstance(node, ast.Call):
        return _dotted(node.func) in {"os.environ.get", "os.getenv", "getenv"}
    return False


def _is_constant_container(node: ast.AST) -> bool:
    """A literal table of constants or operator configuration (environment lookups)."""
    if isinstance(node, ast.Constant) or _is_env_lookup(node):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_constant_container(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is None or _is_constant_container(k) for k in node.keys) and all(
            _is_constant_container(v) for v in node.values)
    if isinstance(node, ast.Call) and _dotted(node.func) in {"set", "frozenset", "tuple", "list", "Decimal", "dict"}:
        return all(_is_constant_container(a) for a in node.args)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "list" and not node.args:
        return True
    return False


def _upper_bounded(test: ast.AST, negated: bool = False) -> set[str]:
    """Names that a rejecting condition bounds from above.

    `if x > MAX: raise` and `if not 0 < x <= MAX: raise` bound x; `if x <= 0: raise` does not.
    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _upper_bounded(test.operand, not negated)
    if isinstance(test, ast.BoolOp):
        return set().union(*(_upper_bounded(v, negated) for v in test.values))
    if not isinstance(test, ast.Compare):
        return set()
    names: set[str] = set()
    left = test.left
    for op, right in zip(test.ops, test.comparators):
        greater = isinstance(op, (ast.Gt, ast.GtE))
        less = isinstance(op, (ast.Lt, ast.LtE))
        # Rejecting when value > bound (or, negated, accepting only value <= bound).
        value, bound = (left, right) if (greater and not negated) or (less and negated) else \
                       (right, left) if (less and not negated) or (greater and negated) else (None, None)
        if value is not None and not (isinstance(bound, ast.Constant) and isinstance(bound.value, (int, float))
                                      and bound.value <= 0) \
                and not any(RECEIVED_NAME.search(n) for n in _compared_names(bound)):
            names |= _compared_names(value)
        left = right
    return names


def _compared_names(side: ast.AST) -> set[str]:
    """Names whose value is compared: x, Decimal(x), int(x), float(x)."""
    if isinstance(side, ast.Name):
        return {side.id}
    if isinstance(side, ast.BinOp) and isinstance(side.op, ast.Add):
        # `spent + amount > LIMIT`: a running total plus this payment, both bounded.
        return _compared_names(side.left) | _compared_names(side.right)
    if isinstance(side, ast.Call) and len(side.args) == 1 and isinstance(side.args[0], ast.Name):
        return {side.args[0].id}
    return set()


def _terminates(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))


class _Project:
    MAX_ROUNDS = 12

    def __init__(self, files: dict[str, str], entrypoints: dict[str, set[str]]):
        self.files = files
        self.trees: dict[str, ast.Module] = {}
        self.lines: dict[str, list[str]] = {}
        self.module_of: dict[str, str] = {}
        self.profile = CodeProfile()
        for path, content in files.items():
            if not path.lower().endswith(".py"):
                continue
            try:
                tree = ast.parse(content)
            except (SyntaxError, ValueError, RecursionError):
                self.profile.unparsed.append(path)
                continue
            module = _module_name(path)
            self.trees[module] = tree
            self.lines[module] = content.splitlines()
            self.module_of[module] = path
        self.functions: dict[str, _Function] = {}
        self.classes: dict[str, set[str]] = {}  # class key -> method names
        self.imports: dict[str, dict[str, str]] = {m: {} for m in self.trees}
        self.constants: dict[str, set[str]] = {m: set() for m in self.trees}
        self.entry: dict[str, list[set[str]]] = {}
        self.returns: dict[str, set[str]] = {}
        self.called: set[str] = set()
        self.handlers: dict[str, str] = {}
        self.class_attrs: dict[str, dict[str, set[str]]] = {}
        self.model_entries: set[str] = set()
        self.declared_entry = entrypoints
        self._types_cache: dict[str, dict[str, str]] = {}
        self._lib_cache: dict[str, frozenset[str]] = {}
        self._index()

    # ------------------------------------------------------------- indexing
    def _resolve_module(self, current: str, target: str, level: int) -> str | None:
        if level:
            base = current.split(".")[:-level] if level <= current.count(".") + 1 else []
            target = ".".join([*base, target] if target else base)
        if target in self.trees:
            return target
        candidates = [m for m in self.trees if m == target or m.endswith("." + target)]
        if len(candidates) == 1:
            return candidates[0]
        tail = target.split(".")[-1]
        candidates = [m for m in self.trees if m.split(".")[-1] == tail]
        return candidates[0] if len(candidates) == 1 else None

    def _index(self) -> None:
        for module, tree in self.trees.items():
            imports = self.imports[module]
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    resolved = self._resolve_module(module, node.module or "", node.level)
                    for alias in node.names:
                        local = alias.asname or alias.name
                        if resolved:
                            sub = self._resolve_module(resolved, alias.name, 0) if f"{resolved}.{alias.name}" in self.trees else None
                            imports[local] = sub and f"module:{sub}" or f"{resolved}:{alias.name}"
                        else:
                            imports[local] = f"lib:{node.module or ''}.{alias.name}".replace(":.", ":")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        resolved = self._resolve_module(module, alias.name, 0)
                        local = alias.asname or alias.name.split(".")[0]
                        imports[local] = f"module:{resolved}" if resolved else f"lib:{alias.name}"
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._add_function(module, stmt, None)
                elif isinstance(stmt, ast.ClassDef):
                    methods = set()
                    for item in stmt.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._add_function(module, item, stmt.name)
                            methods.add(item.name)
                    self.classes[f"{module}:{stmt.name}"] = methods
                elif isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                    if _is_constant_container(stmt.value):
                        for target in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]):
                            if isinstance(target, ast.Name):
                                self.constants[module].add(target.id)
        self.has_schema = any(
            isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value in
                                            {"input_schema", "inputSchema", "parameters"} for k in n.keys)
            for tree in self.trees.values() for n in ast.walk(tree))
        self.has_llm = any(
            isinstance(n, ast.Call) and _LLM_CALL.search("." + _dotted(n.func))
            for tree in self.trees.values() for n in ast.walk(tree))
        for module, tree in self.trees.items():
            self._find_entrypoints(module, tree)

    def _add_function(self, module: str, node, cls: str | None) -> None:
        key = f"{module}:{cls + '.' if cls else ''}{node.name}"
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        params = [a.arg for a in args]
        if cls and params and params[0] in {"self", "cls"}:
            params = params[1:]
        if node.args.vararg:
            params.append("*" + node.args.vararg.arg)
        if node.args.kwarg:
            params.append("**" + node.args.kwarg.arg)
        self.functions[key] = _Function(key, module, node, cls, params)
        self.entry[key] = [set() for _ in params]
        self.returns[key] = set()

    def _resolve_ref(self, module: str, node: ast.AST, local_types: dict[str, str] | None = None) -> str | None:
        """Resolve a function reference (Name or Attribute) to a function key."""
        if isinstance(node, ast.Name):
            key = f"{module}:{node.id}"
            if key in self.functions:
                return key
            if f"{module}:{node.id}" in self.classes:
                init = f"{module}:{node.id}.__init__"
                return init if init in self.functions else None
            target = self.imports[module].get(node.id, "")
            if ":" in target and not target.startswith(("lib:", "module:")):
                mod, name = target.split(":", 1)
                if f"{mod}:{name}" in self.functions:
                    return f"{mod}:{name}"
                init = f"{mod}:{name}.__init__"
                if f"{mod}:{name}" in self.classes:
                    return init if init in self.functions else None
            return None
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name):
                target = self.imports[module].get(base.id, "")
                if target.startswith("module:"):
                    key = f"{target[7:]}:{node.attr}"
                    if key in self.functions:
                        return key
                cls = (local_types or {}).get(base.id) or self._global_types(module).get(base.id)
                if cls:
                    key = f"{cls}.{node.attr}"
                    if key in self.functions:
                        return key
            # Unique method name across project classes, never for library objects.
            if isinstance(base, ast.Name) and (self.imports[module].get(base.id, "").startswith(("lib:", "module:"))
                                               or base.id in self._lib_vars(module)):
                return None
            owners = [c for c, methods in self.classes.items() if node.attr in methods]
            if len(owners) == 1 and not node.attr.startswith("__"):
                return f"{owners[0]}.{node.attr}"
        return None

    def _global_types(self, module: str) -> dict[str, str]:
        if module in self._types_cache:
            return self._types_cache[module]
        types: dict[str, str] = self._types_cache.setdefault(module, {})
        for stmt in self.trees[module].body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                cls = self._class_of(module, stmt.value.func)
                if cls:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            types[target.id] = cls
        return types

    def _lib_vars(self, module: str) -> frozenset[str]:
        if module in self._lib_cache:
            return self._lib_cache[module]
        names = set()
        for stmt in self.trees[module].body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) and not self._class_of(module, stmt.value.func):
                names |= {t.id for t in stmt.targets if isinstance(t, ast.Name)}
        self._lib_cache[module] = frozenset(names)
        return self._lib_cache[module]

    def _class_of(self, module: str, func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            if f"{module}:{func.id}" in self.classes:
                return f"{module}:{func.id}"
            target = self.imports[module].get(func.id, "")
            if ":" in target and not target.startswith(("lib:", "module:")) and target in self.classes:
                return target
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target = self.imports[module].get(func.value.id, "")
            if target.startswith("module:") and f"{target[7:]}:{func.attr}" in self.classes:
                return f"{target[7:]}:{func.attr}"
        return None

    def _mark_entry(self, key: str, label: str, reason: str) -> None:
        fn = self.functions[key]
        if label == "model":
            self.model_entries.add(key)
        for params in self.entry[key]:
            params.add(label)
        self.profile.entrypoints.setdefault(f"{self.module_of[fn.module]}:{fn.node.name}", reason)

    def _find_entrypoints(self, module: str, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            # Handler tables registered with an LLM tool loop: {"name": function}.
            # Dispatch tables {"name": function} next to an LLM tool loop or tool schema.
            if isinstance(node, ast.Dict) and node.values and (self.has_schema or self.has_llm):
                for value in node.values:
                    key = self._resolve_ref(module, value) if value is not None else None
                    if key:
                        self._mark_entry(key, "model", "LLM tool handler")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in {"tools", "functions"} and isinstance(kw.value, (ast.List, ast.Tuple)):
                        for element in kw.value.elts:
                            key = self._resolve_ref(module, element)
                            if key:
                                self._mark_entry(key, "model", "LLM tool function")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = next((k for k, f in self.functions.items() if f.node is node), None)
                if not key:
                    continue
                fn = self.functions[key]
                # getattr(self, <model-chosen name>)(...) exposes every public method of the class.
                if fn.cls and self.has_llm and any(
                        isinstance(c, ast.Call) and isinstance(c.func, ast.Call) and _dotted(c.func.func) == "getattr"
                        and len(c.func.args) >= 2 and not isinstance(c.func.args[1], ast.Constant)
                        for c in ast.walk(node)):
                    for method in self.classes.get(f"{module}:{fn.cls}", set()):
                        target = f"{module}:{fn.cls}.{method}"
                        if not method.startswith("_") and target != key and target in self.functions:
                            self._mark_entry(target, "model", "method reachable through dynamic tool dispatch")
                for decorator in node.decorator_list:
                    label = _dotted(decorator)
                    if _HANDLER_DECORATOR.search(label):
                        self._mark_entry(key, "model", "decorated tool")
                    elif _ROUTE_DECORATOR.search(label):
                        self._mark_entry(key, "external", "HTTP route")
                path = self.module_of[module]
                if node.name in self.declared_entry.get(path, set()):
                    self._mark_entry(key, "external", "declared entrypoint")

    # ------------------------------------------------------------- analysis
    def run(self) -> CodeProfile:
        # Pass 0: which project functions are ever called or referenced.
        for module, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    key = self._resolve_ref(module, node.func)
                    if key:
                        self.called.add(key)
                elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(getattr(node, "ctx", None), ast.Load):
                    key = self._resolve_ref(module, node)
                    if key:
                        self.called.add(key)
        for key, fn in self.functions.items():
            public = not fn.node.name.startswith("_") or fn.node.name == "__call__"
            if key not in self.called and public and not any(self.entry[key]):
                for i, params in enumerate(self.entry[key]):
                    # Conventional input names on an uncalled function are treated as direct input.
                    named = fn.params[i].lstrip("*").lower() in _NAME_SOURCES | {"request", "req", "event"}
                    params.add("external" if named and HANDLER_NAME.search(fn.node.name) else "caller")
                if fn.params:
                    self.profile.entrypoints.setdefault(
                        f"{self.module_of[fn.module]}:{fn.node.name}", "public function with no caller in project")
        self.globals = {m: self._module_state(m) for m in self.trees}
        changed, rounds = True, 0
        while changed and rounds < self.MAX_ROUNDS:
            changed, rounds = False, rounds + 1
            for key in list(self.functions):
                before = ([set(p) for p in self.entry[key]], set(self.returns[key]))
                self._analyse_function(key, record=False)
                after = ([set(p) for p in self.entry[key]], set(self.returns[key]))
                changed |= before != after
            changed |= self._propagated
            self._propagated = False
        # Final recording pass at the fixed point.
        for module in self.trees:
            _Interp(self, module, None, record=True).block(self.trees[module].body, {})
        for key in self.functions:
            self._analyse_function(key, record=True)
        return self.profile

    _propagated = False

    def _module_state(self, module: str) -> dict[str, set[str]]:
        interp = _Interp(self, module, None, record=False)
        state: dict[str, set[str]] = {}
        interp.block(self.trees[module].body, state, toplevel=True)
        return state

    def _analyse_function(self, key: str, *, record: bool) -> None:
        fn = self.functions[key]
        state = {name: set(tags) for name, tags in self.globals[fn.module].items()}
        for name, tags in zip(fn.params, self.entry[key]):
            state[name.lstrip("*")] = set(tags)
        interp = _Interp(self, fn.module, fn, record=record)
        interp.block(fn.node.body, state)
        self.returns[key] |= interp.returned

    def propagate(self, key: str, args: list[set[str]], kwargs: dict[str, set[str]]) -> None:
        params = self.functions[key].params
        entry = self.entry[key]
        for i, tags in enumerate(args):
            idx = i if i < len(params) else next((j for j, p in enumerate(params) if p.startswith("*") and not p.startswith("**")), None)
            if idx is not None and not tags <= entry[idx]:
                entry[idx] |= tags
                self._propagated = True
        for name, tags in kwargs.items():
            idx = params.index(name) if name in params else next((j for j, p in enumerate(params) if p.startswith("**")), None)
            if idx is not None and not tags <= entry[idx]:
                entry[idx] |= tags
                self._propagated = True

    # ------------------------------------------------------------- recording
    def location(self, module: str, node: ast.AST) -> Location:
        lines = self.lines[module]
        line = getattr(node, "lineno", 1)
        return Location(self.module_of[module], line, lines[line - 1] if 0 < line <= len(lines) else "")

    def capability(self, name: str, module: str, node: ast.AST) -> None:
        bucket = self.profile.capabilities.setdefault(name, [])
        loc = self.location(module, node)
        if loc not in bucket:
            bucket.append(loc)

    def control(self, name: str, module: str, node: ast.AST) -> None:
        bucket = self.profile.controls.setdefault(name, [])
        loc = self.location(module, node)
        if loc not in bucket:
            bucket.append(loc)

    def flow(self, category: str, module: str, fn: _Function | None, node: ast.AST, labels: set[str], detail: str = "") -> None:
        loc = self.location(module, node)
        item = Flow(category, loc, frozenset(labels & (UNTRUSTED | {"secret"})), fn.node.name if fn else "<module>", detail)
        if not any(f.category == category and f.location == loc for f in self.profile.flows):
            self.profile.flows.append(item)


class _Interp:
    """Abstract interpreter for one function body."""

    def __init__(self, project: _Project, module: str, fn: _Function | None, *, record: bool):
        self.p, self.module, self.fn, self.record = project, module, fn, record
        self.returned: set[str] = set()
        self.local_types: dict[str, str] = {}
        self.aliases: dict[str, str] = {}
        self.approved = False

    def canonical(self, func: ast.AST) -> str:
        """Call label with local aliases and import aliases expanded (launch -> os.system)."""
        label = _dotted(func)
        head, _, rest = label.partition(".")
        if isinstance(func, ast.Name) and head in self.aliases:
            return self.aliases[head]
        target = self.p.imports[self.module].get(head, "")
        if target.startswith("lib:"):
            expanded = target[4:].strip(".")
            return expanded + ("." + rest if rest else "")
        return label

    # -------------------------------------------------------------- values
    def tags(self, node: ast.AST | None, state: dict[str, set[str]]) -> set[str]:
        if node is None or isinstance(node, ast.Lambda):
            return set()
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and _SEED_LITERAL.search(node.value):
                self._cap("secret_material", node)
                self._cap("hardcoded_secret", node)
                return {"secret"}
            return set()
        if isinstance(node, ast.Name):
            return set(state.get(node.id, set()))
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "self" and self.fn and self.fn.cls:
                stored = self.p.class_attrs.get(f"{self.module}:{self.fn.cls}", {}).get(node.attr)
                if stored is not None:
                    return set(stored)
            base = self.tags(node.value, state)
            if "signer" in base:
                # Public attributes of a keypair are not secret material.
                return {"secret"} if node.attr in {"secret", "signing_key", "raw_secret_key"} else set()
            key = _dotted(node)
            if key in state:
                return set(state[key])
            if _REQUEST_SOURCE.search(key):
                base.add("external")
            return base
        if isinstance(node, ast.Subscript):
            container = node.value
            if isinstance(container, ast.Name) and container.id in self.p.constants[self.module]:
                self.tags(node.slice, state)
                self._control("allowlist", node)
                return set()  # selecting from a fixed table yields a fixed value
            value = self.tags(container, state)
            if _dotted(container) == "os.environ":
                env = node.slice.value if isinstance(node.slice, ast.Constant) else ""
                if isinstance(env, str) and _SECRET_ENV.search(env):
                    self._cap("secret_material", node)
                    return value | {"secret"}
            key = self.tags(node.slice, state)
            if key & UNTRUSTED and not value & UNTRUSTED:
                key = key | {"stored_record"}
            return value | key
        if isinstance(node, ast.Call):
            found = self.call(node, state)
            short = _dotted(node.func).rsplit(".", 1)[-1]
            if _HUMAN_DECISION.search(short) and not _NOT_HUMAN.search(_dotted(node.func)):
                found = found | {"human_decision"}
            if (_LOOKUP.match(short) and isinstance(node.func, ast.Attribute)
                    and not self.tags(node.func.value, state) & UNTRUSTED):
                found = found | {"stored_record"}
            return found
        if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant) \
                and str(node.values[0].value).strip():
            # Text with a fixed prefix cannot be made equal to a transaction hash.
            return set().union(*(self.tags(v, state) for v in node.values)) | {"structured"}
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            inner = dict(state)
            for gen in node.generators:
                for name in self._names(gen.target):
                    inner[name] = self.tags(gen.iter, state)
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return set().union(*(self.tags(p, inner) for p in parts))
        found: set[str] = set()
        for child in ast.iter_child_nodes(node):
            found |= self.tags(child, state)
        return found

    @staticmethod
    def _names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [n for e in target.elts for n in _Interp._names(e)]
        return []

    def forgeable(self, node: ast.AST, state: dict[str, set[str]]) -> bool:
        """An approval value the requester supplies, not one a person returned."""
        found = self.tags(node, state)
        return bool(found & UNTRUSTED) and not found & {"human_decision", "stored_record"}

    def _cap(self, name: str, node: ast.AST) -> None:
        if self.record:
            self.p.capability(name, self.module, node)

    def _flow(self, category: str, node: ast.AST, labels: set[str], detail: str = "") -> None:
        if self.record:
            self.p.flow(category, self.module, self.fn, node, labels, detail)

    def call(self, node: ast.Call, state: dict[str, set[str]]) -> set[str]:
        label = self.canonical(node.func)
        short = label.rsplit(".", 1)[-1]
        receiver = self.tags(node.func.value, state) if isinstance(node.func, ast.Attribute) else set()
        args = [self.tags(a, state) for a in node.args]
        kwargs = {kw.arg: self.tags(kw.value, state) for kw in node.keywords if kw.arg}
        star = set().union(*(self.tags(kw.value, state) for kw in node.keywords if kw.arg is None)) if any(
            kw.arg is None for kw in node.keywords) else set()
        every = set().union(*args, *kwargs.values(), star)

        # Project function: propagate argument labels and use its return summary.
        key = self.p._resolve_ref(self.module, node.func, self.local_types)
        if key:
            if star:
                kwargs = {p.lstrip("*"): star for p in self.p.functions[key].params}
            self.p.propagate(key, args, kwargs)
            out = set(self.p.returns[key])
            if self.p.functions[key].node.name == "__init__":
                out = set(every)
            return out

        if label == "min" and len(node.args) >= 2 and any(
                isinstance(a, ast.Constant) or (isinstance(a, ast.Name) and a.id in self.p.constants[self.module])
                for a in node.args):
            return every | {"bounded"}

        # Selecting from a fixed module table yields a fixed value.
        if (isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "__getitem__"}
                and isinstance(node.func.value, ast.Name) and node.func.value.id in self.p.constants[self.module]):
            self._control("allowlist", node)
            return set()

        # Sources.
        if label.startswith("os.") and short in {"getenv"} or label in {"os.environ.get", "environ.get"}:
            env = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else ""
            if isinstance(env, str) and _SECRET_ENV.search(env):
                self._cap("secret_material", node)
                return {"secret"}
            return set()
        if label.endswith("Keypair.from_secret") or label == "from_secret":
            # Holding a key is custody, not signing; see _custody_to_signing.
            self._cap("key_custody", node)
            return {"signer"}
        if _REQUEST_SOURCE.search(label):
            return every | {"external"}
        if _LLM_CALL.search("." + label):
            self._cap("llm_call", node)
            # The client object holds the provider API key; only the request content reaches the model.
            leaked = every
            if "secret" in leaked:
                self._flow("secret_to_model", node, leaked, "secret material is placed in a model request")
            return {"model"}
        if short in {"Server", "ServerAsync", "SorobanServer", "SorobanServerAsync"} and label.startswith("stellar_sdk") and node.args:
            # The RPC or Horizon server decides what the agent signs (simulation, auth entries, quotes).
            endpoint = self.tags(node.args[0], state)
            if endpoint & UNTRUSTED and not self._fixed_host(node.args[0], state):
                self._flow("endpoint", node, endpoint, "the ledger RPC or Horizon URL comes from input")
            return set()
        if _HTTP_CALL.search(label) or (short in {"get", "post", "put", "patch", "delete", "request"} and
                                        label.split(".")[0] in {"requests", "httpx", "session", "client", "http"}):
            self._cap("network_fetch", node)
            url = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "url"), None)
            url_tags = self.tags(url, state) if url is not None else set()
            # SSRF is about who picks the host. A library's own caller configuring a base
            # URL (`f"{self.api_url}{path}"`) is the developer, not an attacker, and a
            # tainted path on a fixed host is not a server-side request forgery.
            host_tags = self.tags(self._url_head(url), state) if url is not None else set()
            if host_tags & (UNTRUSTED - {"caller"}) and not self._fixed_host(url, state):
                self._flow("ssrf", node, url_tags, "request URL is not fixed to an allowed host")
            if "secret" in every:
                self._flow("secret_exfiltration", node, every, "secret material is sent over the network")
            return {"external"}
        if _CHAIN_READ.search(label):
            return every | receiver | {"chain"}
        if _FOREIGN_TX.search(label):
            out = every | receiver
            if out & UNTRUSTED:
                out.add("foreign_tx")
            return out

        # A callable looked up by a computed name on a module (getattr(__import__(m), name))
        # cannot be resolved statically; untrusted arguments make it an execution boundary.
        if (isinstance(node.func, ast.Call) and _dotted(node.func.func) == "getattr" and len(node.func.args) >= 2
                and not isinstance(node.func.args[1], ast.Constant)
                and (isinstance(node.func.args[0], ast.Call) and _dotted(node.func.args[0].func) in {"__import__", "importlib.import_module"}
                     or isinstance(node.func.args[0], ast.Name) and self.p.imports[self.module].get(node.func.args[0].id, "").startswith("lib:"))):
            self._cap("code_execution", node)
            if every & UNTRUSTED:
                self._flow("command", node, every, "untrusted input reaches a dynamically resolved module function")
            return every

        # A hash, JSON encoding or fixed-prefix text cannot be made equal to a transaction hash.
        if _STRUCTURING.match(short) or label.startswith("hashlib."):
            return every | receiver | {"structured"}
        # Deserializers that execute code from their input (pickle, unsafe YAML).
        if _DESERIALIZE.search(label):
            safe_yaml = label.startswith("yaml.") and short == "load" and any(
                kw.arg == "Loader" and "Safe" in _dotted(kw.value) for kw in node.keywords)
            data = (args[0] if args else set()) | kwargs.get("data", set())
            if data & UNTRUSTED and not safe_yaml:
                self._cap("code_execution", node)
                self._flow("command", node, data, "untrusted data is deserialized by a loader that runs embedded code")
            return data
        # A SQL string built from input (f-string, concatenation, format), not a bound parameter.
        if short in _SQL_CALL and isinstance(node.func, ast.Attribute) and node.args:
            query = node.args[0]
            text = " ".join(str(c.value) for c in ast.walk(query) if isinstance(c, ast.Constant) and isinstance(c.value, str))
            built = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "format")
            if built and _SQL_TEXT.search(text) and args[0] & UNTRUSTED:
                self._flow("sql", node, args[0], "a SQL statement is built from untrusted input")
        # The network passphrase decides which network a signature is valid on.
        passphrase = kwargs.get("network_passphrase", set()) | (args[0] if short == "Network" and label.startswith("stellar_sdk") and args else set())
        if passphrase & UNTRUSTED and (short in {"TransactionBuilder", "Network", "TransactionEnvelope", "build_transaction"}):
            self._flow("endpoint", node, passphrase, "the network passphrase comes from input")
        # Sinks.
        if _COMMAND_SINK.search(label):
            shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in node.keywords)
            # `subprocess.run(["stellar", "keys", name])`: no shell and a fixed program, so input
            # is one argument to that program and cannot start another command.
            first = node.args[0] if node.args else None
            fixed = (not shell and isinstance(first, (ast.List, ast.Tuple)) and first.elts
                     and isinstance(first.elts[0], ast.Constant) and isinstance(first.elts[0].value, str)
                     and not label.startswith(("os.system", "os.popen")))
            # `subprocess.run(cmd)` with an argument list built elsewhere and no shell: input can
            # only be arguments to the program the list names, so it cannot start another one.
            fixed = fixed or (label.startswith("subprocess.") and not shell and isinstance(first, (ast.Name, ast.Call, ast.Attribute))
                              and self._argv_list(first, state))
            # Running one fixed program is not arbitrary code execution.
            self._cap("process_spawn" if fixed else "code_execution", node)
            if every & UNTRUSTED and not fixed:
                self._flow("command", node, every, "shell=True" if shell else "")
            if self.record and CLI_AUTO_SIGN.search(" ".join(ast.unparse(a) for a in node.args)):
                self.p.profile.add_fact("cli_auto_sign", self.p.location(self.module, node),
                                        "stellar contract invoke --auto-sign", direct=bool(every & DIRECT))
            return set()
        if _FILE_SINK.search(label) or (short in _PATH_METHODS and isinstance(node.func, ast.Attribute)):
            self._cap("file_access", node)
            target = (args[0] if args else set()) | (receiver if short in _PATH_METHODS else set())
            if target & UNTRUSTED:
                self._flow("path_traversal", node, target, "file path is derived from untrusted input")
            return target if short in {"read_text", "read_bytes"} else set()
        if _LOG_SINK.search(label):
            if "secret" in every:
                self._flow("secret_exfiltration", node, every, "secret material is written to output")
            elif "secret_possible" in every:
                self._flow("secret_possible", node, every, "return value of a secret-bearing object is written to output")
            return set()
        if short == "build_fee_bump_transaction":
            # The outer envelope is the server's own and its signature covers only the fee; the
            # fee is the exposure when the inner transaction is someone else's.
            fee = kwargs.get("base_fee", args[1] if len(args) > 1 else set())
            inner = kwargs.get("inner_transaction_envelope", args[2] if len(args) > 2 else set())
            # A transaction the server built and stored itself (looked up by id) is not foreign.
            foreign = "foreign_tx" in inner or bool(inner & UNTRUSTED and not inner & {"stored_record", "tx_built"})
            # Chosen by the caller (a tool argument, a request, the client's envelope), not read
            # from the network's fee stats.
            if self.record and foreign and fee & {"model", "external", "foreign_tx"} and "bounded" not in fee and not self.approved:
                self.p.profile.add_fact("fee_bump_unbounded", self.p.location(self.module, node),
                                        "the fee of a foreign inner transaction comes from input")
            return {"tx_built"}
        if short in {"TransactionBuilder", "build_transaction"}:
            return every | {"tx_built"}
        if short in _PAYMENT_OPS:
            self._cap("payment", node)
            return receiver | self._payment_markers(node, state)
        if short in _TRUSTLINE_OPS:
            self._cap("trustline", node)
            return set(receiver)
        if short in _ACCOUNT_OPS:
            self._cap("account_control", node)
            out = set(receiver)
            if every & UNTRUSTED:
                out |= {"acct_untrusted"} | (every & UNTRUSTED)
            return out
        if short in {"sign", "sign_decorated"} and isinstance(node.func, ast.Attribute):
            signer = every | receiver
            if "signer" in signer:
                self._cap("stellar_signing", node)
                self._check_signed(node, receiver)
            # keypair.sign(data): the key signs raw bytes. If the requester picks them, they can
            # submit any transaction hash or Soroban authorization payload for signature.
            if "signer" in receiver and args and args[0] & UNTRUSTED and not args[0] & {"tx_built", "signer", "structured"} \
                    and not self.approved:
                self._flow("signing_oracle", node, args[0], "the agent key signs bytes chosen by the requester")
            return receiver
        if _SUBMIT.search("." + label):
            self._cap("tx_submission", node)
            self._check_signed(node, every)
            if every & UNTRUSTED and not every & {"tx_built", "foreign_tx"} and not self.approved:
                self._flow("financial", node, every, "an untrusted transaction envelope is submitted")
            return {"chain"}
        if _SOROBAN_SINK.search("." + label) or _SOROBAN_SINK.search(label):
            self._cap("contract_invocation", node)
            if every & UNTRUSTED and not self.approved:
                self._flow("financial", node, every, "untrusted values reach a contract invocation")
            return every | receiver
        if label in {"setattr", "getattr"}:
            return every

        if short in {"build", "to_xdr", "append_memo", "add_text_memo", "set_timeout", "add_time_bounds"} and receiver:
            return receiver | (every - {"signer"})
        if short in {"append", "extend", "insert", "add", "update", "setdefault", "put", "put_nowait"} \
                and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            name = node.func.value.id
            state[name] = state.get(name, set()) | every
        out = every | (receiver - {"signer"})
        if "secret" in receiver and "secret" not in every:
            # A method on a secret-holding object may return public data (a receipt).
            out = (out - {"secret"}) | {"secret_possible"}
        return out

    def _argv_list(self, node: ast.AST, state) -> bool:
        """A command value that is a list: a list literal assigned to the name, or a call whose
        project function returns one."""
        if isinstance(node, ast.Call):
            key = self.p._resolve_ref(self.module, node.func, self.local_types)
            fn = self.p.functions[key].node if key else None
            return bool(fn) and any(isinstance(r.value, (ast.List, ast.ListComp)) for r in ast.walk(fn)
                                    if isinstance(r, ast.Return) and r.value is not None)
        if isinstance(node, ast.Name) and self.fn is not None:
            return any(isinstance(a, ast.Assign) and any(isinstance(t, ast.Name) and t.id == node.id for t in a.targets)
                       and isinstance(a.value, (ast.List, ast.ListComp, ast.Call)) and (
                           not isinstance(a.value, ast.Call) or self._argv_list(a.value, state))
                       for a in ast.walk(self.fn.node))
        return False

    @staticmethod
    def _url_head(url: ast.AST) -> ast.AST:
        """The part of a URL expression that decides scheme and host."""
        if isinstance(url, ast.JoinedStr) and url.values:
            first = url.values[0]
            return first.value if isinstance(first, ast.FormattedValue) else first
        if isinstance(url, ast.BinOp) and isinstance(url.op, ast.Add):
            return _Interp._url_head(url.left)
        return url

    def _fixed_host(self, url: ast.AST | None, state) -> bool:
        if isinstance(url, ast.JoinedStr) and url.values and isinstance(url.values[0], ast.Constant):
            return bool(_SAFE_URL_PREFIX.match(str(url.values[0].value)))
        if isinstance(url, ast.BinOp) and isinstance(url.op, ast.Add) and isinstance(url.left, ast.Constant):
            return bool(_SAFE_URL_PREFIX.match(str(url.left.value)))
        return False

    def _payment_markers(self, node: ast.Call, state) -> set[str]:
        def arg(name: str, index: int) -> ast.AST | None:
            for kw in node.keywords:
                if kw.arg == name:
                    return kw.value
            return node.args[index] if len(node.args) > index else None
        dest = arg("destination", 0)
        amount = arg("amount", 2) or arg("starting_balance", 1) or arg("send_amount", 2)
        out: set[str] = set()
        dest_tags = self.tags(dest, state)
        amount_tags = self.tags(amount, state)
        if self.approved:
            return out  # an approval gate in this function covers recipient and amount
        if dest_tags & UNTRUSTED:
            out |= {"pay_dest_untrusted"} | (dest_tags & UNTRUSTED)
        # Only a conversion makes the asset choice matter: a plain payment can move only an asset
        # the account already holds, but a path payment trades through whatever assets and
        # pools it is given.
        if _dotted(node.func).rsplit(".", 1)[-1].startswith("append_path_payment"):
            route = [arg("send_asset", 1), arg("dest_asset", 3), arg("path", 5)]
            if any(t & UNTRUSTED for t in (self.tags(r, state) for r in route if r is not None)):
                out.add("pay_route_untrusted")
        if amount is not None and amount_tags & UNTRUSTED and "bounded" not in amount_tags:
            if self.record:
                self.p.profile.unbounded_amounts.append(self.p.location(self.module, node))
                if amount_tags & DIRECT:
                    self.p.profile.unbounded_direct_amounts.append(self.p.location(self.module, node))
            out |= {"pay_amount_untrusted"} | (amount_tags & UNTRUSTED)
        return out

    def _check_signed(self, node: ast.AST, tx_tags: set[str]) -> None:
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
        if "pay_route_untrusted" in tx_tags:
            self._flow("asset_route", node, tx_tags, "the assets or path of a path payment come from input")

    # -------------------------------------------------------------- guards
    def guard(self, test: ast.AST, state: dict[str, set[str]], *, blocking: bool, node: ast.AST) -> None:
        """Apply a fail-closed condition: code after it runs only when the test passed."""
        if not blocking:
            return
        # Approval gates: an approval call, or a check on an approval record.
        for sub in ast.walk(test):
            approval_call = isinstance(sub, ast.Call) and _APPROVAL_CALL.search(_dotted(sub.func).rsplit(".", 1)[-1])
            # An approval record (approval, approved_by), not a constant table named APPROVED.
            ident = sub.id if isinstance(sub, ast.Name) else sub.attr if isinstance(sub, ast.Attribute) else ""
            approval_name = bool(ident) and not ident.isupper() and re.search(r"approv", ident, re.I)
            if approval_name and not approval_call and self.forgeable(sub, state):
                # `if not args.approved`: the requester supplies the approval itself.
                if self.record:
                    where = (self.p.profile.forgeable_approvals if self.tags(sub, state) & DIRECT
                             else self.p.profile.unresolved_approvals)
                    where.append(self.p.location(self.module, node))
                break
            if approval_call or approval_name:
                self.approved = True
                self._control("approval", node)
                break
        for name in _upper_bounded(test):
            state[name] = state.get(name, set()) | {"bounded"}
            if AMOUNT_NAME.search(name):
                # A retry counter or a rating range is a bound, but not a spending cap.
                self._control("amount_cap", node)
        for sub in ast.walk(test):
            if isinstance(sub, ast.Compare):
                left = sub.left
                for op, right in zip(sub.ops, sub.comparators):
                    if isinstance(op, (ast.In, ast.NotIn)) and isinstance(left, ast.Name):
                        if not re.search(r"block|deny|ban|reject", _dotted(right), re.I):
                            state[left.id] = (state.get(left.id, set()) - UNTRUSTED) | {"checked"}
                            self._control("allowlist", node)
                    elif isinstance(op, (ast.NotEq, ast.IsNot)):
                        # Rejecting unless x equals a trusted (or approved) value binds x to it.
                        for side, other in ((left, right), (right, left)):
                            if isinstance(side, ast.Name) and not (isinstance(other, ast.Constant) and other.value is None):
                                if self.approved or not self.tags(other, state) & UNTRUSTED:
                                    state[side.id] = (state.get(side.id, set()) - UNTRUSTED) | {"checked"}
                                    self._control("value_binding", node)
                    left = right
            elif isinstance(sub, ast.Call):
                short = _dotted(sub.func).rsplit(".", 1)[-1]
                if short in {"is_relative_to", "startswith", "commonpath", "samefile"}:
                    for name in {n.id for n in ast.walk(sub.func) if isinstance(n, ast.Name)} | {
                            n.id for a in sub.args for n in ast.walk(a) if isinstance(n, ast.Name)}:
                        state[name] = state.get(name, set()) - UNTRUSTED
                    self._control("path_containment", node)
            elif isinstance(sub, ast.Attribute) and sub.attr == "operations":
                for name in {n.id for n in ast.walk(sub) if isinstance(n, ast.Name)}:
                    state[name] = state.get(name, set()) - {"foreign_tx"}
                self._control("transaction_inspection", node)

    def _control(self, kind: str, node: ast.AST) -> None:
        if self.record:
            self.p.control(kind, self.module, node)

    def _nonblocking(self, stmt: ast.If) -> bool:
        compares = [c for c in ast.walk(stmt.test) if isinstance(c, ast.Compare)
                    and any(isinstance(op, (ast.Gt, ast.GtE)) for op in c.ops)]
        if not compares or _terminates(stmt.body):
            return False
        warns = any(isinstance(n, ast.Call) and _LOG_SINK.search(_dotted(n.func)) for b in stmt.body for n in ast.walk(b))
        names = " ".join(_dotted(c) for comp in compares for c in [comp.left, *comp.comparators]).lower()
        return warns and bool(re.search(r"max|cap|limit|budget|threshold", names))

    # -------------------------------------------------------------- statements
    def bind(self, target: ast.AST, value: set[str], state: dict[str, set[str]]) -> None:
        if isinstance(target, ast.Name):
            state[target.id] = set(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, value, state)
        elif isinstance(target, ast.Attribute):
            state[_dotted(target)] = set(value)
            if isinstance(target.value, ast.Name) and target.value.id == "self" and self.fn and self.fn.cls:
                attrs = self.p.class_attrs.setdefault(f"{self.module}:{self.fn.cls}", {})
                current = attrs.setdefault(target.attr, set())
                if not value <= current:
                    current |= value
                    self.p._propagated = True

    def block(self, statements: list[ast.stmt], state: dict[str, set[str]], *, toplevel: bool = False) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # analysed as separate functions
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if stmt.value is None:
                    continue
                value = self.tags(stmt.value, state)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if isinstance(stmt, ast.AugAssign):
                    value |= self.tags(stmt.target, state)
                if isinstance(stmt.value, ast.Call):
                    cls = self.p._class_of(self.module, stmt.value.func)
                    if cls:
                        for t in targets:
                            if isinstance(t, ast.Name):
                                self.local_types[t.id] = cls
                for target in targets:
                    self.bind(target, value, state)
                    # Bound-method or function aliases: dispatch = horizon.submit_transaction
                    if isinstance(target, ast.Name):
                        if isinstance(stmt.value, (ast.Attribute, ast.Name)) and not self.p._resolve_ref(self.module, stmt.value, self.local_types):
                            self.aliases[target.id] = self.canonical(stmt.value)
                        else:
                            self.aliases.pop(target.id, None)
            elif isinstance(stmt, ast.If):
                self.tags(stmt.test, state)
                if self._nonblocking(stmt) and self.record:
                    self.p.profile.nonblocking_controls.append(self.p.location(self.module, stmt))
                if _terminates(stmt.body) and not stmt.orelse:
                    self.block(stmt.body, {k: set(v) for k, v in state.items()})
                    self.guard(stmt.test, state, blocking=True, node=stmt)
                    continue
                branches = []
                for body in (stmt.body, stmt.orelse):
                    branch = {k: set(v) for k, v in state.items()}
                    self.block(body, branch)
                    branches.append(branch)
                for key in set(branches[0]) | set(branches[1]):
                    state[key] = branches[0].get(key, set()) | branches[1].get(key, set())
            elif isinstance(stmt, ast.Assert):
                self.tags(stmt.test, state)
                self.guard(stmt.test, state, blocking=True, node=stmt)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                branch = {k: set(v) for k, v in state.items()}
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    self.bind(stmt.target, self.tags(stmt.iter, state), branch)
                else:
                    self.tags(stmt.test, state)
                for _ in range(2):  # second pass lets loop-carried labels reach sinks
                    self.block(stmt.body, branch)
                for key, value in branch.items():
                    state[key] = state.get(key, set()) | value
                self.block(stmt.orelse, state)
            elif isinstance(stmt, ast.Try):
                self.block(stmt.body, state)
                for handler in stmt.handlers:
                    self.block(handler.body, state)
                self.block(stmt.orelse, state)
                self.block(stmt.finalbody, state)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    value = self.tags(item.context_expr, state)
                    if item.optional_vars is not None:
                        self.bind(item.optional_vars, value, state)
                self.block(stmt.body, state)
            elif isinstance(stmt, ast.Return):
                value = self.tags(stmt.value, state)
                self.returned |= value
                if self.fn and self.fn.key in self.p.model_entries and "secret" in value:
                    self._flow("secret_to_model", stmt, value, "a tool result returned to the model contains secret material")
            elif hasattr(ast, "Match") and isinstance(stmt, getattr(ast, "Match")):
                self.tags(stmt.subject, state)
                for case in stmt.cases:
                    self.block(case.body, {k: set(v) for k, v in state.items()})
            else:
                self.tags(stmt, state)


def _js_profile(files: dict[str, str], profile: CodeProfile) -> None:
    """Capability inventory for non-Python sources (lexical; no data flow)."""
    patterns = {
        "key_custody": r"Keypair\.fromSecret",
        "stellar_signing": r"\.sign\(\s*\w*[Kk]eypair|signTransaction\(|authorizeEntry\(",
        "tx_submission": r"submitTransaction\(|sendTransaction\(",
        "payment": r"Operation\.(?:payment|pathPayment\w*|createAccount)\(",
        "account_control": r"Operation\.(?:setOptions|accountMerge)\(",
        "code_execution": r"child_process|\beval\(|new Function\(|execSync\(|spawn\(",
        "network_fetch": r"\bfetch\(|axios\.|https?\.request\(",
        "file_access": r"fs\.(?:readFile|writeFile|createReadStream|unlink)",
        "secret_material": r"process\.env\.\w*(?:SECRET|SEED|PRIVATE|KEY)\w*|\bS[A-Z2-7]{55}\b",
        "llm_call": r"messages\.create\(|chat\.completions\.create\(",
    }
    for path, content in files.items():
        if not path.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
            continue
        lines = content.splitlines()
        for cap, pattern in patterns.items():
            rx = re.compile(pattern)
            for number, line in enumerate(lines, 1):
                if rx.search(line):
                    profile.capabilities.setdefault(cap, []).append(Location(path, number, line))
                    break


#: Capabilities that put a held key to use: building, submitting or invoking transactions.
_KEY_USE = ("tx_submission", "payment", "contract_invocation", "account_control", "foreign_tx_signing")


def _custody_to_signing(profile: CodeProfile) -> None:
    """A loaded key is signing authority only when the project also transacts.

    Many signing paths hand the keypair to a library (contract clients, helpers) where
    `.sign(` never appears, so custody plus any transaction capability counts as
    signing. A wallet that only loads a key to read balances does not.
    """
    custody = profile.capabilities.get("key_custody", [])
    if custody and not profile.capabilities.get("stellar_signing") and any(
            profile.capabilities.get(cap) for cap in _KEY_USE):
        profile.capabilities["stellar_signing"] = list(custody)


def _key(files: dict[str, str], entrypoints: dict[str, set[str]]) -> str:
    payload = json.dumps([sorted(files.items()), sorted((k, sorted(v)) for k, v in entrypoints.items())])
    return hashlib.sha256(payload.encode()).hexdigest()


_CACHE: dict[str, CodeProfile] = {}


def analyse_code(files: dict[str, str], entrypoints: dict[str, set[str]] | None = None) -> CodeProfile:
    entrypoints = entrypoints or {}
    key = _key(files, entrypoints)
    if key not in _CACHE:
        if len(_CACHE) > 64:
            _CACHE.clear()
        try:
            project = _Project(files, entrypoints)
            profile = project.run()
            profile.analysed_files = sorted(project.module_of.values())
            from .jsflow import analyse_js
            js_done = analyse_js(files, profile, entrypoints)
            profile.analysed_files = sorted(set(profile.analysed_files) | set(js_done))
            # Lexical inventory only for JS/TS files the data-flow analysis could not parse.
            _js_profile({p: c for p, c in files.items() if p not in js_done}, profile)
            _custody_to_signing(profile)
        except (RecursionError, ValueError, TypeError, AttributeError, KeyError, IndexError) as exc:
            # Never fail open: an unanalysable submission is reported and cannot pass.
            profile = CodeProfile(error=f"{type(exc).__name__}: source analysis did not complete")
        _CACHE[key] = profile
    return _CACHE[key]
