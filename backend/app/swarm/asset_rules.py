"""Which account and which asset a payment names, and which amount it signs.

A Stellar payment is only as good as three values: the destination, the asset (code plus
issuer, or the SAC contract id) and the amount. These rules find the deterministic ways code
gets them wrong: a StrKey literal with a bad checksum, a payee that falls back to the null
account, a missing issuer that silently becomes XLM, an amount that the spending cap parses
with parseFloat while the signer parses it with BigInt (so '0x3B9ACA00' is 0 to the cap and
1,000,000,000 stroops to the signer), and a received payment accepted by asset code alone.
"""

from __future__ import annotations

import ast
import functools
import itertools
import re

from ..models import AgentArtifact, Severity
from ..services.lockfiles import Lockset, version_key
from ..stellar.canonical import strkey_valid
from .consolidate import stable_id
from .jsflow import _args, _param_names, _props, _string_value, _txt, _unwrap
from .source_index import (TEST_PATH, JsFile, PyFile, SourceIndex, callee_name, drop, index_for,
                           js_functions_type, receiver, unparse)

#: The all-zero ed25519 key: nobody holds its secret, so a payment to it is lost.
NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
#: A literal shaped like an account, muxed account or contract StrKey, including the 55- and
#: 57-character near misses. Seeds (S...) are left out: an invalid one is a placeholder, and a
#: valid one is the committed-seed rule's.
_STRKEY_LIKE = re.compile(r"[GCM][A-Z2-7]{53,69}")
_RUN = re.compile(r"(.)\1{9,}")
#: Names that make a literal a payment value: who is paid, in which asset.
_PAYMENT_NAME = re.compile(r"asset|token|usdc|eurc|sac|pay_?to|payee|destination|recipient|merchant|seller|issuer|"
                           r"receiver|treasury|currency", re.I)
#: Names of credentials and caches: a base32 value bound to SESSION_TOKEN is not a token contract.
_CREDENTIAL_NAME = re.compile(r"session|auth|access|refresh|bearer|jwt|api|secret|csrf|oauth|totp|otp|cache|nonce", re.I)
#: The file is Stellar code: it names the network, an SDK or a payment protocol.
_STELLAR_TEXT = re.compile(r"stellar|soroban|horizon|x402|@stellar/mpp|StrKey", re.I)
_PAYEE_NAME = re.compile(r"pay_?to|payee|recipient|destination|seller|merchant|receiver|treasury", re.I)
_EXEMPT_KEY = re.compile(r"example|placeholder|description|sample|dummy|mock", re.I)
#: Demo data loaded into a database: its addresses are placeholders, not configuration.
_SEED_DATA = re.compile(r"(^|/)seeds?(/|\.[a-z]+$)|(^|/)seed[-_]data", re.I)
#: Calls that only convert or slice a string: their result still holds the raw amount.
_RAW_CALLS = frozenset({"split", "trim", "slice", "substring", "substr", "toString", "toLowerCase", "toUpperCase",
                        "padEnd", "padStart", "replace", "String", "at", "concat"})
_SIMULATION = re.compile(r"source|simulat|placeholder|dummy|zero|null|fake|sim\b", re.I)
#: @stellar/mpp's constants: every published release (0.2.0 to 0.7.1) ships a 54-character
#: USDC_SAC_MAINNET and a 55-character XLM_SAC_MAINNET (dist/constants.js).
MPP_BAD_CONSTANTS = frozenset({"USDC_SAC_MAINNET", "XLM_SAC_MAINNET", "SAC_ADDRESSES"})
MPP_LAST_BAD = "0.7.1"
#: Receipt and verification code: a handler that grants service for, or records, a payment.
_RECEIPT = re.compile(r"verif|receipt|incoming|deposit|paid|settle|confirm|paywall|webhook|proof", re.I)
_LEDGER_READ = re.compile(r"/operations|/payments|\.payments\(\)|\.operations\(\)|forTransaction|/transactions/|"
                          r"getTransaction|\.effects\(\)|\bpayments_for|operations_for|\.records\b", re.I)
_CODE_FIELDS = {"asset_code", "assetCode"}
_ISSUER_FIELD = re.compile(r"\b(?:asset_issuer|assetIssuer|issuer)\b")
_NATIVE = {"native", "XLM", "xlm"}
_ISSUER_COMPARED = re.compile(r"""(?:asset_issuer|assetIssuer|\.issuer|getIssuer\(\))["'\]]*\s*(?:===?|!==?)|(?:===?|!==?)\s*"""
                              r"""[\w$.]*(?:asset_issuer|assetIssuer|\.issuer\b|getIssuer\(\))|\.equals\(""")
#: A receipt check reaches a verdict: it throws or rejects, returns a boolean or a verdict, or
#: records the payment. Display code that filters and maps payment records does none of these.
_OUTCOME = re.compile(r"\bthrow\b|\breturn\s+(?:true|false)\b|\b(?:verified|valid|isValid|ok|paid|success|confirmed|settled|"
                      r"accepted|matched?)\s*:|\.(?:some|every|find|findIndex|includes)\s*\(|\breject\s*\(|\.status\(\s*4\d\d|"
                      r"\b(?:mark|settle|fulfil|deliver|grant|credit|record)\w*\s*\(")
_PY_OUTCOME = re.compile(r"\braise\b|\breturn\s+(?:True|False)\b|[\"'](?:verified|valid|ok|paid|success|confirmed|settled|"
                         r"accepted)[\"']\s*:|\b(?:any|all)\s*\(|\b(?:mark|settle|fulfil|deliver|grant|credit|record)\w*\s*\(")
#: Parsers that read '0x10' as 0 (the cap side) and sinks that read it as 16 (the signer side).
_FLOAT_PARSE = re.compile(r"^(?:parseFloat|Number\.parseFloat)$")
#: Parsers that read '0x10' as 16, as BigInt does: a cap computed with them agrees with the signer.
_SOUND_PARSE = re.compile(r"^(?:Number|BigInt)$")
#: The other side of a spending cap: a maximum, limit, budget or what remains of one (not a
#: floor such as a minimum, zero or dust amount).
_CAP_BOUND = re.compile(r"cap(?!ital|tur|tion|abilit)|max|limit|budget|remaining|ceiling|allowance|quota", re.I)
_FLOOR_BOUND = re.compile(r"(?:^|[^A-Za-z])[Mm]in|[a-z]Min|MIN|[Ff]loor|FLOOR|[Dd]ust|DUST|[Ll]ower")
_ARITHMETIC = frozenset({"+", "-", "*", "/", "%", "**"})
#: Calls that refuse a request in the too-large branch.
_REJECT_CALL = re.compile(r"^(?:reject|deny|abort|exit|fail\w*|refuse\w*)$", re.I)
_BIGINT_SINKS = {"BigInt", "nativeToScVal", "ScInt", "XdrLargeInt"}
#: The value is an amount (the last name of `req.amount`, `value`, `priceStroops`, ...).
_AMOUNT_NAME = re.compile(r"amount|price|value|cost|fee|total|sum|qty|quantity|stroops|units", re.I)
_DIGITS_ONLY = re.compile(r"\^\\d|\^\[0-9\]|\^\(\?:\\d|\^\(\\d")


def _names(node) -> set[str]:
    """The identifiers and member chains an expression reads."""
    return {_txt(n) for n in SourceIndex.walk(node) if n.type in {"identifier", "member_expression"}} \
        if node is not None else set()


#: At most this many amount values are judged per function (A5).
_SEEDS = 32


@functools.lru_cache(maxsize=4096)
def _mention_pattern(names: frozenset[str]) -> re.Pattern:
    """One pattern for a set of names: any of them as a whole name or member chain."""
    return re.compile(r"(?<![\w$.])(?:" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
                      + r")(?![\w$])")


def _js_binder(node) -> str:
    """The name a value is bound to: `key: value`, `const NAME = value`, `x.y = value`,
    through `||`, `??`, parentheses and ternaries."""
    n = node
    while n.parent is not None and n.parent.type in {"binary_expression", "parenthesized_expression", "ternary_expression",
                                                     "as_expression", "satisfies_expression", "non_null_expression"}:
        n = n.parent
    parent = n.parent
    if parent is None:
        return ""
    if parent.type == "pair":
        return _txt(parent.child_by_field_name("key")).strip("'\"")
    if parent.type == "variable_declarator":
        return _txt(parent.child_by_field_name("name"))
    if parent.type == "assignment_expression":
        return _txt(parent.child_by_field_name("left"))
    if parent.type in {"assignment_pattern", "required_parameter", "optional_parameter"}:
        return _txt(parent.child_by_field_name("left") or parent.child_by_field_name("pattern"))
    if parent.type == "public_field_definition":
        return _txt(parent.child_by_field_name("name"))
    return ""


class AssetRules:
    def __init__(self, artifact: AgentArtifact):
        self.index: SourceIndex = index_for(artifact.code_files)
        self.locks = Lockset(artifact.raw_metadata.get("resolved_versions"))
        self._float_memo: dict[tuple, bool] = {}
        self._bigint_memo: dict[tuple, bool] = {}
        self._fn_parts: dict[tuple, dict[str, list]] = {}
        self._derived_memo: dict[tuple, set[str]] = {}
        self._side_memo: dict[tuple, list[tuple[str, str]]] = {}
        self._used: dict[str, int] | None = None

    def _uses(self, name: str) -> int:
        """How often a name occurs as code across the project (declaration included)."""
        if self._used is None:
            counts: dict[str, int] = {}
            for js in self.index.js.values():
                if TEST_PATH.search(js.path):
                    continue
                for node in SourceIndex.walk(js.root):
                    if node.type in {"identifier", "property_identifier", "shorthand_property_identifier"}:
                        counts[_txt(node)] = counts.get(_txt(node), 0) + 1
            for py in self.index.py.values():
                if TEST_PATH.search(py.path):
                    continue
                for node in ast.walk(py.tree):
                    key = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
                    if key:
                        counts[key] = counts.get(key, 0) + 1
            for path, text in self.index.rust.items():
                if not TEST_PATH.search(path):
                    for word in re.findall(r"\b[A-Za-z_]\w*\b", text.split("#[cfg(test)]", 1)[0]):
                        counts[word] = counts.get(word, 0) + 1
            self._used = counts
        return self._used.get(name, 0)

    # ================================================================= A1: invalid StrKey literals
    def bad_strkeys(self) -> list[tuple[str, int, str, str, Severity]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or _SEED_DATA.search(js.path) or not _STRKEY_LIKE.search(js.text):
                continue
            for node in SourceIndex.walk(js.root):
                if node.type not in {"string", "template_string"}:
                    continue
                value = _string_value(node)
                if not value or not _STRKEY_LIKE.fullmatch(value) or _RUN.search(value) or strkey_valid(value):
                    continue
                binder = _js_binder(node)
                if _js_exempt(node) or _EXEMPT_KEY.search(binder):
                    continue
                place = self._strkey_place(js.path, js.line(node), js.snippet(node), value, binder,
                                           bool(_STELLAR_TEXT.search(js.text)))
                if place:
                    out.append(place)
        for py in self.index.py.values():
            if TEST_PATH.search(py.path) or _SEED_DATA.search(py.path):
                continue
            docstrings = {id(n.body[0].value) for n in ast.walk(py.tree)
                          if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                          and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
            for node in ast.walk(py.tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or id(node) in docstrings:
                    continue
                value = node.value
                if not _STRKEY_LIKE.fullmatch(value) or _RUN.search(value) or strkey_valid(value):
                    continue
                binder = _py_binder(node, py)
                if _EXEMPT_KEY.search(binder) or _py_exempt(node, py):
                    continue
                place = self._strkey_place(py.path, node.lineno, py.snippet(node), value, binder,
                                           bool(_STELLAR_TEXT.search(py.text)))
                if place:
                    out.append(place)
        for path, text in self.index.rust.items():
            if TEST_PATH.search(path):
                continue
            code = text.split("#[cfg(test)]", 1)[0]
            for m in re.finditer(r'"([GCM][A-Z2-7]{53,69})"', code):
                value = m.group(1)
                start = code.rfind("\n", 0, m.start()) + 1
                prefix = code[start:m.start()].lstrip()
                if prefix.startswith(("//", "*", "/*")) or _RUN.search(value) or strkey_valid(value):
                    continue
                binder = re.search(r"(?:const|static|let)\s+(?:mut\s+)?(\w+)", prefix)
                line = code.count("\n", 0, m.start()) + 1
                place = self._strkey_place(path, line, " ".join(code[start:code.find("\n", m.end())].split())[:160],
                                           value, binder.group(1) if binder else "", True)
                if place:
                    out.append(place)
        return out

    def _strkey_place(self, path: str, line: int, snippet: str, value: str, binder: str, stellar: bool):
        """The finding place for an invalid literal, or None when nothing makes it a Stellar
        value (no payment name and no Stellar code in the file: a base32 id or secret)."""
        name = binder.rsplit(".", 1)[-1]
        words = {m.group(0).lower() for m in _PAYMENT_NAME.finditer(binder or "")}
        if words == {"token"} and (not stellar or _CREDENTIAL_NAME.search(binder)):
            words = set()  # SESSION_TOKEN, AUTH_TOKEN: a credential, not a token contract
        if not words and not stellar:
            return None
        used = bool(name) and self._uses(name) > 1
        severity = Severity.MEDIUM if words and used else Severity.LOW
        why = f"{len(value)} characters" if len(value) not in (56, 69) else "bad checksum"
        return path, line, snippet, why, drop(severity, path)

    def mpp_constants(self) -> list[tuple[str, int, str, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or "@stellar/mpp" not in js.text:
                continue
            for node in SourceIndex.walk(js.root):
                if node.type != "import_statement":
                    continue
                source = _string_value(node.child_by_field_name("source")) or ""
                if not re.match(r"^@stellar/mpp(?:/|$)", source):
                    continue
                names = {_txt(s.child_by_field_name("name")) for s in SourceIndex.walk(node) if s.type == "import_specifier"}
                hits = names & MPP_BAD_CONSTANTS
                if hits == {"SAC_ADDRESSES"} and not re.search(r"pubnet|mainnet|public", js.text, re.I):
                    continue
                if not hits:
                    continue
                found = self.locks.resolve("@stellar/mpp", near=js.path)
                versions = list(found.versions) if found else []
                if versions and all(version_key(v) is not None and version_key(v) <= version_key(MPP_LAST_BAD)
                                    for v in versions):
                    out.append((js.path, js.line(node), js.snippet(node), f"@stellar/mpp {', '.join(versions)}"))
        return out

    # ================================================================= A2: x402 asset set to an account
    def asset_is_account(self) -> list[tuple[str, int, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or not re.search(r"G[A-Z2-7]{55}", js.text):
                continue
            for node in SourceIndex.walk(js.root):
                if node.type != "object":
                    continue
                props = _props(node)
                for key, siblings in (("asset", {"payTo", "maxAmountRequired", "scheme"}), ("currency", {"recipient"})):
                    value = _string_value(props.get(key)) if props.get(key) is not None else None
                    if value and re.fullmatch(r"G[A-Z2-7]{55}", value) and siblings & set(props):
                        out.append((js.path, js.line(props[key]), js.snippet(props[key])))
        return out

    # ================================================================= A3: payee falls back to the null account
    def null_payee(self) -> list[tuple[str, int, str, Severity]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or NULL_ACCOUNT not in js.text:
                continue
            nulls = {_txt(d.child_by_field_name("name")) for d in SourceIndex.walk(js.root)
                     if d.type == "variable_declarator" and _string_value(d.child_by_field_name("value")) == NULL_ACCOUNT}
            for node in SourceIndex.walk(js.root):
                if node.type != "binary_expression" or _txt(node.child_by_field_name("operator")) not in {"||", "??"}:
                    continue
                right = _unwrap(node.child_by_field_name("right"))
                if right is None or not (_string_value(right) == NULL_ACCOUNT or _txt(right) in nulls):
                    continue
                binder = _js_binder(node)
                named = binder if binder else _txt(right)
                if (_PAYEE_NAME.search(named) or _PAYEE_NAME.search(_txt(right))) and not _SIMULATION.search(binder or ""):
                    out.append((js.path, js.line(node), js.snippet(node), drop(Severity.MEDIUM, js.path)))
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for node in ast.walk(py.tree):
                default = None
                if isinstance(node, ast.Call) and unparse(node.func) in {"os.getenv", "os.environ.get", "getenv"} \
                        and len(node.args) > 1:
                    default = node.args[1]
                elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                    default = node.values[-1]
                if not (isinstance(default, ast.Constant) and default.value == NULL_ACCOUNT):
                    continue
                binder = _py_binder(node, py)
                if _PAYEE_NAME.search(binder) and not _SIMULATION.search(binder):
                    out.append((py.path, node.lineno, py.snippet(node), drop(Severity.MEDIUM, py.path)))
        return out

    # ================================================================= A4: missing issuer becomes XLM
    def native_fallback(self) -> list[tuple[str, int, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or "native" not in js.text:
                continue
            for call in SourceIndex.calls(js.root):
                recv = receiver(call)
                if callee_name(call) != "native" or recv is None or not _txt(recv).endswith("Asset"):
                    continue
                cond, taken = _js_branch(call)
                fn = SourceIndex.enclosing_function(call) or js.root
                if cond is None or not re.search(r"new\s+(?:[\w$]+\.)?Asset\s*\(", _txt(fn)):
                    continue
                if _falls_back(cond, taken, _js_guards(call), _js_condition):
                    out.append((js.path, js.line(call), js.snippet(cond)))
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for node in ast.walk(py.tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "native"
                        and unparse(node.func.value).endswith("Asset")):
                    continue
                cond, taken = _py_branch(node, py)
                fn = _py_function(node, py)
                if cond is None or not re.search(r"\bAsset\s*\(", py.source(fn)):
                    continue
                if _falls_back(cond, taken, _py_guards(node, py), _py_condition):
                    out.append((py.path, node.lineno, py.snippet(cond)))
        return out

    # ================================================================= A5: amount parsed two ways
    def dual_parse(self) -> list[tuple[str, int, str]]:
        out = []
        texts = [js.text for js in self.index.js.values()]
        if not any("parseFloat" in t for t in texts) or \
                not any(re.search(r"BigInt|nativeToScVal|ScInt|XdrLargeInt|createPaymentPayload", t) for t in texts):
            return out  # no cap parsed with parseFloat, or no BigInt signer, anywhere in the project
        for js in self.index.js.values():
            if TEST_PATH.search(js.path):
                continue
            if re.search(r"\.regex\(\s*/" + r"[^/\n]*(?:\\d|\[0-9\])", js.text):
                continue
            for fn in SourceIndex.walk(js.root):
                if not js_functions_type(fn):
                    continue
                float_side, sink_side, payloads = self._reach(fn)
                judged = 0
                for seed, line in self._seeds(js, fn):
                    if not _AMOUNT_NAME.search(seed.rsplit(".", 1)[-1]):
                        continue
                    # Only a value that can reach a parseFloat and a BigInt sink (here, through a
                    # local, or through a project function) is judged, and at most _SEEDS of them.
                    paid = seed in sink_side or (seed.endswith(".amount") and seed.split(".", 1)[0] in payloads)
                    if seed not in float_side or not paid or judged >= _SEEDS:
                        continue
                    judged += 1
                    if self._tested(js, fn, seed) or not self._external(js, fn, seed):
                        continue
                    if self._float_cap(js, fn, seed, 0) and self._bigint(js, fn, seed, 0):
                        out.append((js.path, line, f"{seed}: {js.lines[line - 1].strip()[:120]}"))
                        break
        return out

    def _reach(self, fn) -> tuple[set[str], set[str], set[str]]:
        """The names and member chains that can reach a parseFloat call, or a BigInt sink, in this
        function: those in the parser's or sink's first argument, in a local's initializer (it
        may derive the raw string) or in an argument to a project function; and the payload
        objects passed to createPaymentPayload. One walk per function."""
        names = _names
        shared: set[str] = set()
        floats, sinks, payloads = set(), set(), set()
        for node in SourceIndex.walk(fn):
            if node.type == "variable_declarator":
                shared |= names(node.child_by_field_name("value"))
            elif node.type == "call_expression":
                args = _args(node)
                name = callee_name(node)
                if args and _FLOAT_PARSE.match(_txt(node.child_by_field_name("function"))):
                    floats |= names(args[0])
                if name in _BIGINT_SINKS and args:
                    sinks |= names(args[1] if name == "XdrLargeInt" and len(args) > 1 else args[0])
                if name == "createPaymentPayload" and len(args) > 1:
                    sinks |= names(args[1])
                    payloads.add(_txt(_unwrap(args[1])))
                if args and self.index.defs(name):
                    for arg in args:
                        shared |= names(arg)
        return floats | shared, sinks | shared, payloads

    @staticmethod
    def _seeds(js: JsFile, fn) -> list[tuple[str, int]]:
        """Values passed to a parser or a call in this function (not in nested ones)."""
        seen: dict[str, int] = {}
        for call in SourceIndex.calls(fn, include_nested=False):
            for arg in _args(call):
                arg = _unwrap(arg)
                if arg is not None and arg.type in {"identifier", "member_expression"} and len(_txt(arg)) < 80:
                    seen[_txt(arg)] = min(seen.get(_txt(arg), js.line(arg)), js.line(arg))
            for arg in _args(call)[1:2]:
                amount = _props(arg).get("amount")
                if amount is not None and _unwrap(amount) is not None and _unwrap(amount).type in {"identifier", "member_expression"}:
                    seen[_txt(_unwrap(amount))] = min(seen.get(_txt(_unwrap(amount)), js.line(amount)), js.line(amount))
        return sorted(seen.items(), key=lambda item: item[1])

    @staticmethod
    def _mentions(text: str, names: set[str]) -> bool:
        return bool(names) and bool(_mention_pattern(frozenset(names)).search(text))

    def _parts(self, js: JsFile, fn) -> dict[str, list]:
        """The nodes of a function the A5 checks read, collected in one walk: calls (``own``: not
        inside nested functions), local declarations and size comparisons."""
        key = (js.path, fn.start_byte, fn.end_byte, fn.type)
        if key not in self._fn_parts:
            parts: dict[str, list] = {"calls": [], "own": [], "decls": [], "compares": [], "parsers": []}
            stack = [(c, False) for c in reversed(fn.named_children)]
            while stack:
                node, nested = stack.pop()
                if node.type == "call_expression":
                    parts["calls"].append(node)
                    if not nested and self.index.defs(callee_name(node)):
                        parts["own"].append(node)  # a call into the project: the value may be capped there
                    callee, args = _txt(node.child_by_field_name("function")), _args(node)
                    if args and (_FLOAT_PARSE.match(callee) or _SOUND_PARSE.match(callee)):
                        parts["parsers"].append((node, callee, _txt(args[0])))
                elif node.type == "variable_declarator":
                    parts["decls"].append(node)
                elif node.type == "binary_expression" and _txt(node.child_by_field_name("operator")) in {"<", ">", "<=", ">="}:
                    parts["compares"].append((node, _names(node)))
                inner = nested or js_functions_type(node)
                stack.extend((c, inner) for c in reversed(node.named_children))
            self._fn_parts[key] = parts
        return self._fn_parts[key]

    def _side_calls(self, js: JsFile, node) -> list[tuple[str, str]]:
        """(callee, first argument) of the calls in an expression, itself included; once per node."""
        key = (js.path, node.start_byte, node.end_byte, node.type)
        if key not in self._side_memo:
            self._side_memo[key] = [(_txt(c.child_by_field_name("function")), _txt(_args(c)[0]))
                                    for c in [node, *SourceIndex.calls(node)] if c.type == "call_expression" and _args(c)]
        return self._side_memo[key]

    def _derived(self, js: JsFile, fn, seed: str) -> set[str]:
        """Locals that still hold the raw string: `parts = amount.split('.')`, `whole = parts[0] || '0'`
        (a conversion such as atomicToUsdc(amount) or Number(amount) ends the chain)."""
        key = (js.path, fn.start_byte, fn.end_byte, seed)
        if key in self._derived_memo:
            return self._derived_memo[key]
        names = {seed}
        for node in self._parts(js, fn)["decls"]:
            value, target = node.child_by_field_name("value"), node.child_by_field_name("name")
            if value is None or target is None or not self._raw(value, names):
                continue
            if target.type == "identifier":
                names.add(_txt(target))
            elif target.type in {"array_pattern", "object_pattern"}:  # const [whole, frac] = v.split(".")
                names |= {_txt(n) for n in SourceIndex.walk(target)
                          if n.type in {"identifier", "shorthand_property_identifier_pattern"}}
        self._derived_memo[key] = names
        return names

    def _raw(self, node, names: set[str]) -> bool:
        """The expression carries one of the names as the raw string: no call other than a string
        method (split, trim, ...) takes it as an argument on the way."""
        if not self._mentions(_txt(node), names):
            return False
        return not any(callee_name(c) not in _RAW_CALLS and any(self._mentions(_txt(a), names) for a in _args(c))
                       for c in [node, *SourceIndex.calls(node)] if c.type == "call_expression")

    def _float_cap(self, js: JsFile, fn, seed: str, depth: int) -> bool:
        """The value is capped through parseFloat here or in a callee (and not also capped
        through Number or BigInt, which parse it as the signer does)."""
        key = (js.path, fn.start_byte, fn.end_byte, seed, "float")
        if key in self._float_memo:
            return self._float_memo[key]
        self._float_memo[key] = False
        names = self._derived(js, fn, seed)
        float_side, sound_side = self._parsed(js, fn, names, _FLOAT_PARSE), self._parsed(js, fn, names, _SOUND_PARSE)
        capped = False
        read = names | float_side.parsed | sound_side.parsed
        for node, used in self._parts(js, fn)["compares"] if float_side.found or sound_side.found else []:
            if not used & read:
                continue  # the comparison names none of the value's forms
            if _upper_bound(node, sound_side):
                return False  # a sound cap on the same value: the parseFloat one is only advisory
            capped = capped or _upper_bound(node, float_side)
        result = capped or (depth < 2 and self._through_calls(js, fn, names, depth, self._float_cap))
        self._float_memo[key] = result
        return result

    def _parsed(self, js: JsFile, fn, names: set[str], parser):
        """A test for an expression that holds the value as `parser` reads it: a parser call
        on the value, or a local computed from one (`const price = parseFloat(x) / 1e7`). Its
        ``found`` says whether the function parses the value that way at all."""
        parsed: set[str] = set()
        parts = self._parts(js, fn)
        found = False
        for call, callee, first in parts["parsers"]:
            if parser.match(callee) and self._mentions(first, names):
                found = True
                holder = call.parent
                while holder is not None and (holder.type in {"parenthesized_expression", "await_expression"} or (
                        holder.type == "binary_expression" and _txt(holder.child_by_field_name("operator")) in _ARITHMETIC)):
                    holder = holder.parent
                if holder is not None and holder.type == "variable_declarator":
                    parsed.add(_txt(holder.child_by_field_name("name")))
        changed = True
        while changed and parsed:  # const total = spent + price
            changed = False
            for node in parts["decls"]:
                if node.child_by_field_name("value") is not None and \
                        _txt(node.child_by_field_name("name")) not in parsed and \
                        self._mentions(_txt(node.child_by_field_name("value")), parsed):
                    parsed.add(_txt(node.child_by_field_name("name")))
                    changed = True

        def holds(side) -> bool:
            if side is None:
                return False
            if any(parser.match(callee) and self._mentions(first, names) for callee, first in self._side_calls(js, side)):
                return True
            return bool(parsed) and self._mentions(_txt(side), parsed)
        holds.found, holds.parsed = found, parsed
        return holds

    def _bigint(self, js: JsFile, fn, seed: str, depth: int) -> bool:
        key = (js.path, fn.start_byte, fn.end_byte, seed, "bigint")
        if key in self._bigint_memo:
            return self._bigint_memo[key]
        self._bigint_memo[key] = False
        names = self._derived(js, fn, seed)
        root = seed.split(".", 1)[0]
        for call in self._parts(js, fn)["calls"]:
            name = callee_name(call)
            args = _args(call)
            if name in _BIGINT_SINKS and args:
                if self._raw(args[1] if name == "XdrLargeInt" and len(args) > 1 else args[0], names):
                    self._bigint_memo[key] = True
                    return True
            if name == "createPaymentPayload" and len(args) > 1:
                payload = _unwrap(args[1])
                amount = _props(payload).get("amount") if payload is not None and payload.type == "object" else None
                if (amount is not None and self._raw(amount, names)) or \
                        (payload is not None and _txt(payload) == root and seed.endswith(".amount")):
                    self._bigint_memo[key] = True
                    return True
        result = depth < 2 and self._through_calls(js, fn, names, depth, self._bigint)
        self._bigint_memo[key] = result
        return result

    def _through_calls(self, js: JsFile, fn, names: set[str], depth: int, check) -> bool:
        """The value reaches a project function's parameter that has the property."""
        for call in self._parts(js, fn)["own"]:
            for position, arg in enumerate(_args(call)):
                if not self._raw(arg, names):
                    continue
                for other, target in self.index.defs(callee_name(call)):
                    if other.path == js.path and target == fn:
                        continue
                    params = target.child_by_field_name("parameters")
                    plist = [p for p in (params.named_children if params is not None else []) if p.type != "comment"]
                    if position >= len(plist):
                        continue
                    param = plist[position]
                    pattern = param.child_by_field_name("pattern") if param.type in {"required_parameter", "optional_parameter"} else param
                    if pattern is not None and pattern.type == "identifier" and check(other, target, _txt(pattern), depth + 1):
                        return True
        return False

    def _tested(self, js: JsFile, fn, seed: str) -> bool:
        """A digits-only regular expression is tested against the value first."""
        for call in self._parts(js, fn)["calls"]:
            if callee_name(call) == "test" and any(seed in _txt(a) for a in _args(call)):
                recv = receiver(call)
                if recv is not None and _DIGITS_ONLY.search(_txt(recv)):
                    return True
        return False

    def _external(self, js: JsFile, fn, seed: str) -> bool:
        """The value comes from the caller (a parameter) or from a response or request body."""
        root = seed.split(".", 1)[0]
        if root in _param_names(fn):
            return True
        for node in self._parts(js, fn)["decls"]:
            if _txt(node.child_by_field_name("name")) == root:
                value = _txt(node.child_by_field_name("value"))
                if re.search(r"\.json\(\)|JSON\.parse|accepts|\.body\b|headers\.get|decode\w*\(|\breq\b|\brequest\b", value):
                    return True
                derived = re.match(r"\s*(?:await\s+)?([\w$]+)", value)
                if derived and derived.group(1) != root and derived.group(1) in _param_names(fn):
                    return True
        return False

    # ================================================================= A6: payment accepted by asset code
    def _helper_compares_issuer(self, scope, root: str) -> bool:
        """A project function that receives the record compares its issuer:
        `op.asset_code === code && sameIssuer(op, expected)`."""
        for call in SourceIndex.calls(scope):
            if not any(_txt(_unwrap(a)) == root for a in _args(call)):
                continue
            for _, target in self.index.defs(callee_name(call)):
                if _ISSUER_COMPARED.search(_txt(target)):
                    return True
        return False

    def code_only_checks(self) -> list[tuple[str, int, str, bool]]:
        """(file, line, code, compared with a literal code) for received payments checked by code."""
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path) or not re.search(r"asset_code|assetCode|getCode|\.code\b", js.text):
                continue
            for node in SourceIndex.walk(js.root):
                if node.type != "binary_expression" or _txt(node.child_by_field_name("operator")) not in {"===", "==", "!==", "!="}:
                    continue
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                for code, other in ((left, right), (right, left)):
                    root = _code_access(code)
                    if root is None or _code_access(other) is not None or _ISSUER_FIELD.search(_txt(other)):
                        continue
                    literal = _string_value(other)
                    if literal is not None and (literal in _NATIVE or not re.fullmatch(r"[A-Za-z0-9]{1,12}", literal)):
                        break
                    if other.type not in {"identifier", "member_expression", "string", "subscript_expression"}:
                        break
                    fn = SourceIndex.enclosing_function(node)
                    outer = _outer_function(fn) or js.root
                    if not _RECEIPT.search(_txt(outer)[:4000] + js.path) or not _LEDGER_READ.search(_txt(outer)):
                        break
                    if re.search(r"balance", root, re.I) or _in_balances_callback(fn) or not _js_decides(outer, node):
                        break
                    equality = _txt(node.child_by_field_name("operator")) in {"===", "=="}
                    either = equality and _in_disjunction(node)
                    # An issuer comparison anywhere in the verifier counts (it may test another
                    # handle on the same record, or call a helper that does); only the `||`
                    # fallback fires regardless.
                    checked = re.search(r"(?<![\w$])" + re.escape(root) + r"(?:\.asset)?\.(?:asset_issuer|assetIssuer|issuer|"
                                        r"getIssuer)\b|" + re.escape(root) + r"(?:\.asset)?\.equals\(", _txt(fn or outer)) or \
                        _ISSUER_COMPARED.search(_txt(outer)) or self._helper_compares_issuer(outer, root)
                    if either or not checked:
                        out.append((js.path, js.line(node), js.snippet(node), literal is not None))
                    break
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for fn in ast.walk(py.tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                text = py.source(fn)
                if not _RECEIPT.search(fn.name + text[:4000] + py.path) or not _LEDGER_READ.search(text) or \
                        not _py_decides(fn, py):
                    continue
                for node in ast.walk(fn):
                    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and
                            isinstance(node.ops[0], (ast.Eq, ast.NotEq))):
                        continue
                    sides = [node.left, node.comparators[0]]
                    for code, other in (sides, sides[::-1]):
                        root = _py_code_access(code)
                        if root is None or re.search(r"balance", root, re.I):
                            continue
                        literal = other.value if isinstance(other, ast.Constant) and isinstance(other.value, str) else None
                        if literal is not None and literal in _NATIVE or _ISSUER_FIELD.search(unparse(other)):
                            break
                        parent = py.parents.get(node)
                        either = isinstance(node.ops[0], ast.Eq) and isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.Or)
                        checked = re.search(re.escape(root) + r"""(?:\[["']asset_issuer["']\]|\.(?:asset_issuer|issuer))""", text) \
                            or _ISSUER_COMPARED.search(text)
                        if either or not checked:
                            out.append((py.path, node.lineno, py.snippet(node), literal is not None))
                        break
        return out


# --------------------------------------------------------------------------- spending caps
def _upper_bound(cmp, holds) -> bool:
    """`cmp` (<, >, <= or >=) caps the value `holds` recognises: the value is alone on one side,
    the other side is a positive literal or a cap, limit or budget, and the too-large outcome
    is refused. A positivity check (`parseFloat(x) <= 0`) or a minimum is not a cap: hex
    reads as 0 there and fails closed."""
    op = _txt(cmp.child_by_field_name("operator"))
    left, right = cmp.child_by_field_name("left"), cmp.child_by_field_name("right")
    in_left, in_right = holds(left), holds(right)
    if in_left == in_right:
        return False
    value, bound = (left, right) if in_left else (right, left)
    too_large = (value == left) == (op in {">", ">="})  # the comparison's value for a huge amount
    text = _txt(bound)
    named = bool(_CAP_BOUND.search(text)) and not _FLOOR_BOUND.search(text)
    if not (named or _positive_literal(bound)):
        return False
    node = cmp
    while True:
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "parenthesized_expression":
            node = parent
            continue
        if parent.type == "unary_expression" and _txt(parent.child_by_field_name("operator")) == "!":
            node, too_large = parent, not too_large
            continue
        if parent.type == "binary_expression" and _txt(parent.child_by_field_name("operator")) in {"||", "&&"}:
            if (_txt(parent.child_by_field_name("operator")) == "||") != too_large:
                return False  # `x <= cap || override`: the other term decides
            node = parent
            continue
        break
    if parent.type == "if_statement" and parent.child_by_field_name("condition") == node:
        if too_large:
            return _rejects(parent.child_by_field_name("consequence"))
        alternative = parent.child_by_field_name("alternative")
        if alternative is not None:
            return any(_rejects(c) for c in alternative.named_children)
        return _js_exits(parent.child_by_field_name("consequence"))  # `if (x <= cap) return pay(); throw ...`
    # A boolean that is returned or kept (`return amount <= this.remaining`): only a named cap.
    return named and parent.type in {"return_statement", "variable_declarator", "assignment_expression", "arrow_function",
                                     "arguments", "pair", "ternary_expression"}


def _positive_literal(node) -> bool:
    """A positive number, or arithmetic on positive numbers only (`5 * 1e7`). Walked with an
    explicit stack: a bound written as a long sum must not exhaust the call stack."""
    stack = [node]
    while stack:
        node = _unwrap(stack.pop())
        if node is None:
            return False
        if node.type == "number":
            text = _txt(node).replace("_", "").rstrip("n")
            try:
                if not (int(text, 0) if re.fullmatch(r"0[xXoObB][0-9a-fA-F]+|\d+", text) else float(text)) > 0:
                    return False
            except ValueError:
                return False
        elif node.type == "binary_expression" and _txt(node.child_by_field_name("operator")) in _ARITHMETIC:
            stack += [node.child_by_field_name("left"), node.child_by_field_name("right")]
        else:
            return False
    return True


def _rejects(branch) -> bool:
    """The branch refuses: it throws, returns, leaves the loop or calls reject (a warning
    alone does not)."""
    stack = [branch] if branch is not None else []
    while stack:
        node = stack.pop()
        if node.type in {"throw_statement", "return_statement", "break_statement", "continue_statement"}:
            return True
        if node.type == "call_expression" and _REJECT_CALL.match(callee_name(node)):
            return True
        stack.extend(c for c in node.named_children if not js_functions_type(c))
    return False


# --------------------------------------------------------------------------- condition evaluation
_ISSUER_PRESENT, _ISSUER_ABSENT, _CODE_NATIVE, _CODE_OTHER, _CODE_PRESENT, _UNKNOWN = range(6)


def _falls_back(cond, taken: bool, guards, parse) -> bool:
    """A credit code without an issuer reaches the Asset.native() branch: the branch's
    condition sends it there, and no statement that runs first exits (throw, raise or
    return) for it, such as `if (code !== 'XLM' && !issuer) throw ...`. Conditions too deeply
    nested to evaluate count as not reaching it."""
    try:
        atoms: list = []
        expr = parse(cond, atoms)
        if expr is None or not any(kind in (_ISSUER_PRESENT, _ISSUER_ABSENT) for kind in atoms) or \
                not _always(expr, atoms, taken):
            return False
        for guard in guards:
            atoms = []
            expr = parse(guard, atoms)
            if expr is not None and _always(expr, atoms, True):
                return False
        return True
    except RecursionError:
        return False


def _always(expr, atoms: list, want: bool) -> bool:
    """With a credit code (say USDC) and no issuer, the condition is `want` whatever its
    other terms are."""
    unknown = [i for i, kind in enumerate(atoms) if kind == _UNKNOWN][:4]
    for values in itertools.product((False, True), repeat=len(unknown)):
        assignment = dict(zip(unknown, values))
        fixed = {i: {_ISSUER_PRESENT: False, _ISSUER_ABSENT: True, _CODE_NATIVE: False, _CODE_OTHER: True,
                     _CODE_PRESENT: True}.get(kind) for i, kind in enumerate(atoms)}
        fixed.update(assignment)
        if _evaluate(expr, fixed) is not want:
            return False
    return True


def _evaluate(expr, values: dict) -> bool:
    op = expr[0]
    if op == "atom":
        return bool(values.get(expr[1]))
    if op == "not":
        return not _evaluate(expr[1], values)
    if op == "and":
        return _evaluate(expr[1], values) and _evaluate(expr[2], values)
    return _evaluate(expr[1], values) or _evaluate(expr[2], values)


def _atom(atoms: list, kind: int):
    atoms.append(kind)
    return ("atom", len(atoms) - 1)


def _js_condition(node, atoms: list):
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "unary_expression" and _txt(node.child_by_field_name("operator")) == "!":
        inner = _js_condition(node.child_by_field_name("argument"), atoms)
        return ("not", inner) if inner is not None else None
    if node.type == "binary_expression":
        op = _txt(node.child_by_field_name("operator"))
        if op in {"&&", "||"}:
            left = _js_condition(node.child_by_field_name("left"), atoms)
            right = _js_condition(node.child_by_field_name("right"), atoms)
            return None if left is None or right is None else ("and" if op == "&&" else "or", left, right)
        if op in {"===", "==", "!==", "!="}:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            text = _txt(left) + " " + _txt(right)
            negated = op in {"!==", "!="}
            if re.search(r"issuer", text, re.I) and re.search(r"\b(?:undefined|null)\b|^''$|^\"\"$", _txt(right) + _txt(left)):
                return _atom(atoms, _ISSUER_PRESENT if negated else _ISSUER_ABSENT)
            literal = _string_value(right) or _string_value(left)
            if literal in _NATIVE and re.search(r"code|asset|type", text, re.I):
                return _atom(atoms, _CODE_OTHER if negated else _CODE_NATIVE)
        return _atom(atoms, _UNKNOWN)
    if node.type in {"identifier", "member_expression"}:
        text = _txt(node)
        if re.search(r"issuer", text, re.I):
            return _atom(atoms, _ISSUER_PRESENT)
        if re.search(r"code", text, re.I):
            return _atom(atoms, _CODE_PRESENT)
    return _atom(atoms, _UNKNOWN)


def _py_condition(node, atoms: list):
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ("not", _py_condition(node.operand, atoms))
    if isinstance(node, ast.BoolOp):
        parts = [_py_condition(v, atoms) for v in node.values]
        expr = parts[0]
        for part in parts[1:]:
            expr = ("and" if isinstance(node.op, ast.And) else "or", expr, part)
        return expr
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        text = unparse(node)
        other = node.comparators[0]
        if re.search(r"issuer", text, re.I) and isinstance(other, ast.Constant) and other.value in (None, ""):
            return _atom(atoms, _ISSUER_PRESENT if isinstance(node.ops[0], (ast.IsNot, ast.NotEq)) else _ISSUER_ABSENT)
        literal = other.value if isinstance(other, ast.Constant) else None
        if literal in _NATIVE and re.search(r"code|asset|type", text, re.I):
            return _atom(atoms, _CODE_OTHER if isinstance(node.ops[0], (ast.NotEq, ast.IsNot)) else _CODE_NATIVE)
        return _atom(atoms, _UNKNOWN)
    if isinstance(node, (ast.Name, ast.Attribute)):
        text = unparse(node)
        if re.search(r"issuer", text, re.I):
            return _atom(atoms, _ISSUER_PRESENT)
        if re.search(r"code", text, re.I):
            return _atom(atoms, _CODE_PRESENT)
    return _atom(atoms, _UNKNOWN)


def _js_branch(call) -> tuple[object, bool]:
    """(condition, whether Asset.native() runs when it is true) for the nearest conditional."""
    node = call
    while node.parent is not None and not js_functions_type(node.parent):
        parent = node.parent
        if parent.type == "ternary_expression" and node != parent.child_by_field_name("condition"):
            return parent.child_by_field_name("condition"), node == parent.child_by_field_name("consequence")
        if parent.type == "if_statement" and node != parent.child_by_field_name("condition"):
            return parent.child_by_field_name("condition"), node == parent.child_by_field_name("consequence")
        if parent.type == "else_clause" and parent.parent is not None and parent.parent.type == "if_statement":
            return parent.parent.child_by_field_name("condition"), False
        node = parent
    return None, False


def _js_exits(node) -> bool:
    node = _unwrap(node)
    if node is not None and node.type == "statement_block":
        stmts = [c for c in node.named_children if c.type != "comment"]
        node = stmts[-1] if stmts else None
    return node is not None and node.type in {"throw_statement", "return_statement"}


def _js_guards(call):
    """Conditions of the `if (...) throw/return` statements that run before the call, in
    each enclosing block up to its function."""
    node = call
    while node.parent is not None and not js_functions_type(node.parent):
        parent = node.parent
        if parent.type in {"statement_block", "program", "switch_case", "switch_default"}:
            for stmt in parent.named_children:
                if stmt.start_byte >= node.start_byte:
                    break
                if stmt.type == "if_statement" and _js_exits(stmt.child_by_field_name("consequence")):
                    yield stmt.child_by_field_name("condition")
        node = parent


def _py_guards(node, py: PyFile):
    """Python's `if ...: raise/return` statements that run before the node."""
    child, parent = node, py.parents.get(node)
    while parent is not None:
        for name in ("body", "orelse", "finalbody"):
            block = getattr(parent, name, None)
            if isinstance(block, list) and any(stmt is child for stmt in block):
                for stmt in block[:next(i for i, s in enumerate(block) if s is child)]:
                    if isinstance(stmt, ast.If) and stmt.body and isinstance(stmt.body[-1], (ast.Raise, ast.Return)):
                        yield stmt.test
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        child, parent = parent, py.parents.get(parent)


def _py_branch(call, py: PyFile) -> tuple[object, bool]:
    node = call
    parent = py.parents.get(node)
    while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        if isinstance(parent, ast.IfExp) and node is not parent.test:
            return parent.test, node is parent.body
        if isinstance(parent, ast.If) and node is not parent.test:
            return parent.test, node in parent.body
        node, parent = parent, py.parents.get(parent)
    return None, False


def _py_function(node, py: PyFile):
    parent = py.parents.get(node)
    while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parent = py.parents.get(parent)
    return parent or py.tree


def _py_binder(node, py: PyFile) -> str:
    parent = py.parents.get(node)
    while isinstance(parent, (ast.BoolOp, ast.IfExp, ast.Call)) and not (
            isinstance(parent, ast.Call) and node in parent.args and unparse(parent.func) not in
            {"os.getenv", "os.environ.get", "getenv"}):
        node, parent = parent, py.parents.get(parent)
    if isinstance(parent, ast.Assign):
        return " ".join(unparse(t) for t in parent.targets)
    if isinstance(parent, ast.AnnAssign):
        return unparse(parent.target)
    if isinstance(parent, ast.keyword):
        return parent.arg or ""
    if isinstance(parent, ast.Dict):
        for key, value in zip(parent.keys, parent.values):
            if value is node and isinstance(key, ast.Constant):
                return str(key.value)
    if isinstance(parent, ast.arguments):
        for arg, default in zip(parent.args[len(parent.args) - len(parent.defaults):], parent.defaults):
            if default is node:
                return arg.arg
    return ""


def _js_exempt(node) -> bool:
    """Inside an example, placeholder or description: a JSX placeholder, an `examples:` block."""
    parent = node.parent
    while parent is not None and not js_functions_type(parent):
        if parent.type == "pair" and _EXEMPT_KEY.search(_txt(parent.child_by_field_name("key"))):
            return True
        if parent.type == "jsx_attribute" and re.search(r"placeholder", _txt(parent), re.I):
            return True
        if parent.type == "call_expression" and callee_name(parent) in {"describe", "example", "examples"}:
            return True
        parent = parent.parent
    return False


def _py_exempt(node, py: PyFile) -> bool:
    child, parent = node, py.parents.get(node)
    while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if isinstance(parent, ast.Dict):
            for key, value in zip(parent.keys, parent.values):
                if value is child and isinstance(key, ast.Constant) and _EXEMPT_KEY.search(str(key.value)):
                    return True
        if isinstance(parent, ast.keyword) and _EXEMPT_KEY.search(parent.arg or ""):
            return True
        child, parent = parent, py.parents.get(parent)
    return False


def _code_access(node) -> str | None:
    """The object whose asset code is read: `op.asset_code` -> op, `p.asset.code` -> p."""
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "member_expression":
        prop = _txt(node.child_by_field_name("property"))
        obj = _unwrap(node.child_by_field_name("object"))
        if prop in _CODE_FIELDS:
            return _txt(obj)
        if prop == "code" and obj is not None and obj.type == "member_expression" and \
                _txt(obj.child_by_field_name("property")) == "asset":
            return _txt(_unwrap(obj.child_by_field_name("object")))
    if node.type == "subscript_expression":
        index = _string_value(node.child_by_field_name("index"))
        if index in _CODE_FIELDS:
            return _txt(_unwrap(node.child_by_field_name("object")))
    if node.type == "call_expression" and callee_name(node) == "getCode" and not _args(node):  # op.asset.getCode()
        obj = receiver(node)
        if obj is not None and obj.type == "member_expression" and _txt(obj.child_by_field_name("property")) == "asset":
            return _txt(_unwrap(obj.child_by_field_name("object")))
        return _txt(obj) if obj is not None else None
    return None


def _js_decides(outer, node) -> bool:
    """The receipt function reaches a verdict (see _OUTCOME), or returns the comparison itself."""
    body = outer.child_by_field_name("body") if js_functions_type(outer) else outer
    if body is not None and _OUTCOME.search(_txt(body)):
        return True
    expr = node
    while expr.parent is not None and (expr.parent.type == "parenthesized_expression" or (
            expr.parent.type == "binary_expression" and _txt(expr.parent.child_by_field_name("operator")) in {"&&", "||"})):
        expr = expr.parent
    parent = expr.parent
    if parent is not None and parent.type == "arrow_function":  # (r) => r.asset_code === ...: a callback's verdict
        host = parent.parent.parent if parent.parent is not None and parent.parent.type == "arguments" else None
        return host is None or callee_name(host) not in {"filter", "map", "forEach", "flatMap", "sort", "reduce"}
    return parent is not None and parent.type == "return_statement"


def _py_decides(fn, py: PyFile) -> bool:
    body = "\n".join(py.lines[fn.body[0].lineno - 1:fn.end_lineno]) if fn.body else ""
    return bool(_PY_OUTCOME.search(body)) or any(
        isinstance(n, ast.Return) and isinstance(n.value, (ast.Compare, ast.BoolOp)) for n in ast.walk(fn))


def _py_code_access(node) -> str | None:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in _CODE_FIELDS:
        return unparse(node.value)
    if isinstance(node, ast.Attribute) and node.attr in _CODE_FIELDS:
        return unparse(node.value)
    return None


def _outer_function(fn):
    """The outermost function: callbacks inside a verifier belong to it."""
    outer = fn
    node = fn
    while node is not None:
        if js_functions_type(node):
            outer = node
        node = node.parent
    return outer


def _in_balances_callback(fn) -> bool:
    return fn is not None and fn.parent is not None and fn.parent.type == "arguments" and \
        re.search(r"balances", _txt(fn.parent.parent.child_by_field_name("function")) if fn.parent.parent else "")


def _in_disjunction(node) -> bool:
    """The code test is one alternative of an `||`, alone or AND-ed only with terms that do not
    compare the issuer: `full === expected || (op.asset.getCode && op.asset.getCode() === expected)`."""
    child, parent = node, node.parent
    while parent is not None:
        if parent.type == "parenthesized_expression":
            child, parent = parent, parent.parent
            continue
        if parent.type != "binary_expression":
            return False
        op = _txt(parent.child_by_field_name("operator"))
        if op == "||":
            return True
        if op != "&&":
            return False
        left, right = parent.child_by_field_name("left"), parent.child_by_field_name("right")
        sibling = right if child == left else left
        if _ISSUER_FIELD.search(_txt(sibling)) or re.search(r"getIssuer|\.equals\(", _txt(sibling)):
            return False
        child, parent = parent, parent.parent
    return False


def asset_findings(rules: AssetRules, make) -> list:
    """The findings of the rules above (one per rule and file);
    `make(id, severity, title, detail, evidence, remediation, refs)` builds one."""
    findings = []

    def per_file(rule: str, places: list[tuple], severity_of, title: str, detail: str, remediation: str, refs: list[str]):
        by_file: dict[str, list[tuple]] = {}
        for place in sorted(places, key=lambda p: (p[0], p[1])):
            by_file.setdefault(place[0], []).append(place)
        for path, items in by_file.items():
            severity = max((severity_of(item) for item in items), key=lambda s: s.rank)
            if severity is Severity.INFO:
                continue
            evidence = [f"{path}:{item[1]} `{item[2][:150]}`" + (f" ({item[3]})" if len(item) > 3 and isinstance(item[3], str)
                                                                    and not isinstance(item[3], Severity) else "")
                        for item in items[:6]]
            findings.append(make(stable_id(rule, path, items[0][2]), severity, title, detail, evidence, remediation, refs))

    per_file("security-strkey-invalid", rules.bad_strkeys(), lambda item: item[4],
             "An account or contract id in the code is not a valid StrKey",
             "The literal has the shape of a Stellar address or contract id, but its length or checksum is wrong. Any "
             "payment, requirement or check that uses it fails or never matches: a paywall built on it cannot be "
             "paid, and a client cannot pay it.",
             "Replace it with the real StrKey (StrKey.isValidContract / isValidEd25519PublicKey), and validate configured "
             "addresses at startup.", ["Stellar StrKey (SEP-23)"])
    per_file("security-sac-constant-invalid", rules.mpp_constants(), lambda item: drop(Severity.MEDIUM, item[0]),
             "MPP's mainnet SAC constant is not a valid contract id",
             "@stellar/mpp up to 0.7.1 exports USDC_SAC_MAINNET with 54 characters and XLM_SAC_MAINNET with 55: neither "
             "is a contract id, so a mainnet charge priced in them cannot be paid or verified.",
             "Use the SAC ids derived from the asset (Asset('USDC', issuer).contractId(Networks.PUBLIC)).",
             ["@stellar/mpp dist/constants.js"])
    per_file("security-payment-asset-is-account", rules.asset_is_account(), lambda item: drop(Severity.LOW, item[0]),
             "A payment's asset is an account address, not a token contract",
             "x402 and MPP name the asset by its contract id (C...). An account address (G...) is not an asset: clients "
             "reject the requirement, so the route cannot be paid.",
             "Use the asset's SAC contract id.", ["x402 exact scheme for Stellar"])
    per_file("security-payee-defaults-to-null-account", rules.null_payee(), lambda item: item[3],
             "Payments go to the null account when the payee is not configured",
             "When the variable is unset the payee falls back to GAAAA...WHF, the all-zero key. Nobody holds its secret, "
             "so every payment made to it is lost and the operator receives nothing.",
             "Fail at startup when the payee is not configured.", ["CWE-1188 Insecure Default Initialization"])
    per_file("security-missing-issuer-pays-xlm", rules.native_fallback(), lambda item: drop(Severity.MEDIUM, item[0]),
             "An asset without an issuer silently becomes XLM",
             "When a credit asset code (USDC, EURC, ...) arrives without its issuer, this branch builds Asset.native(). "
             "The operation then moves XLM in the amount meant for the other asset, with no error.",
             "Use native only when the code is XLM; reject a credit code that has no issuer.", ["Stellar assets"])
    per_file("security-amount-parsed-two-ways", rules.dual_parse(), lambda item: drop(Severity.HIGH, item[0]),
             "The spending cap and the signer read the amount differently",
             "The cap parses the amount with parseFloat, but the signed amount comes from BigInt (directly, through "
             "nativeToScVal or through @x402/stellar createPaymentPayload). parseFloat('0x3B9ACA00') is 0 while "
             "BigInt('0x3B9ACA00') is 1,000,000,000 stroops: a hex, binary or octal amount passes every cap and signs "
             "an arbitrarily large payment.",
             "Validate the amount against /^\\d+(\\.\\d{1,7})?$/ (or digits only for atomic units) before the cap, and "
             "compute both the cap and the signed value from the same parsed integer.",
             ["CWE-1287 Improper Validation of Specified Type of Input", "x402 exact scheme for Stellar"])
    return findings


def probe(artifact: AgentArtifact) -> dict[str, list]:
    """Raw results of each rule (used by corpus tooling)."""
    rules = AssetRules(artifact)
    return {"A1": rules.bad_strkeys(), "A1b": rules.mpp_constants(), "A2": rules.asset_is_account(),
            "A3": rules.null_payee(), "A4": rules.native_fallback(), "A5": rules.dual_parse(),
            "A6": rules.code_only_checks()}
