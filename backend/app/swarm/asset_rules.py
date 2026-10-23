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
import itertools
import re

from ..models import AgentArtifact, Severity
from ..services.lockfiles import Lockset, version_key
from ..stellar.canonical import strkey_valid
from .consolidate import stable_id
from .jsflow import _args, _param_names, _props, _string_value, _txt, _unwrap
from .source_index import (EXAMPLE_PATH, TEST_PATH, JsFile, PyFile, SourceIndex, callee_name, index_for,
                           js_functions_type, receiver)

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
_ISSUER_COMPARED = re.compile(r"""(?:asset_issuer|assetIssuer|\.issuer)["'\]]*\s*(?:===?|!==?)|(?:===?|!==?)\s*[\w$.]*"""
                              r"""(?:asset_issuer|assetIssuer|\.issuer)\b|\.equals\(""")
#: Parsers that read '0x10' as 0 (the cap side) and sinks that read it as 16 (the signer side).
_FLOAT_PARSE = re.compile(r"^(?:parseFloat|Number\.parseFloat)$")
_BIGINT_SINKS = {"BigInt", "nativeToScVal", "ScInt", "XdrLargeInt"}
#: The value is an amount (the last name of `req.amount`, `value`, `priceStroops`, ...).
_AMOUNT_NAME = re.compile(r"amount|price|value|cost|fee|total|sum|qty|quantity|stroops|units", re.I)
_DIGITS_ONLY = re.compile(r"\^\\d|\^\[0-9\]|\^\(\?:\\d|\^\(\\d")


def _drop(severity: Severity, path: str) -> Severity:
    if EXAMPLE_PATH.search(path):
        return Severity.LOW if severity.rank >= Severity.MEDIUM.rank else Severity.INFO
    return severity


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
            if TEST_PATH.search(js.path) or _SEED_DATA.search(js.path):
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
                out.append(self._strkey_place(js.path, js.line(node), js.snippet(node), value, binder))
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
                out.append(self._strkey_place(py.path, node.lineno, py.snippet(node), value, binder))
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
                out.append(self._strkey_place(path, line, " ".join(code[start:code.find("\n", m.end())].split())[:160],
                                              value, binder.group(1) if binder else ""))
        return out

    def _strkey_place(self, path: str, line: int, snippet: str, value: str, binder: str):
        name = binder.rsplit(".", 1)[-1]
        used = bool(name) and self._uses(name) > 1
        severity = Severity.MEDIUM if _PAYMENT_NAME.search(binder or "") and used else Severity.LOW
        why = f"{len(value)} characters" if len(value) not in (56, 69) else "bad checksum"
        return path, line, snippet, why, _drop(severity, path)

    def mpp_constants(self) -> list[tuple[str, int, str, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path):
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
            if TEST_PATH.search(js.path):
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
            if TEST_PATH.search(js.path):
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
                    out.append((js.path, js.line(node), js.snippet(node), _drop(Severity.MEDIUM, js.path)))
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for node in ast.walk(py.tree):
                default = None
                if isinstance(node, ast.Call) and ast.unparse(node.func) in {"os.getenv", "os.environ.get", "getenv"} \
                        and len(node.args) > 1:
                    default = node.args[1]
                elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                    default = node.values[-1]
                if not (isinstance(default, ast.Constant) and default.value == NULL_ACCOUNT):
                    continue
                binder = _py_binder(node, py)
                if _PAYEE_NAME.search(binder) and not _SIMULATION.search(binder):
                    out.append((py.path, node.lineno, py.snippet(node), _drop(Severity.MEDIUM, py.path)))
        return out

    # ================================================================= A4: missing issuer becomes XLM
    def native_fallback(self) -> list[tuple[str, int, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path):
                continue
            for call in SourceIndex.calls(js.root):
                recv = receiver(call)
                if callee_name(call) != "native" or recv is None or not _txt(recv).endswith("Asset"):
                    continue
                cond, taken = _js_branch(call)
                fn = SourceIndex.enclosing_function(call) or js.root
                if cond is None or not re.search(r"new\s+(?:[\w$]+\.)?Asset\s*\(", _txt(fn)):
                    continue
                atoms: list = []
                expr = _js_condition(cond, atoms)
                if expr is not None and _missing_issuer_goes_native(expr, atoms, taken):
                    out.append((js.path, js.line(call), js.snippet(cond)))
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for node in ast.walk(py.tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "native"
                        and ast.unparse(node.func.value).endswith("Asset")):
                    continue
                cond, taken = _py_branch(node, py)
                fn = _py_function(node, py)
                if cond is None or "Asset(" not in ast.unparse(fn).replace("Asset.native()", ""):
                    continue
                atoms = []
                expr = _py_condition(cond, atoms)
                if expr is not None and _missing_issuer_goes_native(expr, atoms, taken):
                    out.append((py.path, node.lineno, py.snippet(cond)))
        return out

    # ================================================================= A5: amount parsed two ways
    def dual_parse(self) -> list[tuple[str, int, str]]:
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path):
                continue
            validated = re.search(r"\.regex\(\s*/" + r"[^/\n]*(?:\\d|\[0-9\])", js.text)
            for fn in SourceIndex.walk(js.root):
                if not js_functions_type(fn):
                    continue
                for seed, line in self._seeds(js, fn):
                    if not _AMOUNT_NAME.search(seed.rsplit(".", 1)[-1]) or validated or self._tested(fn, seed):
                        continue
                    if not self._external(js, fn, seed):
                        continue
                    if self._float_cap(js, fn, seed, 0) and self._bigint(js, fn, seed, 0):
                        out.append((js.path, line, f"{seed}: {js.lines[line - 1].strip()[:120]}"))
                        break
        return out

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
        return any(re.search(r"(?<![\w$.])" + re.escape(n) + r"(?![\w$])", text) for n in names)

    def _derived(self, fn, seed: str) -> set[str]:
        """Locals that still hold the raw string: `parts = amount.split('.')`, `whole = parts[0] || '0'`
        (a conversion such as atomicToUsdc(amount) or Number(amount) ends the chain)."""
        names = {seed}
        for node in SourceIndex.walk(fn):
            if node.type == "variable_declarator":
                value, target = node.child_by_field_name("value"), node.child_by_field_name("name")
                if value is None or target is None or not self._raw(value, names):
                    continue
                if target.type == "identifier":
                    names.add(_txt(target))
                elif target.type in {"array_pattern", "object_pattern"}:  # const [whole, frac] = v.split(".")
                    names |= {_txt(n) for n in SourceIndex.walk(target)
                              if n.type in {"identifier", "shorthand_property_identifier_pattern"}}
        return names

    def _raw(self, node, names: set[str]) -> bool:
        """The expression carries one of the names as the raw string: no call other than a string
        method (split, trim, ...) takes it as an argument on the way."""
        if not self._mentions(_txt(node), names):
            return False
        return not any(callee_name(c) not in _RAW_CALLS and any(self._mentions(_txt(a), names) for a in _args(c))
                       for c in [node, *SourceIndex.calls(node)] if c.type == "call_expression")

    def _float_cap(self, js: JsFile, fn, seed: str, depth: int) -> bool:
        key = (js.path, fn.start_byte, fn.end_byte, seed, "float")
        if key in self._float_memo:
            return self._float_memo[key]
        self._float_memo[key] = False
        names = self._derived(fn, seed)
        parsed: set[str] = set()
        for call in SourceIndex.calls(fn):
            if _FLOAT_PARSE.match(_txt(call.child_by_field_name("function"))) and \
                    any(self._mentions(_txt(a), names) for a in _args(call)[:1]):
                holder = call.parent
                while holder is not None and holder.type in {"binary_expression", "parenthesized_expression", "await_expression"}:
                    if holder.type == "binary_expression" and _txt(holder.child_by_field_name("operator")) in {"<", ">", "<=", ">="}:
                        self._float_memo[key] = True
                        return True
                    holder = holder.parent
                if holder is not None and holder.type == "variable_declarator":
                    parsed.add(_txt(holder.child_by_field_name("name")))
        changed = True
        while changed and parsed:  # const price = parseFloat(x) / 1e7; const total = spent + price
            changed = False
            for node in SourceIndex.walk(fn):
                if node.type == "variable_declarator" and node.child_by_field_name("value") is not None and \
                        _txt(node.child_by_field_name("name")) not in parsed and \
                        self._mentions(_txt(node.child_by_field_name("value")), parsed):
                    parsed.add(_txt(node.child_by_field_name("name")))
                    changed = True
        for node in SourceIndex.walk(fn):
            if node.type == "binary_expression" and _txt(node.child_by_field_name("operator")) in {"<", ">", "<=", ">="} \
                    and parsed and self._mentions(_txt(node), parsed):
                self._float_memo[key] = True
                return True
        result = depth < 2 and self._through_calls(js, fn, names, depth, self._float_cap)
        self._float_memo[key] = result
        return result

    def _bigint(self, js: JsFile, fn, seed: str, depth: int) -> bool:
        key = (js.path, fn.start_byte, fn.end_byte, seed, "bigint")
        if key in self._bigint_memo:
            return self._bigint_memo[key]
        self._bigint_memo[key] = False
        names = self._derived(fn, seed)
        root = seed.split(".", 1)[0]
        for call in SourceIndex.calls(fn):
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
        for call in SourceIndex.calls(fn, include_nested=False):
            for position, arg in enumerate(_args(call)):
                if not self._raw(arg, names):
                    continue
                for other, target in self.index.js_defs.get(callee_name(call), []):
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

    @staticmethod
    def _tested(fn, seed: str) -> bool:
        """A digits-only regular expression is tested against the value first."""
        for call in SourceIndex.calls(fn):
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
        for node in SourceIndex.walk(fn):
            if node.type == "variable_declarator" and _txt(node.child_by_field_name("name")) == root:
                value = _txt(node.child_by_field_name("value"))
                if re.search(r"\.json\(\)|JSON\.parse|accepts|\.body\b|headers\.get|decode\w*\(|\breq\b|\brequest\b", value):
                    return True
                derived = re.match(r"\s*(?:await\s+)?([\w$]+)", value)
                if derived and derived.group(1) != root and derived.group(1) in _param_names(fn):
                    return True
        return False

    # ================================================================= A6: payment accepted by asset code
    def code_only_checks(self) -> list[tuple[str, int, str, bool]]:
        """(file, line, code, compared with a literal code) for received payments checked by code."""
        out = []
        for js in self.index.js.values():
            if TEST_PATH.search(js.path):
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
                    if re.search(r"balance", root, re.I) or _in_balances_callback(fn):
                        break
                    equality = _txt(node.child_by_field_name("operator")) in {"===", "=="}
                    either = equality and _in_disjunction(node)
                    # An issuer comparison anywhere in the verifier counts (it may test another
                    # handle on the same record); only the `||` fallback fires regardless.
                    checked = re.search(r"(?<![\w$])" + re.escape(root) + r"(?:\.asset)?\.(?:asset_issuer|assetIssuer|issuer)\b|"
                                        + re.escape(root) + r"(?:\.asset)?\.equals\(", _txt(fn or outer)) or \
                        _ISSUER_COMPARED.search(_txt(outer))
                    if either or not checked:
                        out.append((js.path, js.line(node), js.snippet(node), literal is not None))
                    break
        for py in self.index.py.values():
            if TEST_PATH.search(py.path):
                continue
            for fn in ast.walk(py.tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                text = ast.unparse(fn)
                if not _RECEIPT.search(fn.name + text[:4000] + py.path) or not _LEDGER_READ.search(text):
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
                        if literal is not None and literal in _NATIVE or _ISSUER_FIELD.search(ast.unparse(other)):
                            break
                        parent = py.parents.get(node)
                        either = isinstance(node.ops[0], ast.Eq) and isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.Or)
                        checked = re.search(re.escape(root) + r"""(?:\[["']asset_issuer["']\]|\.(?:asset_issuer|issuer))""", text) \
                            or _ISSUER_COMPARED.search(text)
                        if either or not checked:
                            out.append((py.path, node.lineno, py.snippet(node), literal is not None))
                        break
        return out


# --------------------------------------------------------------------------- condition evaluation
_ISSUER_PRESENT, _ISSUER_ABSENT, _CODE_NATIVE, _CODE_OTHER, _CODE_PRESENT, _UNKNOWN = range(6)


def _missing_issuer_goes_native(expr, atoms: list, taken: bool) -> bool:
    """With a credit code (say USDC) and no issuer, the branch that builds Asset.native()
    is taken whatever the condition's other terms are."""
    if not any(kind in (_ISSUER_PRESENT, _ISSUER_ABSENT) for kind in atoms):
        return False
    unknown = [i for i, kind in enumerate(atoms) if kind == _UNKNOWN][:4]
    for values in itertools.product((False, True), repeat=len(unknown)):
        assignment = dict(zip(unknown, values))
        fixed = {i: {_ISSUER_PRESENT: False, _ISSUER_ABSENT: True, _CODE_NATIVE: False, _CODE_OTHER: True,
                     _CODE_PRESENT: True}.get(kind) for i, kind in enumerate(atoms)}
        fixed.update(assignment)
        if _evaluate(expr, fixed) is not taken:
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
        text = ast.unparse(node)
        other = node.comparators[0]
        if re.search(r"issuer", text, re.I) and isinstance(other, ast.Constant) and other.value in (None, ""):
            return _atom(atoms, _ISSUER_PRESENT if isinstance(node.ops[0], (ast.IsNot, ast.NotEq)) else _ISSUER_ABSENT)
        literal = other.value if isinstance(other, ast.Constant) else None
        if literal in _NATIVE and re.search(r"code|asset|type", text, re.I):
            return _atom(atoms, _CODE_OTHER if isinstance(node.ops[0], (ast.NotEq, ast.IsNot)) else _CODE_NATIVE)
        return _atom(atoms, _UNKNOWN)
    if isinstance(node, (ast.Name, ast.Attribute)):
        text = ast.unparse(node)
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
            isinstance(parent, ast.Call) and node in parent.args and ast.unparse(parent.func) not in
            {"os.getenv", "os.environ.get", "getenv"}):
        node, parent = parent, py.parents.get(parent)
    if isinstance(parent, ast.Assign):
        return " ".join(ast.unparse(t) for t in parent.targets)
    if isinstance(parent, ast.AnnAssign):
        return ast.unparse(parent.target)
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
    return None


def _py_code_access(node) -> str | None:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in _CODE_FIELDS:
        return ast.unparse(node.value)
    if isinstance(node, ast.Attribute) and node.attr in _CODE_FIELDS:
        return ast.unparse(node.value)
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
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    return parent is not None and parent.type == "binary_expression" and _txt(parent.child_by_field_name("operator")) == "||"


def asset_findings(rules: AssetRules, make) -> list:
    """The findings of the rules above (one per rule and file);
    `make(id, severity, title, detail, evidence, remediation, refs)` builds one."""
    findings = []

    def per_file(rule: str, places: list[tuple], severity_of, title: str, detail: str, remediation: str, refs: list[str]):
        by_file: dict[str, list[tuple]] = {}
        for place in places:
            by_file.setdefault(place[0], []).append(place)
        for path, items in by_file.items():
            severity = max((severity_of(item) for item in items), key=lambda s: s.rank)
            if severity is Severity.INFO:
                continue
            evidence = [f"{path}:{item[1]} `{item[2][:150]}`" + (f" ({item[3]})" if len(item) > 3 and isinstance(item[3], str)
                                                                    else "") for item in items[:6]]
            findings.append(make(stable_id(rule, path, items[0][2]), severity, title, detail, evidence, remediation, refs))

    per_file("security-strkey-invalid", rules.bad_strkeys(), lambda item: item[4],
             "An account or contract id in the code is not a valid StrKey",
             "The literal has the shape of a Stellar address or contract id, but its length or checksum is wrong. Any "
             "payment, requirement or check that uses it fails or never matches: a paywall built on it cannot be "
             "paid, and a client cannot pay it.",
             "Replace it with the real StrKey (StrKey.isValidContract / isValidEd25519PublicKey), and validate configured "
             "addresses at startup.", ["Stellar StrKey (SEP-23)"])
    per_file("security-sac-constant-invalid", rules.mpp_constants(), lambda item: _drop(Severity.MEDIUM, item[0]),
             "MPP's mainnet SAC constant is not a valid contract id",
             "@stellar/mpp up to 0.7.1 exports USDC_SAC_MAINNET with 54 characters and XLM_SAC_MAINNET with 55: neither "
             "is a contract id, so a mainnet charge priced in them cannot be paid or verified.",
             "Use the SAC ids derived from the asset (Asset('USDC', issuer).contractId(Networks.PUBLIC)).",
             ["@stellar/mpp dist/constants.js"])
    per_file("security-payment-asset-is-account", rules.asset_is_account(), lambda item: _drop(Severity.LOW, item[0]),
             "A payment's asset is an account address, not a token contract",
             "x402 and MPP name the asset by its contract id (C...). An account address (G...) is not an asset: clients "
             "reject the requirement, so the route cannot be paid.",
             "Use the asset's SAC contract id.", ["x402 exact scheme for Stellar"])
    per_file("security-payee-defaults-to-null-account", rules.null_payee(), lambda item: item[3],
             "Payments go to the null account when the payee is not configured",
             "When the variable is unset the payee falls back to GAAAA...WHF, the all-zero key. Nobody holds its secret, "
             "so every payment made to it is lost and the operator receives nothing.",
             "Fail at startup when the payee is not configured.", ["CWE-1188 Insecure Default Initialization"])
    per_file("security-missing-issuer-pays-xlm", rules.native_fallback(), lambda item: _drop(Severity.MEDIUM, item[0]),
             "An asset without an issuer silently becomes XLM",
             "When a credit asset code (USDC, EURC, ...) arrives without its issuer, this branch builds Asset.native(). "
             "The operation then moves XLM in the amount meant for the other asset, with no error.",
             "Use native only when the code is XLM; reject a credit code that has no issuer.", ["Stellar assets"])
    per_file("security-amount-parsed-two-ways", rules.dual_parse(), lambda item: Severity.HIGH,
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
