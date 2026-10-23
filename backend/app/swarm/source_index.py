"""Parsed sources shared by the SDK-semantics and asset-identity rules.

Those rules ask small syntactic questions across a whole project: which function a call
sits in, who calls a function by name, which string literals are code and which are
comments. Parsing each file once (tree-sitter for JavaScript and TypeScript, ``ast`` for
Python) and indexing functions by name keeps them out of jsflow's and codeflow's taint
engines, whose labels they do not need.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..models import Severity
from .jsflow import _dotted, _parsers, _txt, _unwrap, is_js

#: Paths whose code is not the agent: tests, fixtures, mocks, smoke tests and benches.
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|mocks?|e2e|benches)/|(^|/|[._-])(test|spec|smoke|mock|fixture)s?([._-]|$)",
                       re.I)
#: Paths that show usage rather than ship it; their findings drop one level.
EXAMPLE_PATH = re.compile(r"(^|/)(examples?|demos?|samples?|templates?|playground)/", re.I)
#: Bundled or generated output that is not the project's own source.
BUNDLE_PATH = re.compile(r"(^|/)(dist|build|out|public/assets|vendor|node_modules)/|\.min\.js$|\.bundle\.js$", re.I)
_JS_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition",
                 "generator_function_declaration", "generator_function", "function"}
_STELLAR_JS = re.compile(r"""["'](?:@stellar/stellar-sdk|stellar-sdk|@stellar/stellar-base|soroban-client)(?:/[\w/-]*)?["']""")


def js_functions_type(node) -> bool:
    return node is not None and node.type in _JS_FUNCTIONS


def drop(severity: Severity, path: str) -> Severity:
    """Example and template code drops one level (a HIGH becomes MEDIUM)."""
    return severity.downgrade() if EXAMPLE_PATH.search(path) else severity


def unparse(node) -> str:
    """ast.unparse for small nodes. It recurses, so a deeply nested expression (a long `+`
    chain that ast.parse accepts) raises RecursionError; that reads as no text."""
    try:
        return ast.unparse(node)
    except (RecursionError, ValueError, AttributeError):
        return ""


@dataclass
class JsFile:
    """A JavaScript or TypeScript file, parsed on first use: most rules first test the text
    for a name they need, so most files of a large project are never parsed."""
    path: str
    text: str
    parser: object
    stellar: bool
    lines: list[str] = field(default_factory=list)
    _root: object = None
    _functions: dict | None = None

    @property
    def root(self):
        if self._root is None:
            try:
                self._root = self.parser.parse(self.text.encode("utf-8", "replace")).root_node
            except (ValueError, RecursionError):
                self._root = self.parser.parse(b"").root_node
        return self._root

    def functions(self) -> dict[str, list]:
        """Function name -> the functions in this file called by that name."""
        if self._functions is None:
            found: dict[str, list] = {}
            stack = [self.root]
            while stack:
                node = stack.pop()
                name = js_function_name(node)
                if name:
                    found.setdefault(name, []).append(node)
                stack.extend(node.named_children)
            self._functions = found
        return self._functions

    def line(self, node) -> int:
        return node.start_point[0] + 1

    def snippet(self, node, limit: int = 160) -> str:
        row = node.start_point[0]
        return " ".join(self.lines[row].split())[:limit] if row < len(self.lines) else _txt(node)[:limit]


@dataclass
class PyFile:
    path: str
    text: str
    tree: ast.Module
    stellar: bool
    lines: list[str] = field(default_factory=list)
    parents: dict = field(default_factory=dict)

    def snippet(self, node, limit: int = 160) -> str:
        row = getattr(node, "lineno", 1) - 1
        return " ".join(self.lines[row].split())[:limit] if row < len(self.lines) else ""

    def source(self, node) -> str:
        """The lines a node spans, sliced from the file rather than unparsed (no recursion)."""
        start, end = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        if node is self.tree or start is None or end is None:
            return self.text
        return "\n".join(self.lines[start - 1:end])


class SourceIndex:
    def __init__(self, files: dict[str, str]):
        self.js: dict[str, JsFile] = {}
        self.py: dict[str, PyFile] = {}
        #: function name -> [(file, function node)] for name-based call resolution (see defs()).
        self._js_defs: dict[str, list[tuple[JsFile, object]]] = {}
        self.py_defs: dict[str, list[tuple[PyFile, ast.AST]]] = {}
        self.rust: dict[str, str] = {}
        parsers = None
        for path, text in sorted(files.items()):
            if BUNDLE_PATH.search(path):
                continue
            lower = path.lower()
            if is_js(path):
                if parsers is None:
                    try:
                        parsers = _parsers()
                    except ImportError:
                        parsers = {}
                if not parsers:
                    continue
                parser = parsers["tsx" if lower.endswith(".tsx") else "ts" if lower.endswith((".ts", ".mts", ".cts")) else "js"]
                self.js[path] = JsFile(path, text, parser, bool(_STELLAR_JS.search(text)), text.splitlines())
            elif lower.endswith(".py"):
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    continue
                # ast numbers lines by \n, \r\n and \r only (str.splitlines also splits on \f, \x85, ...).
                py = PyFile(path, text, tree, "stellar_sdk" in text, re.split(r"\r\n|\r|\n", text))
                for node in ast.walk(tree):
                    for child in ast.iter_child_nodes(node):
                        py.parents[child] = node
                self.py[path] = py
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.py_defs.setdefault(node.name, []).append((py, node))
            elif lower.endswith(".rs"):
                self.rust[path] = text
        self._bigint_json: bool | None = None

    def bigint_json_patched(self) -> bool:
        """The project installs a BigInt.prototype.toJSON, so JSON.stringify accepts BigInt."""
        if self._bigint_json is None:
            self._bigint_json = any(re.search(r"BigInt\.prototype\b[^;\n]{0,30}\btoJSON\b", js.text)
                                    for js in self.js.values())
        return self._bigint_json

    # ------------------------------------------------------------------ JavaScript
    def defs(self, name: str) -> list[tuple[JsFile, object]]:
        """The project's JavaScript functions called `name` (only files that contain the name
        are parsed for it)."""
        if not name:
            return []
        found = self._js_defs.get(name)
        if found is None:
            found = [(js, node) for js in self.js.values() if name in js.text for node in js.functions().get(name, [])]
            self._js_defs[name] = found
        return found

    @staticmethod
    def walk(node):
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.named_children))

    @staticmethod
    def enclosing_function(node):
        n = node.parent
        while n is not None and not js_functions_type(n):
            n = n.parent
        return n

    @staticmethod
    def calls(node, include_nested: bool = True):
        """Call expressions under node (optionally not inside nested functions)."""
        stack = list(node.named_children)
        while stack:
            n = stack.pop()
            if not include_nested and js_functions_type(n):
                continue
            if n.type == "call_expression":
                yield n
            stack.extend(n.named_children)


def js_function_name(node) -> str | None:
    """The name a function is called by: a declaration, `const f = () =>`, a method or an
    object-literal property holding a function."""
    if node.type in {"function_declaration", "generator_function_declaration", "method_definition"}:
        name = node.child_by_field_name("name")
        return _txt(name).lstrip("#") if name is not None else None
    if node.type in {"arrow_function", "function_expression", "function"}:
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            return _txt(name) if name is not None and name.type == "identifier" else None
        if parent is not None and parent.type == "pair":
            key = parent.child_by_field_name("key")
            return _txt(key).strip("'\"") if key is not None else None
        if parent is not None and parent.type in {"public_field_definition", "field_definition"}:
            name = parent.child_by_field_name("name") or parent.child_by_field_name("property")
            return _txt(name).lstrip("#") if name is not None else None
    return None


def callee_name(call) -> str:
    """`a.b.c(...)` -> c ; `f(...)` -> f."""
    fn = _unwrap(call.child_by_field_name("function"))
    if fn is None:
        return ""
    if fn.type == "member_expression":
        return _txt(fn.child_by_field_name("property")).lstrip("#")
    return _txt(fn) if fn.type == "identifier" else _dotted(fn).rsplit(".", 1)[-1]


def receiver(call):
    fn = _unwrap(call.child_by_field_name("function"))
    if fn is not None and fn.type == "member_expression":
        return _unwrap(fn.child_by_field_name("object"))
    return None


_LAST: tuple | None = None


def index_for(files: dict[str, str]) -> SourceIndex:
    """One index per audit: the auditors read the same files (the artifact's dict or a copy, so
    contents are compared, not the dict's identity). The (key, index) pair is replaced as a
    whole, so a concurrent audit never reads another one's index; only the latest is kept."""
    global _LAST
    last = _LAST
    key = tuple(sorted((path, len(text), hash(text)) for path, text in files.items()))  # str hashes are cached
    if last is not None and last[0] == key:
        return last[1]
    index = SourceIndex(files)
    _LAST = (key, index)
    return index
