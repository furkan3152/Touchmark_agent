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


@dataclass
class JsFile:
    path: str
    text: str
    root: object
    stellar: bool
    lines: list[str] = field(default_factory=list)

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


class SourceIndex:
    def __init__(self, files: dict[str, str]):
        self.js: dict[str, JsFile] = {}
        self.py: dict[str, PyFile] = {}
        #: function name -> [(file, function node)] for name-based call resolution.
        self.js_defs: dict[str, list[tuple[JsFile, object]]] = {}
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
                try:
                    root = parser.parse(text.encode("utf-8", "replace")).root_node
                except (ValueError, RecursionError):
                    continue
                js = JsFile(path, text, root, bool(_STELLAR_JS.search(text)), text.splitlines())
                self.js[path] = js
                self._index_js(js)
            elif lower.endswith(".py"):
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    continue
                py = PyFile(path, text, tree, "stellar_sdk" in text, text.splitlines())
                for node in ast.walk(tree):
                    for child in ast.iter_child_nodes(node):
                        py.parents[child] = node
                self.py[path] = py
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.py_defs.setdefault(node.name, []).append((py, node))
            elif lower.endswith(".rs"):
                self.rust[path] = text

    # ------------------------------------------------------------------ JavaScript
    def _index_js(self, js: JsFile) -> None:
        stack = [js.root]
        while stack:
            node = stack.pop()
            name = js_function_name(node)
            if name:
                self.js_defs.setdefault(name, []).append((js, node))
            stack.extend(node.named_children)

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
    """One index per audit: the auditors share the artifact's file dict. The (files, index)
    pair is replaced as a whole, so a concurrent audit never reads another one's index."""
    global _LAST
    last = _LAST
    if last is not None and last[0] is files:
        return last[1]
    index = SourceIndex(files)
    _LAST = (files, index)
    return index
