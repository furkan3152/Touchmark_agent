"""Which network an agent's signature is valid on, traced from the value that picks it.

A Stellar signature covers the network passphrase, so most network mistakes fail closed: a
transaction hashed for testnet is rejected by mainnet validators. The mistakes that move real
funds are the ones where someone other than the operator picks the network for a key that
holds funds on both: a tool argument that switches the passphrase and the endpoint together
(N1), a paid server's MPP challenge (N2), or a guess that sends every value it does not
recognise to mainnet (N3). Values that disagree with each other (N4), testnet-only constants
that reach a payment that can be signed for mainnet (N5) and Stellar CLI network names that do
not exist (N6) fail closed and are reported low.

The rules read source text, masked so comments never match; they work on files the data-flow
parsers reject. They are bounded lexical evidence, not a compiler.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from hashlib import sha1

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity
from ..stellar.canonical import MAINNET_PASSPHRASE, NETWORK_MARKERS, TESTNET_PASSPHRASE, USDC_ISSUER, USDC_SAC
from .consolidate import stable_id
from .codeflow import unparse
from .source_index import PARSE_ERRORS

_JS = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".mts", ".cts")
#: Example, test and development code: findings there drop one level.
_NON_PRODUCTION = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|examples?|dev|demo|scripts?/smoke)[^/]*/|"
                             r"(?:^|/)[^/]*(?:\.test|\.spec|_test|smoke)\.\w+$", re.I)
#: Network names the Stellar CLI defines without `stellar network add` (stellar-cli
#: cmd/soroban-cli/src/config/network.rs, DEFAULTS); any other name fails unless added.
CLI_NETWORKS = frozenset({"local", "futurenet", "testnet", "mainnet"})

#: A value that is the public network: SDK constants, the passphrase, a CAIP-2 id or a name.
_MAINNET_VALUE = re.compile(
    r"\bNetworks?\.PUBLIC\b|\bNetwork\.PUBLIC_NETWORK_PASSPHRASE\b|\bPUBLIC_NETWORK_PASSPHRASE\b|\bSTELLAR_PUBNET\w*|"
    r"\bPUBNET\w*|\bMAINNET\w*_PASSPHRASE|" + re.escape(MAINNET_PASSPHRASE) + "|"
    r"""^\s*["'`](?:public|mainnet|pubnet|stellar:pubnet|stellar:mainnet)["'`]\s*$""", re.I)
_TESTNET_VALUE = re.compile(
    r"\bNetworks?\.TESTNET\b|\bNetwork\.TESTNET_NETWORK_PASSPHRASE\b|\bTESTNET_NETWORK_PASSPHRASE\b|\bSTELLAR_TESTNET\w*|"
    r"\bTESTNET\w*_PASSPHRASE|" + re.escape(TESTNET_PASSPHRASE) + "|"
    r"""^\s*["'`](?:testnet|stellar:testnet)["'`]\s*$""", re.I)
#: Network names a declared domain or a selector can list.
_NET_NAME = re.compile(r"^(?:stellar:)?(?:public|mainnet|pubnet|testnet|futurenet|local|standalone|custom|localnet|"
                       r"sandbox|previewnet|devnet)$", re.I)
_MAINNET_NAME = re.compile(r"^(?:stellar:)?(?:public|mainnet|pubnet)$", re.I)
_TESTNET_NAME = re.compile(r"^(?:stellar:)?testnet$", re.I)
#: A variable whose text is a URL or host: guessing the network from a substring of it.
_URLISH = re.compile(r"url|host|server|endpoint|horizon|rpc|uri|origin|base", re.I)
_STRING = re.compile(r"""^\s*(["'`])(.*)\1\s*$""", re.S)


@dataclass
class Hit:
    """One place a rule fires."""
    rule: str
    file: str
    line: int
    text: str
    severity: Severity
    note: str = ""
    group: str = ""
    extra: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- masking
def mask(text: str, python: bool = False) -> tuple[str, str]:
    """(code, skeleton) with offsets kept: comments blanked in both, string contents also
    blanked in the skeleton (its quotes stay). Regular-expression literals are not
    recognised; a quote inside one can only shorten what a rule sees."""
    code, skel = list(text), list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if (python and c == "#") or (not python and text.startswith("//", i)):
            end = text.find("\n", i)
            end = n if end < 0 else end
            for k in range(i, end):
                code[k] = skel[k] = " "
            i = end
        elif not python and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if text[k] != "\n":
                    code[k] = skel[k] = " "
            i = end
        elif c in "'\"`":
            triple = python and text.startswith(c * 3, i)
            quote = c * 3 if triple else c
            j = i + len(quote)
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text.startswith(quote, j):
                    break
                if text[j] == "\n" and quote in ("'", '"'):
                    break  # an unterminated one-line string ends with its line
                j += 1
            end = min(n, j + len(quote))
            for k in range(i + len(quote), min(n, j)):
                if text[k] != "\n":
                    skel[k] = " "
            i = end
        else:
            i += 1
    return "".join(code), "".join(skel)


#: Bracket partners per text and bracket kind, built once (see _closing). Each entry keeps its
#: text alive, so an id is never reused while it is cached.
_PARTNERS: dict[tuple[int, str], tuple[str, dict[int, int]]] = {}


def _closing(skel: str, start: int, opening: str = "{", closing: str = "}", limit: int = 20_000) -> int:
    """Offset of the bracket that closes the one at ``start`` (or the end of the bounded window).
    The partners of every ``opening`` in the text are found in one pass and kept."""
    key = (id(skel), opening)
    entry = _PARTNERS.get(key)
    if entry is None or entry[0] is not skel:
        partners, stack = {}, []
        for m in re.finditer(re.escape(opening) + "|" + re.escape(closing), skel):
            if m.group() == opening:
                stack.append(m.start())
            elif stack:
                partners[stack.pop()] = m.start()
        if len(_PARTNERS) > 64:
            _PARTNERS.clear()
        entry = _PARTNERS[key] = (skel, partners)
    end = min(len(skel), start + limit)
    close = entry[1].get(start)
    return close if close is not None and close < end else end


def _string_value(expr: str) -> str | None:
    m = _STRING.match(expr)
    return m.group(2) if m and "${" not in m.group(2) else None


def net_of(expr: str) -> str | None:
    """'mainnet' or 'testnet' when the expression names that network (a passphrase, an SDK
    constant, a CAIP-2 id or a network name); 'futurenet' and other names come back as is."""
    expr = expr.strip().rstrip(";,").strip()
    value = _string_value(expr)
    if value is not None:
        if _MAINNET_NAME.match(value) or value == MAINNET_PASSPHRASE:
            return "mainnet"
        if _TESTNET_NAME.match(value) or value == TESTNET_PASSPHRASE:
            return "testnet"
        return value.lower() if _NET_NAME.match(value) else None
    if _MAINNET_VALUE.search(expr):
        return "mainnet"
    if _TESTNET_VALUE.search(expr):
        return "testnet"
    if re.search(r"\bNetworks?\.FUTURENET\b|FUTURENET_NETWORK_PASSPHRASE", expr):
        return "futurenet"
    return None


# --------------------------------------------------------------------------- source files
#: Files that make their directory a package of its own.
_MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "Cargo.toml")


_PY_BREAK, _JS_BREAK = re.compile(r"\r\n|\r|\n"), re.compile(r"\n")
_BRACKET = re.compile(r"[(\[{)\]}]")
#: A brace that opens a function body: after `=>`, or after the `)` of a parameter list (with
#: an optional return type).
_FUNCTION_HEAD = re.compile(r"(?:=>|\)(?:\s*:\s*[^{};=()]{1,160})?)\s*$")
_CONTROL_WORDS = frozenset({"if", "for", "while", "switch", "catch", "with"})


@dataclass
class _Source:
    name: str
    text: str
    code: str
    skel: str
    python: bool
    package: str = ""  # the nearest directory with a manifest (the repository root by default)
    selectors: list | None = None  # computed once (fallback and pair rules both read them)
    _newlines: list | None = None
    _lines: list | None = None
    _heads: list | None = None
    _pairs: dict | None = None
    _owner: tuple | None = None
    _bodies: dict = field(default_factory=dict)
    memo: dict = field(default_factory=dict)  # per-file results the rules share

    def _breaks(self) -> re.Pattern:
        # Lines end where the parser numbering them says: ast at \r\n, \r and \n, tree-sitter at
        # \n only (str.splitlines also splits at \f, \x1c-\x1e, \x85, U+2028 and U+2029).
        return _PY_BREAK if self.python else _JS_BREAK

    def line(self, pos: int) -> int:
        """The 1-based line of an offset."""
        if self._newlines is None:
            self._newlines = [m.start() for m in self._breaks().finditer(self.text)]
        return bisect_left(self._newlines, pos) + 1

    def line_start(self, line: int) -> int:
        """The offset where a 1-based line starts."""
        self.line(0)
        if line <= 1:
            return 0
        if line - 2 >= len(self._newlines):
            return len(self.text)
        at = self._newlines[line - 2]
        return at + (2 if self.text.startswith("\r\n", at) else 1)

    def line_text(self, line: int) -> str:
        if self._lines is None:
            self._lines = self._breaks().split(self.text)
        return self._lines[line - 1].rstrip("\r") if 0 < line <= len(self._lines) else ""

    def region(self, pos: int) -> tuple[int, int]:
        """The top-level declaration that holds ``pos``: from the last top-level head at or
        before it to the next one (heads found once per file)."""
        if self._heads is None:
            self._heads = [m.start() for m in _TOP_LEVEL.finditer(self.code)]
        i = bisect_right(self._heads, pos)
        return (self._heads[i - 1] if i else 0), (self._heads[i] if i < len(self._heads) else len(self.code))

    def pairs(self) -> dict[int, int]:
        """Each bracket's partner, both ways, matched with one stack over (, [ and { alike (as
        the depth counters of the scans here count them); an unclosed bracket has none. The
        innermost open bracket at and after each bracket is kept for _owner."""
        if self._pairs is None:
            pairs: dict[int, int] = {}
            stack: list[int] = []
            at, inside, after = [], [], []  # bracket offset, innermost open at it, and after it
            for m in _BRACKET.finditer(self.skel):
                i = m.start()
                at.append(i)
                if m.group() in "([{":
                    inside.append(stack[-1] if stack else -1)
                    stack.append(i)
                else:
                    if stack:
                        start = stack.pop()
                        pairs[start], pairs[i] = i, start
                    inside.append(stack[-1] if stack else -1)
                after.append(stack[-1] if stack else -1)
            self._pairs, self._owner = pairs, (at, inside, after)
        return self._pairs

    def _owner_of(self, pos: int) -> int:
        """The innermost open bracket that holds ``pos`` (-1 at top level)."""
        self.pairs()
        at, inside, after = self._owner
        i = bisect_right(at, pos) - 1
        return -1 if i < 0 else inside[i] if at[i] == pos else after[i]

    def function_at(self, pos: int) -> tuple[int, int] | None:
        """The body `{...}` of the innermost function holding ``pos``, or None at top level."""
        pairs = self.pairs()
        node = self._owner_of(pos)
        path = []
        while node >= 0 and node not in self._bodies:
            path.append(node)
            node = self._owner_of(node)
        found = self._bodies.get(node) if node >= 0 else None
        for opening in reversed(path):  # outermost first: an inner function wins over its parent
            if self.skel[opening] == "{" and opening in pairs and self._function_body(opening):
                found = (opening, pairs[opening])
            self._bodies[opening] = found
        return found

    def _function_body(self, brace: int) -> bool:
        floor = max(0, brace - 200)
        head = _FUNCTION_HEAD.search(self.skel, floor, brace)
        if head is None:
            return False
        if self.skel.startswith("=>", head.start()):
            return True
        opening = self._pairs.get(head.start())
        word = re.search(r"([\w$]+)\s*$", self.skel[max(0, opening - 40):opening]) if opening is not None else None
        return opening is not None and not (word and word.group(1) in _CONTROL_WORDS)


def _package_of(name: str, roots: set[str]) -> str:
    parts = name.split("/")[:-1]
    for i in range(len(parts), 0, -1):
        if "/".join(parts[:i]) in roots:
            return "/".join(parts[:i])
    return ""


def _sources(files: dict[str, str]) -> list[_Source]:
    roots = {n.rpartition("/")[0] for n in files if n.rsplit("/", 1)[-1] in _MANIFESTS}
    out = []
    for name, text in sorted(files.items()):
        lower = name.lower()
        python = lower.endswith(".py")
        if not (python or (lower.endswith(_JS) and not lower.endswith((".d.ts", ".min.js")))) or len(text) > 600_000:
            continue
        if "/node_modules/" in f"/{lower}" or "/dist/" in f"/{lower}" or "/build/" in f"/{lower}":
            continue
        code, skel = mask(text, python)
        out.append(_Source(name, text, code, skel, python, _package_of(name, roots)))
    return out


def _severity(base: Severity, file: str) -> Severity:
    return base.downgrade(1) if _NON_PRODUCTION.search(file) else base


# --------------------------------------------------------------------------- N3: selectors
@dataclass
class Selector:
    """A switch, ternary chain or map fallback that turns a value into a network."""
    file: str
    line: int
    text: str
    subject: str
    explicit: list[str]   # the values tested (case labels, compared strings)
    fallback: str | None  # the network the default branch yields
    yields: set[str]      # every network value the selector can produce
    guess: bool           # tests substrings of a URL or host
    target: str = ""      # the variable or field the result is stored in
    passphrase: bool = False  # its branch values are passphrases (or a table whose entries hold them)


def _passphrases(values) -> bool:
    """Whether a selector's branch values are passphrases (not what it compares against)."""
    return any(re.search(r"[Pp]assphrase|PASSPHRASE|Networks?\.(?:PUBLIC|TESTNET|FUTURENET)\b", v or "") for v in values)


_CASE = re.compile(r"\bcase\s+(?P<label>[^:?]+?)\s*:|\bdefault\s*:")
_SWITCH = re.compile(r"\bswitch\s*\(\s*(?P<subject>[\w$.?!\[\]'\"]+)\s*\)\s*\{")
_YIELD = re.compile(r"\breturn\s+(?P<ret>[^;\n]+)|(?<![\w$.])(?P<target>[\w$.]+)\s*=(?!=)\s*(?P<val>[^;\n]+)")


#: Inside a switch body: a case or default label, or a bracket to skip or stop at.
_SWITCH_EVENT = re.compile(r"[(\[{)\]}]|(?<![\w$.])(?:case|default)\b")


def _js_switches(src: _Source) -> list[Selector]:
    out = []
    pairs = src.pairs() if "switch" in src.skel else {}
    for m in _SWITCH.finditer(src.skel):
        open_at = m.end() - 1
        close = _closing(src.skel, open_at)
        body_skel, body = src.skel[open_at + 1:close], src.code[open_at + 1:close]
        # Labels at the switch's own depth only: nested groups are skipped whole.
        marks, i = [], open_at + 1
        while True:
            event = _SWITCH_EVENT.search(src.skel, i, close)
            if event is None:
                break
            i = event.start()
            if src.skel[i] in ")]}":
                break
            if src.skel[i] in "([{":
                partner = pairs.get(i)
                if partner is None or partner >= close:
                    break  # open to the end of the body: nothing after it is at depth 0
                i = partner + 1
                continue
            hit = _CASE.match(body_skel, i - open_at - 1)
            if hit:
                label = body[hit.start("label"):hit.end("label")].strip() if hit.group("label") else None
                marks.append((hit.start(), hit.end(), label))
            i = event.end()
        clauses = []
        for k, (start, end, label) in enumerate(marks):
            stop = marks[k + 1][0] if k + 1 < len(marks) else len(body)
            clauses.append((label, body[end:stop]))
        explicit, fallback, yields, pending, written = [], None, set(), [], []
        for label, stmts in clauses:
            pending.append(label)
            value = None
            for y in _YIELD.finditer(stmts):
                value = net_of(y.group("ret") or y.group("val") or "")
                if value:
                    written.append(y.group("ret") or y.group("val"))
                if value or y.group("ret"):
                    break
            if not stmts.strip():
                continue  # falls through to the next clause
            if value is None and not re.search(r"\b(?:return|throw)\b|=(?!=)", stmts):
                continue
            for lab in pending:
                if lab is None:
                    fallback = value
                else:
                    explicit.append(_label_value(lab))
            if value:
                yields.add(value)
            pending = []
        if not yields:
            continue
        out.append(Selector(src.name, src.line(m.start()), _snippet(src.code, m.start(), close + 1),
                            m.group("subject"), [e for e in explicit if e], fallback, yields, False,
                            passphrase=_passphrases(written)))
    return out


def _snippet(code: str, start: int, end: int) -> str:
    """Whitespace-collapsed code, at most 400 characters (read from a bounded window)."""
    return " ".join(code[start:min(end, start + 4000)].split())[:400]


def _label_value(label: str) -> str:
    value = _string_value(label)
    if value is not None:
        return value.lower()
    found = net_of(label)
    return found or label


_ASSIGN_TERNARY = re.compile(r"(?:\b(?:const|let|var)\s+(?P<decl>[\w$]+)(?:\s*:[^=;\n]+)?|(?<![\w$])(?P<attr>this\.[\w$]+|[\w$]+))"
                             r"\s*=(?!=)\s*")


def _conditions(src: _Source, conds: list[str], before: int) -> tuple[list[str], bool, str]:
    """(values tested, whether a URL substring is tested, the subject) for the conditions of a
    ternary or if-chain; a bare alias is read through its declaration before ``before``."""
    explicit, guess, subject = [], False, ""
    for c in conds:
        alias = re.fullmatch(r"!?\s*([\w$]+)", c)
        if alias:
            # `const isPubnet = cfg.network === 'stellar:pubnet'; ... isPubnet ? A : B`
            decl = None
            for d in re.finditer(r"\b(?:const|let|var)\s+" + re.escape(alias.group(1)) + r"\s*=\s*([^;\n]+)",
                                 src.code[max(0, before - 3000):before]):
                decl = d
            c = decl.group(1) if decl else c
        found = re.search(r"(?<![\w$.])(?P<subj>[\w$.]+)\s*\.\s*(?:includes|indexOf|startsWith|endsWith|match|search)\s*\(\s*"
                          r"""["'`](?P<val>[^"'`]+)["'`]""", c) or \
            re.search(r"""(?<![\w$.])(?P<subj>[\w$.]+)\s*[!=]==?\s*["'`](?P<val>[^"'`]+)["'`]""", c) or \
            re.search(r"""["'`](?P<val>[^"'`]+)["'`]\s*[!=]==?\s*(?P<subj>[\w$.]+)""", c)
        if not found:
            explicit.append(c)
            continue
        subject = found.group("subj")
        explicit.append(found.group("val").lower())
        if re.search(r"\.\s*(?:includes|indexOf|startsWith|endsWith|match|search)\s*\(", c) and \
                _URLISH.search(subject.rsplit(".", 1)[-1]):
            guess = True
    return explicit, guess, subject


#: What can end a statement, or split a ternary, at its own depth; a bare `=` (not ==, <=,
#: =>) starts another assignment.
_STATEMENT_EVENT = re.compile(r"[(\[{)\]};,\n?:]|(?<![=!<>])=(?![=>])")


def _statement(src: _Source, start: int) -> tuple[int, list[int]]:
    """(end, depth-0 `?` and `:` offsets) of the expression assigned at ``start``. It ends at a
    `;`, `,` or another assignment at its own depth, at a bracket that closes an enclosing one,
    or at a line break that does not continue it (the next line starting with ? : . | &, or
    this one ending with ? : = ( , | &). Bracketed groups are skipped whole, so each character
    is looked at once per statement that holds it at depth 0; the window is 1,200 characters."""
    skel, pairs = src.skel, src.pairs()
    n = min(len(skel), start + 1200)
    marks: list[int] = []
    last, i, tail = start, start, ""  # tail: the last non-blank character so far
    while True:
        event = _STATEMENT_EVENT.search(skel, i, n)
        if event is None:
            return n, marks
        i = event.start()
        ch = skel[i]
        if ch in "([{":
            close = pairs.get(i)
            if close is None or close >= n:
                return n, marks  # still open at the end of the window
            i = last = close + 1
            tail = skel[close]
            continue
        if ch in ")]};,=":
            return i, marks
        if ch in "?:":
            marks.append(i)
            last, tail = i + 1, ch
            i += 1
            continue
        # A line break: the statement goes on only when either side says so.
        gap = skel[last:i].rstrip()
        tail = gap[-1] if gap else tail
        if not re.match(r"\s*[?:.|&]", skel[i + 1:i + 40]) and (not tail or tail not in "?:=(,|&"):
            return i, marks
        last = i + 1
        i += 1


def _split_marks(skel: str, code: str, start: int, end: int, marks: list[int]) -> tuple[list[tuple[str, str]], str] | None:
    """`a ? x : b ? y : z` -> ([(cond, value), ...], else), from the depth-0 `?` and `:` offsets."""
    q, cond_start = None, start
    pieces: list[tuple[str, str]] = []
    for i in marks:
        if i >= end:
            break
        if skel[i] == "?" and skel[i + 1:i + 2] not in ("?", ".") and skel[i - 1:i] != "?":
            q = i
        elif skel[i] == ":" and q is not None:
            pieces.append((code[cond_start:q].strip(), code[q + 1:i].strip()))
            cond_start, q = i + 1, None
    return (pieces, code[cond_start:end].strip()) if pieces else None


def _js_ternaries(src: _Source) -> list[Selector]:
    out = []
    for m in _ASSIGN_TERNARY.finditer(src.skel):
        start = m.end()
        i, marks = _statement(src, start)
        parts = _split_marks(src.skel, src.code, start, i, marks)
        if not parts:
            continue
        pieces, last = parts
        conds = [c for c, _ in pieces]
        values = [v for _, v in pieces] + [last]
        nets = [net_of(v) for v in values]
        if not any(nets):
            continue
        explicit, guess, subject = _conditions(src, conds, m.start())
        target = m.group("decl") or m.group("attr") or ""
        line = src.line(m.start())
        out.append(Selector(src.name, line, " ".join(src.code[m.start():i].split())[:400], subject,
                            explicit, nets[-1], {x for x in nets if x}, guess, target, passphrase=_passphrases(values)))
    return out


def _py_selectors(src: _Source) -> list[Selector]:
    try:
        tree = ast.parse(src.text)
    except PARSE_ERRORS:
        return []
    out = []
    aliases = {t.id: n.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Compare)
               for t in n.targets if isinstance(t, ast.Name)}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.IfExp):
            continue
        pieces, expr = [], node.value
        while isinstance(expr, ast.IfExp):
            pieces.append((expr.test, expr.body))
            expr = expr.orelse
        nets = [net_of(unparse(v)) for _, v in pieces] + [net_of(unparse(expr))]
        if not any(nets):
            continue
        explicit, guess, subject = [], False, ""
        for test, _ in pieces:
            if isinstance(test, ast.Name) and test.id in aliases:
                test = aliases[test.id]  # `is_testnet = "testnet" in network; A if is_testnet else B`
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                left, right = test.left, test.comparators[0]
                if isinstance(test.ops[0], ast.In) and isinstance(left, ast.Constant) and isinstance(left.value, str):
                    subject = unparse(right)
                    explicit.append(left.value.lower())
                    guess = guess or bool(_URLISH.search(subject.rsplit(".", 1)[-1]))
                    continue
                for a, b in ((left, right), (right, left)):
                    if isinstance(b, ast.Constant) and isinstance(b.value, str):
                        subject = unparse(a)
                        explicit.append(b.value.lower())
                        break
                else:
                    explicit.append(unparse(test))
            else:
                explicit.append(unparse(test))
        target = unparse(node.targets[0] if isinstance(node, ast.Assign) else node.target)
        out.append(Selector(src.name, node.lineno, " ".join(unparse(node).split())[:400], subject, explicit,
                            nets[-1], {x for x in nets if x}, guess, target,
                            passphrase=_passphrases([unparse(v) for _, v in pieces] + [unparse(expr)])))
    return out


_IF_HEAD = re.compile(r"\bif\s*\(")


def _return_at(src: _Source, pos: int) -> tuple[str, int] | None:
    """`return X;` or `{ return X; }` starting at ``pos`` (after spaces): (X, end)."""
    m = re.match(r"\s*(\{)?\s*return\s+", src.skel[pos:pos + 200])
    if not m:
        return None
    start = pos + m.end()
    depth, i = 0, start
    while i < min(len(src.skel), start + 400):
        ch = src.skel[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch in ";\n":
            break
        i += 1
    value, end = src.code[start:i].strip(), i + (src.skel[i:i + 1] == ";")
    if m.group(1):
        close = re.match(r"\s*\}", src.skel[end:end + 40])
        if not close:
            return None
        end += close.end()
    return (value, end) if value else None


def _js_if_chains(src: _Source) -> list[Selector]:
    """`if (n === 'testnet') return A; else if (n === 'futurenet') return B; return C;` (with
    or without else and braces): an if-chain of returns, the last return being its fallback."""
    out, seen = [], set()
    for m in _IF_HEAD.finditer(src.skel):
        if m.start() in seen or not re.search(r"(?:^|[;{}])\s*$", src.skel[max(0, m.start() - 200):m.start()]):
            continue
        chain, pos, final = [], m.start(), None
        while True:
            head = _IF_HEAD.match(src.skel, pos)
            if not head:
                final = _return_at(src, pos)
                break
            seen.add(pos)
            open_at = head.end() - 1
            close = _closing(src.skel, open_at, "(", ")", limit=400)
            ret = _return_at(src, close + 1)
            if ret is None:
                break
            chain.append((src.code[open_at + 1:close].strip(), ret[0]))
            pos = ret[1] + re.match(r"\s*(?:else\b\s*)?", src.skel[ret[1]:ret[1] + 40]).end()
        if not chain or final is None:
            continue
        nets = [net_of(v) for _, v in chain] + [net_of(final[0])]
        if not any(nets) or sum(1 for x in nets if x) < 2:
            continue
        explicit, guess, subject = _conditions(src, [c for c, _ in chain], m.start())
        out.append(Selector(src.name, src.line(m.start()), " ".join(src.code[m.start():final[1]].split())[:400],
                            subject, explicit, nets[-1], {x for x in nets if x}, guess,
                            passphrase=_passphrases([v for _, v in chain] + [final[0]])))
    return out


def _top_keys(text: str, python: bool) -> list[str]:
    """The keys at the top level of an object literal or dict (``text`` starts at `{`)."""
    code, skel = mask(text, python)
    keys, depth = [], 0
    for i, ch in enumerate(skel):
        if ch in "([{":
            depth += 1
            if depth != 1:
                continue
        elif ch in ")]}":
            depth -= 1
            continue
        elif ch != "," or depth != 1:
            continue
        key = re.match(r"""\s*(?:(["'`])([\w:-]+)\1|([A-Za-z_$][\w$]*))\s*:""", code[i + 1:i + 120])
        if key:
            keys.append((key.group(2) or key.group(3)).lower())
    return list(dict.fromkeys(keys))


#: `TABLE[key] ?? fallback` or `TABLE[key] || fallback`.
_MAP_FALLBACK = re.compile(r"(?<![\w$.])(?P<table>[\w$]+(?:\.[\w$]+)*)\s*\[(?P<key>[^\]\n]{1,120})\]\s*(?:\?\?|\|\|)\s*")


def _fallback_value(table: str, expr: str) -> str | None:
    """The network a map fallback yields: a network value, or the table's own mainnet or
    testnet entry (`NETWORKS.mainnet`, `NETWORKS['public']`)."""
    found = net_of(expr)
    if found in {"mainnet", "testnet"}:
        return found
    own = re.fullmatch(re.escape(table) + r"""\s*(?:\.\s*(?P<a>\w+)|\[\s*["'](?P<b>[\w:-]+)["']\s*\])""", expr.strip())
    if own:
        name = own.group("a") or own.group("b")
        return "mainnet" if _MAINNET_NAME.match(name) else "testnet" if _TESTNET_NAME.match(name) else None
    return None


def _js_map_fallbacks(src: _Source, group: list[_Source]) -> list[Selector]:
    """N3 through a table: `NETWORKS[name] ?? Networks.PUBLIC`. The table's keys are the
    values with a branch of their own; a table that cannot be read is not judged."""
    out = []
    for m in _MAP_FALLBACK.finditer(src.skel):
        end = m.end()
        stop = re.search(r"[;,)\n}]", src.skel[end:end + 200])
        expr = src.code[end:end + (stop.start() if stop else 200)].strip()
        table = m.group("table")
        fallback = _fallback_value(table, expr)
        if fallback is None:
            continue
        body = _definition(table.rsplit(".", 1)[-1], group)
        keys = _top_keys(body, src.python) if body.startswith("{") else []
        if not keys or not all(_NET_NAME.match(k) for k in keys):
            continue
        head = re.search(r"(?:\b(?:const|let|var)\s+(?P<decl>[\w$]+)(?:\s*:[^=;\n]+)?|(?<![\w$])(?P<attr>this\.[\w$]+|[\w$]+))"
                         r"\s*=(?!=)\s*$", src.skel[max(0, m.start() - 120):m.start()])
        target = (head.group("decl") or head.group("attr")) if head else ""
        nets = {fallback} | {n for n in (net_of(f'"{k}"') for k in keys) if n}
        out.append(Selector(src.name, src.line(m.start()), " ".join(src.code[m.start():end + len(expr)].split())[:400],
                            m.group("key").strip(), keys, fallback, nets, False, target,
                            passphrase=_passphrases([body, expr])))
    return out


def _py_chains(tree: ast.Module, src: _Source) -> list[Selector]:
    """Python if/elif chains of returns, and `TABLE.get(key, fallback)` map fallbacks."""
    out = []
    tables = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and len(node.targets) == 1:
            t = node.targets[0]
            name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            keys = [k.value.lower() for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            if name and keys and len(keys) == len(node.value.keys):
                tables[name] = (keys, unparse(node.value))

    def returns(body):
        return body[0].value if len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is not None else None
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body, i = fn.body, 0
        while i < len(body):
            start, chain, final, j = body[i], [], None, i
            stmt = start
            while isinstance(stmt, ast.If) and returns(stmt.body) is not None:
                chain.append((stmt.test, returns(stmt.body)))
                if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
                    stmt = stmt.orelse[0]  # elif
                    continue
                if stmt.orelse:
                    final = returns(stmt.orelse)  # else: return X
                    break
                j += 1  # `if ...: return X` then the next statement
                stmt = body[j] if j < len(body) else None
                if isinstance(stmt, ast.Return):
                    final = stmt.value
            i = j + 1
            if not chain or final is None:
                continue
            nets = [net_of(unparse(v)) for _, v in chain] + [net_of(unparse(final))]
            if sum(1 for x in nets if x) < 2:
                continue
            explicit, guess, subject = [], False, ""
            for test, _ in chain:
                if isinstance(test, ast.Compare) and len(test.ops) == 1:
                    left, right = test.left, test.comparators[0]
                    if isinstance(test.ops[0], ast.In) and isinstance(left, ast.Constant) and isinstance(left.value, str):
                        subject, guess = unparse(right), guess or bool(_URLISH.search(unparse(right).rsplit(".", 1)[-1]))
                        explicit.append(left.value.lower())
                        continue
                    const = next((x for x in (right, left) if isinstance(x, ast.Constant) and isinstance(x.value, str)), None)
                    if const is not None:
                        subject = unparse(left if const is right else right)
                        explicit.append(const.value.lower())
                        continue
                explicit.append(unparse(test))
            last = min(getattr(final, "end_lineno", start.lineno) or start.lineno, start.lineno + 200)
            lines = [src.line_text(n) for n in range(start.lineno, last + 1)]
            out.append(Selector(src.name, start.lineno, " ".join(" ".join(lines).split())[:400], subject, explicit,
                                nets[-1], {x for x in nets if x}, guess,
                                passphrase=_passphrases([unparse(v) for _, v in chain] + [unparse(final)])))
    seen = set()
    for node in ast.walk(tree):
        call = node.values[0] if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) else node
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "get"):
            continue
        table = unparse(call.func.value).rsplit(".", 1)[-1]
        default = call.args[1] if len(call.args) == 2 else node.values[-1] if call is not node and len(call.args) == 1 else None
        if default is None or table not in tables:
            continue
        fallback = _fallback_value(unparse(call.func.value), unparse(default))
        if fallback is None:
            continue
        keys, body = tables[table]
        if not all(_NET_NAME.match(k) for k in keys):
            continue
        if id(call) in seen:
            continue
        seen.add(id(call))
        nets = {fallback} | {n for n in (net_of(f'"{k}"') for k in keys) if n}
        out.append(Selector(src.name, node.lineno, " ".join(unparse(node).split())[:400], unparse(call.args[0]),
                            keys, fallback, nets, False, passphrase=_passphrases([body, unparse(default)])))
    return out


def selectors(src: _Source, group: list[_Source]) -> list[Selector]:
    """Every selector in a file: switches, ternary chains, if-chains and map fallbacks."""
    if src.selectors is None:
        if src.python:
            found = _py_selectors(src)
            try:
                found += _py_chains(ast.parse(src.text), src)
            except PARSE_ERRORS:
                pass
        else:
            found = _js_switches(src) + _js_ternaries(src) + _js_if_chains(src) + _js_map_fallbacks(src, group)
        src.selectors = found
    return src.selectors


# --------------------------------------------------------------------------- declared domains
_ZOD_ENUM = re.compile(r"""\bz\s*\.\s*enum\s*\(\s*\[(?P<vals>[^\]]{3,400})\]""")
_TS_UNION = re.compile(r"""(?P<vals>["'][\w:-]+["'](?:\s*\|\s*["'][\w:-]+["']){1,8})""")
_PY_CHOICES = re.compile(r"""\b(?:choices\s*=\s*[\[(]|Literal\s*\[)(?P<vals>[^\])]{3,300})[\])]""")


def declared_domains(sources: list[_Source]) -> dict[str, set[str]]:
    """Per package, every network domain declared by a zod enum, a TypeScript union, argparse
    choices or a typing.Literal: lists of two or more network names."""
    out: dict[str, set[str]] = {}
    for src in sources:
        patterns = (_PY_CHOICES,) if src.python else (_ZOD_ENUM, _TS_UNION)
        for pattern in patterns:
            for m in pattern.finditer(src.code):
                values = {v.lower() for v in re.findall(r"""["']([\w:-]+)["']""", m.group("vals"))}
                if len(values) >= 2 and all(_NET_NAME.match(v) for v in values):
                    out.setdefault(src.package, set()).update(values)
    return out


def _handled(value: str, explicit: list[str]) -> bool:
    plain = value.split(":", 1)[-1]
    return any(e == value or e.split(":", 1)[-1] == plain or (_MAINNET_NAME.match(e) and _MAINNET_NAME.match(value))
               for e in explicit)


#: Text that holds a network passphrase (a builder option, an SDK constant, a passphrase table).
_PASSPHRASE_HELD = re.compile(r"[Pp]assphrase|PASSPHRASE|\bNetworks?\.(?:PUBLIC|TESTNET|FUTURENET)\b")
#: A function that turns a network name into a passphrase or a network configuration.
_NETWORK_FN = r"[\w$]*(?:[Pp]assphrase|PASSPHRASE|[Nn]etwork_?[Cc]onfig|NETWORK_?CONFIG)[\w$]*"


def _definition(name: str, group: list[_Source]) -> str:
    """The object literal or dict a table name is assigned, or the body of the function whose
    call result it is assigned (`this.networkConfig = getNetworkConfig(url)`), in the package.
    Looked up once per name and package."""
    memo = group[0].memo.setdefault("definitions", {}) if group else {}
    if name not in memo:
        memo[name] = _find_definition(name, group)
    return memo[name]


def _find_definition(name: str, group: list[_Source]) -> str:
    n = re.escape(name)
    for src in group:
        for m in re.finditer(r"(?<![\w$])(?:this\.|self\.)?" + n + r"\s*(?::[^=;\n{]{0,200})?=(?!=)\s*", src.skel):
            at = m.end()
            if src.skel.startswith("{", at):
                return src.code[at:_closing(src.skel, at) + 1]
            call = re.match(r"(?:new\s+)?([\w$.]+)\s*\(", src.skel[at:at + 200])
            if call:
                fn = re.escape(call.group(1).rsplit(".", 1)[-1])
                for other in group:
                    d = re.search(r"\b(?:function\s+|def\s+)" + fn + r"\s*\(|(?<![\w$.])" + fn
                                  + r"\s*(?::[^=;\n]{0,200})?=\s*(?:async\s*)?(?:\([^)]*\)|[\w$]+)\s*(?::[^=]{0,120})?=>", other.skel)
                    if d:
                        return other.code[d.start():d.start() + 3000]
    return ""


#: Where a name reaches a passphrase (see _feeds_signing), found once per file with the name
#: captured: a network-config call, a CLI --network, and a table subscript.
_TO_NETWORK_FN = re.compile(r"(?<![\w$])" + _NETWORK_FN + r"\s*\(\s*(?:this\.|self\.)?([\w$]+)\s*[,)]")
_TO_CLI = re.compile(r"""--network(?:\s+|=)(?:\$\{|\{)\s*(?:this\.|self\.)?([\w$]+)|["']--network["']\s*,\s*(?:this\.|self\.)?([\w$]+)""")
_SUBSCRIPT = re.compile(r"(?<![\w$])(?P<table>[\w$.]+)\s*\[\s*(?:this\.|self\.)?(?P<name>[\w$]+)\s*\]")


def _uses(src: _Source) -> tuple[set[str], dict[str, list]]:
    """(names passed to a network function or a CLI --network, name -> table subscripts it keys)."""
    if "uses" not in src.memo:
        direct = {m.group(1) for m in _TO_NETWORK_FN.finditer(src.code)}
        direct |= {m.group(1) or m.group(2) for m in _TO_CLI.finditer(src.code)}
        keyed: dict[str, list] = {}
        for m in _SUBSCRIPT.finditer(src.code):
            keyed.setdefault(m.group("name"), []).append(m)
        src.memo["uses"] = (direct, keyed)
    return src.memo["uses"]


def _feeds_signing(src: _Source, sel: Selector, group: list[_Source]) -> bool:
    """The selector's value reaches a passphrase: it yields a passphrase constant itself, keys
    a table whose entries hold passphrases, is passed to a passphrase or network-config
    function, or is the --network of a Stellar CLI command. Logging it, building an explorer
    link from it or passing it to any other function does not count."""
    if sel.passphrase:
        return True
    name = sel.target.rsplit(".", 1)[-1]
    if not name:
        return False
    code = src.code
    direct, keyed = _uses(src)
    if name in direct:
        return True
    for m in keyed.get(name, []):
        if re.match(r"\s*\??\.\s*(?:networkPassphrase|passphrase|network_passphrase)\b", code[m.end():m.end() + 80]):
            return True  # TABLE[net].networkPassphrase
        held = re.search(r"(?<![\w$.])([\w$]+)\s*=\s*$", code[max(0, m.start() - 80):m.start()])
        if held and re.search(r"(?<![\w$])" + re.escape(held.group(1)) + r"\s*\??\.\s*(?:networkPassphrase|passphrase|"
                              r"network_passphrase)\b|(?<![\w$])" + re.escape(held.group(1))
                              + r"""\s*\[\s*["'](?:networkPassphrase|passphrase|network_passphrase)""",
                              code[m.end():m.end() + 2000]):
            return True  # const config = TABLE[net]; ... config.networkPassphrase
        table = m.group("table").rsplit(".", 1)[-1]
        if re.fullmatch(r"Networks?|\w*PASSPHRASES?\w*|\w*[Pp]assphrases\w*", table) \
                or _PASSPHRASE_HELD.search(_definition(table, group)):
            return True
    return False


def fallback_hits(sources: list[_Source]) -> tuple[list[Hit], list[Selector]]:
    """N3. Returns the hits and every selector whose fallback is mainnet (N6 reads them)."""
    domains = declared_domains(sources)
    packages: dict[str, list[_Source]] = {}
    for src in sources:
        packages.setdefault(src.package, []).append(src)
    hits, mainnet_fallbacks = [], []
    for src in sources:
        group = packages[src.package]
        for sel in selectors(src, group):
            domain = domains.get(src.package, set())
            unhandled = {v for v in domain if not _handled(v, sel.explicit)}
            named = [e for e in sel.explicit if _NET_NAME.match(e)]
            if sel.fallback == "mainnet":
                others = {e.split(":", 1)[-1] for e in named if not _MAINNET_NAME.match(e)}
                if domain and not unhandled and not sel.guess:
                    continue  # every declared value has its own branch: the default is unreachable
                if not (sel.guess or len(others) >= 2 or (domain and unhandled - {"mainnet", "public", "pubnet"})):
                    continue  # `x === 'testnet' ? TESTNET : PUBLIC` over two values
                if not _feeds_signing(src, sel, group):
                    continue
                mainnet_fallbacks.append(sel)
                how = ("the network is guessed from a substring of the URL" if sel.guess else
                       "the selector names " + ", ".join(sorted(others)) + " and sends every other value to mainnet"
                       if others else "declared " + ", ".join(sorted(unhandled)) + " have no branch and fall to mainnet")
                hits.append(Hit("security-network-fallback-mainnet", src.name, sel.line, sel.text,
                                _severity(Severity.MEDIUM, src.name), how, group=" ".join(sel.text.split())))
            elif sel.fallback == "testnet":
                # A value compared just before the selector has a branch of its own (`if (net ===
                # 'custom') return config.passphrase`).
                at = src.line_start(sel.line)
                before = src.code[max(0, at - 800):at]
                compared = r"""[!=]==?\s*["'`]{v}["'`]|["'`]{v}["'`]\s*[!=]==?"""
                strays = sorted(v for v in unhandled if not _TESTNET_NAME.match(v)
                                and not re.search(compared.replace("{v}", re.escape(v)), before))
                if not strays or not _feeds_signing(src, sel, group):
                    continue
                hits.append(Hit("security-network-fallback-testnet", src.name, sel.line, sel.text,
                                _severity(Severity.LOW, src.name),
                                f"declared value{'s' if len(strays) > 1 else ''} {', '.join(strays)} "
                                f"silently map{'' if len(strays) > 1 else 's'} to testnet", group=",".join(strays)))
    return hits, mainnet_fallbacks


# --------------------------------------------------------------------------- N6: CLI names
#: A Stellar CLI command in a string or template, and its --network value (literal or ${...}).
_CLI_COMMAND = re.compile(r"""(?:`\s*(?:npx\s+)?(?:stellar|soroban)\s+[^`]*?|["']\s*(?:npx\s+)?(?:stellar|soroban)\s+[^"'\n]*?)"""
                          r"""--network(?:\s+|=)(?P<arg>\$\{(?P<expr>[^}]{1,200})\}|[\w:-]+)""")
#: The same as an argument list: ["stellar", ..., "--network", "public"].
_PY_CLI_LIST = re.compile(r"""\[\s*["'](?:stellar|soroban)["'][^\]]{0,600}?["']--network["']\s*,\s*["'](?P<arg>[\w:-]+)["']""",
                          re.S)
_NETWORK_ADD = re.compile(r"\b(?:stellar|soroban)\s+(?:config\s+)?network\s+add\s+(?:--\S+\s+)*[\"']?(?P<name>[\w:-]+)")


#: A process launch: child_process, execa, zx, subprocess, os.system. `regex.exec(` is not one.
_EXEC = re.compile(r"(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|execa|execaSync|execaCommand)\s*\(|"
                   r"\bchild_process\b|\bnode:child_process\b|\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(|"
                   r"\bos\.(?:system|popen)\s*\(|\bcreate_subprocess_(?:exec|shell)\s*\(|\$`|\bBun\.\$")
#: A string that documents or prints a command rather than running it: help, usage and tool
#: descriptions, and log or print calls.
_DOC_CONTEXT = re.compile(r"""(?i)(?:help|usage|description|example|docs?|hint|instructions?|readme|message|text|title)\w*"""
                          r"""["']?\s*[:=]\s*[\[(]?\s*$|(?:console\.\w+|print|logger\.\w+|log\.\w+|echo)\s*\(\s*$""")


def cli_hits(sources: list[_Source], files: dict[str, str], fallbacks: list[Selector]) -> tuple[list[Hit], dict]:
    """N6. Returns standalone hits and, per mainnet-fallback selector whose value also reaches a
    CLI command, the commands it reaches (folded into that N3 finding). Only commands a
    package can run count: the package launches processes, and the string is not help text,
    a tool description or a log line (the launch itself may sit in another file of the
    package, as with a command table read by a runner)."""
    defined = {m.group("name") for text in files.values() for m in _NETWORK_ADD.finditer(text)}
    known = CLI_NETWORKS | defined
    launches = {src.package for src in sources if _EXEC.search(src.code)}
    package_of = {src.name: src.package for src in sources}
    by_target: dict[str, list[Selector]] = {}
    for sel in fallbacks:
        by_target.setdefault(sel.target.rsplit(".", 1)[-1], []).append(sel)
    hits, folded = [], {}
    for src in sources:
        if src.package not in launches:
            continue
        commands = [(m.start(), m.group("arg"), m.group("expr")) for m in _CLI_COMMAND.finditer(src.code)]
        if src.python:
            commands += [(m.start(), m.group("arg"), None) for m in _PY_CLI_LIST.finditer(src.code)]
        for pos, arg, expr in commands:
            line_at = src.code.rfind("\n", max(0, pos - 4000), pos)
            if _DOC_CONTEXT.search(src.code[max(0, (line_at if line_at >= 0 else pos - 4000) - 200):pos]):
                continue
            line = src.line(pos)
            if expr is None:
                if arg not in known and _NET_NAME.match(arg):
                    hits.append(Hit("security-cli-network-unknown", src.name, line, src.line_text(line),
                                    _severity(Severity.LOW, src.name), f"--network {arg}"))
                continue
            literals = {v for v in re.findall(r"""["'`]([\w:-]+)["'`]""", expr)}
            names = {n.rsplit(".", 1)[-1] for n in re.findall(r"[A-Za-z_$][\w$.]*", expr) if not n.startswith(("'", '"'))}
            for lit in sorted(literals):
                if lit not in known and _NET_NAME.match(lit):
                    hits.append(Hit("security-cli-network-unknown", src.name, line, src.line_text(line),
                                    _severity(Severity.LOW, src.name), f"--network falls back to {lit}"))
            for sel in [s for name in sorted(names) for s in by_target.get(name, [])]:
                same_tree = src.package == package_of.get(sel.file)
                name = sel.target.rsplit(".", 1)[-1]
                strays = sorted(y for y in _selector_names(sel) if y not in known)
                if same_tree and name and name in names and strays:
                    folded.setdefault((sel.file, sel.line), []).append(
                        f"{src.name}:{line} passes {', '.join(strays)} to `stellar --network`, which is not a "
                        f"built-in CLI network ({', '.join(sorted(CLI_NETWORKS))})")
    return hits, folded


def _selector_names(sel: Selector) -> set[str]:
    """The network names a selector's branches yield, as written ('public', 'futurenet')."""
    return set(re.findall(r"""[?:]\s*["'`]([\w:-]+)["'`]""", sel.text)) | \
        set(re.findall(r"""\breturn\s+["'`]([\w:-]+)["'`]""", sel.text))


# --------------------------------------------------------------------------- N1: per-call network
#: Tool and request inputs: the object a handler receives, validated or not.
_INPUT_ROOT = (r"(?:input|args|params|validatedData|validated|validatedInput\.data|parsed|parsedArgs|rawData|"
               r"toolInput|req\.body|req\.query|request\.body)")
#: The region is a tool or request handler: its arguments come from the model or a client.
_HANDLER = re.compile(r"McpToolHandler|\b(?:server|mcp|agent)\.(?:tool|registerTool)\s*\(|\bregisterTool\s*\(|"
                      r"\btool\s*\(\s*\{|\b(?:execute|handler)\s*[:(]|\b(?:app|router|fastify)\.(?:get|post|put|all)\s*\(|"
                      r"setRequestHandler\s*\(")
_NET_ARG = re.compile(r"\b(?:const|let|var)\s+(?P<var>[\w$]+)\s*(?::[^=;\n]+)?=\s*(?P<src>" + _INPUT_ROOT
                      + r"\??\.network)\b\s*(?=\?\?|\|\||;|\n|$)")
_DIRECT_NET_ARG = re.compile(r"(?<![\w$.])(?P<src>" + _INPUT_ROOT + r"\??\.network)\b(?!\s*(?:=(?!=)|\())")
#: A top-level declaration: where one handler's text ends.
_TOP_LEVEL = re.compile(r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\b|const\s+[\w$]+\s*[:=]|class\b)", re.M)
#: An operator-held key: loaded from configuration or the environment, not from the call.
_OPERATOR_KEY = re.compile(r"\bKeypair\.fromSecret\(\s*(?:config|cfg|settings|env|process\.env|CONFIG|this\.(?:config|options|"
                           r"secret\w*|keypair)|[A-Z][A-Z0-9_]*(?:SECRET|SEED|KEY)\w*)[\w$.\[\]'\"!?]*\s*\)")
_SIGNS = re.compile(r"\.sign\s*\(|\bsignTransaction\s*\(|\bauthorizeEntry\s*\(|\bsignAuthEntries\s*\(")
_PY_OPERATOR_KEY = re.compile(r"\bKeypair\.from_secret\(\s*(?:os\.(?:environ|getenv)|settings|config|"
                              r"self\.(?:secret|config|settings)\w*|[A-Z][A-Z0-9_]*(?:SECRET|SEED|KEY)\w*)")


def _region(src: _Source, pos: int) -> tuple[int, int]:
    """The top-level declaration that holds ``pos``: from the last top-level head before it to
    the next one."""
    return src.region(pos)


#: A same-file function, by name: `function f(`, `const f = (...) =>`, `const f = async function`.
_JS_DEF = re.compile(r"\bfunction\s*\*?\s*(?P<a>[\w$]+)\s*\(|\b(?:const|let|var)\s+(?P<b>[\w$]+)\s*(?::[^=;\n]{0,160})?=\s*"
                     r"(?:async\s+)?(?:function\b|\([^)]{0,400}\)\s*(?::[^=;{]{0,160})?=>|[\w$]+\s*=>)")
_CALLED = re.compile(r"(?<![\w$.])([\w$]+)\s*\(")
#: At most this many distinct network values are judged per function, and this many callees read.
_PER_SCOPE_VALUES, _CALLEES = 16, 16


def _js_defs(src: _Source) -> dict[str, tuple[int, int]]:
    """Function name -> body span, for the functions this file defines (first definition wins)."""
    if "defs" not in src.memo:
        defs: dict[str, tuple[int, int]] = {}
        pairs = src.pairs()
        for m in _JS_DEF.finditer(src.skel):
            name = m.group("a") or m.group("b")
            brace = src.skel.find("{", m.end(), m.end() + 400)
            if name in defs or brace < 0 or brace not in pairs:
                continue
            body = src.function_at(brace + 1)
            if body is not None and body[0] == brace:
                defs[name] = body
        src.memo["defs"] = defs
    return src.memo["defs"]


def _signing(src: _Source, span: tuple[int, int]) -> tuple[bool, bool, set[str]]:
    """(signs, loads an operator key, the names its sign calls pass) for one function body;
    computed once per body."""
    cache = src.memo.setdefault("signing", {})
    if span not in cache:
        names: set[str] = set()
        signs = False
        for m in _SIGNS.finditer(src.code, span[0], span[1]):
            signs = True
            close = _closing(src.skel, m.end() - 1, "(", ")", limit=400)
            names |= set(re.findall(r"(?<![\w$])(?:this\.)?([\w$]+)", src.code[m.end():close]))
        key = _OPERATOR_KEY.search(src.code, span[0], span[1])
        operator = bool(key) and not re.search(_INPUT_ROOT + r"\??\.\w*secret", key.group(0), re.I)
        cache[span] = (signs, operator, names)
    return cache[span]


def _operator_keys(src: _Source) -> set[str]:
    """Names this file binds to an operator key: `const kp = Keypair.fromSecret(process.env.X)`,
    `this.keypair = ...`, a class field."""
    if "keys" not in src.memo:
        src.memo["keys"] = {m.group(1) for m in re.finditer(r"(?<![\w$])(?:this\.)?([\w$]+)\s*(?::[^=;\n]{0,120})?=\s*"
                                                         r"(?:await\s+)?(?=Keypair\.fromSecret\()", src.code)
                            if _OPERATOR_KEY.match(src.code, m.end())}
    return src.memo["keys"]


def _operator_signs(src: _Source, scope: tuple[int, int]) -> bool:
    """The function signs with an operator key: it (or a function of this file it calls) signs,
    and the key is loaded there or is a name this file binds to an operator key."""
    spans = [scope]
    defs = _js_defs(src)
    for name in dict.fromkeys(m.group(1) for m in _CALLED.finditer(src.code, scope[0], scope[1])):
        if name in defs and defs[name] != scope and len(spans) <= _CALLEES:
            spans.append(defs[name])
    signs = operator = False
    names: set[str] = set()
    for span in spans:
        s, o, n = _signing(src, span)
        signs, operator, names = signs or s, operator or o, names | n
    return signs and (operator or bool(names & _operator_keys(src)))


def _picks(region: str, value: str):
    """Where ``value`` picks the passphrase, and whether it picks the endpoint, in ``region``."""
    v = re.escape(value)
    passphrase = re.search(
        r"(?<!\w)\w*[Pp]assphrase\w*\s*\(\s*" + v + r"\b|\bNetworks?\s*\[\s*" + v + r"|PASSPHRASES?\w*\s*\[\s*" + v +
        r"|\[\s*" + v + r"\s*\]\s*\??\.\s*(?:networkPassphrase|passphrase)|networkPassphrase\s*:\s*[^,}\n]*\b" + v + r"\b|"
        + v + r"""\s*===?\s*["'`][\w:]+["'`]\s*\?\s*[^;]{0,80}(?:Networks?\.PUBLIC|PUBLIC_NETWORK_PASSPHRASE)""", region)
    endpoint = bool(re.search(
        r"\b\w*(?:Horizon|Rpc|RPC|Soroban|Server|Url|URL|Endpoint)\w*\s*[(\[]\s*" + v + r"\b|\[\s*" + v +
        r"\s*\]\s*\??\.\s*(?:horizon|rpc|soroban|server|url|endpoint)\w*|\bnew\s+(?:[\w$]+\.)*Server\s*\([^)]*\b" + v + r"\b",
        region, re.I))
    return passphrase, endpoint


def _pinned(region: str, value: str) -> bool:
    """`if (args.network && args.network !== config.network) throw`: the call may only repeat
    the configured network."""
    v = re.escape(value)
    return bool(re.search(v + r"\s*!==?\s*(?:config|cfg|env|settings|process\.env)[\w$.]*|(?:config|cfg|env|settings|"
                          r"process\.env)[\w$.]*\s*!==?\s*" + v + r"\b", region))


#: A request to a Horizon or RPC server whose URL a variable holds.
_ENDPOINT_USE = re.compile(r"\bfetch\s*\(\s*`\$\{\s*(?P<a>[\w$.]*(?:horizon|rpc|soroban|server)\w*)|"
                           r"\bnew\s+(?:[\w$]+\.)*Server\s*\(\s*(?P<b>[\w$.]+)", re.I)


def per_call_hits(sources: list[_Source]) -> list[Hit]:
    """N1. A tool or request argument picks both the passphrase and the endpoint of a
    transaction an operator-held key signs. With either one pinned to configuration the
    signature fails on the other network, so both must follow it. When only the passphrase
    follows the argument and the endpoint stays on configuration, the pair is incoherent (N4)."""
    hits = []
    for src in sources:
        if src.python:
            hits += _py_per_call(src)
            continue
        judged: dict[tuple[int, int], set[str]] = {}
        candidates = [(m.group("var"), m.start()) for m in _NET_ARG.finditer(src.code)]
        candidates += [(m.group("src"), m.start()) for m in _DIRECT_NET_ARG.finditer(src.code)]
        for value, pos in candidates:
            # The function that reads the value (a tool callback, a route handler): its own
            # picks and signature count, not those of another tool in the same declaration.
            top = src.region(pos)
            start, end = src.function_at(pos) or top
            values = judged.setdefault((start, end), set())
            if value in values or len(values) >= _PER_SCOPE_VALUES:
                continue
            values.add(value)
            region = src.code[start:end]
            passphrase, endpoint = _picks(region, value)
            if not passphrase or _pinned(region, value):
                continue
            line = src.line(pos if endpoint else start + passphrase.start())
            if not endpoint:
                used = [u.group("a") or u.group("b") for u in _ENDPOINT_USE.finditer(region)]
                if any(u and value not in u and not re.search(r"\b" + re.escape(value.rsplit(".", 1)[-1]) + r"\b", u)
                       for u in used):
                    hits.append(Hit("security-network-endpoint-mismatch", src.name, line, src.line_text(line),
                                    Severity.LOW, f"`{value}` picks the passphrase, but the endpoint stays on configuration",
                                    group="per-call-endpoint"))
                continue
            if not _HANDLER.search(src.code, top[0], top[1]) or not _operator_signs(src, (start, end)):
                continue
            hits.append(Hit("security-network-chosen-per-call", src.name, line, src.line_text(line),
                            _severity(Severity.MEDIUM, src.name),
                            f"`{value}` picks both the passphrase and the endpoint the operator key signs for",
                            group="per-call"))
    return hits


def _py_per_call(src: _Source) -> list[Hit]:
    try:
        tree = ast.parse(src.text)
    except PARSE_ERRORS:
        return []
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tool = any(re.search(r"(?:^|\.)(?:tool|function_tool|mcp_tool)\b", unparse(d)) for d in fn.decorator_list)
        params = {a.arg for a in [*fn.args.args, *fn.args.kwonlyargs]}
        if not tool or "network" not in params:
            continue
        body = src.code[src.line_start(fn.lineno):src.line_start((fn.end_lineno or fn.lineno) + 1)]  # sliced, not unparsed
        if not _PY_OPERATOR_KEY.search(body) or not re.search(r"\.sign\s*\(|authorize_entry\s*\(", body):
            continue
        passphrase = re.search(r"(?:PASSPHRASE\w*|passphrase\w*)\s*\[\s*network\b|\w*passphrase\w*\(\s*network\b|"
                               r"Network\.PUBLIC_NETWORK_PASSPHRASE\s+if\s+network\b|network_passphrase\s*=\s*[^,\n]*\bnetwork\b",
                               body, re.I)
        endpoint = re.search(r"\b\w*(?:horizon|rpc|soroban|server|url)\w*\s*\(\s*network\b|\[\s*network\s*\]\s*\.\s*"
                             r"(?:horizon|rpc|url)|\bServer\s*\([^)]*\bnetwork\b", body, re.I)
        if passphrase and endpoint and not re.search(r"network\s*!=\s*(?:settings|config|os\.)", body):
            hits.append(Hit("security-network-chosen-per-call", src.name, fn.lineno, src.line_text(fn.lineno),
                            _severity(Severity.MEDIUM, src.name),
                            "the tool's `network` argument picks both the passphrase and the endpoint", group="per-call"))
    return hits


# --------------------------------------------------------------------------- N2: counterparty network
_MPP_CLIENT = re.compile(r"""["'`]@stellar/mpp/charge/client["'`]""")
_MPP_IMPORT = re.compile(r"""import\s*\{(?P<names>[^}]*)\}\s*from\s*["'`]@stellar/mpp/charge/client["'`]""")
#: A check that the challenge's network is the configured one.
_CHALLENGE_NETWORK_CHECK = re.compile(r"methodDetails\??\.network\s*[!=]==?|[!=]==?\s*[\w$.?]*methodDetails\??\.network")


def counterparty_hits(sources: list[_Source]) -> list[Hit]:
    """N2. An @stellar/mpp charge client with an operator key and no pinned RPC: it signs for
    whatever network the paid server's challenge names (methodDetails.network) and talks to
    that network's default RPC (@stellar/mpp 0.3.0 to 0.7.1 charge client; the client takes no
    network option)."""
    checked = {src.package for src in sources if _CHALLENGE_NETWORK_CHECK.search(src.code)}
    hits = []
    for src in sources:
        if src.python or not _MPP_CLIENT.search(src.code) or src.package in checked:
            continue
        names = set()
        for m in _MPP_IMPORT.finditer(src.code):
            for part in m.group("names").split(","):
                bits = part.split(" as ")
                if bits[0].strip() in {"stellar", "charge"}:
                    names.add((bits[-1].strip(), bits[0].strip()))
        calls = []
        for alias, original in names:
            pattern = re.escape(alias) + (r"(?:\.charge)?" if original == "stellar" else "")
            calls += list(re.finditer(r"(?<![\w$.])" + pattern + r"\s*\(\s*\{", src.code))
        if not names:  # a dynamic import: `const { stellar } = await import(...)`
            calls = list(re.finditer(r"(?<![\w$])[\w$]+\.charge\s*\(\s*\{", src.code))
        for call in calls:
            open_at = call.end() - 1
            options = src.code[open_at:_closing(src.skel, open_at, limit=2000) + 1]
            if not re.search(r"\b(?:secretKey|keypair)\b", options) or re.search(r"\brpcUrl\b", options):
                continue
            line = src.line(call.start())
            hits.append(Hit("security-network-chosen-by-counterparty", src.name, line, src.line_text(line),
                            _severity(Severity.MEDIUM, src.name), group=f"{src.name}:{line}"))
    return hits


# --------------------------------------------------------------------------- N4: incoherent pairs
_HOSTS = {net: tuple(m for m in markers if "." in m and " " not in m) for net, markers in NETWORK_MARKERS.items()}
#: A fixed-network URL as a default: zod .default(url), `?? url`, `|| url`, getenv(name, url).
_URL_DEFAULT = re.compile(r"""(?:\.default\(\s*|(?:\|\||\?\?)\s*|getenv\(\s*["']\w+["']\s*,\s*|get\(\s*["']\w+["']\s*,\s*)"""
                          r"""["'](?P<url>https?://[^"'\s]+)["']""")
#: A configuration entry for a Horizon or RPC URL, and one for a network name.
_ENDPOINT_KEY = re.compile(r"""(?<![\w$])(?P<key>[\w$]*(?:HORIZON|Horizon|horizon|RPC|Rpc|rpc|SOROBAN|Soroban)[\w$]*)["']?\s*[:=]\s*"""
                           r"""(?P<expr>[^\n;]+)""")
_NETWORK_KEY = re.compile(r"""(?<![\w$])(?P<key>[\w$]*(?:NETWORK|Network|network)(?!_?PASSPHRASE|_?Passphrase|_?passphrase|_?URL|Url)"""
                          r"""[\w$]*)["']?\s*[:=]\s*(?P<expr>[^\n;]+)""")
_CONFIGURED = re.compile(r"process\.env|import\.meta\.env|os\.(?:getenv|environ)|\bz\s*\.\s*(?:string|enum)|\benv\b")
#: A start-up check that the server's own passphrase (RPC getNetwork, the Horizon root) is the
#: configured one.
_STARTUP_CHECK = re.compile(r"(?:getNetwork|get_network|root|fetchRoot|loadRoot)\s*\(\s*\)[\s\S]{0,300}?[Pp]assphrase"
                            r"[\s\S]{0,120}?(?:!==?|!=)")


def _host_net(url: str) -> str | None:
    for net, hosts in _HOSTS.items():
        if any(h in url for h in hosts):
            return net
    return None


#: A passphrase constant a configured network name can pick.
_PASS_SITE = re.compile(r"Networks?\.(?:PUBLIC|TESTNET)|_NETWORK_PASSPHRASE")
_WORD = re.compile(r"[\w$]+")


def _inside_word(code: str, at: int) -> bool:
    return at > 0 and (code[at - 1].isalnum() or code[at - 1] in "_$")


def _near_passphrase(group: list[_Source]) -> dict[str, dict[str, tuple[int, int]]]:
    """word -> {file: (first, last offset)} of the words that stand within 120 characters of a
    passphrase constant in the same statement (no `;` or line break between): what
    `KEY[^;\\n]{0,120}PASSPHRASE` or the reverse would match, indexed once per package."""
    memo = group[0].memo
    if "near" not in memo:
        near: dict[str, dict[str, tuple[int, int]]] = {}

        def add(word: str, name: str, at: int) -> None:
            first, last = near.setdefault(word, {}).get(name, (at, at))
            near[word][name] = (min(first, at), max(last, at))
        for s in group:
            code = s.code
            for m in _PASS_SITE.finditer(code):
                floor = max(0, m.start() - 120)
                left = max(floor, code.rfind(";", floor, m.start()) + 1, code.rfind("\n", floor, m.start()) + 1)
                for w in _WORD.finditer(code, max(0, left - 64), m.start()):
                    if w.end() >= left and not _inside_word(code, w.start()):
                        add(w.group(), s.name, w.start())
                ceiling = min(len(code), m.end() + 121)
                stops = [x for x in (code.find(";", m.end(), ceiling), code.find("\n", m.end(), ceiling)) if x >= 0]
                right = min(stops) if stops else ceiling
                for w in _WORD.finditer(code, m.end(), right + 64):
                    if w.start() < right and not _inside_word(code, w.start()):
                        add(w.group(), s.name, w.start())
        memo["near"] = near
    return memo["near"]


def mismatch_hits(sources: list[_Source]) -> list[Hit]:
    """N4. A configured network name picks the passphrase while the Horizon or RPC URL keeps a
    fixed-network default of its own (or the passphrase is fixed while the URL is
    configurable). Setting one without the other signs for one network and submits to the
    other: the transaction fails."""
    by_package: dict[str, list[_Source]] = {}
    for src in sources:
        by_package.setdefault(src.package, []).append(src)
    hits = []
    for package, group in by_package.items():
        text = "\n".join(s.code for s in group)
        if _STARTUP_CHECK.search(text):
            continue
        for src in group:
            eligible = None
            for m in _ENDPOINT_KEY.finditer(src.code):
                expr = m.group("expr")
                default = _URL_DEFAULT.search(expr)
                ternary = "?" in expr.replace("??", "").replace("?.", "")
                if not default or not _CONFIGURED.search(expr) or ternary or _host_net(default.group("url")) is None:
                    continue
                if eligible is None:
                    # The configured network names that pick the passphrase somewhere in the
                    # package other than their own definition.
                    near, eligible = _near_passphrase(group), []
                    for n in _NETWORK_KEY.finditer(src.code):
                        places = near.get(n.group("key"), {})
                        own = places.get(src.name)
                        if _CONFIGURED.search(n.group("expr")) and (len(places) > (1 if own else 0) or (
                                own and (own[0] < n.start() or own[1] >= n.end()))):
                            eligible.append(n.group("key"))
                key = next((k for k in eligible if k not in expr), None)
                if key is None:
                    continue
                line = src.line(m.start())
                hits.append(Hit("security-network-endpoint-mismatch", src.name, line, src.line_text(line),
                                _severity(Severity.LOW, src.name),
                                f"{key} picks the passphrase, but {m.group('key')} defaults to a "
                                f"{_host_net(default.group('url'))} URL of its own", group=f"{src.name}:{key}"))
        hits += _fixed_pairs(group, text)
    return hits


_FIXED_PASSPHRASE_JS = re.compile(r"\bnetworkPassphrase\s*:\s*(?:Networks\.(?:TESTNET|PUBLIC)\b|[\"'](?:Test SDF Network|"
                                  r"Public Global))")
_CONFIG_PASSPHRASE_JS = re.compile(r"\bnetworkPassphrase\s*:\s*(?:process\.env\.\w+|import\.meta\.env\.\w+|"
                                   r"[\w$.]*[Pp]assphrase\b(?!\s*\())")
_ENV_URL_JS = re.compile(r"""\b(?:const|let|var)\s+(?P<name>[\w$]+)\s*=\s*(?:process\.env|import\.meta\.env)\.\w+\s*"""
                         r"""(?:\|\||\?\?)\s*["'](?P<url>https?://[^"'\s]+)["']""")
_LITERAL_SERVER_JS = re.compile(r"""\bnew\s+(?:[\w$]+\.)*Server\s*\(\s*["'](?P<url>https?://[^"'\s]+)["']""")


def _fixed_pairs(group: list[_Source], text: str) -> list[Hit]:
    """N4 when one side is written into the code: a fixed passphrase with a configurable URL,
    or a configurable passphrase with a fixed URL."""
    hits = []
    found = [sel for src in group for sel in selectors(src, group)]
    selected = any(sel.yields and re.search(r"[Pp]assphrase|PASSPHRASE|Networks?\.", sel.text) for sel in found)
    configured = bool(_CONFIG_PASSPHRASE_JS.search(text))
    served: dict[str, bool] = {}  # name -> a Server is built from it somewhere in the package
    py_text = "\n".join(s.code for s in group if s.python)
    for src in group:
        if _NON_PRODUCTION.search(src.name):
            continue
        if src.python:
            hits += _py_fixed_pairs(src, group, selected, py_text)
            continue
        if _FIXED_PASSPHRASE_JS.search(src.code) and not selected and not configured:
            for m in _ENV_URL_JS.finditer(src.code):
                name = m.group("name")
                if name not in served:
                    served[name] = bool(re.search(r"Server\s*\(\s*" + re.escape(name) + r"\b", text))
                if _host_net(m.group("url")) and served[name]:
                    line = src.line(m.start())
                    hits.append(Hit("security-network-endpoint-mismatch", src.name, line, src.line_text(line),
                                    Severity.LOW, f"the passphrase is fixed, but {name} is configurable",
                                    group=f"{src.name}:{name}"))
        if _CONFIG_PASSPHRASE_JS.search(src.code):
            for m in _LITERAL_SERVER_JS.finditer(src.code):
                if _host_net(m.group("url")):
                    line = src.line(m.start())
                    hits.append(Hit("security-network-endpoint-mismatch", src.name, line, src.line_text(line),
                                    Severity.LOW, f"the passphrase is configurable, but the server is fixed to "
                                    f"{_host_net(m.group('url'))}", group=f"{src.name}:literal-server"))
                    break
    return hits


def _py_fixed_pairs(src: _Source, group: list[_Source], selected: bool, package_text: str) -> list[Hit]:
    try:
        tree = ast.parse(src.text)
    except PARSE_ERRORS:
        return []
    hits = []
    # (b) a module-level fixed passphrase reaches a builder; the URL comes from the environment.
    fixed: dict[str, str] = {}  # name -> the network of its value
    for n in tree.body:
        if not isinstance(n, ast.Assign):
            continue
        value = unparse(n.value)
        net = net_of(value) if re.search(r"PASSPHRASE|Test SDF|Public Global", value) and "getenv" not in value else None
        if net in {"testnet", "mainnet"}:
            fixed.update({t.id: net for t in n.targets if isinstance(t, ast.Name)})
    configurable = re.search(r"getenv\(\s*[\"']\w*PASSPHRASE|environ(?:\.get\(|\[)\s*[\"']\w*PASSPHRASE", package_text)
    built = sorted({net for name, net in fixed.items()
                    if re.search(r"network_passphrase\s*=\s*" + re.escape(name) + r"\b", package_text)})
    if built and not configurable and not selected:
        for n in tree.body:
            if not (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name)):
                continue
            call = unparse(n.value.func)
            args = n.value.args
            if call in {"os.getenv", "os.environ.get", "getenv"} and len(args) == 2 and isinstance(args[1], ast.Constant) \
                    and isinstance(args[1].value, str) and _host_net(args[1].value):
                name = n.targets[0].id
                if re.search(r"(?:Server\w*|_client\w*)\s*\(\s*" + re.escape(name) + r"\b", package_text):
                    hits.append(Hit("security-network-endpoint-mismatch", src.name, n.lineno, src.line_text(n.lineno),
                                    Severity.LOW, f"the passphrase is fixed to {' and '.join(built)} constants, but "
                                    f"{name} is configurable", group=f"{src.name}:fixed-passphrase"))
    # (c) a configurable passphrase next to a server fixed to one network.
    for scope in ast.walk(tree):
        if not isinstance(scope, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fns = [f for f in scope.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))] \
            if isinstance(scope, ast.ClassDef) else [scope]
        if not any("passphrase" in a.arg for f in fns for a in [*f.args.args, *f.args.kwonlyargs]):
            continue
        for call in ast.walk(scope):
            server = isinstance(call, ast.Call) and re.search(r"(?:^|\.)(?:Server|SorobanServer|ServerAsync)$",
                                                              unparse(call.func))
            if server and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str) \
                    and _host_net(call.args[0].value):
                hits.append(Hit("security-network-endpoint-mismatch", src.name, call.lineno, src.line_text(call.lineno),
                                Severity.LOW, f"the passphrase is a parameter, but the server is fixed to "
                                f"{_host_net(call.args[0].value)}", group=f"{src.name}:{call.lineno}"))
                break
    first: dict[str, Hit] = {}
    for hit in hits:
        first.setdefault(hit.group, hit)
    return list(first.values())


# --------------------------------------------------------------------------- N5: cross-network constants
#: Values that exist on one network only, other than passphrases: Circle's USDC issuer and
#: SAC, and the public x402 facilitators that serve testnet alone.
_ONLY_ON = {"testnet": (USDC_ISSUER["testnet"], USDC_SAC["testnet"], "x402.org/facilitator",
                        "channels.openzeppelin.com/x402/testnet"),
            "mainnet": (USDC_ISSUER["mainnet"], USDC_SAC["mainnet"])}


def _only_on(value: str) -> str | None:
    for net, markers in _ONLY_ON.items():
        if any(m in value for m in markers):
            return net
    return None


class _PyNets:
    """For one Python module: which networks each passphrase value can be, and which
    one-network constants each value carries, by assignment (locals, then self attributes
    across a class)."""

    def __init__(self, tree: ast.Module):
        self.attrs: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                        self.attrs.setdefault(t.attr, set()).update(self.passphrases(node.value, {}))

    def passphrases(self, node: ast.AST, local: dict[str, set[str]]) -> set[str]:
        if isinstance(node, ast.IfExp):
            return self.passphrases(node.body, local) | self.passphrases(node.orelse, local)
        if isinstance(node, ast.Name):
            return set(local.get(node.id, set()))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            return set(self.attrs.get(node.attr, set()))
        text = unparse(node)
        if re.search(r"PASSPHRASE|Test SDF|Public Global", text):
            found = net_of(text)
            return {found} if found in {"testnet", "mainnet"} else set()
        return set()


def _py_constants(node: ast.AST, consts: dict[str, tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    """(network, value, line) of every one-network constant an expression carries."""
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _only_on(sub.value):
            out.append((_only_on(sub.value), sub.value, getattr(sub, "lineno", 0)))
        elif isinstance(sub, ast.Name) and sub.id in consts:
            out.append(consts[sub.id])
    return out


def _holding(tree: ast.AST, marked: set[int]) -> dict[int, frozenset[int]]:
    """id(node) -> the marked nodes in its subtree (itself included), in one bottom-up pass."""
    out: dict[int, frozenset[int]] = {}
    empty: frozenset[int] = frozenset()
    stack: list[tuple[ast.AST, bool]] = [(tree, False)]
    while stack:
        node, done = stack.pop()
        if not done:
            stack.append((node, True))
            stack.extend((child, False) for child in ast.iter_child_nodes(node))
            continue
        found = set()
        for child in ast.iter_child_nodes(node):
            found |= out.get(id(child), empty)
        if id(node) in marked:
            found.add(id(node))
        out[id(node)] = frozenset(found) if found else empty
    return out


def cross_constant_hits(sources: list[_Source]) -> list[Hit]:
    """N5. A transaction whose passphrase can be one network carries a constant that exists
    only on the other (a payment in testnet USDC signed for mainnet), with no branch on the
    network between them: by value flow through one builder chain, never by co-occurrence."""
    hits = []
    for src in sources:
        if not src.python or not re.search("|".join(re.escape(m) for ms in _ONLY_ON.values() for m in ms), src.text):
            continue
        try:
            tree = ast.parse(src.text)
        except PARSE_ERRORS:
            continue
        nets = _PyNets(tree)
        builders = {id(n) for n in ast.walk(tree) if isinstance(n, ast.Call) and unparse(n.func).endswith("TransactionBuilder")}
        below = _holding(tree, builders)
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            local: dict[str, set[str]] = {}
            consts: dict[str, tuple[str, str, int]] = {}
            branched: set[str] = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.If) and re.search(r"network|testnet|mainnet|pubnet|passphrase", unparse(node.test),
                                                          re.I):
                    branched |= {t.id for n in ast.walk(node) if isinstance(n, ast.Assign) for t in n.targets
                                 if isinstance(t, ast.Name)}
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    name = node.targets[0].id
                    local[name] = nets.passphrases(node.value, local)
                    found = _py_constants(node.value, consts)
                    if found and name not in branched:
                        consts[name] = found[0]
            # The operations appended to each builder: every call whose receiver holds it.
            chains: dict[int, list[ast.Call]] = {}
            for op in ast.walk(fn):
                if isinstance(op, ast.Call) and isinstance(op.func, ast.Attribute) and op.func.attr.startswith("append_"):
                    for builder in below.get(id(op.func.value), ()):
                        chains.setdefault(builder, []).append(op)
            for call in ast.walk(fn):
                if not (isinstance(call, ast.Call) and id(call) in builders):
                    continue
                passphrase = next((k.value for k in call.keywords if k.arg == "network_passphrase"),
                                  call.args[1] if len(call.args) > 1 else None)
                if passphrase is None:
                    continue
                signs_for = nets.passphrases(passphrase, local)
                for op in chains.get(id(call), []):
                    values = [*op.args, *(k.value for k in op.keywords)]
                    arguments = ast.Module(body=[ast.Expr(a) for a in values], type_ignores=[])
                    for net, value, line in _py_constants(arguments, consts):
                        other = {"testnet": "mainnet", "mainnet": "testnet"}[net]
                        if other in signs_for:
                            line = line or op.lineno
                            hits.append(Hit("security-network-cross-constant", src.name, line,
                                            src.line_text(line), _severity(Severity.LOW, src.name),
                                            f"a {net}-only constant ({value[:12]}…) reaches a transaction whose passphrase "
                                            f"can be {other}", group=f"{src.name}:{value}"))
    return hits


# --------------------------------------------------------------------------- findings
#: The @stellar/mpp releases whose charge client was read: none takes a network option, and
#: each signs for methodDetails.network with that network's default RPC (0.3.0, 0.4.0, 0.7.1).
MPP_CLIENT_FOLLOWS_CHALLENGE = "0.7.1"
#: Rules whose hits mean the code can sign for mainnet although testnet was meant: under a
#: .tmark that declares testnet they are evidence for intent-tmark-network-mismatch (HIGH).
MAINNET_REACHABLE = frozenset({"security-network-chosen-per-call", "security-network-chosen-by-counterparty",
                               "security-network-fallback-mainnet"})
_RULES = {
    # rule: (title, detail, remediation, references, grade)
    "security-network-chosen-per-call": (
        "A tool argument chooses the network the operator key signs for",
        "A tool or request argument picks both the network passphrase and the Horizon or RPC endpoint of a "
        "transaction the server signs with its own key. Whoever steers the model (or sends the request) can move "
        "a call configured for testnet to mainnet; a key that also holds mainnet funds then pays for real.",
        "Take the network from operator configuration only, or refuse a per-call network that differs from it.",
        ["Stellar network passphrases", "OWASP LLM06 Excessive Agency"], EvidenceGrade.INFERRED),
    "security-network-chosen-by-counterparty": (
        "The paid server chooses which network the MPP client pays on",
        "The @stellar/mpp charge client signs for the network named in the server's 402 challenge "
        "(methodDetails.network) and uses that network's default RPC; it has no network option. A paid endpoint "
        "can answer with stellar:pubnet and the agent's key pays real USDC, whatever network the agent is "
        "configured for.",
        "Pass rpcUrl for the configured network (a challenge for the other network then fails), or reject "
        "challenges whose methodDetails.network differs from the configured one before paying.",
        ["MPP charge client", "OWASP LLM06 Excessive Agency"], EvidenceGrade.CONFIRMED),
    "security-network-fallback-mainnet": (
        "An unrecognised network value signs for mainnet",
        "The code turns a configured value into a network, and every value it does not recognise ends on the "
        "public network: a local or custom endpoint, a provider URL without 'testnet' in it, or a typo. A key "
        "that also holds funds on mainnet then signs real payments the operator meant for a test network.",
        "Map only known values (testnet, mainnet, futurenet) and refuse anything else at start-up; never default "
        "to the public network.",
        ["Stellar network passphrases"], EvidenceGrade.CONFIRMED),
    "security-network-fallback-testnet": (
        "A declared network value is silently used with the testnet passphrase",
        "A network the configuration or tool schema accepts has no branch of its own and falls through to the "
        "testnet passphrase: whatever the code signs, verifies or looks up for that network is done against "
        "testnet instead, so it fails or reads the wrong ledger.",
        "Give every declared network its own passphrase, or remove the value from the accepted list.",
        ["Stellar network passphrases"], EvidenceGrade.CONFIRMED),
    "security-network-endpoint-mismatch": (
        "The passphrase and the Horizon or RPC URL are configured separately",
        "One of the two follows the configured network and the other keeps a fixed network of its own. Changing "
        "the network without the other setting signs for one network and submits to the other: transactions "
        "fail, and balances and simulations come from the wrong ledger.",
        "Derive passphrase, Horizon URL and RPC URL from one network setting (a NETWORKS[net] table), or check "
        "at start-up that the server's passphrase (RPC getNetwork, the Horizon root) matches.",
        ["Stellar network passphrases"], EvidenceGrade.INFERRED),
    "security-network-cross-constant": (
        "A constant from one network reaches a transaction signed for the other",
        "A value that exists on one network only (Circle's testnet USDC issuer or contract, a testnet-only "
        "facilitator) is used in a transaction whose passphrase can be the other network, with no branch on the "
        "network in between. On that network the issuer, contract or service does not exist, so the trustline or "
        "payment fails there.",
        "Select network-specific constants from the same network setting as the passphrase "
        "({testnet: ..., mainnet: ...}[net]).",
        ["Stellar assets and issuers"], EvidenceGrade.INFERRED),
    "security-cli-network-unknown": (
        "A Stellar CLI command names a network the CLI does not define",
        "stellar-cli defines only local, futurenet, testnet and mainnet; any other --network value fails unless "
        "`stellar network add` defines it, so the command fails or runs against whatever a user registered "
        "under that name.",
        "Use mainnet (with an RPC URL) or testnet, or define the name with `stellar network add` in setup.",
        ["stellar-cli network configuration"], EvidenceGrade.CONFIRMED),
}


def _mpp_versions(artifact: AgentArtifact, file: str) -> tuple[bool, str]:
    """Whether the @stellar/mpp near ``file`` is a release whose client was read."""
    from ..services.lockfiles import Lockset, below
    found = Lockset(artifact.raw_metadata.get("resolved_versions")).resolve("@stellar/mpp", file)
    versions = list(found.versions) if found else []
    if versions and all(v == MPP_CLIENT_FOLLOWS_CHALLENGE or below(v, MPP_CLIENT_FOLLOWS_CHALLENGE) is True
                        for v in versions):
        return True, f"@stellar/mpp {', '.join(versions)} installed"
    return False, (f"@stellar/mpp {', '.join(versions)} installed; releases after {MPP_CLIENT_FOLLOWS_CHALLENGE} "
                   "were not read" if versions else "installed @stellar/mpp version not resolved")


def _findings(hits: list[Hit], auditor: str, folded: dict | None = None, artifact: AgentArtifact | None = None,
              sdk: bool = False) -> list[Finding]:
    """One finding per rule and group (identical copies of one selector are one defect), at the
    worst severity, with every place as evidence."""
    groups: dict[tuple[str, str], list[Hit]] = {}
    for hit in hits:
        groups.setdefault((hit.rule, hit.group or f"{hit.file}:{hit.line}"), []).append(hit)
    out = []
    for (rule, _), group in groups.items():
        group.sort(key=lambda h: (h.file, h.line))
        worst = max(group, key=lambda h: h.severity.rank)
        title, detail, remediation, refs, grade = _RULES[rule]
        notes = list(dict.fromkeys(n for h in group for n in [h.note] + h.extra if n))
        if rule == "security-network-chosen-by-counterparty" and artifact is not None:
            read, why = _mpp_versions(artifact, group[0].file)
            grade = EvidenceGrade.CONFIRMED if read else EvidenceGrade.INFERRED
            notes.append(why)
        extra = list(dict.fromkeys(x for h in group for x in (folded or {}).get((h.file, h.line), [])))
        evidence = [f"{h.file}:{h.line} `{' '.join(h.text.split())[:160]}`" for h in group[:5]]
        severity = worst.severity.downgrade(1) if sdk else worst.severity
        if sdk:
            notes.append("the .tmark declares an SDK, which its integrators configure")
        out.append(Finding(
            id=stable_id(rule, group[0].file, group[0].text), dimension=Dimension.SECURITY, severity=severity,
            title=title, detail=detail + "".join(f" {n[:1].upper()}{n[1:]}." for n in notes)
            + (" The same value reaches the Stellar CLI: " + "; ".join(extra) + "." if extra else ""),
            evidence="; ".join(evidence + extra[:2]), evidence_grade=grade,
            remediation=remediation, references=refs, auditor=auditor, confidence=0.85))
    return out


_CACHE: dict[str, tuple[list[Hit], dict]] = {}


def network_hits(files: dict[str, str]) -> tuple[list[Hit], dict]:
    """Every network-binding hit in the code, and the CLI notes folded into fallback hits.
    The security and intent auditors both read it, so it is computed once per code tree."""
    key = sha1("\0".join(f"{k}\0{v}" for k, v in sorted(files.items())).encode("utf-8", "replace")).hexdigest()
    if key not in _CACHE:
        if len(_CACHE) > 16:
            _CACHE.clear()
        sources = _sources(files)
        hits, fallbacks = fallback_hits(sources)
        cli, folded = cli_hits(sources, files, fallbacks)
        hits += per_call_hits(sources) + counterparty_hits(sources) + mismatch_hits(sources) + cross_constant_hits(sources)
        _CACHE[key] = (hits + cli, folded)
    hits, folded = _CACHE[key]
    return list(hits), dict(folded)


def network_findings(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    hits, folded = network_hits(artifact.code_files)
    declared = ((artifact.raw_metadata.get("tmark") or {}).get("declared") or {}).get("agent") or {}
    return _findings(hits, auditor, folded, artifact, sdk=declared.get("kind") == "sdk")
