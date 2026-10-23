"""Soroban contract rules that ask whose authorization a contract checks, and what it covers.

stellar_native's ST-001 only asks whether a mutating entry point calls require_auth at all. An
agent's on-chain limits live in custom-account __check_auth functions and spending policies
(OpenZeppelin `enforce`, passkey-kit `policy__`), and the auth mistakes that lose funds are about
the address: an upgrade authorized by whoever calls it, a token move from an address that never
signed for this call, a role attribute that checks membership but not authorization. These rules
cover those cases. They reuse stellar_native's masker, function splitter and helper resolution;
code-generator templates (.rs.hbs) are rendered by union first, so every branch is judged. It is
bounded lexical evidence, not a compiler.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import EvidenceGrade, Finding, FindingKind, Severity
from .consolidate import stable_id
from .stellar_native import _AUTH, _MUTATION, _rust_code, _rust_functions

#: Handlebars comments, partials and block tags ({{#if}}, {{else}}, {{/each}}). Union rendering
#: blanks them and keeps every branch body.
_TEMPLATE_COMMENT = re.compile(r'\{\{!--[\s\S]*?--\}\}|\{\{![\s\S]*?\}\}')
_TEMPLATE_TAG = re.compile(r'\{\{~?\s*(?:[#/^]\s*[^{}]*|else\b[^{}]*|>[^{}]*)~?\}\}')
#: Any other {{expression}} becomes an identifier of the same length, so offsets and lines hold.
_TEMPLATE_EXPR = re.compile(r'\{\{\{?[^{}]*\}?\}\}')

#: A contract entry-point block. Trait impls export every fn; inherent impls their pub fns.
_IMPL = re.compile(r'#\[\s*contractimpl\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*impl\b([^{;]*)\{')
_STORE_READ = re.compile(r'storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)\s*\.\s*get\b')
_STORE_WRITE = re.compile(r'storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)\s*'
                          r'\.\s*(?:set|remove|update|try_update)\b')
_SELF = re.compile(r'\b(?:env|e|self\.env)\s*\.\s*current_contract_address\s*\(\s*\)')
#: Code-replacing sinks: the deployer's update_current_contract_wasm, soroban-sdk 28's
#: update_current_contract and executable_refs().set (CAP-85 executable references), and the
#: OpenZeppelin upgradeable::upgrade helper, which has no authorization of its own. Matched by
#: method name, whatever the receiver chain.
_SINK = re.compile(r'\.\s*update_current_contract(?:_wasm)?\s*\(|\bexecutable_refs\s*\(\s*\)\s*\.\s*set\s*\(|'
                   r'\bupgradeable\s*::\s*upgrade\s*\(')
#: The OpenZeppelin kill switch, also without authorization of its own.
_PAUSE_SINK = re.compile(r'\bpausable\s*::\s*(?:un)?pause\s*\(')
#: OpenZeppelin attributes that read the owner, admin or role holder and require its auth.
_STRONG_ATTR = re.compile(r'#\[\s*(?:only_owner|only_admin|only_role|only_any_role)\b')
#: OpenZeppelin library guards that read the owner or admin from storage and require its auth.
_STRONG_CALL = re.compile(r'\b(?:enforce_owner_auth|enforce_admin_auth)\s*\(')
_ROLE_ATTR = re.compile(r'#\[\s*(?:has_role|has_any_role)\s*\(\s*([A-Za-z_]\w*)')
_VERIFY = re.compile(r'\.\s*(?:ed25519_verify|secp256r1_verify|secp256k1_recover)\s*\(')
#: Names that say the contract restricts what a key may do: limits, policies, agents, sessions.
_RESTRICTS = re.compile(r'(?i)\b\w*(?:limit|allowance|spend|budget|quota|whitelist|allowlist|policy|agent|session|'
                        r'max_amount|per_tx|per_call)\w*\b|\b(?:cap|Cap)\b|\w+_cap\b|\bcap_\w+')
#: Test code by its path: test.rs, tests.rs, test_*.rs, *_test(s).rs, or anything under test/, tests/
#: or benches/. Its mock contracts are never deployed, so the rules skip it.
_TEST_PATH = re.compile(r'(^|/)(?:tests?|benches)/|(^|/)(?:tests?|test_[^/]*|[^/]*_tests?)\.rs$', re.I)
#: Sample code (examples, demos, fixtures): judged one level lower.
_SAMPLE_PATH = re.compile(r'(^|/)(?:examples?|samples?|fixtures?|demos?)/', re.I)
#: `mod name;` with its attributes. Declared only under #[cfg(test)] (or cfg(any(test, ..))), the
#: module file is test code.
_MOD_DECL = re.compile(r'((?:#\[[^\]]*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;')
#: A whole file compiled only for tests.
_TEST_INNER = re.compile(r'#!\[\s*cfg\s*\(([^\]]*)\)\s*\]')
_TESTUTILS_USE = re.compile(r'\buse\s+soroban_sdk\s*::[^;]*\btestutils\b[^;]*;')
#: A call of a crate function: bare, Self::/self., or through a module path (utils::upgrade).
_CALL_NAME = re.compile(r'(?:\bSelf::|\bself\.|\b(?:[a-z_][a-z0-9_]*\s*::\s*)+|(?<![\w.:!]))([A-Za-z_]\w*)\s*\(')
#: A call through Self::, self., a module or type path, or bare: the called name is group 1.
_PATH_CALL = r'(?:Self::|self\.|(?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*\('
#: A contract client built in place: token::Client::new, TokenClient::new, StellarAssetClient::new.
_CLIENT_NEW = re.compile(r'\b\w*Client\s*(?:::\s*<[^>]*>\s*)?::\s*new\s*\(')
#: Calls that move tokens on a contract client.
_MOVE = re.compile(r'\.\s*(transfer_from|transfer|burn|mint)\s*\(')
#: A state change through a library or type path (OpenZeppelin `Base::mint(e, ..)`).
_PATH_MUTATION = re.compile(r'\b[A-Za-z_]\w*\s*::\s*(?:mint|burn|transfer\w*|approve|set_\w+|update\w*|upgrade|pause|unpause|'
                            r'grant_role|revoke_role|clawback|freeze\w*|withdraw\w*|deposit\w*)\s*\(')
#: soroban-sdk value types: their associated functions convert values and authorize nobody.
_SDK_TYPES = frozenset({'Address', 'MuxedAddress', 'Vec', 'Map', 'Symbol', 'String', 'Bytes', 'BytesN', 'Val', 'Env',
                        'IntoVal', 'TryIntoVal', 'FromVal', 'TryFromVal', 'I256', 'U256', 'Duration', 'Timepoint', 'Hash'})
#: What rejects a call: a panic, an error return, an early return.
_REJECT = re.compile(r'\bpanic|\bErr\s*\(|\breturn\b|\bunreachable\s*!|\bassert')


def _cfg_test(cfg: str) -> bool:
    """A cfg(...) predicate that holds only in test (or test-helper) builds."""
    return bool(re.search(r'\btest\b', cfg)) and not re.search(r'\bnot\s*\(', cfg)


def cfg_test_files(files: dict[str, str], masked: dict[str, str] | None = None) -> set[str]:
    """The Rust files that are test code: by path, by a top-level #![cfg(test)] or an unconditional
    `use soroban_sdk::testutils` (only test builds enable that feature), or because the parent
    module declares them with `#[cfg(test)] mod name;`."""
    masked = masked or {}
    rust = {name: text for name, text in files.items() if name.endswith('.rs')}
    tests = {name for name in rust if _TEST_PATH.search(name)}
    for name, text in rust.items():
        if 'cfg' not in text and 'testutils' not in text:
            continue
        code = masked.get(name) or _rust_code(text)
        if any(_cfg_test(m.group(1)) for m in _TEST_INNER.finditer(code)):
            tests.add(name)
        for m in _TESTUTILS_USE.finditer(code):
            before = code[:m.start()]
            attr = before[max(before.rfind(';'), before.rfind('}'), before.rfind('{')) + 1:]
            if before.count('{') == before.count('}') and not re.search(r'#\[\s*cfg\b', attr):
                tests.add(name)
        stem = name[:-3]
        base = stem.rsplit('/', 1)[0] if stem.rsplit('/', 1)[-1] in {'lib', 'main', 'mod'} else stem
        prefix = (base + '/') if '/' in stem else ('' if stem in {'lib', 'main', 'mod'} else stem + '/')
        gated: dict[str, bool] = {}
        for m in _MOD_DECL.finditer(code):
            test_only = any(_cfg_test(c) for c in re.findall(r'#\[\s*cfg\s*\(([^\]]*)\)\s*\]', m.group(1)))
            # A module declared again for other builds (#[cfg(not(test))] pub(crate) mod x;) is not test-only.
            gated[m.group(2)] = gated.get(m.group(2), True) and test_only
        for module in (prefix + name for name, test_only in gated.items() if test_only):
            tests |= {f for f in rust if f in {module + '.rs', module + '/mod.rs'} or f.startswith(module + '/')}
    return tests


def render_template(text: str) -> str:
    """Union rendering of a Handlebars template: every {{#if}}/{{else}} branch and {{#each}}
    body is kept once, tags are blanked, and {{expr}} becomes a same-length identifier."""
    blank = lambda m: re.sub(r'[^\n]', ' ', m.group())
    text = _TEMPLATE_COMMENT.sub(blank, text)
    text = _TEMPLATE_TAG.sub(blank, text)
    return _TEMPLATE_EXPR.sub(lambda m: ('tpl' + '_' * len(m.group()))[:len(m.group())], text)


def _close(code: str, i: int) -> int:
    """Index just past the bracket that closes the one at ``i``."""
    pairs = {'(': ')', '[': ']', '{': '}'}
    opening, closing, depth = code[i], pairs[code[i]], 0
    for j in range(i, len(code)):
        if code[j] == opening:
            depth += 1
        elif code[j] == closing:
            depth -= 1
            if not depth:
                return j + 1
    return len(code)


def _split(text: str, angle: bool = False) -> list[str]:
    """Top-level comma split; ``angle`` also nests <...> (types, not expressions)."""
    parts, depth, cur = [], 0, []
    opening, closing = '([{<' if angle else '([{', ')]}>' if angle else ')]}'
    for ch in text:
        if ch in opening:
            depth += 1
        elif ch in closing:
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if ''.join(cur).strip():
        parts.append(''.join(cur))
    return [p.strip() for p in parts]


def _args(code: str, open_paren: int) -> list[str]:
    return _split(code[open_paren + 1:_close(code, open_paren) - 1])


def _arg_spans(code: str, open_paren: int) -> list[tuple[int, int]]:
    """(start, end) offsets of each top-level argument of the call whose '(' is at ``open_paren``."""
    spans, depth, start = [], 0, open_paren + 1
    for i in range(open_paren + 1, _close(code, open_paren) - 1):
        if code[i] in '([{':
            depth += 1
        elif code[i] in ')]}':
            depth -= 1
        elif code[i] == ',' and depth == 0:
            spans.append((start, i)); start = i + 1
    spans.append((start, _close(code, open_paren) - 1))
    return spans


def _root(arg: str) -> str:
    """The variable an argument passes: `&x`, `x.clone()`, `&mut x` -> x; else ''."""
    m = re.fullmatch(r'&?\s*(?:mut\s+)?([A-Za-z_]\w*)(?:\s*\.\s*(?:clone|into|to_owned|as_ref)\s*\(\s*\))*', arg.strip())
    return m.group(1) if m else ''


def _aliases(body: str, names: set[str]) -> set[str]:
    """``names`` plus `let p = name[.into()|.clone()|.to_bytes()|.to_array()]` bindings and loop
    variables over them."""
    out = set(names)
    for _ in range(3):
        grew = set()
        for m in re.finditer(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*&?\s*([A-Za-z_]\w*)'
                             r'((?:\s*\.\s*(?:into|clone|to_bytes|to_array|to_owned)\s*\(\s*\))*)\s*;', body):
            if m.group(2) in out:
                grew.add(m.group(1))
        for m in re.finditer(r'\bfor\s+(?:\(([^)]*)\)|([A-Za-z_]\w*))\s+in\s+&?\s*([A-Za-z_]\w*)\b', body):
            if m.group(3) in out:
                grew |= set(re.findall(r'[A-Za-z_]\w*', m.group(1) or m.group(2)))
        if grew <= out:
            break
        out |= grew
    return out


def _uses(text: str, names: set[str]) -> bool:
    return any(re.search(r'(?<![\w.])' + re.escape(n) + r'\b', text) for n in names)


def _receiver(code: str, dot: int) -> str:
    """The receiver chain of the method call whose '.' is at ``dot``: `client`,
    `token::Client::new(&e, &t)`, `TokenUtils::new(&e).events()`."""
    i = dot
    while True:
        j = i
        while j > 0 and code[j - 1].isspace():
            j -= 1
        if j > 0 and code[j - 1] == '?':
            j -= 1
        if j > 0 and code[j - 1] in ')]':
            depth, k = 0, j - 1
            while k >= 0:
                if code[k] in ')]':
                    depth += 1
                elif code[k] in '([':
                    depth -= 1
                    if not depth:
                        break
                k -= 1
            j = max(k, 0)
            while j > 0 and code[j - 1].isspace():
                j -= 1
        k = j
        while k > 0 and (code[k - 1].isalnum() or code[k - 1] == '_'):
            k -= 1
        start = k
        t = k
        while t > 0 and code[t - 1].isspace():
            t -= 1
        if k < j and t > 0 and code[t - 1] == '.':
            i = t - 1
        elif k < j and t > 1 and code[t - 2:t] == '::':
            i = t - 2
        else:
            return code[start:dot]


def _in_loop(body: str, pos: int) -> bool:
    """``pos`` lies inside a for/while/loop body or an iterator closure (for_each, all, map)."""
    for m in re.finditer(r'\b(?:for\b[^{;]*\bin\b|while\b|loop\b)[^{;]*\{|\.\s*(?:for_each|try_for_each|all|any|map)\s*\(', body[:pos]):
        if _close(body, m.end() - 1) > pos:
            return True
    return False


def _fields(body: str) -> dict[tuple[str, str], str]:
    """Fields of local struct literals and the variables they are set from:
    `let req = Req { from: from.clone(), to }` -> {('req', 'from'): 'from', ('req', 'to'): 'to'}."""
    out = {}
    for m in re.finditer(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*[A-Z]\w*(?:\s*::\s*\w+)*\s*\{', body):
        for part in _split(body[m.end():_close(body, m.end() - 1) - 1]):
            fm = re.fullmatch(r'([A-Za-z_]\w*)\s*(?::\s*(.+))?', part, re.S)
            if fm and _root(fm.group(2) or fm.group(1)):
                out[(m.group(1), fm.group(1))] = _root(fm.group(2) or fm.group(1))
    return out


@dataclass
class _Fn:
    file: str
    name: str
    line: int
    start: int
    body_start: int
    body: str
    params: dict
    attrs: str
    entry: bool
    trait: str
    template: bool
    #: The contract type of the enclosing impl block ('' outside one).
    owner: str
    code: str = field(repr=False, default='')
    #: The declared return type ('' for none).
    ret: str = ''

    def line_of(self, offset: int) -> int:
        """Line of an offset into ``body``."""
        return self.code.count('\n', 0, self.body_start + offset) + 1

    def params_of(self, pattern: str) -> list[str]:
        return [p for p, t in self.params.items() if re.search(pattern, t)]


def _params(signature: str) -> dict:
    m = re.search(r'\bfn\s+\w+\s*(?:<[^(]*>)?\s*\(', signature)
    if not m:
        return {}
    out = {}
    for part in _split(signature[m.end():_close(signature, m.end() - 1) - 1], angle=True):
        pm = re.match(r'(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$', part, re.S)
        if pm:
            out[pm.group(1)] = ' '.join(pm.group(2).split())
    return out


def _parse(name: str, source: str, loose: bool, template: bool, code: str) -> list[_Fn]:
    impls = [(m.end() - 1, _close(code, m.end() - 1), m.group(1).strip()) for m in _IMPL.finditer(code)]
    raw = _rust_functions(source, include_private=True, code=code)
    out, enclosing = [], []
    for fn in raw:
        # Bodies nest properly, so the functions still open form a stack.
        while enclosing and enclosing[-1][1] <= fn['start']:
            enclosing.pop()
        nested = bool(enclosing) and enclosing[-1][0] <= fn['start']
        enclosing.append((fn['body_start'], fn['end']))
        block = next((b for b in impls if b[0] < fn['start'] < b[1]), None)
        header = block[2] if block else ''
        trait = header.split(' for ')[0].strip() if ' for ' in header else ''
        entry = not nested and (bool(block) and (fn['public'] or bool(trait)) or (loose and not impls and fn['public']))
        # Attributes and doc comments between the previous item and this fn.
        before = max(code.rfind(c, 0, fn['start']) for c in '{};')
        signature = code[fn['start']:fn['body_start'] - 1]
        ret = re.search(r'\)\s*->\s*([^{]*)$', signature)
        out.append(_Fn(name, fn['name'], fn['line'], fn['start'], fn['body_start'], fn['body'],
                       _params(signature), code[before + 1:fn['start']],
                       entry, trait, template, header.split(' for ')[-1].strip(), code, ret.group(1).strip() if ret else ''))
    return out


class _Crate:
    """Every function of the contract sources, with the helper sets the rules share."""

    def __init__(self, files: dict[str, str], loose: bool, templates: set[str], masked: dict[str, str]):
        self.code = {name: masked.get(name) or _rust_code(text) for name, text in files.items()}
        self.fns = [fn for name, text in files.items() for fn in _parse(name, text, loose, name in templates, self.code[name])]
        self.by_name: dict[str, list[_Fn]] = {}
        for f in self.fns:
            self.by_name.setdefault(f.name, []).append(f)
        self.store = self._names(self._closure(lambda f: bool(_STORE_READ.search(f.body))))
        self.strong = self._closure(lambda f: self._strong_receiver(f.body))
        self.auth = self._closure(lambda f: bool(_AUTH.search(f.body)))
        self.sinks = self._closure(lambda f: bool(_SINK.search(f.body)))
        self.pauses = self._closure(lambda f: bool(_PAUSE_SINK.search(f.body)))
        self.mutates = self._closure(lambda f: bool(_MUTATION.search(f.body) or _PATH_MUTATION.search(f.body)))
        self.constructors = {f.file for f in self.fns if f.name == '__constructor'}

    def _closure(self, direct) -> set[int]:
        """Functions that do something directly or through helpers they call (bounded depth)."""
        found = {id(f) for f in self.fns if direct(f)}
        for _ in range(4):
            grew = {id(f) for f in self.fns if id(f) not in found and self.calls(f, found)}
            if not grew:
                break
            found |= grew
        return found

    def _names(self, ids: set[int]) -> set[str]:
        return {f.name for f in self.fns if id(f) in ids}

    def calls(self, fn: '_Fn', ids: set[int]):
        """The first call in ``fn`` to a crate function in ``ids`` (other than ``fn`` itself)."""
        return next((m for m in _CALL_NAME.finditer(fn.body)
                     if any(id(h) in ids for h in self.resolve(m.group(1), fn.file) if h is not fn)), None)

    def resolve(self, name: str, file: str) -> list[_Fn]:
        """Crate functions a call by this name may reach: the same file's first, else up to two."""
        named = self.by_name.get(name, [])
        return [f for f in named if f.file == file] or named[:2]

    def reach(self, fn: _Fn, depth: int = 3) -> list[_Fn]:
        """Same-crate helpers called from ``fn``, a few hops deep."""
        seen, frontier, out = {id(fn)}, [fn], []
        for _ in range(depth):
            nxt = []
            for f in frontier:
                for name in set(_CALL_NAME.findall(f.body)):
                    for h in self.resolve(name, f.file):
                        if id(h) not in seen:
                            seen.add(id(h)); nxt.append(h); out.append(h)
            frontier = nxt
        return out

    def bound(self, fn: _Fn, names: set[str]) -> list[tuple[_Fn, set[str]]]:
        """Helpers (one hop) that receive one of ``names``, with the parameters they receive it as."""
        out = []
        for m in _CALL_NAME.finditer(fn.body):
            args = _args(fn.body, m.end() - 1)
            for h in self.resolve(m.group(1), fn.file):
                if h is fn:
                    continue
                params = list(h.params)
                if params and params[0] in {'self'}:
                    params = params[1:]
                got = {params[i] for i, a in enumerate(args) if i < len(params) and _root(a) in names}
                if got:
                    out.append((h, got))
        return out

    def _strong_receiver(self, body: str) -> bool:
        """require_auth on the contract itself, on a stored address, or on a store helper's result."""
        for m in re.finditer(r'\.\s*require_auth(?:_for_args)?\s*\(', body):
            stmt = body[max(body.rfind(';', 0, m.start()), body.rfind('{', 0, m.start()), body.rfind('}', 0, m.start())) + 1:m.start()]
            if _SELF.search(stmt) or _STORE_READ.search(stmt):
                return True
            # read_admin(&e), Self::admin(&e), storage::get_admin(&e), AdminStore::get(&e)
            call = re.search(r'(?:\bSelf::|\bself\.|\b(?:[A-Za-z_]\w*\s*::\s*)+|(?<![\w.:]))([A-Za-z_]\w*)\s*\([^;]*$', stmt)
            if call and call.group(1) in self.store:
                return True
            root = re.match(r'\s*\(?\s*&?\s*([A-Za-z_]\w*)', stmt)
            if root and self._stored(body, root.group(1)):
                return True
        return False

    def _stored(self, body: str, var: str) -> bool:
        """``var`` is bound to a storage read, a store helper's result or the contract address."""
        for m in re.finditer(r'\b(?:let\s+(?:mut\s+)?|if\s+let\s+Some\s*\(\s*)' + re.escape(var) + r'\b[^;=]*=\s*([^;]*)', body):
            expr = m.group(1)
            if _STORE_READ.search(expr) or _SELF.search(expr):
                return True
            call = re.match(r'\s*&?\s*' + _PATH_CALL, expr)
            if call and call.group(1) in self.store:
                return True
        return False


class SorobanRules:
    """Runs every rule over the contract sources of one audit."""

    def __init__(self, auditor, files: dict[str, str], *, loose: bool = False, templates: set[str] = frozenset(),
                 limits_declared: bool = False, masked: dict[str, str] | None = None,
                 context: dict[str, str] | None = None):
        """``context`` is every file of the audit (for the modules that declare test files)."""
        self.auditor = auditor
        masked = masked or {}
        #: Test code (mock contracts) is never deployed: no rule judges it, and its helpers do
        #: not stand in for the contract's.
        self.tests = cfg_test_files({**(context or {}), **files}, masked)
        self.crate = _Crate({n: t for n, t in files.items() if n not in self.tests}, loose, set(templates), masked)
        self.limits_declared = limits_declared
        self.findings: list[Finding] = []
        #: (file, fn) judged here; ST-001 does not report them again.
        self.claimed: set[tuple[str, str]] = set()
        #: Initializers anyone can call again: stellar_native folds them into soroban-auth-missing.
        self.reinit: list[_Fn] = []
        #: Accounts that hand __check_auth to a library: input for the advisory version check.
        self.library_auth: list[str] = []

    # ------------------------------------------------------------------ helpers
    def _emit(self, rule: str, severity: Severity, title: str, detail: str, fn: _Fn, offset: int | None, snippet: str,
              remediation: str, *, grade: EvidenceGrade = EvidenceGrade.CONFIRMED, gap: bool = False,
              confidence: float = 0.85, claim: bool = True) -> None:
        """Add a finding; ``claim`` (an authorization finding) keeps ST-001 from reporting the
        function again."""
        if _SAMPLE_PATH.search(fn.file):
            severity = severity.downgrade(1)
        if fn.template:
            detail += " The file is a code-generator template, so this holds for every generated contract."
        line = fn.line if offset is None else fn.line_of(offset)
        finding = self.auditor.finding(
            stable_id(rule, fn.file, f"{fn.name}: {snippet}"), severity, title, detail,
            evidence=f"{fn.file}:{line} {fn.name}: {' '.join(snippet.split())[:160]}",
            remediation=remediation, grade=grade, confidence=confidence)
        self.findings.append(finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP}) if gap else finding)
        if claim:
            self.claimed.add((fn.file, fn.name))

    def _authed(self, fn: _Fn, names: set[str]) -> bool:
        """require_auth[_for_args] on one of ``names`` (or on a local struct's field set from one),
        directly or in a helper that receives it, or ``names`` handed to code outside the crate (a
        library that may authorize it)."""
        body = fn.body
        if any(re.search(r'(?<![\w.])' + re.escape(n) + r'\s*\.\s*require_auth(?:_for_args)?\s*\(', body) for n in names):
            return True
        if any(root in names and re.search(r'(?<![\w.])' + re.escape(var) + r'\s*\.\s*' + re.escape(f) +
                                           r'\s*\.\s*require_auth(?:_for_args)?\s*\(', body)
               for (var, f), root in _fields(body).items()):
            return True
        for m in re.finditer(r'(?:\b[A-Za-z_]\w*\s*::\s*)*([A-Za-z_]\w*)\s*\(', body):
            args = _args(body, m.end() - 1)
            if not any(_root(a) in names for a in args):
                continue
            if re.search(r'\b[a-z_][a-z0-9_]*\s*::\s*[a-z_]\w*\s*\($', m.group(0)):
                return True  # a module function such as spending_limit::enforce(..., &smart_account)
            # Type::f reaches the crate only through an impl of that type (or Self).
            typed = re.search(r'\b([A-Z]\w*)\s*::\s*([a-z_]\w*)\s*\($', m.group(0))
            helpers = [h for h in self.crate.resolve(m.group(1), fn.file) if h is not fn
                       and (not typed or typed.group(1) in {'Self', h.owner})]
            if any(id(h) in self.crate.auth for h in helpers):
                return True
            if typed and not helpers and typed.group(2) != 'new' and typed.group(1) not in _SDK_TYPES | {'Self'}:
                return True  # a library type such as OpenZeppelin's Base::burn(e, &from, ..), which authorizes
        return False

    def _scope(self, fn: _Fn) -> list[_Fn]:
        return [fn] + self.crate.reach(fn)

    def _token_client(self, fn: _Fn, receiver: str, depth: int = 0) -> bool:
        """``receiver`` is a contract client (token::Client::new(..), a variable or parameter
        holding one, a crate helper that returns one), not an event publisher such as
        soroban-token-sdk's `TokenUtils::new(&e).events()`."""
        if re.search(r'\bevents\s*\(\s*\)', receiver) or depth > 3:
            return False
        if _CLIENT_NEW.search(receiver):
            return True
        head = re.match(r'\s*\(?\s*&?\s*(?:mut\s+)?(?:Self::|self\.|(?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*(\()?', receiver)
        if not head:
            return False
        name = head.group(1)
        if head.group(2):
            return any('Client' in h.ret for h in self.crate.resolve(name, fn.file))
        if 'Client' in fn.params.get(name, ''):
            return True
        return any((m.group(1) and 'Client' in m.group(1)) or self._token_client(fn, m.group(2), depth + 1)
                   for m in re.finditer(r'\blet\s+(?:mut\s+)?' + re.escape(name) + r'\b\s*(?::\s*([^=;]+))?=\s*([^;]+);', fn.body))

    def _moves(self, fn: _Fn, methods: str = 'transfer_from|transfer|burn|mint') -> list[re.Match]:
        """Token-moving calls on a contract client in ``fn``'s body."""
        return [m for m in _MOVE.finditer(fn.body)
                if re.fullmatch(methods, m.group(1)) and self._token_client(fn, _receiver(fn.body, m.start()))]

    def _weak(self, fn: _Fn) -> bool:
        """Authorization that may be the administrator's but is not shown to be: an auth helper, an
        unknown admin/owner/role attribute, a caller parameter handed to a role, ownership or
        store lookup, or a caller parameter compared with a stored address."""
        callers = {p for p, t in fn.params.items() if not re.search(r'\bEnv\b', t) and p != 'self'}
        lookups = (r'(?:\b\w*(?:access_control|ownable|role)\w*\s*::\s*\w+|'
                   r'(?:Self::|self\.|\b(?:[A-Za-z_]\w*\s*::\s*)*)(?:' + '|'.join(map(re.escape, self.crate.store or {'_'})) + r'))\s*\(')
        return bool(self.crate.calls(fn, self.crate.auth) or re.search(r'#\[\s*\w*(?:admin|owner|auth|role)\w*', fn.attrs)
                    or any(_root(a) in callers for m in re.finditer(lookups, fn.body) for a in _args(fn.body, m.end() - 1))
                    or self._compared_with_stored(fn.body, callers))

    # ------------------------------------------------------------------ run
    def run(self) -> 'SorobanRules':
        for fn in self.crate.fns:
            if fn.name == '__check_auth' and len(fn.params) >= 4:
                self._check_auth(fn)
            elif fn.name == 'enforce' and ('Policy' in fn.trait or {'smart_account', 'authenticated_signers'} <= set(fn.params)):
                self._enforce(fn)
            elif fn.name == 'policy__' and len(fn.params) >= 4:
                self._policy(fn)
        # The constructor runs once, at deployment, with arguments the deployer chooses.
        for fn in [f for f in self.crate.fns if f.entry and f.name not in {'__check_auth', 'enforce', 'policy__', '__constructor'}]:
            self._upgrade(fn)
            self._roles(fn)
            self._token_moves(fn)
            self._auth_args(fn)
            self._amount_checks(fn)
            self._replay(fn)
            self._initializer(fn)
        return self

    # ------------------------------------------------------------ custom accounts
    def _check_auth(self, fn: _Fn) -> None:
        params = list(fn.params)
        payload, signature, contexts = params[1], params[2], params[3]
        scope = self._scope(fn)
        text = '\n'.join(f.body for f in scope)
        self.claimed.add((fn.file, fn.name))
        if re.search(r'\bdo_check_auth\s*\(', text):
            self.library_auth.append(f"{fn.file}:{fn.line}")
            return
        delegated = re.search(r'\bdelegate_(?:account_)?auth\s*\(', text)
        payload_read = _uses(fn.body, _aliases(fn.body, {payload}))
        signer_names = _aliases(fn.body, {signature})
        auths = [m for m in re.finditer(r'([A-Za-z_]\w*)(?:\s*\.\s*\w+)*\s*\.\s*require_auth(?:_for_args)?\s*\(', text)
                 if m.group(1) not in signer_names]
        if not payload_read and not auths and not delegated:
            self._emit("soroban-check-auth-unauthenticated", Severity.CRITICAL,
                       "The custom account's __check_auth authenticates nobody",
                       "__check_auth never reads the signature payload, verifies no signature over it, calls no "
                       "verifier, requires no stored address's authorization and delegates to no signer. Whatever "
                       "it checks about the call, anyone can authorize as this account and move what it holds.",
                       fn, None, f"fn __check_auth({payload}, {signature}, {contexts})",
                       "Verify a signature over signature_payload with a stored key (ed25519_verify or "
                       "secp256r1_verify), or require_auth a stored signer address, before approving any context.")
            return
        context_names = _aliases(fn.body, {contexts})
        # Contexts handed to a helper count as read only when the helper reads its parameter.
        handed = [(a, b) for m in _CALL_NAME.finditer(fn.body) if self.crate.resolve(m.group(1), fn.file)
                  for a, b in _arg_spans(fn.body, m.end() - 1) if _root(fn.body[a:b]) in context_names]
        direct = ''.join(' ' if any(a <= i < b for a, b in handed) else ch for i, ch in enumerate(fn.body))
        read = _uses(direct, context_names) or any(_uses(h.body, _aliases(h.body, got))
                                                    for h, got in self.crate.bound(fn, context_names))
        if not read and not delegated and _RESTRICTS.search(re.sub(r'#\[[^\]]*\]', '', self.crate.code[fn.file])):
            self._emit("soroban-check-auth-contexts-ignored", Severity.HIGH,
                       "__check_auth approves every call the key signs: the auth contexts are never read",
                       "The account names limits or a scoped key, but __check_auth never looks at the contexts it is "
                       "authorizing (which contract, which function, which arguments). A valid signature therefore "
                       "authorizes any transfer, approve or admin call, so the limits this account suggests are not "
                       "enforced on chain.",
                       fn, None, f"fn __check_auth(.., {contexts})",
                       "Iterate over auth_contexts and allow only the contracts, functions and amounts the key is "
                       "meant for; reject every other context.")
        self._deny_list(fn, scope)
        self._self_admin(fn, scope)
        self._caps(fn, scope, policy=False)

    def _deny_list(self, fn: _Fn, scope: list[_Fn]) -> None:
        """C3: unmatched contracts or functions fall through to approval, and nothing else in the
        check rejects them."""
        text = '\n'.join(f.body for f in scope)
        rejects = re.search(r'\b(?:fn_name|contract)\s*!=[^{;]*\{[^{}]*(?:\bErr\s*\(|panic)|'
                            r'!\s*[\w.]+\s*\.\s*contains\s*\([^)]*\b(?:fn_name|contract)\b[^{;]*\{[^{}]*(?:\bErr\s*\(|panic)', text)
        for m in re.finditer(r'\bmatch\s+([^{;]*)\{', text):
            if re.search(r'\b(?:fn_name|contract)\b', m.group(1)) and re.search(
                    r'(?:^|[,}\s])_\s*=>\s*\{?\s*(?:return\s+)?(?:Err\s*\(|panic)', text[m.end() - 1:_close(text, m.end() - 1)]):
                rejects = True
        if rejects:
            return
        for f in scope:
            body = f.body
            for m in re.finditer(r'\bif\s+([^{;]*\b(?:fn_name|contract)\s*!=[^{;]*)\{', body):
                block = body[m.end() - 1:_close(body, m.end() - 1)]
                if re.search(r'\bcontinue\b|\breturn\s+Ok\s*\(\s*\(\s*\)\s*\)', block) and not re.search(r'\bErr\s*\(|panic', block):
                    self._deny(fn, f, m.start(), m.group(0))
                    return
            for m in re.finditer(r'\bmatch\s+([^{;]*)\{', body):
                if not re.search(r'\b(?:fn_name|contract)\b', m.group(1)) or re.search(r'\bContext\b', m.group(1)):
                    continue
                block = body[m.end() - 1:_close(body, m.end() - 1)]
                arm = re.search(r'(?:^|[,}\s])_\s*=>\s*(\{\s*\}|\(\s*\)|continue\b|(?:return\s+)?Ok\s*\(\s*\(\s*\)\s*\))', block)
                if arm:
                    self._deny(fn, f, m.start(), m.group(0) + ' .. ' + arm.group(0))
                    return

    def _deny(self, fn: _Fn, where: _Fn, offset: int, snippet: str) -> None:
        self._emit("soroban-check-auth-deny-list", Severity.HIGH,
                   "The account approves every contract or function it does not list",
                   "Inside the check over the auth contexts, a context whose contract or function is not one of the "
                   "listed ones is approved (continue, Ok, or an empty `_ =>` arm) instead of rejected. Any call the "
                   "list does not anticipate, such as a vault withdraw or a router swap that moves this account's "
                   "funds, is authorized by the key alone. This is the deny-list shape of the soroban-examples "
                   "account.",
                   where, offset, snippet,
                   "Allow-list instead: approve only the contracts and functions the key is meant for, and return an "
                   "error for every other context.",
                   grade=EvidenceGrade.CONFIRMED if where is fn else EvidenceGrade.INFERRED)

    def _self_admin(self, fn: _Fn, scope: list[_Fn]) -> None:
        """C7: a call to the account itself (its own limit setters) passes on the spending key."""
        own = [f for f in self.crate.fns if f.file == fn.file and f.entry
               and re.search(_SELF.pattern + r'\s*\.\s*require_auth', f.body) and _STORE_WRITE.search(f.body)]
        if not own or len(_VERIFY.findall(fn.body)) > 1 or re.search(r'(?i)threshold|all_signed|weight|signers', fn.body):
            return
        # Signatures verified in a loop: several keys sign, not one spending key.
        if any(_in_loop(f.body, v.start()) for f in scope for v in _VERIFY.finditer(f.body)):
            return
        if not re.search(r'\btransfer\b|\bamount\b', '\n'.join(f.body for f in scope)):
            return  # nothing is spent on this path, so there is no limit to rewrite
        params = list(fn.params)
        signed = _aliases(fn.body, {params[1], params[2]})
        selfs = _aliases(fn.body, set(re.findall(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*' + _SELF.pattern, fn.body)))
        for f in scope:
            names = selfs if f is fn else {p for h, got in self.crate.bound(fn, selfs) if h is f for p in got} | selfs
            selves = '|'.join([_SELF.pattern] + [re.escape(n) for n in names])
            pattern = (r'\b(?:\w+\s*\.\s*)?contract\s*==\s*&?\s*(?:' + selves + r')(?!\w)|'
                       r'(?:' + selves + r')\s*==\s*&?\s*(?:\w+\s*\.\s*)?contract\b')
            for m in re.finditer(pattern, f.body):
                end = f.body.find('{', m.end())
                if end < 0:
                    continue
                block = f.body[end:_close(f.body, end)]
                # A self-call branch that checks another signature or address is not the spending key alone.
                extra = (re.search(r'(?i)signer|threshold|verify|admin|guardian|require_auth', block)
                         or _uses(block, signed | {p for h, got in self.crate.bound(fn, signed) if h is f for p in got}))
                if re.search(r'\bOk\s*\(\s*\(\s*\)\s*\)', block) and not extra:
                    severity = Severity.HIGH if self.limits_declared else Severity.MEDIUM
                    self._emit("soroban-account-self-admin", severity,
                               "The key that spends can also rewrite the account's limits",
                               "__check_auth accepts a call to the account itself (" + ", ".join(sorted({o.name for o in own})) +
                               ") on the same single signature that authorizes payments. Whoever holds that key, "
                               "including an agent driven by a prompt injection, can raise its own cap or add a "
                               "recipient and then spend under the new limit."
                               + (" The .tmark declares spending limits, which this makes the agent able to change." if self.limits_declared else ""),
                               f, m.start(), m.group(0),
                               "Require a separate administrator signature (or a timelock) for calls to the account's own "
                               "configuration functions, distinct from the key that authorizes spending.",
                               grade=EvidenceGrade.CONFIRMED if f is fn else EvidenceGrade.INFERRED)
                    return

    def _caps(self, fn: _Fn, scope: list[_Fn], policy: bool) -> None:
        """C6 and C8: an amount cap per call, without a running total or without a lower bound."""
        text = '\n'.join(f.body for f in scope)
        if not re.search(r'\bargs\b', text):
            return
        cap = None
        for f in scope:
            cap = re.search(r'\b(\w*amount\w*)\s*>=?\s*(?!-?[01]\b)[\w.]+|\b(?!-?[01]\b)[\w.]+\s*<=?\s*(\w*amount\w*)\b', f.body)
            if cap:
                where = f
                break
        if not cap:
            return
        var = cap.group(1) or cap.group(2)
        accumulates = re.search(r'\+=\s*&?\s*\w*amount\w*\b|\b\w*amount\w*\s*\+(?![+=])|\+\s*&?\s*\w*amount\w*\b|'
                                r'(?:checked|saturating|wrapping)_add\s*\(\s*&?\s*\w*amount', text)
        grade = EvidenceGrade.CONFIRMED if where is fn else EvidenceGrade.INFERRED
        if accumulates:
            lower = re.search(r'\b\w*amount\w*\s*(?:<=?)\s*0\b|\b0\s*>=?\s*\w*amount|\b\w*amount\w*\s*>=?\s*[01]\b|'
                              r'\b[01]\s*<=?\s*\w*amount|is_negative|is_positive|LessThanZero', text)
            if not lower and _STORE_WRITE.search(text):
                self._emit("soroban-policy-negative-amount", Severity.MEDIUM,
                           "A negative amount lowers the running spend total",
                           "The amount taken from the authorized call's arguments is checked only against an upper bound "
                           "and then added to a stored running total. A context with a negative amount (any contract's "
                           "`transfer` that accepts one) reduces the total, so later transfers can exceed the limit.",
                           where, cap.start(), cap.group(0),
                           "Reject amounts below zero (and zero) before adding them to the running total.", grade=grade)
            return
        severity = Severity.MEDIUM if policy else Severity.LOW
        self._emit("soroban-policy-per-call-cap", severity,
                   "The on-chain amount limit is per call, with no running total",
                   f"The {'policy' if policy else '__check_auth'} compares `{var}` from the authorized call against a "
                   "cap, but keeps no stored total of what was spent. Repeating capped calls (or several contexts in "
                   "one transaction) moves any amount, so the cap bounds one transfer, not the agent's spending.",
                   where, cap.start(), cap.group(0),
                   "Keep a persistent per-window total (read, add, compare, write) and check the cap against it.",
                   grade=grade)

    def _enforce(self, fn: _Fn) -> None:
        """C4 and C5 for OpenZeppelin smart-account policies."""
        self.claimed.add((fn.file, fn.name))
        account = next((p for p in fn.params if 'account' in p and 'Address' in fn.params[p]), None)
        signers = next((p for p in fn.params if 'signers' in p), None)
        scope = self._scope(fn)
        if account and not self._authed(fn, _aliases(fn.body, {account})):
            writes = any(_STORE_WRITE.search(f.body) for f in scope)
            self._emit("soroban-policy-enforce-unauthorized", Severity.HIGH,
                       "The policy's enforce runs without the smart account's authorization",
                       "enforce never calls smart_account.require_auth(). OpenZeppelin's Policy contract requires it: "
                       "without it anyone can call enforce directly for any account"
                       + (" and change the policy's stored state (spent totals, windows)" if writes else "")
                       + ", so the policy's limits can be used up or reset by a third party.",
                       fn, None, f"fn enforce(.., {account})",
                       "Call smart_account.require_auth() at the start of enforce.")
        if signers and not _uses(fn.body, _aliases(fn.body, {signers})) and not any(
                _uses(h.body, got) for h, got in self.crate.bound(fn, {signers})):
            self._emit("soroban-policy-signers-unread", Severity.MEDIUM,
                       "The policy approves without looking at which signers authenticated",
                       "enforce never reads authenticated_signers. A context rule may consist of a policy alone, and "
                       "then this policy approves the call with no signature at all.",
                       fn, None, f"fn enforce(.., {signers}, ..)",
                       "Reject the call when authenticated_signers is empty, or check the signers the rule requires.",
                       confidence=0.75)
        self._caps(fn, scope, policy=True)

    def _policy(self, fn: _Fn) -> None:
        """C5 for passkey-kit policies (policy__)."""
        self.claimed.add((fn.file, fn.name))
        source = list(fn.params)[1]
        scope = self._scope(fn)
        write = next(((f, m) for f in scope for m in [_STORE_WRITE.search(f.body)] if m), None)
        if write and not self._authed(fn, _aliases(fn.body, {source})):
            where, m = write
            self._emit("soroban-policy-state-unauthorized", Severity.MEDIUM,
                       "Anyone can call the policy and change its stored state",
                       "policy__ writes storage but never calls require_auth on the wallet that invokes it "
                       f"(`{source}`). Anyone can call it directly with any signer key and contexts, so stored state "
                       "such as the last-use ledger of a rate limit can be bumped by a third party, locking the "
                       "wallet's signer out.",
                       where, m.start(), where.body[m.start():where.body.find(';', m.start())],
                       f"Call {source.lstrip('_')}.require_auth() first, as passkey-kit's sample policy does; the "
                       "wallet satisfies it during __check_auth.",
                       grade=EvidenceGrade.CONFIRMED if where is fn else EvidenceGrade.INFERRED)
        self._deny_list(fn, scope)
        self._caps(fn, scope, policy=True)

    # ------------------------------------------------------------ upgrades and pause
    def _upgrade(self, fn: _Fn) -> None:
        body = fn.body
        sink = _SINK.search(body) or _PAUSE_SINK.search(body)
        via = None
        if not sink:
            via = self.crate.calls(fn, self.crate.sinks) or self.crate.calls(fn, self.crate.pauses)
            if not via:
                return
        pause = (sink and _PAUSE_SINK.match(body, sink.start()) is not None) or (via and not self.crate.calls(fn, self.crate.sinks))
        self.claimed.add((fn.file, fn.name))
        if self._strong(fn) or _ROLE_ATTR.search(fn.attrs):
            return  # a bare has_role attribute is reported by _roles
        params = set(fn.params)
        receivers = {m.group(1) for m in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)(?:\s*\.\s*\w+)*\s*\.\s*require_auth(?:_for_args)?\s*\(', body)}
        weak = self._weak(fn)
        offset = (sink or via).start()
        snippet = body[offset:body.find(';', offset) if body.find(';', offset) > 0 else offset + 80]
        grade = EvidenceGrade.CONFIRMED if sink else EvidenceGrade.INFERRED
        if receivers and receivers <= params:
            # The only authorization is the caller's own: unless the parameter decides something
            # else, anyone passes their own address and signs.
            rest = body
            for n in receivers:
                rest = re.sub(r'(?<![\w.])' + re.escape(n) + r'\s*\.\s*require_auth(?:_for_args)?\s*\([^;]*;', '', rest)
            rest = re.sub(r'[^;{}]*(?:' + _SINK.pattern + '|' + _PAUSE_SINK.pattern + r')[^;]*;', '', rest)
            rest = re.sub(r'[^;{}]*(?:\.publish\s*\(|events\s*\(\s*\))[^;]*;', '', rest)
            if not _uses(rest, set().union(*(_aliases(body, {n}) for n in receivers))) and not weak:
                receivers = set()
            else:
                weak = True
        if receivers and not (receivers <= params):
            weak = True
        if weak:
            self._emit("soroban-upgrade-weak-guard", Severity.MEDIUM,
                       "Who may " + ("pause" if pause else "replace the contract code") + " is not established",
                       "This entry point " + ("pauses or unpauses the contract" if pause else "replaces the contract's code") +
                       ". Its authorization goes through a helper, a role or ownership lookup, or a comparison of a "
                       "caller parameter, but no require_auth on a stored administrator (or an OpenZeppelin only_* "
                       "attribute) was found. Confirm that only the administrator can reach it.",
                       fn, offset, snippet,
                       "Require the stored administrator's (or owner's) authorization in this function, for example "
                       "with #[only_owner] or read_admin(&env).require_auth().", grade=EvidenceGrade.INFERRED, gap=True,
                       confidence=0.7)
            return
        if pause:
            self._emit("soroban-upgrade-pause-unguarded", Severity.HIGH,
                       "Anyone can pause or unpause the contract",
                       "This entry point reaches the pause switch with no authorization of a stored administrator. "
                       "Anyone can freeze the contract's operations, or lift a pause an administrator set during an "
                       "incident.",
                       fn, offset, snippet,
                       "Gate pause and unpause behind the stored owner, for example with #[only_owner].", grade=grade)
            return
        self._emit("soroban-upgrade-unguarded", Severity.CRITICAL,
                   "Anyone can replace the contract's code",
                   "This entry point replaces the contract's executable (or repoints an executable reference other "
                   "contracts run) and requires no stored administrator's authorization; at most it requires the "
                   "authorization of an address the caller chooses. Anyone can install code that transfers out "
                   "every balance the contract holds.",
                   fn, offset, snippet,
                   "Require the stored administrator's authorization before the upgrade (read_admin(&env).require_auth() "
                   "or #[only_owner]), and prefer a timelock or multisig administrator.", grade=grade)

    def _compared_with_stored(self, body: str, params: set[str]) -> bool:
        """A parameter is compared (==, !=, assert_eq!, assert_ne!) with a stored address."""
        def stored(expr: str) -> bool:
            call = re.match(r'\s*&?\s*' + _PATH_CALL, expr)
            root = _root(expr)
            return bool(_STORE_READ.search(expr) or (call and call.group(1) in self.crate.store)
                        or (root and self.crate._stored(body, root)))
        pairs = [(m.group(1), m.group(2)) for m in re.finditer(r'([&\w.:()]+?)\s*[!=]=\s*([&\w.:()]+)', body)]
        pairs += [tuple(_split(body[m.end():_close(body, m.end() - 1) - 1])[:2]) for m in re.finditer(r'assert_(?:eq|ne)!\s*\(', body)]
        return any(len(pair) == 2 and ((_root(a) in params and stored(b)) or (_root(b) in params and stored(a)))
                   for pair in pairs for a, b in [pair])

    def _strong(self, fn: _Fn) -> bool:
        if fn.name == '__constructor' or _STRONG_ATTR.search(fn.attrs) or _STRONG_CALL.search(fn.body):
            return True
        if self.crate._strong_receiver(fn.body) or self.crate.calls(fn, self.crate.strong):
            return True
        # A caller that authorizes and is checked against the stored owner is the owner.
        if any(self._compared_with_stored(fn.body, {p}) and self._authed(fn, _aliases(fn.body, {p})) for p in fn.params):
            return True
        # #[has_role(p, ..)] plus p.require_auth() is what #[only_role] expands to.
        role = _ROLE_ATTR.search(fn.attrs)
        return bool(role and self._authed(fn, {role.group(1)}))

    # ------------------------------------------------------------ roles, token moves, auth args
    def _roles(self, fn: _Fn) -> None:
        role = _ROLE_ATTR.search(fn.attrs)
        if not role or self._authed(fn, _aliases(fn.body, {role.group(1)})):
            return
        if not (_MUTATION.search(fn.body) or _PATH_MUTATION.search(fn.body) or _SINK.search(fn.body)
                or _PAUSE_SINK.search(fn.body) or self.crate.calls(fn, self.crate.mutates)):
            return
        self._emit("soroban-role-without-auth", Severity.HIGH,
                   "A role attribute checks membership but nobody's authorization",
                   f"#[has_role]/#[has_any_role] only checks that `{role.group(1)}` holds the role; it does not call "
                   "require_auth (OpenZeppelin documents this). The function never authorizes that address either, "
                   "so anyone can pass a role holder's address and act as them.",
                   fn, None, role.group(0).lstrip('#['),
                   f"Use #[only_role] instead, or call {role.group(1)}.require_auth() in the body.")

    def _token_moves(self, fn: _Fn) -> None:
        """A and P: tokens moved, through a token client, from an address that never authorized
        this call. The function fails unless every require_auth in it is satisfied, so an
        authorization anywhere in the body binds the address."""
        body = fn.body
        addresses = [p for p in fn.params_of(r'(?<!Muxed)\bAddress\b')]
        if not addresses:
            return
        selfs = _aliases(body, set(re.findall(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*' + _SELF.pattern, body)))
        moves = self._moves(fn)
        for m in moves:
            if m.group(1) == 'mint':
                continue
            args = _args(body, m.end() - 1)
            pull = m.group(1) == 'transfer_from'
            if len(args) < (4 if pull else 2):
                continue
            src = _root(args[1] if pull else args[0])
            owner = next((p for p in addresses if src in _aliases(body, {p})), None)
            if not owner or src in selfs or self._authed(fn, _aliases(body, {owner})):
                continue
            snippet = body[m.start():_close(body, m.end() - 1)]
            if pull:
                spender_self = _SELF.search(args[0]) or _root(args[0]) in selfs
                dest = _root(args[2])
                dest_param = next((p for p in addresses if dest in _aliases(body, {p})), None)
                if not spender_self or not dest_param or dest_param == owner:
                    continue  # a spender's own allowance is the token's business
                self._pull(fn, m, snippet, owner, dest_param)
                continue
            # Someone else's authorization drives the debit, or the call records or credits
            # something the token authorization does not cover: high. A bare pass-through to the
            # token is bound by the token's own authorization of every argument it uses: low.
            fields = _fields(body)
            owners = _aliases(body, {owner})
            others = []
            for a in re.finditer(r'\.\s*require_auth(?:_for_args)?\s*\(', body):
                chain = _receiver(body, a.start())
                head = re.match(r'\s*\(?\s*&?\s*([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?', chain)
                if head and fields.get((head.group(1), head.group(2) or '')) not in owners and head.group(1) not in owners:
                    others.append(head.group(1))
            severity = (Severity.HIGH if others or self._strong(fn) or _STORE_WRITE.search(body) or len(moves) > 1
                        else Severity.LOW)
            self._emit("soroban-token-move-unbound", severity,
                       "Tokens are moved from an address that did not authorize this call",
                       f"The function calls {m.group(1)} with `{owner}` as the source but never calls "
                       f"{owner}.require_auth(). The token then asks `{owner}` to authorize only the bare token call, "
                       + ("detached from this function's other arguments: a signed token authorization can be "
                          "replayed through this entry point with a different beneficiary or terms, and nothing here "
                          f"binds `{owner}` to them." if severity is Severity.HIGH else
                          "so this entry point's own arguments are unsigned. It only passes the call through, and the "
                          "token's authorization still covers the recipient and amount it moves."),
                       fn, m.start(), snippet,
                       f"Call {owner}.require_auth() (or require_auth_for_args over the arguments that matter) before "
                       "moving its tokens.")
            return

    def _pull(self, fn: _Fn, m: re.Match, snippet: str, owner: str, dest: str) -> None:
        """P: transfer_from with this contract as the spender, from and to chosen by the caller."""
        if self._strong(fn):
            # Only the stored operator can pull: a trust assumption, not an open drain.
            self._emit("soroban-operator-pull", Severity.MEDIUM,
                       "The operator can pull any approved balance to any address",
                       f"transfer_from moves tokens from `{owner}` to `{dest}`, both chosen by the caller, with this "
                       f"contract as the spender. Only the stored operator (administrator) can call it, but `{owner}` "
                       "does not authorize the individual pull: whoever holds the operator key, including an agent "
                       "driven by a prompt injection, can move every approved balance to any address, up to each "
                       "allowance.",
                       fn, m.start(), snippet,
                       f"Bind each pull to the payer ({owner}.require_auth(), or a stored subscription that fixes the "
                       "destination and amount), and keep allowances small and short-lived.", confidence=0.8)
            return
        if _ROLE_ATTR.search(fn.attrs):
            return  # a role attribute without authorization is reported by _roles
        if self._weak(fn):
            self._emit("soroban-token-move-allowance", Severity.MEDIUM,
                       "Who may spend the allowances users gave this contract is not established",
                       f"transfer_from moves tokens from `{owner}` to `{dest}`, both chosen by the caller, with this "
                       f"contract as the spender, and `{owner}` never authorizes the call. The caller's authorization "
                       "goes through a helper, a role or ownership lookup, or a comparison, but no require_auth on a "
                       "stored operator was found. If anyone can reach it, anyone can drain every account that "
                       "approved this contract.",
                       fn, m.start(), snippet,
                       f"Call {owner}.require_auth() before transfer_from, or require the stored operator's "
                       "authorization in this function.", grade=EvidenceGrade.INFERRED, gap=True, confidence=0.7)
            return
        handed = any(_root(a) in _aliases(fn.body, {owner})
                     for c in _CALL_NAME.finditer(fn.body) if self.crate.resolve(c.group(1), fn.file)
                     for a in _args(fn.body, c.end() - 1))
        self._emit("soroban-token-move-allowance", Severity.CRITICAL,
                   "Anyone can spend the allowances users gave this contract",
                   f"transfer_from moves tokens from `{owner}` to `{dest}`, both chosen by the caller, "
                   f"with this contract as the spender, and `{owner}` never authorizes the call. Anyone can "
                   "drain every account that approved this contract to an address of their choice.",
                   fn, m.start(), snippet,
                   f"Call {owner}.require_auth() before transfer_from, or take the source from storage.",
                   gap=handed, grade=EvidenceGrade.INFERRED if handed else EvidenceGrade.CONFIRMED)

    def _auth_args(self, fn: _Fn) -> None:
        """D: require_auth_for_args that leaves out the recipient or the amount."""
        body = fn.body
        for m in re.finditer(r'\.\s*require_auth_for_args\s*\(', body):
            args = body[m.end():_close(body, m.end() - 1) - 1]
            if re.fullmatch(r'\s*&?\s*[A-Za-z_]\w*\s*', args):
                bound = re.search(r'\blet\s+(?:mut\s+)?' + re.escape(args.strip(' &')) + r'\b[^=;]*=\s*([^;]*);', body[:m.start()])
                if not bound:
                    continue
                args = bound.group(1)
            moved = ' '.join(body[c.end():_close(body, c.end() - 1)] for c in
                             re.finditer(r'\.\s*(?:transfer|transfer_from|approve|burn_from)\s*\(', body)
                             if c.start() > m.end() and self._token_client(fn, _receiver(body, c.start())))
            missing = [p for p in fn.params_of(r'\bAddress\b')
                       if re.fullmatch(r'to|recipient|dest|destination|spender|receiver|payee', p)
                       and _uses(moved, {p}) and not _uses(args, _aliases(body, {p}))]
            missing += [p for p in fn.params_of(r'^i128$') if _uses(moved, {p}) and not _uses(args, _aliases(body, {p}))]
            if missing:
                self._emit("soroban-auth-args-incomplete", Severity.HIGH,
                           "The authorized arguments leave out where the tokens go or how many",
                           "require_auth_for_args signs over a list that omits " + ", ".join(f"`{p}`" for p in missing) +
                           ", which the function then uses to move tokens. A signature for one call can be submitted "
                           "with a different recipient or amount.",
                           fn, m.start(), body[m.start():_close(body, m.end() - 1)],
                           "Include every argument that decides the payment (recipient and amount) in "
                           "require_auth_for_args, or use require_auth(), which covers all arguments.")
                return

    def _amount_checks(self, fn: _Fn) -> None:
        """V: funding entry points that take any amount, or a deadline nothing checks."""
        if not re.match(r'(?:create|deposit|lock|open|fund|escrow)', fn.name):
            return
        body = fn.body
        problems = []
        for p in fn.params_of(r'^i128$'):
            if not re.search(r'amount|deposit|value', p):
                continue
            names = _aliases(body, {p})
            if not any(_uses(body[c.end():_close(body, c.end() - 1)], names) for c in self._moves(fn, 'transfer|transfer_from')):
                continue
            alt = '|'.join(map(re.escape, names))
            checked = re.search(rf'\b(?:{alt})\s*(?:<=?|>=?)\s*[01]\b|\b[01]\s*(?:<=?|>=?)\s*(?:{alt})\b|'
                                rf'\b(?:{alt})\s*\.\s*(?:is_positive|is_negative|signum)', body) or any(
                re.search(r'(?:<=?|>=?)\s*[01]\b|\b[01]\s*(?:<=?|>=?)|is_positive|is_negative', h.body)
                for h, _ in self.crate.bound(fn, names)) or _lower_bounded(body, alt)
            if not checked:
                problems.append((p, f"`{p}` is never required to be positive"))
        for p in fn.params:
            if re.search(r'deadline|expir|valid_until|timeout', p) and not self._ledger_compared(fn.file, p):
                problems.append((p, f"`{p}` is never compared with the ledger time or sequence"))
        if problems:
            self._emit("soroban-entry-amount-unchecked", Severity.LOW,
                       "A funding entry point does not validate its amount or deadline",
                       "In " + fn.name + ": " + "; ".join(text for _, text in problems) + ". Zero-value records can be "
                       "created, and a token that accepts negative amounts would move funds the wrong way.",
                       fn, None, f"fn {fn.name}(" + ", ".join(p for p, _ in problems) + ")",
                       "Reject amounts <= 0 and deadlines that are already past (or too far ahead) at creation.",
                       confidence=0.8, claim=False)

    def _replay(self, fn: _Fn) -> None:
        """E: a signature verified outside __check_auth that can be submitted again."""
        scope = self._scope(fn)
        text = '\n'.join(f.body for f in scope)
        verify = next(((f, m) for f in scope for m in [_VERIFY.search(f.body)] if m), None)
        if not verify or not (_MUTATION.search(text) or _STORE_WRITE.search(text)):
            return
        if re.search(r'(?i)nonce|replay|\bused\b|consumed|\bseen\b', text) or re.search(r'\.\s*ledger\s*\(\s*\)|\.\s*has\s*\(', text):
            return
        if self._monotonic(fn):
            return
        where, m = verify
        self._emit("soroban-signature-replay", Severity.HIGH,
                   "A signed message can be submitted again",
                   "This entry point verifies a signature itself (not through Soroban authorization) and then changes "
                   "state, but stores no nonce or used-message marker and checks no ledger expiry. The same signed "
                   "message can be submitted again, by anyone, to repeat the action.",
                   where, m.start(), where.body[m.start():where.body.find(';', m.start())],
                   "Include a nonce (stored and consumed) and an expiry ledger in the signed message, or use "
                   "require_auth, whose nonces the host enforces.",
                   grade=EvidenceGrade.CONFIRMED if where is fn else EvidenceGrade.INFERRED, claim=False)

    def _monotonic(self, fn: _Fn) -> bool:
        """A parameter is checked against a stored value and then stored: a sequence number, round
        or timestamp that only moves forward makes an old signed message fail, like a nonce."""
        body = fn.body
        for p in fn.params:
            alt = '|'.join(map(re.escape, _aliases(body, {p})))
            written = re.search(_STORE_WRITE.pattern + rf'\s*\([^;]*(?<![\w.])(?:{alt})\b', body)
            if not written:
                continue
            for m in re.finditer(rf'(?<![\w.])(?:{alt})\s*(?:<=?|>=?)\s*&?\s*([A-Za-z_][\w.]*(?:\([^;{{}})]*\))?)|'
                                 rf'([A-Za-z_][\w.]*(?:\([^;{{}})]*\))?)\s*(?:<=?|>=?)\s*&?\s*(?:{alt})\b', body):
                other = m.group(1) or m.group(2)
                if _STORE_READ.search(other) or self.crate._stored(body, _root(other) or other.split('.')[0]):
                    return True
        return False

    def _ledger_compared(self, file: str, param: str) -> bool:
        """``param`` (or a record field of that name) is compared with env.ledger() somewhere in the file."""
        code = self.crate.code[file]
        clocks = set(re.findall(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*[^;]*\.\s*ledger\s*\(\s*\)', code))
        clock = r'(?:\.\s*ledger\s*\(\s*\)[\w\s.()]*' + ''.join(f'|\\b{re.escape(c)}\\b' for c in clocks) + ')'
        name = r'(?:\b|\.\s*)' + re.escape(param) + r'\b'
        return any(re.search(name + r'[^;{}]*?(?:<=?|>=?)[^;{}]*?' + clock + '|' + clock + r'[^;{}]*?(?:<=?|>=?)[^;{}]*?' + name, stmt)
                   for stmt in re.split(r'[;{}]', code))

    def _initializer(self, fn: _Fn) -> None:
        """I: an initializer with no once-only guard can be called again by anyone, and what it
        writes decides authorization elsewhere (an administrator, an authorized oracle)."""
        if not re.fullmatch(r'init(?:ialize)?', fn.name) or fn.file in self.crate.constructors:
            return
        if not _STORE_WRITE.search(fn.body) or self._strong(fn) or self._once_only(fn):
            return
        keys = set(re.findall(r'\.\s*set\s*\(\s*&\s*(?:\w+\s*::\s*)?([A-Za-z_]\w*)', fn.body))
        decides = any(re.search(r'\.\s*get\s*(?:::<[^>]*>)?\s*\(\s*&\s*(?:\w+\s*::\s*)?(?:' + '|'.join(map(re.escape, keys)) + r')\b', f.body)
                      and (_AUTH.search(f.body) or re.search(r'[!=]=|assert|panic', f.body))
                      for f in self.crate.fns if f.file == fn.file and f is not fn and keys
                      and f.owner in {fn.owner, ''})
        if decides:
            self.reinit.append(fn)

    def _once_only(self, fn: _Fn) -> bool:
        """Something before the first storage write refuses a second run: a has()/is_some()
        test, or a condition (if, match, assert!) that reads stored state, directly, through a
        variable, or through a has_*/get_*/store helper, and rejects (or writes only once); or a
        crate helper called first that reads storage and rejects."""
        body = fn.body
        if re.search(r'\.\s*has\s*\(|is_some\s*\(|is_none\s*\(|(?i:already|initiali[sz]ed)|\bif\s+let\s+Some', body):
            return True
        first = _STORE_WRITE.search(body).start()

        def state(expr: str, depth: int = 0) -> bool:
            if _STORE_READ.search(expr) or re.search(r'\bstorage\s*\(', expr):
                return True
            for c in re.finditer(r'(?<![\w.])' + _PATH_CALL, expr):  # functions, not methods on a value
                name = c.group(1)
                if re.match(r'(?:has|is|get|read|load|fetch)_', name) or name in self.crate.store:
                    return True
            return depth < 2 and any(
                state(b.group(1), depth + 1) for v in set(re.findall(r'(?<![\w.])[A-Za-z_]\w*', expr))
                for b in re.finditer(r'\blet\s+(?:mut\s+)?' + re.escape(v) + r'\b[^=;]*=\s*([^;]*);', body[:first]))

        for m in re.finditer(r'\b(?:if|match)\s+([^{;]*)\{', body[:first]):
            block = body[m.end() - 1:_close(body, m.end() - 1)]
            if (_REJECT.search(block) or m.end() - 1 + len(block) > first) and state(m.group(1)):
                return True
        for m in re.finditer(r'\b(?:assert|require|ensure)\w*!\s*\(', body[:first]):
            if state(body[m.end():_close(body, m.end() - 1) - 1]):
                return True
        return any(_STORE_READ.search(h.body) and re.search(r'\bpanic|\bErr\s*\(|\bassert|\bunreachable\s*!', h.body)
                   for c in _CALL_NAME.finditer(body[:first]) for h in self.crate.resolve(c.group(1), fn.file) if h is not fn)

    # ------------------------------------------------------------ instance storage (S)
    def open_writer(self, file: str, offset: int) -> bool:
        """The instance write at ``offset`` creates a record (it does not first load the same key)
        in an entry point any caller can reach (no stored administrator authorizes it), in a
        contract that holds tokens."""
        code = self.crate.code.get(file, '')
        holds = any(not re.search(r'\bevents\s*\(\s*\)', _receiver(code, m.start()))
                    for m in re.finditer(r'\.\s*transfer(?:_from)?\s*\([^;]*' + _SELF.pattern, code))
        family = re.match(r'[^&]*&\s*((?:\w+\s*::\s*)?\w+)\s*\(', code[offset:offset + 200])
        if not holds or not family:
            return False
        fn = min((f for f in self.crate.fns if f.file == file and f.body_start <= offset < f.body_start + len(f.body)),
                 key=lambda f: len(f.body), default=None)
        if fn is None or re.search(r'\.\s*(?:get|has)\s*(?:::<[^>]*>)?\s*\(\s*&\s*' + re.escape(family.group(1)) + r'\s*\(',
                                   ''.join(f.body for f in self._scope(fn))):
            return False
        callers = [fn] if fn.entry else [f for f in self.crate.fns if f.entry and f.file == file
                                         and self.crate.calls(f, {id(fn)})]
        return any(not self._strong(f) for f in callers)


def _lower_bounded(body: str, alt: str) -> bool:
    """An amount is held to a lower bound: `if amount < MIN { panic }`, `assert!(amount >= min)`."""
    if re.search(rf'\b(?:assert|require|ensure)\w*!\s*\([^;]*?(?:\b(?:{alt})\s*>|<=?\s*&?\s*(?:{alt})\b)', body):
        return True
    for m in re.finditer(r'\bif\s+([^{;]*)\{', body):
        if re.search(rf'\b(?:{alt})\s*<|>=?\s*&?\s*(?:{alt})\b', m.group(1)) and \
                _REJECT.search(body[m.end() - 1:_close(body, m.end() - 1)]):
            return True
    return False


def placed_in_package(file: str, files: dict[str, str], tests: set[str] = frozenset()) -> bool:
    """The file belongs to a package the build compiles: its nearest Cargo.toml has a [package]
    (a virtual workspace root builds nothing next to it), and it is not test code (``tests``, as
    cfg_test_files finds it) or a sample."""
    if (file in tests or _TEST_PATH.search(file) or _SAMPLE_PATH.search(file)
            or re.search(r'(?i)sample|example|fixture|mock', file.rsplit('/', 1)[-1])):
        return False
    manifests = {name.rsplit('/', 1)[0] if '/' in name else '': text for name, text in files.items()
                 if name.rsplit('/', 1)[-1] in {'Cargo.toml', 'Cargo.toml.hbs'}}
    if not manifests:
        return True
    parts = file.split('/')[:-1]
    for i in range(len(parts), -1, -1):
        directory = '/'.join(parts[:i])
        if directory in manifests:
            return bool(re.search(r'^\s*\[package\]', manifests[directory], re.M))
    return False
