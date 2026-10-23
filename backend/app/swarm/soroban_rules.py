"""Soroban contract rules that ask whose authorization a contract checks, and what it covers.

stellar_native's ST-001 only asks whether a mutating entry point calls require_auth at all. An
agent's on-chain limits live in custom-account __check_auth functions and spending policies
(OpenZeppelin `enforce`, passkey-kit `policy__`), and the auth mistakes that lose funds are about
the address: an upgrade authorized by whoever calls it, a token move from an address that never
signed for this call, a role attribute that checks membership but not authorization. These rules
cover those cases. They reuse stellar_native's masker, function splitter and helper resolution;
code-generator templates (.rs.hbs) are rendered by union first, so every branch is judged. It is
bounded lexical evidence, not a compiler. Every scan is linear in the source: what the rules ask
of a text again and again (matching brackets, statement ends, call sites, bindings) is found once,
so a hostile file cannot stall the audit.
"""

from __future__ import annotations

import heapq
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from functools import cached_property
from itertools import islice

from ..models import EvidenceGrade, Finding, FindingKind, Severity
from .consolidate import stable_id
from .stellar_native import _AUTH, _MUTATION, _NOT_NEWLINE, _rust_code, _rust_functions

#: Handlebars block tags ({{#if}}, {{else}}, {{/each}}) and partials. Union rendering blanks them
#: and keeps every branch body; comments are found by _template_comments.
_TEMPLATE_TAG = re.compile(r'\{\{~?\s*(?:[#/^][^{}]*|else\b[^{}]*|>[^{}]*)~?\}\}')
#: Any other {{expression}} becomes an identifier of the same length with the same line breaks,
#: so offsets and lines hold.
_TEMPLATE_EXPR = re.compile(r'\{\{\{?[^{}]*\}?\}\}')

#: A contract entry-point block: the attribute, any other attributes, then the impl header. Trait
#: impls export every fn; inherent impls their pub fns.
_IMPL_ATTR = re.compile(r'#\[\s*contractimpl\b[^\[\]]*\]')
_ATTRS = re.compile(r'\s*(?:#\[[^\]]*\]\s*)*')
_IMPL_HEAD = re.compile(r'impl\b([^{;]*)\{')
_STORE_READ = re.compile(r'storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)\s*\.\s*get\b')
_STORE_WRITE = re.compile(r'storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)\s*'
                          r'\.\s*(?:set|remove|update|try_update)\b')
_STORE_WRITE_CALL = re.compile(_STORE_WRITE.pattern + r'\s*\(')
_SELF = re.compile(r'\b(?:env|e|self\.env)\s*\.\s*current_contract_address\s*\(\s*\)')
#: Code-replacing sinks: the deployer's update_current_contract_wasm, soroban-sdk 28's
#: update_current_contract and executable_refs().set (CAP-85 executable references), and the
#: OpenZeppelin upgradeable::upgrade helper, which has no authorization of its own. Matched by
#: method name, whatever the receiver chain.
_SINK = re.compile(r'\.\s*update_current_contract(?:_wasm)?\s*\(|\bexecutable_refs\s*\(\s*\)\s*\.\s*set\s*\(|'
                   r'\bupgradeable\s*::\s*upgrade\s*\(')
#: The OpenZeppelin kill switch, also without authorization of its own.
_PAUSE_SINK = re.compile(r'\bpausable\s*::\s*(?:un)?pause\s*\(')
_ANY_SINK = re.compile(_SINK.pattern + '|' + _PAUSE_SINK.pattern)
#: Event emission, which authorizes nobody.
_EMIT = re.compile(r'\.publish\s*\(|events\s*\(\s*\)')
#: OpenZeppelin attributes that read the owner, admin or role holder and require its auth, bare or
#: path-qualified (#[stellar_macros::only_owner]).
_STRONG_ATTR = re.compile(r'#\[\s*(?:\w+\s*::\s*)*(?:only_owner|only_admin|only_role|only_any_role)\b')
#: OpenZeppelin library guards that read the owner or admin from storage and require its auth.
_STRONG_CALL = re.compile(r'\b(?:enforce_owner_auth|enforce_admin_auth)\s*\(')
_ROLE_ATTR = re.compile(r'#\[\s*(?:\w+\s*::\s*)*(?:has_role|has_any_role)\s*\(\s*([A-Za-z_]\w*)')
#: An attribute whose name suggests an administrator, owner, auth or role check.
_WEAK_ATTR = re.compile(r'#\[\s*(?:\w+\s*::\s*)*\w*(?:admin|owner|auth|role)\w*')
#: A path segment naming an access-control, ownable or role library.
_ROLE_LIBRARY = re.compile(r'access_control|ownable|role')
_VERIFY = re.compile(r'\.\s*(?:ed25519_verify|secp256r1_verify|secp256k1_recover)\s*\(')
#: Names that say the contract restricts what a key may do: limits, policies, agents, sessions.
_RESTRICTS = re.compile(r'(?i)\b\w*(?:limit|allowance|spend|budget|quota|whitelist|allowlist|policy|agent|session|'
                        r'max_amount|per_tx|per_call)\w*\b|\b(?:cap|Cap)\b|\b\w+_cap\b|\bcap_\w+')
#: Test code by its path: test.rs, tests.rs, test_*.rs, *_test(s).rs, or anything under test/, tests/
#: or benches/. Its mock contracts are never deployed, so the rules skip it.
_TEST_PATH = re.compile(r'(^|/)(?:tests?|benches)/|(^|/)(?:tests?|test_[^/]*|[^/]*_tests?)\.rs$', re.I)
#: Sample code (examples, demos, fixtures): judged one level lower.
_SAMPLE_PATH = re.compile(r'(^|/)(?:examples?|samples?|fixtures?|demos?)/', re.I)
#: `mod name;` or `mod name {`. Declared only under #[cfg(test)] (or cfg(any(test, ..))), the module
#: is test code; its attributes are read back to the previous item.
_MOD = re.compile(r'\bmod\s+([A-Za-z_]\w*)\s*([;{])')
_CFG = re.compile(r'#\[\s*cfg\s*\(([^\[\]]*)\)\s*\]')
#: A whole file compiled only for tests.
_TEST_INNER = re.compile(r'#!\[\s*cfg\s*\(([^\[\]]*)\)\s*\]')
_TESTUTILS_USE = re.compile(r'\buse\s+soroban_sdk\s*::')
_TESTUTILS = re.compile(r'\btestutils\b')
#: A call through Self::, self., a module or type path, or bare: the called name is group 1.
_PATH_CALL = r'(?:Self::|self\.|(?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*\('
_HEAD_CALL = re.compile(r'\s*(?:&\s*)?' + _PATH_CALL)
#: A contract client built in place: token::Client::new, TokenClient::new, StellarAssetClient::new.
_CLIENT_NEW = re.compile(r'\b\w*Client\s*(?:::\s*<[^>]{0,256}>\s*)?::\s*new\s*\(')
_CLIENT_HEAD = re.compile(r'\s*(?:\(\s*)?(?:&\s*)?(?:mut\s+)?(?:Self::|self\.|(?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*(\()?')
_EVENTS = re.compile(r'\bevents\s*\(\s*\)')
#: Calls that move tokens on a contract client.
_MOVE = re.compile(r'\.\s*(transfer_from|transfer|burn|mint)\s*\(')
#: Calls whose recipient and amount an authorization over the arguments should cover.
_PAYMENT = re.compile(r'\.\s*(transfer|transfer_from|approve|burn_from)\s*\(')
_TRANSFER_OPEN = re.compile(r'\.\s*transfer(?:_from)?\s*\(')
#: A state change through a library or type path (OpenZeppelin `Base::mint(e, ..)`).
_PATH_MUTATION = re.compile(r'\b[A-Za-z_]\w*\s*::\s*(?:mint|burn|transfer\w*|approve|set_\w+|update\w*|upgrade|pause|unpause|'
                            r'grant_role|revoke_role|clawback|freeze\w*|withdraw\w*|deposit\w*)\s*\(')
#: soroban-sdk value types: their associated functions convert values and authorize nobody.
_SDK_TYPES = frozenset({'Address', 'MuxedAddress', 'Vec', 'Map', 'Symbol', 'String', 'Bytes', 'BytesN', 'Val', 'Env',
                        'IntoVal', 'TryIntoVal', 'FromVal', 'TryFromVal', 'I256', 'U256', 'Duration', 'Timepoint', 'Hash'})
#: What rejects a call: a panic, an error return, an early return.
_REJECT = re.compile(r'\bpanic|\bErr\s*\(|\breturn\b|\bunreachable\s*!|\bassert')
_FAILS = re.compile(r'\bpanic|\bErr\s*\(|\bassert|\bunreachable\s*!')
_ERR_OR_PANIC = re.compile(r'\bErr\s*\(|panic')
_AUTH_FOR_ARGS = re.compile(r'\.\s*require_auth_for_args\s*\(')
_PLAIN_AUTH = re.compile(r'\.\s*require_auth\s*\(\s*\)')
_SELF_LETS = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]{1,256})?=\s*' + _SELF.pattern)
#: Deny-list shapes in an account's context check.
_DENY_NE = re.compile(r'\b(?:fn_name|contract)\s*!=')
_DENY_WORD = re.compile(r'\b(?:fn_name|contract)\b')
_CONTEXT_WORD = re.compile(r'\bContext\b')
_CONTAINS = re.compile(r'\.\s*contains\s*\(')
_CONTINUE_OR_OK = re.compile(r'\bcontinue\b|\breturn\s+Ok\s*\(\s*\(\s*\)\s*\)')
_WILD_REJECT = re.compile(r'(?:^|[,}\s])_\s*=>\s*(?:\{\s*)?(?:return\s+)?(?:Err\s*\(|panic)')
_WILD_APPROVE = re.compile(r'(?:^|[,}\s])_\s*=>\s*(\{\s*\}|\(\s*\)|continue\b|(?:return\s+)?Ok\s*\(\s*\(\s*\)\s*\))')
_IF_HEAD = re.compile(r'\bif\s+')
_FOR_HEAD = re.compile(r'\bfor\s+')
_NAME_AT = re.compile(r'[A-Za-z_]\w*')
_MATCH_HEAD = re.compile(r'\bmatch\s+')
_IF_OR_MATCH_HEAD = re.compile(r'\b(?:if|match)\s+')
_LOOP_KEYWORD = re.compile(r'\b(for|while|loop)\b')
_LOOP_METHOD = re.compile(r'\.\s*(?:for_each|try_for_each|all|any|map)\s*\(')
_IN_WORD = re.compile(r'\bin\b')
#: Amount checks of caps and policies (C6, C8). Words containing `amount` are matched with a
#: lookahead, so a long word is read once.
_ARGS_WORD = re.compile(r'\bargs\b')
_ACCUMULATES = re.compile(r'\+=\s*(?:&\s*)?\w*amount\w*\b|\b(?=\w*amount)\w+\s*\+(?![+=])|\+\s*(?:&\s*)?\w*amount\w*\b|'
                          r'(?:checked|saturating|wrapping)_add\s*\(\s*(?:&\s*)?\w*amount')
_LOWER_BOUND = re.compile(r'\b(?=\w*amount)\w+\s*(?:<=?)\s*0\b|\b0\s*>=?\s*\w*amount|\b(?=\w*amount)\w+\s*>=?\s*[01]\b|'
                          r'\b[01]\s*<=?\s*\w*amount|is_positive|is_negative|LessThanZero')
#: A policy documented or named as a per-transaction cap that runs beside a spending-limit policy.
_PER_TX_DOC = re.compile(r'(?i)\bper[\s_-]?(?:transaction|tx)\b|\btx[\s_-]?max\b|\bmax(?:imum)?[\s_-]?per[\s_-]?(?:tx|transaction)\b')
_PER_TX_NAME = re.compile(r'(?i)tx[_-]?max|per[_-]?tx|per[_-]?transaction')
_SPENDING_POLICY_DOC = re.compile(r'(?i)spending[\s_-]?limit[\s_-]?polic')
_SELF_ADMIN_EXTRA = re.compile(r'(?i)signer|threshold|verify|admin|guardian|require_auth')
_OK_UNIT = re.compile(r'\bOk\s*\(\s*\(\s*\)\s*\)')
_MULTISIG = re.compile(r'(?i)threshold|all_signed|weight|signers')
_TRANSFER_OR_AMOUNT = re.compile(r'\btransfer\b|\bamount\b')
_DO_CHECK_AUTH = re.compile(r'\bdo_check_auth\s*\(')
_DELEGATE = re.compile(r'\bdelegate_(?:account_)?auth\s*\(')
_REPLAY_WORDS = re.compile(r'(?i)nonce|replay|\bused\b|consumed|\bseen\b')
_LEDGER_OR_HAS = re.compile(r'\.\s*ledger\s*\(\s*\)|\.\s*has\s*\(')
_LEDGER = re.compile(r'\.\s*ledger\s*\(\s*\)')
_LET_HEAD = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]{1,256})?=\s*')
_TYPED_LET = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\b\s*(?::\s*([^=;]{1,256}))?=\s*')
_STATE_LET = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\b[^=;]{0,256}=\s*')
#: A binding whose value may be a stored address: `let x = ..`, `if let Some(x) = ..`, and a
#: let-else `let Some(x) = .. else { .. }`.
_STORED_LET = re.compile(r'\b(?:if\s+let\s+Some\s*\(\s*|let\s+Some\s*\(\s*|let\s+(?:mut\s+)?)([A-Za-z_]\w*)\b[^;=]{0,256}=\s*')
_SOME_ARM = re.compile(r'\bSome\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>')
_LOOP_BINDING = re.compile(r'(?:\(([^)]{0,256})\)|([A-Za-z_]\w*))\s+in\s+(?:&\s*)?(?:mut\s+)?')
_ALIAS_LET = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]{1,256})?=\s*(?:&\s*)?([A-Za-z_]\w*)'
                        r'((?:\s*\.\s*(?:into|clone|to_bytes|to_array|to_owned)\s*\(\s*\))*)\s*;')
_ALIAS_FOR = re.compile(r'\bfor\s+(?:\(([^)]{0,256})\)|([A-Za-z_]\w*))\s+in\s+(?:&\s*)?([A-Za-z_]\w*)\b')
_STRUCT_LET = re.compile(r'\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]{1,256})?=\s*[A-Z]\w*(?:\s*::\s*\w+)*\s*\{')
_SET_KEY = re.compile(r'\.\s*set\s*\(\s*&\s*(?:\w+\s*::\s*)?([A-Za-z_]\w*)')
_GET_KEY = re.compile(r'\.\s*get\s*(?:::<[^>]{0,256}>\s*)?\(\s*&\s*(\w+)(?:\s*::\s*([A-Za-z_]\w*))?')
_DECIDES = re.compile(r'[!=]=|assert|panic')
_ONCE_HINT = re.compile(r'\.\s*has\s*\(|is_some\s*\(|is_none\s*\(|(?i:already|initiali[sz]ed)|\bif\s+let\s+Some')
_GUARD_MACRO = re.compile(r'\b(?:assert|require|ensure)\w*!\s*\(')
_STORAGE_CALL = re.compile(r'\bstorage\s*\(')
_STATE_NAME = re.compile(r'(?:has|is|get|read|load|fetch)_')
_IDENT = re.compile(r'(?<![\w.])[A-Za-z_]\w*')
#: The variable a statement or receiver chain starts from, and a field read on it.
_ROOT_AT = re.compile(r'\s*(?:\(\s*)?(?:&\s*)?([A-Za-z_]\w*)')
_FIELD_AT = re.compile(r'\s*\.\s*([A-Za-z_]\w*)')
_ASSERT_EQ = re.compile(r'assert_(?:eq|ne)!\s*\(')
_EQ_OP = re.compile(r'(?=[!=]=)')
_CMP_OP = re.compile(r'[<>]')
_OPERAND = re.compile(r'[A-Za-z_][\w.]{0,256}(?:\([^;{})]{0,256}\))?')
_LOWER_SEGMENT = re.compile(r'[a-z_][a-z0-9_]*')
_TYPE_SEGMENT = re.compile(r'[A-Z]\w*')
_LOWER_START = re.compile(r'[a-z_]')
_NAME_START = re.compile(r'[A-Za-z_]')
_EQ_CLASS = frozenset('&.:()_')

#: Bounds that keep each rule linear on hostile input; real contracts stay far below them.
#: Parts of an argument list that are read.
_MAX_ARGS = 64
#: Characters of one argument kept; a longer one is cut and ends in '…', so it never reads as a
#: plain variable.
_ARG_CHARS = 512
#: Characters of an argument list, a condition or a snippet that a rule reads.
_ARG_TEXT = 4000
#: Characters of a signature read for parameters and the return type.
_SIGNATURE_CHARS = 4000
#: Links of a receiver chain (`a.b().c()`) or path (`a::b::c`) walked back.
_MAX_LINKS = 32
#: Same-name functions of one file that a call may resolve to.
_MAX_SAME_NAME = 8
#: Helpers gathered into one function's scope.
_MAX_REACH = 256
#: Occurrences of one construct (an authorization over arguments, a self-call branch, a signature
#: check) judged per function.
_MAX_SITES = 32
#: Characters of a type annotation, operand or turbofish a pattern may span.
_SPAN = 256
#: Characters of indexed text kept between calls; the index cache is emptied past this.
_CACHE_CHARS = 2_000_000


def _word(ch: str) -> bool:
    return ch.isalnum() or ch == '_'


def _cfg_test(cfg: str) -> bool:
    """A cfg(...) predicate that holds only in test (or test-helper) builds."""
    return bool(re.search(r'\btest\b', cfg)) and not re.search(r'\bnot\s*\(', cfg)


# ---------------------------------------------------------------------- text index

_BRACKETS = re.compile(r'[()\[\]{},;]')
_OPENER = {')': '(', ']': '[', '}': '{'}


class _Text:
    """Positions in one text, found once and shared by every rule that reads it: brackets paired
    per type (as _close counts them), ( and [ paired together backwards (as _receiver walks), commas
    by nesting depth, and the ; { } that end statements and headers. Lookups are dictionary reads
    and bisects, so nested or unclosed brackets cost linear time instead of a scan per call."""

    def __init__(self, text: str):
        self.text, self.n = text, len(text)
        #: Opening bracket -> index just past its closing bracket of the same type.
        self.close: dict[int, int] = {}
        #: ')' or ']' -> its '(' or '[' (counted together; -1 when unmatched).
        self.back: dict[int, int] = {}
        #: Opening bracket -> nesting depth (all bracket types) before it.
        self.depth: dict[int, int] = {}
        #: Nesting depth -> positions of the commas at that depth.
        self.commas: dict[int, list[int]] = {}
        self.stops: list[int] = []      # '{' and ';': where a header ends
        self.bounds: list[int] = []     # ';', '{', '}': where a statement ends
        self.semis: list[int] = []
        self.lbraces: list[int] = []
        self.braces: list[int] = []     # '{' and '}'
        self.rparens: list[int] = []
        self.opens: list[int] = []      # every opening bracket
        self.closes: list[int] = []     # every closing bracket
        stacks: dict[str, list[int]] = {'(': [], '[': [], '{': []}
        round_, depth = [], 0
        for m in _BRACKETS.finditer(text):
            ch, i = m.group(), m.start()
            if ch == ',':
                self.commas.setdefault(depth, []).append(i)
            elif ch == ';':
                self.stops.append(i); self.bounds.append(i); self.semis.append(i)
            elif ch in '([{':
                stacks[ch].append(i); self.depth[i] = depth; depth += 1; self.opens.append(i)
                if ch == '{':
                    self.stops.append(i); self.bounds.append(i); self.lbraces.append(i); self.braces.append(i)
                else:
                    round_.append(i)
            else:
                opener = stacks[_OPENER[ch]]
                if opener:
                    self.close[opener.pop()] = i + 1
                depth -= 1
                self.closes.append(i)
                if ch == '}':
                    self.bounds.append(i); self.braces.append(i)
                else:
                    self.back[i] = round_.pop() if round_ else -1
                    if ch == ')':
                        self.rparens.append(i)
        self._found: dict = {}
        #: Per-text results of the rules' own helpers (aliases, bindings, comparisons).
        self.memo: dict = {}

    def end(self, i: int) -> int:
        """Index just past the bracket (of the same type) that closes the one at ``i``."""
        return self.close.get(i, self.n)

    def depth_at(self, pos: int) -> int:
        return bisect_left(self.opens, pos) - bisect_left(self.closes, pos)

    def spans(self, o: int) -> list[tuple[int, int]]:
        """(start, end) of each top-level part inside the bracket at ``o``, as _split cuts them
        (at most _MAX_ARGS)."""
        stop = self.end(o) - 1
        edges = [o]
        level = self.commas.get(self.depth[o] + 1) if o in self.depth else None
        if level:
            a = bisect_right(level, o)
            edges += level[a:min(bisect_left(level, stop), a + _MAX_ARGS - 1)]
        edges.append(stop)
        return [(edges[k] + 1, edges[k + 1]) for k in range(len(edges) - 1)]

    def part(self, a: int, b: int) -> str:
        """text[a:b] stripped; past _ARG_CHARS it is cut and ends in '…'."""
        t = self.text
        while a < b and t[a].isspace():
            a += 1
        while b > a and t[b - 1].isspace():
            b -= 1
        return t[a:b] if b - a <= _ARG_CHARS else t[a:a + _ARG_CHARS] + '…'

    def args(self, o: int) -> list[str]:
        """The bracket's contents split at top-level commas: parts stripped, an empty last part
        dropped (as _split does)."""
        parts = [self.part(a, b) for a, b in self.spans(o)]
        if parts and not parts[-1]:
            parts.pop()
        return parts

    def item_start(self, pos: int) -> int:
        """Just past the last ; { } before ``pos``: where its statement or item starts."""
        k = bisect_left(self.bounds, pos)
        return self.bounds[k - 1] + 1 if k else 0

    def _next(self, positions: list[int], pos: int) -> int:
        k = bisect_left(positions, pos)
        return positions[k] if k < len(positions) else self.n

    def next_stop(self, pos: int) -> int:
        """The first '{' or ';' at or after ``pos`` (len(text) for none)."""
        return self._next(self.stops, pos)

    def next_semi(self, pos: int) -> int:
        return self._next(self.semis, pos)

    def next_bound(self, pos: int) -> int:
        return self._next(self.bounds, pos)

    def next_lbrace(self, pos: int) -> int:
        return self._next(self.lbraces, pos)

    def next_brace(self, pos: int) -> int:
        return self._next(self.braces, pos)

    def next_rparen(self, pos: int) -> int:
        return self._next(self.rparens, pos)

    def found(self, pattern: re.Pattern) -> tuple[list[int], list[int]]:
        """Start and end of every match of ``pattern``, as finditer finds them."""
        hit = self._found.get(pattern)
        if hit is None:
            starts, ends = [], []
            for m in pattern.finditer(self.text):
                starts.append(m.start()); ends.append(m.end())
            hit = self._found[pattern] = (starts, ends)
        return hit

    def first(self, pattern: re.Pattern, a: int, b: int) -> int:
        """Index (into found()) of the first match lying within [a, b), or -1."""
        starts, ends = self.found(pattern)
        k = bisect_left(starts, a)
        return k if k < len(starts) and ends[k] <= b else -1

    def has(self, pattern: re.Pattern, a: int, b: int) -> bool:
        return self.first(pattern, a, b) >= 0

    @cached_property
    def sites(self) -> list['_Site']:
        return _call_sites(self.text)

    @cached_property
    def site_starts(self) -> list[int]:
        return [s.at for s in self.sites]

    @cached_property
    def newlines(self) -> list[int]:
        return [m.start() for m in re.finditer('\n', self.text)]


#: Indexes by the id of their text (the text is kept, so the id stays its own).
_TEXTS: dict[int, tuple[str, _Text]] = {}
_cached_chars = 0


def _text(text: str) -> _Text:
    """The index of ``text``, built on first use and kept while the cache has room."""
    global _cached_chars
    hit = _TEXTS.get(id(text))
    if hit is not None and hit[0] is text:
        return hit[1]
    if _cached_chars > _CACHE_CHARS:
        _TEXTS.clear()
        _cached_chars = 0
    index = _Text(text)
    _TEXTS[id(text)] = (text, index)
    _cached_chars += len(text) + 64
    return index


def release() -> None:
    """Drop every cached index (an audit calls this when its Soroban checks are done)."""
    global _cached_chars
    _TEXTS.clear()
    _cached_chars = 0


def _memo(text: str, key, compute):
    """A per-text result, computed once while the text's index is cached."""
    memo = _text(text).memo
    if key not in memo:
        memo[key] = compute()
    return memo[key]


# ---------------------------------------------------------------------- call sites

_NAME_PAREN = re.compile(r'(?<!\w)([A-Za-z_]\w*)\s*\(')


@dataclass(frozen=True)
class _Site:
    """One `name(` at ``at``. ``crate``: it may call one of the crate's own functions (bare,
    Self::, self., or through a lowercase module path such as `storage::get_admin`), the call text
    starting at ``start``; ``function``: not a method on a value; ``head``: where the call text
    starts when any path (`AdminStore::get`) counts, -1 when that reading does not apply;
    ``segment``: the path segment just before the name ('' for none)."""
    name: str
    at: int
    paren: int
    start: int
    crate: bool
    function: bool
    head: int
    segment: str


def _segments(t: str, s: int) -> list[tuple[int, str]]:
    """The `seg ::` path segments before position ``s``, nearest first."""
    out, i = [], s
    while len(out) < _MAX_LINKS:
        j = i
        while j > 0 and t[j - 1].isspace():
            j -= 1
        if j < 2 or t[j - 1] != ':' or t[j - 2] != ':':
            break
        j -= 2
        while j > 0 and t[j - 1].isspace():
            j -= 1
        k = j
        while k > 0 and _word(t[k - 1]):
            k -= 1
        if k == j:
            break
        out.append((k, t[k:j]))
        i = k
    return out


def _call_sites(t: str) -> list[_Site]:
    out = []
    for m in _NAME_PAREN.finditer(t):
        name, s = m.group(1), m.start()
        prev = t[s - 1] if s else ''
        before = t[s - 6] if s >= 6 else ''
        self_dot = s >= 5 and prev == '.' and t[s - 5:s] == 'self.' and not (s > 5 and _word(t[s - 6]))
        self_type = s >= 6 and t[s - 6:s] == 'Self::' and not (s > 6 and _word(t[s - 7]))
        segs = _segments(t, s) if prev == ':' or prev.isspace() else []
        lower = 0
        while lower < len(segs) and _LOWER_SEGMENT.fullmatch(segs[lower][1]):
            lower += 1
        named = 0
        while named < len(segs) and _NAME_START.match(segs[named][1]):
            named += 1
        bare = not prev or not (_word(prev) or prev in '.:')
        crate = [s - 6] * self_type + [s - 5] * self_dot + ([segs[lower - 1][0]] if lower else []) \
            + ([s] if bare and prev != '!' else [])
        heads = [s - 6] * self_type + [s - 5] * self_dot + ([segs[named - 1][0]] if named else []) + ([s] if bare else [])
        function = (not prev or not (_word(prev) or prev == '.')) or (
            self_dot and (s == 5 or not (_word(before) or before == '.')))
        out.append(_Site(name, s, m.end() - 1, min(crate) if crate else s, bool(crate), function,
                         min(heads) if heads else -1, segs[0][1] if segs else ''))
    return out


# ---------------------------------------------------------------------- source preparation

def _template_comments(text: str) -> list[tuple[int, int]]:
    """Spans of {{!-- .. --}} and {{! .. }} comments, as the lazy patterns match them, in one
    pass: a closing marker is searched again only when the cursor has passed the last one found."""
    spans, i, dash, close = [], 0, -2, -2
    while (i := text.find('{{!', i)) >= 0:
        end = -1
        if text.startswith('{{!--', i):
            if dash != -1 and dash < i + 5:
                dash = text.find('--}}', i + 5)
            if dash >= 0:
                end = dash + 4
        if end < 0:
            if close != -1 and close < i + 3:
                close = text.find('}}', i + 3)
            if close < 0:
                break
            end = close + 2
        spans.append((i, end))
        i = end
    return spans


def render_template(text: str) -> str:
    """Union rendering of a Handlebars template: every {{#if}}/{{else}} branch and {{#each}}
    body is kept once, tags are blanked, and {{expr}} becomes a same-length identifier with the
    same line breaks."""
    blank = lambda m: _NOT_NEWLINE.sub(' ', m.group())
    out, last = [], 0
    for a, b in _template_comments(text):
        out += [text[last:a], _NOT_NEWLINE.sub(' ', text[a:b])]
        last = b
    text = ''.join(out) + text[last:]
    text = _TEMPLATE_TAG.sub(blank, text)

    def identifier(m):
        s = _NOT_NEWLINE.sub('_', m.group())
        return 'tp' + ('l' if s[2] == '_' else s[2]) + s[3:]
    return _TEMPLATE_EXPR.sub(identifier, text)


def _item_start(code: str, pos: int, lo: int = 0) -> int:
    """Just past the last ; { } in code[lo:pos]."""
    return max(code.rfind(c, lo, pos) for c in '{};') + 1 if pos > lo else lo


def _test_only(attrs: str) -> bool:
    return any(_cfg_test(c) for c in _CFG.findall(attrs))


def without_test_modules(code: str) -> str:
    """Blank inline modules compiled only for tests (#[cfg(test)] mod tests { .. }), keeping
    offsets and lines: their mock contracts are never deployed."""
    if 'mod' not in code or 'cfg' not in code:
        return code
    out, last, lo = [], 0, 0
    for m in _MOD.finditer(code):
        if m.start() < last:
            continue
        if m.group(2) == '{' and _test_only(code[max(_item_start(code, m.start(), lo), lo):m.start()]):
            end = _text(code).end(m.end() - 1)
            out += [code[last:m.start()], _NOT_NEWLINE.sub(' ', code[m.start():end])]
            last = end
        lo = m.end()
    if not out:
        return code
    out.append(code[last:])
    return ''.join(out)


def _testutils_unconditional(code: str) -> bool:
    """An unconditional `use soroban_sdk::..testutils..;` at the top level of the file."""
    pos, last, depth = 0, 0, 0
    while (m := _TESTUTILS_USE.search(code, pos)):
        semi = code.find(';', m.end())
        if semi < 0:
            return False
        if _TESTUTILS.search(code, m.end(), semi):
            depth += code.count('{', last, m.start()) - code.count('}', last, m.start())
            last = m.start()
            attr = code[_item_start(code, m.start()):m.start()]
            if depth == 0 and not re.search(r'#\[\s*cfg\b', attr):
                return True
        pos = semi + 1
    return False


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
        if 'testutils' in code and _testutils_unconditional(code):
            tests.add(name)
        stem = name[:-3]
        base = stem.rsplit('/', 1)[0] if stem.rsplit('/', 1)[-1] in {'lib', 'main', 'mod'} else stem
        prefix = (base + '/') if '/' in stem else ('' if stem in {'lib', 'main', 'mod'} else stem + '/')
        gated: dict[str, bool] = {}
        lo = 0
        for m in _MOD.finditer(code):
            if m.group(2) == ';':
                test_only = _test_only(code[max(_item_start(code, m.start(), lo), lo):m.start()])
                # A module declared again for other builds (#[cfg(not(test))] pub(crate) mod x;) is not test-only.
                gated[m.group(1)] = gated.get(m.group(1), True) and test_only
            lo = m.end()
        for module in (prefix + name for name, test_only in gated.items() if test_only):
            tests |= {f for f in rust if f in {module + '.rs', module + '/mod.rs'} or f.startswith(module + '/')}
    return tests


# ---------------------------------------------------------------------- small readers

def _scan_close(code: str, i: int) -> int:
    """Index just past the bracket that closes the one at ``i`` (a scan; for short texts)."""
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


def _close(code: str, i: int) -> int:
    """Index just past the bracket that closes the one at ``i``."""
    return _text(code).end(i)


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
    return _text(code).args(open_paren)


def _root(arg: str) -> str:
    """The variable an argument passes: `&x`, `x.clone()`, `&mut x` -> x; else ''."""
    m = re.fullmatch(r'&?\s*(?:mut\s+)?([A-Za-z_]\w*)(?:\s*\.\s*(?:clone|into|to_owned|as_ref)\s*\(\s*\))*', arg.strip())
    return m.group(1) if m else ''


def _bindings(body: str) -> tuple[list[tuple[str, str]], list[tuple[frozenset, str]]]:
    """`let p = name[.into()|.clone()|..];` pairs and `for (pattern) in name` loops of a body."""
    def compute():
        lets = [(m.group(1), m.group(2)) for m in _ALIAS_LET.finditer(body)]
        loops = [(frozenset(re.findall(r'[A-Za-z_]\w*', m.group(1) or m.group(2))), m.group(3)) for m in _ALIAS_FOR.finditer(body)]
        return lets, loops
    return _memo(body, 'bindings', compute)


def _aliases(body: str, names: set[str]) -> set[str]:
    """``names`` plus `let p = name[.into()|.clone()|.to_bytes()|.to_array()]` bindings and loop
    variables over them."""
    key = ('aliases', frozenset(names))
    memo = _text(body).memo
    if key in memo:
        return set(memo[key])
    lets, loops = _bindings(body)
    out = set(names)
    for _ in range(3):
        grew = {target for target, source in lets if source in out}
        for targets, source in loops:
            if source in out:
                grew |= targets
        if grew <= out:
            break
        out |= grew
    memo[key] = frozenset(out)
    return out


def _uses(text: str, names: set[str]) -> bool:
    return any(re.search(r'(?<![\w.])' + re.escape(n) + r'\b', text) for n in names)


def _receiver(code: str, dot: int) -> str:
    """The receiver chain of the method call whose '.' is at ``dot``: `client`,
    `token::Client::new(&e, &t)`, `TokenUtils::new(&e).events()` (at most _MAX_LINKS links)."""
    tx, i, start = _text(code), dot, dot
    for _ in range(_MAX_LINKS):
        j = i
        while j > 0 and code[j - 1].isspace():
            j -= 1
        if j > 0 and code[j - 1] == '?':
            j -= 1
        if j > 0 and code[j - 1] in ')]':
            j = max(tx.back.get(j - 1, -1), 0)
            while j > 0 and code[j - 1].isspace():
                j -= 1
        k = j
        while k > 0 and (code[k - 1].isalnum() or code[k - 1] == '_'):
            k -= 1
        start = t = k
        while t > 0 and code[t - 1].isspace():
            t -= 1
        if k < j and t > 0 and code[t - 1] == '.':
            i = t - 1
        elif k < j and t > 1 and code[t - 2:t] == '::':
            i = t - 2
        else:
            break
    return code[start:dot]


def _auth_roots(text: str) -> list[tuple[str, bool]]:
    """For each require_auth[_for_args] call: the first link of the `a.b.c` chain it is called on,
    and whether the character just before that link is a word character or a '.'."""
    def compute():
        out = []
        for m in _AUTH.finditer(text):
            i, root, at = m.start(), '', -1
            for _ in range(_MAX_LINKS):
                j = i
                while j > 0 and text[j - 1].isspace():
                    j -= 1
                k = j
                while k > 0 and _word(text[k - 1]):
                    k -= 1
                if k == j:
                    break
                root, at = text[k:j], k
                t = k
                while t > 0 and text[t - 1].isspace():
                    t -= 1
                if t > 0 and text[t - 1] == '.':
                    i = t - 1
                else:
                    break
            if root and _NAME_START.match(root):
                out.append((root, at > 0 and (_word(text[at - 1]) or text[at - 1] == '.')))
        return out
    return _memo(text, 'auth_roots', compute)


def _auth_receivers(text: str) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    """Who require_auth names directly: `x.require_auth[_for_args](`, `x.require_auth()` alone
    (plain), and struct fields `req.from.require_auth(..)`, each not preceded by a word or '.'."""
    def free(k):
        return not (k and (_word(text[k - 1]) or text[k - 1] == '.'))

    def compute():
        direct, plain, fields = set(), set(), set()
        plains = set(_text(text).found(_PLAIN_AUTH)[0])
        for m in _AUTH.finditer(text):
            j = m.start()
            while j > 0 and text[j - 1].isspace():
                j -= 1
            k = j
            while k > 0 and _word(text[k - 1]):
                k -= 1
            if k == j:
                continue
            word = text[k:j]
            if free(k):
                direct.add(word)
                if m.start() in plains:
                    plain.add(word)
            t = k
            while t > 0 and text[t - 1].isspace():
                t -= 1
            if t > 0 and text[t - 1] == '.':
                t -= 1
                while t > 0 and text[t - 1].isspace():
                    t -= 1
                v = t
                while v > 0 and _word(text[v - 1]):
                    v -= 1
                if v < t and free(v):
                    fields.add((text[v:t], word))
        return direct, plain, fields
    return _memo(text, 'auth_receivers', compute)


def _headed(text: str, head: re.Pattern, end: int | None = None):
    """Matches of `head([^{;]*)\\{` as finditer finds them, as (start, head end, '{'), without
    rescanning a header for each head inside it: one that ends in ';' fails for every head before
    that ';'. ``end`` limits the search to text[:end]."""
    tx = _text(text)
    end = tx.n if end is None else end
    pos = 0
    while (m := head.search(text, pos, end)):
        stop = tx.next_stop(m.end())
        if stop >= end:
            return
        if text[stop] == '{':
            yield m.start(), m.end(), stop
        pos = stop + 1


def _loops(body: str) -> list[tuple[int, int]]:
    """(match end, closing index) of every loop body or iterator closure: for/while/loop blocks and
    .for_each/.all/.any/.map calls (a call inside a loop header is part of that header)."""
    def compute():
        tx, out, headers, pos = _text(body), [], [], 0
        for m in _LOOP_KEYWORD.finditer(body):
            if m.start() < pos:
                continue
            stop = tx.next_stop(m.end())
            if stop >= tx.n:
                break
            if body[stop] == ';':
                pos = stop + 1
                continue
            if m.group(1) == 'for' and not tx.has(_IN_WORD, m.end(), stop):
                continue
            headers.append((m.start(), stop))
            out.append((stop + 1, tx.end(stop)))
            pos = stop + 1
        starts = [a for a, _ in headers]
        for m in _LOOP_METHOD.finditer(body):
            k = bisect_right(starts, m.start()) - 1
            if k >= 0 and m.start() <= headers[k][1]:
                continue
            out.append((m.end(), tx.end(m.end() - 1)))
        return out
    return _memo(body, 'loops', compute)


def _in_loop(body: str, pos: int) -> bool:
    """``pos`` lies inside a for/while/loop body or an iterator closure (for_each, all, map)."""
    return any(e <= pos < c for e, c in _loops(body))


def _fields(body: str) -> dict[tuple[str, str], str]:
    """Fields of local struct literals and the variables they are set from:
    `let req = Req { from: from.clone(), to }` -> {('req', 'from'): 'from', ('req', 'to'): 'to'}."""
    def compute():
        out = {}
        for m in _STRUCT_LET.finditer(body):
            for part in _args(body, m.end() - 1):
                fm = re.fullmatch(r'([A-Za-z_]\w*)\s*(?::\s*(.+))?', part, re.S)
                if fm and _root(fm.group(2) or fm.group(1)):
                    out[(m.group(1), fm.group(1))] = _root(fm.group(2) or fm.group(1))
        return out
    return _memo(body, 'fields', compute)


def _typed_lets(body: str) -> dict[str, list[tuple[str | None, str]]]:
    """`let name[: Type] = expr;` per name, the expression cut at _ARG_TEXT."""
    def compute():
        tx, out = _text(body), {}
        for m in _TYPED_LET.finditer(body):
            semi = tx.next_semi(m.end())
            if m.end() < semi < tx.n:
                out.setdefault(m.group(1), []).append((m.group(2), body[m.end():min(semi, m.end() + _ARG_TEXT)]))
        return out
    return _memo(body, 'typed_lets', compute)


def _drop_to_semi(text: str, head: re.Pattern) -> str:
    """re.sub(head + r'[^;]*;', '', text), cutting from each head to the next ';'."""
    out, last = [], 0
    for m in head.finditer(text):
        if m.start() < last:
            continue
        semi = text.find(';', m.end())
        if semi < 0:
            break
        out.append(text[last:m.start()])
        last = semi + 1
    out.append(text[last:])
    return ''.join(out)


def _drop_statements(text: str, pattern: re.Pattern) -> str:
    """re.sub(r'[^;{}]*(?:' + pattern + r')[^;]*;', '', text) without its backtracking: from the
    start of the statement holding an occurrence (the last one in that statement) to the next ';'."""
    tx = _text(text)
    hits = [m.start() for m in pattern.finditer(text)]
    out, last, i = [], 0, 0
    while i < len(hits):
        if hits[i] < last:
            i += 1
            continue
        run_end = tx.next_bound(hits[i])
        j = i
        while j + 1 < len(hits) and hits[j + 1] < run_end:
            j += 1
        semi = tx.next_semi(hits[j])
        if semi >= tx.n:
            break
        out.append(text[last:max(tx.item_start(hits[i]), last)])
        last, i = semi + 1, j + 1
    out.append(text[last:])
    return ''.join(out)


def _blank_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """``text`` with the given spans replaced by spaces."""
    out, last = [], 0
    for a, b in sorted(spans):
        a = max(a, last)
        if b <= a:
            continue
        out += [text[last:a], ' ' * (b - a)]
        last = b
    out.append(text[last:])
    return ''.join(out)


def _without_attributes(code: str) -> str:
    """re.sub(r'#\\[[^\\]]*\\]', '', code): each `#[` up to the next ']'."""
    out, last = [], 0
    while (i := code.find('#[', last)) >= 0:
        j = code.find(']', i + 2)
        if j < 0:
            break
        out.append(code[last:i])
        last = j + 1
    out.append(code[last:])
    return ''.join(out)


def _cap_match(t: str) -> tuple[int, int, str] | None:
    """The first match of `\\b(\\w*amount\\w*)\\s*>=?\\s*(?!-?[01]\\b)[\\w.]+` or
    `\\b(?!-?[01]\\b)[\\w.]+\\s*<=?\\s*(\\w*amount\\w*)\\b`, as (start, end, amount variable). It
    is read outward from each '<' and '>', so long words and dotted runs are read once."""
    n, best = len(t), None

    def dotted(c):
        return _word(c) or c == '.'

    def literal_01(p):  # where (?!-?[01]\b) fails
        q = p + 1 if p < n and t[p] == '-' else p
        return q < n and t[q] in '01' and (q + 1 >= n or not _word(t[q + 1]))

    for m in _CMP_OP.finditer(t):
        o = m.start()
        j = o
        while j > 0 and t[j - 1].isspace():
            j -= 1
        k = o + 1 + (o + 1 < n and t[o + 1] == '=')
        while k < n and t[k].isspace():
            k += 1
        if t[o] == '>':
            w = j
            while w > 0 and _word(t[w - 1]):
                w -= 1
            if w == j or 'amount' not in t[w:j] or literal_01(k):
                continue
            e = k
            while e < n and dotted(t[e]):
                e += 1
            if e > k and (best is None or w < best[0]):
                best = (w, e, t[w:j])
        else:
            e = k
            while e < n and _word(t[e]):
                e += 1
            if 'amount' not in t[k:e]:
                continue
            r = j
            while r > 0 and dotted(t[r - 1]):
                r -= 1
            for p in range(r, j):
                if (p > 0 and _word(t[p - 1])) != _word(t[p]) and not literal_01(p):
                    if best is None or p < best[0]:
                        best = (p, e, t[k:e])
                    break
    return best


# ---------------------------------------------------------------------- functions and the crate

@dataclass(eq=False)
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
    #: The function this one is nested in (None at the top level).
    parent: '_Fn | None' = field(repr=False, default=None)
    #: Offsets of the newlines in ``code``.
    newlines: list = field(repr=False, default_factory=list)

    def line_of(self, offset: int) -> int:
        """Line of an offset into ``body``."""
        return bisect_left(self.newlines, self.body_start + offset) + 1

    def params_of(self, pattern: str) -> list[str]:
        return [p for p, t in self.params.items() if re.search(pattern, t)]

    @cached_property
    def sites(self) -> list[_Site]:
        return _text(self.body).sites

    @cached_property
    def called(self) -> list[str]:
        """Names of the crate functions this one may call, in order of first call."""
        return list(dict.fromkeys(s.name for s in self.sites if s.crate))


def _params(signature: str) -> dict:
    m = re.search(r'\bfn\s+\w+\s*(?:<[^(]*>)?\s*\(', signature)
    if not m:
        return {}
    out = {}
    for part in _split(signature[m.end():_scan_close(signature, m.end() - 1) - 1], angle=True):
        pm = re.match(r'(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$', part, re.S)
        if pm:
            out[pm.group(1)] = ' '.join(pm.group(2).split())
    return out


def _impls(code: str) -> list[tuple[int, int, str]]:
    """(the impl's '{', its closing index, its header) of each #[contractimpl] block."""
    out, pos = [], 0
    while (m := _IMPL_ATTR.search(code, pos)):
        run = _ATTRS.match(code, m.end()).end()
        head = _IMPL_HEAD.match(code, run)
        if head:
            out.append((head.end() - 1, _close(code, head.end() - 1), head.group(1).strip()))
            pos = head.end()
        else:
            # Every other contractimpl attribute of this run is followed by the same text.
            pos = max(run, m.end())
    return out


def _parse(name: str, loose: bool, template: bool, code: str, raw: list[dict]) -> list[_Fn]:
    impls = _impls(code)
    tx = _text(code)
    out, enclosing, alive, k = [], [], [], 0
    for fn in raw:
        # Bodies nest properly, so the functions still open form a stack.
        while enclosing and enclosing[-1][1] <= fn['start']:
            enclosing.pop()
        nested = bool(enclosing) and enclosing[-1][0] <= fn['start']
        # The first impl block (in source order) around the function.
        while k < len(impls) and impls[k][0] < fn['start']:
            heapq.heappush(alive, k)
            k += 1
        while alive and impls[alive[0]][1] <= fn['start']:
            heapq.heappop(alive)
        block = impls[alive[0]] if alive else None
        header = block[2] if block else ''
        trait = header.split(' for ')[0].strip() if ' for ' in header else ''
        entry = not nested and (bool(block) and (fn['public'] or bool(trait)) or (loose and not impls and fn['public']))
        # Attributes and doc comments between the previous item and this fn.
        before = tx.item_start(fn['start'])
        signature = code[fn['start']:min(fn['body_start'] - 1, fn['start'] + _SIGNATURE_CHARS)]
        ret = re.search(r'\)\s*->\s*', signature)
        f = _Fn(name, fn['name'], fn['line'], fn['start'], fn['body_start'], fn['body'],
                _params(signature), code[before:fn['start']], entry, trait, template,
                header.split(' for ')[-1].strip(), code, signature[ret.end():].strip() if ret else '',
                enclosing[-1][2] if nested else None, tx.newlines)
        enclosing.append((fn['body_start'], fn['end'], f))
        out.append(f)
    return out


class _Crate:
    """Every function of the contract sources, with the helper sets the rules share."""

    def __init__(self, files: dict[str, str], loose: bool, templates: set[str], masked: dict[str, str]):
        #: Masked code per file, with inline #[cfg(test)] modules blanked (offsets kept).
        self.code = {name: without_test_modules(masked.get(name) or _rust_code(text)) for name, text in files.items()}
        #: stellar_native's split of each file (every function, nested ones blanked), made once.
        self.raw = {name: _rust_functions(text, include_private=True, code=self.code[name]) for name, text in files.items()}
        self.fns = [f for name in files for f in _parse(name, loose, name in templates, self.code[name], self.raw[name])]
        self.by_name: dict[str, list[_Fn]] = {}
        self.local: dict[tuple[str, str], list[_Fn]] = {}
        for f in self.fns:
            self.by_name.setdefault(f.name, []).append(f)
            self.local.setdefault((f.file, f.name), []).append(f)
        self.store = self._names(self._closure(lambda f: bool(_STORE_READ.search(f.body))))
        self._stored_memo: dict = {}
        self._compared_memo: dict = {}
        self.strong = self._closure(lambda f: self._strong_receiver(f.body))
        self.auth = self._closure(lambda f: bool(_AUTH.search(f.body)))
        self.sinks = self._closure(lambda f: bool(_SINK.search(f.body)))
        self.pauses = self._closure(lambda f: bool(_PAUSE_SINK.search(f.body)))
        self.mutates = self._closure(lambda f: bool(_MUTATION.search(f.body) or _PATH_MUTATION.search(f.body)))
        self.constructors = {f.file for f in self.fns if f.name == '__constructor'}
        self._reach: dict[int, list[_Fn]] = {}
        self._bound: dict = {}

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

    def calls(self, fn: _Fn, ids: set[int]) -> _Site | None:
        """The first call in ``fn`` to a crate function in ``ids`` (other than ``fn`` itself)."""
        return next((s for s in fn.sites if s.crate
                     and any(id(h) in ids for h in self.resolve(s.name, fn.file) if h is not fn)), None)

    def resolve(self, name: str, file: str) -> list[_Fn]:
        """Crate functions a call by this name may reach: the same file's first, else up to two."""
        return self.local.get((file, name), [])[:_MAX_SAME_NAME] or self.by_name.get(name, [])[:2]

    def reach(self, fn: _Fn, depth: int = 3) -> list[_Fn]:
        """Same-crate helpers called from ``fn``, a few hops deep (at most _MAX_REACH)."""
        if id(fn) in self._reach:
            return self._reach[id(fn)]
        seen, frontier, out = {id(fn)}, [fn], []
        for _ in range(depth):
            nxt = []
            for f in frontier:
                for name in f.called:
                    for h in self.resolve(name, f.file):
                        if id(h) not in seen and len(out) < _MAX_REACH:
                            seen.add(id(h)); nxt.append(h); out.append(h)
            frontier = nxt
        self._reach[id(fn)] = out
        return out

    def bound(self, fn: _Fn, names: set[str]) -> list[tuple[_Fn, set[str]]]:
        """Helpers (one hop) that receive one of ``names``, with the parameters they receive it as."""
        key = (id(fn), frozenset(names))
        if key in self._bound:
            return self._bound[key]
        out = []
        for s in fn.sites:
            helpers = [h for h in self.resolve(s.name, fn.file) if h is not fn] if s.crate else []
            if not helpers:
                continue
            roots = [_root(a) for a in _args(fn.body, s.paren)]
            for h in helpers:
                params = list(h.params)
                if params and params[0] in {'self'}:
                    params = params[1:]
                got = {params[i] for i, r in enumerate(roots) if i < len(params) and r in names}
                if got:
                    out.append((h, got))
        self._bound[key] = out
        return out

    def _strong_receiver(self, body: str) -> bool:
        """require_auth on the contract itself, on a stored address, or on a store helper's result."""
        tx = _text(body)
        # x.require_auth() on a variable bound to a stored address (`let`, let-else, a match arm on
        # a store read, a loop over a stored list).
        if any(self._stored(body, root) for root, _ in _auth_roots(body)):
            return True
        statements: dict[int, int] = {}
        for m in _AUTH.finditer(body):
            statements[tx.item_start(m.start())] = m.start()
        for start, last in statements.items():
            # The statement up to its last require_auth holds every earlier one's text.
            if tx.has(_SELF, start, last) or tx.has(_STORE_READ, start, last):
                return True
            # read_admin(&e), Self::admin(&e), storage::get_admin(&e), AdminStore::get(&e): the
            # statement's first call.
            sites = _memo(body, 'headed_sites', lambda: [s for s in tx.sites if s.head >= 0])
            heads = _memo(body, 'heads', lambda: [s.head for s in sites])
            k = bisect_left(heads, start)
            if k < len(heads) and sites[k].paren < last and sites[k].name in self.store:
                return True
            root = _ROOT_AT.match(body, start, last)
            if root and self._stored(body, root.group(1)):
                return True
        return False

    def _stored_bindings(self, body: str) -> tuple[dict, dict]:
        """Where a variable's value comes from: let bindings (to the next ';'), `Some(x) =>` arms of a
        match (its scrutinee), and loop variables (the iterated expression and its variable)."""
        def compute():
            tx, values, loops = _text(body), {}, {}
            for m in _STORED_LET.finditer(body):
                values.setdefault(m.group(1), []).append((m.end(), tx.next_semi(m.end())))
            for start, head_end, brace in _headed(body, _MATCH_HEAD):
                level, close = tx.depth[brace] + 1, tx.end(brace)
                starts, _ = tx.found(_SOME_ARM)
                first = bisect_left(starts, brace)
                for i in range(first, min(len(starts), first + _MAX_ARGS)):
                    if starts[i] >= close:
                        break
                    if tx.depth_at(starts[i]) == level:
                        arm = _SOME_ARM.match(body, starts[i])
                        values.setdefault(arm.group(1), []).append((head_end, brace))
            for start, head_end, brace in _headed(body, _FOR_HEAD):
                b = _LOOP_BINDING.match(body, head_end, brace)
                if not b:
                    continue
                source = _NAME_AT.match(body, b.end(), brace)
                for var in re.findall(r'[A-Za-z_]\w*', b.group(1) or b.group(2)):
                    loops.setdefault(var, []).append((b.end(), brace, source.group() if source else ''))
            return values, loops
        return _memo(body, 'stored_bindings', compute)

    def _stored_value(self, body: str, a: int, b: int) -> bool:
        tx = _text(body)
        if tx.has(_STORE_READ, a, b) or tx.has(_SELF, a, b):
            return True
        call = _HEAD_CALL.match(body, a, b)
        return bool(call and call.group(1) in self.store)

    def _stored(self, body: str, var: str, depth: int = 0) -> bool:
        """``var`` is bound to a storage read, a store helper's result or the contract address,
        directly, through a let-else or a match arm, or as the variable of a loop over one."""
        key = (id(body), var, depth)
        if key not in self._stored_memo:
            values, loops = self._stored_bindings(body)
            self._stored_memo[key] = (
                any(self._stored_value(body, a, b) for a, b in values.get(var, ()))
                or any(self._stored_value(body, a, b) or (depth < 1 and src and src != var and self._stored(body, src, depth + 1))
                       for a, b, src in loops.get(var, ())))
        return self._stored_memo[key]

    def _stored_side(self, body: str, expr: str) -> bool:
        call = _HEAD_CALL.match(expr)
        root = _root(expr)
        return bool(_STORE_READ.search(expr) or (call and call.group(1) in self.store) or (root and self._stored(body, root)))

    def compared(self, body: str) -> set[str]:
        """Variables compared (==, !=, assert_eq!, assert_ne!) with a stored address."""
        key = id(body)
        if key not in self._compared_memo:
            pairs = _eq_pairs(body)
            for m in _ASSERT_EQ.finditer(body):
                parts = _args(body, m.end() - 1)[:2]
                if len(parts) == 2:
                    pairs.append((parts[0], parts[1]))
            out = set()
            for a, b in pairs:
                ra, rb = _root(a), _root(b)
                if ra and ra not in out and self._stored_side(body, b):
                    out.add(ra)
                if rb and rb not in out and self._stored_side(body, a):
                    out.add(rb)
            self._compared_memo[key] = out
        return self._compared_memo[key]


def _eq_operand(t: str, i: int, step: int, lo: int) -> int:
    """Walk from ``i`` over an `==` operand (`[&\\w.:()]`, plus a `::<..>` turbofish) in the
    direction ``step``; return where it ends."""
    n = len(t)
    while True:
        if step < 0:
            if i > lo and (_word(t[i - 1]) or t[i - 1] in _EQ_CLASS):
                i -= 1
                continue
            if i > lo and t[i - 1] == '>':
                # get::<K, Address>(..): skip back over the turbofish to the `::` before it.
                depth, j = 0, i - 1
                while j > max(lo, i - _SPAN) and t[j] not in ';{}':
                    depth += {'>': 1, '<': -1}.get(t[j], 0)
                    if not depth:
                        break
                    j -= 1
                if not depth and t[j] == '<' and t[j - 2:j] == '::' and j - 2 >= lo:
                    i = j - 2
                    continue
            return i
        if i < n and (_word(t[i]) or t[i] in _EQ_CLASS):
            i += 1
            continue
        if i < n and t[i] == '<' and t[i - 2:i] == '::':
            depth, j = 0, i
            while j < min(n, i + _SPAN) and t[j] not in ';{}':
                depth += {'<': 1, '>': -1}.get(t[j], 0)
                if not depth:
                    break
                j += 1
            if not depth and j < n and t[j] == '>':
                i = j + 1
                continue
        return i


def _eq_pairs(body: str) -> list[tuple[str, str]]:
    """The operands of each `==` / `!=` comparison, as `([&\\w.:()]+?)\\s*[!=]=\\s*([&\\w.:()]+)`
    pairs them (left to right, without overlap), read outward from each operator; a turbofish
    (`get::<K, Address>(&key)`) stays part of its operand."""
    t, out, last = body, [], 0
    for m in _EQ_OP.finditer(t):
        i = m.start()
        if i < last:
            continue
        j = i
        while j > last and t[j - 1].isspace():
            j -= 1
        r = _eq_operand(t, j, -1, last)
        if r == j:
            continue
        k = i + 2
        while k < len(t) and t[k].isspace():
            k += 1
        e = _eq_operand(t, k, 1, last)
        if e == k:
            continue
        out.append((t[r:j], t[k:e]))
        last = e
    return out


def _operand_before(t: str, j: int) -> str:
    """The operand `[A-Za-z_][\\w.]*(\\([^;{})]*\\))?` that ends at ``j``, starting as far left as the
    pattern allows ('' for none)."""
    def word_run(q):
        r = q
        while r > max(0, q - _SPAN) and (_word(t[r - 1]) or t[r - 1] == '.'):
            r -= 1
        return next((p for p in range(r, q) if _NAME_START.match(t[p])), -1)
    if j > 0 and t[j - 1] == ')':
        r = j - 1
        while r > max(0, j - 1 - _SPAN) and t[r - 1] not in ';{})':
            r -= 1
        for q in range(r, j - 1):
            if t[q] == '(':
                p = word_run(q)
                if 0 <= p < q:
                    return t[p:j]
        return ''
    p = word_run(j)
    return t[p:j] if 0 <= p < j else ''


def _comparisons(body: str) -> list[tuple[str, str, str, str]]:
    """Each `<`/`>` comparison as (left word, operand after, word after, operand before): the two
    shapes _monotonic reads (`alias < other`, `other < alias`)."""
    def compute():
        t, n, out = body, len(body), []
        for m in _CMP_OP.finditer(t):
            o = m.start()
            j = o
            while j > 0 and t[j - 1].isspace():
                j -= 1
            w = j
            while w > 0 and _word(t[w - 1]):
                w -= 1
            left = t[w:j] if w < j and not (w and (_word(t[w - 1]) or t[w - 1] == '.')) else ''
            k = o + 1 + (o + 1 < n and t[o + 1] == '=')
            while k < n and t[k].isspace():
                k += 1
            if k < n and t[k] == '&':
                k += 1
                while k < n and t[k].isspace():
                    k += 1
            operand = _OPERAND.match(t, k)
            e = k
            while e < n and _word(t[e]):
                e += 1
            out.append((left, operand.group() if operand else '', t[k:e], _operand_before(t, j)))
        return out
    return _memo(body, 'comparisons', compute)


class SorobanRules:
    """Runs every rule over the contract sources of one audit."""

    def __init__(self, auditor, files: dict[str, str], *, loose: bool = False, templates: set[str] = frozenset(),
                 limits_declared: bool = False, masked: dict[str, str] | None = None,
                 context: dict[str, str] | None = None):
        """``context`` is every file of the audit (for the modules that declare test files)."""
        self.auditor = auditor
        masked = masked or {}
        #: Test code (mock contracts) is never deployed: no rule judges it, and its helpers do
        #: not stand in for the contract's. Whole test files are left out here, and inline
        #: #[cfg(test)] modules are blanked by _Crate.
        self.tests = cfg_test_files({**(context or {}), **files}, masked)
        self.sources = {n: t for n, t in files.items() if n not in self.tests}
        self.crate = _Crate(self.sources, loose, set(templates), masked)
        self.limits_declared = limits_declared
        self.findings: list[Finding] = []
        self._by_id: dict[str, int] = {}
        #: (file, fn) judged here; ST-001 does not report them again.
        self.claimed: set[tuple[str, str]] = set()
        #: Initializers anyone can call again: stellar_native folds them into soroban-auth-missing.
        self.reinit: list[_Fn] = []
        #: Accounts that hand __check_auth to a library: input for the advisory version check.
        self.library_auth: list[str] = []
        self._memo: dict = {}

    # ------------------------------------------------------------------ helpers
    def _once(self, key, compute):
        if key not in self._memo:
            self._memo[key] = compute()
        return self._memo[key]

    def _has(self, fn: _Fn, pattern: re.Pattern) -> bool:
        """``pattern`` occurs in the function's body (remembered per function)."""
        return self._once(('has', id(fn), pattern), lambda: bool(pattern.search(fn.body)))

    def _first(self, fn: _Fn, pattern: re.Pattern):
        return self._once(('first', id(fn), pattern), lambda: pattern.search(fn.body))

    def _emit(self, rule: str, severity: Severity, title: str, detail: str, fn: _Fn, offset: int | None, snippet: str,
              remediation: str, *, grade: EvidenceGrade = EvidenceGrade.CONFIRMED, gap: bool = False,
              confidence: float = 0.85, claim: bool = True) -> None:
        """Add a finding; ``claim`` (an authorization finding) keeps ST-001 from reporting the
        function again. The same defect found twice (cfg-gated impl blocks, a template's {{#if}}
        branches, both rendered) is one finding with both places as evidence."""
        if _SAMPLE_PATH.search(fn.file):
            severity = severity.downgrade(1)
        if fn.template:
            detail += " The file is a code-generator template, so this holds for every generated contract."
        line = fn.line if offset is None else fn.line_of(offset)
        finding = self.auditor.finding(
            stable_id(rule, fn.file, f"{fn.name}: {snippet}"), severity, title, detail,
            evidence=f"{fn.file}:{line} {fn.name}: {' '.join(snippet[:_ARG_TEXT].split())[:160]}",
            remediation=remediation, grade=grade, confidence=confidence)
        if gap:
            finding = finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP})
        if claim:
            self.claimed.add((fn.file, fn.name))
        seen = self._by_id.get(finding.id)
        if seen is None:
            self._by_id[finding.id] = len(self.findings)
            self.findings.append(finding)
            return
        first = self.findings[seen]
        keep, other = ((finding, first) if (finding.severity.rank, finding.is_risk) > (first.severity.rank, first.is_risk)
                       else (first, finding))
        if other.evidence not in keep.evidence:
            keep = keep.model_copy(update={"evidence": (keep.evidence + "; " + other.evidence)[:2000]})
        self.findings[seen] = keep

    def _authed(self, fn: _Fn, names: set[str]) -> bool:
        """require_auth[_for_args] on one of ``names`` (or on a local struct's field set from one),
        directly or in a helper that receives it, or ``names`` handed to code outside the crate (a
        library that may authorize it)."""
        key = ('authed', id(fn), frozenset(names))
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = result = self._authorizes(fn, names)
        return result

    def _authorizes(self, fn: _Fn, names: set[str]) -> bool:
        body = fn.body
        direct, _, fields = _auth_receivers(body)
        if names & direct:
            return True
        if any(root in names and (var, f) in fields for (var, f), root in _fields(body).items()):
            return True
        for s in fn.sites:
            if not any(_root(a) in names for a in _args(body, s.paren)):
                continue
            if s.segment and _LOWER_SEGMENT.fullmatch(s.segment) and _LOWER_START.match(s.name):
                return True  # a module function such as spending_limit::enforce(..., &smart_account)
            # Type::f reaches the crate only through an impl of that type (or Self).
            typed = s.segment if s.segment and _TYPE_SEGMENT.fullmatch(s.segment) and _LOWER_START.match(s.name) else ''
            helpers = [h for h in self.crate.resolve(s.name, fn.file) if h is not fn
                       and (not typed or typed in {'Self', h.owner})]
            if any(id(h) in self.crate.auth for h in helpers):
                return True
            if typed and not helpers and s.name != 'new' and typed not in _SDK_TYPES | {'Self'}:
                return True  # a library type such as OpenZeppelin's Base::burn(e, &from, ..), which authorizes
        return False

    def _scope(self, fn: _Fn) -> list[_Fn]:
        return [fn] + self.crate.reach(fn)

    def _token_client(self, fn: _Fn, receiver: str, depth: int = 0) -> bool:
        """``receiver`` is a contract client (token::Client::new(..), a variable or parameter
        holding one, a crate helper that returns one), not an event publisher such as
        soroban-token-sdk's `TokenUtils::new(&e).events()`."""
        key = ('client', id(fn), receiver, depth)
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = result = self._is_client(fn, receiver, depth)
        return result

    def _is_client(self, fn: _Fn, receiver: str, depth: int) -> bool:
        if _EVENTS.search(receiver) or depth > 3:
            return False
        if _CLIENT_NEW.search(receiver):
            return True
        head = _CLIENT_HEAD.match(receiver)
        if not head:
            return False
        name = head.group(1)
        if head.group(2):
            return any('Client' in h.ret for h in self.crate.resolve(name, fn.file))
        if 'Client' in fn.params.get(name, ''):
            return True
        return any((kind and 'Client' in kind) or self._token_client(fn, expr, depth + 1)
                   for kind, expr in _typed_lets(fn.body).get(name, ()))

    def _moves(self, fn: _Fn, methods: str = 'transfer_from|transfer|burn|mint') -> list[re.Match]:
        """Token-moving calls on a contract client in ``fn``'s body."""
        moves = self._once(('moves', id(fn)), lambda: [m for m in _MOVE.finditer(fn.body)
                                                         if self._token_client(fn, _receiver(fn.body, m.start()))])
        return [m for m in moves if re.fullmatch(methods, m.group(1))]

    def _strong(self, fn: _Fn) -> bool:
        return self._once(('strong', id(fn)), lambda: self._is_strong(fn))

    def _is_strong(self, fn: _Fn) -> bool:
        if fn.name == '__constructor' or _STRONG_ATTR.search(fn.attrs) or _STRONG_CALL.search(fn.body):
            return True
        if self.crate._strong_receiver(fn.body) or self.crate.calls(fn, self.crate.strong):
            return True
        # A caller that authorizes and is checked against the stored owner is the owner.
        compared = self.crate.compared(fn.body)
        if any(p in compared and self._authed(fn, _aliases(fn.body, {p})) for p in fn.params):
            return True
        # #[has_role(p, ..)] plus p.require_auth() is what #[only_role] expands to.
        role = _ROLE_ATTR.search(fn.attrs)
        return bool(role and self._authed(fn, {role.group(1)}))

    def _weak(self, fn: _Fn) -> bool:
        """Authorization that may be the administrator's but is not shown to be: an auth helper, an
        unknown admin/owner/role attribute, a caller parameter handed to a role, ownership or
        store lookup, or a caller parameter compared with a stored address."""
        return self._once(('weak', id(fn)), lambda: self._is_weak(fn))

    def _is_weak(self, fn: _Fn) -> bool:
        callers = {p for p, t in fn.params.items() if not re.search(r'\bEnv\b', t) and p != 'self'}
        if self.crate.calls(fn, self.crate.auth) or _WEAK_ATTR.search(fn.attrs):
            return True
        for s in fn.sites:
            if s.name in self.crate.store or (s.segment and _ROLE_LIBRARY.search(s.segment)):
                if any(_root(a) in callers for a in _args(fn.body, s.paren)):
                    return True
        return bool(self.crate.compared(fn.body) & callers)

    # ------------------------------------------------------------------ run
    def _is_policy(self, fn: _Fn) -> bool:
        return ((fn.name == 'enforce' and ('Policy' in fn.trait or {'smart_account', 'authenticated_signers'} <= set(fn.params)))
                or (fn.name == 'policy__' and len(fn.params) >= 4))

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
        self.claimed.add((fn.file, fn.name))
        if any(self._has(f, _DO_CHECK_AUTH) for f in scope):
            self.library_auth.append(f"{fn.file}:{fn.line}")
            return
        delegated = any(self._has(f, _DELEGATE) for f in scope)
        payload_read = _uses(fn.body, _aliases(fn.body, {payload}))
        signer_names = _aliases(fn.body, {signature})
        auths = any(root not in signer_names for f in scope for root, _ in _auth_roots(f.body))
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
        tx = _text(fn.body)
        handed = [(a, b) for s in fn.sites if s.crate and self.crate.resolve(s.name, fn.file)
                  for a, b in tx.spans(s.paren) if _root(tx.part(a, b)) in context_names]
        direct = _blank_spans(fn.body, handed)
        read = _uses(direct, context_names) or any(_uses(h.body, _aliases(h.body, got))
                                                    for h, got in self.crate.bound(fn, context_names))
        if not read and not delegated and self._restricts(fn.file):
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

    def _restricts(self, file: str) -> bool:
        return self._once(('restricts', file), lambda: bool(_RESTRICTS.search(_without_attributes(self.crate.code[file]))))

    def _rejects(self, body: str) -> bool:
        """The context check rejects what it does not list: `fn_name != x { .. Err/panic }`,
        `!list.contains(.. fn_name ..) { .. Err/panic }`, or `match fn_name { .., _ => Err/panic }`."""
        def compute():
            tx = _text(body)

            def rejecting_block(after: int) -> bool:  # `[^{;]*\{[^{}]*(?:\bErr\s*\(|panic)`
                stop = tx.next_stop(after)
                return stop < tx.n and body[stop] == '{' and tx.has(_ERR_OR_PANIC, stop + 1, tx.next_brace(stop + 1))
            if any(rejecting_block(e) for e in tx.found(_DENY_NE)[1]):
                return True
            words, ends = tx.found(_DENY_WORD)
            rejecting = [w for w, e in zip(words, ends) if rejecting_block(e)]
            for c in _CONTAINS.finditer(body):
                j = c.start()
                while j > 0 and body[j - 1].isspace():
                    j -= 1
                r = j
                while r > 0 and (_word(body[r - 1]) or body[r - 1] == '.'):
                    r -= 1
                q = r
                while q > 0 and body[q - 1].isspace():
                    q -= 1
                if r == j or q == 0 or body[q - 1] != '!':
                    continue
                k = bisect_left(rejecting, c.end())
                if k < len(rejecting) and rejecting[k] < tx.next_rparen(c.end()):
                    return True
            for start, head_end, brace in _headed(body, _MATCH_HEAD):
                if _DENY_WORD.search(body, head_end, brace) and tx.has(_WILD_REJECT, brace, tx.end(brace)):
                    return True
            return False
        return _memo(body, 'rejects', compute)

    def _deny_list(self, fn: _Fn, scope: list[_Fn]) -> None:
        """C3: unmatched contracts or functions fall through to approval, and nothing else in the
        check rejects them."""
        if any(self._rejects(f.body) for f in scope):
            return
        for f in scope:
            body, tx = f.body, _text(f.body)
            for start, head_end, brace in _headed(body, _IF_HEAD):
                if not tx.has(_DENY_NE, head_end, brace):
                    continue
                close = tx.end(brace)
                if tx.has(_CONTINUE_OR_OK, brace, close) and not tx.has(_ERR_OR_PANIC, brace, close):
                    self._deny(fn, f, start, body[start:brace + 1])
                    return
            for start, head_end, brace in _headed(body, _MATCH_HEAD):
                if not _DENY_WORD.search(body, head_end, brace) or _CONTEXT_WORD.search(body, head_end, brace):
                    continue
                close = tx.end(brace)
                k = tx.first(_WILD_APPROVE, brace, close)
                if k >= 0:
                    starts, ends = tx.found(_WILD_APPROVE)
                    self._deny(fn, f, start, body[start:brace + 1] + ' .. ' + body[starts[k]:ends[k]])
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

    def _own_setters(self, file: str) -> list[_Fn]:
        """Entry points of ``file`` that require the contract's own authorization and write storage."""
        self_auth = re.compile(_SELF.pattern + r'\s*\.\s*require_auth')
        return self._once(('own', file), lambda: [f for f in self.crate.fns if f.file == file and f.entry
                                                   and self_auth.search(f.body) and _STORE_WRITE.search(f.body)])

    def _self_admin(self, fn: _Fn, scope: list[_Fn]) -> None:
        """C7: a call to the account itself (its own limit setters) passes on the spending key."""
        own = self._own_setters(fn.file)
        if not own or len(_VERIFY.findall(fn.body)) > 1 or _MULTISIG.search(fn.body):
            return
        # Signatures verified in a loop: several keys sign, not one spending key.
        if any(_in_loop(f.body, v.start()) for f in scope for v in islice(_VERIFY.finditer(f.body), _MAX_SITES)):
            return
        if not any(self._has(f, _TRANSFER_OR_AMOUNT) for f in scope):
            return  # nothing is spent on this path, so there is no limit to rewrite
        params = list(fn.params)
        signed = _aliases(fn.body, {params[1], params[2]})
        selfs = _aliases(fn.body, set(_SELF_LETS.findall(fn.body)))
        for f in scope:
            names = selfs if f is fn else {p for h, got in self.crate.bound(fn, selfs) if h is f for p in got} | selfs
            selves = '|'.join([_SELF.pattern] + [re.escape(n) for n in sorted(names)])
            pattern = re.compile(r'\b(?:\w+\s*\.\s*)?contract\s*==\s*(?:&\s*)?(?:' + selves + r')(?!\w)|'
                                 r'(?:' + selves + r')\s*==\s*(?:&\s*)?(?:\w+\s*\.\s*)?contract\b')
            tx = _text(f.body)
            others = signed | {p for h, got in self.crate.bound(fn, signed) if h is f for p in got}
            used = re.compile(r'(?<![\w.])(?:' + '|'.join(map(re.escape, sorted(others))) + r')\b') if others else None
            for m in islice(pattern.finditer(f.body), _MAX_SITES):
                end = tx.next_lbrace(m.end())
                if end >= tx.n:
                    continue
                close = tx.end(end)
                # A self-call branch that checks another signature or address is not the spending key alone.
                extra = tx.has(_SELF_ADMIN_EXTRA, end, close) or (used is not None and tx.has(used, end, close))
                if tx.has(_OK_UNIT, end, close) and not extra:
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

    def _running_total(self, fn: _Fn) -> bool:
        """The policy keeps a stored running total: its scope reads storage, adds the amount and
        writes storage back."""
        scope = self._scope(fn)
        return (any(self._has(f, _ACCUMULATES) for f in scope) and any(self._has(f, _STORE_READ) for f in scope)
                and any(self._has(f, _STORE_WRITE) for f in scope))

    def _paired_policy(self, fn: _Fn) -> bool:
        """Another policy contract of the audit keeps a stored running total: a per-call cap here
        is the per-transaction half of a pair."""
        totals = self._once(('totals',), lambda: {(g.file, g.owner) for g in self.crate.fns
                                                  if self._is_policy(g) and self._running_total(g)})
        return len(totals) > 1 or (bool(totals) and (fn.file, fn.owner) not in totals)

    def _caps(self, fn: _Fn, scope: list[_Fn], policy: bool) -> None:
        """C6 and C8: an amount cap per call, without a running total or without a lower bound."""
        if not any(self._has(f, _ARGS_WORD) for f in scope):
            return
        cap = where = None
        for f in scope:
            cap = self._once(('cap', id(f)), lambda: _cap_match(f.body))
            if cap:
                where = f
                break
        if not cap:
            return
        start, end, var = cap
        snippet = where.body[start:end]
        grade = EvidenceGrade.CONFIRMED if where is fn else EvidenceGrade.INFERRED
        if any(self._has(f, _ACCUMULATES) for f in scope):
            lower = any(self._has(f, _LOWER_BOUND) for f in scope)
            if not lower and any(self._has(f, _STORE_WRITE) for f in scope):
                self._emit("soroban-policy-negative-amount", Severity.MEDIUM,
                           "A negative amount lowers the running spend total",
                           "The amount taken from the authorized call's arguments is checked only against an upper bound "
                           "and then added to a stored running total. A context with a negative amount (any contract's "
                           "`transfer` that accepts one) reduces the total, so later transfers can exceed the limit.",
                           where, start, snippet,
                           "Reject amounts below zero (and zero) before adding them to the running total.", grade=grade)
            return
        severity, note = (Severity.MEDIUM if policy else Severity.LOW), ""
        if policy:
            # Blind adjudication: a deliberate per-transaction cap deployed beside a rolling-total
            # policy is one half of a pair, not a missing total.
            if self._paired_policy(fn):
                return
            raw = self.sources.get(fn.file, '')
            if _SPENDING_POLICY_DOC.search(raw) and (_PER_TX_DOC.search(raw) or _PER_TX_NAME.search(f"{fn.owner} {fn.file}")):
                severity = Severity.INFO
                note = (" The contract documents itself as a per-transaction cap used together with a spending-limit "
                        "policy; that policy, attached to the same context rule, is what bounds the total.")
        self._emit("soroban-policy-per-call-cap", severity,
                   "The on-chain amount limit is per call, with no running total",
                   f"The {'policy' if policy else '__check_auth'} compares `{var}` from the authorized call against a "
                   "cap, but keeps no stored total of what was spent. Repeating capped calls (or several contexts in "
                   "one transaction) moves any amount, so the cap bounds one transfer, not the agent's spending." + note,
                   where, start, snippet,
                   "Keep a persistent per-window total (read, add, compare, write) and check the cap against it.",
                   grade=grade)

    def _enforce(self, fn: _Fn) -> None:
        """C4 and C5 for OpenZeppelin smart-account policies."""
        self.claimed.add((fn.file, fn.name))
        account = next((p for p in fn.params if 'account' in p and 'Address' in fn.params[p]), None)
        signers = next((p for p in fn.params if 'signers' in p), None)
        scope = self._scope(fn)
        if account and not self._authed(fn, _aliases(fn.body, {account})):
            writes = any(self._has(f, _STORE_WRITE) for f in scope)
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
        write = next(((f, m) for f in scope for m in [self._first(f, _STORE_WRITE)] if m), None)
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
        receivers = {root for root, dotted in _auth_roots(body) if not dotted}
        weak = self._weak(fn)
        offset = sink.start() if sink else via.start
        semi = body.find(';', offset)
        snippet = body[offset:semi if semi > 0 else offset + 80]
        grade = EvidenceGrade.CONFIRMED if sink else EvidenceGrade.INFERRED
        if receivers and receivers <= params:
            # The only authorization is the caller's own: unless the parameter decides something
            # else, anyone passes their own address and signs.
            rest = body
            for n in receivers:
                rest = _drop_to_semi(rest, re.compile(r'(?<![\w.])' + re.escape(n) + r'\s*\.\s*require_auth(?:_for_args)?\s*\('))
            rest = _drop_statements(_drop_statements(rest, _ANY_SINK), _EMIT)
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
        selfs = _aliases(body, set(_SELF_LETS.findall(body)))
        moves = self._moves(fn)
        tx = _text(body)
        for m in moves:
            if m.group(1) == 'mint':
                continue
            args = tx.args(m.end() - 1)
            pull = m.group(1) == 'transfer_from'
            if len(args) < (4 if pull else 2):
                continue
            src = _root(args[1] if pull else args[0])
            owner = next((p for p in addresses if src in _aliases(body, {p})), None)
            if not owner or src in selfs or self._authed(fn, _aliases(body, {owner})):
                continue
            snippet = body[m.start():min(tx.end(m.end() - 1), m.start() + _ARG_TEXT)]
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
            for a in _AUTH.finditer(body):
                chain = _receiver(body, a.start())
                head = _ROOT_AT.match(chain)
                field_name = _FIELD_AT.match(chain, head.end()) if head else None
                if head and fields.get((head.group(1), field_name.group(1) if field_name else '')) not in owners \
                        and head.group(1) not in owners:
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
        owners = _aliases(fn.body, {owner})
        handed = any(_root(a) in owners for s in fn.sites if s.crate and self.crate.resolve(s.name, fn.file)
                     for a in _args(fn.body, s.paren))
        self._emit("soroban-token-move-allowance", Severity.CRITICAL,
                   "Anyone can spend the allowances users gave this contract",
                   f"transfer_from moves tokens from `{owner}` to `{dest}`, both chosen by the caller, "
                   f"with this contract as the spender, and `{owner}` never authorizes the call. Anyone can "
                   "drain every account that approved this contract to an address of their choice.",
                   fn, m.start(), snippet,
                   f"Call {owner}.require_auth() before transfer_from, or take the source from storage.",
                   gap=handed, grade=EvidenceGrade.INFERRED if handed else EvidenceGrade.CONFIRMED)

    def _payments(self, fn: _Fn) -> list[tuple[int, int, str]]:
        """(start, after '(', source variable) of each transfer, transfer_from, approve or burn_from
        on a token client: the calls whose recipient and amount an authorization should cover."""
        def compute():
            out, tx = [], _text(fn.body)
            for c in _PAYMENT.finditer(fn.body):
                if not self._token_client(fn, _receiver(fn.body, c.start())):
                    continue
                args = tx.args(c.end() - 1)
                index = 1 if c.group(1) in {'transfer_from', 'burn_from'} else 0
                out.append((c.start(), c.end(), _root(args[index]) if len(args) > index else ''))
            return out
        return self._once(('payments', id(fn)), compute)

    def _auth_args(self, fn: _Fn) -> None:
        """D: the address whose tokens move signs with require_auth_for_args over a list that leaves
        out the recipient or the amount. Another signer's partial authorization (an oracle signing
        its price) is not this defect, and neither is a source that also gives a full
        require_auth()."""
        body = fn.body
        tx = _text(body)
        _, plain, _ = _auth_receivers(body)
        for m in islice(_AUTH_FOR_ARGS.finditer(body), _MAX_SITES):
            signer = _root(_receiver(body, m.start()))
            signers = _aliases(body, {signer}) if signer else set()
            if not signers or signers & plain:
                continue
            args = body[m.end():min(tx.end(m.end() - 1) - 1, m.end() + _ARG_TEXT)]
            if re.fullmatch(r'\s*(?:&\s*)?[A-Za-z_]\w*\s*', args):
                bound = re.compile(r'\blet\s+(?:mut\s+)?' + re.escape(args.strip(' &')) + r'\b[^=;]{0,256}=\s*([^;]*);').search(
                    body, 0, m.start())
                if not bound:
                    continue
                args = bound.group(1)
            moved = ' '.join(body[c_end:min(tx.end(c_end - 1), c_end + _ARG_TEXT)]
                             for c_start, c_end, source in self._payments(fn) if c_start > m.end() and source in signers)
            missing = [p for p in fn.params_of(r'\bAddress\b')
                       if re.fullmatch(r'to|recipient|dest|destination|spender|receiver|payee', p)
                       and _uses(moved, {p}) and not _uses(args, _aliases(body, {p}))]
            missing += [p for p in fn.params_of(r'^i128$') if _uses(moved, {p}) and not _uses(args, _aliases(body, {p}))]
            if missing:
                self._emit("soroban-auth-args-incomplete", Severity.HIGH,
                           "The authorized arguments leave out where the tokens go or how many",
                           "require_auth_for_args signs over a list that omits " + ", ".join(f"`{p}`" for p in missing) +
                           ", which the function then uses to move the signer's tokens. A signature for one call can be "
                           "submitted with a different recipient or amount.",
                           fn, m.start(), body[m.start():min(tx.end(m.end() - 1), m.start() + _ARG_TEXT)],
                           "Include every argument that decides the payment (recipient and amount) in "
                           "require_auth_for_args, or use require_auth(), which covers all arguments.")
                return

    def _amount_checks(self, fn: _Fn) -> None:
        """V: funding entry points that take any amount, or a deadline nothing checks."""
        if not re.match(r'(?:create|deposit|lock|open|fund|escrow)', fn.name):
            return
        body = fn.body
        tx = _text(body)
        problems = []
        for p in fn.params_of(r'^i128$'):
            if not re.search(r'amount|deposit|value', p):
                continue
            names = _aliases(body, {p})
            if not any(_uses(body[c.end():min(tx.end(c.end() - 1), c.end() + _ARG_TEXT)], names)
                       for c in self._moves(fn, 'transfer|transfer_from')):
                continue
            alt = '|'.join(map(re.escape, names))
            checked = re.search(rf'\b(?:{alt})\s*(?:<=?|>=?)\s*[01]\b|\b[01]\s*(?:<=?|>=?)\s*(?:{alt})\b|'
                                rf'\b(?:{alt})\s*\.\s*(?:is_positive|is_negative|signum)', body) or any(
                re.search(r'(?:<=?|>=?)\s*[01]\b|\b[01]\s*(?:<=?|>=?)|is_positive|is_negative', h.body)
                for h, _ in self.crate.bound(fn, names)) or _lower_bounded(body, alt)
            if not checked:
                problems.append((p, f"`{p}` is never required to be positive"))
        for p in fn.params:
            if re.search(r'deadline|expir|valid_until|timeout', p) and p not in self._ledger_names(fn.file):
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
        verify = next(((f, m) for f in scope for m in [self._first(f, _VERIFY)] if m), None)
        if not verify or not any(self._has(f, _MUTATION) or self._has(f, _STORE_WRITE) for f in scope):
            return
        if any(self._has(f, _REPLAY_WORDS) or self._has(f, _LEDGER_OR_HAS) for f in scope):
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
        tx = _text(body)
        writes = {}
        for m in _STORE_WRITE_CALL.finditer(body):
            writes.setdefault(tx.next_semi(m.end()), m.end())
        for p in fn.params:
            names = _aliases(body, {p})
            used = re.compile(r'(?<![\w.])(?:' + '|'.join(map(re.escape, sorted(names))) + r')\b')
            starts = [m.start() for m in used.finditer(body)]
            if not any(bisect_left(starts, a) < len(starts) and starts[bisect_left(starts, a)] < semi
                       for semi, a in writes.items()):
                continue
            for left, after, right, before in _comparisons(body):
                for other in ([after] if left in names else []) + ([before] if right in names else []):
                    if other and (_STORE_READ.search(other) or self.crate._stored(body, _root(other) or other.split('.')[0])):
                        return True
        return False

    def _ledger_names(self, file: str) -> set[str]:
        """Words compared (in one statement) with env.ledger() or a variable read from it, on either
        side of a `<` or `>`: the deadlines the file checks."""
        def compute():
            code = self.crate.code[file]
            tx = _text(code)
            lstarts, lends = tx.found(_LEDGER)
            clocks, pos = set(), 0
            for m in _LET_HEAD.finditer(code):
                if m.start() < pos:
                    continue
                semi = tx.next_semi(m.end())
                k = bisect_right(lends, semi) - 1
                if k >= 0 and lstarts[k] >= m.end():
                    clocks.add(m.group(1))
                    pos = lends[k]
                else:
                    pos = semi  # every later let of this statement fails the same way
            spans = list(zip(lstarts, lends))
            if clocks:
                spans += [(m.start(), m.end()) for m in re.finditer(r'\b(?:' + '|'.join(map(re.escape, sorted(clocks))) + r')\b', code)]
            spans.sort()
            ops = [m.start() for m in _CMP_OP.finditer(code)]
            words = [(m.start(), m.end(), m.group()) for m in re.finditer(r'\w+', code)]
            word_starts = [w[0] for w in words]
            names, edges = set(), [-1] + tx.bounds + [tx.n]
            span_starts = [s for s, _ in spans]
            for a, b in zip(edges, edges[1:]):
                a += 1
                if b - a < 3:
                    continue
                inside = spans[bisect_left(span_starts, a):bisect_left(span_starts, b)]
                inside = [(s, e) for s, e in inside if e <= b]
                if not inside:
                    continue
                stmt_ops = ops[bisect_left(ops, a):bisect_left(ops, b)]
                if not stmt_ops:
                    continue
                # name .. op .. clock: every word that ends before the last op some clock follows.
                last_clock = inside[-1][0]
                forward = [o for o in stmt_ops if o < last_clock]
                lo, hi = bisect_left(word_starts, a), bisect_left(word_starts, b)
                if forward:
                    names |= {w for s, e, w in words[lo:hi] if e <= forward[-1]}
                # clock .. op .. name: every word that starts after the first op some clock precedes.
                first_end = min(e for _, e in inside)
                backward = [o for o in stmt_ops if o >= first_end]
                if backward:
                    names |= {w for s, e, w in words[lo:hi] if s > backward[0]}
            return names
        return self._once(('ledger', file), compute)

    def _initializer(self, fn: _Fn) -> None:
        """I: an initializer with no once-only guard can be called again by anyone, and what it
        writes decides authorization elsewhere (an administrator, an authorized oracle)."""
        if not re.fullmatch(r'init(?:ialize)?', fn.name) or fn.file in self.crate.constructors:
            return
        if not _STORE_WRITE.search(fn.body) or self._strong(fn) or self._once_only(fn):
            return
        keys = set(_SET_KEY.findall(fn.body))
        readers = self._key_readers(fn.file)
        if any(f is not fn for k in keys for owner in {fn.owner, ''} for f in readers.get((k, owner), ())):
            self.reinit.append(fn)

    def _key_readers(self, file: str) -> dict[tuple[str, str], list[_Fn]]:
        """(storage key, impl type) -> the functions of ``file`` that read that key and decide with it
        (require_auth, a comparison, an assert or a panic)."""
        def compute():
            out: dict[tuple[str, str], list[_Fn]] = {}
            for f in self.crate.fns:
                if f.file != file or not (_AUTH.search(f.body) or _DECIDES.search(f.body)):
                    continue
                for m in _GET_KEY.finditer(f.body):
                    for key in {m.group(1), m.group(2)} - {None}:
                        bucket = out.setdefault((key, f.owner), [])
                        if not bucket or bucket[-1] is not f:
                            bucket.append(f)
            return out
        return self._once(('readers', file), compute)

    def _once_only(self, fn: _Fn) -> bool:
        """Something before the first storage write refuses a second run: a has()/is_some()
        test, or a condition (if, match, assert!) that reads stored state, directly, through a
        variable, or through a has_*/get_*/store helper, and rejects (or writes only once); or a
        crate helper called first that reads storage and rejects."""
        body = fn.body
        if _ONCE_HINT.search(body):
            return True
        first = _STORE_WRITE.search(body).start()
        tx = _text(body)
        lets: dict[str, list[tuple[int, int]]] = {}
        for m in _STATE_LET.finditer(body, 0, first):
            semi = tx.next_semi(m.end())
            if semi < first:
                lets.setdefault(m.group(1), []).append((m.end(), min(semi, m.end() + _ARG_TEXT)))
        memo: dict = {}

        def state(a: int, e: int, depth: int = 0) -> bool:
            key = (a, e, depth)
            if key in memo:
                return memo[key]
            memo[key] = False
            found = tx.has(_STORE_READ, a, e) or tx.has(_STORAGE_CALL, a, e)
            if not found:
                # Functions, not methods on a value.
                for s in tx.sites[bisect_left(tx.site_starts, a):bisect_left(tx.site_starts, e)]:
                    if s.paren < e and s.function and (_STATE_NAME.match(s.name) or s.name in self.crate.store):
                        found = True
                        break
            if not found and depth < 2:
                found = any(state(ba, be, depth + 1) for v in set(_IDENT.findall(body, a, e)) for ba, be in lets.get(v, ()))
            memo[key] = found
            return found

        for start, head_end, brace in _headed(body, _IF_OR_MATCH_HEAD, end=first):
            close = tx.end(brace)
            if (tx.has(_REJECT, brace, close) or close > first) and state(head_end, brace):
                return True
        for m in _GUARD_MACRO.finditer(body, 0, first):
            if state(m.end(), min(tx.end(m.end() - 1) - 1, m.end() + _ARG_TEXT)):
                return True
        return any(self._once(('rejecting-store', id(h)), lambda h=h: bool(_STORE_READ.search(h.body) and _FAILS.search(h.body)))
                   for s in fn.sites if s.crate and s.paren < first for h in self.crate.resolve(s.name, fn.file) if h is not fn)

    # ------------------------------------------------------------ instance storage (S)
    def _holds_tokens(self, file: str) -> bool:
        """A transfer in ``file`` names the contract itself (not an event): it holds tokens."""
        def compute():
            code = self.crate.code.get(file, '')
            tx = _text(code)
            starts, ends = tx.found(_SELF)
            pos = 0
            for m in _TRANSFER_OPEN.finditer(code):
                if m.start() < pos:
                    continue
                semi = tx.next_semi(m.end())
                k = bisect_right(ends, semi) - 1
                if k < 0 or starts[k] < m.end():
                    pos = semi  # no later transfer of this statement names the contract either
                    continue
                if not _EVENTS.search(_receiver(code, m.start())):
                    return True
                pos = ends[k]
            return False
        return self._once(('holds', file), compute)

    def _innermost(self, file: str, offset: int) -> _Fn | None:
        """The innermost function of ``file`` whose body holds ``offset``."""
        fns = self._once(('file-fns', file), lambda: sorted((f for f in self.crate.fns if f.file == file),
                                                            key=lambda f: f.body_start))
        starts = self._once(('file-starts', file), lambda: [f.body_start for f in fns])
        k = bisect_right(starts, offset) - 1
        while k > 0 and starts[k - 1] == starts[k]:
            k -= 1
        f = fns[k] if k >= 0 else None
        while f is not None and not (f.body_start <= offset < f.body_start + len(f.body)):
            f = f.parent
        return f

    def open_writer(self, file: str, offset: int) -> bool:
        """The instance write at ``offset`` creates a record (it does not first load the same key)
        in an entry point any caller can reach (no stored administrator authorizes it), in a
        contract that holds tokens."""
        code = self.crate.code.get(file, '')
        family = re.match(r'[^&]*&\s*((?:\w+\s*::\s*)?\w+)\s*\(', code[offset:offset + 200])
        if not self._holds_tokens(file) or not family:
            return False
        fn = self._innermost(file, offset)
        if fn is None:
            return False
        loads = re.compile(r'\.\s*(?:get|has)\s*(?:::<[^>]{0,256}>\s*)?\(\s*&\s*' + re.escape(family.group(1)) + r'\s*\(')
        if self._once(('loads', id(fn), family.group(1)), lambda: any(loads.search(f.body) for f in self._scope(fn))):
            return False
        callers = [fn] if fn.entry else self._once(
            ('callers', id(fn)), lambda: [f for f in self.crate.fns if f.entry and f.file == file and self.crate.calls(f, {id(fn)})])
        return any(not self._strong(f) for f in callers)


def _lower_bounded(body: str, alt: str) -> bool:
    """An amount is held to a lower bound: `if amount < MIN { panic }`, `assert!(amount >= min)`."""
    tx = _text(body)
    comparison = re.compile(rf'(?:\b(?:{alt})\s*>|<=?\s*(?:&\s*)?(?:{alt})\b)')
    seen = set()
    for m in _GUARD_MACRO.finditer(body):
        semi = tx.next_semi(m.end())
        if semi in seen:
            continue  # an earlier macro of this statement searched the same text
        seen.add(semi)
        if comparison.search(body, m.end(), semi):
            return True
    lower = re.compile(rf'\b(?:{alt})\s*<|>=?\s*(?:&\s*)?(?:{alt})\b')
    for start, head_end, brace in _headed(body, _IF_HEAD):
        if lower.search(body, head_end, brace) and tx.has(_REJECT, brace, tx.end(brace)):
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
