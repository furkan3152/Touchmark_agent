"""Advisory matches that need the code as well as the version.

A lockfile can show that a repository installs soroban-sdk-macros 23.5.1, but the macro bug only
bites a contract that defines a trait function and an inherent function with the same name.
Each advisory in stellar/advisories.py names such a condition; this module tests it against the
source. A version that matches without its condition is reported as a fact to verify, never as
a risk. Known-bad smart-wallet WASM hashes are matched against the deployed code read from the
ledger and against hashes the code deploys wallets from.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from datetime import date
from functools import lru_cache
from pathlib import PurePosixPath

from ..models import AgentArtifact, EvidenceGrade, Finding, FindingKind, Severity
from ..services.lockfiles import Lockset, _directory, below, exact_pin
from ..stellar import advisories as adv
from .consolidate import stable_id
from .network_rules import mask
from .stellar_native import _FUNCTION, _rust_code, contract_sources
from .tmark_check import _MAINNET, network_hits

#: Lockfile names: a version read from one of them is what is installed.
_NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
_LOCKS = {"Cargo.lock"} | _NPM_LOCKS
_JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")
#: @stellar/mpp's own constants for the public network, next to the shared mainnet markers.
_MPP_MAINNET = re.compile(r"\b(?:STELLAR_PUBNET|USDC_SAC_MAINNET|XLM_SAC_MAINNET)\b|" + _MAINNET.pattern)
#: Tests, fixtures and mocks, and Rust targets that are separate crates (integration tests,
#: benches, fuzz targets) or test-only modules: none of it is deployed.
_TEST_FILE = re.compile(r"(?:^|/)(?:tests?|__tests__|__mocks__|mocks?|spec|e2e|fixtures?|fuzz|benches)/|"
                        r"[._-](?:test|spec)s?\.[cm]?[jt]sx?$|(?:^|/)(?:testutils?|test_?utils?)(?:/|\.rs$)|"
                        r"(?:^|/)tests?\.rs$|_tests?\.rs$")
#: A test module inside a source file: #[cfg(test)] mod tests { ... }.
_TEST_MODULE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*"
                          r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+\w+\s*\{")

_CONTRACTIMPL = re.compile(r"#\s*\[\s*contractimpl\b")
_IMPL = re.compile(r"\bimpl\s*(?:<[^>{;]*>\s*)?(?:(?P<trait>[\w:]+(?:<[^>{;]*>)?)\s+for\s+)?"
                   r"(?P<type>[A-Za-z_]\w*)(?:<[^>{;]*>)?\s*(?:where\b[^{;]*)?\{")
#: Bytes::slice and Vec::slice (u32 bounds), and Prng::gen_range (u64; rand's Rng::gen_range is not
#: affected) on env.prng() or on a name bound to it.
_SLICE = re.compile(r"\.\s*slice\s*\(")
_GEN_RANGE = re.compile(r"(?:\.\s*prng\s*\(\s*\)|\b([a-z_]\w*))\s*\.\s*gen_range\s*(?:::\s*<[^>]*>\s*)?\(")
#: Where the SDK's bare arithmetic wraps (soroban-sdk 22.0.8 bytes.rs, vec.rs, prng.rs; the
#: advisory's Detail): slice adds one to an Included end and an Excluded start, so each wraps at
#: u32::MAX; gen_range adds one to an Excluded start (wraps at u64::MAX) and subtracts one from
#: an Excluded end (wraps at 0). A half-open `a..b` ends Excluded(b); `a..=b` ends Included(b).
_WRAPS = {"slice": {"start": ("Excluded", 2**32 - 1), "end": ("Included", 2**32 - 1)},
          "gen_range": {"start": ("Excluded", 2**64 - 1), "end": ("Excluded", 0)}}
#: A bound written as an integer literal, or as the type's maximum.
_LITERAL = re.compile(r"^(\d[\d_]*)(?:_?u(?:32|64))?$")
_TYPE_MAX = re.compile(r"^(?:(?:core|std)\s*::\s*)?u(32|64)\s*::\s*MAX$")
#: std::ops::Bound, written with or without its path (only the last segment is read).
_BOUND = re.compile(r"\bBound\s*::\s*(Included|Excluded|Unbounded)\b")
#: A range argument longer than this, or wrapped in more redundant parentheses, is not read: its
#: bounds count as not visible, as those of a range held in a variable do.
_RANGE_CHARS, _RANGE_PARENS = 400, 8
_PRNG_BINDING = re.compile(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*(?::[^=;]*)?=[^;]*\.\s*prng\s*\(\s*\)\s*;|"
                           r"\b([a-z_]\w*)\s*:\s*&?\s*(?:[\w:]*::)?Prng\b")
_FR_IMPORT = re.compile(r"\b(?:bn254|bls12_381)\s*::\s*(?:\{[^}]*\bFr\b|Fr\b)")
_FR_BINDING = re.compile(r"\b([a-z_]\w*)\s*:\s*&?\s*(?:[\w:]*::)?Fr\b|"
                         r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*(?::[^=;]*)?=\s*(?:[\w:]*::)?Fr\s*::")
_DELEGATED = re.compile(r"\bSigner\s*::\s*Delegated\s*\(")
_POLICY_SIGNER = re.compile(r"\baddPolicy\s*\(|\bSignerKey\s*\.\s*Policy\b|\bPolicySigner\b|\bfn\s+policy__\s*\(")
_MPP_SERVER_IMPORT = re.compile(
    r"""import\s*(?:\{(?P<names>[^}]*)\}|\*\s*as\s+(?P<ns>[\w$]+))\s*from\s*["']@stellar/mpp/charge/server["']|"""
    r"""(?:const|let|var)\s*\{(?P<req>[^}]*)\}\s*=\s*require\(\s*["']@stellar/mpp/charge/server["']\s*\)""")
_WASM_HASH_USE = re.compile(r"wasm_?hash|createWallet|deploy", re.I)
#: Words that name a list of hashes to refuse (KNOWN_VULNERABLE_..., denyList, blockedHashes),
#: matched as whole words of identifiers and strings in code, never in comments: 'blockchain',
#: 'unknown' and 'badge' are not deny words.
_DENY_WORDS = frozenset({"vulnerable", "vulnerability", "vulnerabilities", "vuln", "deny", "denied", "denylist",
                         "denylisted", "block", "blocked", "blocklist", "blocklisted", "blacklist", "blacklisted",
                         "legacy", "known", "revoked", "reject", "rejected", "insecure", "bad"})
_UPGRADE_WALLET = ("Deploy new wallets from the current canonical passkey-kit WASM, and upgrade each existing wallet in "
                   "place to the legacy-line build passkey-kit names in its SECURITY.md, or move its funds out.")


# Line numbers and bracket matches come from one pass over each text, cached for the texts in
# use: a file with thousands of calls or unclosed brackets costs no more than one read of it.
@lru_cache(maxsize=32)
def _newlines(text: str) -> list[int]:
    return [m.start() for m in re.finditer("\n", text)]


@lru_cache(maxsize=32)
def _closers(text: str, opening: str, closing: str) -> dict[int, int]:
    """Each opening bracket and the one that closes it."""
    out, stack = {}, []
    for m in re.finditer(re.escape(opening) + "|" + re.escape(closing), text):
        if m.group() == opening:
            stack.append(m.start())
        elif stack:
            out[stack.pop()] = m.start()
    return out


def _line(text: str, pos: int) -> int:
    return bisect_left(_newlines(text), pos) + 1


def _block(code: str, open_brace: int) -> int:
    """Index just past the brace that closes the one at ``open_brace`` (the end when none does)."""
    close = _closers(code, "{", "}").get(open_brace)
    return len(code) if close is None else close + 1


def _installed(lockset: Lockset, package: str, near: str, ecosystem: str) -> tuple[tuple[str, ...], str] | None:
    """Installed versions and where they come from: a lockfile, or an exact pin in the manifest
    ('=1.2.3' for Cargo, where a bare version is a caret range). A range is never a match."""
    found = lockset.resolve(package, near)
    if found is None or not found.versions:
        return None
    if PurePosixPath(found.source).name in _LOCKS:
        return found.versions, found.source
    spec = (found.spec or "").strip()
    exact = spec.startswith("=") if ecosystem == "cargo" else exact_pin(spec) is not None
    return (found.versions, found.source) if exact else None


def _package_root(lockset: Lockset, path: str) -> str:
    """The nearest directory above ``path`` with its own manifest ('' for the repository root)."""
    parts = PurePosixPath(path).parts[:-1]
    return next(("/".join(parts[:i]) for i in range(len(parts), 0, -1) if "/".join(parts[:i]) in lockset.importers), "")


def _separate_installs(lockset: Lockset, package: str) -> set[str]:
    """Directories that install npm packages on their own: they have their own npm lockfile, or
    their manifest declares ``package`` and so resolves it themselves."""
    locks = [lock for imp in lockset.importers.values() for lock in imp.get("lockfiles") or []] + list(lockset.locked)
    return ({_directory(lock) for lock in locks if PurePosixPath(lock).name in _NPM_LOCKS}
            | {d for d, imp in lockset.importers.items() if package in (imp.get("deps") or {})})


def _in_tree(path: str, root: str, separate: set[str]) -> bool:
    """``path`` is in ``root``'s directory tree and not under a nested directory in ``separate``."""
    if root and not path.startswith(root + "/"):
        return False
    parts = PurePosixPath(path).parts[:-1]
    first = len(PurePosixPath(root).parts) + 1 if root else 1
    return not any("/".join(parts[:i]) in separate for i in range(first, len(parts) + 1))


def _manifest(directory: str) -> str:
    return "Cargo.toml" if directory in ("", ".") else f"{directory}/Cargo.toml"


def _crate_root(files: dict[str, str], path: str) -> str:
    """The nearest directory above ``path`` that has a Cargo.toml ('' for the repository root)."""
    parents = [str(d) for d in PurePosixPath(path).parents]
    return next(("" if d == "." else d for d in parents if _manifest(d) in files), "")


def _profile_manifest(files: dict[str, str], source: str) -> str | None:
    """The manifest whose [profile.release] applies. Cargo reads profiles only at the workspace
    root: next to the lockfile, or the nearest manifest above a pinned member that has [workspace]."""
    here = str(PurePosixPath(source).parent)
    if PurePosixPath(source).name in _LOCKS:
        return files.get(_manifest(here))
    manifests = [files[_manifest(str(d))] for d in (PurePosixPath(here), *PurePosixPath(here).parents)
                 if _manifest(str(d)) in files]
    return next((m for m in manifests if re.search(r"(?m)^\s*\[workspace\]", m)), manifests[0] if manifests else None)


def _deployed(files: dict[str, str], name: str) -> bool:
    """A contract source the release build includes: not a test, bench, example or fuzz target."""
    crate = _crate_root(files, name)
    inner = name[len(crate) + 1:] if crate else name
    return not _TEST_FILE.search(name) and not inner.startswith(("examples/", "benches/"))


def _without_test_modules(code: str) -> str:
    """Blank #[cfg(test)] modules: they are compiled into test builds only."""
    spans = [(m.start(), _block(code, m.end() - 1)) for m in _TEST_MODULE.finditer(code)]
    pieces, done = [], 0
    for start, end in spans:
        if end <= done:
            continue  # inside a module already blanked
        start = max(start, done)
        pieces += [code[done:start], re.sub(r"[^\n]+", lambda s: " " * len(s.group()), code[start:end])]
        done = end
    return "".join(pieces) + code[done:]


# ------------------------------------------------------------------ Rust conditions

def _impls(name: str, code: str) -> list[dict]:
    out = []
    for m in _IMPL.finditer(code):
        end = _block(code, m.end() - 1)
        head = code[max(0, m.start() - 300):m.start()]
        head = head[max(head.rfind("}"), head.rfind(";")) + 1:]
        fns = [(f["name"], _line(code, m.end() + f.start())) for f in _FUNCTION.finditer(code[m.end():end])]
        out.append({"type": m["type"], "trait": m["trait"], "contractimpl": bool(_CONTRACTIMPL.search(head)),
                    "fns": fns, "file": name})
    return out


def _name_collisions(files: dict[str, str], crates: dict[str, str]) -> list[str]:
    """GHSA-4chv-4c6w-w254: a #[contractimpl] trait impl and a plain inherent impl of the same
    type define a function with the same name. Inherent impls live in the type's own crate, so a
    type is (crate, name): two contracts that both call their type `Contract` do not collide."""
    impls = [i for name, code in files.items() for i in _impls(name, code)]
    exported = {(crates[i["file"]], i["type"], fn): f"{i['file']}:{line}"
                for i in impls if i["trait"] and i["contractimpl"] for fn, line in i["fns"]}
    return [f"{fn}: trait fn at {exported[(crates[i['file']], i['type'], fn)]}, inherent fn at {i['file']}:{line}"
            for i in impls if not i["trait"] and not i["contractimpl"]
            for fn, line in i["fns"] if (crates[i["file"]], i["type"], fn) in exported]


@lru_cache(maxsize=32)
def _range_index(code: str) -> tuple[list[int], list[int], dict[int, list[int]], list[int], list[tuple[int, str]]]:
    """One pass over a file for _bounds: each bracket's offset and the depth after it, each
    range operator `..` by the depth it sits at, and each Bound:: path (start, end, kind)."""
    brackets, depths, dots, depth = [], [], {}, 0
    for m in re.finditer(r"[(\[{)\]}]|\.\.(?!\.)", code):
        if m.group() == "..":
            dots.setdefault(depth, []).append(m.start())
        else:
            depth += 1 if m.group() in "([{" else -1
            brackets.append(m.start())
            depths.append(depth)
    paths = list(_BOUND.finditer(code))
    return brackets, depths, dots, [m.start() for m in paths], [(m.end(), m[1]) for m in paths]


def _bounds(code: str, open_paren: int) -> list[tuple[str, str]] | None:
    """[(kind, value)] for the start and end bound of the range argument of the call whose
    parenthesis opens at ``open_paren``, kind being Included, Excluded or Unbounded; None when
    the argument is not written as a range (a variable), or is too long or too deeply wrapped to
    read (_RANGE_CHARS, _RANGE_PARENS). Brackets and operators come from _range_index, so a file
    with thousands of calls or nested parentheses is read once, not once per call."""
    closers = _closers(code, "(", ")")
    close = closers.get(open_paren)
    if close is None or close - open_paren > _RANGE_CHARS:
        return None
    a, b = open_paren + 1, close
    for _ in range(_RANGE_PARENS + 1):  # strip whitespace and redundant parentheses
        a = b - len(code[a:b].lstrip())
        b = a + len(code[a:b].rstrip())
        if a < b and code[a] == "(" and closers.get(a) == b - 1:
            a, b = a + 1, b - 1
        else:
            break
    else:
        return None
    brackets, depths, dots, path_starts, paths = _range_index(code)
    first, last = bisect_left(path_starts, a), bisect_left(path_starts, b)
    if first < last:  # (Bound::Excluded(x), Bound::Included(y)): exactly two
        if last - first != 2:
            return None
        out = []
        for end, kind in paths[first:last]:
            value = ""
            if kind != "Unbounded":
                p = end + len(code[end:b]) - len(code[end:b].lstrip())
                inner = closers.get(p) if code.startswith("(", p) else None
                if inner is None or inner >= b:
                    return None
                value = code[p + 1:inner]
            out.append((kind, value.strip()))
        return out
    k = bisect_left(brackets, a)
    level = depths[k - 1] if k else 0
    found = dots.get(level, [])
    i = bisect_left(found, a)
    if i == len(found) or found[i] + 2 > b:
        return None
    p = found[i]
    inclusive = code.startswith("..=", p) and p + 3 <= b
    start, end = code[a:p].strip(), code[p + (3 if inclusive else 2):b].strip()
    return [("Included", start) if start else ("Unbounded", ""),
            (("Included" if inclusive else "Excluded"), end) if end else ("Unbounded", "")]


def _can_wrap(value: str, edge: int) -> bool:
    """The bound can take the value the SDK's arithmetic wraps at: it is not a literal, or it is
    that literal."""
    value = re.sub(r"\s+", "", value).strip("()")
    if _TYPE_MAX.match(value):
        return edge == (2**32 - 1 if _TYPE_MAX.match(value)[1] == "32" else 2**64 - 1)
    literal = _LITERAL.match(value)
    return int(literal[1].replace("_", "")) == edge if literal else True


def _range_wraps(method: str, code: str, open_paren: int) -> bool:
    bounds = _bounds(code, open_paren)
    if bounds is None:
        return True  # a range held in a variable: its bounds are not visible
    return any(kind == _WRAPS[method][side][0] and _can_wrap(value, _WRAPS[method][side][1])
               for side, (kind, value) in zip(("start", "end"), bounds))


def _unchecked_ranges(files: dict[str, str], manifest: str | None) -> tuple[list[str], list[str]]:
    """GHSA-96xm-fv9w-pf3f: release builds without overflow checks, and a Bytes/Vec slice or a
    Prng::gen_range in contract code whose bound can sit where the SDK's arithmetic wraps
    (_WRAPS). Returns (calls that can wrap, the places of calls whose bounds cannot: literals
    away from the edge, or bounds of a kind the SDK does no arithmetic on). Without the
    workspace manifest the profile is unknown: no match."""
    if manifest is None or re.search(r"(?ms)^\[profile\.release\][^\[]*?^\s*overflow-checks\s*=\s*true", manifest):
        return [], []
    hits, safe = [], []
    for name, code in files.items():
        prng = {a or b for a, b in _PRNG_BINDING.findall(code)}
        calls = [("slice", m) for m in _SLICE.finditer(code)]
        calls += [("gen_range", m) for m in _GEN_RANGE.finditer(code) if not m[1] or m[1] in prng]
        for method, m in sorted(calls, key=lambda c: c[1].start()):
            place = f"{name}:{_line(code, m.start())}"
            (hits if _range_wraps(method, code, m.end() - 1) else safe).append(place)
            if len(hits) >= 5:
                break
        if len(hits) >= 5:
            break
    return hits, list(dict.fromkeys(safe))[:5]


def _fr_equality(files: dict[str, str], raw: dict[str, str]) -> list[str]:
    """GHSA-x2hw-px52-wp4m: an Fr value of BN254 or BLS12-381 compared with == or assert_eq."""
    hits = []
    for name, code in files.items():
        if not _FR_IMPORT.search(raw[name]):
            continue
        names = {a or b for a, b in _FR_BINDING.findall(code)}
        if not names:
            continue
        ids = "|".join(map(re.escape, sorted(names)))
        cmp = re.compile(rf"\b(?:{ids})\b\s*[!=]=|[!=]=\s*&?\s*\b(?:{ids})\b|assert_(?:eq|ne)!\s*\([^;]{{0,500}}?\b(?:{ids})\b")
        hits += [f"{name}:{_line(code, m.start())}" for m in cmp.finditer(code)]
        if len(hits) >= 5:
            break
    return hits[:5]


def _contract_delegates(files: dict[str, str], raw: dict[str, str]) -> list[str]:
    """stellar-accounts before 0.7.3: a Delegated signer built from a contract address (the
    account's own address or a C... literal)."""
    hits = []
    for name, code in files.items():
        for m in _DELEGATED.finditer(code):
            close = _closers(code, "(", ")").get(m.end() - 1)
            i = len(code) if close is None else close + 1
            argument_code, argument_raw = code[m.end():i], raw[name][m.end():i]
            if "current_contract_address" in argument_code or re.search(r"\bC[A-Z2-7]{55}\b", argument_raw):
                hits.append(f"{name}:{_line(code, m.start())}")
    return hits[:5]


# ------------------------------------------------------------------ JS conditions

def _mpp_servers_without_fee_payer(name: str, text: str) -> list[str]:
    """Charge-method calls from '@stellar/mpp/charge/server' whose options object has no feePayer.
    Comments are masked, and calls and braces are read with string contents masked too, so an
    example in a comment or a brace in a string is not a call or its options."""
    code, skel = mask(text)
    callees: set[str] = set()
    for m in _MPP_SERVER_IMPORT.finditer(code):
        if m["ns"]:
            callees |= {f"{m['ns']}.stellar", f"{m['ns']}.charge"}
        for spec in (m["names"] or m["req"] or "").split(","):
            parts = re.split(r"\s+as\s+|\s*:\s*", spec.strip())
            if parts[0] in {"stellar", "charge"}:
                callees.add(parts[-1])
    hits = []
    # Every feePayer and spread in the file, found once: an options object holds one when the
    # first that starts inside it also ends inside it, so nested calls cost no rescans.
    present = [(m.start(), m.end()) for m in re.finditer(r"\bfeePayer\b|\.\.\.", code)] if callees else []
    starts = [start for start, _ in present]
    for callee in callees:
        for m in re.finditer(rf"(?<![\w$.]){re.escape(callee)}(?:\s*\.\s*charge)?\s*\(\s*\{{", skel):
            close = _closers(skel, "{", "}").get(m.end() - 1)
            if close is None:
                continue  # an options object that never closes is not a call to judge
            k = bisect_left(starts, m.end() - 1)
            if k == len(present) or present[k][1] > close:
                hits.append(f"{name}:{_line(text, m.start())}")
    return sorted(set(hits))


# ------------------------------------------------------------------ findings

#: What each Rust condition looks for, said when an affected version does not show it.
_NOT_SHOWN = {
    "contractimpl_name_collision": "No inherent function of a contract type shares its name with a function of a "
                                   "#[contractimpl] trait impl of that type in the same crate.",
    # A delegate the operator or a tool passes in at run time (a C... strkey on a command line)
    # is not a self or mutual delegate shown in source; whether one is configured needs a
    # ledger read of the account's rules, so this stays a note.
    "delegated_contract_signer": "The source builds no Delegated signer from the account's own address or a "
                                 "contract-address literal. Delegates chosen at run time (an address an operator or a "
                                 "tool passes in) are not visible to this check: confirm that no configured Delegated "
                                 "signer is the account itself or a contract that delegates back to it.",
    "unchecked_range_arithmetic": "No contract source built without overflow checks passes Bytes::slice, Vec::slice "
                                  "or Prng::gen_range a bound that can wrap: an inclusive slice end or excluded slice "
                                  "start at u32::MAX, an excluded gen_range start at u64::MAX or end at 0, or such a "
                                  "bound that is not a literal.",
    "fr_equality": "No BN254 or BLS12-381 Fr value is compared with == or assert_eq.",
}


def _words(text: str) -> set[str]:
    """Lower-case words of identifiers and strings: KNOWN_VULNERABLE -> known, vulnerable;
    denyList -> deny, list; blockchain stays one word."""
    return set(re.findall(r"[a-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text).lower()))


def advisory_findings(artifact: AgentArtifact, auditor, today: date | None = None,
                      masked: dict[str, str] | None = None) -> list[Finding]:
    """``masked`` maps each contract source to its comment- and literal-masked text, when the
    caller (StellarNativeAuditor) already has it; otherwise each file is masked when needed.

    Copies of one affected version (sibling crates with their own lockfiles, two servers in one
    workspace) are one finding per advisory, package and version, listing every location; its
    id hashes the advisory, package and version, not a lockfile path."""
    lockset = Lockset(artifact.raw_metadata.get("resolved_versions"))
    files = artifact.code_files
    out: list[Finding] = []
    consulted = False
    contracts = list(masked) if masked is not None else list(contract_sources(artifact))
    masked, built_code = masked or {}, {}
    copies: dict[tuple, list[dict]] = {}

    def code_of(name: str) -> str:
        """Masked text, without #[cfg(test)] modules; computed once, and only when asked for."""
        if name not in built_code:
            built_code[name] = _without_test_modules(masked[name] if name in masked else _rust_code(files[name]))
        return built_code[name]

    def finding(advisory: adv.Advisory, place: str, severity: Severity, title: str, detail: str, evidence: str,
                grade: EvidenceGrade = EvidenceGrade.CONFIRMED, gap: bool = False, remediation: str = "") -> None:
        slug = re.sub(r"[^a-z0-9]+", "-", f"{advisory.id}-{advisory.package}".lower()).strip("-")
        f = auditor.finding(
            stable_id(f"dep-{slug}", place), severity, title,
            f"{detail} {advisory.summary}" + (f" Fixed in {advisory.fixed}." if advisory.affected else ""),
            evidence=evidence,
            remediation=remediation or f"Upgrade {advisory.package} to a fixed release ({advisory.fixed}), rebuild and "
                                       "redeploy; until then remove the condition named here.",
            references=[advisory.url], grade=grade, confidence=0.9 if grade is EvidenceGrade.CONFIRMED else 0.75)
        out.append(f.model_copy(update={"kind": FindingKind.EVIDENCE_GAP}) if gap else f)

    def copy(advisory: adv.Advisory, versions: list[str], location: str, severity: Severity, title: str,
             detail: str, hits: list[str], grade: EvidenceGrade = EvidenceGrade.CONFIRMED, gap: bool = False) -> None:
        """One installed copy of an affected version; reported by ``report_copies``."""
        copies.setdefault((advisory, tuple(versions)), []).append(
            {"location": location, "severity": severity, "title": title, "detail": detail, "hits": hits,
             "grade": grade, "gap": gap})

    def report_copies() -> None:
        """Where any copy meets the condition, the risk is reported and the copies that do not
        are left out of it; otherwise one fact lists every copy."""
        for (advisory, versions), found in copies.items():
            chosen = [c for c in found if not c["gap"]] or found
            lead = max(chosen, key=lambda c: c["severity"].rank)
            locations = list(dict.fromkeys(c["location"] for c in chosen))
            hits = list(dict.fromkeys(h for c in chosen for h in c["hits"]))
            finding(advisory, f"{advisory.package} {', '.join(versions)}", lead["severity"], lead["title"],
                    lead["detail"], "; ".join(locations + hits[:5]), lead["grade"], gap=lead["gap"])

    # Rust: the contract sources, grouped by the lockfile that resolves each advisory's package.
    # Files are masked only for a group whose installed version is affected.
    for advisory in (a for a in adv.ADVISORIES if a.ecosystem == "cargo"):
        groups: dict[tuple, list[str]] = {}
        for name in contracts:
            found = _installed(lockset, advisory.package, name, "cargo")
            if found:
                groups.setdefault(found, []).append(name)
        for (versions, source), names in sorted(groups.items()):
            consulted = True
            affected = [v for v in versions if advisory.affects(v)]
            if not affected:
                continue
            built = [n for n in names if _deployed(files, n)]
            code = {n: code_of(n) for n in built}
            raw = {n: files[n] for n in built}
            installed = f"{source}: {advisory.package} {', '.join(affected)}"
            safe: list[str] = []
            if advisory.condition == "contractimpl_name_collision":
                hits, severity, grade = (_name_collisions(code, {n: _crate_root(files, n) for n in built}),
                                         Severity.HIGH, EvidenceGrade.CONFIRMED)
            elif advisory.condition == "delegated_contract_signer":
                hits, severity, grade = _contract_delegates(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED
            elif advisory.condition == "unchecked_range_arithmetic":
                (hits, safe), severity, grade = (_unchecked_ranges(code, _profile_manifest(files, source)),
                                                 Severity.MEDIUM, EvidenceGrade.INFERRED)
            else:
                hits, severity, grade = _fr_equality(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED
            if hits:
                copy(advisory, affected, installed, severity,
                     f"{advisory.package} {affected[0]} is affected by {advisory.id}, and the code meets its condition",
                     "The installed version has a published flaw and the source uses the affected feature.",
                     hits[:5], grade)
            else:
                copy(advisory, affected, installed, Severity.INFO,
                     f"{advisory.package} {affected[0]} is within {advisory.id}; check whether its condition applies",
                     f"The installed version is affected. {_NOT_SHOWN[advisory.condition]}",
                     [f"calls whose bounds cannot wrap at {', '.join(safe)}"] if safe else [],
                     EvidenceGrade.INFERRED, gap=True)

    # JS: MPP charge servers, and passkey-kit wallets used with policy signers.
    mpp = adv.for_package("@stellar/mpp")[0]
    for name, text in sorted(files.items()):
        if not name.endswith(_JS) or "@stellar/mpp/charge/server" not in text or _TEST_FILE.search(name):
            continue
        found = _installed(lockset, mpp.package, name, "npm")
        if not found:
            continue
        consulted = True
        affected = [v for v in found[0] if mpp.affects(v)]
        calls = _mpp_servers_without_fee_payer(name, text) if affected else []
        if calls:
            # Mainnet is reachable when the package's own code (not a comment, not a test) names it,
            # a network-keyed map included: the map can select it.
            root = _package_root(lockset, name)
            package = {n: t for n, t in files.items() if (not root or n.startswith(root + "/"))
                       and n.endswith(_JS) and not _TEST_FILE.search(n)}
            mainnet = bool(network_hits(package, _MPP_MAINNET, skip_keyed=False))
            copy(mpp, affected, f"{found[1]}: @stellar/mpp {', '.join(affected)}", Severity.HIGH if mainnet else Severity.MEDIUM,
                 "The MPP charge server accepts unsigned transaction-hash credentials",
                 f"@stellar/mpp {affected[0]} is installed and the charge method has no feePayer."
                 + ("" if mainnet else " Only testnet constants are reachable in this package."), calls[:5])
    # Policy signers count only inside the package root that resolves passkey-kit: its directory
    # tree, nested crates included, but not a nested package that installs on its own (its own
    # npm lockfile, or its own passkey-kit dependency). That package is another wallet.
    passkey = adv.for_package("passkey-kit")[0]
    separate = _separate_installs(lockset, passkey.package)
    policy_files = [n for n, t in files.items() if n.endswith(_JS + (".rs", ".rs.hbs")) and _POLICY_SIGNER.search(t)
                    and _POLICY_SIGNER.search(code_of(n) if n.endswith(".rs") else mask(t)[0])]
    seen: set[str] = set()
    for name, text in sorted(files.items()):
        if not name.endswith(_JS) or not re.search(r"""["']passkey-kit["']""", text):
            continue
        resolution = lockset.resolve(passkey.package, name)
        found = _installed(lockset, passkey.package, name, "npm")
        if not found or resolution is None or resolution.root in seen:
            continue
        seen.add(resolution.root)
        consulted = True
        affected = [v for v in found[0] if passkey.affects(v)]
        root = resolution.root
        policies = [n for n in policy_files if _in_tree(n, root, separate)]
        if affected and policies:
            legacy = " Kits before 0.13 deploy the pre-1.0 wallet contract, four builds of which have an " \
                     "unauthenticated update_signer (PASSKEY-KIT-UPDATE-SIGNER)." if below(affected[0], "0.13.0") else ""
            copy(passkey, affected, f"{found[1]}: passkey-kit {', '.join(affected)}", Severity.INFO,
                 "Deployed smart wallets may predate the passkey-kit 0.16.3 contract fix; verify their WASM hash",
                 f"passkey-kit {affected[0]} is installed and the project uses policy signers.{legacy}",
                 [f"policy signers: {', '.join(policies[:3])}"], EvidenceGrade.INFERRED, gap=True)
    report_copies()

    # Known-bad smart-wallet code: deployed (ledger) or deployed from (a literal hash in code).
    bad = adv.KNOWN_BAD_WASM
    contract = (artifact.chain_authority or {}).get("contract") or {}
    for field in ("wasm_hash", "resolved_wasm_hash"):
        value = str(contract.get(field) or "").lower()
        if contract.get("status") == "found":
            consulted = True
        if value in adv.KNOWN_BAD_WASM_HASHES:
            finding(bad, contract.get("contract_id", ""), Severity.CRITICAL,
                    "The agent's smart wallet runs code with an unauthenticated update_signer",
                    "The deployed WASM hash is on passkey-kit's list of known-vulnerable wallet builds.",
                    f"{contract.get('contract_id')}: {field.replace('_', ' ')} {value}", remediation=_UPGRADE_WALLET)
    # The SDK version the deployed contract was built with (contractmetav0 rssdkver). The macros
    # crate is released with the SDK, so the version stands for both; it is still only a fact.
    built = str((contract.get("meta") or {}).get("rssdkver", "")).split("#", 1)[0].strip()
    for advisory in (a for a in adv.ADVISORIES if a.package.startswith("soroban-sdk") and built and a.affects(built)):
        consulted = True
        finding(advisory, contract.get("contract_id", ""), Severity.INFO,
                f"The deployed contract was built with soroban-sdk {built}, within {advisory.id}",
                "The contract metadata names an affected SDK release; whether the code meets the advisory's condition "
                "needs its source.", f"{contract.get('contract_id')}: rssdkver {built}", EvidenceGrade.INFERRED, gap=True)
    # Hashes are read in comment-masked code, so a commented-out line is not a use. A hash on a
    # line that deploys or connects wallets is a use unless the code around it (that line and
    # the three above) names a list to refuse (_DENY_WORDS): the list is the fix.
    uses: dict[str, list[str]] = {}
    for name, text in sorted(files.items()):
        lower = text.lower()
        if _TEST_FILE.search(name) or not any(h in lower for h in adv.KNOWN_BAD_WASM_HASHES):
            continue
        code = mask(text, python=name.endswith((".py", ".toml", ".yaml", ".yml", ".sh")) or "/.env" in f"/{name}")[0]
        newlines = _newlines(code)
        for m in re.finditer(r"\b[0-9a-fA-F]{64}\b", code):
            value, number = m.group(0).lower(), _line(code, m.start())
            if value not in adv.KNOWN_BAD_WASM_HASHES:
                continue
            # The line (at most 300 characters either side on a minified one) and the three above.
            start = newlines[number - 2] + 1 if number > 1 else 0
            end = newlines[number - 1] if number <= len(newlines) else len(code)
            if not _WASM_HASH_USE.search(code, max(start, m.start() - 300), min(end, m.end() + 300)):
                continue
            above = newlines[number - 5] + 1 if number > 4 else 0
            if _DENY_WORDS & _words(code[max(above, m.start() - 1_200):min(end, m.end() + 300)]):
                continue
            uses.setdefault(value, []).append(f"{name}:{number}: {value}")
    for value, places in uses.items():
        consulted = True
        finding(bad, value, Severity.CRITICAL, "New smart wallets are deployed from a known-vulnerable WASM",
                "The code deploys or connects wallets with a WASM hash on passkey-kit's list of builds whose "
                "update_signer has no authorization check.", "; ".join(list(dict.fromkeys(places))[:5]),
                remediation=_UPGRADE_WALLET)

    stale = adv.stale_rows(today)
    if consulted and stale:
        out.append(auditor.finding(
            "dep-advisory-table-stale", Severity.LOW, "The advisory table has not been reviewed recently",
            f"{len(stale)} advisory row(s) were last checked more than {adv.STALE_AFTER_DAYS} days ago; advisories "
            "published since are not matched.", evidence=", ".join(f"{a.id} ({a.reviewed_at})" for a in stale[:8]),
            remediation="Re-check each row of backend/app/stellar/advisories.py against its source and update reviewed_at.",
            grade=EvidenceGrade.CONFIRMED, confidence=0.9).model_copy(update={"kind": FindingKind.EVIDENCE_GAP}))
    return out
