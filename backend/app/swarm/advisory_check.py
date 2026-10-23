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
from datetime import date
from pathlib import PurePosixPath

from ..models import AgentArtifact, EvidenceGrade, Finding, FindingKind, Severity
from ..services.lockfiles import Lockset, below, exact_pin
from ..stellar import advisories as adv
from .consolidate import stable_id
from .stellar_native import _FUNCTION, _rust_code, contract_sources
from .tmark_check import _MAINNET, network_hits

#: Lockfile names: a version read from one of them is what is installed.
_LOCKS = {"Cargo.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
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
#: Bytes/Vec slices whose bound the SDK adds one to: an inclusive end, or an excluded start.
_UNCHECKED_SLICE = re.compile(r"\.\s*slice\s*\(\s*(?:[^;{}]*?\.\.=|\(\s*(?:[\w:]*::)?Bound\s*::\s*Excluded\b)")
#: Prng::gen_range, on env.prng() or on a name bound to it (rand's Rng::gen_range is not affected).
_GEN_RANGE = re.compile(r"(?:\.\s*prng\s*\(\s*\)|\b([a-z_]\w*))\s*\.\s*gen_range\s*(?:::\s*<[^>]*>\s*)?\(")
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
_DENY_LIST = re.compile(r"vulnerab|deny|block|legacy|known|revoked|reject|insecure|bad", re.I)
_UPGRADE_WALLET = ("Deploy new wallets from the current canonical passkey-kit WASM, and upgrade each existing wallet in "
                   "place to the legacy-line build passkey-kit names in its SECURITY.md, or move its funds out.")


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _block(code: str, open_brace: int) -> int:
    """Index just past the brace that closes the one at ``open_brace``."""
    depth, i = 0, open_brace
    while i < len(code):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        i += 1
        if depth == 0:
            break
    return i


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
    for m in reversed(list(_TEST_MODULE.finditer(code))):
        end = _block(code, m.end() - 1)
        code = code[:m.start()] + re.sub(r"[^\n]+", lambda s: " " * len(s.group()), code[m.start():end]) + code[end:]
    return code


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


def _unchecked_ranges(files: dict[str, str], manifest: str | None) -> list[str]:
    """GHSA-96xm-fv9w-pf3f: release builds without overflow checks, and a Bytes/Vec slice with
    an inclusive end or excluded start, or Prng::gen_range, in contract code. Without the
    workspace manifest the profile is unknown: no match."""
    if manifest is None or re.search(r"(?ms)^\[profile\.release\][^\[]*?^\s*overflow-checks\s*=\s*true", manifest):
        return []
    hits = []
    for name, code in files.items():
        prng = {a or b for a, b in _PRNG_BINDING.findall(code)}
        hits += [f"{name}:{_line(code, m.start())}" for m in _UNCHECKED_SLICE.finditer(code)]
        hits += [f"{name}:{_line(code, m.start())}" for m in _GEN_RANGE.finditer(code) if not m[1] or m[1] in prng]
    return hits[:5]


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
        cmp = re.compile(rf"\b(?:{ids})\b\s*[!=]=|[!=]=\s*&?\s*\b(?:{ids})\b|assert_(?:eq|ne)!\s*\([^;]*\b(?:{ids})\b")
        hits += [f"{name}:{_line(code, m.start())}" for m in cmp.finditer(code)]
    return hits[:5]


def _contract_delegates(files: dict[str, str], raw: dict[str, str]) -> list[str]:
    """stellar-accounts before 0.7.3: a Delegated signer built from a contract address (the
    account's own address or a C... literal)."""
    hits = []
    for name, code in files.items():
        for m in _DELEGATED.finditer(code):
            depth, i = 1, m.end()
            while i < len(code) and depth:
                depth += {"(": 1, ")": -1}.get(code[i], 0)
                i += 1
            argument_code, argument_raw = code[m.end():i], raw[name][m.end():i]
            if "current_contract_address" in argument_code or re.search(r"\bC[A-Z2-7]{55}\b", argument_raw):
                hits.append(f"{name}:{_line(code, m.start())}")
    return hits[:5]


# ------------------------------------------------------------------ JS conditions

def _mpp_servers_without_fee_payer(name: str, text: str) -> list[str]:
    """Charge-method calls from '@stellar/mpp/charge/server' whose options object has no feePayer."""
    callees: set[str] = set()
    for m in _MPP_SERVER_IMPORT.finditer(text):
        if m["ns"]:
            callees |= {f"{m['ns']}.stellar", f"{m['ns']}.charge"}
        for spec in (m["names"] or m["req"] or "").split(","):
            parts = re.split(r"\s+as\s+|\s*:\s*", spec.strip())
            if parts[0] in {"stellar", "charge"}:
                callees.add(parts[-1])
    hits = []
    for callee in callees:
        for m in re.finditer(rf"(?<![\w$.]){re.escape(callee)}(?:\s*\.\s*charge)?\s*\(\s*\{{", text):
            options = text[m.end() - 1:_block(text, m.end() - 1)]
            if not re.search(r"\bfeePayer\b|\.\.\.", options):
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
    "unchecked_range_arithmetic": "No contract source built without overflow checks slices Bytes or Vec with an "
                                  "inclusive end or excluded start, or calls Prng gen_range.",
    "fr_equality": "No BN254 or BLS12-381 Fr value is compared with == or assert_eq.",
}


def advisory_findings(artifact: AgentArtifact, auditor, today: date | None = None,
                      masked: dict[str, str] | None = None) -> list[Finding]:
    """``masked`` maps each contract source to its comment- and literal-masked text, when the
    caller (StellarNativeAuditor) already has it; otherwise each file is masked when needed."""
    lockset = Lockset(artifact.raw_metadata.get("resolved_versions"))
    files = artifact.code_files
    out: list[Finding] = []
    consulted = False
    contracts = list(masked) if masked is not None else list(contract_sources(artifact))
    masked, built_code = masked or {}, {}

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
            hits, severity, grade = {
                "contractimpl_name_collision": lambda: (_name_collisions(code, {n: _crate_root(files, n) for n in built}),
                                                        Severity.HIGH, EvidenceGrade.CONFIRMED),
                "delegated_contract_signer": lambda: (_contract_delegates(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED),
                "unchecked_range_arithmetic": lambda: (_unchecked_ranges(code, _profile_manifest(files, source)),
                                                       Severity.MEDIUM, EvidenceGrade.INFERRED),
                "fr_equality": lambda: (_fr_equality(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED),
            }[advisory.condition]()
            if hits:
                finding(advisory, source, severity, f"{advisory.package} {affected[0]} is affected by {advisory.id}, and the code meets its condition",
                        "The installed version has a published flaw and the source uses the affected feature.",
                        installed + "; " + "; ".join(hits[:5]), grade)
            else:
                finding(advisory, source, Severity.INFO, f"{advisory.package} {affected[0]} is within {advisory.id}; check whether its condition applies",
                        f"The installed version is affected. {_NOT_SHOWN[advisory.condition]}",
                        installed, EvidenceGrade.INFERRED, gap=True)

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
            finding(mpp, name, Severity.HIGH if mainnet else Severity.MEDIUM,
                    "The MPP charge server accepts unsigned transaction-hash credentials",
                    f"@stellar/mpp {affected[0]} is installed and the charge method has no feePayer."
                    + ("" if mainnet else " Only testnet constants are reachable in this package."),
                    f"{found[1]}: @stellar/mpp {affected[0]}; " + "; ".join(calls[:5]))
    passkey = adv.for_package("passkey-kit")[0]
    policies = any(_POLICY_SIGNER.search(t) and (not n.endswith(".rs") or _POLICY_SIGNER.search(code_of(n)))
                   for n, t in files.items() if n.endswith(_JS + (".rs", ".rs.hbs")))
    seen: set[str] = set()
    for name, text in sorted(files.items()):
        if not name.endswith(_JS) or not re.search(r"""["']passkey-kit["']""", text):
            continue
        found = _installed(lockset, passkey.package, name, "npm")
        if not found or found[1] in seen:
            continue
        seen.add(found[1])
        consulted = True
        affected = [v for v in found[0] if passkey.affects(v)]
        if affected and policies:
            legacy = " Kits before 0.13 deploy the pre-1.0 wallet contract, four builds of which have an " \
                     "unauthenticated update_signer (PASSKEY-KIT-UPDATE-SIGNER)." if below(affected[0], "0.13.0") else ""
            finding(passkey, found[1], Severity.INFO,
                    "Deployed smart wallets may predate the passkey-kit 0.16.3 contract fix; verify their WASM hash",
                    f"passkey-kit {affected[0]} is installed and the project uses policy signers.{legacy}",
                    f"{found[1]}: passkey-kit {affected[0]}", EvidenceGrade.INFERRED, gap=True)

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
    for name, text in sorted(files.items()):
        if _TEST_FILE.search(name):
            continue
        for m in re.finditer(r"\b[0-9a-fA-F]{64}\b", text):
            value = m.group(0).lower()
            if value not in adv.KNOWN_BAD_WASM_HASHES:
                continue
            lines, number = text.splitlines(), _line(text, m.start())
            # A commented-out line, or a list of hashes to refuse (a deny list, passkey-kit's own
            # table), is not a use: the list is the fix.
            if lines[number - 1].lstrip().startswith(("//", "#", "*", "/*")):
                continue
            if _WASM_HASH_USE.search(lines[number - 1]) and not _DENY_LIST.search("\n".join(lines[max(0, number - 4):number])):
                consulted = True
                finding(bad, name, Severity.CRITICAL, "New smart wallets are deployed from a known-vulnerable WASM",
                        "The code deploys or connects wallets with a WASM hash on passkey-kit's list of builds whose "
                        "update_signer has no authorization check.", f"{name}:{number}: {value}",
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
