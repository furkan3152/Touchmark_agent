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
from .stellar_native import _FUNCTION, _rust_code
from .tmark_check import _MAINNET

#: Lockfile names: a version read from one of them is what is installed.
_LOCKS = {"Cargo.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
_JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")
#: @stellar/mpp's own constants for the public network, next to the shared mainnet markers.
_MPP_MAINNET = re.compile(r"\b(?:STELLAR_PUBNET|USDC_SAC_MAINNET|XLM_SAC_MAINNET)\b")

_CONTRACTIMPL = re.compile(r"#\s*\[\s*contractimpl\b")
_IMPL = re.compile(r"\bimpl\s*(?:<[^>{;]*>\s*)?(?:(?P<trait>[\w:]+(?:<[^>{;]*>)?)\s+for\s+)?"
                   r"(?P<type>[A-Za-z_]\w*)(?:<[^>{;]*>)?\s*(?:where\b[^{;]*)?\{")
_INCLUSIVE_SLICE = re.compile(r"\.\s*slice\s*\([^;{}]*?\.\.=")
_GEN_RANGE = re.compile(r"\.\s*gen_range\s*(?:::\s*<[^>]*>\s*)?\(")
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


def _name_collisions(files: dict[str, str]) -> list[str]:
    """GHSA-4chv-4c6w-w254: a #[contractimpl] trait impl and a plain inherent impl of the same
    type define a function with the same name."""
    impls = [i for name, code in files.items() for i in _impls(name, code)]
    exported = {(i["type"], fn): f"{i['file']}:{line}" for i in impls if i["trait"] and i["contractimpl"] for fn, line in i["fns"]}
    return [f"{fn}: trait fn at {exported[(i['type'], fn)]}, inherent fn at {i['file']}:{line}"
            for i in impls if not i["trait"] and not i["contractimpl"]
            for fn, line in i["fns"] if (i["type"], fn) in exported]


def _unchecked_ranges(files: dict[str, str], manifest: str | None) -> list[str]:
    """GHSA-96xm-fv9w-pf3f: release builds without overflow checks, and an inclusive slice or
    gen_range in the source. Without the workspace manifest the profile is unknown: no match."""
    if manifest is None or re.search(r"(?ms)^\[profile\.release\][^\[]*?^\s*overflow-checks\s*=\s*true", manifest):
        return []
    return [f"{name}:{_line(code, m.start())}" for name, code in files.items()
            for m in (*_INCLUSIVE_SLICE.finditer(code), *_GEN_RANGE.finditer(code))][:5]


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

def advisory_findings(artifact: AgentArtifact, auditor, today: date | None = None) -> list[Finding]:
    lockset = Lockset(artifact.raw_metadata.get("resolved_versions"))
    files = artifact.code_files
    out: list[Finding] = []
    consulted = False

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

    # Rust: group the crate sources by the lockfile that resolves each advisory's package.
    rust_raw = {n: t for n, t in files.items() if n.endswith(".rs")}
    rust = {n: _rust_code(t) for n, t in rust_raw.items()}
    for advisory in (a for a in adv.ADVISORIES if a.ecosystem == "cargo"):
        groups: dict[tuple, list[str]] = {}
        for name in rust:
            found = _installed(lockset, advisory.package, name, "cargo")
            if found:
                groups.setdefault(found, []).append(name)
        for (versions, source), names in sorted(groups.items()):
            consulted = True
            affected = [v for v in versions if advisory.affects(v)]
            if not affected:
                continue
            code, raw = {n: rust[n] for n in names}, {n: rust_raw[n] for n in names}
            installed = f"{source}: {advisory.package} {', '.join(affected)}"
            root = str(PurePosixPath(source).parent)
            hits, severity, grade = {
                "contractimpl_name_collision": lambda: (_name_collisions(code), Severity.HIGH, EvidenceGrade.CONFIRMED),
                "delegated_contract_signer": lambda: (_contract_delegates(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED),
                "unchecked_range_arithmetic": lambda: (_unchecked_ranges(code, files.get("Cargo.toml" if root == "." else f"{root}/Cargo.toml")),
                                                       Severity.MEDIUM, EvidenceGrade.INFERRED),
                "fr_equality": lambda: (_fr_equality(code, raw), Severity.MEDIUM, EvidenceGrade.INFERRED),
            }[advisory.condition]()
            if hits:
                finding(advisory, source, severity, f"{advisory.package} {affected[0]} is affected by {advisory.id}, and the code meets its condition",
                        "The installed version has a published flaw and the source uses the affected feature.",
                        installed + "; " + "; ".join(hits[:5]), grade)
            else:
                finding(advisory, source, Severity.INFO, f"{advisory.package} {affected[0]} is within {advisory.id}; its code condition was not found",
                        "The installed version is affected, but the source does not show the condition that makes it exploitable.",
                        installed, EvidenceGrade.INFERRED, gap=True)

    # JS: MPP charge servers, and passkey-kit wallets used with policy signers.
    mpp = adv.for_package("@stellar/mpp")[0]
    for name, text in sorted(files.items()):
        if not name.endswith(_JS) or "@stellar/mpp/charge/server" not in text:
            continue
        found = _installed(lockset, mpp.package, name, "npm")
        if not found:
            continue
        consulted = True
        affected = [v for v in found[0] if mpp.affects(v)]
        calls = _mpp_servers_without_fee_payer(name, text) if affected else []
        if calls:
            root = _package_root(lockset, name)
            package = {n: t for n, t in files.items() if not root or n.startswith(root + "/")}
            mainnet = any(_MAINNET.search(t) or _MPP_MAINNET.search(t) for n, t in package.items() if n.endswith(_JS))
            finding(mpp, name, Severity.HIGH if mainnet else Severity.MEDIUM,
                    "The MPP charge server accepts unsigned transaction-hash credentials",
                    f"@stellar/mpp {affected[0]} is installed and the charge method has no feePayer."
                    + ("" if mainnet else " Only testnet constants are reachable in this package."),
                    f"{found[1]}: @stellar/mpp {affected[0]}; " + "; ".join(calls[:5]))
    passkey = adv.for_package("passkey-kit")[0]
    policies = any(_POLICY_SIGNER.search(rust.get(n, t)) for n, t in files.items() if n.endswith(_JS + (".rs", ".rs.hbs")))
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
        lines = text.splitlines()
        for m in re.finditer(r"\b[0-9a-fA-F]{64}\b", text):
            value, number = m.group(0).lower(), _line(text, m.start())
            if value not in adv.KNOWN_BAD_WASM_HASHES:
                continue
            # A list of hashes to refuse (a deny list, passkey-kit's own table) is the fix, not a use.
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
