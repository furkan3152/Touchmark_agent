"""Advisories match an installed version only together with the code that makes it exploitable.

Each case pairs a vulnerable fixture with its nearest safe one: the patched release, the same
release without the code condition, a range instead of a lockfile, a client-only import."""

from __future__ import annotations

import json
import time
from datetime import date

import pytest

from backend.app.models import AgentArtifact, Severity, SourceKind
from backend.app.stellar import advisories
from backend.app.swarm import advisory_check
from backend.app.swarm.advisory_check import advisory_findings
from backend.app.swarm.stellar_native import StellarNativeAuditor, _rust_code
from backend.tests.test_deep_checks import audit

BAD_HASH = "0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865"
CARGO_TOML = '[package]\nname = "vault"\nversion = "0.1.0"\n\n[dependencies]\nsoroban-sdk = "{sdk}"\n{extra}'
VAULT = '''use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Ownable for Vault {
    fn transfer_ownership(e: Env, new: Address) { owner(&e).require_auth(); set_owner(&e, &new) }
}
'''
INHERENT = '''
impl Vault {
    pub fn transfer_ownership(e: Env, new: Address) { set_owner(&e, &new) }
}
'''


def cargo_lock(**versions: str) -> str:
    return "version = 3\n" + "".join(f'\n[[package]]\nname = "{name.replace("_", "-")}"\nversion = "{v}"\n'
                                     for name, v in versions.items())


def package_lock(**versions: str) -> str:
    names = {k.replace("__", "/").replace("_", "-").replace("stellar/", "@stellar/"): v for k, v in versions.items()}
    return json.dumps({"name": "a", "lockfileVersion": 3, "packages": {
        "": {"dependencies": {n: f"^{v}" for n, v in names.items()}},
        **{f"node_modules/{n}": {"version": v} for n, v in names.items()}}})


def dep_findings(found: dict, advisory: str) -> list[dict]:
    return [f for i, f in found.items() if i.startswith(f"stellar_native-dep-{advisory}")]


def rust_repo(tmp_path, macros: str | None, source: str, sdk_spec: str = "", extra: str = "") -> dict:
    files = {"Cargo.toml": CARGO_TOML.format(sdk=sdk_spec or macros, extra=extra), "src/lib.rs": source}
    if macros:
        files["Cargo.lock"] = cargo_lock(soroban_sdk=macros, soroban_sdk_macros=macros)
    return audit(tmp_path, files)


# ----------------------------------------------------------------- GHSA-4chv-4c6w-w254
def test_a_trait_function_shadowed_by_an_inherent_one_is_high_on_affected_macros(tmp_path):
    [finding] = dep_findings(rust_repo(tmp_path, "23.5.1", VAULT + INHERENT), "ghsa-4chv-4c6w-w254-soroban-sdk-macros")
    assert finding["severity"] == "high" and finding["kind"] == "risk" and finding["evidence_grade"] == "confirmed"
    assert "Cargo.lock: soroban-sdk-macros 23.5.1" in finding["evidence"] and "transfer_ownership" in finding["evidence"]


def test_the_fixed_macros_or_no_collision_is_not_a_risk(tmp_path):
    assert not dep_findings(rust_repo(tmp_path / "a", "23.5.2", VAULT + INHERENT), "ghsa-4chv")
    [fact] = dep_findings(rust_repo(tmp_path / "b", "23.5.1", VAULT), "ghsa-4chv")
    assert fact["severity"] == "info" and fact["kind"] == "evidence_gap"
    # A Cargo manifest version is a caret range, not a pin: no lockfile, no match.
    assert not [i for i in rust_repo(tmp_path / "c", None, VAULT + INHERENT, sdk_spec="21.7.0") if "-dep-" in i]
    pinned = rust_repo(tmp_path / "d", None, VAULT + INHERENT, sdk_spec="=22.0.8")
    assert [f["severity"] for f in dep_findings(pinned, "ghsa-96xm")] == ["info"]


WORKSPACE = '[workspace]\nmembers = ["contracts/*"]\n{extra}'
MEMBER = '[package]\nname = "{name}"\nversion = "0.1.0"\n\n[dependencies]\nsoroban-sdk = {{ workspace = true }}\n'


def workspace(tmp_path, crates: dict[str, str], lock: str, extra: str = "", more: dict | None = None) -> dict:
    files = {"Cargo.toml": WORKSPACE.format(extra=extra), "Cargo.lock": lock, **(more or {})}
    for name, source in crates.items():
        files.update({f"contracts/{name}/Cargo.toml": MEMBER.format(name=name), f"contracts/{name}/src/lib.rs": source})
    return audit(tmp_path, files)


def test_a_same_named_type_in_another_crate_or_a_test_module_does_not_collide(tmp_path):
    lock = cargo_lock(soroban_sdk="23.5.1", soroban_sdk_macros="23.5.1")
    # Both crates keep the template name `Contract`; the inherent helper is in the other crate.
    token = VAULT.replace("Vault", "Contract")
    router = ('use soroban_sdk::{contract, contractimpl, Address, Env};\n#[contract]\npub struct Contract;\n'
              + INHERENT.replace("Vault", "Contract"))
    found = workspace(tmp_path / "a", {"token": token, "router": router}, lock)
    assert [f["severity"] for f in dep_findings(found, "ghsa-4chv")] == ["info"]
    found = workspace(tmp_path / "b", {"token": token + INHERENT.replace("Vault", "Contract")}, lock)
    [finding] = dep_findings(found, "ghsa-4chv")
    assert finding["severity"] == "high" and "contracts/token/src/lib.rs" in finding["evidence"]
    in_tests = VAULT + "\n#[cfg(test)]\nmod test {\n    use super::*;\n" + INHERENT + "}\n"
    assert [f["severity"] for f in dep_findings(rust_repo(tmp_path / "c", "23.5.1", in_tests), "ghsa-4chv")] == ["info"]


# ----------------------------------------------------------------- GHSA-96xm-fv9w-pf3f and GHSA-x2hw-px52-wp4m
RANGES = VAULT.replace("{ owner(&e).require_auth(); set_owner(&e, &new) }",
                       "{ let b = load(&e); let part = b.slice(0..=end(&e)); set_owner(&e, &new) }")


def test_an_inclusive_slice_without_overflow_checks_is_medium(tmp_path):
    [finding] = dep_findings(rust_repo(tmp_path / "a", "22.0.8", RANGES), "ghsa-96xm-fv9w-pf3f")
    assert finding["severity"] == "medium" and "src/lib.rs:" in finding["evidence"]
    checked = rust_repo(tmp_path / "b", "22.0.8", RANGES, extra="\n[profile.release]\noverflow-checks = true\n")
    assert [f["severity"] for f in dep_findings(checked, "ghsa-96xm")] == ["info"]


def test_prng_gen_range_is_medium_but_rand_gen_range_off_chain_is_not(tmp_path):
    lock = cargo_lock(soroban_sdk="22.0.5", rand="0.8.5")
    prng = VAULT.replace("{ owner(&e).require_auth(); set_owner(&e, &new) }",
                         "{ let pick = e.prng().gen_range::<u64>(0..count(&e)); set_owner(&e, &new) }")
    [finding] = dep_findings(workspace(tmp_path / "a", {"vault": prng}, lock), "ghsa-96xm")
    assert finding["severity"] == "medium" and "contracts/vault/src/lib.rs:8" in finding["evidence"]
    # A CLI next to the contracts that jitters with rand, and a contract test that does: not contract code.
    cli = ('use rand::Rng;\nfn main() {\n    let mut rng = rand::thread_rng();\n'
           '    let jitter_ms: u64 = rng.gen_range(100..500);\n    let _ = bytes::Bytes::new().slice(0..=1);\n}\n')
    more = {"cli/Cargo.toml": '[package]\nname = "cli"\nversion = "0.1.0"\n\n[dependencies]\nrand = "0.8"\nsoroban-sdk = "22.0.5"\n',
            "cli/src/main.rs": cli,
            "contracts/vault/tests/fuzz.rs": "use soroban_sdk::Env;\n#[test]\nfn f() { let e = Env::default(); e.prng().gen_range::<u64>(0..10); }\n"}
    found = workspace(tmp_path / "b", {"vault": VAULT}, lock, extra="\n[profile.release]\nopt-level = \"z\"\n", more=more)
    assert [f["severity"] for f in dep_findings(found, "ghsa-96xm")] == ["info"]


def test_overflow_checks_are_read_from_the_workspace_root(tmp_path):
    # An exact pin in a member, no lockfile: the profile that applies is the workspace root's.
    member = '[package]\nname = "vault"\nversion = "0.1.0"\n\n[dependencies]\nsoroban-sdk = "=22.0.8"\n'
    files = {"Cargo.toml": WORKSPACE.format(extra="\n[profile.release]\noverflow-checks = true\n"),
             "contracts/vault/Cargo.toml": member, "contracts/vault/src/lib.rs": RANGES}
    assert [f["severity"] for f in dep_findings(audit(tmp_path / "a", files), "ghsa-96xm")] == ["info"]
    files["Cargo.toml"] = WORKSPACE.format(extra="")
    assert [f["severity"] for f in dep_findings(audit(tmp_path / "b", files), "ghsa-96xm")] == ["medium"]


def test_fr_equality_is_medium_only_with_fr_values(tmp_path):
    fr = ('use soroban_sdk::crypto::bn254::Fr;\n' + VAULT.replace(
        "fn transfer_ownership(e: Env, new: Address) {",
        "fn transfer_ownership(e: Env, new: Address, a: Fr, b: Fr) { if a == b { return; }"))
    [finding] = dep_findings(rust_repo(tmp_path / "a", "25.2.0", fr), "ghsa-x2hw-px52-wp4m")
    assert finding["severity"] == "medium"
    plain = VAULT.replace("{ owner(&e)", "{ if 1 == 2 { return; } owner(&e)")
    assert [f["severity"] for f in dep_findings(rust_repo(tmp_path / "b", "25.2.0", plain), "ghsa-x2hw")] == ["info"]


# ----------------------------------------------------------------- stellar-accounts delegated signers
def test_a_contract_delegated_signer_on_old_stellar_accounts_is_medium(tmp_path):
    account = ('use soroban_sdk::{contract, contractimpl, Env};\nuse stellar_accounts::smart_account::Signer;\n'
               '#[contract]\npub struct Account;\n#[contractimpl]\nimpl Account {\n'
               '    pub fn __constructor(e: Env) { add_signer(&e, 0, &Signer::Delegated(e.current_contract_address())); }\n}\n')
    lock = cargo_lock(soroban_sdk="23.5.3", stellar_accounts="0.7.2")
    found = audit(tmp_path / "a", {"Cargo.toml": CARGO_TOML.format(sdk="23.5.3", extra='stellar-accounts = "0.7.2"\n'),
                                   "Cargo.lock": lock, "src/lib.rs": account})
    [finding] = dep_findings(found, "stellar-accounts-delegated-signer")
    assert finding["severity"] == "medium" and finding["evidence_grade"] == "inferred"
    g_signer = account.replace("e.current_contract_address()", "owner_address(&e)")
    found = audit(tmp_path / "b", {"Cargo.toml": CARGO_TOML.format(sdk="23.5.3", extra='stellar-accounts = "0.7.2"\n'),
                                   "Cargo.lock": lock, "src/lib.rs": g_signer})
    [note] = dep_findings(found, "stellar-accounts")
    assert note["severity"] == "info" and "Delegates chosen at run time" in note["detail"]


# ----------------------------------------------------------------- @stellar/mpp charge servers
MPP_SERVER = '''import { Mppx } from "mppx/server";
import { stellar } from "@stellar/mpp/charge/server";
import { USDC_SAC_TESTNET, STELLAR_TESTNET } from "@stellar/mpp";

export const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET!,
  methods: [stellar({ recipient: process.env.PAY_TO!, currency: USDC_SAC_TESTNET, network: STELLAR_TESTNET })],
});
'''


def mpp_findings(tmp_path, version: str, source: str) -> list[dict]:
    found = audit(tmp_path, {"package.json": json.dumps({"dependencies": {"@stellar/mpp": f"^{version}"}}),
                             "package-lock.json": package_lock(stellar__mpp=version), "src/server.ts": source})
    return dep_findings(found, "mpp-unsigned-hash-push-stellar-mpp")


def test_an_old_mpp_charge_server_without_fee_payer_accepts_unsigned_hashes(tmp_path):
    [finding] = mpp_findings(tmp_path / "a", "0.4.0", MPP_SERVER)
    assert finding["severity"] == "medium" and "src/server.ts:7" in finding["evidence"]  # testnet constants only
    pubnet = MPP_SERVER.replace("STELLAR_TESTNET }", "STELLAR_PUBNET }").replace("STELLAR_TESTNET", "STELLAR_PUBNET")
    assert [f["severity"] for f in mpp_findings(tmp_path / "b", "0.4.0", pubnet)] == ["high"]


def test_mainnet_in_a_comment_or_a_test_does_not_raise_an_mpp_server_to_high(tmp_path):
    files = {"package.json": json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0"}}),
             "package-lock.json": package_lock(stellar__mpp="0.4.0"),
             "src/server.ts": "// mainnet later: https://horizon.stellar.org\n" + MPP_SERVER,
             "src/server.test.ts": 'import { STELLAR_PUBNET } from "@stellar/mpp";\nexpect(net).not.toBe(STELLAR_PUBNET);\n'
                                   + MPP_SERVER}
    [finding] = dep_findings(audit(tmp_path, files), "mpp-unsigned-hash-push-stellar-mpp")
    assert finding["severity"] == "medium" and "src/server.ts:8" in finding["evidence"]
    # A network-keyed map can select mainnet: it is reachable.
    files["src/net.ts"] = "export const USDC = { 'stellar:pubnet': USDC_SAC_MAINNET, 'stellar:testnet': USDC_SAC_TESTNET };\n"
    [finding] = dep_findings(audit(tmp_path / "b", files), "mpp-unsigned-hash-push-stellar-mpp")
    assert finding["severity"] == "high"


def test_mpp_fixed_release_fee_payer_or_client_import_is_not_matched(tmp_path):
    assert not mpp_findings(tmp_path / "a", "0.7.1", MPP_SERVER)
    sponsored = MPP_SERVER.replace("network: STELLAR_TESTNET", "network: STELLAR_TESTNET, feePayer: { envelopeSigner: kp }")
    assert not mpp_findings(tmp_path / "b", "0.4.0", sponsored)
    client = ('import { stellar } from "@stellar/mpp/charge/client";\n'
              'export const method = stellar({ secretKey: process.env.KEY! });\n')
    assert not mpp_findings(tmp_path / "c", "0.4.0", client)


# ----------------------------------------------------------------- passkey-kit
def test_old_passkey_kit_with_policy_signers_is_a_note_to_verify(tmp_path):
    wallet = 'import { PasskeyKit } from "passkey-kit";\nexport const add = (kit: PasskeyKit, p: string) => kit.addPolicy(p, {});\n'
    files = {"package.json": json.dumps({"dependencies": {"passkey-kit": "^0.12.0"}}),
             "package-lock.json": package_lock(passkey_kit="0.12.0"), "src/wallet.ts": wallet}
    [note] = dep_findings(audit(tmp_path / "a", files), "passkey-kit-policy-signer")
    assert note["severity"] == "info" and note["kind"] == "evidence_gap" and "PASSKEY-KIT-UPDATE-SIGNER" in note["detail"]
    files["package-lock.json"] = package_lock(passkey_kit="0.16.3")
    assert not dep_findings(audit(tmp_path / "b", files), "passkey-kit")
    files.update({"package-lock.json": package_lock(passkey_kit="0.12.0"), "src/wallet.ts": wallet.split("\nexport")[0]})
    assert not dep_findings(audit(tmp_path / "c", files), "passkey-kit")


# ----------------------------------------------------------------- known-bad wallet WASM
def stellar_native(settings, run, **artifact):
    verdict = run(StellarNativeAuditor(settings).run(AgentArtifact(
        name="wallet", source_kind=SourceKind.REPO, source_ref="fixture", **artifact), deep=True))
    return [f for f in verdict.findings if "-dep-passkey-kit-update-signer-" in f.id]


def test_a_wallet_on_a_known_vulnerable_wasm_is_critical(settings, run):
    contract = {"status": "found", "contract_id": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
                "executable": "wasm", "wasm_hash": BAD_HASH}
    [finding] = stellar_native(settings, run, chain_authority={"contract": contract})
    assert finding.severity is Severity.CRITICAL and BAD_HASH in finding.evidence
    assert not stellar_native(settings, run, chain_authority={"contract": {**contract, "wasm_hash": "ab" * 32}})


def test_an_affected_sdk_in_contract_metadata_is_only_a_fact(settings, run):
    contract = {"status": "found", "contract_id": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
                "executable": "wasm", "wasm_hash": "ab" * 32, "meta": {"rssdkver": "23.5.1#0a1b2c3d"}}
    verdict = run(StellarNativeAuditor(settings).run(AgentArtifact(
        name="c", source_kind=SourceKind.REPO, source_ref="r", chain_authority={"contract": contract}), deep=True))
    facts = [f for f in verdict.findings if "-dep-ghsa-" in f.id]
    assert {f.id.split("-dep-")[1][:19] for f in facts} == {"ghsa-4chv-4c6w-w254", "ghsa-x2hw-px52-wp4m"}
    assert all(f.severity is Severity.INFO and f.kind.value == "evidence_gap" for f in facts)


@pytest.mark.parametrize("source,hits", [
    (f'export const kit = new PasskeyKit({{ rpcUrl, networkPassphrase, walletWasmHash: "{BAD_HASH}" }});\n', 1),
    (f'// Refuse these known-vulnerable builds\nexport const KNOWN_VULNERABLE_WALLET_WASM_HASHES = [\n  "{BAD_HASH}",\n];\n', 0),
    (f'export const walletWasmHash = "{"cd" * 32}";\n', 0),
    (f'// const kit = new PasskeyKit({{ walletWasmHash: "{BAD_HASH}" }});\n', 0),
])
def test_deploying_from_a_known_vulnerable_hash_is_critical(settings, run, source, hits):
    assert len(stellar_native(settings, run, code_files={"src/kit.ts": source})) == hits
    assert not stellar_native(settings, run, code_files={"tests/kit.test.ts": source})


# ----------------------------------------------------------------- the table itself
def test_each_row_is_dated_and_ranges_are_half_open():
    gh = {a.id: a for a in advisories.ADVISORIES}
    assert gh["GHSA-4chv-4c6w-w254"].affects("23.5.1") and not gh["GHSA-4chv-4c6w-w254"].affects("23.5.2")
    assert gh["GHSA-4chv-4c6w-w254"].affects("22.0.9") and not gh["GHSA-4chv-4c6w-w254"].affects("24.0.0")
    assert gh["GHSA-96xm-fv9w-pf3f"].affects("25.0.1") and not gh["GHSA-96xm-fv9w-pf3f"].affects("25.0.2")
    assert gh["GHSA-x2hw-px52-wp4m"].affects("25.2.9") and not gh["GHSA-x2hw-px52-wp4m"].affects("22.0.11")
    assert all(date.fromisoformat(a.reviewed_at) for a in advisories.ADVISORIES)


def test_a_stale_table_is_reported_only_where_it_was_consulted(settings):
    lock = {"importers": {"": {"lockfiles": ["Cargo.lock"], "deps": {"soroban-sdk": {"spec": "23.5.3", "version": "23.5.3",
                                                                                      "source": "Cargo.lock"}}}},
            "locked": {"Cargo.lock": {"soroban-sdk": ["23.5.3"]}}}
    later = date.fromisoformat(advisories.ADVISORIES[0].reviewed_at).replace(year=2027)
    auditor = StellarNativeAuditor(settings)
    used = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="r",
                         code_files={"Cargo.toml": CARGO_TOML.format(sdk="23.5.3", extra=""), "src/lib.rs": VAULT},
                         raw_metadata={"resolved_versions": lock})
    [gap] = advisory_findings(used, auditor, today=later)
    assert gap.id == "stellar_native-dep-advisory-table-stale" and gap.kind.value == "evidence_gap"
    assert not advisory_findings(used, auditor, today=date.fromisoformat(advisories.ADVISORIES[0].reviewed_at))
    unrelated = used.model_copy(update={"raw_metadata": {}})
    assert not advisory_findings(unrelated, auditor, today=later)


# ----------------------------------------------------------------- cost
def test_masking_is_linear_and_only_affected_contract_code_is_masked(settings, monkeypatch):
    unit = 'pub fn f(e: Env) -> u32 { let s = "a \\" b"; let c = \'x\'; /* c /* n */ */ // x\n  r#"raw"#; 1 }\n'
    big = unit * (400_000 // len(unit))
    started = time.perf_counter()
    assert len(_rust_code(big)) == len(big)
    assert time.perf_counter() - started < 0.5  # a quadratic masker takes seconds here

    masked: list[str] = []
    monkeypatch.setattr(advisory_check, "_rust_code", lambda text: masked.append(text) or _rust_code(text))
    lock = {"importers": {"": {"lockfiles": ["Cargo.lock"], "deps": {
        "soroban-sdk": {"spec": "23.5.3", "version": "23.5.3", "source": "Cargo.lock"},
        "soroban-sdk-macros": {"spec": "23.5.3", "version": "23.5.3", "source": "Cargo.lock"}}}},
        "locked": {"Cargo.lock": {"soroban-sdk": ["23.5.3"], "soroban-sdk-macros": ["23.5.3"]}}}
    files = {"Cargo.toml": CARGO_TOML.format(sdk="23.5.3", extra=""), "src/lib.rs": VAULT,
             "cli/Cargo.toml": '[package]\nname = "cli"\n', "cli/src/main.rs": big}
    artifact = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="r", code_files=files,
                             raw_metadata={"resolved_versions": lock})
    advisory_findings(artifact, StellarNativeAuditor(settings), today=date.fromisoformat(advisories.ADVISORIES[0].reviewed_at))
    assert masked == []  # no affected version: nothing to mask
    lock["importers"][""]["deps"]["soroban-sdk-macros"]["version"] = "23.5.1"
    advisory_findings(artifact, StellarNativeAuditor(settings), today=date.fromisoformat(advisories.ADVISORIES[0].reviewed_at))
    assert masked == [VAULT]  # the contract source, not the CLI
