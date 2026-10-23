"""Advisories match an installed version only together with the code that makes it exploitable.

Each case pairs a vulnerable fixture with its nearest safe one: the patched release, the same
release without the code condition, a range instead of a lockfile, a client-only import."""

from __future__ import annotations

import json
import time
from datetime import date

import pytest

from backend.app.models import AgentArtifact, Severity, SourceKind
from backend.app.services.lockfiles import Lockset
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


@pytest.mark.parametrize("call,risk", [
    ("e.prng().gen_range::<u64>(1..=6)", False),          # Included bounds: no arithmetic
    ("e.prng().gen_range::<u64>(0..10)", False),          # Excluded(10) end: 10 - 1 cannot wrap
    ("e.prng().gen_range::<u64>(0..n)", True),            # Excluded(n) end wraps when n is 0
    ("e.prng().gen_range::<u64>(0..0)", True),
    ("e.prng().gen_range::<u64>((Bound::Excluded(u64::MAX), Bound::Unbounded))", True),
    ("e.prng().gen_range::<u64>((Bound::Excluded(5), Bound::Unbounded))", False),
    ("e.prng().gen_range::<u64>(range)", True),           # bounds not visible
    ("b.slice(0..=5)", False),
    ("b.slice(0..=u32::MAX)", True),
    ("b.slice(a..b)", False),                             # Included start, Excluded end: no arithmetic
    ("b.slice(0..=end)", True),
    ("b.slice((Bound::Excluded(start), Bound::Unbounded))", True),
    ("b.slice(0..4).len() as u64 + (0..=n).count() as u64", False),  # the range after the call is not its argument
    ("b.slice(((0..4)))", False),                         # redundant parentheses are read through
    ("b.slice(0..(1 + 1))", False),
    # Past _RANGE_PARENS parentheses or _RANGE_CHARS characters the bounds are not read: not visible.
    ("b.slice(" + "(" * 9 + "0..4" + ")" * 9 + ")", True),
    ("b.slice(0..(" + "1 + " * 120 + "1))", True),
])
def test_only_a_range_bound_that_can_wrap_meets_the_overflow_condition(tmp_path, call, risk):
    source = VAULT.replace("{ owner(&e).require_auth(); set_owner(&e, &new) }",
                           f"{{ let b = load(&e); let n = count(&e); let _x = {call}; set_owner(&e, &new) }}")
    [finding] = dep_findings(rust_repo(tmp_path, "22.0.8", source), "ghsa-96xm-fv9w-pf3f")
    assert finding["severity"] == ("medium" if risk else "info"), call
    if not risk:
        assert finding["evidence"].endswith("calls whose bounds cannot wrap at src/lib.rs:8"), finding["evidence"]


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


def test_sibling_lockfiles_with_one_affected_version_are_one_finding_with_a_path_free_id(tmp_path):
    account = ('use soroban_sdk::{contract, contractimpl, Env};\nuse stellar_accounts::policies::Policy;\n'
               '#[contract]\npub struct P;\n#[contractimpl]\nimpl P {\n    pub fn enforce(e: Env) {}\n}\n')
    lock = cargo_lock(soroban_sdk="23.5.3", stellar_accounts="0.7.1")
    files = {}
    for crate in ("tx-cap", "spend-cap"):
        files.update({f"contracts/{crate}/Cargo.toml": CARGO_TOML.format(sdk="23.5.3", extra='stellar-accounts = "0.7.1"\n'),
                      f"contracts/{crate}/Cargo.lock": lock, f"contracts/{crate}/src/lib.rs": account})
    [note] = dep_findings(audit(tmp_path / "a", files), "stellar-accounts")
    assert note["severity"] == "info"
    assert "contracts/tx-cap/Cargo.lock" in note["evidence"] and "contracts/spend-cap/Cargo.lock" in note["evidence"]
    moved = {k.replace("contracts/", "crates/"): v for k, v in files.items()}
    [again] = dep_findings(audit(tmp_path / "b", moved), "stellar-accounts")
    assert again["id"] == note["id"]


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


def test_mainnet_in_a_nested_app_that_installs_on_its_own_does_not_raise_the_root_server(tmp_path):
    root = {"package.json": json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0"}}),
            "package-lock.json": package_lock(stellar__mpp="0.4.0"), "src/server.ts": MPP_SERVER}
    example = {"apps/mainnet-demo/package.json": json.dumps({"dependencies": {"@stellar/stellar-sdk": "^14.0.0"}}),
               "apps/mainnet-demo/package-lock.json": package_lock(stellar__stellar_sdk="14.0.0"),
               "apps/mainnet-demo/src/index.ts": "import { Networks } from '@stellar/stellar-sdk';\n"
                                                     "export const p = Networks.PUBLIC;\n"}
    [finding] = dep_findings(audit(tmp_path / "a", {**root, **example}), "mpp-unsigned-hash-push-stellar-mpp")
    assert finding["severity"] == "medium"
    # Near miss: the same mainnet code in the server's own tree (a workspace member installed
    # through the root's lockfile, or a script) can reach the server's package: high.
    member = {k.replace("apps/mainnet-demo/", "packages/demo/"): v for k, v in example.items()
              if not k.endswith("package-lock.json")}
    [finding] = dep_findings(audit(tmp_path / "b", {**root, **member}), "mpp-unsigned-hash-push-stellar-mpp")
    assert finding["severity"] == "high"
    script = {"scripts/deploy.ts": "export const horizon = 'https://horizon.stellar.org';\n"}
    [finding] = dep_findings(audit(tmp_path / "c", {**root, **example, **script}), "mpp-unsigned-hash-push-stellar-mpp")
    assert finding["severity"] == "high"


def test_a_commented_out_charge_call_or_a_brace_in_a_string_is_not_a_server_without_fee_payer(tmp_path):
    sponsored = ('import { stellar } from "@stellar/mpp/charge/server";\n'
                 '// Without a sponsor you could write: stellar.charge({ recipient, currency })\n'
                 '/* stellar({ recipient }) */\n'
                 'export const method = stellar.charge({ recipient: "}", currency: USDC, feePayer: sponsor, '
                 "network: 'stellar:pubnet' });\n")
    assert not mpp_findings(tmp_path / "a", "0.4.0", sponsored)
    # Near miss: the same server without the sponsor is still reported, at the call's line.
    [finding] = mpp_findings(tmp_path / "b", "0.4.0", sponsored.replace("feePayer: sponsor, ", ""))
    assert finding["severity"] == "high" and "src/server.ts:4" in finding["evidence"]
    # A quote in a regular-expression literal opens no string: the call after it is still read.
    regex = ('import { stellar } from "@stellar/mpp/charge/server";\n'
             'const quote = /"/; export const method = stellar.charge({ recipient, currency: USDC });\n')
    [finding] = mpp_findings(tmp_path / "c", "0.4.0", regex)
    assert "src/server.ts:2" in finding["evidence"]


def test_two_servers_on_one_mpp_version_are_one_finding(tmp_path):
    files = {"package.json": json.dumps({"workspaces": ["packages/*"]}),
             "package-lock.json": package_lock(stellar__mpp="0.3.0")}
    for name in ("a", "b"):
        files[f"packages/{name}/package.json"] = json.dumps({"dependencies": {"@stellar/mpp": "^0.3.0"}})
        files[f"packages/{name}/src/server.ts"] = MPP_SERVER
    [finding] = dep_findings(audit(tmp_path, files), "mpp-unsigned-hash-push-stellar-mpp")
    assert "packages/a/src/server.ts:7" in finding["evidence"] and "packages/b/src/server.ts:7" in finding["evidence"]


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


def test_policy_signers_count_only_inside_the_package_root_that_installs_the_kit(tmp_path):
    wallet = 'import { PasskeyKit } from "passkey-kit";\nexport const kit = (k: PasskeyKit) => k;\n'
    policy = 'import { PasskeyKit } from "passkey-kit";\nexport const add = (kit: PasskeyKit, p: string) => kit.addPolicy(p, {});\n'
    template = {"templates/wallet/package.json": json.dumps({"dependencies": {"passkey-kit": "^0.12.0"}}),
                "templates/wallet/package-lock.json": package_lock(passkey_kit="0.12.0"),
                "templates/wallet/src/passkey.ts": wallet}
    root = {"package.json": json.dumps({"dependencies": {"passkey-kit": "^0.10.19"}}),
            "package-lock.json": package_lock(passkey_kit="0.10.19"), "src/utils.ts": wallet,
            "policy-cli/Cargo.toml": '[package]\nname = "policy-cli"\n',
            "policy-cli/templates/contract/lib.rs.hbs": "use soroban_sdk::contract;\npub fn policy__(e: Env) {}\n"}
    # The repository root's tree has a policy contract template; the browser template has none.
    [note] = dep_findings(audit(tmp_path / "a", {**root, **template}), "passkey-kit-policy-signer")
    assert "package-lock.json: passkey-kit 0.10.19" in note["evidence"] and "0.12.0" not in note["evidence"]
    # Policies used inside the template's own tree do count for it.
    template["templates/wallet/src/policy.ts"] = policy
    found = dep_findings(audit(tmp_path / "b", {**template, "package.json": "{}", "src/utils.ts": "export {};\n"}),
                         "passkey-kit-policy-signer")
    assert [f["evidence"].split(";")[0] for f in found] == ["templates/wallet/package-lock.json: passkey-kit 0.12.0"]


def test_a_nested_package_that_installs_on_its_own_is_not_part_of_the_root_wallet(tmp_path):
    wallet = 'import { PasskeyKit } from "passkey-kit";\nexport const kit = (k: PasskeyKit) => k;\n'
    policy = 'import { PasskeyKit } from "passkey-kit";\nexport const add = (kit: PasskeyKit, p: string) => kit.addPolicy(p, {});\n'
    root = {"package.json": json.dumps({"dependencies": {"passkey-kit": "^0.12.0"}}),
            "package-lock.json": package_lock(passkey_kit="0.12.0"), "src/index.ts": wallet}
    nested = {"apps/policy-wallet/package.json": json.dumps({"dependencies": {"passkey-kit": "^0.11.0"}}),
              "apps/policy-wallet/package-lock.json": package_lock(passkey_kit="0.11.0"),
              "apps/policy-wallet/src/policy.ts": policy}
    # Near miss: the root wallet (0.12.0) has no policy signer; the nested app's own install does.
    found = dep_findings(audit(tmp_path / "a", {**root, **nested}), "passkey-kit-policy-signer")
    assert [f["evidence"] for f in found] == [
        "apps/policy-wallet/package-lock.json: passkey-kit 0.11.0; policy signers: apps/policy-wallet/src/policy.ts"]
    # The same holds below a nested package root, and for a nested package that declares the kit
    # itself without a lockfile of its own.
    moved = {f"web/{k}": v for k, v in {**root, **nested}.items()}
    found = dep_findings(audit(tmp_path / "b", {**moved, "package.json": "{}"}), "passkey-kit-policy-signer")
    assert [f["evidence"].split(";")[0] for f in found] == ["web/apps/policy-wallet/package-lock.json: passkey-kit 0.11.0"]
    lockset = Lockset({"importers": {"": {"lockfiles": ["package-lock.json"], "deps": {"passkey-kit": {}}},
                                     "apps/w": {"lockfiles": ["package-lock.json"], "deps": {"passkey-kit": {}}},
                                     "apps/m": {"lockfiles": ["package-lock.json"], "deps": {}}}})
    separate = advisory_check._separate_installs(lockset, "passkey-kit")
    assert not advisory_check._in_tree("apps/w/src/policy.ts", "", separate)
    assert advisory_check._in_tree("apps/m/src/policy.ts", "", separate)
    assert advisory_check._in_tree("apps/w/src/policy.ts", "apps/w", separate)
    # A workspace member that installs through the root's lockfile is part of the root's wallet.
    member = {"packages/policies/package.json": json.dumps({"name": "policies"}),
              "packages/policies/src/policy.ts": policy.replace("passkey-kit", "./kit")}
    [note] = dep_findings(audit(tmp_path / "d", {**root, **member}), "passkey-kit-policy-signer")
    assert note["evidence"] == "package-lock.json: passkey-kit 0.12.0; policy signers: packages/policies/src/policy.ts"


def test_a_rust_policy_contract_beside_npm_bindings_stays_in_the_root_wallet(tmp_path):
    wallet = 'import { PasskeyKit } from "passkey-kit";\nexport const kit = (k: PasskeyKit) => k;\n'
    root = {"package.json": json.dumps({"dependencies": {"passkey-kit": "^0.11.0"}}),
            "package-lock.json": package_lock(passkey_kit="0.11.0"), "src/kit.ts": wallet,
            "contracts/policy/Cargo.toml": '[package]\nname = "policy"\n',
            "contracts/policy/src/lib.rs": "use soroban_sdk::Env;\npub fn policy__(e: Env) {}\n"}
    bindings = {"contracts/package.json": json.dumps({"devDependencies": {"@stellar/stellar-sdk": "^14.0.0"}}),
                "contracts/package-lock.json": package_lock(stellar__stellar_sdk="14.0.0")}
    [note] = dep_findings(audit(tmp_path / "a", {**root, **bindings}), "passkey-kit-policy-signer")
    assert note["evidence"] == "package-lock.json: passkey-kit 0.11.0; policy signers: contracts/policy/src/lib.rs"
    # Near miss: when that directory is another wallet (it installs the kit), the contract is
    # that wallet's, and its own copy is the one reported.
    other = {"contracts/package.json": json.dumps({"dependencies": {"passkey-kit": "^0.12.0"}}),
             "contracts/package-lock.json": package_lock(passkey_kit="0.12.0"), "contracts/src/w.ts": wallet}
    found = dep_findings(audit(tmp_path / "b", {**root, **other}), "passkey-kit-policy-signer")
    assert [f["evidence"].split(";")[0] for f in found] == ["contracts/package-lock.json: passkey-kit 0.12.0"]
    # A lockfile that installs the kit without the manifest naming it (a wallet SDK brings it) counts too.
    lockset = Lockset({"importers": {"": {"lockfiles": ["package-lock.json"], "deps": {"passkey-kit": {}}},
                                     "contracts": {"lockfiles": ["contracts/package-lock.json"], "deps": {}},
                                     "web": {"lockfiles": ["web/package-lock.json"], "deps": {}}},
                       "locked": {"package-lock.json": {"passkey-kit": ["0.11.0"]},
                                  "contracts/package-lock.json": {"@stellar/stellar-sdk": ["14.0.0"]},
                                  "web/package-lock.json": {"passkey-kit": ["0.12.0"]}}})
    assert advisory_check._separate_installs(lockset, "passkey-kit", installing=True) == {"", "web"}
    assert advisory_check._separate_installs(lockset, "passkey-kit") == {"", "contracts", "web"}


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


@pytest.mark.parametrize("above,hits", [
    ("// create the agent wallet on the blockchain\n", 1),   # 'blockchain' is not 'block'
    ("const badge = 'unknown';\n", 1),                         # nor 'badge' 'bad', nor 'unknown' 'known'
    ("// known bad hash, replace before release\n", 1),        # a comment is not a deny list
    ("const DENY_LIST = new Set([\n", 0),
    ("export const blockedWasm = [\n", 0),
])
def test_deny_words_count_only_as_whole_words_in_code(settings, run, above, hits):
    source = above + f'export const w = await kit.createWallet({{ wasmHash: "{BAD_HASH}" }});\n'
    assert len(stellar_native(settings, run, code_files={"src/wallet.ts": source})) == hits


def test_hash_lines_are_counted_like_line_numbers_and_each_hash_is_one_finding(settings, run):
    use = f'export const kit = new PasskeyKit({{ walletWasmHash: "{BAD_HASH}" }});\n'
    # Characters that str.splitlines() treats as line breaks must not shift the line read.
    shifted = "const a = 1;\u2028const b = 2;\x0cconst c = 3;\n" + use + use
    [finding] = stellar_native(settings, run, code_files={"src/kit.ts": shifted})
    assert finding.severity is Severity.CRITICAL and "src/kit.ts:2" in finding.evidence and "src/kit.ts:3" in finding.evidence


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


def test_unclosed_calls_and_repeated_hashes_cost_one_pass(settings):
    lock = {"importers": {"": {"lockfiles": ["Cargo.lock", "package-lock.json"], "deps": {
        "soroban-sdk": {"spec": "22.0.8", "version": "22.0.8", "source": "Cargo.lock"},
        "@stellar/mpp": {"spec": "0.4.0", "version": "0.4.0", "source": "package-lock.json"}}}},
        "locked": {"Cargo.lock": {"soroban-sdk": ["22.0.8"]}}}
    cases = {
        "mpp": {"src/server.ts": 'import { stellar } from "@stellar/mpp/charge/server";\n' + "stellar({ a: 1, " * 8_000},
        "slices": {"Cargo.toml": CARGO_TOML.format(sdk="22.0.8", extra=""), "src/lib.rs": VAULT + ".slice(" * 50_000},
        "nested mpp": {"src/server.ts": 'import { stellar } from "@stellar/mpp/charge/server";\n'
                                        + "stellar.charge({ a: " * 20_000 + "1" + " })" * 20_000},
        "hashes": {"src/kit.ts": f'export const w = kit.createWallet({{ wasmHash: "{BAD_HASH}" }});\n' * 5_000},
    }
    for label, files in cases.items():
        artifact = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="r", code_files=files,
                                 raw_metadata={"resolved_versions": lock})
        started = time.perf_counter()
        found = advisory_findings(artifact, StellarNativeAuditor(settings),
                                  today=date.fromisoformat(advisories.ADVISORIES[0].reviewed_at))
        assert time.perf_counter() - started < 1.5, label
        assert len({f.id for f in found}) == len(found), label  # duplicate ids fail the whole auditor
    assert [f.severity for f in found] == [Severity.CRITICAL]


def test_many_aliases_of_the_charge_method_cost_one_read_of_the_file():
    aliases = ", ".join(f"stellar as a{i}" for i in range(4_000))
    body = "const x = foo(1, 2);\n" * 15_000
    text = f"import {{ {aliases} }} from '@stellar/mpp/charge/server';\n" + body + "a3999.charge({ recipient });\n"
    started = time.perf_counter()
    assert advisory_check._mpp_servers_without_fee_payer("s.ts", text) == ["s.ts:15002"]
    assert time.perf_counter() - started < 1.0  # one scan per alias took 30 s here
    # The forms each alias is called in, and a near miss: `.charge` of another object is not the import.
    head = "import { stellar as s, charge } from '@stellar/mpp/charge/server';\nimport * as m from '@stellar/mpp/charge/server';\n"
    for call, hit in (("s({ a })", True), ("s . charge({ a })", True), ("charge({ a })", True), ("m.stellar.charge({ a })", True),
                      ("m.charge({ a })", True), ("x. charge({ a })", False), ("x.s.charge({ a })", False), ("s({ feePayer })", False)):
        assert bool(advisory_check._mpp_servers_without_fee_payer("s.ts", head + call + ";\n")) is hit, call


def test_many_servers_in_one_package_read_the_package_once(settings):
    lock = {"importers": {"": {"lockfiles": ["package-lock.json"], "deps": {
        "@stellar/mpp": {"spec": "0.4.0", "version": "0.4.0", "source": "package-lock.json"}}}}}
    server = ("import { stellar } from '@stellar/mpp/charge/server';\n"
              "export const m = stellar({ recipient: R, network: 'stellar:testnet' });\n" + "const x = foo(1, 2);\n" * 25)
    files = {f"src/s{i}.ts": server for i in range(800)}
    artifact = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="r", code_files=files,
                             raw_metadata={"resolved_versions": lock})
    started = time.perf_counter()
    [finding] = advisory_findings(artifact, StellarNativeAuditor(settings),
                                  today=date.fromisoformat(advisories.ADVISORIES[0].reviewed_at))
    assert time.perf_counter() - started < 2.0  # the package was read once per server: 25 s
    assert finding.severity is Severity.MEDIUM


def test_range_arguments_are_read_from_one_pass_over_the_file():
    # Deep parentheses, thousands of Bound paths in one argument, and thousands of literal calls.
    manifest = CARGO_TOML.format(sdk="22.0.8", extra="")
    for body, wraps in (("b.slice(" + "(" * 16_000 + "0..=n" + ")" * 16_000 + ");", True),
                        ("b.slice((" + ", ".join(["Bound::Included(1)"] * 8_000) + "));", True),
                        ("let x = b.slice(1..b.slice(1..3).len());\n" * 10_000, False),
                        # Nested calls: the outer arguments are too long to read, so they count.
                        ("b.slice((1 + b.slice((" * 2_000 + "1..3" + ")).len())..3)" * 2_000 + ";", True)):
        started = time.perf_counter()
        hits, safe = advisory_check._unchecked_ranges({"src/lib.rs": _rust_code(body)}, manifest)
        assert time.perf_counter() - started < 1.0, body[:30]
        assert bool(hits) is wraps and (bool(safe) or wraps), body[:30]
