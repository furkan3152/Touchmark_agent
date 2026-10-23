"""Stellar lexical evidence must not turn declarations into enforcement proof."""
import asyncio
import json
import time

import httpx
import pytest
from stellar_sdk import Keypair

from backend.app.config import Settings
from backend.app.models import AgentArtifact, EvidenceGrade, Severity, SourceKind
from backend.app.services.repo_audit import audit_repository
from backend.app.stellar.authority import seed_exposure
from backend.app.swarm.stellar_native import StellarNativeAuditor, _seed_severity


def check(settings, run, source):
    return run(StellarNativeAuditor(settings).run(AgentArtifact(
        name='Contract boundary fixture', source_kind=SourceKind.UPLOAD,
        source_ref='fixture', code_files={'src/lib.rs': source},
    ), deep=True))


def scenario(verdict, identifier):
    return next(row for row in verdict.scenarios if row.scenario_id == identifier)


@pytest.mark.parametrize('decoy', [
    '// admin.require_auth();',
    '/* admin.require_auth(); /* nested comment */ */',
    'let documentation = "admin.require_auth();";',
    'let documentation = r###"admin.require_auth(); }"###;',
    'let documentation = br#"admin.require_auth();"#;',
])
def test_auth_in_comments_or_strings_is_not_call_evidence(settings, run, decoy):
    verdict = check(settings, run, 'pub fn set(env: Env, value: u32) {\n' + decoy + '\nenv.storage().instance().set(&0, &value); }')
    assert scenario(verdict, 'ST-001').passed is False
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-soroban-auth-missing')
    assert finding.evidence_grade is EvidenceGrade.INFERRED
    assert 'src/lib.rs:1 set' in finding.evidence


def test_one_protected_public_function_does_not_cover_another(settings, run):
    verdict = check(settings, run, '''
pub fn update(env: Env, admin: Address) { admin.require_auth(); env.storage().instance().set(&0, &1); }
pub fn set(env: Env, value: u32) { env.storage().instance().set(&0, &value); }
''')
    assert scenario(verdict, 'ST-001').passed is False
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-soroban-auth-missing')
    assert 'set' in finding.evidence and 'update' not in finding.evidence


def test_nested_protected_function_does_not_cover_parent(settings, run):
    verdict = check(settings, run, '''
pub fn execute(env: Env, value: u32) {
    fn unused_guard(admin: Address) { admin.require_auth(); }
    env.storage().instance().set(&0, &value);
}
''')
    assert scenario(verdict, 'ST-001').passed is False


def test_helper_auth_is_unresolved_review_evidence_not_confirmed_bypass(settings, run):
    verdict = check(settings, run, '''
fn check_admin(admin: &Address) { admin.require_auth(); }
pub fn set(env: Env, admin: Address) {
    check_admin(&admin); env.storage().instance().set(&0, &1);
}
''')
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-soroban-auth-missing')
    assert finding.evidence_grade is EvidenceGrade.INFERRED
    assert 'helper' in finding.detail and 'does not establish' in finding.detail


def test_constructor_and_custom_auth_do_not_require_recursive_require_auth(settings, run):
    verdict = check(settings, run, '''
pub fn __constructor(env: Env, admin: Address) { env.storage().instance().set(&0, &admin); }
pub fn __check_auth(env: Env) { env.storage().instance().set(&1, &2); }
''')
    assert not any(f.id == 'stellar_native-soroban-auth-missing' for f in verdict.findings)
    assert not any(s.scenario_id == 'ST-001' for s in verdict.scenarios)
    assert 'Constructor' in verdict.notes


def test_direct_call_is_only_static_presence_not_runtime_verification(settings, run):
    verdict = check(settings, run, '''
pub fn set<'a>(env: Env, admin: &'a Address) {
    let brace = '}'; admin.require_auth_for_args(vec![&env, 1]);
    env.storage().instance().set(&0, &1);
}
''')
    row = scenario(verdict, 'ST-001')
    assert row.passed is True
    assert row.evidence_grade is EvidenceGrade.INFERRED
    assert 'runtime enforcement remain unverified' in row.reason


@pytest.mark.parametrize('decoy', [
    '// env.storage().persistent().extend_ttl(&key, 10, 20);',
    'let documentation = r#"env.storage().persistent().extend_ttl(&key, 10, 20);"#;',
    'env.storage().instance().extend_ttl(10, 20);',
])
def test_comments_strings_and_instance_ttl_do_not_cover_persistent_keys(settings, run, decoy):
    verdict = check(settings, run, 'pub fn read(env: Env, key: u32) {\n' + decoy + '\nenv.storage().persistent().get::<_,u32>(&key); }')
    assert scenario(verdict, 'ST-002').passed is False
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-persistent-ttl')
    assert finding.evidence_grade is EvidenceGrade.INFERRED


def test_ttl_renewal_in_other_function_does_not_imply_path_coverage(settings, run):
    verdict = check(settings, run, '''
pub fn renew(env: Env, key: u32) { env.storage().persistent().extend_ttl(&key, 10, 20); }
pub fn read(env: Env, key: u32) { env.storage().persistent().get::<_,u32>(&key); }
''')
    assert scenario(verdict, 'ST-002').passed is False
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-persistent-ttl')
    assert 'read' in finding.evidence and 'renew' not in finding.evidence


@pytest.mark.parametrize('body', [
    'env . storage ( ) . persistent ( ) . get::<_,u32>(&key); env.storage().persistent().extend_ttl(&key, 10, 20);',
    'let storage = env.storage().persistent(); storage.get::<_,u32>(&key); storage.extend_ttl(&key, 10, 20);',
])
def test_same_function_persistent_ttl_is_static_presence_only(settings, run, body):
    verdict = check(settings, run, 'pub fn read(env: Env, key: u32) {' + body + '}')
    row = scenario(verdict, 'ST-002')
    assert row.passed is True
    assert row.evidence_grade is EvidenceGrade.INFERRED
    assert 'key binding' in row.reason and 'unverified' in row.reason


def test_missing_rust_surface_is_not_counted_as_authorization_or_ttl_pass(settings, run):
    verdict = check(settings, run, '// No contract functions supplied.')
    assert not any(s.scenario_id in {'ST-001', 'ST-002'} for s in verdict.scenarios)


def test_helper_checks_and_reads_are_review_items_not_high_risks(settings, run):
    helper = check(settings, run, '''
fn check_admin(admin: &Address) { admin.require_auth(); }
fn bump(env: &Env, key: &u32) { env.storage().persistent().extend_ttl(key, 10, 20); }
pub fn set(env: Env, admin: Address, key: u32) {
    check_admin(&admin); env.storage().persistent().set(&key, &1); Self::bump(&env, &key);
}
pub fn read(env: Env, key: u32) { env.storage().persistent().get::<_,u32>(&key); }
''')
    by_id = {f.id: f for f in helper.findings}
    assert by_id['stellar_native-soroban-auth-missing'].severity.value == 'low'
    assert by_id['stellar_native-persistent-ttl'].severity.value == 'low'  # restorable: a liveness risk
    # Everything reaches a checking helper: unverified, not shown missing.
    assert not by_id['stellar_native-soroban-auth-missing'].is_risk
    bare = check(settings, run, 'pub fn set(env: Env, key: u32) { env.storage().persistent().set(&key, &1); }')
    by_id = {f.id: f for f in bare.findings}
    assert by_id['stellar_native-soroban-auth-missing'].severity.value == 'medium'
    assert by_id['stellar_native-persistent-ttl'].severity.value == 'medium'


def test_temporary_storage_is_flagged_only_for_critical_keys(settings, run):
    counters = check(settings, run, '''
pub fn spend(env: Env, agent: Address, amount: i128) {
    agent.require_auth();
    env.storage().temporary().set(&DataKey::Spent(agent, 1), &amount);
    env.storage().temporary().extend_ttl(&DataKey::Spent(agent, 1), 0, 17280);
}
''')
    assert not any(f.id == 'stellar_native-temporary-critical-state' for f in counters.findings)
    escrow = check(settings, run, '''
pub fn lock(env: Env, payer: Address, amount: i128) {
    payer.require_auth();
    env.storage().temporary().set(&DataKey::Escrow(payer), &amount);
}
''')
    assert any(f.id == 'stellar_native-temporary-critical-state' for f in escrow.findings)


def test_openzeppelin_only_attributes_count_as_authorization(settings, run):
    verdict = check(settings, run, '''
#[only_owner]
pub fn set_fee(e: &Env, fee: u32) { e.storage().instance().set(&0, &fee); }
#[only_role(caller, "manager")]
pub fn set_limit(e: &Env, limit: u32, caller: Address) { e.storage().instance().set(&1, &limit); }
pub fn set_other(e: &Env, value: u32) { e.storage().instance().set(&2, &value); }
''')
    finding = next(f for f in verdict.findings if f.id == 'stellar_native-soroban-auth-missing')
    assert 'set_other' in finding.evidence
    assert 'set_fee' not in finding.evidence and 'set_limit' not in finding.evidence


def test_upgrade_entry_points_are_judged_by_the_upgrade_rule_not_twice(settings, run):
    verdict = check(settings, run, '''
pub fn upgrade(env: Env, hash: BytesN<32>) { env.deployer().update_current_contract_wasm(hash); }
''')
    assert [f.severity.value for f in verdict.findings if f.id.startswith('stellar_native-soroban-upgrade-unguarded')] == ['critical']
    assert not any(f.id == 'stellar_native-soroban-auth-missing' for f in verdict.findings)


# ----------------------------------------------------------------- seed triage from the ledger
def _exposure(place, mainnet="not_found", testnet="not_found", declared="", status="checked", balances=()):
    key = Keypair.random().public_key
    return {"status": status, "checked_at": "2026-10-22T00:00:00+00:00", "keys": [
        {"public_key": key, "locations": [place], "declared": declared,
         "mainnet": {"status": mainnet, "exists": mainnet == "found", "signs_for": 0,
                     "balances": [{"asset": "XLM", "balance": b} for b in balances]},
         "testnet": {"status": testnet, "exists": testnet == "found", "signs_for": 0, "balances": []}}]}


@pytest.mark.parametrize("place,ledger,expected", [
    ("tests/fixtures/keys.ts:3", dict(mainnet="found", balances=("500.0000000",)), Severity.CRITICAL),
    ("tests/fixtures/keys.ts:3", {}, Severity.LOW),
    ("tests/fixtures/keys.ts:3", dict(testnet="found"), Severity.LOW),
    ("keys/agent-wallet.key:2", {}, Severity.MEDIUM),
    ("src/agent.ts:9", dict(testnet="found"), Severity.MEDIUM),
    ("src/test.ts:23", dict(declared="owner", status="not_checked"), Severity.CRITICAL),
])
def test_seed_severity_follows_what_the_key_controls(place, ledger, expected):
    severity, notes = _seed_severity(_exposure(place, **ledger), [place])
    assert severity is expected and notes and notes[0].startswith(place)


def test_seed_severity_falls_back_to_the_path_when_the_ledger_was_not_read():
    for status, note in (("not_checked", False), ("unavailable", True)):
        exposure = _exposure("src/agent.ts:9", mainnet="unavailable", status=status)
        assert _seed_severity(exposure, ["src/agent.ts:9"])[0] is Severity.CRITICAL
        assert bool(_seed_severity(exposure, ["src/agent.ts:9"])[1]) is note
        exposure = _exposure("tests/keys.ts:1", mainnet="unavailable", status=status)
        assert _seed_severity(exposure, ["tests/keys.ts:1"])[0] is Severity.MEDIUM
    assert _seed_severity(None, ["tests/keys.ts:1", "src/agent.ts:9"]) == (Severity.CRITICAL, [])


def test_two_seeds_on_one_line_are_each_judged_and_the_funded_one_decides(tmp_path):
    from backend.app.services.repo_audit import committed_seeds, seed_public_keys

    funded, empty = Keypair.random(), Keypair.random()
    line = '{"funder": "%s", "agent": "%s"}\n' % (funded.secret, empty.secret)
    (tmp_path / "keys.json").write_text(line)
    keys: dict = {}
    assert len(committed_seeds(tmp_path, set(), keys=keys)) == 2
    assert keys == {"keys.json:1": [funded.public_key, empty.public_key]}
    located = seed_public_keys({}, keys)
    assert located == {funded.public_key: ["keys.json:1"], empty.public_key: ["keys.json:1"]}
    exposure = {"status": "checked", "checked_at": "2026-10-23T00:00:00+00:00", "keys": [
        {"public_key": key, "locations": where, "declared": "",
         "mainnet": {"status": "found" if key == funded.public_key else "not_found",
                     "balances": [{"asset": "XLM", "balance": "5000"}] if key == funded.public_key else []},
         "testnet": {"status": "not_found"}} for key, where in located.items()]}
    for order in (["keys.json:1", "keys.json:1"], ["keys.json:1"]):
        severity, notes = _seed_severity(exposure, order)
        assert severity is Severity.CRITICAL
        assert any(funded.public_key[:8] in n and "controls mainnet funds" in n for n in notes)
        assert any(empty.public_key[:8] in n and "no account" in n for n in notes)
    # Near miss: both unfunded stays medium.
    for item in exposure["keys"]:
        item["mainnet"] = {"status": "not_found", "balances": []}
    assert _seed_severity(exposure, ["keys.json:1"])[0] is Severity.MEDIUM


def test_seed_exposure_sends_public_keys_only():
    seed = Keypair.random()
    asked: list[str] = []

    def horizon(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        if request.url.host == "horizon.stellar.org" and request.url.path.endswith(seed.public_key):
            return httpx.Response(200, json={"account_id": seed.public_key,
                                             "balances": [{"asset_type": "native", "balance": "500.0000000"}]})
        if request.url.path == "/accounts":
            return httpx.Response(200, json={"_embedded": {"records": []}})
        return httpx.Response(404, json={})
    out = asyncio.run(seed_exposure([seed.public_key], transport=httpx.MockTransport(horizon)))
    record = out["keys"][seed.public_key]
    assert record["mainnet"] == {"status": "found", "exists": True, "signs_for": 0,
                                 "balances": [{"asset": "XLM", "balance": "500.0000000"}]}
    assert record["testnet"]["status"] == "not_found"
    assert asked and not any(seed.secret in url for url in asked)
    assert {httpx.URL(u).host for u in asked} == {"horizon.stellar.org", "horizon-testnet.stellar.org"}


def test_seed_lookup_stops_a_failing_network_and_keeps_to_its_budget():
    keys = [Keypair.random().public_key for _ in range(12)]
    asked: list[str] = []

    async def horizon(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.host)
        if request.url.host == "horizon.stellar.org":
            raise httpx.ConnectError("unreachable", request=request)
        await asyncio.sleep(10 if request.url.path.endswith(keys[-1]) else 0)
        return httpx.Response(404, json={}) if request.url.path != "/accounts" else \
            httpx.Response(200, json={"_embedded": {"records": []}})
    started = time.monotonic()
    out = asyncio.run(seed_exposure(keys, transport=httpx.MockTransport(horizon), budget=0.5))
    assert time.monotonic() - started < 2
    assert all(out["keys"][k]["mainnet"] == {"status": "unavailable"} for k in keys)
    assert asked.count("horizon.stellar.org") <= 6  # the reads already in flight, then none
    assert out["keys"][keys[0]]["testnet"]["status"] == "not_found"
    assert out["keys"][keys[-1]]["testnet"] == {"status": "unavailable"}  # still waiting at the budget


def test_a_committed_seed_path_with_a_space_keeps_its_test_severity(settings, run):
    verdict = run(StellarNativeAuditor(settings).run(AgentArtifact(
        name="a", source_kind=SourceKind.REPO, source_ref="r", code_files={"src/a.py": "x = 1\n"},
        raw_metadata={"committed_seeds": ["my tests/keys.txt:2 (SABC…redacted)"]}), deep=False))
    finding = next(f for f in verdict.findings if f.id == "stellar_native-stellar-secret-seed")
    assert finding.severity is Severity.MEDIUM


def test_a_fixture_seed_funded_on_mainnet_is_critical(tmp_path, monkeypatch):
    seed = Keypair.random()
    root = tmp_path / "agent"
    (root / "tests/fixtures").mkdir(parents=True)
    (root / "server.py").write_text("import os\nKEY = os.environ['AGENT_SECRET']\n")
    (root / "tests/fixtures/keys.ts").write_text(f'export const PAYER = "{seed.secret}";\n')
    sent: list[list[str]] = []

    async def ledger(public_keys, **_):
        sent.append(public_keys)
        return {"checked_at": "2026-10-22T00:00:00+00:00", "keys": {seed.public_key: {
            "mainnet": {"status": "found", "exists": True, "signs_for": 0,
                        "balances": [{"asset": "XLM", "balance": "500.0000000"}]},
            "testnet": {"status": "not_found", "exists": False, "signs_for": 0, "balances": []}}}}
    monkeypatch.setattr("backend.app.stellar.authority.seed_exposure", ledger)

    def seed_finding(**settings):
        out = asyncio.run(audit_repository(root, name="a", purpose="", deep=False,
                                           settings=Settings(_env_file=None, **settings)))
        return next(f for f in out["report"]["findings"] if f["id"] == "stellar_native-stellar-secret-seed")
    assert seed_finding()["severity"] == "medium" and sent == []  # reads off: today's path-based severity
    finding = seed_finding(enable_onchain_verification=True)
    assert finding["severity"] == "critical" and "controls mainnet funds" in finding["evidence"]
    assert sent == [[seed.public_key]] and seed.secret not in json.dumps(finding)


def test_on_chain_finding_ids_do_not_depend_on_order(settings):
    a, b = Keypair.random().public_key, Keypair.random().public_key
    issuer = Keypair.random().public_key

    def ids(destinations):
        facts = {"network": "testnet", "account": {"status": "found", "address": a, "thresholds": {"high": 1},
                                                    "trustlines": [{"asset": f"USDC:{issuer}", "limit": "x", "unlimited": True}],
                                                    "home_domain": "x.org"},
                 "destinations": [{"address": d, "location": "src/a.ts:1", "status": "found", "memo_required": True,
                                   "code_attaches_memo": False} for d in destinations]}
        artifact = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="r", chain_authority=facts)
        return sorted(f.id for f in StellarNativeAuditor(settings)._authority_findings(artifact))
    assert ids([a, b]) == ids([b, a])
    assert f"stellar_native-onchain-memo-required-{b[:8]}" in ids([a, b])
    assert f"stellar_native-onchain-unlimited-trustline-USDC-{issuer[:8]}" in ids([a])
