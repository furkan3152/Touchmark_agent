"""Stellar lexical evidence must not turn declarations into enforcement proof."""
import pytest

from backend.app.models import AgentArtifact, EvidenceGrade, SourceKind
from backend.app.swarm.stellar_native import StellarNativeAuditor


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
