"""Soroban contract rules: each one fires on its vulnerable shape and stays silent on the near miss."""
import time

import pytest

from backend.app.models import AgentArtifact, EvidenceGrade, FindingKind, Severity, SourceKind
from backend.app.reporting.english import english_finding
from backend.app.swarm.orchestrator import _KEEPS_SEVERITY
from backend.app.swarm.soroban_rules import cfg_test_files, render_template, without_test_modules
from backend.app.swarm.stellar_native import StellarNativeAuditor, _rust_code

CARGO = '[package]\nname = "c"\nversion = "0.1.0"\n\n[dependencies]\nsoroban-sdk = "23.0.0"\n'


def audit(settings, run, files, kind=SourceKind.UPLOAD, raw=None):
    if isinstance(files, str):
        files = {'src/lib.rs': files}
    return run(StellarNativeAuditor(settings).run(AgentArtifact(
        name='Soroban rule fixture', source_kind=kind, source_ref='fixture', code_files=files,
        raw_metadata=raw or {}), deep=True))


def rule(verdict, slug):
    return [f for f in verdict.findings if f.id.startswith(f'stellar_native-{slug}')]


def soroban_rules(verdict):
    return sorted(f.id.rsplit('-', 1)[0] for f in verdict.findings
                  if f.id.startswith('stellar_native-soroban-') and f.id != 'stellar_native-soroban-auth-missing')


ACCOUNT = '''
use soroban_sdk::{auth::{Context, CustomAccountInterface}, contract, contractimpl, contracttype, crypto::Hash, BytesN, Env, Vec};
#[contracttype]
enum DataKey { Agent, Spent }
#[contract]
pub struct AgentAccount;
#[contractimpl]
impl CustomAccountInterface for AgentAccount {
    type Signature = BytesN<64>;
    type Error = Error;
    fn __check_auth(env: Env, payload: Hash<32>, sig: BytesN<64>, CTX) -> Result<(), Error> {
        let pk: BytesN<32> = env.storage().instance().get(&DataKey::Agent).unwrap();
        env.crypto().ed25519_verify(&pk, &payload.into(), &sig);
        BODY
        Ok(())
    }
}
'''


def account(ctx='_ctx: Vec<Context>', body=''):
    return ACCOUNT.replace('CTX', ctx).replace('BODY', body)


# ---------------------------------------------------------------- __check_auth (C1, C2, C3)

def test_check_auth_that_ignores_contexts_is_high(settings, run):
    verdict = audit(settings, run, account())
    [finding] = rule(verdict, 'soroban-check-auth-contexts-ignored')
    assert finding.severity is Severity.HIGH and finding.is_risk
    assert soroban_rules(verdict) == ['stellar_native-soroban-check-auth-contexts-ignored']


def test_check_auth_with_an_allow_list_is_silent(settings, run):
    verdict = audit(settings, run, account('ctx: Vec<Context>', '''
        for c in ctx.iter() {
            match c {
                Context::Contract(cc) if cc.contract == usdc(&env) && cc.fn_name == symbol_short!("transfer") => check_window(&env, &cc.args)?,
                _ => return Err(Error::NotAllowed),
            }
        }'''))
    assert soroban_rules(verdict) == []


def test_plain_single_key_account_is_not_a_limit_bypass(settings, run):
    # The soroban-examples simple account: one owner key, no limits promised anywhere.
    verdict = audit(settings, run, account().replace('Agent', 'Owner').replace('Spent', 'Nonce'))
    assert soroban_rules(verdict) == []


def test_delegating_account_forwards_contexts(settings, run):
    source = account().replace('env.crypto().ed25519_verify(&pk, &payload.into(), &sig);',
                               'for d in env.custom_account().get_delegated_signers().iter() { env.custom_account().delegate_auth(&d); }')
    assert soroban_rules(audit(settings, run, source)) == []


def test_check_auth_that_verifies_nothing_is_critical(settings, run):
    source = account('ctx: Vec<Context>', 'for c in ctx.iter() { if let Context::Contract(cc) = c { check(&env, &cc)?; } }')
    source = source.replace('env.crypto().ed25519_verify(&pk, &payload.into(), &sig);', '')
    [finding] = rule(audit(settings, run, source), 'soroban-check-auth-unauthenticated')
    assert finding.severity is Severity.CRITICAL and finding.evidence_grade is EvidenceGrade.CONFIRMED


def test_payload_alias_counts_as_verification(settings, run):
    source = account('ctx: Vec<Context>', 'for c in ctx.iter() { screen(&env, c)?; }').replace(
        'env.crypto().ed25519_verify(&pk, &payload.into(), &sig);',
        'let msg: Bytes = payload.into(); env.crypto().ed25519_verify(&pk, &msg, &sig);')
    source += 'fn screen(env: &Env, c: Context) -> Result<(), Error> { match c { _ => Err(Error::NotAllowed) } }'
    assert soroban_rules(audit(settings, run, source)) == []


def test_deny_list_copy_approves_unlisted_functions(settings, run):
    verdict = audit(settings, run, account('ctx: Vec<Context>', '''
        for c in ctx.iter() {
            if let Context::Contract(cc) = c {
                if cc.fn_name != symbol_short!("transfer") && cc.fn_name != symbol_short!("approve") { continue; }
                let amount: i128 = cc.args.get(2).unwrap().into_val(&env);
                if amount > 1000 { return Err(Error::OverLimit); }
            }
        }'''))
    [finding] = rule(verdict, 'soroban-check-auth-deny-list')
    assert finding.severity is Severity.HIGH


def test_negated_test_that_rejects_is_an_allow_list(settings, run):
    verdict = audit(settings, run, account('ctx: Vec<Context>', '''
        for c in ctx.iter() {
            if let Context::Contract(cc) = c {
                if cc.fn_name != symbol_short!("transfer") { return Err(Error::NotAllowed); }
            } else { return Err(Error::NotAllowed); }
        }'''))
    assert rule(verdict, 'soroban-check-auth-deny-list') == []


# ---------------------------------------------------------------- self-administration and caps (C7, C8, C6)

SELF_ADMIN = '''
use soroban_sdk::{auth::{Context, CustomAccountInterface}, contract, contractimpl, contracttype, crypto::Hash, Bytes, BytesN, Env, Symbol, Vec};
#[contracttype]
enum Key { Signer, Limit }
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    pub fn set_limit(env: Env, limit: i128) {
        env.current_contract_address().require_auth();
        env.storage().instance().set(&Key::Limit, &limit);
    }
}
#[contractimpl]
impl CustomAccountInterface for Wallet {
    type Signature = Sig;
    type Error = Error;
    fn __check_auth(env: Env, payload: Hash<32>, sig: Sig, contexts: Vec<Context>) -> Result<(), Error> {
        let signer: BytesN<32> = env.storage().instance().get(&Key::Signer).unwrap();
        let msg: Bytes = payload.into();
        env.crypto().ed25519_verify(&signer, &msg, &sig.signature);
        let cap: i128 = env.storage().instance().get(&Key::Limit).unwrap();
        let me = env.current_contract_address();
        for c in contexts.iter() { allowed(&env, c, &me, cap)?; }
        Ok(())
    }
}
fn allowed(env: &Env, c: Context, me: &Address, cap: i128) -> Result<(), Error> {
    let c = match c { Context::Contract(c) => c, _ => return Err(Error::NotAllowed) };
    if &c.contract == me {
        SELF_BRANCH
        return Err(Error::NotAllowed);
    }
    if c.fn_name == Symbol::new(env, "transfer") {
        let amount: i128 = c.args.get(2).unwrap().into_val(env);
        if amount < 0 { return Err(Error::Invalid); }
        if amount > cap { return Err(Error::OverCap); }
        return Ok(());
    }
    Err(Error::NotAllowed)
}
'''


def test_spending_key_can_rewrite_its_own_cap(settings, run):
    source = SELF_ADMIN.replace('SELF_BRANCH', 'if c.fn_name == Symbol::new(env, "set_limit") { return Ok(()); }')
    verdict = audit(settings, run, source)
    [self_admin] = rule(verdict, 'soroban-account-self-admin')
    assert self_admin.severity is Severity.MEDIUM and self_admin.evidence_grade is EvidenceGrade.INFERRED
    [cap] = rule(verdict, 'soroban-policy-per-call-cap')
    assert cap.severity is Severity.LOW  # a per-transaction cap in __check_auth
    assert sorted(soroban_rules(verdict)) == ['stellar_native-soroban-account-self-admin',
                                              'stellar_native-soroban-policy-per-call-cap']
    declared = {'tmark': {'declared': {'limits': {'per_payment': {'amount': '10', 'asset': 'XLM'}}}}}
    [raised] = rule(audit(settings, run, source, raw=declared), 'soroban-account-self-admin')
    assert raised.severity is Severity.HIGH


SELF_INLINE = '''
use soroban_sdk::{auth::{Context, CustomAccountInterface}, contract, contractimpl, contracttype, crypto::Hash, symbol_short, BytesN, Env, Vec};
#[contracttype]
enum Key { Signer, Limit }
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    pub fn set_limit(env: Env, limit: i128) {
        env.current_contract_address().require_auth();
        env.storage().instance().set(&Key::Limit, &limit);
    }
}
#[contractimpl]
impl CustomAccountInterface for Wallet {
    type Signature = Vec<BytesN<64>>;
    type Error = Error;
    fn __check_auth(env: Env, payload: Hash<32>, sigs: Vec<BytesN<64>>, contexts: Vec<Context>) -> Result<(), Error> {
        VERIFY
        for ctx in contexts.iter() {
            if let Context::Contract(c) = ctx {
                if c.contract == env.current_contract_address() { SELF_BRANCH return Ok(()); }
                if c.fn_name != symbol_short!("transfer") { return Err(Error::NotAllowed); }
                let amount: i128 = c.args.get(2).unwrap().into_val(&env);
                if amount < 0 || amount > 100 { return Err(Error::OverCap); }
            } else { return Err(Error::NotAllowed); }
        }
        Ok(())
    }
}
'''
ONE_KEY = ('let k: BytesN<32> = env.storage().instance().get(&Key::Signer).unwrap(); '
           'env.crypto().ed25519_verify(&k, &payload.clone().into(), &sigs.get(0).unwrap());')


def test_self_call_compared_with_the_contract_address_inline(settings, run):
    source = SELF_INLINE.replace('VERIFY', ONE_KEY).replace('SELF_BRANCH', '')
    [finding] = rule(audit(settings, run, source), 'soroban-account-self-admin')
    assert finding.severity is Severity.MEDIUM and finding.evidence_grade is EvidenceGrade.CONFIRMED


def test_multisig_or_guardian_self_calls_are_not_self_administration(settings, run):
    multisig = SELF_INLINE.replace('SELF_BRANCH', '').replace('VERIFY', (
        'let keys: Vec<BytesN<32>> = env.storage().instance().get(&Key::Signer).unwrap(); '
        'for i in 0..keys.len() { env.crypto().ed25519_verify(&keys.get(i).unwrap(), &payload.clone().into(), &sigs.get(i).unwrap()); }'))
    assert rule(audit(settings, run, multisig), 'soroban-account-self-admin') == []
    guardian = SELF_INLINE.replace('VERIFY', ONE_KEY).replace('SELF_BRANCH', 'second_key(&env, &payload, &sigs)?;')
    assert rule(audit(settings, run, guardian), 'soroban-account-self-admin') == []


def test_self_calls_that_need_another_signer_are_not_self_administration(settings, run):
    source = SELF_ADMIN.replace('SELF_BRANCH', 'return Err(Error::NeedsAdmin);')
    assert rule(audit(settings, run, source), 'soroban-account-self-admin') == []


def test_running_total_is_not_a_per_call_cap(settings, run):
    source = SELF_ADMIN.replace('SELF_BRANCH', '').replace(
        'if amount > cap { return Err(Error::OverCap); }',
        'let spent: i128 = env.storage().persistent().get(&Key::Limit).unwrap_or(0);\n'
        '        if spent + amount > cap { return Err(Error::OverCap); }\n'
        '        env.storage().persistent().set(&Key::Limit, &(spent + amount));')
    assert rule(audit(settings, run, source), 'soroban-policy-per-call-cap') == []
    assert rule(audit(settings, run, source), 'soroban-policy-negative-amount') == []


def test_negative_amount_lowers_the_running_total(settings, run):
    source = SELF_ADMIN.replace('SELF_BRANCH', '').replace('if amount < 0 { return Err(Error::Invalid); }', '').replace(
        'if amount > cap { return Err(Error::OverCap); }',
        'let spent: i128 = env.storage().persistent().get(&Key::Limit).unwrap_or(0);\n'
        '        if spent + amount > cap { return Err(Error::OverCap); }\n'
        '        env.storage().persistent().set(&Key::Limit, &(spent + amount));')
    [finding] = rule(audit(settings, run, source), 'soroban-policy-negative-amount')
    assert finding.severity is Severity.MEDIUM


# ---------------------------------------------------------------- policies (C4, C5, C8) and templates

POLICY = '''
use soroban_sdk::{auth::{Context, ContractContext}, contract, contractimpl, contracttype, Address, Env, TryFromVal, Vec};
#[contracttype]
pub enum Key { Last(SignerKey) }
#[contract]
pub struct Policy;
#[contractimpl]
impl Policy {
    pub fn policy__(env: Env, SOURCE: Address, signer: SignerKey, contexts: Vec<Context>) {
        AUTH
        for context in contexts.iter() {
            match context {
                Context::Contract(ContractContext { args, .. }) => {
                    if let Some(v) = args.get(2) {
                        if let Ok(amount) = i128::try_from_val(&env, &v) {
                            if amount > 1_000_0000000 { panic_with_error!(&env, Error::OverLimit); }
                        }
                    }
                    env.storage().persistent().set(&Key::Last(signer.clone()), &env.ledger().sequence());
                }
                _ => panic_with_error!(&env, Error::NotAllowed),
            }
        }
    }
}
'''


def test_policy_without_wallet_auth_writes_state(settings, run):
    verdict = audit(settings, run, POLICY.replace('SOURCE', '_source').replace('AUTH', ''))
    [state] = rule(verdict, 'soroban-policy-state-unauthorized')
    assert state.severity is Severity.MEDIUM
    [cap] = rule(verdict, 'soroban-policy-per-call-cap')
    assert cap.severity is Severity.MEDIUM  # a policy contract's cap
    # policy__ is judged here, not again by the presence check.
    assert 'policy__' not in ' '.join(f.evidence for f in rule(verdict, 'soroban-auth-missing'))


def test_policy_that_authorizes_its_wallet_is_silent_on_state(settings, run):
    verdict = audit(settings, run, POLICY.replace('SOURCE', 'source').replace('AUTH', 'source.require_auth();'))
    assert rule(verdict, 'soroban-policy-state-unauthorized') == []


OZ_POLICY = '''
use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};
#[contract]
pub struct Limit;
#[contractimpl]
impl Policy for Limit {
    type AccountParams = i128;
    fn enforce(e: &Env, context: Context, SIGNERS: Vec<Signer>, context_rule: ContextRule, smart_account: Address) {
        BODY
    }
}
'''


def test_enforce_without_smart_account_auth_is_high(settings, run):
    verdict = audit(settings, run, OZ_POLICY.replace('SIGNERS', 'authenticated_signers').replace(
        'BODY', 'if authenticated_signers.is_empty() { panic!() } e.storage().persistent().set(&smart_account, &1);'))
    [finding] = rule(verdict, 'soroban-policy-enforce-unauthorized')
    assert finding.severity is Severity.HIGH and 'stored state' in finding.detail
    assert rule(verdict, 'soroban-policy-signers-unread') == []


def test_enforce_that_never_reads_signers_is_medium(settings, run):
    verdict = audit(settings, run, OZ_POLICY.replace('SIGNERS', '_authenticated_signers').replace(
        'BODY', 'smart_account.require_auth();'))
    assert [f.severity for f in rule(verdict, 'soroban-policy-signers-unread')] == [Severity.MEDIUM]
    assert rule(verdict, 'soroban-policy-enforce-unauthorized') == []


def test_enforce_delegating_to_the_library_is_silent(settings, run):
    verdict = audit(settings, run, OZ_POLICY.replace('SIGNERS', 'authenticated_signers').replace(
        'BODY', 'spending_limit::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)'))
    assert soroban_rules(verdict) == []


TEMPLATE = '''#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};
{{#if managed}}
mod keys;
{{/if}}
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn policy__(env: Env, _source: Address, _signer: SignerKey, contexts: Vec<Context>) {
        for context in contexts.iter() {
            {{#if throttle}}
            {{#if managed}}
            env.storage().persistent().set(&StorageKey::LastUse({{key}}), &env.ledger().sequence());
            {{else}}
            let gap: u32 = {{throttle.gap}};
            {{/if}}
            {{/if}}
        }
    }
}
'''


def test_template_is_rendered_by_union():
    rendered = render_template(TEMPLATE)
    assert '{{' not in rendered and rendered.count('\n') == TEMPLATE.count('\n')
    assert 'env.storage().persistent().set(' in rendered and 'let gap: u32 = tpl' in rendered


def test_contract_template_is_judged_as_every_generated_contract(settings, run):
    files = {'cli/templates/contract/lib.rs.hbs': TEMPLATE, 'cli/Cargo.toml': '[package]\nname = "cli"\n[dependencies]\nclap = "4"\n'}
    verdict = audit(settings, run, files, kind=SourceKind.REPO)
    [finding] = rule(verdict, 'soroban-policy-state-unauthorized')
    assert 'every generated contract' in finding.detail
    assert finding.evidence.startswith('cli/templates/contract/lib.rs.hbs:14 policy__')


# ---------------------------------------------------------------- upgrades and pause (U)

def test_upgrade_authorized_by_the_caller_alone_is_critical(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl Upgradeable for C {
    fn upgrade(e: &Env, h: BytesN<32>, op: Address) { op.require_auth(); upgradeable::upgrade(e, &h); }
}''')
    [finding] = rule(verdict, 'soroban-upgrade-unguarded')
    assert finding.severity is Severity.CRITICAL and finding.evidence_grade is EvidenceGrade.CONFIRMED
    assert _KEEPS_SEVERITY.search(finding.id)


@pytest.mark.parametrize('guard', ['#[only_role(op, "admin")]', '#[only_owner]'])
def test_upgrade_behind_an_openzeppelin_attribute_is_silent(settings, run, guard):
    verdict = audit(settings, run, f'''
#[contractimpl]
impl Upgradeable for C {{
    {guard}
    fn upgrade(e: &Env, h: BytesN<32>, op: Address) {{ upgradeable::upgrade(e, &h); }}
}}''')
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


def test_executable_ref_publish_by_stored_admin_is_silent(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl ExecRefs {
    pub fn __constructor(env: Env, admin: Address) { env.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn publish(env: Env, tag: String, wasm_hash: BytesN<32>) {
        read_admin(&env).require_auth();
        env.executable_refs().set(&tag, &wasm_hash);
    }
}
fn read_admin(env: &Env) -> Address { env.storage().instance().get(&DataKey::Admin).expect("admin") }''')
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


def test_upgrade_wasm_with_no_guard_through_a_helper_is_inferred_critical(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, hash: BytesN<32>) { Self::swap(&env, hash); }
    fn swap(env: &Env, hash: BytesN<32>) { env.deployer().update_current_contract_wasm(hash); }
}''')
    [finding] = rule(verdict, 'soroban-upgrade-unguarded')
    assert finding.severity is Severity.CRITICAL and finding.evidence_grade is EvidenceGrade.INFERRED
    assert rule(verdict, 'soroban-auth-missing') == []


def test_upgrade_behind_a_helper_on_a_parameter_is_an_evidence_gap(settings, run):
    verdict = audit(settings, run, '''
fn check(env: &Env, who: &Address) { who.require_auth(); }
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, who: Address, hash: BytesN<32>) {
        Self::check(&env, &who);
        env.deployer().update_current_contract_wasm(hash);
    }
}''')
    [finding] = rule(verdict, 'soroban-upgrade-weak-guard')
    assert finding.kind is FindingKind.EVIDENCE_GAP and finding.severity is Severity.MEDIUM


def test_caller_compared_with_the_admin_but_never_authorized_is_a_gap(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, caller: Address, hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin { panic!() }
        env.deployer().update_current_contract_wasm(hash);
    }
}''')
    assert [f.kind for f in rule(verdict, 'soroban-upgrade-weak-guard')] == [FindingKind.EVIDENCE_GAP]
    assert rule(verdict, 'soroban-upgrade-unguarded') == []


STORE_MODULE = '''
mod storage {
    use super::*;
    pub fn get_admin(env: &Env) -> Address { env.storage().instance().get(&DataKey::Admin).unwrap() }
}
pub struct AdminStore;
impl AdminStore {
    pub fn get(env: &Env) -> Address { env.storage().instance().get(&DataKey::Admin).unwrap() }
}
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        GUARD
        env.deployer().update_current_contract_wasm(hash);
    }
}
'''


@pytest.mark.parametrize('guard', ['storage::get_admin(&env).require_auth();', 'AdminStore::get(&env).require_auth();',
                                   'let admin = storage::get_admin(&env); admin.require_auth();'])
def test_upgrade_by_an_admin_read_through_a_module_path_is_silent(settings, run, guard):
    verdict = audit(settings, run, STORE_MODULE.replace('GUARD', guard))
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


def test_upgrade_that_only_reads_the_admin_is_critical(settings, run):
    # Passing env to a store helper is not a guard.
    verdict = audit(settings, run, STORE_MODULE.replace('GUARD', 'let _admin = storage::get_admin(&env);'))
    [finding] = rule(verdict, 'soroban-upgrade-unguarded')
    assert finding.severity is Severity.CRITICAL and finding.is_risk


def test_role_attribute_on_an_upgrade_is_one_finding(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl Upgradeable for C {
    #[has_role(op, "upgrader")]
    fn upgrade(e: &Env, h: BytesN<32>, op: Address) { upgradeable::upgrade(e, &h); }
}''')
    assert soroban_rules(verdict) == ['stellar_native-soroban-role-without-auth']


def test_unguarded_pause_is_high(settings, run):
    verdict = audit(settings, run, '''
#[contractimpl]
impl Pausable for C {
    fn pause(e: &Env, caller: Address) { caller.require_auth(); pausable::pause(e); }
    #[only_owner]
    fn unpause(e: &Env, caller: Address) { pausable::unpause(e); }
}''')
    [finding] = rule(verdict, 'soroban-upgrade-pause-unguarded')
    assert finding.severity is Severity.HIGH and 'pause' in finding.evidence


# ---------------------------------------------------------------- token moves (A, P), roles (R), auth args (D)

TOKEN = '''
#[contractimpl]
impl Vault {
    BODY
}
fn admin(env: &Env) -> Address { env.storage().instance().get(&Key::Admin).unwrap() }
'''


def test_token_move_from_an_unauthorized_address_is_high(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn settle(env: Env, user: Address, amount: i128) {
        admin(&env).require_auth();
        token::Client::new(&env, &usdc(&env)).transfer(&user, &env.current_contract_address(), &amount);
    }'''))
    [finding] = rule(verdict, 'soroban-token-move-unbound')
    assert finding.severity is Severity.HIGH and _KEEPS_SEVERITY.search(finding.id)


def test_bare_token_pass_through_is_low(settings, run):
    # The token's own authorization of `from` covers every argument the transfer uses.
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn swap(env: Env, from: Address, to: Address, amount: i128, min_out: i128) {
        let out = quote(amount);
        assert!(out >= min_out);
        token::Client::new(&env, &usdc(&env)).transfer(&from, &to, &out);
    }'''))
    assert [f.severity for f in rule(verdict, 'soroban-token-move-unbound')] == [Severity.LOW]


def test_token_move_after_the_owners_auth_is_silent(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        if amount <= 0 { panic_with_error!(&env, Error::Invalid); }
        token::Client::new(&env, &usdc(&env)).transfer(&user, &env.current_contract_address(), &amount);
    }'''))
    assert soroban_rules(verdict) == []


def test_allowance_pull_to_a_caller_chosen_address_is_critical(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn pull(env: Env, from: Address, to: Address, amount: i128) {
        let token = token::Client::new(&env, &usdc(&env));
        token.transfer_from(&env.current_contract_address(), &from, &to, &amount);
    }'''))
    [finding] = rule(verdict, 'soroban-token-move-allowance')
    assert finding.severity is Severity.CRITICAL and finding.is_risk


def test_spender_that_authorizes_its_own_allowance_is_silent(settings, run):
    # A SEP-41 token's own transfer_from, and a proxy where the spender signs.
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        move_balance(&env, &from, &to, amount);
    }
    pub fn relay(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        token::Client::new(&env, &usdc(&env)).transfer_from(&spender, &from, &to, &amount);
    }'''))
    assert soroban_rules(verdict) == []


EVENT_TOKEN = '''
use soroban_sdk::{contract, contractimpl, Address, Env};
use soroban_token_sdk::TokenUtils;
#[contract]
pub struct Token;
#[contractimpl]
impl token::Interface for Token {
    fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&e, from.clone(), spender, amount);
        spend_balance(&e, from.clone(), amount);
        receive_balance(&e, to.clone(), amount);
        TokenUtils::new(&e).events().transfer(from, to, amount);
    }
    fn burn_from(e: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&e, from.clone(), spender, amount);
        spend_balance(&e, from.clone(), amount);
        TokenUtils::new(&e).events().burn(from, amount);
    }
}
'''


def test_token_event_emitters_are_not_token_moves(settings, run):
    # soroban-token-sdk's TokenUtils events are named transfer and burn; they move nothing.
    verdict = audit(settings, run, EVENT_TOKEN)
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


@pytest.mark.parametrize('auth', ['let req = Req { from: from.clone(), amount }; req.from.require_auth();', 'LATER'])
def test_owner_authorized_through_a_struct_field_or_later_is_bound(settings, run, auth):
    body = '''pub fn deposit(env: Env, from: Address, amount: i128) {
        AUTH
        if amount <= 0 { panic!() }
        token::Client::new(&env, &usdc(&env)).transfer(&from, &env.current_contract_address(), &amount);
        TAIL
    }'''
    body = body.replace('AUTH', '').replace('TAIL', 'from.require_auth();') if auth == 'LATER' else \
        body.replace('AUTH', auth).replace('TAIL', '')
    assert soroban_rules(audit(settings, run, TOKEN.replace('BODY', body))) == []


def test_allowance_pull_by_the_stored_operator_is_a_medium_trust_risk(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn charge(env: Env, payer: Address, merchant: Address, amount: i128) {
        let operator: Address = env.storage().instance().get(&Key::Admin).unwrap();
        operator.require_auth();
        token::Client::new(&env, &usdc(&env)).transfer_from(&env.current_contract_address(), &payer, &merchant, &amount);
    }'''))
    assert rule(verdict, 'soroban-token-move-allowance') == []
    [finding] = rule(verdict, 'soroban-operator-pull')
    assert finding.severity is Severity.MEDIUM and finding.is_risk and 'operator' in finding.title


def test_allowance_pull_behind_an_unverified_role_check_is_a_gap(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn charge(env: Env, caller: Address, payer: Address, merchant: Address, amount: i128) {
        access_control::ensure_role(&env, &caller, &symbol_short!("billing"));
        token::Client::new(&env, &usdc(&env)).transfer_from(&env.current_contract_address(), &payer, &merchant, &amount);
    }'''))
    [finding] = rule(verdict, 'soroban-token-move-allowance')
    assert finding.severity is Severity.MEDIUM and finding.kind is FindingKind.EVIDENCE_GAP


def test_has_role_without_auth_is_high(settings, run):
    source = TOKEN.replace('BODY', '''#[has_role(caller, "minter")]
    pub fn mint(e: &Env, to: Address, amount: i128, caller: Address) {
        AUTH
        e.storage().persistent().set(&to, &amount);
    }''')
    [finding] = rule(audit(settings, run, source.replace('AUTH', '')), 'soroban-role-without-auth')
    assert finding.severity is Severity.HIGH
    assert rule(audit(settings, run, source.replace('AUTH', 'caller.require_auth();')), 'soroban-role-without-auth') == []


def test_has_role_without_auth_on_a_library_mint_is_high(settings, run):
    source = TOKEN.replace('BODY', '''#[has_role(caller, "minter")]
    pub fn mint(e: &Env, to: Address, amount: i128, caller: Address) { Base::mint(e, &to, amount); }''')
    [finding] = rule(audit(settings, run, source), 'soroban-role-without-auth')
    assert finding.severity is Severity.HIGH
    # The library's burn authorizes the holder it is given.
    burn = TOKEN.replace('BODY', '''#[has_role(from, "burner")]
    pub fn burn(e: &Env, from: Address, id: u32) { Base::burn(e, &from, id); }''')
    assert rule(audit(settings, run, burn), 'soroban-role-without-auth') == []


def test_auth_args_that_leave_out_the_recipient_are_high(settings, run):
    source = TOKEN.replace('BODY', '''pub fn pay(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth_for_args(ARGS);
        token::Client::new(&env, &usdc(&env)).transfer(&from, &to, &amount);
    }''')
    [finding] = rule(audit(settings, run, source.replace('ARGS', '(amount,).into_val(&env)')), 'soroban-auth-args-incomplete')
    assert finding.severity is Severity.HIGH and '`to`' in finding.detail
    assert soroban_rules(audit(settings, run, source.replace('ARGS', '(to.clone(), amount).into_val(&env)'))) == []


# ---------------------------------------------------------------- replay (E) and funding checks (V)

def test_signature_checked_without_a_nonce_can_be_replayed(settings, run):
    source = TOKEN.replace('BODY', '''pub fn claim(env: Env, to: Address, msg: Bytes, sig: BytesN<64>) {
        let pk: BytesN<32> = env.storage().instance().get(&Key::Signer).unwrap();
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        NONCE
        token::Client::new(&env, &usdc(&env)).transfer(&env.current_contract_address(), &to, &100);
    }''')
    [finding] = rule(audit(settings, run, source.replace('NONCE', '')), 'soroban-signature-replay')
    assert finding.severity is Severity.HIGH
    stored = source.replace('NONCE', 'let n: u64 = env.storage().persistent().get(&Key::Nonce).unwrap_or(0); '
                                      'env.storage().persistent().set(&Key::Nonce, &(n + 1));')
    assert rule(audit(settings, run, stored), 'soroban-signature-replay') == []


def test_signed_value_that_must_increase_is_not_replayable(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn submit(env: Env, price: i128, round: u64, msg: Bytes, sig: BytesN<64>) {
        let pk: BytesN<32> = env.storage().instance().get(&Key::Signer).unwrap();
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        let last: u64 = env.storage().instance().get(&Key::Round).unwrap_or(0);
        if round <= last { panic!() }
        env.storage().instance().set(&Key::Round, &round);
        env.storage().instance().set(&Key::Price, &price);
    }'''))
    assert rule(verdict, 'soroban-signature-replay') == []


def test_amount_held_to_a_named_minimum_is_checked(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount < MIN_DEPOSIT { panic!() }
        token::Client::new(&env, &usdc(&env)).transfer(&from, &env.current_contract_address(), &amount);
    }'''))
    assert rule(verdict, 'soroban-entry-amount-unchecked') == []


def test_funding_entry_point_without_an_amount_check_is_low(settings, run):
    source = TOKEN.replace('BODY', '''pub fn create_escrow(env: Env, payer: Address, amount: i128, deadline: u64) {
        payer.require_auth();
        CHECK
        token::Client::new(&env, &usdc(&env)).transfer(&payer, &env.current_contract_address(), &amount);
        env.storage().persistent().set(&Key::Deadline, &deadline);
    }
    pub fn refund(env: Env, id: u64) {
        let deadline: u64 = env.storage().persistent().get(&Key::Deadline).unwrap();
        if env.ledger().timestamp() < deadline { panic!() }
    }''')
    [finding] = rule(audit(settings, run, source.replace('CHECK', '')), 'soroban-entry-amount-unchecked')
    assert finding.severity is Severity.LOW and '`amount`' in finding.detail and 'deadline' not in finding.detail
    assert rule(audit(settings, run, source.replace('CHECK', 'if amount <= 0 { panic!() }')),
                'soroban-entry-amount-unchecked') == []


def test_amount_finding_does_not_hide_a_missing_authorization(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn create_escrow(env: Env, id: u64, amount: i128) {
        token::Client::new(&env, &usdc(&env)).transfer(&env.current_contract_address(), &vault(&env), &amount);
        env.storage().persistent().set(&id, &amount);
    }'''))
    assert rule(verdict, 'soroban-entry-amount-unchecked')
    assert 'create_escrow' in rule(verdict, 'soroban-auth-missing')[0].evidence


def test_deadline_never_compared_with_the_ledger(settings, run):
    source = TOKEN.replace('BODY', '''pub fn open(env: Env, payer: Address, deposit: i128, expiry_ledger: u32) {
        payer.require_auth();
        if deposit <= 0 { panic!() }
        token::Client::new(&env, &usdc(&env)).transfer(&payer, &env.current_contract_address(), &deposit);
    }''')
    [finding] = rule(audit(settings, run, source), 'soroban-entry-amount-unchecked')
    assert 'expiry_ledger' in finding.detail
    checked = source.replace('if deposit <= 0 { panic!() }',
                             'if deposit <= 0 { panic!() } let now = env.ledger().sequence(); if expiry_ledger <= now { panic!() }')
    assert rule(audit(settings, run, checked), 'soroban-entry-amount-unchecked') == []


# ---------------------------------------------------------------- initializers (I) and instance records (S)

INIT = '''
#[contractimpl]
impl Registry {
    pub fn initialize(env: Env, admin: Address) {
        GUARD
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }
    pub fn set_fee(env: Env, fee: u32) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
'''


def test_initializer_that_can_run_again_is_high(settings, run):
    files = {'contracts/registry/src/lib.rs': INIT.replace('GUARD', ''), 'contracts/registry/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing')
    assert finding.severity is Severity.HIGH and finding.is_risk
    assert finding.evidence.startswith('contracts/registry/src/lib.rs:4 initialize')
    assert 'once-only guard' in finding.detail and 'lack a direct require_auth' not in finding.detail
    assert english_finding(finding).detail == finding.detail  # the report keeps the specific text


def test_guarded_initializer_or_sample_contract_is_not_raised(settings, run):
    guarded = {'contracts/registry/src/lib.rs': INIT.replace('GUARD', 'if env.storage().instance().has(&DataKey::Admin) { panic!() }'),
               'contracts/registry/Cargo.toml': CARGO}
    assert rule(audit(settings, run, guarded, kind=SourceKind.REPO), 'soroban-auth-missing') == []
    # A loose file next to a virtual workspace manifest is not built.
    loose = {'sample_contract.rs': 'use soroban_sdk::contract;\n' + INIT.replace('GUARD', ''),
             'Cargo.toml': '[workspace]\nmembers = ["contracts/a"]\n[workspace.dependencies]\nsoroban-sdk = "22"\n'}
    assert all(f.severity is not Severity.HIGH for f in rule(audit(settings, run, loose, kind=SourceKind.REPO), 'soroban-auth-missing'))


@pytest.mark.parametrize('guard', [
    'if env.storage().instance().get(&DataKey::Init).unwrap_or(false) { panic!("x") } env.storage().instance().set(&DataKey::Init, &true);',
    'match env.storage().instance().get::<_, Address>(&DataKey::Admin) { Some(_) => panic!("x"), None => {} }',
    'if storage::has_admin(&env) { panic!("x") }',
    'let done: bool = env.storage().instance().get(&DataKey::Init).unwrap_or(false); if done { return; }',
    'ensure_fresh(&env);',
])
def test_initializer_with_another_once_only_guard_is_not_raised(settings, run, guard):
    source = INIT.replace('GUARD', guard) + '''
fn ensure_fresh(env: &Env) { if env.storage().instance().get::<_, bool>(&DataKey::Init).unwrap_or(false) { panic!() } }'''
    files = {'contracts/registry/src/lib.rs': source, 'contracts/registry/Cargo.toml': CARGO}
    assert all(f.severity is not Severity.HIGH for f in rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing'))


def test_parameter_check_is_not_a_once_only_guard(settings, run):
    source = INIT.replace('GUARD', 'if admin == env.current_contract_address() { panic!() }')
    files = {'contracts/registry/src/lib.rs': source, 'contracts/registry/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing')
    assert finding.severity is Severity.HIGH


def test_reinit_beside_lexical_gaps_is_not_confirmed_as_a_whole(settings, run):
    source = INIT.replace('GUARD', '').replace('    pub fn set_fee', '''    pub fn touch(env: Env, v: u32) { env.storage().instance().set(&DataKey::Other, &v); }
    pub fn set_fee''')
    files = {'contracts/registry/src/lib.rs': source, 'contracts/registry/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing')
    assert finding.severity is Severity.HIGH and finding.evidence_grade is EvidenceGrade.INFERRED
    assert 'initialize' in finding.evidence and 'touch' in finding.evidence


def test_plain_authorization_gap_keeps_the_stock_english_text(settings, run):
    files = {'contracts/c/src/lib.rs': INIT.replace('GUARD', 'if env.storage().instance().has(&DataKey::Admin) { panic!() }').replace(
        '    pub fn set_fee', '    pub fn touch(env: Env, v: u32) { env.storage().instance().set(&DataKey::Other, &v); }\n    pub fn set_fee'),
        'contracts/c/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing')
    assert english_finding(finding).title == 'Soroban authorization not evidenced'


def test_reinitializing_an_unused_value_is_not_raised(settings, run):
    files = {'contracts/c/src/lib.rs': INIT.replace('GUARD', '').replace('DataKey::Fee', 'DataKey::Other').replace(
        'get(&DataKey::Admin)', 'get(&DataKey::Owner)'), 'contracts/c/Cargo.toml': CARGO}
    assert all(f.severity is not Severity.HIGH for f in rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing'))


MOCK = '''use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};
#[contract]
pub struct Attacker;
#[contractimpl]
impl Attacker {
    pub fn steal(env: Env, tok: Address, victim: Address, amount: i128) {
        token::Client::new(&env, &tok).transfer(&victim, &env.current_contract_address(), &amount);
        env.storage().instance().set(&1u32, &amount);
    }
    pub fn pause(e: &Env) { pausable::pause(e); }
    pub fn init(env: Env, admin: Address) { env.storage().instance().set(&0u32, &admin); }
}
'''


@pytest.mark.parametrize('layout', [
    {'contracts/c/src/lib.rs': 'use soroban_sdk::contract;\n#[cfg(test)]\nmod test;\n', 'contracts/c/src/test.rs': MOCK},
    {'contracts/c/src/lib.rs': 'use soroban_sdk::contract;\n#[cfg(test)]\nmod mocks;\n', 'contracts/c/src/mocks.rs': MOCK},
    {'contracts/c/src/lib.rs': 'use soroban_sdk::contract;\nmod helpers;\n',
     'contracts/c/src/helpers.rs': MOCK.replace('token, Address', 'testutils::Address as _, token, Address')},
    {'contracts/c/src/lib.rs': 'use soroban_sdk::contract;\nmod helpers;\n', 'contracts/c/src/helpers.rs': '#![cfg(test)]\n' + MOCK},
])
def test_mock_contracts_in_test_code_are_not_judged(settings, run, layout):
    verdict = audit(settings, run, {**layout, 'contracts/c/Cargo.toml': CARGO}, kind=SourceKind.REPO)
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


def test_test_files_follow_the_module_tree():
    files = {'src/lib.rs': '#[cfg(test)]\nmod test;\n#[cfg(not(test))]\nmod real;\nmod a;\n', 'src/test.rs': '', 'src/real.rs': '',
             'src/a.rs': '#[cfg(any(test, feature = "testutils"))]\nmod fake;\n#[cfg(test)]\nmod inline { use soroban_sdk::testutils::Address as _; }\n',
             'src/a/fake.rs': '', 'src/a/fake/deep.rs': '', 'src/b.rs': '#[cfg(test)]\nuse soroban_sdk::testutils::Ledger;\n',
             'src/c.rs': '#[cfg(not(any(test, feature = "helpers")))]\npub(crate) mod both;\n#[cfg(any(test, feature = "helpers"))]\npub mod both;\n',
             'src/c/both.rs': ''}
    assert cfg_test_files(files) == {'src/test.rs', 'src/a/fake.rs', 'src/a/fake/deep.rs'}


def test_masker_keeps_offsets_and_lifetimes():
    source = 'fn f<\'a>(x: &\'a str) { let s = r#"a "quoted" // no"#; let c = \'"\'; /* x /* y */ z */ g(s) } // end'
    masked = _rust_code(source)
    assert len(masked) == len(source) and "<'a>" in masked and 'g(s)' in masked
    assert 'quoted' not in masked and 'end' not in masked and ' z ' not in masked


CHANNEL = '''use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};
#[contracttype]
pub enum DataKey { Channel(u64), Next, Admin }
#[contractimpl]
impl Channels {
    pub fn open(env: Env, payer: Address, token: Address, deposit: i128) -> u64 {
        GUARD
        if deposit <= 0 { panic!() }
        token::Client::new(&env, &token).transfer(&payer, &env.current_contract_address(), &deposit);
        let id: u64 = env.storage().instance().get(&DataKey::Next).unwrap_or(1);
        env.storage().instance().set(&DataKey::Channel(id), &deposit);
        id
    }
}
'''


def test_records_anyone_can_create_stay_medium_and_claim_no_locked_deposits(settings, run):
    # A full instance blocks new records only: same-size rewrites (claims, closes) still work.
    files = {'contracts/ch/src/lib.rs': CHANNEL.replace('GUARD', 'payer.require_auth();'), 'contracts/ch/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'instance-storage-records')
    assert finding.severity is Severity.MEDIUM and 'Any caller can create these records' in finding.detail
    assert 'lock' not in finding.detail and 'creating a new record fails' in finding.detail


def test_records_only_an_administrator_writes_stay_medium(settings, run):
    guard = ('let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap(); '
             'admin.require_auth(); payer.require_auth();')
    files = {'contracts/ch/src/lib.rs': CHANNEL.replace('GUARD', guard), 'contracts/ch/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'instance-storage-records')
    assert finding.severity is Severity.MEDIUM
    sample = {'examples/ch/src/lib.rs': CHANNEL.replace('GUARD', 'payer.require_auth();'), 'examples/ch/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, sample, kind=SourceKind.REPO), 'instance-storage-records')
    assert finding.severity is Severity.MEDIUM


def test_rule_ids_are_stable_across_line_moves(settings, run):
    source = TOKEN.replace('BODY', '''pub fn settle(env: Env, user: Address, amount: i128) {
        admin(&env).require_auth();
        token::Client::new(&env, &usdc(&env)).transfer(&user, &env.current_contract_address(), &amount);
    }''')
    first = rule(audit(settings, run, source), 'soroban-token-move-unbound')[0]
    moved = rule(audit(settings, run, '\n\n\n' + source), 'soroban-token-move-unbound')[0]
    assert first.id == moved.id and first.evidence != moved.evidence


# ---------------------------------------------------------------- review fixes

DUP_TEMPLATE = '''use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
{{#if ownable}}
    pub fn upgrade(e: Env, operator: Address, hash: BytesN<32>) {
        operator.require_auth();
        e.deployer().update_current_contract_wasm(hash);
    }
{{else}}
    pub fn upgrade(e: Env, hash: BytesN<32>) {
        e.deployer().update_current_contract_wasm(hash);
    }
{{/if}}
}
'''

CFG_GATED = '''use soroban_sdk::{contract, contractimpl, BytesN, Env};
#[contract]
pub struct Vault;
#[cfg(feature = "v1")]
#[contractimpl]
impl Vault {
    pub fn upgrade(e: Env, hash: BytesN<32>) { e.deployer().update_current_contract_wasm(hash); }
}
#[cfg(not(feature = "v1"))]
#[contractimpl]
impl Vault {
    pub fn upgrade(e: Env, hash: BytesN<32>) { e.deployer().update_current_contract_wasm(hash); }
    pub fn version() -> u32 { 2 }
}
'''


@pytest.mark.parametrize('files', [{'src/lib.rs.hbs': DUP_TEMPLATE}, {'src/lib.rs': CFG_GATED}])
def test_one_defect_found_twice_is_one_finding_not_a_failed_audit(settings, run, files):
    # Both template branches (union rendering) and both cfg variants define the same entry point.
    verdict = audit(settings, run, {**files, 'Cargo.toml': CARGO}, kind=SourceKind.REPO)
    assert verdict.status == 'completed'
    [finding] = rule(verdict, 'soroban-upgrade-unguarded')
    assert finding.severity is Severity.CRITICAL and finding.evidence.count(' upgrade: ') == 2


INLINE_MOCKS = '''#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn deposit(e: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 { panic!() }
        token::Client::new(&e, &e.current_contract_address()).transfer(&from, &e.current_contract_address(), &amount);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[contract]
    pub struct MockUpgrader;
    #[contractimpl]
    impl MockUpgrader {
        pub fn upgrade(e: Env, hash: BytesN<32>) { e.deployer().update_current_contract_wasm(hash); }
        pub fn steal(e: Env, victim: Address, to: Address, token: Address, amount: i128) {
            token::Client::new(&e, &token).transfer(&victim, &to, &amount);
            e.storage().instance().set(&1u32, &amount);
        }
    }
}
'''


def test_mock_contracts_in_an_inline_test_module_are_not_judged(settings, run):
    verdict = audit(settings, run, {'src/lib.rs': INLINE_MOCKS, 'Cargo.toml': CARGO}, kind=SourceKind.REPO)
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []
    # The same module compiled into the contract is judged.
    live = INLINE_MOCKS.replace('#[cfg(test)]\nmod tests', 'mod tests')
    judged = soroban_rules(audit(settings, run, {'src/lib.rs': live, 'Cargo.toml': CARGO}, kind=SourceKind.REPO))
    assert 'stellar_native-soroban-upgrade-unguarded' in judged and 'stellar_native-soroban-token-move-unbound' in judged


def test_test_module_blanking_keeps_offsets_and_other_builds():
    code = 'fn a() {}\n#[cfg(test)]\nmod t {\n    fn b() {}\n}\nfn c() {}\n'
    blanked = without_test_modules(code)
    assert len(blanked) == len(code) and blanked.count('\n') == code.count('\n')
    assert 'fn b' not in blanked and 'fn a' in blanked and 'fn c' in blanked
    other = code.replace('#[cfg(test)]', '#[cfg(not(test))]')
    assert without_test_modules(other) == other


ORACLE = TOKEN.replace('BODY', '''pub fn settle(env: Env, from: Address, to: Address, amount: i128, price: i128) {
        PAYER
        let oracle: Address = env.storage().instance().get(&Key::Oracle).unwrap();
        oracle.require_auth_for_args((price,).into_val(&env));
        token::Client::new(&env, &usdc(&env)).transfer(&from, &to, &amount);
    }''')


def test_another_signers_partial_authorization_is_not_the_payers(settings, run):
    # The payer signs every argument; an oracle signs only its price.
    assert rule(audit(settings, run, ORACLE.replace('PAYER', 'from.require_auth();')), 'soroban-auth-args-incomplete') == []
    # The payer itself signing only the price is the defect, whatever the oracle signs.
    [finding] = rule(audit(settings, run, ORACLE.replace('PAYER', 'from.require_auth_for_args((price,).into_val(&env));')),
                     'soroban-auth-args-incomplete')
    assert finding.severity is Severity.HIGH and '`to`' in finding.detail and '`amount`' in finding.detail


def test_multi_line_template_expression_keeps_lines(settings, run):
    source = '''use soroban_sdk::{contract, contractimpl, BytesN, Env};
const NAME: &str = "{{lookup
   config
   "name"}}";
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn upgrade(e: Env, hash: BytesN<32>) {
        e.deployer().update_current_contract_wasm(hash);
    }
}
'''
    rendered = render_template(source)
    assert len(rendered) == len(source) and rendered.count('\n') == source.count('\n') and '{{' not in rendered
    [finding] = rule(audit(settings, run, {'src/lib.rs.hbs': source, 'Cargo.toml': CARGO}, kind=SourceKind.REPO),
                     'soroban-upgrade-unguarded')
    assert finding.evidence.startswith('src/lib.rs.hbs:10 upgrade')


@pytest.mark.parametrize('guard', ['#[stellar_macros::only_owner]', '#[stellar_access::only_role(op, "upgrader")]'])
def test_path_qualified_openzeppelin_attribute_guards_the_upgrade(settings, run, guard):
    verdict = audit(settings, run, f'''
#[contractimpl]
impl Upgradeable for C {{
    {guard}
    fn upgrade(e: &Env, h: BytesN<32>, op: Address) {{ upgradeable::upgrade(e, &h); }}
}}''')
    assert soroban_rules(verdict) == [] and rule(verdict, 'soroban-auth-missing') == []


def test_path_qualified_has_role_without_auth_is_still_high(settings, run):
    source = TOKEN.replace('BODY', '''#[stellar_access::has_role(caller, "minter")]
    pub fn mint(e: &Env, to: Address, amount: i128, caller: Address) { Base::mint(e, &to, amount); }''')
    [finding] = rule(audit(settings, run, source), 'soroban-role-without-auth')
    assert finding.severity is Severity.HIGH


GUARDED_UPGRADE = '''
#[contractimpl]
impl C {
    pub fn upgrade(e: Env, caller: Address, PARAMS hash: BytesN<32>) {
        GUARD
        e.deployer().update_current_contract_wasm(hash);
    }
}'''


@pytest.mark.parametrize('guard', [
    'match e.storage().instance().get::<DataKey, Address>(&DataKey::Admin) { Some(admin) => admin.require_auth(), '
    'None => panic!("no admin"), }',
    'let Some(admin) = e.storage().instance().get::<DataKey, Address>(&DataKey::Admin) else { panic!("no admin") }; '
    'admin.require_auth();',
    'caller.require_auth(); if e.storage().instance().get::<DataKey, Address>(&DataKey::Admin).unwrap() != caller { panic!("no"); }',
    'let admins: Vec<Address> = e.storage().instance().get(&DataKey::Admins).unwrap(); for a in admins.iter() { a.require_auth(); }',
    'let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap(); let admin = admin.clone(); admin.require_auth();',
    'let admins: Vec<Address> = e.storage().instance().get(&DataKey::Admins).unwrap_or_else(|| panic!("none")); '
    'for a in admins.iter() { a.require_auth(); }',
])
def test_stored_administrator_in_other_shapes_is_a_strong_guard(settings, run, guard):
    verdict = audit(settings, run, GUARDED_UPGRADE.replace('PARAMS', '').replace('GUARD', guard))
    assert soroban_rules(verdict) == []


@pytest.mark.parametrize('params, guard', [
    ('admins: Vec<Address>,', 'for a in admins.iter() { a.require_auth(); }'),
    ('maybe: Option<Address>,', 'match maybe { Some(admin) => admin.require_auth(), None => panic!("x"), }'),
])
def test_caller_supplied_admins_are_not_a_strong_guard(settings, run, params, guard):
    verdict = audit(settings, run, GUARDED_UPGRADE.replace('PARAMS', params).replace('GUARD', guard))
    assert rule(verdict, 'soroban-upgrade-weak-guard') or rule(verdict, 'soroban-upgrade-unguarded')


def test_single_argument_assert_does_not_stop_the_rules(settings, run):
    verdict = audit(settings, run, GUARDED_UPGRADE.replace('PARAMS', '').replace('GUARD', 'assert_eq!(caller);'))
    assert verdict.status == 'completed' and rule(verdict, 'soroban-upgrade-unguarded')


TX_CAP = '''//! A per-transaction cap, deployed alongside a SpendingLimitPolicy that keeps the rolling total.
use soroban_sdk::{auth::{Context, ContractContext}, contract, contractimpl, Address, Env, TryFromVal, Vec};
#[contract]
pub struct CapPolicy;
#[contractimpl]
impl Policy for CapPolicy {
    fn enforce(e: &Env, context: Context, authenticated_signers: Vec<Signer>, rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        if authenticated_signers.is_empty() { panic!() }
        let cap: i128 = e.storage().persistent().get(&smart_account).unwrap();
        if let Context::Contract(ContractContext { args, .. }) = context {
            let amount = i128::try_from_val(e, &args.get(2).unwrap()).unwrap();
            if amount < 0 { panic!() }
            if amount > cap { panic!() }
        }
    }
}
'''

ROLLING_TOTAL = '''use soroban_sdk::{auth::{Context, ContractContext}, contract, contractimpl, Address, Env, TryFromVal, Vec};
#[contract]
pub struct RollingPolicy;
#[contractimpl]
impl Policy for RollingPolicy {
    fn enforce(e: &Env, context: Context, authenticated_signers: Vec<Signer>, rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        if authenticated_signers.is_empty() { panic!() }
        let mut spent: i128 = e.storage().persistent().get(&smart_account).unwrap_or(0);
        if let Context::Contract(ContractContext { args, .. }) = context {
            let amount = i128::try_from_val(e, &args.get(2).unwrap()).unwrap();
            if amount < 0 { panic!() }
            spent += amount;
            if spent > LIMIT { panic!() }
            e.storage().persistent().set(&smart_account, &spent);
        }
    }
}
'''


def test_per_call_cap_beside_a_rolling_total_policy_is_one_half_of_a_pair(settings, run):
    lone = TX_CAP.split('\n', 1)[1]
    crate = {'contracts/cap/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, {**crate, 'contracts/cap/src/lib.rs': lone}, kind=SourceKind.REPO),
                     'soroban-policy-per-call-cap')
    assert finding.severity is Severity.MEDIUM
    pair = {**crate, 'contracts/cap/src/lib.rs': lone, 'contracts/rolling/src/lib.rs': ROLLING_TOTAL,
            'contracts/rolling/Cargo.toml': CARGO}
    assert rule(audit(settings, run, pair, kind=SourceKind.REPO), 'soroban-policy-per-call-cap') == []
    # Documented as the per-transaction half of a pair whose rolling-total policy lives elsewhere.
    [documented] = rule(audit(settings, run, {**crate, 'contracts/cap/src/lib.rs': TX_CAP}, kind=SourceKind.REPO),
                        'soroban-policy-per-call-cap')
    assert documented.severity is Severity.INFO and 'spending-limit policy' in documented.detail


def _hostile(body: str) -> dict:
    head = ('use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};\n#[contract]\npub struct C;\n'
            '#[contractimpl]\nimpl C {\n')
    return {'src/lib.rs': head + body + '}\n', 'Cargo.toml': CARGO}


UPGRADE_HEAD = '    pub fn upgrade(e: Env, who: Address, h: BytesN<32>) {\n        who.require_auth();\n'
UPGRADE_SINK = '\n        e.deployer().update_current_contract_wasm(h);\n    }\n'
PAY_HEAD = '    pub fn pay(e: Env, from: Address, to: Address, amount: i128) {\n'
PAY_SINK = '\n        token::Client::new(&e, &t).transfer(&from, &to, &amount);\n    }\n'
#: Shapes that made one regex or loop quadratic (tens of seconds to minutes at these sizes).
HOSTILE = {
    'unclosed template comments': {'src/lib.rs.hbs': 'use soroban_sdk::contract;\n#[contractimpl]\n' + '{{!' * 40000,
                                   'Cargo.toml': CARGO},
    'long identifier in an initializer': _hostile('    pub fn init(e: Env, admin: Address) {\n        let x = ' + 'a' * 120000
                                                  + ';\n        e.storage().instance().set(&1, &admin);\n    }\n'),
    'dotted run in an upgrade': _hostile(UPGRADE_HEAD + '        let x = ' + 'a.' * 60000 + 'b;' + UPGRADE_SINK),
    'module path run': _hostile(UPGRADE_HEAD + '        let x = ' + 'a::' * 40000 + 'b(1);' + UPGRADE_SINK),
    'comparison run': _hostile(UPGRADE_HEAD + '        if ' + 'a < ' * 30000 + '{}' + UPGRADE_SINK),
    'nested calls': _hostile(PAY_HEAD + '        let v = ' + 'f(' * 30000 + 'x' + ')' * 30000 + ';' + PAY_SINK),
    'unclosed calls': _hostile(PAY_HEAD + '        ' + 'f(' * 60000 + PAY_SINK),
    'deadline comparisons': _hostile('    pub fn create(e: Env, payer: Address, deadline: u64, amount: i128) {\n'
                                     + 'deadline < < < ' * 8000 + '\n        token::Client::new(&e, &t).transfer('
                                     '&payer, &e.current_contract_address(), &amount);\n    }\n'),
    'instance record writes': _hostile('    pub fn open(e: Env, payer: Address) {\n        token::Client::new(&e, &t).transfer('
                                       '&payer, &e.current_contract_address(), &1);\n'
                                       + 'e.storage().instance().set(&DataKey::Channel(id), &1); ' * 2000 + '\n    }\n'),
    'many functions': _hostile(''.join(f'    pub fn f{i}(e: Env, a: Address) {{ e.storage().persistent().set(&a, &{i}); }}\n'
                                       for i in range(5500))),
    'deeply nested functions': _hostile('fn a() { ' * 12000 + '}' * 12000),
    'one body, many signatures': _hostile('fn a(' * 30000 + ') { e.deployer().update_current_contract_wasm(h); }'),
    # Masked comments are whitespace: a call after a comment block has a blank receiver.
    'comment block before a call': _hostile(PAY_HEAD + '        // a note\n' * 4000 + '        .transfer(&from, &to, &amount);\n    }\n'),
    'whitespace after operators': _hostile(UPGRADE_HEAD + '        let a = ' + ' ' * 40000 + '(1); spent += ' + ' ' * 40000
                                           + '; for b in ' + ' ' * 40000 + '(c) {}' + UPGRADE_SINK),
    # Each impl header was read to the end of the file.
    'contractimpl attributes without a block': {'src/lib.rs': 'use soroban_sdk::{contract, contractimpl, Env};\n'
                                                + '#[contractimpl] impl X ' * 10000, 'Cargo.toml': CARGO},
    # Helpers that create records, each called by entry points: every entry point was read per helper.
    'record-writing helpers': {'Cargo.toml': CARGO, 'src/lib.rs': (
        'use soroban_sdk::{contract, contractimpl, token, Address, Env};\n#[contract]\npub struct C;\n'
        + ''.join(f'fn h{i}(e: &Env, a: u32) {{ e.storage().instance().set(&K(a), &1); }}\n' for i in range(1500))
        + '#[contractimpl]\nimpl C {\n    pub fn dep(e: Env, f: Address, t: Address) { f.require_auth(); '
        'token::Client::new(&e, &t).transfer(&f, &e.current_contract_address(), &1); }\n'
        + ''.join(f'    pub fn e{i}(e: Env, a: u32) {{ h{i}(&e, a); h{(i + 1) % 1500}(&e, a); }}\n' for i in range(1500)) + '}\n')},
    # Thousands of aliases of one parameter: each was an alternative of one regex, run over the body.
    'aliases of a signed round': _hostile('    pub fn submit(e: Env, round: u64, sig: BytesN<64>, key: BytesN<32>, msg: Bytes) {\n'
                                          '        e.crypto().ed25519_verify(&key, &msg, &sig);\n'
                                          + ''.join(f'        let a{i} = round;\n' for i in range(9000))
                                          + '        e.storage().instance().set(&1u32, &round);\n    }\n'),
    'aliases of the contract address': _hostile(
        '    pub fn __check_auth(e: Env, payload: BytesN<32>, sig: BytesN<64>, ctx: Vec<Context>) -> Result<(), E> {\n'
        '        e.crypto().ed25519_verify(&k, &payload.into(), &sig);\n'
        + ''.join(f'        let s{i} = e.current_contract_address();\n' for i in range(5000))
        + '        for c in ctx.iter() { if c.contract == s0 { return Ok(()); } let amount = 1; }\n        Ok(())\n    }\n'
        '    pub fn set_limit(e: Env, l: i128) { e.current_contract_address().require_auth(); e.storage().instance().set(&1, &l); }\n'),
    'aliases of a deposited amount': _hostile('    pub fn deposit(e: Env, from: Address, amount: i128) {\n        from.require_auth();\n'
                                              + ''.join(f'        let a{i} = amount;\n' for i in range(14000))
                                              + '        token::Client::new(&e, &e.current_contract_address()).transfer(&from, '
                                              '&e.current_contract_address(), &amount);\n    }\n'),
    'aliases beside long authorized argument lists': _hostile(
        PAY_HEAD + ''.join(f'        let a{i} = amount;\n' for i in range(4000))
        + ('        from.require_auth_for_args((' + 'x, ' * 1300 + 'amount, to).into_val(&e));\n') * 32 + PAY_SINK),
    'many parameters sharing aliases': _hostile(
        '    pub fn submit(e: Env, ' + ', '.join(f'p{i}: i128' for i in range(600)) + ', sig: BytesN<64>) {\n'
        '        e.crypto().ed25519_verify(&k, &m, &sig);\n' + ''.join(f'        let x = p{i};\n' for i in range(600))
        + '        let y = x;\n' * 8000 + '        if y < z { }\n' * 8000 + '        e.storage().instance().set(&1u32, &y);\n    }\n'),
    'record families in one function': _hostile(
        '    pub fn open(e: Env, payer: Address) {\n        token::Client::new(&e, &t).transfer(&payer, '
        '&e.current_contract_address(), &1);\n'
        + ''.join(f'        e.storage().instance().set(&K{i}(id), &1);\n' for i in range(6000)) + '    }\n'),
}


@pytest.mark.parametrize('name', sorted(HOSTILE))
def test_hostile_source_is_analysed_in_linear_time(settings, run, name):
    start = time.perf_counter()
    verdict = audit(settings, run, HOSTILE[name], kind=SourceKind.REPO)
    assert verdict.status == 'completed' and time.perf_counter() - start < 3


@pytest.mark.parametrize('guard', [
    # No administrator stored: the upgrade goes ahead with nobody's authorization.
    'match e.storage().instance().get::<DataKey, Address>(&DataKey::Admin) { Some(admin) => admin.require_auth(), None => {} }',
    'let admins: Vec<Address> = e.storage().instance().get(&DataKey::Admins).unwrap_or(Vec::new(&e)); '
    'for a in admins.iter() { a.require_auth(); }',
    # The stored administrator is shadowed by the caller before it authorizes.
    'let Some(admin) = e.storage().instance().get::<DataKey, Address>(&DataKey::Admin) else { panic!() }; '
    'let admin = caller; admin.require_auth();',
])
def test_stored_administrator_that_may_be_absent_or_replaced_is_a_gap(settings, run, guard):
    verdict = audit(settings, run, GUARDED_UPGRADE.replace('PARAMS', '').replace('GUARD', guard))
    [gap] = rule(verdict, 'soroban-upgrade-weak-guard')
    assert gap.kind is FindingKind.EVIDENCE_GAP


WITHDRAW = TOKEN.replace('BODY', '''pub fn withdraw(env: Env, user: Address, to: Address, amount: i128) {
        user.require_auth_for_args((amount,).into_val(&env));
        GUARD
        token::Client::new(&env, &usdc(&env)).transfer(&env.current_contract_address(), &RECIPIENT, &amount);
    }''')


def test_partial_authorization_of_a_payout_from_the_contract_is_high(settings, run):
    [finding] = rule(audit(settings, run, WITHDRAW.replace('GUARD', '').replace('RECIPIENT', 'to')),
                     'soroban-auth-args-incomplete')
    assert finding.severity is Severity.HIGH and '`to`' in finding.detail and 'the contract holds' in finding.detail
    # Near misses: an administrator authorizes the whole call, or the user withdraws to itself.
    guarded = WITHDRAW.replace('GUARD', 'admin(&env).require_auth();').replace('RECIPIENT', 'to')
    assert rule(audit(settings, run, guarded), 'soroban-auth-args-incomplete') == []
    to_self = WITHDRAW.replace('GUARD', '').replace('RECIPIENT', 'user')
    assert rule(audit(settings, run, to_self), 'soroban-auth-args-incomplete') == []


@pytest.mark.parametrize('body', [
    'let payer = from.clone();\n        payer.require_auth_for_args((amount,).into_val(&env));\n        SOURCE = from;',
    'from.require_auth_for_args((amount,).into_val(&env));\n        SOURCE = from.clone();',
])
def test_payer_that_signs_through_a_copy_is_still_the_payer(settings, run, body):
    source = TOKEN.replace('BODY', f'''pub fn pay(env: Env, from: Address, to: Address, amount: i128) {{
        {body.replace('SOURCE', 'let src')}
        token::Client::new(&env, &usdc(&env)).transfer(&src, &to, &amount);
    }}''')
    [finding] = rule(audit(settings, run, source), 'soroban-auth-args-incomplete')
    assert finding.severity is Severity.HIGH and '`to`' in finding.detail and "signer's tokens" in finding.detail


def test_lone_per_call_cap_named_like_a_spending_limit_policy_stays_medium(settings, run):
    lone = TX_CAP.split('\n', 1)[1]
    crate = {'contracts/cap/Cargo.toml': CARGO}
    # Its own names say "spending limit policy" and "max per tx", but no comment pairs it with another policy.
    named = lone.replace('CapPolicy', 'SpendingLimitPolicy').replace('cap', 'max_per_tx')
    # A doc comment that calls the policy itself a per-transaction spending limit policy.
    described = '//! Spending limit policy: caps each transaction (per transaction).\n' + lone
    for source in (named, described):
        [finding] = rule(audit(settings, run, {**crate, 'contracts/cap/src/lib.rs': source}, kind=SourceKind.REPO),
                         'soroban-policy-per-call-cap')
        assert finding.severity is Severity.MEDIUM


def test_each_text_is_indexed_once_when_the_index_cache_is_small(settings, run, monkeypatch):
    from backend.app.swarm import soroban_rules
    monkeypatch.setattr(soroban_rules, '_CACHE_CHARS', 3000)
    built, original = [], soroban_rules._Text.__init__

    def counting(self, text):
        built.append(text)  # kept, so no two texts share an id
        original(self, text)
    monkeypatch.setattr(soroban_rules._Text, '__init__', counting)
    head = 'use soroban_sdk::{contract, contractimpl, Address, Env};\n#[contract]\npub struct C;\n#[contractimpl]\nimpl C {\n'
    files = {'Cargo.toml': CARGO, **{f'src/m{i}.rs': head + f'    pub fn f{i}(e: Env, a: Address) {{\n'
                                     + '([{}]), ' * 300 + '\n    }\n}\n' for i in range(6)}}
    assert audit(settings, run, files, kind=SourceKind.REPO).status == 'completed'
    assert built and len({id(text) for text in built}) == len(built)
