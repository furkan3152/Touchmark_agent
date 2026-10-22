"""Soroban contract rules: each one fires on its vulnerable shape and stays silent on the near miss."""
import pytest

from backend.app.models import AgentArtifact, EvidenceGrade, FindingKind, Severity, SourceKind
from backend.app.reporting.english import english_finding
from backend.app.swarm.orchestrator import _KEEPS_SEVERITY
from backend.app.swarm.soroban_rules import render_template
from backend.app.swarm.stellar_native import StellarNativeAuditor

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
    source = account('ctx: Vec<Context>', 'for c in ctx.iter() { check_context(&env, c)?; }').replace(
        'env.crypto().ed25519_verify(&pk, &payload.into(), &sig);',
        'let msg: Bytes = payload.into(); env.crypto().ed25519_verify(&pk, &msg, &sig);')
    source += 'fn check_context(env: &Env, c: Context) -> Result<(), Error> { match c { _ => Err(Error::NotAllowed) } }'
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


def test_bare_token_pass_through_is_medium(settings, run):
    verdict = audit(settings, run, TOKEN.replace('BODY', '''pub fn swap(env: Env, from: Address, to: Address, amount: i128, min_out: i128) {
        let out = quote(amount);
        assert!(out >= min_out);
        token::Client::new(&env, &usdc(&env)).transfer(&from, &to, &out);
    }'''))
    assert [f.severity for f in rule(verdict, 'soroban-token-move-unbound')] == [Severity.MEDIUM]


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


def test_has_role_without_auth_is_high(settings, run):
    source = TOKEN.replace('BODY', '''#[has_role(caller, "minter")]
    pub fn mint(e: &Env, to: Address, amount: i128, caller: Address) {
        AUTH
        e.storage().persistent().set(&to, &amount);
    }''')
    [finding] = rule(audit(settings, run, source.replace('AUTH', '')), 'soroban-role-without-auth')
    assert finding.severity is Severity.HIGH
    assert rule(audit(settings, run, source.replace('AUTH', 'caller.require_auth();')), 'soroban-role-without-auth') == []


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


def test_reinitializing_an_unused_value_is_not_raised(settings, run):
    files = {'contracts/c/src/lib.rs': INIT.replace('GUARD', '').replace('DataKey::Fee', 'DataKey::Other').replace(
        'get(&DataKey::Admin)', 'get(&DataKey::Owner)'), 'contracts/c/Cargo.toml': CARGO}
    assert all(f.severity is not Severity.HIGH for f in rule(audit(settings, run, files, kind=SourceKind.REPO), 'soroban-auth-missing'))


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


def test_records_anyone_can_create_next_to_deposits_are_high(settings, run):
    files = {'contracts/ch/src/lib.rs': CHANNEL.replace('GUARD', 'payer.require_auth();'), 'contracts/ch/Cargo.toml': CARGO}
    [finding] = rule(audit(settings, run, files, kind=SourceKind.REPO), 'instance-storage-records')
    assert finding.severity is Severity.HIGH and 'locks every deposit' in finding.detail


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
