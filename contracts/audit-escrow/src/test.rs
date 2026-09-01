extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env,
};

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

#[test]
fn sac_fund_and_complete_is_atomic() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    let asset_admin = token::StellarAssetClient::new(&env, &asset.address());
    asset_admin.mint(&requester, &1_000_000);

    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &1_500);
    let job_id = b32(&env, 1);
    client.create(&requester, &job_id, &provider, &evaluator, &500_000, &100);
    client.fund(&requester, &job_id);
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&contract_id),
        500_000
    );
    client.submit(&provider, &job_id, &b32(&env, 2));
    let job = client.complete(&evaluator, &job_id, &90);

    assert_eq!(job.state, JobState::Complete);
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&provider),
        425_000
    );
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&fee_to),
        75_000
    );
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&contract_id),
        0
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn wrong_provider_cannot_submit() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let attacker = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    token::StellarAssetClient::new(&env, &asset.address()).mint(&requester, &100);
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &0);
    let job_id = b32(&env, 3);
    client.create(&requester, &job_id, &provider, &evaluator, &100, &100);
    client.fund(&requester, &job_id);
    client.submit(&attacker, &job_id, &b32(&env, 4));
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn requester_cannot_refund_before_deadline() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    token::StellarAssetClient::new(&env, &asset.address()).mint(&requester, &100);
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &0);
    let job_id = b32(&env, 5);
    client.create(&requester, &job_id, &provider, &evaluator, &100, &100);
    client.fund(&requester, &job_id);
    client.refund(&requester, &job_id);
}

#[test]
fn submitted_job_can_be_refunded_after_deadline() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    token::StellarAssetClient::new(&env, &asset.address()).mint(&requester, &100);
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &0);
    let job_id = b32(&env, 6);
    client.create(&requester, &job_id, &provider, &evaluator, &100, &10);
    client.fund(&requester, &job_id);
    client.submit(&provider, &job_id, &b32(&env, 7));
    env.ledger().set_sequence_number(10);

    let job = client.refund(&requester, &job_id);
    assert_eq!(job.state, JobState::Refunded);
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&requester),
        100
    );
    assert_eq!(
        token::Client::new(&env, &asset.address()).balance(&contract_id),
        0
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn conflicting_roles_are_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &0);
    client.create(&requester, &b32(&env, 8), &requester, &evaluator, &100, &10);
}

#[test]
fn fee_is_snapshotted_when_job_is_created() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let original_fee_to = Address::generate(&env);
    let new_fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    token::StellarAssetClient::new(&env, &asset.address()).mint(&requester, &100);
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &original_fee_to, &1_000);
    let job_id = b32(&env, 9);
    client.create(&requester, &job_id, &provider, &evaluator, &100, &100);
    client.fund(&requester, &job_id);
    client.set_fee(&admin, &new_fee_to, &3_000);
    client.submit(&provider, &job_id, &b32(&env, 10));
    client.complete(&evaluator, &job_id, &90);

    let token_client = token::Client::new(&env, &asset.address());
    assert_eq!(token_client.balance(&provider), 90);
    assert_eq!(token_client.balance(&original_fee_to), 10);
    assert_eq!(token_client.balance(&new_fee_to), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn provider_cannot_submit_after_deadline() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let requester = Address::generate(&env);
    let provider = Address::generate(&env);
    let evaluator = Address::generate(&env);
    let fee_to = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    token::StellarAssetClient::new(&env, &asset.address()).mint(&requester, &100);
    let contract_id = env.register(AuditEscrow, ());
    let client = AuditEscrowClient::new(&env, &contract_id);
    client.init(&admin, &asset.address(), &fee_to, &0);
    let job_id = b32(&env, 11);
    client.create(&requester, &job_id, &provider, &evaluator, &100, &10);
    client.fund(&requester, &job_id);
    env.ledger().set_sequence_number(10);
    client.submit(&provider, &job_id, &b32(&env, 12));
}
