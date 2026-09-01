extern crate std;

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, AuthorizedFunction},
    Address, BytesN, Env, String,
};

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

#[test]
fn registration_requests_exact_owner_authorization() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let agent_id = b32(&env, 40);

    client.init(&admin);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 41),
        &b32(&env, 42),
        &1,
    );

    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, owner);
    match &auths[0].1.function {
        AuthorizedFunction::Contract((authorized_contract, function, args)) => {
            assert_eq!(authorized_contract, &contract_id);
            assert_eq!(function, &symbol_short!("reg_agent"));
            assert_eq!(args.len(), 6);
        }
        _ => panic!("unexpected authorization function"),
    }
    assert!(auths[0].1.sub_invocations.is_empty());
}

#[test]
fn full_validation_and_unique_review_flow() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let requester = Address::generate(&env);
    let validator = Address::generate(&env);
    let reviewer = Address::generate(&env);
    let agent_id = b32(&env, 1);
    let req_id = b32(&env, 2);

    client.init(&admin);
    client.set_valid(&admin, &validator, &true);
    client.set_reviewer(&admin, &reviewer, &true);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 3),
        &b32(&env, 4),
        &1,
    );
    client.req_valid(&requester, &req_id, &agent_id, &validator);
    let done = client.respond(
        &validator,
        &req_id,
        &88,
        &String::from_str(&env, "ipfs://report"),
        &b32(&env, 5),
    );
    assert_eq!(done.state, ValState::Complete);
    assert_eq!(done.score, 88);

    client.review(&reviewer, &req_id, &91);
    assert_eq!(client.avg_score(&agent_id), 91);
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn assigned_validator_cannot_be_replaced() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let requester = Address::generate(&env);
    let validator = Address::generate(&env);
    let attacker = Address::generate(&env);
    let agent_id = b32(&env, 10);
    let req_id = b32(&env, 11);

    client.init(&admin);
    client.set_valid(&admin, &validator, &true);
    client.set_valid(&admin, &attacker, &true);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 12),
        &b32(&env, 13),
        &1,
    );
    client.req_valid(&requester, &req_id, &agent_id, &validator);
    client.respond(
        &attacker,
        &req_id,
        &100,
        &String::from_str(&env, "ipfs://fake"),
        &b32(&env, 14),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn reviewer_cannot_double_count() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let requester = Address::generate(&env);
    let validator = Address::generate(&env);
    let reviewer = Address::generate(&env);
    let agent_id = b32(&env, 20);
    let req_id = b32(&env, 21);

    client.init(&admin);
    client.set_valid(&admin, &validator, &true);
    client.set_reviewer(&admin, &reviewer, &true);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 22),
        &b32(&env, 23),
        &1,
    );
    client.req_valid(&requester, &req_id, &agent_id, &validator);
    client.respond(
        &validator,
        &req_id,
        &80,
        &String::from_str(&env, "ipfs://report"),
        &b32(&env, 24),
    );
    client.review(&reviewer, &req_id, &50);
    client.review(&reviewer, &req_id, &99);
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn unapproved_reviewer_cannot_change_reputation() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let requester = Address::generate(&env);
    let validator = Address::generate(&env);
    let attacker = Address::generate(&env);
    let agent_id = b32(&env, 30);
    let req_id = b32(&env, 31);

    client.init(&admin);
    client.set_valid(&admin, &validator, &true);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 32),
        &b32(&env, 33),
        &1,
    );
    client.req_valid(&requester, &req_id, &agent_id, &validator);
    client.respond(
        &validator,
        &req_id,
        &80,
        &String::from_str(&env, "ipfs://report"),
        &b32(&env, 34),
    );
    client.review(&attacker, &req_id, &100);
}

#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn zero_report_hash_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AgentRegistry, ());
    let client = AgentRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let requester = Address::generate(&env);
    let validator = Address::generate(&env);
    let agent_id = b32(&env, 50);
    let req_id = b32(&env, 51);

    client.init(&admin);
    client.set_valid(&admin, &validator, &true);
    client.reg_agent(
        &owner,
        &agent_id,
        &String::from_str(&env, "ipfs://agent"),
        &b32(&env, 52),
        &b32(&env, 53),
        &1,
    );
    client.req_valid(&requester, &req_id, &agent_id, &validator);
    client.respond(
        &validator,
        &req_id,
        &80,
        &String::from_str(&env, "ipfs://report"),
        &BytesN::from_array(&env, &[0; 32]),
    );
}
