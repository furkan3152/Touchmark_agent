extern crate std;

use super::*;
use agent_veritas_registry::{AgentRegistry, AgentRegistryClient as RealRegistryClient};
use soroban_sdk::{
    testutils::{Address as _, EnvTestConfig, Ledger as _},
    String,
};

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

struct Fixture {
    env: Env,
    admin: Address,
    requester: Address,
    provider: Address,
    evaluator: Address,
    fee_to: Address,
    asset: Address,
    registry: Address,
    escrow: Address,
    request: BytesN<32>,
    agent: BytesN<32>,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let requester = Address::generate(&env);
        let provider = Address::generate(&env);
        let evaluator = Address::generate(&env);
        let fee_to = Address::generate(&env);
        let asset = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        token::StellarAssetClient::new(&env, &asset).mint(&requester, &1_000_000);
        let registry = env.register(AgentRegistry, (&admin,));
        let rc = RealRegistryClient::new(&env, &registry);
        let agent = b32(&env, 1);
        let request = b32(&env, 2);
        rc.set_valid(&admin, &provider, &true);
        rc.reg_agent(
            &requester,
            &agent,
            &String::from_str(&env, "ipfs://agent-v1"),
            &b32(&env, 3),
            &b32(&env, 4),
            &1,
        );
        rc.req_valid(&requester, &request, &agent, &provider);
        let escrow = env.register(AuditEscrow, (&admin, &asset, &fee_to, &1_500u32, &registry));
        Self {
            env,
            admin,
            requester,
            provider,
            evaluator,
            fee_to,
            asset,
            registry,
            escrow,
            request,
            agent,
        }
    }
    fn client(&self) -> AuditEscrowClient<'_> {
        AuditEscrowClient::new(&self.env, &self.escrow)
    }
    fn registry(&self) -> RealRegistryClient<'_> {
        RealRegistryClient::new(&self.env, &self.registry)
    }
    fn create(&self) -> AuditJob {
        self.client().create(
            &self.requester,
            &self.request,
            &self.provider,
            &self.evaluator,
            &500_000,
            &100,
        )
    }
    fn funded() -> Self {
        let f = Self::new();
        f.create();
        f.client().fund(&f.requester, &f.request);
        f
    }
    fn respond(&self) {
        self.registry().respond(
            &self.provider,
            &self.request,
            &90,
            &String::from_str(&self.env, "ipfs://report"),
            &b32(&self.env, 5),
        );
    }
    fn submitted() -> Self {
        let f = Self::funded();
        f.respond();
        f.client().submit(&f.provider, &f.request, &b32(&f.env, 5));
        f
    }
    fn update(&self) {
        self.registry().upd_agent(
            &self.requester,
            &self.agent,
            &String::from_str(&self.env, "ipfs://agent-v2"),
            &b32(&self.env, 6),
            &b32(&self.env, 7),
            &2,
        );
    }
    fn balance(&self, address: &Address) -> i128 {
        token::Client::new(&self.env, &self.asset).balance(address)
    }
}

#[test]
fn sac_fund_and_complete_is_atomic_and_bound_to_registry() {
    let f = Fixture::submitted();
    let c = f.client();
    assert_eq!(c.get_registry(), f.registry);
    assert_eq!(f.balance(&f.escrow), 500_000);
    let binding = c.get_binding(&f.request);
    assert_eq!(binding.agent_id, f.agent);
    assert_eq!(binding.owner, f.requester);
    assert_eq!(binding.version, 1);
    assert_eq!(binding.meta_hash, b32(&f.env, 3));
    assert_eq!(binding.end_hash, b32(&f.env, 4));
    let job = c.complete(&f.evaluator, &f.request, &90);
    let validation = f.registry().get_valid(&f.request);
    assert_eq!(job.state, JobState::Complete);
    assert_eq!(job.del_hash, validation.rep_hash);
    assert_eq!(job.score, validation.score);
    assert_eq!(f.balance(&f.provider), 425_000);
    assert_eq!(f.balance(&f.fee_to), 75_000);
    assert_eq!(f.balance(&f.escrow), 0);
    assert!(c.try_complete(&f.evaluator, &f.request, &90).is_err());
}

#[test]
fn pending_and_completed_registry_requests_can_be_created() {
    let f = Fixture::new();
    assert_eq!(f.create().state, JobState::Created);
    let f = Fixture::new();
    f.respond();
    assert_eq!(f.create().state, JobState::Created);
}

#[test]
fn wrong_provider_cannot_submit() {
    let f = Fixture::funded();
    assert_eq!(
        f.client()
            .try_submit(&Address::generate(&f.env), &f.request, &b32(&f.env, 5)),
        Err(Ok(Error::BadRole.into()))
    );
}

#[test]
fn requester_cannot_refund_before_deadline() {
    let f = Fixture::funded();
    assert_eq!(
        f.client().try_refund(&f.requester, &f.request),
        Err(Ok(Error::TooEarly.into()))
    );
}

#[test]
fn submitted_job_can_be_refunded_after_deadline() {
    let f = Fixture::submitted();
    f.env.ledger().set_sequence_number(100);
    let job = f.client().refund(&f.requester, &f.request);
    assert_eq!(job.state, JobState::Refunded);
    assert_eq!(f.balance(&f.requester), 1_000_000);
    assert_eq!(f.balance(&f.escrow), 0);
}

#[test]
fn conflicting_roles_are_rejected() {
    let f = Fixture::new();
    for (provider, evaluator) in [
        (&f.requester, &f.evaluator),
        (&f.provider, &f.requester),
        (&f.provider, &f.provider),
    ] {
        assert_eq!(
            f.client()
                .try_create(&f.requester, &f.request, provider, evaluator, &100, &100),
            Err(Ok(Error::BadRole.into()))
        );
    }
}

#[test]
fn fee_is_snapshotted_when_job_is_created() {
    let f = Fixture::submitted();
    let new_fee_to = Address::generate(&f.env);
    f.client().set_fee(&f.admin, &new_fee_to, &3_000);
    f.client().complete(&f.evaluator, &f.request, &90);
    assert_eq!(f.balance(&f.provider), 425_000);
    assert_eq!(f.balance(&f.fee_to), 75_000);
    assert_eq!(f.balance(&new_fee_to), 0);
}

#[test]
fn provider_cannot_submit_at_deadline() {
    let f = Fixture::funded();
    f.respond();
    f.env.ledger().set_sequence_number(100);
    assert_eq!(
        f.client()
            .try_submit(&f.provider, &f.request, &b32(&f.env, 5)),
        Err(Ok(Error::TooLate.into()))
    );
}

#[test]
fn arbitrary_job_id_cannot_create_unbound_escrow() {
    let f = Fixture::new();
    assert!(f
        .client()
        .try_create(
            &f.requester,
            &b32(&f.env, 99),
            &f.provider,
            &f.evaluator,
            &100,
            &100,
        )
        .is_err());
    assert!(f.client().try_get_job(&b32(&f.env, 99)).is_err());
}

#[test]
fn wrong_requester_and_assigned_validator_cannot_bind_request() {
    let f = Fixture::new();
    let outsider = Address::generate(&f.env);
    // Another authorized validator still cannot replace the assigned validator.
    f.registry().set_valid(&f.admin, &outsider, &true);
    assert_eq!(
        f.client()
            .try_create(&outsider, &f.request, &f.provider, &f.evaluator, &100, &100),
        Err(Ok(Error::InvalidValidation.into()))
    );
    assert_eq!(
        f.client().try_create(
            &f.requester,
            &f.request,
            &outsider,
            &f.evaluator,
            &100,
            &100
        ),
        Err(Ok(Error::InvalidValidation.into()))
    );
}

#[test]
fn pending_registry_request_cannot_submit_any_report() {
    let f = Fixture::funded();
    assert_eq!(
        f.client()
            .try_submit(&f.provider, &f.request, &b32(&f.env, 5)),
        Err(Ok(Error::InvalidValidation.into()))
    );
    assert_eq!(f.client().get_job(&f.request).state, JobState::Funded);
    assert_eq!(f.balance(&f.escrow), 500_000);
}

#[test]
fn mismatched_report_cannot_submit_or_pay() {
    let f = Fixture::funded();
    f.respond();
    assert_eq!(
        f.client()
            .try_submit(&f.provider, &f.request, &b32(&f.env, 99)),
        Err(Ok(Error::InvalidValidation.into()))
    );
    assert_eq!(f.client().get_job(&f.request).state, JobState::Funded);
    assert_eq!(f.balance(&f.provider), 0);
    assert_eq!(f.balance(&f.escrow), 500_000);
}

#[test]
fn evaluator_cannot_substitute_score() {
    let f = Fixture::submitted();
    for wrong_score in [0u32, 89, 91, 101] {
        assert_eq!(
            f.client()
                .try_complete(&f.evaluator, &f.request, &wrong_score),
            Err(Ok(Error::BadScore.into()))
        );
    }
    assert_eq!(f.client().get_job(&f.request).state, JobState::Submitted);
    assert_eq!(f.balance(&f.provider), 0);
    assert_eq!(f.balance(&f.fee_to), 0);
    assert_eq!(f.balance(&f.escrow), 500_000);
}

#[test]
fn version_change_blocks_create_fund_submit_and_complete() {
    let f = Fixture::new();
    f.update();
    assert_eq!(
        f.client().try_create(
            &f.requester,
            &f.request,
            &f.provider,
            &f.evaluator,
            &100,
            &100
        ),
        Err(Ok(Error::StaleIdentity.into()))
    );
    let f = Fixture::new();
    f.create();
    f.update();
    assert_eq!(
        f.client().try_fund(&f.requester, &f.request),
        Err(Ok(Error::StaleIdentity.into()))
    );
    assert_eq!(f.balance(&f.requester), 1_000_000);
    let f = Fixture::funded();
    f.respond();
    f.update();
    assert_eq!(
        f.client()
            .try_submit(&f.provider, &f.request, &b32(&f.env, 5)),
        Err(Ok(Error::StaleIdentity.into()))
    );
    let f = Fixture::submitted();
    f.update();
    assert_eq!(
        f.client().try_complete(&f.evaluator, &f.request, &90),
        Err(Ok(Error::StaleIdentity.into()))
    );
    assert_eq!(f.balance(&f.escrow), 500_000);
}

#[test]
fn version_only_change_invalidates_unchanged_source_hashes() {
    let f = Fixture::submitted();
    f.registry().upd_agent(
        &f.requester,
        &f.agent,
        &String::from_str(&f.env, "ipfs://agent-v1"),
        &b32(&f.env, 3),
        &b32(&f.env, 4),
        &2,
    );
    assert_eq!(
        f.client().try_complete(&f.evaluator, &f.request, &90),
        Err(Ok(Error::StaleIdentity.into()))
    );
    assert_eq!(f.balance(&f.escrow), 500_000);
}

#[test]
fn deactivated_agent_blocks_settlement_but_dispute_refund_remains_available() {
    let f = Fixture::submitted();
    f.registry().set_active(&f.requester, &f.agent, &false);
    assert_eq!(
        f.client().try_complete(&f.evaluator, &f.request, &90),
        Err(Ok(Error::StaleIdentity.into()))
    );
    f.client().dispute(&f.evaluator, &f.request);
    f.client().refund(&f.requester, &f.request);
    assert_eq!(f.balance(&f.requester), 1_000_000);
}

#[test]
fn disabled_validator_blocks_submit_and_complete_without_locking_refund() {
    let f = Fixture::funded();
    f.respond();
    f.registry().set_valid(&f.admin, &f.provider, &false);
    assert_eq!(
        f.client()
            .try_submit(&f.provider, &f.request, &b32(&f.env, 5)),
        Err(Ok(Error::InvalidValidation.into()))
    );
    f.env.ledger().set_sequence_number(100);
    f.client().refund(&f.requester, &f.request);
    assert_eq!(f.balance(&f.requester), 1_000_000);
    let f = Fixture::submitted();
    f.registry().set_valid(&f.admin, &f.provider, &false);
    assert_eq!(
        f.client().try_complete(&f.evaluator, &f.request, &90),
        Err(Ok(Error::InvalidValidation.into()))
    );
    f.client().dispute(&f.evaluator, &f.request);
    f.client().refund(&f.requester, &f.request);
    assert_eq!(f.balance(&f.requester), 1_000_000);
}

#[test]
fn changed_agent_version_does_not_lock_dispute_refund() {
    let f = Fixture::submitted();
    f.update();
    f.client().dispute(&f.evaluator, &f.request);
    f.client().refund(&f.requester, &f.request);
    assert_eq!(f.balance(&f.requester), 1_000_000);
    assert_eq!(f.balance(&f.provider), 0);
}

#[test]
fn fund_and_complete_reject_expired_jobs() {
    let f = Fixture::new();
    f.create();
    f.env.ledger().set_sequence_number(100);
    assert_eq!(
        f.client().try_fund(&f.requester, &f.request),
        Err(Ok(Error::TooLate.into()))
    );
    assert_eq!(f.balance(&f.requester), 1_000_000);
    let f = Fixture::submitted();
    f.env.ledger().set_sequence_number(100);
    assert_eq!(
        f.client().try_complete(&f.evaluator, &f.request, &90),
        Err(Ok(Error::TooLate.into()))
    );
}

#[test]
fn signatures_and_evaluator_role_are_still_required() {
    let f = Fixture::submitted();
    assert_eq!(
        f.client().try_complete(&f.provider, &f.request, &90),
        Err(Ok(Error::BadRole.into()))
    );
    f.env.mock_auths(&[]);
    assert!(f
        .client()
        .try_complete(&f.evaluator, &f.request, &90)
        .is_err());
    assert_eq!(f.balance(&f.escrow), 500_000);
}
