#![no_std]

// Share the wire ABI, never link the registry implementation into escrow WASM.
#[path = "../../audit-credential/src/registry_interface.rs"]
mod registry_interface;
use registry_interface::{AgentRec, AgentRegistryClient, ValState, ValidRec};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype,
    panic_with_error, token, Address, BytesN, Env,
};

contractmeta!(key = "name", val = "AgentVeritas Audit Escrow");
contractmeta!(key = "version", val = "0.4.0");
contractmeta!(key = "asset", val = "SEP-41 Stellar Asset Contract client");
contractmeta!(key = "purpose", val = "optional agent audit settlement");

const TTL_MIN: u32 = 17_280;
const TTL_EXTEND: u32 = 518_400;
const MAX_FEE_BPS: u32 = 3_000;
/// Ledgers (~1 day) the evaluator has to accept or dispute a submitted report.
/// After this window an undisputed delivery is payable to the provider.
pub const REVIEW_LEDGERS: u32 = 17_280;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobState {
    Created,
    Funded,
    Submitted,
    Disputed,
    Complete,
    Refunded,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditJob {
    pub requester: Address,
    pub provider: Address,
    pub evaluator: Address,
    pub amount: i128,
    pub deadline: u32,
    pub fee_bps: u32,
    pub fee_to: Address,
    pub state: JobState,
    pub del_hash: BytesN<32>,
    pub score: u32,
    /// Ledger at which the review window of a submitted report closes (0 before submission).
    pub review_end: u32,
}

/// Identity accepted when the requester created the paid audit.
/// A later registry update cannot silently change the scope of settlement.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryBinding {
    pub agent_id: BytesN<32>,
    pub owner: Address,
    pub version: u32,
    pub meta_hash: BytesN<32>,
    pub end_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Token,
    FeeTo,
    FeeBps,
    Registry,
    Job(BytesN<32>),
    Binding(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInit = 1,
    NotInit = 2,
    Unauthorized = 3,
    Exists = 4,
    NotFound = 5,
    BadAmount = 6,
    BadFee = 7,
    BadState = 8,
    BadScore = 9,
    TooEarly = 10,
    BadRole = 11,
    Overflow = 12,
    TooLate = 13,
    BadHash = 14,
    InvalidValidation = 15,
    StaleIdentity = 16,
    ReviewOpen = 17,
}

#[contractevent(topics = ["audit_esc", "created"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Created {
    #[topic]
    pub job_id: BytesN<32>,
    pub requester: Address,
    pub provider: Address,
    pub evaluator: Address,
    pub amount: i128,
}

#[contractevent(topics = ["audit_esc", "funded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Funded {
    #[topic]
    pub job_id: BytesN<32>,
    pub amount: i128,
}

#[contractevent(topics = ["audit_esc", "submitted"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Submitted {
    #[topic]
    pub job_id: BytesN<32>,
    pub del_hash: BytesN<32>,
}

#[contractevent(topics = ["audit_esc", "completed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completed {
    #[topic]
    pub job_id: BytesN<32>,
    pub score: u32,
    pub fee: i128,
    pub payout: i128,
}

#[contractevent(topics = ["audit_esc", "refunded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refunded {
    #[topic]
    pub job_id: BytesN<32>,
    pub amount: i128,
}

#[contractevent(topics = ["audit_esc", "disputed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disputed {
    #[topic]
    pub job_id: BytesN<32>,
}

#[contractevent(topics = ["audit_esc", "fee_set"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeSet {
    pub fee_to: Address,
    pub fee_bps: u32,
}

#[contract]
pub struct AuditEscrow;

#[contractimpl]
impl AuditEscrow {
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        fee_to: Address,
        fee_bps: u32,
        registry: Address,
    ) {
        Self::init(env, admin, token, fee_to, fee_bps, registry);
    }

    pub fn init(
        env: Env,
        admin: Address,
        token: Address,
        fee_to: Address,
        fee_bps: u32,
        registry: Address,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, Error::AlreadyInit);
        }
        admin.require_auth();
        if fee_bps > MAX_FEE_BPS {
            panic_with_error!(&env, Error::BadFee);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::FeeTo, &fee_to);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        env.storage().instance().set(&DataKey::Registry, &registry);
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    }

    pub fn set_fee(env: Env, admin: Address, fee_to: Address, fee_bps: u32) {
        Self::require_admin(&env, &admin);
        if fee_bps > MAX_FEE_BPS {
            panic_with_error!(&env, Error::BadFee);
        }
        env.storage().instance().set(&DataKey::FeeTo, &fee_to);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        FeeSet { fee_to, fee_bps }.publish(&env);
    }

    pub fn create(
        env: Env,
        requester: Address,
        job_id: BytesN<32>,
        provider: Address,
        evaluator: Address,
        amount: i128,
        deadline: u32,
    ) -> AuditJob {
        requester.require_auth();
        Self::require_hash(&env, &job_id);
        if amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        if deadline <= env.ledger().sequence() {
            panic_with_error!(&env, Error::TooEarly);
        }
        if requester == provider || requester == evaluator || provider == evaluator {
            panic_with_error!(&env, Error::BadRole);
        }
        let key = DataKey::Job(job_id.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, Error::Exists);
        }
        // job_id is the existing registry request id, not an unrelated invoice id.
        let (validation, agent) = Self::current_validation(&env, &job_id, &requester, &provider);
        let binding = RegistryBinding {
            agent_id: validation.agent_id,
            owner: agent.owner,
            version: validation.version,
            meta_hash: validation.meta_hash,
            end_hash: validation.end_hash,
        };
        let binding_key = DataKey::Binding(job_id.clone());
        env.storage().persistent().set(&binding_key, &binding);
        env.storage()
            .persistent()
            .extend_ttl(&binding_key, TTL_MIN, TTL_EXTEND);
        let job = AuditJob {
            requester: requester.clone(),
            provider: provider.clone(),
            evaluator: evaluator.clone(),
            amount,
            deadline,
            fee_bps: env
                .storage()
                .instance()
                .get(&DataKey::FeeBps)
                .unwrap_or_else(|| panic_with_error!(&env, Error::NotInit)),
            fee_to: env
                .storage()
                .instance()
                .get(&DataKey::FeeTo)
                .unwrap_or_else(|| panic_with_error!(&env, Error::NotInit)),
            state: JobState::Created,
            del_hash: BytesN::from_array(&env, &[0; 32]),
            score: 0,
            review_end: 0,
        };
        Self::put_job(&env, &key, &job);
        Created {
            job_id,
            requester,
            provider,
            evaluator,
            amount,
        }
        .publish(&env);
        job
    }

    pub fn fund(env: Env, requester: Address, job_id: BytesN<32>) -> AuditJob {
        requester.require_auth();
        let key = DataKey::Job(job_id.clone());
        let mut job = Self::read_job(&env, &key);
        if job.requester != requester {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Created {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() >= job.deadline {
            panic_with_error!(&env, Error::TooLate);
        }
        Self::bound_validation(&env, &job_id, &job);
        let token = Self::token(&env);
        token::Client::new(&env, &token).transfer(
            &requester,
            env.current_contract_address(),
            &job.amount,
        );
        job.state = JobState::Funded;
        Self::put_job(&env, &key, &job);
        Funded {
            job_id,
            amount: job.amount,
        }
        .publish(&env);
        job
    }

    pub fn submit(
        env: Env,
        provider: Address,
        job_id: BytesN<32>,
        del_hash: BytesN<32>,
    ) -> AuditJob {
        provider.require_auth();
        Self::require_hash(&env, &job_id);
        Self::require_hash(&env, &del_hash);
        let key = DataKey::Job(job_id.clone());
        let mut job = Self::read_job(&env, &key);
        if job.provider != provider {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Funded {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() >= job.deadline {
            panic_with_error!(&env, Error::TooLate);
        }
        let validation = Self::bound_validation(&env, &job_id, &job);
        if validation.state != ValState::Complete || validation.rep_hash != del_hash {
            panic_with_error!(&env, Error::InvalidValidation);
        }
        job.del_hash = del_hash.clone();
        job.score = validation.score;
        job.review_end = env
            .ledger()
            .sequence()
            .checked_add(REVIEW_LEDGERS)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        job.state = JobState::Submitted;
        Self::put_job(&env, &key, &job);
        Submitted { job_id, del_hash }.publish(&env);
        job
    }

    /// Evaluator accepts the delivered report inside the review window.
    pub fn complete(env: Env, evaluator: Address, job_id: BytesN<32>, score: u32) -> AuditJob {
        evaluator.require_auth();
        if score > 100 {
            panic_with_error!(&env, Error::BadScore);
        }
        let key = DataKey::Job(job_id.clone());
        let job = Self::read_job(&env, &key);
        if job.evaluator != evaluator {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Submitted {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() >= job.review_end {
            panic_with_error!(&env, Error::TooLate);
        }
        let validation = Self::bound_validation(&env, &job_id, &job);
        if validation.state != ValState::Complete || validation.rep_hash != job.del_hash {
            panic_with_error!(&env, Error::InvalidValidation);
        }
        if validation.score != score || job.score != score {
            panic_with_error!(&env, Error::BadScore);
        }
        Self::pay_provider(&env, job_id, &key, job)
    }

    /// Provider collects an undisputed delivery once the review window has closed.
    /// Registry state is not re-read: the delivery was verified at submission and a
    /// later requester-controlled identity change must not cancel payment.
    pub fn claim(env: Env, provider: Address, job_id: BytesN<32>) -> AuditJob {
        provider.require_auth();
        let key = DataKey::Job(job_id.clone());
        let job = Self::read_job(&env, &key);
        if job.provider != provider {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Submitted {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() < job.review_end {
            panic_with_error!(&env, Error::ReviewOpen);
        }
        Self::pay_provider(&env, job_id, &key, job)
    }

    /// Evaluator rejects a delivery inside the review window. Funds stay locked
    /// until the admin resolves the dispute; neither party can take them alone.
    pub fn dispute(env: Env, evaluator: Address, job_id: BytesN<32>) -> AuditJob {
        evaluator.require_auth();
        let key = DataKey::Job(job_id.clone());
        let mut job = Self::read_job(&env, &key);
        if job.evaluator != evaluator {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Submitted {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() >= job.review_end {
            panic_with_error!(&env, Error::TooLate);
        }
        job.state = JobState::Disputed;
        Self::put_job(&env, &key, &job);
        Disputed { job_id }.publish(&env);
        job
    }

    /// Admin arbitration of a disputed delivery.
    pub fn resolve(env: Env, admin: Address, job_id: BytesN<32>, refund: bool) -> AuditJob {
        Self::require_admin(&env, &admin);
        let key = DataKey::Job(job_id.clone());
        let job = Self::read_job(&env, &key);
        if job.state != JobState::Disputed {
            panic_with_error!(&env, Error::BadState);
        }
        if refund {
            Self::refund_requester(&env, job_id, &key, job)
        } else {
            Self::pay_provider(&env, job_id, &key, job)
        }
    }

    /// Requester recovers funds only when no report was submitted before the deadline.
    pub fn refund(env: Env, requester: Address, job_id: BytesN<32>) -> AuditJob {
        requester.require_auth();
        let key = DataKey::Job(job_id.clone());
        let job = Self::read_job(&env, &key);
        if job.requester != requester {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Funded {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() < job.deadline {
            panic_with_error!(&env, Error::TooEarly);
        }
        Self::refund_requester(&env, job_id, &key, job)
    }

    pub fn get_job(env: Env, job_id: BytesN<32>) -> AuditJob {
        Self::read_job(&env, &DataKey::Job(job_id))
    }

    pub fn get_binding(env: Env, job_id: BytesN<32>) -> RegistryBinding {
        let key = DataKey::Binding(job_id);
        let binding = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_MIN, TTL_EXTEND);
        binding
    }

    pub fn get_registry(env: Env) -> Address {
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
        env.storage()
            .instance()
            .get(&DataKey::Registry)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInit))
    }

    fn current_validation(
        env: &Env,
        job_id: &BytesN<32>,
        requester: &Address,
        provider: &Address,
    ) -> (ValidRec, AgentRec) {
        let registry = Self::get_registry(env.clone());
        let client = AgentRegistryClient::new(env, &registry);
        let validation = client.get_valid(job_id);
        if validation.requester != *requester
            || validation.validator != *provider
            || !client.is_valid(provider)
        {
            panic_with_error!(env, Error::InvalidValidation);
        }
        let agent = client.get_agent(&validation.agent_id);
        if !agent.active
            || agent.version != validation.version
            || agent.meta_hash != validation.meta_hash
            || agent.end_hash != validation.end_hash
        {
            panic_with_error!(env, Error::StaleIdentity);
        }
        (validation, agent)
    }

    fn bound_validation(env: &Env, job_id: &BytesN<32>, job: &AuditJob) -> ValidRec {
        let (validation, agent) =
            Self::current_validation(env, job_id, &job.requester, &job.provider);
        let binding = Self::get_binding(env.clone(), job_id.clone());
        if binding.agent_id != validation.agent_id
            || binding.owner != agent.owner
            || binding.version != validation.version
            || binding.meta_hash != validation.meta_hash
            || binding.end_hash != validation.end_hash
        {
            panic_with_error!(env, Error::StaleIdentity);
        }
        validation
    }

    fn pay_provider(env: &Env, job_id: BytesN<32>, key: &DataKey, mut job: AuditJob) -> AuditJob {
        let fee = job
            .amount
            .checked_mul(job.fee_bps as i128)
            .and_then(|v| v.checked_div(10_000))
            .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
        let payout = job
            .amount
            .checked_sub(fee)
            .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
        // Final state is written before any token call.
        job.state = JobState::Complete;
        Self::put_job(env, key, &job);
        let token = token::Client::new(env, &Self::token(env));
        let escrow = env.current_contract_address();
        if fee > 0 {
            token.transfer(&escrow, &job.fee_to, &fee);
        }
        token.transfer(&escrow, &job.provider, &payout);
        Completed {
            job_id,
            score: job.score,
            fee,
            payout,
        }
        .publish(env);
        job
    }

    fn refund_requester(
        env: &Env,
        job_id: BytesN<32>,
        key: &DataKey,
        mut job: AuditJob,
    ) -> AuditJob {
        job.state = JobState::Refunded;
        Self::put_job(env, key, &job);
        token::Client::new(env, &Self::token(env)).transfer(
            &env.current_contract_address(),
            &job.requester,
            &job.amount,
        );
        Refunded {
            job_id,
            amount: job.amount,
        }
        .publish(env);
        job
    }

    fn require_admin(env: &Env, supplied: &Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInit));
        if admin != *supplied {
            panic_with_error!(env, Error::Unauthorized);
        }
        supplied.require_auth();
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    }

    fn token(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInit))
    }

    fn read_job(env: &Env, key: &DataKey) -> AuditJob {
        let job = env
            .storage()
            .persistent()
            .get(key)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotFound));
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_MIN, TTL_EXTEND);
        job
    }

    fn put_job(env: &Env, key: &DataKey, job: &AuditJob) {
        env.storage().persistent().set(key, job);
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_MIN, TTL_EXTEND);
    }

    fn require_hash(env: &Env, value: &BytesN<32>) {
        if value == &BytesN::from_array(env, &[0; 32]) {
            panic_with_error!(env, Error::BadHash);
        }
    }
}

#[cfg(test)]
mod test;
