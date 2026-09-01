#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype,
    panic_with_error, token, Address, BytesN, Env,
};

contractmeta!(key = "name", val = "AgentVeritas Audit Escrow");
contractmeta!(key = "version", val = "0.1.0");
contractmeta!(key = "asset", val = "SEP-41 Stellar Asset Contract client");
contractmeta!(key = "purpose", val = "optional agent audit settlement");

const TTL_MIN: u32 = 17_280;
const TTL_EXTEND: u32 = 518_400;
const MAX_FEE_BPS: u32 = 3_000;

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
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Token,
    FeeTo,
    FeeBps,
    Job(BytesN<32>),
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

#[contract]
pub struct AuditEscrow;

#[contractimpl]
impl AuditEscrow {
    pub fn init(env: Env, admin: Address, token: Address, fee_to: Address, fee_bps: u32) {
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
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    }

    pub fn set_fee(env: Env, admin: Address, fee_to: Address, fee_bps: u32) {
        Self::require_admin(&env, &admin);
        if fee_bps > MAX_FEE_BPS {
            panic_with_error!(&env, Error::BadFee);
        }
        env.storage().instance().set(&DataKey::FeeTo, &fee_to);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
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
        job.del_hash = del_hash.clone();
        job.state = JobState::Submitted;
        Self::put_job(&env, &key, &job);
        Submitted { job_id, del_hash }.publish(&env);
        job
    }

    pub fn complete(env: Env, evaluator: Address, job_id: BytesN<32>, score: u32) -> AuditJob {
        evaluator.require_auth();
        if score > 100 {
            panic_with_error!(&env, Error::BadScore);
        }
        let key = DataKey::Job(job_id.clone());
        let mut job = Self::read_job(&env, &key);
        if job.evaluator != evaluator {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Submitted {
            panic_with_error!(&env, Error::BadState);
        }
        if env.ledger().sequence() >= job.deadline {
            panic_with_error!(&env, Error::TooLate);
        }
        let fee = job
            .amount
            .checked_mul(job.fee_bps as i128)
            .and_then(|v| v.checked_div(10_000))
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let payout = job
            .amount
            .checked_sub(fee)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let token = token::Client::new(&env, &Self::token(&env));
        let escrow = env.current_contract_address();
        if fee > 0 {
            token.transfer(&escrow, &job.fee_to, &fee);
        }
        token.transfer(&escrow, &job.provider, &payout);
        job.score = score;
        job.state = JobState::Complete;
        Self::put_job(&env, &key, &job);
        Completed {
            job_id,
            score,
            fee,
            payout,
        }
        .publish(&env);
        job
    }

    pub fn dispute(env: Env, evaluator: Address, job_id: BytesN<32>) -> AuditJob {
        evaluator.require_auth();
        let key = DataKey::Job(job_id);
        let mut job = Self::read_job(&env, &key);
        if job.evaluator != evaluator {
            panic_with_error!(&env, Error::BadRole);
        }
        if job.state != JobState::Submitted {
            panic_with_error!(&env, Error::BadState);
        }
        job.state = JobState::Disputed;
        Self::put_job(&env, &key, &job);
        job
    }

    pub fn refund(env: Env, requester: Address, job_id: BytesN<32>) -> AuditJob {
        requester.require_auth();
        let key = DataKey::Job(job_id.clone());
        let mut job = Self::read_job(&env, &key);
        if job.requester != requester {
            panic_with_error!(&env, Error::BadRole);
        }
        let immediate = job.state == JobState::Disputed;
        let timed_refund = job.state == JobState::Funded || job.state == JobState::Submitted;
        if !timed_refund && !immediate {
            panic_with_error!(&env, Error::BadState);
        }
        if !immediate && env.ledger().sequence() < job.deadline {
            panic_with_error!(&env, Error::TooEarly);
        }
        token::Client::new(&env, &Self::token(&env)).transfer(
            &env.current_contract_address(),
            &requester,
            &job.amount,
        );
        job.state = JobState::Refunded;
        Self::put_job(&env, &key, &job);
        Refunded {
            job_id,
            amount: job.amount,
        }
        .publish(&env);
        job
    }

    pub fn get_job(env: Env, job_id: BytesN<32>) -> AuditJob {
        Self::read_job(&env, &DataKey::Job(job_id))
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
