#![no_std]
//! Non-transferable audit credentials. They prove issuer assertions, not safety.
use agent_veritas_registry::{AgentRegistryClient, ValState};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, Env, String,
};

const TTL_MIN: u32 = 17_280;
const TTL_EXTEND: u32 = 518_400;
const MAX_VALIDITY: u64 = 90 * 86_400;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub owner: Address,
    pub issuer: Address,
    pub agent_id: BytesN<32>,
    pub version: u32,
    pub meta_hash: BytesN<32>,
    pub end_hash: BytesN<32>,
    pub report_hash: BytesN<32>,
    pub report_uri: String,
    pub score: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub reason_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Registry,
    Token(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotFound = 1,
    Exists = 2,
    InvalidValidation = 3,
    Expiry = 4,
    Unauthorized = 5,
    EmptyReason = 6,
}

#[contractevent(topics = ["audit", "issued"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issued {
    #[topic]
    pub token_id: BytesN<32>,
    pub agent_id: BytesN<32>,
    pub report_hash: BytesN<32>,
    pub expires_at: u64,
}

#[contractevent(topics = ["audit", "revoked"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revoked {
    #[topic]
    pub token_id: BytesN<32>,
    pub reason_hash: BytesN<32>,
}

#[contract]
pub struct AuditCredential;

#[contractimpl]
impl AuditCredential {
    // Atomic initialization prevents a separate init call being front-run.
    pub fn __constructor(env: Env, registry: Address) {
        env.storage().instance().set(&Key::Registry, &registry);
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    }

    // token_id is the registry request ID: one unique token per completed audit.
    // Deliberately no transfer, approve, or burn method: history cannot be sold or erased.
    pub fn issue(env: Env, token_id: BytesN<32>, expires_at: u64) -> Credential {
        let key = Key::Token(token_id.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, Error::Exists);
        }
        let registry = Self::registry(&env);
        let client = AgentRegistryClient::new(&env, &registry);
        let validation = client.get_valid(&token_id);
        validation.validator.require_auth();
        let agent = client.get_agent(&validation.agent_id);
        if validation.state != ValState::Complete
            || !agent.active
            || agent.version != validation.version
            || agent.meta_hash != validation.meta_hash
            || agent.end_hash != validation.end_hash
            || !client.is_valid(&validation.validator)
        {
            panic_with_error!(&env, Error::InvalidValidation);
        }
        let now = env.ledger().timestamp();
        if expires_at <= now || expires_at - now > MAX_VALIDITY {
            panic_with_error!(&env, Error::Expiry);
        }
        let record = Credential {
            owner: agent.owner,
            issuer: validation.validator,
            agent_id: validation.agent_id,
            version: validation.version,
            meta_hash: validation.meta_hash,
            end_hash: validation.end_hash,
            report_hash: validation.rep_hash,
            report_uri: validation.rep_uri,
            score: validation.score,
            issued_at: now,
            expires_at,
            revoked: false,
            reason_hash: BytesN::from_array(&env, &[0; 32]),
        };
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_MIN, TTL_EXTEND);
        Issued {
            token_id,
            agent_id: record.agent_id.clone(),
            report_hash: record.report_hash.clone(),
            expires_at,
        }
        .publish(&env);
        record
    }

    pub fn get(env: Env, token_id: BytesN<32>) -> Credential {
        Self::registry(&env);
        let key = Key::Token(token_id);
        let record = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_MIN, TTL_EXTEND);
        record
    }

    pub fn owner_of(env: Env, token_id: BytesN<32>) -> Address {
        Self::get(env, token_id).owner
    }

    pub fn revoke(env: Env, actor: Address, token_id: BytesN<32>, reason_hash: BytesN<32>) {
        actor.require_auth();
        let mut record = Self::get(env.clone(), token_id.clone());
        if actor != record.issuer && actor != record.owner {
            panic_with_error!(&env, Error::Unauthorized);
        }
        if reason_hash == BytesN::from_array(&env, &[0; 32]) {
            panic_with_error!(&env, Error::EmptyReason);
        }
        record.revoked = true;
        record.reason_hash = reason_hash.clone();
        env.storage()
            .persistent()
            .set(&Key::Token(token_id.clone()), &record);
        Revoked {
            token_id,
            reason_hash,
        }
        .publish(&env);
    }

    pub fn is_current(env: Env, token_id: BytesN<32>) -> bool {
        let record = Self::get(env.clone(), token_id);
        if record.revoked || env.ledger().timestamp() >= record.expires_at {
            return false;
        }
        let registry = Self::registry(&env);
        let client = AgentRegistryClient::new(&env, &registry);
        let agent = client.get_agent(&record.agent_id);
        agent.active
            && agent.owner == record.owner
            && agent.version == record.version
            && agent.meta_hash == record.meta_hash
            && agent.end_hash == record.end_hash
            && client.is_valid(&record.issuer)
    }
}

impl AuditCredential {
    fn registry(env: &Env) -> Address {
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
        env.storage().instance().get(&Key::Registry).unwrap()
    }
}

#[cfg(test)]
mod test;
