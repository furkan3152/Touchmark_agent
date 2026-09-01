#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype,
    panic_with_error, Address, BytesN, Env, String,
};

contractmeta!(key = "name", val = "AgentVeritas Registry");
contractmeta!(key = "version", val = "0.1.0");
contractmeta!(
    key = "sep",
    val = "SEP-46 metadata; SEP-48 generated interface"
);
contractmeta!(
    key = "purpose",
    val = "agent identity and validation evidence"
);

const TTL_MIN: u32 = 17_280;
const TTL_EXTEND: u32 = 518_400;
const MAX_URI_BYTES: u32 = 512;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRec {
    pub owner: Address,
    pub meta_uri: String,
    pub meta_hash: BytesN<32>,
    pub end_hash: BytesN<32>,
    pub active: bool,
    pub version: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValState {
    Pending,
    Complete,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidRec {
    pub agent_id: BytesN<32>,
    pub requester: Address,
    pub validator: Address,
    pub score: u32,
    pub rep_uri: String,
    pub rep_hash: BytesN<32>,
    pub state: ValState,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Agent(BytesN<32>),
    Valid(BytesN<32>),
    IsVal(Address),
    IsReviewer(Address),
    Review(BytesN<32>, Address),
    Score(BytesN<32>),
    Count(BytesN<32>),
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
    Inactive = 6,
    BadScore = 7,
    BadState = 8,
    NotValidator = 9,
    Reviewed = 10,
    BadVersion = 11,
    NotReviewer = 12,
    Overflow = 13,
    BadUri = 14,
    BadHash = 15,
}

#[contractevent(topics = ["agent_ver", "registered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentReg {
    #[topic]
    pub agent_id: BytesN<32>,
    pub owner: Address,
    pub version: u32,
}

#[contractevent(topics = ["agent_ver", "requested"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValReq {
    #[topic]
    pub req_id: BytesN<32>,
    #[topic]
    pub agent_id: BytesN<32>,
    pub requester: Address,
    pub validator: Address,
}

#[contractevent(topics = ["agent_ver", "responded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValResp {
    #[topic]
    pub req_id: BytesN<32>,
    #[topic]
    pub agent_id: BytesN<32>,
    pub validator: Address,
    pub score: u32,
    pub rep_hash: BytesN<32>,
}

#[contractevent(topics = ["agent_ver", "reviewed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reviewed {
    #[topic]
    pub req_id: BytesN<32>,
    #[topic]
    pub agent_id: BytesN<32>,
    pub reviewer: Address,
    pub score: u32,
}

#[contract]
pub struct AgentRegistry;

#[contractimpl]
impl AgentRegistry {
    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, Error::AlreadyInit);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    }

    pub fn set_valid(env: Env, admin: Address, validator: Address, enabled: bool) {
        Self::require_admin(&env, &admin);
        let key = DataKey::IsVal(validator);
        env.storage().persistent().set(&key, &enabled);
        Self::bump(&env, &key);
    }

    pub fn set_reviewer(env: Env, admin: Address, reviewer: Address, enabled: bool) {
        Self::require_admin(&env, &admin);
        let key = DataKey::IsReviewer(reviewer);
        env.storage().persistent().set(&key, &enabled);
        Self::bump(&env, &key);
    }

    pub fn reg_agent(
        env: Env,
        owner: Address,
        agent_id: BytesN<32>,
        meta_uri: String,
        meta_hash: BytesN<32>,
        end_hash: BytesN<32>,
        version: u32,
    ) -> AgentRec {
        owner.require_auth();
        Self::require_uri(&env, &meta_uri);
        Self::require_hash(&env, &agent_id);
        Self::require_hash(&env, &meta_hash);
        Self::require_hash(&env, &end_hash);
        if version == 0 {
            panic_with_error!(&env, Error::BadVersion);
        }
        let key = DataKey::Agent(agent_id.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, Error::Exists);
        }
        let record = AgentRec {
            owner: owner.clone(),
            meta_uri,
            meta_hash,
            end_hash,
            active: true,
            version,
        };
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
        AgentReg {
            agent_id,
            owner,
            version,
        }
        .publish(&env);
        record
    }

    pub fn upd_agent(
        env: Env,
        owner: Address,
        agent_id: BytesN<32>,
        meta_uri: String,
        meta_hash: BytesN<32>,
        end_hash: BytesN<32>,
        version: u32,
    ) -> AgentRec {
        owner.require_auth();
        Self::require_uri(&env, &meta_uri);
        Self::require_hash(&env, &agent_id);
        Self::require_hash(&env, &meta_hash);
        Self::require_hash(&env, &end_hash);
        let key = DataKey::Agent(agent_id);
        let mut record: AgentRec = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        if record.owner != owner {
            panic_with_error!(&env, Error::Unauthorized);
        }
        if version <= record.version {
            panic_with_error!(&env, Error::BadVersion);
        }
        record.meta_uri = meta_uri;
        record.meta_hash = meta_hash;
        record.end_hash = end_hash;
        record.version = version;
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
        record
    }

    pub fn set_active(env: Env, owner: Address, agent_id: BytesN<32>, active: bool) {
        owner.require_auth();
        let key = DataKey::Agent(agent_id);
        let mut record: AgentRec = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        if record.owner != owner {
            panic_with_error!(&env, Error::Unauthorized);
        }
        record.active = active;
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
    }

    pub fn req_valid(
        env: Env,
        requester: Address,
        req_id: BytesN<32>,
        agent_id: BytesN<32>,
        validator: Address,
    ) -> ValidRec {
        requester.require_auth();
        Self::require_hash(&env, &req_id);
        Self::require_hash(&env, &agent_id);
        let agent = Self::get_agent(env.clone(), agent_id.clone());
        if !agent.active {
            panic_with_error!(&env, Error::Inactive);
        }
        if !Self::is_valid(env.clone(), validator.clone()) {
            panic_with_error!(&env, Error::NotValidator);
        }
        let key = DataKey::Valid(req_id.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, Error::Exists);
        }
        let empty = BytesN::from_array(&env, &[0; 32]);
        let record = ValidRec {
            agent_id: agent_id.clone(),
            requester: requester.clone(),
            validator: validator.clone(),
            score: 0,
            rep_uri: String::from_str(&env, ""),
            rep_hash: empty,
            state: ValState::Pending,
        };
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
        ValReq {
            req_id,
            agent_id,
            requester,
            validator,
        }
        .publish(&env);
        record
    }

    pub fn respond(
        env: Env,
        validator: Address,
        req_id: BytesN<32>,
        score: u32,
        rep_uri: String,
        rep_hash: BytesN<32>,
    ) -> ValidRec {
        validator.require_auth();
        Self::require_uri(&env, &rep_uri);
        Self::require_hash(&env, &req_id);
        Self::require_hash(&env, &rep_hash);
        if score > 100 {
            panic_with_error!(&env, Error::BadScore);
        }
        let key = DataKey::Valid(req_id.clone());
        let mut record: ValidRec = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        if record.validator != validator || !Self::is_valid(env.clone(), validator.clone()) {
            panic_with_error!(&env, Error::NotValidator);
        }
        if record.state != ValState::Pending {
            panic_with_error!(&env, Error::BadState);
        }
        record.score = score;
        record.rep_uri = rep_uri;
        record.rep_hash = rep_hash.clone();
        record.state = ValState::Complete;
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
        ValResp {
            req_id,
            agent_id: record.agent_id.clone(),
            validator,
            score,
            rep_hash,
        }
        .publish(&env);
        record
    }

    pub fn review(env: Env, reviewer: Address, req_id: BytesN<32>, score: u32) {
        reviewer.require_auth();
        if score > 100 {
            panic_with_error!(&env, Error::BadScore);
        }
        if !Self::is_reviewer(env.clone(), reviewer.clone()) {
            panic_with_error!(&env, Error::NotReviewer);
        }
        let validation = Self::get_valid(env.clone(), req_id.clone());
        if validation.state != ValState::Complete {
            panic_with_error!(&env, Error::BadState);
        }
        let review_key = DataKey::Review(req_id.clone(), reviewer.clone());
        if env.storage().persistent().has(&review_key) {
            panic_with_error!(&env, Error::Reviewed);
        }
        env.storage().persistent().set(&review_key, &score);
        Self::bump(&env, &review_key);

        let score_key = DataKey::Score(validation.agent_id.clone());
        let count_key = DataKey::Count(validation.agent_id.clone());
        let total: u64 = env.storage().persistent().get(&score_key).unwrap_or(0);
        let count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        let next_total = total
            .checked_add(score as u64)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let next_count = count
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        env.storage().persistent().set(&score_key, &next_total);
        env.storage().persistent().set(&count_key, &next_count);
        Self::bump(&env, &score_key);
        Self::bump(&env, &count_key);
        Reviewed {
            req_id,
            agent_id: validation.agent_id,
            reviewer,
            score,
        }
        .publish(&env);
    }

    pub fn get_agent(env: Env, agent_id: BytesN<32>) -> AgentRec {
        let key = DataKey::Agent(agent_id);
        let value = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        Self::bump(&env, &key);
        value
    }

    pub fn get_valid(env: Env, req_id: BytesN<32>) -> ValidRec {
        let key = DataKey::Valid(req_id);
        let value = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotFound));
        Self::bump(&env, &key);
        value
    }

    pub fn is_valid(env: Env, validator: Address) -> bool {
        let key = DataKey::IsVal(validator);
        let value = env.storage().persistent().get(&key).unwrap_or(false);
        if env.storage().persistent().has(&key) {
            Self::bump(&env, &key);
        }
        value
    }

    pub fn is_reviewer(env: Env, reviewer: Address) -> bool {
        let key = DataKey::IsReviewer(reviewer);
        let value = env.storage().persistent().get(&key).unwrap_or(false);
        if env.storage().persistent().has(&key) {
            Self::bump(&env, &key);
        }
        value
    }

    pub fn avg_score(env: Env, agent_id: BytesN<32>) -> u32 {
        let score_key = DataKey::Score(agent_id.clone());
        let count_key = DataKey::Count(agent_id);
        let total: u64 = env.storage().persistent().get(&score_key).unwrap_or(0);
        let count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        if env.storage().persistent().has(&score_key) {
            Self::bump(&env, &score_key);
        }
        if env.storage().persistent().has(&count_key) {
            Self::bump(&env, &count_key);
        }
        if count == 0 {
            0
        } else {
            (total / count as u64) as u32
        }
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

    fn bump(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_MIN, TTL_EXTEND);
    }

    fn require_uri(env: &Env, uri: &String) {
        if uri.is_empty() || uri.len() > MAX_URI_BYTES {
            panic_with_error!(env, Error::BadUri);
        }
    }

    fn require_hash(env: &Env, value: &BytesN<32>) {
        if value == &BytesN::from_array(env, &[0; 32]) {
            panic_with_error!(env, Error::BadHash);
        }
    }
}

#[cfg(test)]
mod test;
