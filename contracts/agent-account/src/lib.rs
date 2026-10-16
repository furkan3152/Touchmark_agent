#![no_std]
//! Experimental bounded agent spending account. This enforces on-chain authority,
//! not the agent's intentions or the security of off-chain tools.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, symbol_short, token, Address, Bytes, BytesN, Env, TryFromVal, Vec,
};

const TTL_MIN: u32 = 17_280;
const TTL_EXTEND: u32 = 518_400;
pub const MAX_SESSION_LEDGERS: u32 = 17_280;
const MAX_AUTH_CONTEXTS: u32 = 16;
const SIGNATURE_DOMAIN: &[u8] = b"AgentVeritas/session/v1\0";

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub public_key: BytesN<32>,
    pub token: Address,
    pub recipient: Address,
    pub per_call_limit: i128,
    pub total_limit: i128,
    pub expires_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: u64,
    pub policy: SessionPolicy,
    /// Reserved authorization budget, potentially greater than settled transfers.
    pub spent: i128,
    pub revoked: bool,
}

#[contracttype]
#[derive(Clone)]
struct State {
    owner: Address,
    last_id: u64,
    halted: bool,
    active: ActiveSession,
}

// Contract ABI values cannot use Box; this has only one stored instance.
#[allow(clippy::large_enum_variant)]
#[contracttype]
#[derive(Clone)]
enum ActiveSession {
    Missing,
    Present(Session),
}

#[contracttype]
#[derive(Clone)]
enum Key {
    State,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSignature {
    pub session_id: u64,
    pub signature: BytesN<64>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    MissingState = 1,
    InvalidOwner = 2,
    Halted = 3,
    InvalidPolicy = 4,
    Expired = 5,
    NoSession = 6,
    WrongSession = 7,
    Revoked = 8,
    InvalidContext = 9,
    InvalidAmount = 10,
    BudgetExceeded = 11,
    Overflow = 12,
}

#[contractevent(topics = ["agent", "session"])]
#[derive(Clone)]
pub struct SessionOpened {
    #[topic]
    pub id: u64,
    pub policy: SessionPolicy,
}

#[contractevent(topics = ["agent", "revoked"])]
#[derive(Clone)]
pub struct SessionRevoked {
    #[topic]
    pub id: u64,
}

#[contractevent(topics = ["agent", "halted"])]
#[derive(Clone)]
pub struct AccountHalted {
    pub owner: Address,
}

#[contract]
pub struct AgentSessionAccount;

fn state(env: &Env) -> State {
    // Missing/archived state must never be interpreted as fresh account state.
    let result = env
        .storage()
        .instance()
        .get(&Key::State)
        .unwrap_or_else(|| panic_with_error!(env, Error::MissingState));
    env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
    result
}

fn save(env: &Env, state: &State) {
    env.storage().instance().set(&Key::State, state);
    env.storage().instance().extend_ttl(TTL_MIN, TTL_EXTEND);
}

// Host payload binds the network, nonce, expiry and auth tree. The required
// transfer's from argument binds this specific account in that signed tree.
// The extra domain and ID prevent a signature being reused after key rotation,
// even if an owner deliberately chooses the same public key for a new session.
fn signing_message(env: &Env, payload: &BytesN<32>, session_id: u64) -> Bytes {
    let mut message = Bytes::from_slice(env, SIGNATURE_DOMAIN);
    message.append(&Bytes::from_array(env, &session_id.to_be_bytes()));
    message.append(&payload.clone().into());
    message
}

#[contractimpl]
impl AgentSessionAccount {
    pub fn __constructor(env: Env, owner: Address) {
        if owner == env.current_contract_address() {
            panic_with_error!(&env, Error::InvalidOwner);
        }
        save(
            &env,
            &State {
                owner,
                last_id: 0,
                halted: false,
                active: ActiveSession::Missing,
            },
        );
    }

    /// Atomically replaces the single active session; never resets/reuses its ID.
    pub fn open_session(env: Env, policy: SessionPolicy) -> u64 {
        let mut state = state(&env);
        state.owner.require_auth();
        if state.halted {
            panic_with_error!(&env, Error::Halted);
        }
        let now = env.ledger().sequence();
        if policy.expires_ledger <= now
            || policy.expires_ledger - now > MAX_SESSION_LEDGERS
            || policy.per_call_limit <= 0
            || policy.total_limit < policy.per_call_limit
            || policy.public_key == BytesN::from_array(&env, &[0; 32])
            || policy.recipient == env.current_contract_address()
            || policy.token == env.current_contract_address()
        {
            panic_with_error!(&env, Error::InvalidPolicy);
        }
        let id = state
            .last_id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        state.last_id = id;
        state.active = ActiveSession::Present(Session {
            id,
            policy: policy.clone(),
            spent: 0,
            revoked: false,
        });
        save(&env, &state);
        SessionOpened { id, policy }.publish(&env);
        id
    }

    pub fn revoke_session(env: Env, session_id: u64) {
        let mut state = state(&env);
        state.owner.require_auth();
        let ActiveSession::Present(session) = &mut state.active else {
            panic_with_error!(&env, Error::NoSession);
        };
        if session.id != session_id {
            panic_with_error!(&env, Error::WrongSession);
        }
        session.revoked = true;
        save(&env, &state);
        SessionRevoked { id: session_id }.publish(&env);
    }

    /// Irreversible kill switch. Owner-only recovery remains available.
    pub fn shutdown(env: Env) {
        let mut state = state(&env);
        state.owner.require_auth();
        state.halted = true;
        if let ActiveSession::Present(session) = &mut state.active {
            session.revoked = true;
        }
        save(&env, &state);
        AccountHalted { owner: state.owner }.publish(&env);
    }

    /// The only direct token invocation: return funds to the immutable owner.
    /// Session signatures never authorize this function or another recipient.
    pub fn recover(env: Env, token: Address, amount: i128) {
        let state = state(&env);
        state.owner.require_auth();
        if amount <= 0 || token == env.current_contract_address() {
            panic_with_error!(&env, Error::InvalidAmount);
        }
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &state.owner,
            &amount,
        );
    }

    pub fn session(env: Env) -> Option<Session> {
        match state(&env).active {
            ActiveSession::Missing => None,
            ActiveSession::Present(session) => Some(session),
        }
    }

    pub fn owner(env: Env) -> Address {
        state(&env).owner
    }

    pub fn halted(env: Env) -> bool {
        state(&env).halted
    }
}

#[contractimpl]
impl CustomAccountInterface for AgentSessionAccount {
    type Signature = SessionSignature;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: SessionSignature,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let mut state = state(&env);
        if state.halted {
            return Err(Error::Halted);
        }
        let ActiveSession::Present(mut session) = state.active.clone() else {
            return Err(Error::NoSession);
        };
        if session.id != signatures.session_id {
            return Err(Error::WrongSession);
        }
        if session.revoked {
            return Err(Error::Revoked);
        }
        // Expiry is exclusive: at this ledger the key already has no authority.
        if env.ledger().sequence() >= session.policy.expires_ledger {
            return Err(Error::Expired);
        }
        if auth_contexts.is_empty() || auth_contexts.len() > MAX_AUTH_CONTEXTS {
            return Err(Error::InvalidContext);
        }
        env.crypto().ed25519_verify(
            &session.policy.public_key,
            &signing_message(&env, &signature_payload.into(), session.id),
            &signatures.signature,
        );

        let mut amount_sum: i128 = 0;
        for context in auth_contexts.iter() {
            let Context::Contract(call) = context else {
                return Err(Error::InvalidContext);
            };
            if call.contract != session.policy.token
                || call.fn_name != symbol_short!("transfer")
                || call.args.len() != 3
            {
                return Err(Error::InvalidContext);
            }
            let from = Address::try_from_val(&env, &call.args.get(0).unwrap())
                .map_err(|_| Error::InvalidContext)?;
            let to = Address::try_from_val(&env, &call.args.get(1).unwrap())
                .map_err(|_| Error::InvalidContext)?;
            let amount = i128::try_from_val(&env, &call.args.get(2).unwrap())
                .map_err(|_| Error::InvalidContext)?;
            if from != env.current_contract_address() || to != session.policy.recipient {
                return Err(Error::InvalidContext);
            }
            if amount <= 0 {
                return Err(Error::InvalidAmount);
            }
            if amount > session.policy.per_call_limit {
                return Err(Error::BudgetExceeded);
            }
            amount_sum = amount_sum.checked_add(amount).ok_or(Error::Overflow)?;
        }
        let spent = session
            .spent
            .checked_add(amount_sum)
            .ok_or(Error::Overflow)?;
        if spent > session.policy.total_limit {
            return Err(Error::BudgetExceeded);
        }
        // Check the complete tree before writing. Host transaction rollback also
        // rolls this reservation back if the surrounding transaction fails.
        session.spent = spent;
        state.active = ActiveSession::Present(session);
        save(&env, &state);
        Ok(())
    }
}

#[cfg(test)]
mod test;
