//! Wire-compatible registry interface. Do not link the registry implementation into WASM.
use soroban_sdk::{contractclient, contracttype, Address, BytesN, Env, String};

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
    pub version: u32,
    pub meta_hash: BytesN<32>,
    pub end_hash: BytesN<32>,
    pub requester: Address,
    pub validator: Address,
    pub score: u32,
    pub rep_uri: String,
    pub rep_hash: BytesN<32>,
    pub state: ValState,
}

#[allow(dead_code)]
#[contractclient(name = "AgentRegistryClient")]
pub trait RegistryInterface {
    fn get_agent(env: Env, agent_id: BytesN<32>) -> AgentRec;
    fn get_valid(env: Env, req_id: BytesN<32>) -> ValidRec;
    fn is_valid(env: Env, validator: Address) -> bool;
}
