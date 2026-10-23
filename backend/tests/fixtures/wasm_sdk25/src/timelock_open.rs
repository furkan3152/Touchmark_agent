#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};
#[contracttype]
pub enum DataKey { Admin, Pending, Eta }
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn schedule(e: Env, hash: BytesN<32>) {
        e.storage().instance().set(&DataKey::Pending, &hash);
        e.storage().instance().set(&DataKey::Eta, &(e.ledger().timestamp() + 86400));
    }
    pub fn execute(e: Env) {
        let eta: u64 = e.storage().instance().get(&DataKey::Eta).unwrap();
        if e.ledger().timestamp() < eta { panic!("early"); }
        let hash: BytesN<32> = e.storage().instance().get(&DataKey::Pending).unwrap();
        e.deployer().update_current_contract_wasm(hash);
    }
}
