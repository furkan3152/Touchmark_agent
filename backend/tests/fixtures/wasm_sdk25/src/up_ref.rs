#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};
#[contracttype]
pub enum DataKey { Admin, Last }
#[contract]
pub struct C;
fn install(e: &Env, hash: &BytesN<32>) {
    e.storage().instance().set(&DataKey::Last, hash);
    e.deployer().update_current_contract_wasm(hash.clone());
}
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) { install(&e, &new_wasm_hash); }
    pub fn rollback(e: Env) {
        let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let last: BytesN<32> = e.storage().instance().get(&DataKey::Last).unwrap();
        install(&e, &last);
    }
}
