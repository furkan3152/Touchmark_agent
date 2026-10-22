#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};
#[contracttype]
pub enum DataKey { Admin, Approved }
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn approve(e: Env, hash: BytesN<32>) {
        let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        e.storage().instance().set(&DataKey::Approved, &hash);
    }
    pub fn upgrade(e: Env, hash: BytesN<32>) {
        let approved: BytesN<32> = e.storage().instance().get(&DataKey::Approved).unwrap();
        if hash != approved { panic!("not approved"); }
        e.deployer().update_current_contract_wasm(hash);
    }
}
