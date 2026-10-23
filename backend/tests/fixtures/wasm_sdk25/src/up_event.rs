#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env};
#[contracttype]
pub enum DataKey { Admin, Count }
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        let n: u32 = e.storage().instance().get(&DataKey::Count).unwrap_or(0);
        e.storage().instance().set(&DataKey::Count, &(n + 1));
        e.events().publish((symbol_short!("upgrade"),), new_wasm_hash.clone());
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
