#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};
#[contracttype]
pub enum DataKey { Admin, Op(BytesN<32>) }
#[contracttype]
pub struct Op { pub hash: BytesN<32>, pub eta: u64 }
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn schedule(e: Env, id: BytesN<32>, hash: BytesN<32>) {
        let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        e.storage().persistent().set(&DataKey::Op(id), &Op { hash, eta: e.ledger().timestamp() + 86400 });
    }
    pub fn execute(e: Env, id: BytesN<32>) {
        let op: Op = e.storage().persistent().get(&DataKey::Op(id.clone())).unwrap();
        if e.ledger().timestamp() < op.eta { panic!("early"); }
        e.storage().persistent().remove(&DataKey::Op(id));
        e.deployer().update_current_contract_wasm(op.hash);
    }
}
