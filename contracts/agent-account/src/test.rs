extern crate std;

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    auth::{
        ContractContext, ContractExecutable, CreateContractHostFnContext,
        CreateContractWithConstructorHostFnContext,
    },
    testutils::{storage::Instance as _, Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, xdr, IntoVal, Symbol, TryIntoVal, Val,
};

struct Fixture {
    env: Env,
    account: Address,
    owner: Address,
    token: Address,
    recipient: Address,
    signer: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.ledger().set_sequence_number(100);
        let owner = Address::generate(&env);
        let account = env.register(AgentSessionAccount, (&owner,));
        let token = env
            .register_stellar_asset_contract_v2(owner.clone())
            .address();
        Self {
            recipient: Address::generate(&env),
            env,
            account,
            owner,
            token,
            signer: SigningKey::from_bytes(&[37; 32]),
        }
    }

    fn client(&self) -> AgentSessionAccountClient<'_> {
        AgentSessionAccountClient::new(&self.env, &self.account)
    }

    fn policy(&self) -> SessionPolicy {
        SessionPolicy {
            public_key: BytesN::from_array(&self.env, &self.signer.verifying_key().to_bytes()),
            token: self.token.clone(),
            recipient: self.recipient.clone(),
            per_call_limit: 60,
            total_limit: 100,
            expires_ledger: 200,
        }
    }

    // Administrative setup mocks ONLY the owner's exact call. Account-session
    // checks below always run the actual Ed25519 verifier and policy code.
    fn owner_auth(&self, name: &str, args: Vec<Val>) {
        self.env.mock_auths(&[MockAuth {
            address: &self.owner,
            invoke: &MockAuthInvoke {
                contract: &self.account,
                fn_name: name,
                args,
                sub_invokes: &[],
            },
        }]);
    }

    fn open(&self, policy: &SessionPolicy) -> u64 {
        self.owner_auth("open_session", (policy,).into_val(&self.env));
        let id = self.client().open_session(policy);
        self.env.set_auths(&[]);
        id
    }

    fn transfer(&self, amount: i128) -> Context {
        Context::Contract(ContractContext {
            contract: self.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&self.account, &self.recipient, amount).into_val(&self.env),
        })
    }

    fn signature(&self, payload: &BytesN<32>, id: u64) -> SessionSignature {
        let message: std::vec::Vec<u8> = signing_message(&self.env, payload, id).iter().collect();
        SessionSignature {
            session_id: id,
            signature: BytesN::from_array(&self.env, &self.signer.sign(&message).to_bytes()),
        }
    }

    fn check(&self, contexts: Vec<Context>) -> Result<(), Result<Error, soroban_sdk::InvokeError>> {
        let payload = BytesN::from_array(&self.env, &[49; 32]);
        let id = self.client().session().unwrap().id;
        self.env.try_invoke_contract_check_auth(
            &self.account,
            &payload,
            self.signature(&payload, id).into_val(&self.env),
            &contexts,
        )
    }

    fn assert_denied(&self, context: Context, error: Error) {
        let spent = self.client().session().unwrap().spent;
        assert_eq!(self.check(vec![&self.env, context]), Err(Ok(error)));
        assert_eq!(self.client().session().unwrap().spent, spent);
    }

    fn host_auth(&self, amount: i128, nonce: i64) -> xdr::SorobanAuthorizationEntry {
        self.host_auth_on_network(amount, nonce, self.env.ledger().network_id().to_array())
    }

    fn host_auth_on_network(
        &self,
        amount: i128,
        nonce: i64,
        network_id: [u8; 32],
    ) -> xdr::SorobanAuthorizationEntry {
        use xdr::WriteXdr;
        let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
            contract: &self.token,
            fn_name: "transfer",
            args: (&self.account, &self.recipient, amount).into_val(&self.env),
            sub_invokes: &[],
        })
            .into();
        let expiry = 190;
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(network_id),
                nonce,
                signature_expiration_ledger: expiry,
                invocation: invocation.clone(),
            });
        let payload: BytesN<32> = self
            .env
            .crypto()
            .sha256(&Bytes::from_slice(
                &self.env,
                &preimage.to_xdr(xdr::Limits::none()).unwrap(),
            ))
            .into();
        let id = self.client().session().unwrap().id;
        let signature: Val = self.signature(&payload, id).into_val(&self.env);
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: (&self.account).into(),
                nonce,
                signature_expiration_ledger: expiry,
                signature: signature.try_into_val(&self.env).unwrap(),
            }),
            root_invocation: invocation,
        }
    }

    fn mint(&self, amount: i128) {
        self.env.mock_auths(&[MockAuth {
            address: &self.owner,
            invoke: &MockAuthInvoke {
                contract: &self.token,
                fn_name: "mint",
                args: (&self.account, amount).into_val(&self.env),
                sub_invokes: &[],
            },
        }]);
        token::StellarAssetClient::new(&self.env, &self.token).mint(&self.account, &amount);
        self.env.set_auths(&[]);
    }
}

#[test]
fn valid_signature_enforces_cumulative_budget_across_contexts_and_calls() {
    let f = Fixture::new();
    f.open(&f.policy());
    assert_eq!(
        f.check(vec![&f.env, f.transfer(20), f.transfer(30)]),
        Ok(())
    );
    assert_eq!(f.client().session().unwrap().spent, 50);
    f.assert_denied(f.transfer(51), Error::BudgetExceeded);
    assert_eq!(f.check(vec![&f.env, f.transfer(50)]), Ok(()));
    f.assert_denied(f.transfer(1), Error::BudgetExceeded);
    assert_eq!(f.client().session().unwrap().spent, 100);
}

#[test]
fn multi_context_failure_has_no_partial_spend() {
    let f = Fixture::new();
    f.open(&f.policy());
    assert_eq!(
        f.check(vec![&f.env, f.transfer(60), f.transfer(60)]),
        Err(Ok(Error::BudgetExceeded))
    );
    assert_eq!(f.client().session().unwrap().spent, 0);
    assert_eq!(
        f.check(vec![&f.env, f.transfer(1), f.transfer(-1)]),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(f.client().session().unwrap().spent, 0);
}

#[test]
fn wrong_signature_payload_and_rotated_session_fail() {
    let f = Fixture::new();
    let first = f.open(&f.policy());
    let payload = BytesN::from_array(&f.env, &[3; 32]);
    let mut signature = f.signature(&payload, first);
    let contexts = vec![&f.env, f.transfer(1)];
    assert!(f
        .env
        .try_invoke_contract_check_auth::<Error>(
            &f.account,
            &BytesN::from_array(&f.env, &[4; 32]),
            signature.clone().into_val(&f.env),
            &contexts,
        )
        .is_err());
    let second = f.open(&f.policy());
    assert_eq!(second, first + 1);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<Error>(
            &f.account,
            &payload,
            signature.clone().into_val(&f.env),
            &contexts,
        ),
        Err(Ok(Error::WrongSession))
    );
    // Relabelling an old signature with a new ID and reused public key fails.
    signature.session_id = second;
    assert!(f
        .env
        .try_invoke_contract_check_auth::<Error>(
            &f.account,
            &payload,
            signature.into_val(&f.env),
            &contexts,
        )
        .is_err());
    assert_eq!(f.client().session().unwrap().spent, 0);
}

#[test]
fn wrong_key_cannot_sign_even_correct_scope() {
    let f = Fixture::new();
    f.open(&f.policy());
    let payload = BytesN::from_array(&f.env, &[9; 32]);
    let other = SigningKey::from_bytes(&[38; 32]);
    let signature = SessionSignature {
        session_id: 1,
        signature: BytesN::from_array(
            &f.env,
            &other
                .sign(
                    &signing_message(&f.env, &payload, 1)
                        .iter()
                        .collect::<std::vec::Vec<u8>>(),
                )
                .to_bytes(),
        ),
    };
    assert!(f
        .env
        .try_invoke_contract_check_auth::<Error>(
            &f.account,
            &payload,
            signature.into_val(&f.env),
            &vec![&f.env, f.transfer(1)],
        )
        .is_err());
}

#[test]
fn every_contract_field_and_argument_is_checked() {
    let f = Fixture::new();
    f.open(&f.policy());
    let contexts = [
        ContractContext {
            contract: Address::generate(&f.env),
            fn_name: symbol_short!("transfer"),
            args: (&f.account, &f.recipient, 1i128).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("approve"),
            args: (&f.account, &f.recipient, 1i128).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: Symbol::new(&f.env, "transfer_from"),
            args: (&f.account, &f.recipient, 1i128).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&f.owner, &f.recipient, 1i128).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&f.account, &f.owner, 1i128).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&f.account, &f.recipient, 1i128, 0u32).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&f.account, &f.recipient).into_val(&f.env),
        },
        ContractContext {
            contract: f.token.clone(),
            fn_name: symbol_short!("transfer"),
            args: (&f.account, &f.recipient, true).into_val(&f.env),
        },
    ];
    for context in contexts {
        f.assert_denied(Context::Contract(context), Error::InvalidContext);
    }
    f.assert_denied(f.transfer(0), Error::InvalidAmount);
    f.assert_denied(f.transfer(-1), Error::InvalidAmount);
    f.assert_denied(f.transfer(61), Error::BudgetExceeded);
}

#[test]
fn empty_creation_and_oversized_contexts_are_denied() {
    let f = Fixture::new();
    f.open(&f.policy());
    assert_eq!(f.check(vec![&f.env]), Err(Ok(Error::InvalidContext)));
    let executable = ContractExecutable::Wasm(BytesN::from_array(&f.env, &[1; 32]));
    let salt = BytesN::from_array(&f.env, &[2; 32]);
    f.assert_denied(
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: executable.clone(),
            salt: salt.clone(),
        }),
        Error::InvalidContext,
    );
    f.assert_denied(
        Context::CreateContractWithCtorHostFn(CreateContractWithConstructorHostFnContext {
            executable,
            salt,
            constructor_args: vec![&f.env, 1u32.into_val(&f.env)],
        }),
        Error::InvalidContext,
    );
    let mut contexts = Vec::new(&f.env);
    for _ in 0..17 {
        contexts.push_back(f.transfer(1));
    }
    assert_eq!(f.check(contexts), Err(Ok(Error::InvalidContext)));
}

#[test]
fn overflow_is_rejected_without_state_change() {
    let f = Fixture::new();
    let mut policy = f.policy();
    policy.per_call_limit = i128::MAX;
    policy.total_limit = i128::MAX;
    f.open(&policy);
    assert_eq!(
        f.check(vec![&f.env, f.transfer(i128::MAX), f.transfer(1)]),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(f.client().session().unwrap().spent, 0);
    assert_eq!(f.check(vec![&f.env, f.transfer(i128::MAX)]), Ok(()));
    f.assert_denied(f.transfer(1), Error::Overflow);
}

#[test]
fn expiry_revocation_shutdown_and_rotation_preserve_spend_history() {
    let f = Fixture::new();
    let id = f.open(&f.policy());
    f.check(vec![&f.env, f.transfer(3)]).unwrap();
    f.owner_auth("revoke_session", (id,).into_val(&f.env));
    f.client().revoke_session(&id);
    f.env.set_auths(&[]);
    f.assert_denied(f.transfer(1), Error::Revoked);
    assert_eq!(f.client().session().unwrap().spent, 3);
    assert_eq!(f.open(&f.policy()), 2);
    f.env.ledger().set_sequence_number(200);
    f.assert_denied(f.transfer(1), Error::Expired);
    f.owner_auth("shutdown", ().into_val(&f.env));
    f.client().shutdown();
    f.env.set_auths(&[]);
    assert!(f.client().halted());
    f.assert_denied(f.transfer(1), Error::Halted);
    f.owner_auth("open_session", (&f.policy(),).into_val(&f.env));
    assert_eq!(
        f.client().try_open_session(&f.policy()),
        Err(Ok(Error::Halted.into()))
    );
}

#[test]
fn administration_requires_owner_and_session_cannot_authorize_it() {
    let f = Fixture::new();
    assert!(f.client().try_open_session(&f.policy()).is_err());
    let id = f.open(&f.policy());
    assert!(f.client().try_revoke_session(&id).is_err());
    assert!(f.client().try_shutdown().is_err());
    assert!(f.client().try_recover(&f.token, &1).is_err());
    for name in ["open_session", "revoke_session", "shutdown", "recover"] {
        f.assert_denied(
            Context::Contract(ContractContext {
                contract: f.account.clone(),
                fn_name: Symbol::new(&f.env, name),
                args: vec![&f.env],
            }),
            Error::InvalidContext,
        );
    }
}

#[test]
fn policy_boundaries_are_validated_and_session_ids_never_wrap() {
    let f = Fixture::new();
    let mut bad = f.policy();
    for expiry in [100, 99, 100 + MAX_SESSION_LEDGERS + 1] {
        bad.expires_ledger = expiry;
        f.owner_auth("open_session", (&bad,).into_val(&f.env));
        assert_eq!(
            f.client().try_open_session(&bad),
            Err(Ok(Error::InvalidPolicy.into()))
        );
    }
    for (per_call, total) in [(0, 100), (-1, 100), (101, 100), (1, -1)] {
        bad = f.policy();
        bad.per_call_limit = per_call;
        bad.total_limit = total;
        f.owner_auth("open_session", (&bad,).into_val(&f.env));
        assert_eq!(
            f.client().try_open_session(&bad),
            Err(Ok(Error::InvalidPolicy.into()))
        );
    }
    f.env.as_contract(&f.account, || {
        let mut state = state(&f.env);
        state.last_id = u64::MAX;
        save(&f.env, &state);
    });
    f.owner_auth("open_session", (&f.policy(),).into_val(&f.env));
    assert_eq!(
        f.client().try_open_session(&f.policy()),
        Err(Ok(Error::Overflow.into()))
    );
}

#[test]
fn real_sac_transfer_checks_signature_budget_nonce_and_rollback() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.mint(90);
    let token = token::Client::new(&f.env, &f.token);
    let entry = f.host_auth(40, 1);
    f.env.set_auths(core::slice::from_ref(&entry));
    token.transfer(&f.account, &f.recipient, &40);
    assert_eq!(token.balance(&f.recipient), 40);
    assert_eq!(f.client().session().unwrap().spent, 40);
    f.env.set_auths(&[entry]);
    assert!(token.try_transfer(&f.account, &f.recipient, &40).is_err());
    assert_eq!(f.client().session().unwrap().spent, 40);
    // Valid signature and budget, insufficient actual balance: reservation rolls back.
    f.env.set_auths(&[f.host_auth(60, 2)]);
    assert!(token.try_transfer(&f.account, &f.recipient, &60).is_err());
    assert_eq!(f.client().session().unwrap().spent, 40);
    f.env.set_auths(&[f.host_auth(50, 3)]);
    token.transfer(&f.account, &f.recipient, &50);
    assert_eq!(f.client().session().unwrap().spent, 90);
    f.mint(50);
    f.env.set_auths(&[f.host_auth(11, 4)]);
    assert!(token.try_transfer(&f.account, &f.recipient, &11).is_err());
    assert_eq!(token.balance(&f.recipient), 90);
}

#[test]
fn recovery_is_owner_only_and_works_after_shutdown() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.mint(100);
    assert!(f.client().try_recover(&f.token, &100).is_err());
    f.owner_auth("shutdown", ().into_val(&f.env));
    f.client().shutdown();
    f.env.set_auths(&[]);
    assert!(f.client().try_recover(&f.token, &100).is_err());
    f.owner_auth("recover", (&f.token, 100i128).into_val(&f.env));
    f.client().recover(&f.token, &100);
    assert_eq!(token::Client::new(&f.env, &f.token).balance(&f.owner), 100);
    assert_eq!(token::Client::new(&f.env, &f.token).balance(&f.account), 0);
    assert!(f.client().halted());
    for amount in [0, -1] {
        f.owner_auth("recover", (&f.token, amount).into_val(&f.env));
        assert_eq!(
            f.client().try_recover(&f.token, &amount),
            Err(Ok(Error::InvalidAmount.into()))
        );
    }
}

#[test]
fn state_lifetime_exceeds_sessions_and_missing_state_fails_closed() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.env.as_contract(&f.account, || {
        assert!(f.env.storage().instance().get_ttl() > MAX_SESSION_LEDGERS);
        f.env.storage().instance().remove(&Key::State);
    });
    assert_eq!(
        f.client().try_session(),
        Err(Ok(Error::MissingState.into()))
    );
    assert!(f.client().try_open_session(&f.policy()).is_err());
}

#[test]
fn constructor_cannot_be_reinvoked_to_reset_authority_or_counter() {
    let f = Fixture::new();
    f.open(&f.policy());
    let attacker = Address::generate(&f.env);
    assert!(f
        .env
        .try_invoke_contract::<(), soroban_sdk::Error>(
            &f.account,
            &Symbol::new(&f.env, "__constructor"),
            (&attacker,).into_val(&f.env),
        )
        .is_err());
    assert_eq!(f.client().owner(), f.owner);
    assert_eq!(f.client().session().unwrap().id, 1);
    assert_eq!(f.open(&f.policy()), 2);
}

#[test]
fn real_sac_rejects_tampered_destination_amount_and_network() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.mint(100);
    let token = token::Client::new(&f.env, &f.token);
    let attacker = Address::generate(&f.env);
    for (recipient, amount, nonce) in [(&attacker, 40i128, 10), (&f.recipient, 41, 11)] {
        let mut entry = f.host_auth(40, nonce);
        // Replace the invocation with the one actually submitted, while retaining
        // the original signature. Tree matching succeeds; authentication must fail.
        entry.root_invocation = (&MockAuthInvoke {
            contract: &f.token,
            fn_name: "transfer",
            args: (&f.account, recipient, amount).into_val(&f.env),
            sub_invokes: &[],
        })
            .into();
        f.env.set_auths(&[entry]);
        assert!(token.try_transfer(&f.account, recipient, &amount).is_err());
        assert_eq!(f.client().session().unwrap().spent, 0);
    }
    f.env.set_auths(&[f.host_auth_on_network(40, 12, [99; 32])]);
    assert!(token.try_transfer(&f.account, &f.recipient, &40).is_err());
    assert_eq!(token.balance(&f.account), 100);
    assert_eq!(token.balance(&f.recipient), 0);
    assert_eq!(token.balance(&attacker), 0);
    assert_eq!(f.client().session().unwrap().spent, 0);
}

#[test]
fn real_sac_host_expiry_precedes_session_expiry() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.mint(100);
    let entry = f.host_auth(40, 20); // auth entry expires at 190, session at 200
    f.env.ledger().set_sequence_number(191);
    f.env.set_auths(&[entry]);
    assert!(token::Client::new(&f.env, &f.token)
        .try_transfer(&f.account, &f.recipient, &40)
        .is_err());
    assert_eq!(f.client().session().unwrap().spent, 0);
    assert_eq!(
        token::Client::new(&f.env, &f.token).balance(&f.account),
        100
    );
}

#[test]
fn real_sac_presigned_entries_fail_after_rotation_revocation_and_shutdown() {
    let f = Fixture::new();
    f.open(&f.policy());
    f.mint(100);
    let token = token::Client::new(&f.env, &f.token);
    let old = f.host_auth(40, 30);
    let id = f.open(&f.policy()); // deliberately reuse the exact same key
    f.env.set_auths(&[old]);
    assert!(token.try_transfer(&f.account, &f.recipient, &40).is_err());
    let revoked = f.host_auth(40, 31);
    f.owner_auth("revoke_session", (id,).into_val(&f.env));
    f.client().revoke_session(&id);
    f.env.set_auths(&[revoked]);
    assert!(token.try_transfer(&f.account, &f.recipient, &40).is_err());
    f.open(&f.policy());
    let halted = f.host_auth(40, 32);
    f.owner_auth("shutdown", ().into_val(&f.env));
    f.client().shutdown();
    f.env.set_auths(&[halted]);
    assert!(token.try_transfer(&f.account, &f.recipient, &40).is_err());
    assert_eq!(token.balance(&f.account), 100);
    assert_eq!(token.balance(&f.recipient), 0);
    assert_eq!(f.client().session().unwrap().spent, 0);
}

#[test]
fn real_sac_signature_cannot_be_relabelled_for_another_account() {
    let f = Fixture::new();
    f.open(&f.policy());
    let other = f.env.register(AgentSessionAccount, (&f.owner,));
    let other_client = AgentSessionAccountClient::new(&f.env, &other);
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &other,
            fn_name: "open_session",
            args: (&f.policy(),).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    other_client.open_session(&f.policy()); // same key, ID and transfer policy
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.token,
            fn_name: "mint",
            args: (&other, 100i128).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    token::StellarAssetClient::new(&f.env, &f.token).mint(&other, &100);
    let mut entry = f.host_auth(40, 40);
    let xdr::SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        panic!()
    };
    credentials.address = (&other).into();
    entry.root_invocation = (&MockAuthInvoke {
        contract: &f.token,
        fn_name: "transfer",
        args: (&other, &f.recipient, 40i128).into_val(&f.env),
        sub_invokes: &[],
    })
        .into();
    f.env.set_auths(&[entry]);
    let token = token::Client::new(&f.env, &f.token);
    assert!(token.try_transfer(&other, &f.recipient, &40).is_err());
    assert_eq!(token.balance(&other), 100);
    assert_eq!(other_client.session().unwrap().spent, 0);
}
