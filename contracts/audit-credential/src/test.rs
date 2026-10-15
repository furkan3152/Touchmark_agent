extern crate std;
use super::*;
use agent_veritas_registry::AgentRegistry;
use soroban_sdk::testutils::{Address as _, Ledger};

fn hash(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}

struct Fixture {
    env: Env,
    registry: Address,
    credential: Address,
    owner: Address,
    admin: Address,
    issuer: Address,
    request: BytesN<32>,
    agent: BytesN<32>,
}
impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|li| li.timestamp = 1000);
        let admin = Address::generate(&env);
        let registry = env.register(AgentRegistry, (&admin,));
        let owner = Address::generate(&env);
        let issuer = Address::generate(&env);
        let agent = hash(&env, 1);
        let request = hash(&env, 2);
        let client = AgentRegistryClient::new(&env, &registry);
        client.set_valid(&admin, &issuer, &true);
        client.reg_agent(
            &owner,
            &agent,
            &String::from_str(&env, "ipfs://source"),
            &hash(&env, 3),
            &hash(&env, 4),
            &1,
        );
        client.req_valid(&owner, &request, &agent, &issuer);
        client.respond(
            &issuer,
            &request,
            &70,
            &String::from_str(&env, "ipfs://report"),
            &hash(&env, 5),
        );
        let credential = env.register(AuditCredential, (&registry,));
        Self {
            env,
            registry,
            credential,
            owner,
            admin,
            issuer,
            request,
            agent,
        }
    }
    fn issue(&self) -> Credential {
        AuditCredentialClient::new(&self.env, &self.credential).issue(&self.request, &2000)
    }
    fn update(&self) {
        AgentRegistryClient::new(&self.env, &self.registry).upd_agent(
            &self.owner,
            &self.agent,
            &String::from_str(&self.env, "ipfs://new"),
            &hash(&self.env, 6),
            &hash(&self.env, 7),
            &2,
        );
    }
}

#[test]
fn credential_binds_owner_report_version_and_issuer_auth() {
    let f = Fixture::new();
    let record = f.issue();
    assert_eq!(record.owner, f.owner);
    assert_eq!(record.report_hash, hash(&f.env, 5));
    assert_eq!(record.version, 1);
    assert_eq!(f.env.auths()[0].0, f.issuer);
    let c = AuditCredentialClient::new(&f.env, &f.credential);
    assert!(c.is_current(&f.request));
    assert_eq!(c.owner_of(&f.request), f.owner);
    assert!(c.try_issue(&f.request, &2000).is_err());
}

#[test]
fn source_change_invalidates_and_prevents_stale_mint() {
    let f = Fixture::new();
    f.issue();
    f.update();
    assert!(!AuditCredentialClient::new(&f.env, &f.credential).is_current(&f.request));
    let f = Fixture::new();
    f.update();
    assert!(AuditCredentialClient::new(&f.env, &f.credential)
        .try_issue(&f.request, &2000)
        .is_err());
}

#[test]
fn revocation_is_authorized_and_permanent() {
    let f = Fixture::new();
    f.issue();
    let c = AuditCredentialClient::new(&f.env, &f.credential);
    assert!(c
        .try_revoke(&Address::generate(&f.env), &f.request, &hash(&f.env, 9))
        .is_err());
    assert!(c
        .try_revoke(&f.owner, &f.request, &hash(&f.env, 0))
        .is_err());
    c.revoke(&f.owner, &f.request, &hash(&f.env, 9));
    assert!(!c.is_current(&f.request));
    assert!(c.get(&f.request).revoked);
    assert!(c.try_issue(&f.request, &2000).is_err());
}

#[test]
fn expiry_and_validator_removal_fail_closed() {
    let f = Fixture::new();
    f.issue();
    let c = AuditCredentialClient::new(&f.env, &f.credential);
    f.env.ledger().with_mut(|li| li.timestamp = 2000);
    assert!(!c.is_current(&f.request));
    let f = Fixture::new();
    f.issue();
    AgentRegistryClient::new(&f.env, &f.registry).set_valid(&f.admin, &f.issuer, &false);
    assert!(!AuditCredentialClient::new(&f.env, &f.credential).is_current(&f.request));
}

#[test]
fn invalid_expiration_and_missing_signature_rejected() {
    let f = Fixture::new();
    let c = AuditCredentialClient::new(&f.env, &f.credential);
    assert!(c.try_issue(&f.request, &1000).is_err());
    assert!(c.try_issue(&f.request, &(1001 + MAX_VALIDITY)).is_err());
    f.env.mock_auths(&[]);
    assert!(c.try_issue(&f.request, &2000).is_err());
}
