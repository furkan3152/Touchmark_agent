# Stellar Architecture Decision — 2026-08-30

## Decision

The root of trust for agent validation is a custom and versioned Soroban `AgentRegistry` contract. There is no direct "AI agent validation SEP" in the Stellar ecosystem. Therefore, agent identity, assigned validator, report hash, score, and independent reviewer signal are kept in the contract; payment/anchor protocols are not mixed into the validation core.

This repository is solely the Stellar pipeline. It does not import contracts, addresses, environment variables, signature schemes, or runtimes from another network. `scripts/verify_independence.sh` checks for source symlinks, hardlinks, and cross-runtime identifiers fail-closed.

## Validation flow

1. Agent input is normalized with secure ingestion.
2. G-account ownership claim is verified via network passphrase and SEP-53 message bound to the agent identity.
3. Seven auditors produce evidence in intent, security, economic, compliance, reliability, Stellar-native, and provenance dimensions.
4. Each auditor reports its success/failure status. A missing auditor does not silently join the quorum.
5. The report is converted to canonical JSON; the content hash and URI are committed together.
6. The backend does not hold a signer or seed. It prepares the `AgentRegistry.respond` call and delegates it to an external signer.
7. `confirmed=true` is only granted when the expected `responded` event, request/report hash match, and RPC `getTransaction=SUCCESS` are verified together.

Prepared invocation, simulation, contract ID configuration, or accessible RPC alone is not an on-chain success.

## Soroban contracts

### AgentRegistry — core

- G and C addresses are authorized through the same contract interface with `Address.require_auth()`.
- Agent registration is owner-bound, versioned, and can be made active/inactive.
- Validator and reviewer are separate admin allowlists.
- The validator is pinned upon request creation; another validator cannot respond.
- The response carries a score, URI, and 32-byte report hash; it is completed only once.
- A reviewer can score a request only once; the sum and count use checked arithmetic.
- The TTL of persistent records is renewed during read/write.
- The URI upper limit is 512 bytes; typed contract events are used.
- SEP-46 metadata and SEP-48 contract spec surface are embedded in the build artifact.

### AuditEscrow — optional

The validation core works without an escrow. If escrow is enabled, it uses the SAC token client; the requester, provider, and evaluator roles are separated from each other. Funding, delivery, evaluator completion, platform fee, deadline refund, and dispute flows are tested. This mode is not enabled without `ENABLE_AUDIT_ESCROW=true` and a verified contract/asset ID.

## SEP and system selection

Statuses were verified from the official SEP directory on 2026-08-30.

| Standard | Status | Decision |
|---|---|---|
| SEP-1 | Active | Recommended for service discovery and endpoint declaration; no published `stellar.toml` proof in core yet. |
| SEP-10 | Active | Used if G/M account web session is required; does not replace ownership report or Soroban auth. |
| SEP-24 | Active | Only the user's own interactive deposit/withdrawal anchor flow. Not included in the agent validation core. |
| SEP-31 | Active | Separate adapter for recipient/cross-border payout. Not modeled as the same business as SEP-24. |
| SEP-38 | Draft | If an anchor quote is needed, in a separate payment module by pinning the version; not a core trust proof. |
| SEP-41 | Draft | Optional escrow associated with the SAC token surface; not presented as a "Final standard". |
| SEP-45 | Draft | Correct direction for C-account web auth; a full challenge/session server is not implemented in this repository. |
| SEP-46 | Active | Used for contract metadata. |
| SEP-48 | Active | Used for generated contract interface/spec. |
| SEP-53 | Final | G-account off-chain message signature; verified with the official ASCII test vector. |
| SEP-55 | Draft | Monitored for build info; not a current release proof. |
| SEP-58 | Draft | Monitored for reproducible build verification; not a current release proof. |

SEP-53 proves private key control; it does not prove that a single signer can manage the entire account in a multisig setup. The actual authorization boundary in a transaction that carries value or changes registry state is the Soroban host authorization and a successful ledger outcome.

## Data and indexing

- Stellar RPC is for short-lived operational queries; it is not a historical indexer.
- `getEvents` results are continued with a cursor; written idempotently to SQLite with a unique event ID.
- Only events within the scope of the configured contract ID, contract event type, and successful contract call are accepted.
- A persistent ingest service is mandatory for the period outside the RPC provider's event retention window.
- The Horizon account `sequence` value is not the transaction count. The backend does not use it as economic behavior volume.
- Trustline, issuer, and strict-send/strict-receive/path payment risks are separate in the Stellar-native auditor.

## Production gates

1. Reproducible WASM generation and hash record with pinned Rust/SDK.
2. Match of source/WASM hash with the explorer or validation record.
3. Admin, validator, and reviewer key management; multisig/governance decision instead of single admin.
4. Real G-account and C-account authorization negative tests; `mock_all_auths` alone is not sufficient.
5. Continuous event ingest, cursor backup, lag/retention alert, and documentation of reorg/finality assumptions.
6. Proof of request → external signer → response → event/state readback on Testnet.
7. Real fund → submit → complete/refund lifecycle with actual SAC asset for escrow.
8. Independent Soroban security audit, dependency CVE/SBOM, and operations runbook.

## Official resources

- [Stellar contract authorization](https://developers.stellar.org/docs/build/guides/auth/contract-authorization)
- [Stellar Asset Contract](https://developers.stellar.org/docs/tokens/stellar-asset-contract)
- [Stellar RPC](https://developers.stellar.org/docs/data/apis/rpc)
- [RPC getEvents](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents)
- [SEP status directory](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/README.md)
- [SEP-53 Final](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md)
- [SEP-45 Draft](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md)
- [SEP-46](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0046.md)
- [SEP-48](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0048.md)
