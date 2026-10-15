# AgentSessionAccount — experimental Soroban enforcement

This contract turns one narrow audit recommendation into an enforceable rule:
an agent session key may spend only a bounded amount of a specified token to
one specified recipient, before a specified ledger. A report or prompt cannot
grant additional authority. The rule runs inside Soroban authorization.

**Status:** experimental, locally tested code. Not independently audited,
deployed, wired into Studio or offered as a production wallet. Do not deposit
production funds. This contract does not detect vulnerabilities, prove an
agent's intentions, or control keys and tools outside this account.

## Authority model

The immutable owner is a Stellar `Address` (G-account or C-account). Deployment
initializes it atomically in `__constructor`; deployment does not itself prove
the chosen owner's consent. The owner must authenticate every
administrative change using `owner.require_auth()`.

| Operation | Authority and effect |
| --- | --- |
| `open_session(policy)` | Owner only; replaces the active session with a new, never-reused numeric ID. |
| `revoke_session(id)` | Owner only; revokes the current session and retains its spent counter. |
| `shutdown()` | Owner only; permanently disables session authorization and new sessions. |
| `recover(token, amount)` | Owner only; transfers a positive amount back to the immutable owner, including after shutdown. No destination parameter. |
| `session()`, `owner()`, `halted()` | Public state inspection. |

There is one active session, no upgrade function, no owner replacement, no
arbitrary execution function and no session-controlled administration. The
owner can intentionally grant a fresh budget by opening a new session; the
budget is a **session budget**, not a lifetime account cap. A fresh session
invalidates the previous one even when the public key is reused.

## Session policy

`SessionPolicy` contains `public_key` (Ed25519), `token`, `recipient`,
`per_call_limit`, `total_limit`, and `expires_ledger`.

- Amounts are positive signed 128-bit integers in the token's smallest units.
  No floating-point amounts or implicit decimals are used.
- The session lasts at most 17,280 ledgers. Expiry is exclusive: at
  `expires_ledger` authorization already fails. Ledger count is not a wall-clock
  guarantee.
- Each authorized context must be **exactly** the approved token's
  `transfer(account_address, approved_recipient, positive_amount)` with exactly
  three correctly typed arguments.
- Every context is checked. Empty or more than 16 contexts, contract creation,
  other methods, other token addresses, other senders and other recipients are
  rejected. `approve`, `transfer_from`, owner recovery and arbitrary agent calls
  are not authorized by the session.
- Each amount must fit the per-call limit. All contexts are summed with checked
  arithmetic and charged against the persistent session total. Multiple
  authorization checks share the same counter. Overflow is rejected.
- All contexts are checked before saving the reservation. Soroban rolls the
  reservation back when the containing transaction fails. An unused authorized
  sub-invocation may still consume reserved budget; `spent` is conservative
  authorized spend, not an accounting receipt for settled payments.

Only a **trusted token implementation**, preferably the Stellar Asset Contract,
should be approved. A malicious or upgradeable token may misrepresent the
meaning of its `transfer` call or its authorization arguments. Matching an
address and method is not a proof of arbitrary contract semantics.

## Signatures and transaction submission

The SDK's `CustomAccountInterface::__check_auth` receives Soroban's 32-byte
signature payload and the contexts the host is authorizing. A signature is:

```text
SessionSignature { session_id: u64, signature: BytesN<64> }
```

Sign the following exact byte concatenation using Ed25519:

```text
UTF8("AgentVeritas/session/v1") || 0x00 || uint64_be(session_id) || host_payload_32
```

The host payload already binds network, nonce, expiration and authorized
invocation tree. The mandatory `from == this account` argument binds this
account within that signed tree. The additional domain and session ID prevent
relabeling an old signature as a new session when the owner reuses a key. Never
sign a caller-supplied payload without independently deriving and inspecting
its invocation tree. The relayer supplies the transaction envelope and fees;
this contract supplies no relayer, UI signer or fee-sponsorship service.

Soroban itself verifies authorization-entry expiration and consumes nonces.
Direct `try_invoke_contract_check_auth` unit tests do not exercise that host
nonce layer, so the suite additionally uses signed authorization entries to
execute real SAC transfers and check replay rejection.

## Storage and shutdown

Owner, last session ID, halt flag and active session live together in instance
storage. The contract never initializes absent state on a read, never deletes
the ID counter and never uses expiring temporary storage for its budget.
Access extends instance TTL (threshold 17,280, target 518,400 ledgers), beyond
the maximum session duration. Archived instance state must be restored by the
normal Stellar archival mechanism; a missing state record fails closed.
Storage maintenance and contract-code restoration are operational requirements,
not an authorization bypass or automatic service provided by this package.

Shutdown is irreversible. Owner-authenticated recovery to the owner remains
available. Loss of the owner credential, an owner contract that refuses auth,
token issuer freezes, missing balances and token failures can still prevent
recovery. The account does not control network availability or issuer powers.

## Reproduce verification

From the repository root:

```bash
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo test -p agent-veritas-account
cargo fmt -p agent-veritas-account -- --check
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo clippy -p agent-veritas-account --all-targets -- -D warnings
CARGO_BUILD_JOBS=1 cargo build -p agent-veritas-account --target wasm32v1-none --release
```

The tests exercise real Ed25519 checks, exact scope, malformed arguments,
creation attempts, cumulative multi-context and multi-call spend, integer
overflow, expiry, revocation, session/key reuse, owner-only administration,
recovery after shutdown, TTL, absent state, actual SAC settlement, nonce replay,
tampered authorization trees, wrong network/account, auth-entry expiry,
pre-signed entries after policy revocation, and rollback after insufficient
balance. These tests are evidence for these
specific properties, not a comprehensive security audit.

## Official API references

- [Custom accounts and authorization](https://developers.stellar.org/docs/build/guides/auth/contract-authorization)
- [Complex account example](https://developers.stellar.org/docs/build/smart-contracts/example-contracts/complex-account)
- [Authorization fundamentals and host nonces](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization)
- [Storage types and archival behavior](https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage)

The implementation uses the repository's pinned `soroban-sdk = 25.3.0` APIs.
It is a project-specific account policy, not an implementation of a new SEP.
Comparable spending-policy accounts can be built on other networks; the
Stellar advantage here is integration with Soroban's native authorization
contexts, atomic execution, SAC balances and separately signed auth entries.
