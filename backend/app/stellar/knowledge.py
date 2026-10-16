"""Stellar review knowledge pack.

Concrete, checkable failure modes for agents that hold Stellar authority. The deep
reviewer reads these through its `stellar_reference` tool; each item names what to
look for in code and why it matters on Stellar specifically.
"""

from __future__ import annotations

TOPICS: dict[str, str] = {
    "payments": """Payments and path payments
- Destination must come from a fixed allowlist or an approved record, never directly from model or request text.
- Amounts need a fail-closed upper bound before the transaction is built; Decimal, not float, for asset amounts (7 decimal places).
- Path payments: strict-send must set a meaningful dest_min, strict-receive a meaningful send_max. A dest_min of "0.0000001" or a send_max equal to the balance lets the path drain value through a manipulated order book.
- create_account and claimable balances move funds too; treat them like payments.
- Asset identity is code + issuer. Matching only the asset code ("USDC") accepts look-alike assets from any issuer.""",
    "memos_and_muxed": """Memos and muxed accounts
- Exchanges and custodians require a memo (SEP-29 `config.memo_required` on the destination account). A payment without the memo is credited to nobody; agents paying exchanges must check SEP-29.
- Memos and muxed IDs are attacker-writable data. Text read from incoming transaction memos is untrusted input and is a prompt-injection channel when given to a model.
- M... muxed addresses share the underlying G account; an allowlist on G addresses must decide explicitly whether muxed sub-accounts are allowed.""",
    "multisig": """Signers and thresholds
- Account authority is public: signers, weights and low/medium/high thresholds are on-ledger. Payments need the medium threshold; set_options and account_merge need high.
- An agent hot key whose weight alone meets the medium threshold can move every asset. A key below the threshold needs a co-signer, which is an on-chain enforced control.
- set_options that adds a signer, changes weights or thresholds, or sets the master weight is an account takeover primitive when its parameters come from untrusted input.
- account_merge transfers the whole balance and deletes the account.""",
    "trustlines_and_assets": """Trustlines and asset authorization
- change_trust to an issuer chosen by untrusted input lets an attacker make the agent hold arbitrary assets; a maximum limit removes the holding cap.
- Issuer flags matter: auth_required, auth_revocable and auth_clawback_enabled mean the issuer can freeze or claw back what the agent holds.
- Verify an issuer through its home_domain stellar.toml (SEP-1 CURRENCIES), not by name.""",
    "soroban_auth": """Soroban authorization
- Contract functions that change state must call require_auth for the address whose state changes.
- Authorization entries carry a nonce and signature_expiration_ledger. Signing entries supplied by someone else, or with far-future expiry, lets them be replayed or used for a different invocation.
- Inspect the full invocation tree before signing an auth entry: a sub-invocation can transfer tokens to a different recipient than the top-level call suggests.
- Persistent storage needs TTL extension; archived entries make contract state disappear until restored.""",
    "web_auth": """SEP-10 / SEP-45 web authentication
- Verify the challenge transaction: server signing key from the anchor's stellar.toml, the home domain operation, timebounds, and that the only operations are manage_data.
- Never sign an arbitrary challenge with a funded account key; a challenge that contains payment operations is an attack.
- JWTs from SEP-10 must be bound to the account and expiry checked.""",
    "anchors": """SEP-6 / SEP-24 / SEP-31 anchors
- Deposit and withdrawal instructions (destination, memo, amount) come from the anchor's API and must be checked against the transaction record and the anchor's stellar.toml.
- A submitted transaction hash is not proof of settlement; poll the anchor status and ledger.
- Withdraw flows pay the anchor's account with a specific memo; a wrong memo loses funds.""",
    "transaction_lifecycle": """Transaction lifecycle
- Every transaction needs timebounds; without them a signed envelope stays valid forever.
- Sequence numbers serialize an account. Parallel agents sharing one source account collide; use channel accounts or a sequence lock.
- A submit timeout or 504 does not mean failure. Re-check by hash before re-signing, or the agent pays twice.
- Fee bumps let another account pay fees for an inner transaction; signing the inner transaction still authorizes its operations.
- Signing an envelope received from outside authorizes every operation in it. Decode and allowlist operations, source accounts, destinations and amounts first.
- Horizon facts that are easy to get wrong:
  - a synchronous POST /transactions returns the full transaction resource (id, successful, created_at, source_account, fee_charged, operation_count ...), the same shape as GET /transactions/{hash}; SDK typings for the submit response are narrower than the real body;
  - GET /transactions/{hash} and /transactions/{hash}/operations also return FAILED transactions (successful=false), so payment verification must check `successful`;
  - js-stellar-sdk and py-stellar-sdk `submitTransaction` / `submit_transaction` run the SEP-29 memo-required check by default unless explicitly skipped.""",
    "key_management": """Key management
- Secret seeds (S...) must never appear in source, logs, model prompts, tool results or error messages.
- Keys should live in an external signer, KMS or a separate process the model cannot read.
- A model that can see a key can be induced to reveal it through prompt injection.
- Scope the agent key: low-weight signer, per-agent account, spending policy contract (Soroban custom account) with recipient and budget limits.""",
}

CHECKLIST = "\n".join(f"- {name}: {text.splitlines()[0]}" for name, text in TOPICS.items())


def reference(topic: str) -> str:
    return TOPICS.get(topic, "Unknown topic. Available: " + ", ".join(sorted(TOPICS)))
