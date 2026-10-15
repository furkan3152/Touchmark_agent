# Testnet wallet checkout

**2026-10-15 update:** funding now requires a saved private order, SEP-53 requester proof and a running official fulfillment service. Automatic delivery, private report storage, access recovery and refund preparation are described in [OFFICIAL_FULFILLMENT.md](OFFICIAL_FULFILLMENT.md). The Vercel Studio blocks funding until persistent fulfillment is available. The older four-step description below remains the wallet transaction sequence, not the complete order lifecycle.

The checkout prepares real unsigned Soroban transactions against the verified delivery deployment in `deployments/testnet-audit-delivery-2026-10-15.json`. It never loads a seed, signs a transaction, submits a transaction, or charges Mainnet funds. The wallet signs and submits only after explicit user action. Testnet XLM has no monetary value.

## Configuration

Set `STELLAR_NETWORK=testnet`. Set **two different secrets** in the backend environment:

- `RUNTIME_API_KEY`: at least 32 characters; the private Studio API access token used in `Authorization: Bearer …`.
- `CHECKOUT_QUOTE_SIGNING_KEY`: a separate, random, server-only value of at least 32 characters. Never expose it to the browser, prefix it with `NEXT_PUBLIC_`, or reuse the API access token. Quote signing needs a secret that clients cannot possess.

A key rotation invalidates outstanding quotes. No `STELLAR_SECRET_KEY`, signing seed, customer wallet secret, caller-provided RPC URL, or arbitrary contract address is accepted. The service uses the fixed public Testnet RPC origin, fixed contract IDs and the native Testnet XLM asset contract. Local/API and Vercel environments need the same non-public configuration independently.

## API sequence

1. Generate and acknowledge the current official engagement plan through the Studio plan endpoint. Preserve the exact engagement and `plan_sha256`.
2. `POST /api/v1/studio/checkout` with `{ "engagement": <acknowledged EngagementRequest>, "requester": "G…" }`. Use the actual customer's public Testnet G-address. The provider and evaluator addresses cannot be requester wallets.
3. Inspect the returned quote: network, source/plan hashes, roles, contract addresses, amount, fee split, ledger deadline and expiry. It is a quote, not a wallet authorization or payment receipt.
4. `POST /api/v1/studio/checkout/prepare` with `{ "quote": <quote>, "quote_signature": "…", "step": "register" }`, using the returned `next_step`. Both endpoints require the private API access token.
5. Inspect and sign the returned `unsigned_xdr` in a Testnet wallet. Verify `signer`, the Testnet passphrase, operation, contract, amounts, and the additional network fee. Submit from the wallet/client only after a separate explicit action.
6. Refresh checkout using step 2 after successful ledger inclusion. The IDs are deterministic for the same wallet, exact source/plan and offer, so refresh resumes the existing job. Prepare each newly returned `next_step`.

The four transaction steps are:

| Step | Contract call | Customer authorization |
| --- | --- | --- |
| `register` | Registry `reg_agent` | Version 1 with plan and source commitments |
| `request` | Registry `req_valid` | Assigned official provider and same agent snapshot |
| `create` | Escrow `create` | Same registry request ID, amount, provider, evaluator and deadline |
| `fund` | Escrow `fund` | Transfer exact native Testnet XLM amount from requester to escrow |

The amount is fixed server-side: Preview `1000000` stroops (0.1 XLM), Assurance `10000000` (1 XLM), Deep `30000000` (3 XLM). The protocol fee is 1500 bps of the escrow amount on successful settlement, already included in that amount. Stellar transaction fees are additional. The transaction preparation rejects a simulated fee above 2 XLM. There is no USD billing or production payment processor.

Quotes expire after 10 minutes. Each prepared transaction has a maximum two-minute time bound, capped by quote expiry, and uses the live account sequence. Reprepare if the wallet has submitted another transaction or the XDR expires. Quote refresh preserves an existing job's deadline. A new job has a deadline 17,280 ledgers after the observed live ledger, approximately one day; elapsed time is not guaranteed.

## Response meanings

Checkout returns `quote`, `quote_signature`, `quote_sha256`, `status`, `next_step`, `steps`, `chain`, `payment_confirmed`, and `limitations`. Preparation adds `step`, `unsigned_xdr`, `transaction_hash`, `network_passphrase`, `signer`, `fee_atomic`, `expires_at`, and `simulation`.

`payment_confirmed=true` requires a live, correctly bound escrow in Funded, Submitted, Disputed, or Complete state. A Complete job is `status=settled`. A Refunded job is not currently paid. A simulation or returned transaction hash never sets this flag. A transaction hash identifies the prepared envelope; it does not establish submission or inclusion.

The backend rereads the Testnet passphrase, deployed WASM hashes, escrow registry/token/treasury/fee configuration, enabled validator, account sequence, agent snapshot, registry validation, escrow job and registry binding. Any mismatch fails closed. A missing or archived contract requires operator maintenance; this checkout does not prepare restoration transactions. Simulation uses `authMode=record`, which discovers authorization requirements without proving wallet authorization. Only source-account authorization is supported; the wallet must satisfy the source account's signing thresholds when submitting.

## Delivery and remaining boundaries

Funding **does not start an automatic operator queue**. The official provider must execute/review the acknowledged engagement, publish the canonical report, respond to the matching registry validation and submit its committed report hash. The official evaluator then completes settlement; credential issuance is a separate official transaction. The current provider and evaluator are distinct first-party keys under one operator, not independent reviewers.

Customers must retain the exact acknowledged source and plan for delivery. This stateless checkout publishes only hashes and the plan commitment URI, not customer source code. It does not provide durable source storage or an order queue. The same source/plan/wallet offer resumes a single request rather than creating duplicate purchases.

Expired Created jobs cannot be funded; funded jobs may have refund rights under the escrow contract after the deadline. The four-step UI does not yet prepare refund or dispute transactions. A production payment launch needs a durable delivery queue, authenticated customer ownership, refund/dispute UX, operator availability commitments, secrets management, contract release review and monitoring. None of those are implied by a Testnet simulation.

## Verification

`backend/tests/test_testnet_checkout.py` checks signed quote integrity, expiry, deterministic resume, separate API/quote keys, fixed amounts, exact transaction arguments, network boundaries, changed registry/job snapshots, refund status, simulation failures and response/fee bounds.

A read-only live canary on 2026-10-15 checked the pinned deployment and prepared a successful `reg_agent` simulation at Testnet ledger **5209334**. The unsigned transaction fee was **382168 stroops**. No canary transaction was signed or submitted; it did not fund a customer job. The evidence is recorded in `deployments/checkout-preparation-2026-10-15.json`. The already published delivery manifest separately contains a real official fixture lifecycle through settlement and credential issuance.

Official references, checked 2026-10-15:

- [simulateTransaction](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction): trial invocation, authorization recording, fee/resource data and restoration preamble.
- [getLedgerEntries](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries): live ledger entries for account and contract state.
