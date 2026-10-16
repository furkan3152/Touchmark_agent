# Deployment and operations

## Public Studio on Vercel

`app.py` exports the FastAPI application with a strict public-route allowlist. It sets `STATELESS_STUDIO=true`, disables the patrol lifecycle and denies operator endpoints. Temporary framework bookkeeping uses `/tmp`; it is not durable storage. No source bundle or report is persisted by the Studio.

Connect this repository and deploy the reviewed feature branch as a **preview**. `vercel.json` selects FastAPI and a 180-second request limit, subject to the account's platform limits. `requirements.txt` includes the backend requirements. No signing key is needed for the stateless Studio. Automatic order funding and settlement stay disabled there.

AI review requires explicit source-sharing consent and private pilot authorization. Keep it disabled until there is a provider budget and deployment-level rate limiting. Process-local admission control is per instance, **not a distributed cost cap**. For the verified Gateway path, set:

```text
LLM_PROVIDER=vercel
LLM_MODEL=openai/gpt-4.1-mini
ENABLE_PUBLIC_AI_REVIEW=true
```

Vercel supplies its own OIDC identity. Outside Vercel, securely configure a Gateway API key. See [AI configuration](AI_CONFIGURATION.md) for exact request limits, private access keys and live evidence. Source review sends one bounded prompt for its optional AI second opinion; runtime AI planning is a separate call. Static review can still return when AI is unavailable, but paid fulfillment refuses to settle when a requested AI review did not complete. Redaction is best effort: do not submit production credentials.

## Durable operator service

Use the supplied Dockerfile and Compose configuration on a host with a persistent volume, or a managed container service with a disk mounted at `/app/data`. Run **one worker and one replica**: the legacy operator store is a process-cached JSON store, and increasing replicas would introduce lost updates. Multi-replica operation requires a transactional shared-store migration before launch.

```sh
cp .env.example .env
# Configure ADMIN_API_KEY in a secret manager or the local ignored .env.
# Keep ALLOW_MAINNET=false and ENABLE_AUDIT_ESCROW=false during initial setup.
docker compose up --build -d
```

The service binds to loopback in Compose; place a TLS reverse proxy with request-size, concurrency and rate limits in front of it. The image is non-root, uses a read-only root filesystem in Compose and writes only to its named volume and bounded temporary directory. Back up and restore-test the data volume. Do not publish `.env`, keys, job state or private source.

Persistent operator reports are access-controlled but not encrypted at rest by this application. Use host encryption and a retention policy. The shared operator bearer token is an administrative pilot boundary, not customer tenant isolation. Do not expose it to customer browsers or sell multi-tenant accounts without adding per-tenant authorization.

For the new official Testnet order service, follow [OFFICIAL_FULFILLMENT.md](OFFICIAL_FULFILLMENT.md). Compose pins its SQLite database to the named `/app/data` volume. Explicitly enable `ENABLE_OFFICIAL_ORDERS`, `OFFICIAL_ORDERS_STORAGE_DURABLE` and `ENABLE_TESTNET_ORDER_SETTLEMENT`, keep `OFFICIAL_ORDERS_LOCAL_PILOT=false`, and configure the pinned service identities plus private Blob storage in the host's secret manager. These switches are assertions of deployment responsibility; they do not provision backups or verify the host's durability. Leave them disabled until the volume and recovery procedure have been checked.

## New contract deployment

The historical `deployments/stellar-testnet.json` describes an older release. Do not overwrite its transaction evidence or use it to claim the new contracts are deployed.

1. Build and test with Rust 1.91.0 and pinned Soroban SDK 25.3.0.
2. Deploy registry v0.2 with constructor argument `admin` using an external signer.
3. Deploy escrow with constructor arguments `admin`, `token`, `fee_to`, `fee_bps`, `registry`, in that order. Supply the new registry address and an explicitly verified SAC contract. Native XLM is not USDC. The current verified deployment is recorded in `deployments/testnet-audit-delivery-2026-10-15.json`.
4. Deploy `AuditCredential` with constructor argument `registry` pointing at the new registry.
5. Register an agent; authorize a validator; create a validation request; submit the report hash/URI; issue the credential using that request ID and an expiry within 90 days.
6. Read back the credential and `is_current`. Verify the exact WASM hash and successful transaction status.
7. Change the agent version and confirm `is_current=false`. Exercise owner and issuer revocation and exact expiry. Verify unauthorized issuance fails.
8. Verify a funded escrow completion, rejected evaluator and deadline refund before enabling real checkout.
9. Record new IDs, hashes, network, transaction IDs, events and readbacks in a separate release manifest.

**Breaking ABI/storage change:** validation records now include version and source commitments. This is a fresh-deployment release; do not point a new credential contract at the old registry or assume old records can be decoded as v0.2. Existing records need an explicit migration design. `init` remains a compatibility symbol but all new deployments initialize atomically; calling it again fails.

```sh
cargo test --workspace --locked
cargo build --workspace --target wasm32v1-none --release --locked
python -m backend.deploy hashes
```

Contract expiry uses ledger timestamps; TTL uses ledger counts. Expiry and state archival are different concepts. Reads renew storage TTL, but inactive records still require a maintenance/restoration strategy. `is_current` is not a safety approval: it verifies that a recorded assessment is current according to contract state.

## Runtime policy gateway

`backend.app.services.runtime_policy.PolicyGateway` is an opt-in SDK. The trusted host loads an approved policy, obtains an HMAC approval for the exact policy/action digests, calls `authorize`, and only invokes the real tool after an allowed result. Keep the approval key, policy store and database outside the agent's sandbox. Never accept an agent-supplied policy as authoritative.

The SQLite reservation transaction prevents concurrent requests from overspending or replaying a nonce. Accounting is agent-wide and intentionally does not reset when code or policy version changes. Failed tool calls still consume their reservation. This conservative model avoids automatic refunds creating a retry/double-spend gap; reconciliation needs trusted operator handling.

The SDK is **not a wallet, signer, transparent network proxy or universal sandbox**. An agent with direct access to credentials can bypass an SDK wrapper. Integration must route all consequential tool calls through the gateway and isolate the actual credentials. A kill switch stops subsequent authorizations; it cannot recall an action that already passed authorization or settled on-chain. Currency/asset policy changes need an explicit accounting migration because reservations are raw integer units, not exchange-rate normalized amounts.

## Production release gates

- Real provider test using a securely configured API key and documented retention settings.
- Browser visual and accessibility QA at desktop and mobile sizes.
- Durable store, backup restoration, customer identity/tenant isolation and distributed quotas.
- Fresh testnet deployment with exact ledger/state evidence and wallet-signing flow.
- Issued USDC asset verification, funded delivery, evaluator and refund tests.
- Independent review of contracts, authorization boundaries and runtime adapters before mainnet funds.

Do not describe these gates as complete based on local unit tests.
