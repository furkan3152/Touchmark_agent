# Official Testnet fulfillment

The official operator can now accept a private order, reconcile funding after a browser disconnect, run the committed audit, store its canonical report privately, respond to the registry, settle escrow and issue the matching nontransferable audit credential. These identities belong to one operator; this is not independent validation or a guarantee of security.

## Deployment boundary

`backend.app.api:app` runs the persistent operator service and its supervised worker. SQLite records, lease claims, signed transaction intents and report checkpoints survive a process restart on the same disk. Enable this only on a persistent host with backups. This implementation is not a distributed queue and has not been deployed as a persistent hosted service.

`app:app` is the Vercel Studio. It remains stateless and cannot accept/fund automatic orders on its ephemeral disk. Its capability endpoint returns the reason and the UI blocks funding. Connecting Blob storage does not create a database or a worker. A hosted persistent service, or a separately verified database/queue implementation, is still needed for hosted automatic checkout.

## Customer flow

1. Import source or a `.veritas` capsule and acknowledge the exact audit plan.
2. Connect a Testnet G-account. Consent to private source retention, private report storage with a public hash/URI, and automatic official settlement.
3. Read the short-lived order challenge, then explicitly sign its SEP-53 message. It binds requester, network, source/plan, consents and nonce. It is not a payment signature or a SEP-10 session.
4. Save the private order receipt. Its access token authorizes status/report downloads and is stored only as a hash on the server. A new wallet-signed challenge can recover access and revoke the old token without resetting the paid job.
5. Review, sign and submit each wallet transaction separately. Funding preparation requires the matching saved order. Only exact live contract state queues computation.
6. Follow persisted status and download the report. The canonical report hash binds the registry response, escrow submission and credential. Delivery is claimed only after live `Complete` escrow and current owner/hash readback.

The wallet proof establishes possession of the G-address master signing key, not a multisig threshold or contract-account session. Funding still passes Stellar's transaction authorization. Contract account onboarding and production customer identity are not implemented.

## Failure and retry behavior

- Source, scope, image, module selection, AI provider/model and case commitments cannot silently change after payment.
- Missing dependencies/environment, absent runtime telemetry, or an unavailable requested AI review prevent fulfillment. Actually executed agent exceptions/timeouts are negative audit evidence.
- A worker must retain its current lease to checkpoint or reserve a transaction. Shared signer sequences are reserved across orders.
- The signed envelope and transaction hash are committed before broadcast. Unknown/pending outcomes are reconciled by the same hash. A send response alone is never completion.
- Reports and publication are checkpointed, so retrying settlement does not rerun a completed audit. An interruption before the report checkpoint can repeat compute; callbacks have at-least-once semantics, not exactly-once execution or billing.
- Expired unresolved transaction intents deliberately stop the signer lane until operator reconciliation. There is no speculative replacement transaction.
- The requester can prepare a refund for disputed escrow, or funded/submitted escrow after its ledger deadline. A separate wallet signature/submission is required. Refund reconciliation does not queue another audit. Completed payment is not refundable through this contract.

## Privacy and credentials

Full source stays in the private local order database. Reports may contain bounded source excerpts and observed agent outputs; they are stored in a **private** Vercel Blob store. Uploads use content-addressed paths, disallow overwrite and require authenticated exact-byte readback. The onchain URI contains no token. Knowing the hash/URI does not grant download access.

Keep `OFFICIAL_PROVIDER_SECRET`, `OFFICIAL_EVALUATOR_SECRET`, `BLOB_READ_WRITE_TOKEN` and `CHECKOUT_QUOTE_SIGNING_KEY` on the operator server. The client pilot key is separate and cannot forge a quote. All signing in this new service is restricted to the pinned Testnet provider/evaluator, contracts and native XLM SAC. Customer transactions remain externally signed. The older generic operator pipeline still only prepares external invocations.

Source retention/deletion policy, tenant accounts, encrypted backups, operational alerting, independent evaluator operation and a production incident/reconciliation process remain release work. A passing fixture pilot does not remove these requirements.

## Running locally

Install `requirements.txt`, configure the private settings from `.env.example`, then run:

```sh
.venv/bin/python -m uvicorn backend.app.api:app --host 127.0.0.1 --port 8000
```

Use `scripts/run_local_pilot.py` only when this development checkout already contains the ignored Testnet pilot identity and access files. It binds loopback and loads those files without printing their values. Never copy these Testnet identities to Mainnet.

The explicit one-off `scripts/verify_deployed_integrations.py --run-id ...` canary exercises the build environment's own OIDC identity with an owned fixture. It does not export that identity, disable deployment protection or establish browser/Freighter verification. Private claims prevent paid calls from repeating under the same run ID.
