# Deployments and on-chain evidence

All deployments are on Stellar **testnet**. Manifests contain public addresses, WASM
hashes and transaction hashes only; no keys.

| Manifest | What it proves |
|---|---|
| [`demo-testnet.json`](demo-testnet.json) | The demo's AgentRegistry and AuditCredential. Every credential issued from the demo links its transactions. `owner_flow_example` records a credential issued to an owner who signed the registration in their own wallet. |
| [`testnet-audit-delivery-2026-10-15.json`](testnet-audit-delivery-2026-10-15.json) | Registry-bound escrow, report delivery and credential: 20 transactions, read-backs and rejected mismatches. |
| [`agent-account-testnet-2026-10-15.json`](agent-account-testnet-2026-10-15.json) | AgentAccount session limits: an authorized transfer; a forbidden recipient, an over-budget transfer and a revoked key all rejected. |
| [`stellar-testnet.json`](stellar-testnet.json) | The first registry and escrow deployment (2026-08-30). |

The remaining `*-2026-10-15.json` files record earlier pilots (official orders, runtime
sampling, private report storage). They are kept for the record, and the code reads some
of them.

To check a manifest, open its contract and transaction hashes on a testnet explorer, or
re-read the ledger:

```bash
python -m backend.deploy verify-testnet
```
