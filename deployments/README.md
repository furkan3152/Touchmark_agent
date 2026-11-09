# Deployments and on-chain evidence

All deployments are on Stellar **testnet**. Manifests contain public addresses, WASM
hashes and transaction hashes only; no keys.

**Current:** the public demo uses [`demo-testnet.json`](demo-testnet.json) (registry `CBIZOE…`, credential
`CBBTOB…`, operator `GCRGIG…`, which is also the assay book account). The other manifests are earlier
deployments kept as evidence; a contract id that appears only in them is not what the demo uses today.

Both sets that are in use are listed, with what each is for, in the site's
[`stellar.toml`](https://usetouchmark.app/.well-known/stellar.toml) (SEP-1): the demo's contracts and the assay book
account, and the paid-order contracts from [`testnet-audit-delivery-2026-10-15.json`](testnet-audit-delivery-2026-10-15.json).

| Manifest | What it proves |
|---|---|
| [`demo-testnet.json`](demo-testnet.json) | The demo's AgentRegistry and AuditCredential. Every credential issued from the demo links its transactions. `owner_flow_example` records a credential issued to an owner who signed the registration in their own wallet. |
| [`testnet-audit-delivery-2026-10-15.json`](testnet-audit-delivery-2026-10-15.json) | Registry-bound escrow, report delivery and credential: 20 transactions, read-backs and rejected mismatches. |
| [`agent-account-testnet-2026-10-15.json`](agent-account-testnet-2026-10-15.json) | AgentAccount session limits: an authorized transfer; a forbidden recipient, an over-budget transfer and a revoked key all rejected. |
| [`agent-account-local-2026-10-15.json`](agent-account-local-2026-10-15.json) | A local rehearsal of the session account contract (`AgentSessionAccount`): test, lint and WASM build results only; not deployed (`deployed: false`). |
| [`stellar-testnet.json`](stellar-testnet.json) | The first registry and escrow deployment (2026-08-30). |
| [`reports/`](reports) | The report from the testnet audit delivery above, named by its SHA-256: JSON, HTML, credential metadata and SVG badge. |

The remaining `*-2026-10-15.json` files record earlier pilots (official orders, runtime
sampling, private report storage). They are kept for the record, and the code reads some
of them.

To check that the contracts on the ledger are built from this repository (ledger code hash,
manifest and local build all equal):

```bash
cargo build --workspace --target wasm32v1-none --release --locked
python scripts/verify_contracts.py
```

To check a manifest, open its contract and transaction hashes on a testnet explorer, or
re-read the ledger:

```bash
python -m backend.deploy verify-testnet
```
