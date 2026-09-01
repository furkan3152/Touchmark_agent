# Stellar deployments

The active release is in the [stellar-testnet.json](stellar-testnet.json) file. Two contracts were deployed and initialized on the Stellar Testnet on August 30, 2026, using the external Stellar CLI signer:

- AgentRegistry: `CBBBUECSLXGXVXYMRYK3BCTL3YYBRWDZGW3RNCH5CWKY6KU6UGE576KT`
- AuditEscrow: `CD6Q7DJMM3XR7NIBD7XCGQ34GK6UOA5BBUL7BGP5EMYDZ2ZADV37KH7W`
- Escrow test asset: native XLM SAC `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`

The manifest carries the following proofs together:

1. Local release WASM SHA-256 and chain-read WASM SHA-256 match.
2. Upload, deploy, init, and role transaction hash/ledger results.
3. Separate admin/requester, validator/provider, and reviewer/evaluator public accounts.
4. `registered → requested → responded → reviewed` event/state readback.
5. `create → fund → submit → complete` with an actual 1 XLM; 0.15 XLM fee + 0.85 XLM payout and zero remaining escrow balance.
6. Mainnet, USDC, SEP-1 publication, and professional audit limits.

Read-only re-verification:

```bash
.venv/bin/python -m backend.deploy hashes
.venv/bin/python -m backend.deploy verify-testnet
.venv/bin/python -m backend.cli chain
```

`configured=true` alone is not deployed. In addition to manifest ID/hash matching, the runtime does not produce `onchain_verified=true` without seeing `SUCCESS` for the deploy transaction in the live RPC. The testnet signer files are out-of-git under `data/stellar-cli/`; the manifest contains no seeds or secrets.
