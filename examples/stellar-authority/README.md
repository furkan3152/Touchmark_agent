# Inspect a proposed authorization tree

These are unsigned synthetic XDR fixtures with fabricated public addresses and ledger numbers. No key or usable transaction is provided. They exercise a declared policy comparison, not network state or signature validation.

```bash
.venv/bin/python scripts/inspect_stellar_auth.py examples/stellar-authority/matching-transfer.json
.venv/bin/python scripts/inspect_stellar_auth.py examples/stellar-authority/nested-recipient-change.json
```

The first matches its declared transfer policy. The second rejects a substituted recipient in a child invocation even though the root transfer matches. Exit codes: 0 matches declared policy, 1 differs/unsupported, 2 invalid request. None grants authorization.

The same request can be posted to `POST /api/v1/studio/stellar/inspect-auth`. The response includes `report`, canonical `report_json` and `report_sha256`. API inspection is public, bounded and read-only. It does not contact RPC, use a model, persist source, sign or submit a transaction.

Use a single `SorobanAuthorizationEntry`, not an entire transaction envelope. Amounts are decimal strings of atomic token units, never floating point. Policies and ledger numbers are caller supplied. Signature, network, current ledger and replay status remain explicitly unverified. Contract creation, source-account/v2/delegate credentials and non-transfer calls are unsupported and rejected. Authorization trees omit calls that do not require the inspected address's authorization, so they are not complete execution traces.
