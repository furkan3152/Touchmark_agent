# payout-relay

Go service that pays creator earnings in USDC on Stellar. The earnings pipeline
writes approved payouts into Postgres; an operator (or the scheduled job in our
ops agent) calls `POST /payouts/run` to pay every approved payout to the creator's
verified Stellar address. Each submitted payment writes a JSON receipt that support
can fetch by transaction hash.

## Routes

- `POST /payouts/run` – pay all approved payouts (operator token required)
- `GET /receipts/{hash}` – fetch a payment receipt
- `GET /healthz`

## Environment

| Variable | Meaning |
| --- | --- |
| `PAYOUT_SEED` | secret seed of the payout account |
| `OPERATOR_TOKEN` | bearer token for operator routes |
| `DATABASE_URL` | Postgres DSN |
| `RECEIPT_DIR` | directory for receipts (default `./receipts`) |
| `HORIZON_URL` | defaults to the public Horizon |

```bash
go build ./...
./payout-relay
```
