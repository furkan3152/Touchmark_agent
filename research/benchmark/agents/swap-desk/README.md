# swap-desk

Ktor service behind the in-app trading assistant. Customer funds sit in one
omnibus Stellar account; each customer has an internal balance per asset. The
assistant asks the service for swaps (executed as `PathPaymentStrictSend` from the
omnibus account to itself) and for withdrawals to the customer's own wallet.
Operations staff can rebalance the omnibus account against the treasury.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| GET | `/users/{userId}/balances` | customer JWT |
| POST | `/swap` | customer JWT |
| POST | `/users/{userId}/withdraw` | customer JWT |
| POST | `/admin/rebalance` | staff JWT with `ops` role |

Swap request body:

```json
{"sendCode": "USDC", "sendIssuer": "GA5Z...", "sendAmount": "100",
 "destCode": "XLM", "destIssuer": null, "expectedOut": "812.4", "slippageBps": 50}
```

`expectedOut` is the quote the assistant showed the customer.

## Configuration

- `OMNIBUS_SEED`, `TREASURY_SEED`
- `JWT_SECRET`, `JWT_ISSUER`
- `HORIZON_URL` (default public Horizon)

```bash
./gradlew run
```
