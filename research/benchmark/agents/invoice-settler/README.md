# invoice-settler

Small FastAPI service that settles approved vendor invoices in USDC on Stellar and
handles customer refunds and incoming deposit verification for our billing team.

The accounting system pushes approved invoices to `/v1/webhooks/accounting`. Finance
operators (or the billing assistant, which calls the same API with an operator key)
then trigger settlement with `POST /v1/invoices/{id}/settle`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/webhooks/accounting` | Receive approved invoices (HMAC signed) |
| POST | `/v1/invoices/{id}/settle` | Pay an approved invoice to the vendor |
| POST | `/v1/refunds` | Refund a customer |
| POST | `/v1/deposits/verify` | Credit a customer balance from an incoming payment |
| GET  | `/healthz` | Liveness |

## Configuration

All settings are read from the environment (see `app/config.py`):

- `SETTLER_SIGNING_SECRET` – secret seed of the settlement account
- `SETTLER_API_KEYS` – comma separated operator API keys
- `SETTLER_WEBHOOK_SECRET` – shared HMAC key with the accounting system
- `SETTLER_HORIZON_URL`, `SETTLER_NETWORK_PASSPHRASE`
- `SETTLER_USDC_ISSUER`

## Running

```bash
pip install -e .
uvicorn app.main:app --port 8080
```
