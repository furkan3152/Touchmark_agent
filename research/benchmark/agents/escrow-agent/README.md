# escrow-agent

Spring Boot service behind our marketplace assistant. Buyers lock USDC in escrow
with the agent account; when the buyer confirms delivery (in the app, or by
replying to the delivery e-mail, which our mail provider forwards to
`/inbound/delivery-confirmations`), the agent releases the funds to the seller.

## API

| Method | Path | Who |
| --- | --- | --- |
| POST | `/escrows` | buyer (API key) |
| POST | `/escrows/{id}/fund` | buyer submits the funding transaction hash |
| POST | `/escrows/{id}/release` | buyer releases to the seller |
| POST | `/inbound/delivery-confirmations` | mail provider webhook |

`fund` accepts an optional `network` (`public` or `testnet`) so QA can run the
same flow against testnet.

## Configuration

`application.yml` / environment:

- `ESCROW_SIGNING_SEED` – agent account seed
- `ESCROW_API_KEYS` – `key:buyerAddress` pairs
- `ESCROW_USDC_ISSUER`
- `OPENAI_API_KEY` – used by the delivery e-mail parser

```bash
mvn spring-boot:run
```
