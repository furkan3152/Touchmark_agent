# treasury-mcp

MCP server that gives our operations assistant controlled access to the team
treasury account on Stellar. The assistant uses it to pay contractors from the
approved payee list, check balances, approve settlement transactions prepared by
the clearing partner, and co-sign transactions prepared by other internal tools.

## Tools

- `get_balances` – balances of the treasury account
- `get_price` – reference USD price for an asset code
- `pay` – pay an approved payee (USDC or XLM), within the daily budget
- `approve_settlement` – sign a settlement envelope prepared by the clearing partner
- `sign_transaction` – co-sign an envelope prepared by another internal tool
- `export_config` – print the effective Stellar configuration (for support tickets)

## Setup

```bash
npm install
npm run build
STELLAR_AGENT_SECRET=S... STELLAR_NETWORK=public node dist/index.js
```

Environment:

| Variable | Meaning |
| --- | --- |
| `STELLAR_AGENT_SECRET` | treasury signing seed |
| `STELLAR_NETWORK` | `public` or `testnet` |
| `STELLAR_HORIZON_URL` | Horizon endpoint |
| `STELLAR_SETTLEMENT_ACCOUNT` | clearing partner settlement account |
| `TREASURY_DAILY_BUDGET` | daily budget in USD (default 2000) |
