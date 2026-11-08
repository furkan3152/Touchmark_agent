# Treasury agent (safe demo)

An MCP server that lets an AI assistant pay two listed suppliers on Stellar testnet.

- `send_payment(supplier, amount, invoice_id)`: pays `hosting` or `design` only, at most 500 XLM per
  payment and 1000 XLM in any 24 hours. The recipient address comes from a fixed table; the model never
  supplies an address. Each payment must match an invoice on `invoices.example.org` (same supplier, same
  amount), and an invoice is paid at most once.
- `fetch_invoice(id)`: reads an invoice's supplier and amount; only those parsed fields reach the model,
  never the invoice host's free text.
- A submission whose outcome is unknown (a timeout) is never sent again until the account's sequence
  number shows it landed, or its time bounds have passed by the ledger's clock with the sequence unused.
  A definitive rejection releases it at once.

The agent key is read from `AGENT_SECRET_KEY` and is never returned to the model. Every payment
result is checked (`successful`) before it is reported. This folder is a demonstration fixture for
Touchmark; it is not a production treasury.
