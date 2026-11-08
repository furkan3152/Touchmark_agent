# Treasury agent (safe demo)

An MCP server that lets an AI assistant pay two listed suppliers on Stellar testnet.

- `send_payment(supplier, amount, invoice_id)`: pays `hosting` or `design` only, at most 500 XLM per
  payment and 1000 XLM in any 24 hours. The recipient address comes from a fixed table; the model never
  supplies an address. Each payment pays one invoice that exists on the invoice host, and an invoice is
  paid at most once.
- A submission whose outcome is unknown (a timeout) is never sent again until the ledger shows it landed,
  or its time bounds have passed so it can never land; only then is its budget released.
- `fetch_invoice(id)`: reads an invoice by id from `invoices.example.org`; the model never supplies a URL.

The agent key is read from `AGENT_SECRET_KEY` and is never returned to the model. Every payment
result is checked (`successful`) before it is reported. This folder is a demonstration fixture for
Touchmark; it is not a production treasury.
