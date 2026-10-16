# Treasury agent (safe demo)

An MCP server that lets an AI assistant pay two listed suppliers on Stellar testnet.

- `send_payment(supplier, amount)`: pays `hosting` or `design` only, at most 500 XLM per payment.
  The recipient address comes from a fixed table; the model never supplies an address.
- `fetch_invoice(id)`: reads an invoice by id from `invoices.example.org`; the model never supplies a URL.

The agent key is read from `AGENT_SECRET_KEY` and is never returned to the model. Every payment
result is checked (`successful`) before it is reported. This folder is a demonstration fixture for
AgentVeritas; it is not a production treasury.
