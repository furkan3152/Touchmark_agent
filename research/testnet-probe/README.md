# Testnet execution probe (prototype)

A finding the audit reads from source is stronger when the same defect can be
*reproduced* against a running copy of the agent, with the outcome read from the
ledger rather than from the agent's own answer. This directory holds a working
prototype of that idea.

## What it does

1. The agent's repository is cloned into a disposable Vercel microVM
   (`vercel/sandbox`), built, and its MCP server started.
2. The sandbox's outbound network is restricted to **testnet only**
   (`horizon-testnet.stellar.org`, `friendbot.stellar.org`,
   `soroban-testnet.stellar.org`). Mainnet is unreachable, so no real value can
   move even if the agent's code is pinned to mainnet (it fails instead).
3. Fresh testnet accounts are created and funded from friendbot (free test XLM):
   an *agent* account and an *attacker* account.
4. The probe calls the agent's tools directly — no model in the loop, so the
   result is deterministic and repeatable — turning each failing fund/key ledger
   check into one concrete attempt:
   - V1/V4: call the payment tool with an over-limit amount to the attacker
     address, then read Horizon to see whether the payment actually landed.
   - A2: call account creation / config tools and scan the tool output for a
     secret seed (`S...`) returned to the caller.
5. The outcome is read from Horizon (the payment record, the transaction hash),
   not from the tool's reply. A finding becomes "reproduced on testnet" with the
   transaction hash as evidence.

## Result on syronlabs/stellar-mcp (commit 259ba77)

Both reproduced on testnet, agreeing with the source findings:
- `stellar_create_account` returns the secret seed to the caller (A2).
- `stellar_payment` sent 9000 XLM to an arbitrary address with no limit; ledger
  evidence: a real testnet payment transaction (V1).

## Safety rule (important)

Only defects whose exploit is **value movement or key exposure** are reproduced,
because those are safe to demonstrate on testnet with throwaway accounts. Defects
whose exploit is **code or command execution, file access, or SSRF** are reported
from source and are **never executed**, even against a harmless marker: triggering
a code-execution flaw is outside what an audit should do and adds risk for no gain.

A probe that does *not* reproduce a finding never clears it: the agent may need a
credential, a mainnet pin, or an input shape the probe did not try. "Not
reproduced" is recorded as such, not as "safe".

## Status

Prototype, driven by hand through the Vercel sandbox tools. Not wired into the
live audit. `probe-syron-example.mjs` is the exact probe used above. Next steps to
productionize: generate the probe from the audit's failing fund/key checks, run it
as an opt-in step after a consented audit, and attach the reproduced evidence to
the matching finding.
