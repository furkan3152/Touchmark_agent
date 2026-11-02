# Testnet execution probe (prototype)

A finding the audit reads from source is stronger when the same defect can be
*reproduced* against a running copy of the agent, with the outcome read from the
ledger rather than from the agent's own answer. This directory holds a working
prototype of that idea.

## What it does

1. The agent's repository is cloned into a disposable Vercel microVM
   (`vercel/sandbox`), built, and its MCP server started.
2. The sandbox's outbound network is limited to testnet hosts
   (`horizon-testnet.stellar.org`, `friendbot.stellar.org`,
   `soroban-testnet.stellar.org`) through the sandbox's network policy; the probe
   script does not set it. Mainnet is unreachable, so no real value can move even
   if the agent's code is pinned to mainnet (it fails instead).
3. Two fresh testnet accounts are created and funded from friendbot (free test
   XLM): an *agent* account and an *attacker* account.
4. The probe calls the agent's tools directly, with no model in the loop, so the
   result is deterministic and repeatable. Each failing fund or key ledger check
   becomes one concrete attempt:
   - V1/V4: call the payment tool with a large amount to the attacker address,
     then read Horizon to see whether the payment landed.
   - A2: call the account-creation tool and scan its output for a secret seed
     (`S...`) returned to the caller.
5. The outcome is read from Horizon (the payment record), not from the tool's
   reply. The probe prints what it found, with any secret seed redacted.

## Result on one open-source Stellar MCP server

Both findings from source were reproduced on testnet:
- The account-creation tool returns the new account's secret seed to the caller (A2).
- The payment tool accepts a secret key supplied by the caller and pays any amount
  to any destination, with no cap. The probe paid 9,000 test XLM from one fresh
  friendbot account to the other, and the payment was read back from Horizon (V1).

## Safety rule

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
live audit. [`probe-example.mjs`](probe-example.mjs) is the probe used above.

## Next steps (as of 2026-11)

Generate the probe from the audit's failing fund and key checks, run it as an
opt-in step after a consented audit, and attach the reproduced evidence to the
matching finding.
