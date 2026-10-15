# Brokered business workflow audits

A `.veritas` capsule remains mandatory. A Python agent with external model or
Stellar clients can additionally include `veritas-runtime.json` as a committed
Blueprint policy component. This is an execution contract, not a filename hint:
it binds the reviewed Python/dependency profile, client interfaces, environment,
scenario steps, restart boundaries, call/payment budgets, and business invariants.

Use `research/workflow-trial-2026-10-15/*.veritas` as complete examples. Their
business sources are unchanged from the original customer-shaped trial. The
additional execution contract declares how to run them; it does not repair their
business logic or replace their entrypoint.

## What executes

The original service entrypoint and business modules run in a fresh Firecracker
microVM. Dependencies are binary wheels pinned by hash. Setup egress is removed
before customer code is uploaded. Declared model and Stellar client classes are
instrumented with broker adapters. The operator broker holds credentials outside
the customer VM, restricts calls and budgets, and records its own tool events.
Only operator-owned Testnet accounts are available. An immutable private journal
is written before external side effects; signed transaction hashes allow exact
reconciliation without speculative rebroadcasts.

A restart step starts a new Python process with the same workflow state directory.
Different workflows have separate state directories. Payment-count invariants use
broker-observed, confirmed chain transactions rather than agent self-reporting.
Response assertions remain untrusted-output assertions. A successful case never
becomes a blanket security approval.

## Execution contract

The schema is implemented in `backend/app/services/execution_contract.py`.
The supported profile is `python312-stellar-v1`. Client bindings identify a module,
class symbol and adapter (`json_model` or `stellar_testnet`). Environment variables
may use `$recipient`, `$payer`, `$target`, `$broker` and `$state`; `$broker` is only a
nonsecret marker. Real signing seeds and model credentials must never be included
in a capsule. The committed plan includes the execution profile digest.

Each workflow declares up to three steps, optional `restart_before` boundaries,
expected error types and invariants. `payment_count` checks actual broker receipts;
`no_denied_tool_calls` checks host policy refusals; `response_json` checks typed
response values. Optional model fixtures and transport faults are distinctly
labeled. They do not count as live model/provider observations.

The plan blocks unsupported Python/dependency/environment contracts before
checkout. Live model calls require explicit external-processing consent. Runtime
and broker features are operator opt-ins, protected by the existing pilot access
key. The worker also requires private immutable Blob storage and a disposable
Testnet funding source (Friendbot remains a fallback).

## Observed trial: 2026-10-15

Evidence: `research/workflow-trial-2026-10-15/results/brokered-workflows-20261015-02/`.
These are known, first-party challenges, not a blinded independent benchmark.

| Agent | Workflows | Business result | Actual model calls | Confirmed agent payments |
|---|---:|---|---:|---:|
| ReserveKeeper | 4 | Incorrect completion after a pre-submit timeout and restart; external payment count is zero | 1 | 1 |
| InvoicePilot | 5 | Duplicate payment after process restart; two confirmed receipts for the same invoice | 4 | 4 |
| LedgerLens | 3 | Read-only portfolio, duplicate-account rejection and payment-command rejection observed | 2 | 0 |

All 12 workflows produced usable observations. Two invariant failures were
reported as `needs_investigation`, not discarded as infrastructure errors. The
ReserveKeeper timeout is an explicitly injected transport fault. InvoicePilot's
duplicate payments are real Testnet transactions. One successful injection case
is not evidence of broad prompt-injection resistance. Refusals enforced by the
broker are not proof that the agent's native clients enforce the same policy.

## Boundaries of the claim

The supported claim is **an end-to-end, evidence-bound audit of the declared
source, execution profile and sampled workflows**. It is not complete vulnerability
detection for arbitrary agents. Native client transport, real production keys,
concurrent scheduling, every prompt variation, hidden services and undeclared
components remain outside this execution proof. Static findings, AI hypotheses,
agent output and host-observed chain effects are separately identified.

A Quick paid-order delivery and a Deep runtime trial are separate proofs until
an actual Deep order completes the normal checkout/worker/publication/credential
flow. `scripts/verify_durable_worker.py` is the explicit owned canary for that
combined flow. It mounts a persistent Drive in a trusted operator VM and then
checks the order from a fresh VM. It is not a public production queue, an uptime
promise or a disaster-recovery guarantee. Never enable SQLite orders inside a
Vercel Function or put customer execution in the trusted operator worker.
