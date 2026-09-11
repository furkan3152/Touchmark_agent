# AgentVeritas Stellar — Deep Agent Audit

Policy: `agentveritas.stellar.policy.2026-09-11.1`

## What makes the Deep tier different?

The Basic tier is a fast heuristic, fundamental attack scenario, tool permission, and dependency review. The Deep tier additionally evaluates the data paths in the agent implementation and the blast radius created jointly by the seven dimensions.

The Stellar-specific deep analysis looks for these paths:

- API/webhook/user input → `eval`, `exec`, shell or process execution;
- external input → Stellar transaction submit/sign, Soroban `invoke_contract`, host function, authorization entry or token transfer;
- Stellar secret seed/private key/API secret → log or outbound network call;
- signing/spending tool → absence of `require_auth`, allowlist, limits, and sequence/idempotency enforcement in the executable code.

Python paths use AST-based propagation with function-local state, reassignment and conservative branch joins. A visible source-to-sink path is `CONFIRMED` **static evidence**, backed by file:line context; this is not confirmation of exploitability. Comments do not create Python paths and unrelated `validate`/`require_auth` text does not suppress them. Other languages and text-pattern-only matches remain `INFERRED`. Missing controls require additional enforcement tests.

## Compounded risks

The Synthesis Judge separately establishes the relationships between code/command execution + Stellar signature, network content + code execution, and unauthenticated endpoint verified by live probe + unlimited spending. Verified critical combinations enter the score/badge ceiling; the dimension average cannot mask a fund loss path.

## Coverage gate

`coverage.surface_coverage` separately displays the behavioral contract, tool permissions, executable implementation, supply chain, runtime endpoint, ownership, and ledger history. The manifest/config file does not count as implementation. In the deep audit, if prompt + tool inventory + executable code are not present together, `SAFE` is not granted; a highly incomplete core surface is taken to the `HIGH_RISK` score ceiling.

## Active probe security gate

An adversarial payload to the real endpoint might produce side effects or fund movement. Default:

```dotenv
ENABLE_ACTIVE_AGENT_PROBES=false
```

It must only be enabled on an isolated, test-funded, and resettable target. When disabled, the report does not claim that a live attack was performed.

## Evidence boundary

The Python analysis uses a bounded AST, not inter-procedural or symbolic execution. It may miss import aliases, dynamic dispatch, external policy gateways, exception-dependent flow and authorization checks in another repository. A finding-free result is not a professional Stellar/Soroban audit or proof of exploit absence. Process invocation does not automatically imply shell injection, and a financial input path does not prove that a downstream authorization policy is bypassable.

The public [Studio](AUDIT_STUDIO.md) always runs source review without active probes or external integrations. Its scenario checks describe defense signals, not executed attacks. The legacy operator probe remains an explicitly enabled endpoint check, not an isolated runtime harness. The latter is a [pilot milestone](PRODUCT_AND_PILOT.md).
