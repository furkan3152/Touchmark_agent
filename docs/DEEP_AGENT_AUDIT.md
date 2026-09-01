# AgentVeritas Stellar — Deep Agent Audit

Policy: `agentveritas.stellar.policy.2026-08-31.4`

## What makes the Deep tier different?

The Basic tier is a fast heuristic, fundamental attack scenario, tool permission, and dependency review. The Deep tier additionally evaluates the data paths in the agent implementation and the blast radius created jointly by the seven dimensions.

The Stellar-specific deep analysis looks for these paths:

- API/webhook/user input → `eval`, `exec`, shell or process execution;
- external input → Stellar transaction submit/sign, Soroban `invoke_contract`, host function, authorization entry or token transfer;
- Stellar secret seed/private key/API secret → log or outbound network call;
- signing/spending tool → absence of `require_auth`, allowlist, limits, and sequence/idempotency enforcement in the executable code.

When a source variable and sink are seen in the same file, the finding is `CONFIRMED` and backed by file:line evidence. The absence of checks or tool chainability remains `INFERRED`; it is not presented as an actualized exploit.

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

The analysis is deterministic, intra-file, and a lightweight taint approach; it is not full AST, inter-procedural, or symbolic execution. It may miss dynamic dispatch, external policy gateways, and authorization checks in another repository. A finding-free result is not a professional Stellar/Soroban audit or proof of exploit absence.
