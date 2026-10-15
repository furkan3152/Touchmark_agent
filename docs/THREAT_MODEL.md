# Threat model and coverage boundaries

## Assets and attackers

Protect customer source, secrets, signing authority, audit integrity, payment funds, agent-scoped budgets and deployment state. Consider malicious submitted source, malicious tool output, an agent trying to exceed authority, a compromised dependency/MCP server, a dishonest provider/evaluator, stolen operator credentials and misleading or hallucinated model output.

## Current defenses

| Boundary | Implemented control | Residual risk |
|---|---|---|
| Public intake | Pre-parse 128 KiB bound; source file/AST complexity limits; no execution | Supported languages and bounded static analysis can miss dataflow and runtime behavior |
| GitHub import | Immutable commit, Git blob integrity, Blueprint paths or bounded provisional selection | Does not audit an entire repository automatically; declared scope can omit behavior |
| AI second opinion | Explicit consent, operator enablement, bounded redacted input, no tools, validated file/line references | Prompt injection and hallucination remain possible; valid citations do not prove a claim |
| Deterministic result | AI observations kept outside scores and release decisions | Static heuristics have false positives and false negatives |
| Evidence inventory | 24 visible control areas, absent evidence distinguished from located source | Keyword presence is only surface discovery, never a verified defense |
| Client rendering | Text-only DOM creation for uploaded/model content; CSP; exact download hash verification | Visual/accessibility QA and independent application security review still required |
| Execution policy | Exact action/policy approval; integer limits; SQLite atomic reservation; replay denial; persistent stop | Integration can be bypassed if the agent retains raw credentials; stop does not recall in-flight actions |
| Registry | Source version/hash pinned at request; stale response rejected; constructor initialization | Trusted validators can still publish incorrect assessments |
| Credential | Reads completed registry state; issuer auth; one request/credential; nontransferable; expiry/revocation/version checks | Custom credential interface, no general NFT-marketplace interoperability claim |
| Escrow | Separate roles, SAC transfer, snapshotted fees, atomic completion and deadline paths | Independent evaluator operation and real funded checkout remain deployment gates |
| Persistence | Protected single-operator service; atomic local writes | Not a multi-tenant service; no shared distributed state or built-in at-rest encryption |

## What a certificate proves

It proves that an authorized registry validator recorded a report commitment about an agent version, and that the credential state has not expired, been revoked or been superseded by the current registry version. It does not prove that source corresponds to every deployed service, that the model cannot be manipulated, that all dependencies were reviewed, or that no future exploit exists.

## Covered review areas

Intent and instruction hierarchy; prompt/tool-output injection; identity and authorization; tool scopes; MCP integrity; agent-to-agent delegation; memory/RAG isolation; privacy; secrets; network/SSRF; sandbox execution; dependencies/build provenance; spending; approvals; replay; resilience; trace integrity; emergency stops; Soroban auth; Stellar assets; TTL/restoration; settlement; report lifecycle; applicable policy boundaries.

## High-priority next experiments

Build an isolated runtime adapter with no production signing keys; record actual attempted actions under hostile inputs. Add multi-file/language dataflow and MCP schema-change fixtures. Validate DNS rebinding and redirected egress at the execution layer. Measure detection against independently labeled realistic agents, including benign near-miss examples. Verify tenant isolation and approval races in the actual host integration. These are specific missing evidence, not hidden behind a high score.

Update 2026-10-15: a bounded Python microVM sampler now exists, but does not provide tamper-proof tool traces. Canonical path checks, visible entrypoint rebinding rejection and exact import-origin checks address source-to-runtime substitution examples. The public auth-entry inspector checks one decoded tree against caller-declared limits without verifying signatures, network or ledger freshness. The experimental AgentSessionAccount enforces a separate trusted-token spending policy locally; it is not deployed or production-audited. See the [adversarial review and retained misses](INDEPENDENT_REVIEW_2026-10-15.md).
