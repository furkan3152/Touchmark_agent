# Analysis model (policy 2026-10-16.1)

This document describes how a source review reaches its decision, score and credential
eligibility. It replaces the earlier model, where declared tool permissions drove most
rules and missing documentation lowered the same score as observed defects.

## 1. What the code can do is derived from the code

`backend/app/swarm/codeflow.py` parses every submitted Python file (it never imports or
executes them) and runs a project-wide, context-insensitive data-flow analysis:

- **Calls are resolved across files**: imports and import aliases, module functions,
  class methods, `self.x` state, local aliases such as `dispatch = horizon.submit_transaction`.
- **Untrusted inputs are recognised by role, not by parameter name**:
  - `model`: arguments of LLM tool handlers, model responses and methods reachable
    through dispatch tables or `getattr(self, name)` dispatch.
  - `external`: HTTP routes, request bodies, fetched network content.
  - `chain`: memos and payment records, which anyone can write.
  - `caller`: parameters of public functions that nothing in the project calls. These
    are reported with a lower grade.
- **Sinks** are signed Stellar payments, account-authority operations, signing of
  externally supplied envelopes, contract invocation, process and code execution,
  server-side fetches, file paths, logs, and model requests.
- **Controls count only when they fail closed**, meaning code after them runs only if the
  check passed:
  - an allowlist or fixed-table lookup;
  - an upper bound (`if amount > MAX: raise`; `if amount <= 0: raise` is not one);
  - binding to an approved record;
  - an approval check;
  - `Path.resolve().is_relative_to(base)`;
  - inspection of transaction operations.
  
  A cap that only logs a warning is reported as a finding.

`backend/app/swarm/capabilities.py` reconciles the declaration with the code before any
auditor runs:

- A capability in the code that no declared tool grants is added as a tool with
  `origin: "observed"`, and is reported as `security-undeclared-capability`.
- A declared spend limit is credited only if the code bounds every untrusted payment amount.
- Building an unsigned transaction for someone else's wallet is not signing authority.

The input commitment always covers the submitted bundle. Declaring every tool read-only
no longer removes the financial rules.

## 2. Risks and evidence gaps are separate

Every finding has a `kind`:

- **`risk`**: the material shows a defect or dangerous capability. Only risks lower the
  score.
- **`evidence_gap`**: something that would support trust was not supplied, for example:
  - no ownership proof, lockfile or SBOM;
  - no defensive prompt wording;
  - static attack hypotheses that were never executed.
  
  Gaps are listed separately. They limit assurance (no `SAFE` without verified ownership)
  but are not vulnerabilities.

The gap rules are listed in `EVIDENCE_GAP_RULES` in `backend/app/swarm/policy.py`. Static
scenario checks no longer lower the score; only executed scenarios (live probes, sandbox)
do.

## 3. One decision rule

`policy.review_decision()` is used by the Studio, official audits and credentials alike:

| Decision | Meaning |
|---|---|
| `needs_fixes` | A high or critical risk exists, or accumulated risks put the score below 65. |
| `needs_evidence` | No actionable risk, but the prompt, tools and implementation were not all reviewed. |
| `pass` | No open high or critical risk, with the full core surface reviewed. |

The judge enforces two score caps:

- Any actionable risk caps the score at 64.
- A confirmed critical risk caps it at 39.

A `pass` therefore always scores 65 or more, and a report with an actionable risk never
does. `pass` is scoped to the reviewed material. It is not a safety certificate.

## 4. Credentials state that an audit passed

- **Settlement:** payment for a delivered review always settles.
- **Credential issuance:** the `issue` step runs only when the report decision is `pass`
  and the registry score is at least 65.
- **On-chain enforcement:** the `AuditCredential` contract refuses scores below
  `PASS_SCORE = 65` (`BelowPassScore`).
- **Revocation:** the first revocation reason is permanent (`AlreadyRevoked`).
- **Receipt:** a failing audit is delivered with `credential_status: "not_eligible"` and
  `token_id: null`.

The Testnet deployment pinned in `deployments/` predates this contract version. Until it
is redeployed, the backend rule is what keeps failing audits from receiving a credential.

## 5. Measured behaviour and its limits

The suites live in `backend/tests/test_agent_corpus.py` and
`examples/studio/benchmark/`.

### Labelled corpus (25 bundles)

- 16 have one realistic defect and 9 are look-alikes with the control implemented
  correctly.
- 15 bundles were written by the maintainer. 10 were written by a separate author who
  did not see the analyser.
- On the 10 independent bundles, before any tuning:
  - all 6 flawed bundles received `needs_fixes`, but only 3 for the right reason;
  - only 1 of the 4 sound bundles passed.
- The gaps those bundles exposed were then fixed: dispatch tables, `getattr` dispatch,
  class state, lower-bound-only checks, approval records, configuration tables and
  secrets returned to the model.
- After the fixes, all 25 bundles get the expected decision for the expected reason.
- Each of the 16 flawed bundles still fails when its declaration is rewritten as
  read-only with a defensive prompt.

### Earlier suites

- The 16-case benchmark in `examples/studio/benchmark/` now passes 16/16 (11/16 before).
- `scripts/evaluate_detection.py` now matches 10/10 (8/10 before).

### Limits

These sets are small, and the analyser was improved using them. They are regression
gates, not estimates of real-world precision or recall. The analysis also has fixed
limits:

- It is static and context-insensitive.
- It does not resolve reflection beyond the patterns above.
- Data flow is Python-only; JavaScript and TypeScript sources get a capability inventory,
  and Rust contracts are checked by separate rules.
- It cannot see what libraries do internally.

A new, independently written corpus is the next meaningful measurement.
