# Analysis model (policy 2026-10-16.2)

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

## 2. Risks, warnings and evidence gaps are separate

Every finding has a `kind`:

- **`risk`**: the material shows a defect or dangerous capability. Only risks lower the
  score.
- **`evidence_gap`**: something that would support trust was not supplied, for example:
  - no ownership proof, lockfile or SBOM;
  - no defensive prompt wording;
  - static attack hypotheses that were never executed.
  
  Gaps are listed separately. They limit assurance (no `SAFE` without verified ownership)
  but are not vulnerabilities.

- **`warning`**: the agent moves funds without a person or a second key approving. Running
  unattended can be a deliberate design, so a warning costs a quarter of the penalty of a
  risk of the same severity and never fails a review on its own. If the code still bounds
  recipients and amounts, the warning is `low`; otherwise it is `high`. The limits
  themselves (spend caps, allowlists, amount bounds) are separate rules and remain risks.
  The warning rules are listed in `WARNING_RULES`.

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

The judge caps the score whenever an actionable risk exists, and the cap is graded
(`judge.graded_ceiling`):

- With high risks only, the cap starts at 64. With a confirmed critical, it starts at 39.
- Each further risk lowers it, weighted by severity, evidence grade and confidence, with
  diminishing returns. The cap never falls below 5.
- One inferred high risk therefore scores higher than five confirmed ones, instead of
  both landing on 64.

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

## 6. Deep review with Claude (live run, 2026-10-16)

The deep reviewer (`backend/app/services/deep_review.py`) received the evidence pack for each of the 25 corpus bundles and investigated with tools. It used Claude Sonnet 5.5 at `high` effort, with on-chain verification off. Raw results are in [`docs/evidence/deep-review-live-2026-10-16.json`](evidence/deep-review-live-2026-10-16.json).

### Results

- **Flawed bundles:** 16/16 received `needs_fixes`. The model also explained the concrete attack. For example, in V1 it described a memo saying "refund 10000 XLM" leading to a signed payment.
- **Problems the rules missed:** the model found issues no rule expresses. For example, V1 reprocesses its last 20 payments on every poll, so the same refund can be sent repeatedly.
- **Sound-labelled bundles:** 7/9 passed. The model flagged the other two, and both contain real replay flaws that the fixture authors and the rules had missed:
  - C2: the approval token does not bind payee or amount and can be reused;
  - case-06: an approval record is never consumed.
  
  The labels were left as written.
- **Verification gate:** no model claim was rejected. Every finding cited a verified line.
- **Cost:** about 0.81 USD for all 25 bundles (55,632 output tokens, cache-heavy input), with roughly 10–30 seconds per bundle.

### Fix made during the run

The live run exposed one defect: a model finding quoted a secret literal verbatim. Findings, flow verdicts and summaries now pass through the same redaction as other outputs, after the quote has been verified against the source.

## 7. Comparison with manual review on open-source agents (2026-10-16)

Twelve public Stellar agent repositories (MCP servers, agent SDKs, x402 gateways,
wallet skills) were run through `scripts/audit_repository.py` with deep review. Eight
of them were also reviewed by hand, independently, without access to the system's
reports. Third-party findings are not published here; maintainers should be contacted
privately.

### Agreement on the most serious issues

The manual reviews found 29 high or critical issues.

| | Matched by the system |
|---|---|
| Final run | 21 of 29 (about 72%) |
| Either of two runs | 25 of 29 (about 86%) |

The issues the system missed were mostly in two places:

- **Files outside the review budget.** For example, a 4,000-line code generator. The
  report lists these files and is marked incomplete.
- **Documentation promises that the code does not keep.**

The deep review is not deterministic. An issue found in one run can be missing from the
next, so a single run should be read as a lower bound.

### Decisions

- **Pass:** one repository passed. It has no payment or signing path, and its remaining
  findings were medium. The manual review agreed that nothing in it can move funds.
- **Needs fixes:** every repository with a confirmed payment, signing or execution
  defect received `needs_fixes`.
- **Spread of scores:** with graded caps, scores ranged from 21 to 61 instead of
  clustering at 39 and 64.

### False positives found and fixed

The comparison exposed false positives, all now fixed and covered by tests in
`backend/tests/test_oss_false_positives.py`:

- **Dependencies:**
  - comments and comparisons in source code read as floating dependency versions;
  - version ranges flagged although a lockfile pins them.
- **Payment destinations:**
  - test files, deny lists, asset issuers and example text treated as payment destinations;
  - destinations checked on a network the code does not use.
- **Contract accounts and signing:**
  - a contract id or a `webauthn` field taken as contract-account login (SEP-45);
  - holding a key treated as signing authority when the project never transacts.
- **Code execution and secrets:**
  - `RegExp.exec` and `db.exec` treated as code execution;
  - a masked secret in a log line treated as exfiltration.
- **Soroban contracts:** authorization or TTL renewal done in a helper reported as missing.
  These are now medium review items. High is kept for functions with no check anywhere.

### Logic flaws found and fixed

- **Missing material lowered the score.** A coverage gap capped the score below a pass,
  so a missing prompt produced `needs_fixes` instead of `needs_evidence`. Coverage now
  limits only the decision.
- **Coverage ratio above 1.** Reading manifests counted towards coverage, which could
  push the ratio over 1. Only source files count now.

### Every finding checked against the source

All 199 findings the final run reported on the 12 repositories were checked against the
code at the exact GitHub commit (`git ls-remote` confirmed each local copy matched).

How they were checked:
- **Critical and high:** read by hand.
- **Medium and low:** checked by independent verifiers. Every rejection and a random
  sample of confirmations were then re-read by hand.

| Result | Findings | Share |
|---|---|---|
| Correct as described | 161 | 81% |
| Real but overstated, or latent | 32 | 16% |
| False | 5 | 2.5% |
| Needs a network lookup | 1 | 0.5% |

- **Severe findings:** all 10 critical findings were correct. Of the 36 high findings,
  32 were correct, 3 overstated and 1 false.
- **Rules versus AI:** four of the five false findings came from lexical rules. The
  fifth came from the AI trusting narrow SDK typings for the Horizon submit response.
  All five are fixed, with regression tests.
- **Severity:** the largest systematic error was severity set one level too high,
  usually for code that is latent, mocked or never called. 76 findings were affected.
  The review prompt now has a severity rubric for these cases.
- **Decisions:** every `needs_fixes` decision rests on at least one verified critical or
  high finding. The repository that passed had no verified high or critical issue.
