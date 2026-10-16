# Analysis model (policy 2026-10-16.3)

This document describes how a source review reaches its decision, score and credential
eligibility. It replaces the earlier model, where declared tool permissions drove most
rules and missing documentation lowered the same score as observed defects.

## 1. What the code can do is derived from the code

`backend/app/swarm/codeflow.py` parses every submitted Python file, and
`backend/app/swarm/jsflow.py` parses every JavaScript and TypeScript file (`.js`, `.jsx`,
`.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`) with tree-sitter. Neither imports nor executes
the code. Both run the same project-wide, context-insensitive data-flow analysis with the
same labels, sinks and fail-closed controls:

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

### JavaScript and TypeScript specifics

- Entry points are found from how code is wired, not from names: MCP/agent tool
  registration (`server.tool`, `registerTool`, `tool({...execute})`, `DynamicStructuredTool`,
  `CallTool` handlers), HTTP routes (Express/Hono/Fastify style, Next.js route files), bot
  handlers and exported functions nothing calls. Only a tool's first parameter is model
  input; zod `enum`/`literal`/`max` constraints in its schema count as allowlists and caps.
- Workspace packages are resolved by their `package.json` name, so a monorepo is one project.
- Stellar-specific sinks include `Operation.payment` and other operations, `contract.call`,
  `authorizeEntry`, `signTransaction`/`signAuthEntry`/`signAndSubmit*`, submission, and x402
  paying fetch wrappers (`wrapFetchWithPayment*` and similar). A paying wrapper without a
  spend-limit option is reported as `security-path-x402-payment-unbounded`.
- Browser wallet prompts (Freighter, Stellar Wallets Kit) are human approval, not agent
  signing. Relaying a transaction someone else signed is not signing authority.
- A secret-named field or argument the model supplies (`secretKey` in a tool schema) is
  reported as `security-path-secret-handled-by-model`.

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

### How the score is computed (policy 2026-10-16.3)

The score measures the size of the risks found. Every report carries the calculation
as `result.score_breakdown`, and the demo shows it under "Why this score?".

1. **Risk points per finding.** Each risk or warning costs:

   | Factor | Values |
   |---|---|
   | Severity | critical 30, high 14, medium 6, low 2 |
   | Evidence grade | confirmed ×1, inferred ×0.6 |
   | Confidence | ×confidence (at least 0.4) |
   | Spread | ×1 for one affected place, up to ×1.75 (log scale) for many |
   | Warning (autonomy without approval) | a quarter of a risk |

   Evidence gaps cost nothing.
2. **Root causes count once.** Findings that restate one cause are grouped; for example,
   no spend policy, unbounded spend, controls not enforced and no human approval all
   restate one missing spending control. The largest counts in full and each further
   restatement adds 30%. Further distinct findings of the same severity have mildly
   diminishing returns (×1/(1 + 0.25n)).
3. **Points to score:** `100 × e^(−risk points / 100)`. Small problems cost about one
   point per point (5 points → 95). Large ones stay ordered instead of all reaching 0:
   150 points → 22, 300 points → 5.
4. **Ceilings keep the decision honest, without charging twice.**
   - A confirmed critical risk keeps the score at 39 or below.
   - Any other actionable risk keeps it at 64 or below, under the pass mark.
   - Below the ceiling the raw score stands. Only the range above (ceiling − 10) is
     squeezed into the last 10 points, so risky agents never look passable and still
     differ from one another.
   - An earlier version rescaled the whole raw score into the band (×0.39 for a critical).
     That charged the same risks twice and pushed most failing agents under 20.
   - The model choosing a payment's recipient and amount is grouped with "no spend
     policy" as one root cause.

**Assurance limits the badge, not the number.** Unverified ownership or ledger evidence,
or an incomplete core review, keeps the badge at CAUTION. It no longer replaces the score
with 84. Under the previous rule every clean report showed exactly 84.

On the 14 repositories audited in this session:
- Clean reports score 94–99.6.
- An agent with three high Soroban and file risks scores 57.8.
- Agents with an unbounded model-controlled payment score 28–34, in order of how much
  else is wrong.
- Command injection plus payments and account control scores 18.4.

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
- Data flow covers Python, JavaScript and TypeScript. Rust contracts are checked by
  separate rules. A JS/TS file the parser cannot read cleanly (more than 2% syntax errors)
  is listed as unparsed, gets only the lexical inventory, and keeps the
  `security-source-analysis-incomplete` gap open until the deep review reads it.
- Logic flaws that are not a flow from an untrusted input to a sink (for example, a
  verifier that never checks a payment, or secrets stored in plaintext) are left to the
  deep review.
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

## 8. What can be audited from an agent reference

`backend/app/services/agent_resolver.py` accepts any of these references
(`POST /api/v1/studio/resolve`, `scripts/audit_agent.py`) and decides what the audited
source is bound to. It reads the ledger only (`getLedgerEntries`, Horizon); it never
signs or submits.

| Reference | What is read | Binding of source to the agent | Can it pass? |
|---|---|---|---|
| GitHub URL (`owner/repo`, optional ref) | Repository, pinned to a commit | `user_supplied`: the source is what was named | Yes, on its own merits |
| AgentRegistry agent ID (64 hex) | `AgentRec` (owner, card URI and hash, endpoint hash, active, version) | `registry_card` when the fetched card's sha256 equals `meta_hash`; the endpoint is bound when its sha256 equals `end_hash` | Yes if the card names a repository; the record's facts are added |
| Contract address (`C...`) | Instance, WASM (hash recomputed), function spec, SEP-46 metadata | `attested_build` when a GitHub build attestation matches the WASM hash; `wasm_metadata` when metadata only names a repository | Only with source; a declared but unattested repository is weaker evidence |
| Account (`G...`) | Signers, thresholds, flags, home domain | None from the ledger alone | No: authority facts only |
| Agent card URL / JSON | Card fields (repository, endpoint) | `unbound_card` unless it matches a registry record | Yes if it names a repository, at the lower binding |
| Endpoint only | Nothing about its code | None | No |

Without source, the audit reports what the chain shows (upgradeability, authority,
custom account) and the blocking gap `stellar_native-onchain-source-unbound`. An agent
whose code cannot be read cannot be shown to be safe, so it cannot pass.

## 9. JavaScript and TypeScript measurement (2026-10-16)

- **Labelled TS corpus** (`backend/tests/test_ts_agent_corpus.py`): 21 cases, 12 flawed and
  9 sound; all 21 are classified correctly.
- **Real repositories:** 8 open-source TypeScript/JavaScript agents had 19 verified issues
  that can be expressed as a data flow or a Stellar rule. The rules alone, without the deep
  review, find 17 of the 19. The two misses are design flaws (secrets stored in plaintext,
  and an x402 verifier that never checks the payment), which are left to the deep review.
- **Parsing:** every JS/TS file in the 12 repositories parsed without errors, at about one
  second per repository.

These repositories were also used to fix false positives, so the numbers are a
regression check, not an independent estimate of precision or recall.

## 10. Large-repository run: an EVM/Solana TypeScript monorepo (2026-10-16)

A 1,060-file TypeScript monorepo (EVM and Solana, non-custodial) exposed defects that the
smaller agents had not:

- **Selection:** the old 120-file budget left out the authentication and routing files,
  and the deep review then raised a high finding it could not verify (the route guard it
  needed was in an unselected file). The budget is now 1,500 files / 12 MB, files that
  decide authority (auth, router, middleware, policy, webhooks, keys) are kept first,
  and any source left out keeps `security-source-analysis-incomplete` open.
- **Termination:** several anonymous functions on one line reused a function key, which
  made a function its own parent and hung the analysis. Keys are now unique, and scope
  walks stop on cycles.
- **Precision:**
  - `JSON.parse` no longer resolves to a project method named `parse`. That leak had
    spread model taint across the repository.
  - The analyser recognises more control shapes: SSRF pinned to a checked address,
    branch-sensitive `cond ? p : null` and `a || b` checks, and nested `const` arrow
    functions.
  - Signers supplied by the caller (EIP-1193, Wallet Standard) are treated as
    delegated, not as agent signing.
  - Comments are ignored by the lexical rules.
  - CI workflows float only through unpinned actions.
- **Result:** rules-only, the score went from needs_fixes 57 (mostly false findings) to
  pass 84. The deep review then found the same calldata-binding issue as an independent
  manual review. Logic flaws such as an approval page that discloses a capability id, or
  provider transactions checked only by simulation, were found by the manual review and
  not by the system. Chain rules remain Stellar-specific; EVM and Solana value-movement
  checks are left to the deep review.
