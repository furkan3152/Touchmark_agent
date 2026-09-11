# Verification record — 2026-09-11

Scope: Stellar Audit Studio, public address/GitHub intake, source-analysis corrections and report/access boundaries. Contract source and deployment IDs were not changed. This record is not an independent security audit or a production-readiness certificate.

## Implemented

- Public, stateless source review and a dedicated Studio at `/`; existing operator UI retained at `/operator`.
- Source bundle import, two explicitly labeled fixtures, actual seven-dimension analysis, prioritized findings, missing evidence and report/input downloads.
- Simplified neo-brutalist interface: three intake tabs, capability checkboxes, optional advanced JSON, collapsed findings, and free versus planned paid pricing.
- Public G/C address lookup through fixed Stellar endpoints; bounded public GitHub root-bundle import. No ownership or deployed-code association is inferred from either.
- Pre-parse body limit, source/AST bounds and process-local admission limit.
- No uploaded-program execution, endpoint probing, chain queries, external AI processing or persistence in the Studio review path.
- Python AST paths with function-local state, safe reassignment and conservative branch joins. A control keyword elsewhere in the file no longer hides a financial path. Non-Python/text-pattern candidates are inferred evidence.
- Static scenario notes no longer claim attacks were executed. Missing ownership is not presented as a Studio source defect; it remains unproven.
- Stored agents, jobs, badges, reports, subscriptions and accounting reads require operator authentication. Operator downloads use authenticated requests.
- A separate committed-report endpoint serves the exact bytes hashed before mutable attestation metadata. Uploaded source whitespace remains part of the input commitment.
- Product, revenue hypotheses, native Stellar choices and a bounded Instawards pilot documented separately from implemented functionality.

## Targeted local checks

```bash
.venv/bin/python -m pytest \
  backend/tests/test_studio_intake.py \
  backend/tests/test_audit_studio.py \
  backend/tests/test_deep_agent_audit.py \
  backend/tests/test_api_security.py \
  backend/tests/test_swarm_e2e.py \
  backend/tests/test_stellar_attestation.py \
  backend/tests/test_audit_integrity.py -q
```

Result: **79 passed** after the self-service intake changes (69 before this iteration). A full repository suite was not run. New behavior changes were introduced with failing targeted regressions, then checked after implementation. `node --check` passed for `frontend/studio.js` and `frontend/app.js`; `git diff --check` passed.

These tests include control-comment bypass, irrelevant validation helpers, Python comment-only paths, clean reassignment, cross-function secret contamination, evidence-grade honesty, bounded uploads, private-list access, external integration isolation, immutable report download and input whitespace commitment.

The additional intake cases cover fixed external destinations, public GitHub import using a mocked provider response, invalid/private-key input rejection, address-only missing-evidence behavior, network-bound input hashes, missing contract state, and upstream failure remaining unknown. Provider mocks are not live integration evidence.

## Browser checks

Playwright opened the local application at 1440 × 1050 and 390 × 844. Both layouts had no horizontal overflow. The mobile result view and desktop page were captured and visually inspected. No console errors were reported on the successful review flow.

The unsafe payment fixture returned **8 prioritized high/critical findings**. The read-only fixture returned **0 prioritized source findings** and `needs_evidence`, not a safety approval. These two constructed examples are not a population accuracy benchmark.

Bundle import was exercised through the browser File API using an in-memory `agent-audit.json` fixture. The native file chooser was opened, but direct selection from the sibling Stellar directory was blocked by the browser tool's configured filesystem roots. This is not claimed as a successful native-chooser filesystem upload test. The resulting review and actual browser download succeeded; SHA-256 of the downloaded `agent-review.json` matched the displayed fingerprint.

Local screenshots are under ignored `data/previews/`. They are inspection artifacts, not hosted product evidence.

### Simplified intake iteration

- Playwright checked the redesigned page at 1440 × 1000 and 390 × 844; 320-pixel width was additionally checked for overflow. No horizontal overflow was found. Desktop and mobile screenshots were captured and visually inspected.
- A real read-only Testnet lookup found the existing registry contract below. The address-only report explicitly stated that source and runtime behavior were not inspected. No mainnet lifecycle was exercised.
- Unsafe/reader fixture reviews again returned 8/0 priority findings respectively. The reader still required more evidence. An actual downloaded report hash matched the UI fingerprint.
- Keyboard tab navigation and browser File API bundle import passed. The File API test is not a native filesystem-chooser test.
- A real public GitHub repository without a root bundle returned the expected actionable error. This is evidence for the missing-bundle flow, not a successful live GitHub import. The successful import path was checked with a bounded provider mock in the HTTP tests.
- A failing browser regression showed that an invalid URL in an inactive GitHub tab prevented a valid file review. The field now leaves URL validation to the import endpoint; the same browser scenario and subsequent reader review passed after the fix.
- The successful review flows had no JavaScript exceptions. The deliberate missing-bundle request produced an expected HTTP 422 browser resource error.

## Live Testnet readback

```bash
.venv/bin/python scripts/verify_testnet_deployment.py
```

Result: **31 checks passed, zero failed**. The read-only verifier checked local/onchain WASM hashes, role addresses, assigned validator/reviewer state, registry response/hash, escrow completion/balance and the historical manifest transactions through Horizon.

| Component | Existing Testnet contract |
|---|---|
| Registry | `CBBBUECSLXGXVXYMRYK3BCTL3YYBRWDZGW3RNCH5CWKY6KU6UGE576KT` |
| Escrow | `CD6Q7DJMM3XR7NIBD7XCGQ34GK6UOA5BBUL7BGP5EMYDZ2ZADV37KH7W` |

The checked funded lifecycle used native XLM SAC, **not USDC**. No new transaction or deployment was submitted for this iteration. See the existing [deployment manifest](../deployments/stellar-testnet.json) for transaction and ledger details. The live verification is a dated snapshot; Testnet resets, TTL expiry or role changes can invalidate it later.

## Remaining gates

1. Isolated runtime runner and independent labeled adversarial benchmark; current source review does not execute agents.
2. Version/input commitments pinned at registry request time; existing `ValidRec` does not snapshot the agent version.
3. Public HTTPS deployment, real SEP-1 discovery and wallet-backed sessions before multi-tenant persistence.
4. Reverse-proxy time/body limits, distributed/per-client quotas, bounded workers, consent/retention and backup policies.
5. Independent contract review, governance/key separation, real negative authorization tests and event-retention operations.
6. Full legacy diagnostic localization and removal/review of overbroad legal classifications; no legal compliance certificate is offered.
7. Paid checkout and issuer-verified asset lifecycle before accepting customer payments.
8. Chapter engagement, agreed scope, applicant eligibility and approval for Instawards; no grant submission was made.

The [product/pilot plan](PRODUCT_AND_PILOT.md) turns these gaps into explicit acceptance criteria rather than claiming them as finished.
