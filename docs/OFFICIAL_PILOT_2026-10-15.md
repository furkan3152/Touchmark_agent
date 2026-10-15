# Official pilot — 15 October 2026

AgentVeritas now has an official first-party review catalogue, portable Veritas Capsules, actual isolated Python execution, and an executed Stellar Testnet report/payment/credential workflow. It remains a **private pilot**. This document is the current evidence record; older dated product and review documents describe earlier states and are not current pricing or deployment promises.

No universal agent detector, complete vulnerability coverage, independently operated validator network, live paid checkout or production security certification is claimed. A file map can validate the submitted scope without proving that the entire deployed agent was submitted.

## Review service

All specialists are operated by one team, **Veritas Official**. Eight selectable specialists organize seven baseline source-analysis dimensions; baseline rules still run even when a specialist is not selected.

| Module | Official specialist | Focus |
| --- | --- | --- |
| `intent` | Intent Analyst | Declared purpose, conflicting instructions and forbidden goals |
| `injection` | Adversarial Examiner | Instruction override and untrusted-content manipulation |
| `tools` | Authority Inspector | Dangerous sinks, permissions and delegation boundaries |
| `privacy` | Privacy Examiner | Secret handling and data-boundary signals |
| `financial` | Treasury Inspector | Spending authority and recipient/budget boundaries |
| `resilience` | Reliability Examiner | Failure handling and bounded execution |
| `stellar` | Soroban Inspector | Contract authorization, storage lifetime and transaction boundaries |
| `provenance` | Provenance Examiner | Source commitments, dependencies and release traceability |

| Tier ID / name | Proposed USD price | Testnet quote | Runtime case ceiling |
| --- | ---: | ---: | ---: |
| `quick` / Preview | 3 | 0.1 faucet XLM | 0 |
| `standard` / Assurance | 19 | 1 faucet XLM | 12 |
| `deep` / Deep | 49 | 3 faucet XLM | 24 |

Prices are proposals, not active sales. A larger case budget samples more behavior; it does not prove complete security. Optional AI review requires a configured provider and consent. Independent reviewers are future work. See [REVENUE_MODEL.md](REVENUE_MODEL.md).

## Evidence index

| Evidence | Observed result | What it establishes |
| --- | --- | --- |
| [Local browser journey](../deployments/local-browser-ui-2026-10-15.json) | Real Chromium with a live local HTTP backend; 1440, 390 and 320px layout checks | File intake, source review, unsafe-fixture findings, report download and unavailable-order gates; no wallet extension or deployed protected HTTP journey |
| [Private official order](../deployments/official-order-pilot-2026-10-15.json) | Eight successful Testnet transactions, 12 readback/recovery checks | Wallet-bound order, real source-only audit, private report storage, exact credential binding and no repeat settlement after restart; an operator-assisted publication checkpoint is disclosed |
| [Deployed integrations](../deployments/deployed-integrations-2026-10-15.json) | Real OIDC AI connection/review and 12 observed Sandbox case responses | Python SDK integration in a Preview build; two output assertions matched and one did not; this is not 12 passed security controls or a browser test |
| [Bound report delivery](../deployments/testnet-audit-delivery-2026-10-15.json) | 20 successful Testnet transactions, 16 readback assertions, 4 expected contract-error simulations | Exact report/version consistency, first-party settlement and credential delivery for one controlled static fixture; refund for a separate stale-version fixture |
| [Agent account](../deployments/agent-account-testnet-2026-10-15.json) | 7 successful Testnet transactions and 3 rejected enforcing simulations | Actual session-authorized transfer; forbidden recipient, excess cumulative spend and revoked session rejected; account funds recovered |
| [Capsule runtime](../deployments/capsule-runtime-pilot-2026-10-15.json) | 24 actual cases with responses; 4 typed output assertions; 4 separate blocked environment preflights | Real callable execution and bounded multi-turn state in a disposable microVM, with explicit environment mismatch handling |
| [Report rendering/readback](../deployments/delivery-render-verification-2026-10-15.json) | Current credential, matching report hash and owner at ledger 5,209,181; HTML/SVG artifact hashes | A dated live verification of the delivered report and its display artifacts |
| [Disclosed detection challenge](../deployments/detection-evaluation-2026-10-15.json) | Eight expected outcomes matched out of ten source-signal cases; two retained misses | Reproducible limitations in a small developer-visible challenge set, not market-wide security accuracy |

These are separate experiments. The 24-case capsule run was not the report funded by the 1-XLM delivery transaction. Combining their evidence into one future paid Standard/Deep customer journey remains a release gate. Self-generated Testnet transactions are engineering evidence, not customer demand or revenue.

Python verification covers **696 passing tests**, including the exact-input and stale-plan regressions added after the clean-install check. Dependency consistency checking passed, and a package advisory scan reported no known vulnerabilities. **51 Rust tests** passed locally. The local HTTP verification exercised source intake, Blueprint missing-file rejection, plan/report integrity, capsule roundtrip and private route boundaries. The package scan is a dated advisory check, not a code-security guarantee. Current official order operations, access recovery and refunds are described in [OFFICIAL_FULFILLMENT.md](OFFICIAL_FULFILLMENT.md).

## Report, settlement and credential

The canonical report is [626639c658a15ca265c620c76dd64a7344a55de84471f7ae148af9bedf427c35.json](../deployments/reports/626639c658a15ca265c620c76dd64a7344a55de84471f7ae148af9bedf427c35.json). Its exact public bytes were fetched and checked before the registry response. The result is `needs_evidence`, with static score 64. It contains explicit `runtime_executed: false` and no live AI-model claim.

| Contract | Testnet address |
| --- | --- |
| Registry | `CANHPHK5BGUDSQ6AUJQC7AWTAWBHBQVBRP2HB5ZU4HNBCGHSFOBO5DXH` |
| Registry-bound escrow | `CD4OOPXGVL64YSUVZWDBAM2AATNITI5DKY4HXRALYUURH27MQZNF2O4V` |
| Report credential | `CAPYQST5PLKLYYNSAM5QXNPVPJID776BALTW5LUVCCESJZKRBEZ2BKSZ` |

The main validation request, escrow job and credential token share ID `8915cc2eb03f845a18b5359ec43ae6229cea15f5cf2bc6ea2819e251f3855b13`. Requester ownership, matching report hash/score and current credential status were read back. Current status can later change through expiry, revocation, source changes or issuer removal; the receipt is a dated observation.

The main escrow settled exactly 1 faucet XLM: 0.85 to the official provider and 0.15 to its treasury. Wrong report hash and wrong score were rejected before submission with expected contract errors 15 and 9. A second agent/request changed source version after submission: settlement and credential issuance were rejected with errors 16 and 3. Evaluator dispute and requester refund returned 0.25 XLM; the amount was checked after accounting for the refund transaction fee. Final escrow balance was zero. The main credential was not changed by this negative branch.

The new escrow checks the actual registry request and its assigned validator, stores an identity snapshot, and rechecks version, source commitments, report hash and score. It can enforce consistent evidence, not the truth of an auditor's conclusions. Its constructor includes a fixed registry address; historical generic escrow deployments do not acquire these checks. See the [contract description](../contracts/audit-escrow/README.md).

## Authority enforcement and isolated execution

The deployed experimental agent account is `CDU22F3VBVTNUCC5YWR3LSJU7KA4WEQFYDIZGAXJCB3HWMDL6WJLJ7SQ`. A session signed an actual 0.2-XLM SAC transfer. Signed enforcing simulations then rejected a forbidden recipient, an exceeded cumulative budget and use after revocation, without changing account balance or spent counter. The session was revoked and remaining funds recovered. This proves those controlled authorization paths, not general wallet readiness or independently audited contract safety.

The Capsule experiment used a deterministic async Python fixture in a pinned microVM image, deny-all networking and no production credentials. All 24 cases produced responses; a three-turn scenario preserved in-process state, while a fresh scenario began at turn one. Four typed JSON assertions matched. Separate actual preflights blocked missing environment, wrong Python version, missing distribution and an unverified distribution digest. Both VMs were stopped with provider confirmation.

Runtime evidence retains `controls_verified: []`. Output assertions do not prove that a real tool call, payment or secret disclosure was prevented. Fixture context is not a production tool integration. The connector-based run did not exercise the deployed HTTP-to-Python-Sandbox-SDK transport; its probe supervisor exit code was unavailable, although completed results and the verifier's zero exit code were observed. See [VERITAS_CAPSULE.md](VERITAS_CAPSULE.md) for the adapter and bounds.

The later Preview-build integration canary did exercise the application's Python Sandbox SDK with a 12-case capsule. All cases returned actual observations under deny-all networking. One developer-declared `capsule_no_signing` response assertion failed; the proof preserves the expected and actual output. A separate AI review completed through deployment OIDC but produced only an unverified hypothesis. Neither result proves the fixture's security, and the build canary does not establish an HTTP or wallet browser journey.

Investigating that mismatch exposed a harness defect: prepending declared purpose and policy to every input could change the submitted callable's behavior and coach its answers. The corrected compiler keeps those declarations in committed evaluator metadata, passes ordinary scenario/operator text unchanged and labels only explicitly selected fixture augmentation. The old evidence remains historical. Previously acknowledged runtime plans are rejected before review, provider or checkout RPC; a funded order is never silently moved to the changed test pack. Access recovery does not change its plan, and refund eligibility still follows the contract deadline/state rules.

## Release gates

1. Verify one customer-facing hosted flow from plan approval through wallet authorization, selected Standard/Deep runtime, immutable report, registry-bound settlement and live credential verification. Exercise changed plans, retries, failures, refusals and refunds.
2. Add instrumented adapters that reach real model/tool/memory paths with synthetic credentials and trusted observation. Unsupported integrations must block or disclose missing coverage.
3. Validate privacy/retention, tenant isolation, distributed quotas, secret handling, incident response and restoration/TTL operations. Test deployed transport and browser journeys with the intended access configuration.
4. Measure actual per-tier costs and obtain consented external pilot feedback. Publish failures and a larger independently labeled evaluation; do not convert a small fixture score into an accuracy claim.
5. Complete independent contract and operational review before granting production financial authority. Design independent operator governance and disputes separately from this first-party launch.

These gates are delivery work, not reasons to mark unperformed controls as verified. No customer keys, mainnet funds, grant approval or SDF endorsement are part of this pilot evidence.
