# AgentVeritas — Instawards execution brief

Prepared 15 October 2026. Draft for discussion with a local Stellar Ambassador Chapter. No application has been submitted, no users or funding are claimed, and acceptance is not guaranteed.

## Product thesis

AI agents increasingly receive tools, signing authority and access to private data. Teams need to know which permissions and failure paths they are accepting before deployment, and when a software change invalidates an earlier assessment.

AgentVeritas is an evidence-first release review and authority-control toolkit for Stellar agents. It combines bounded source analysis, explicitly consented AI hypotheses, a 24-area evidence inventory, an opt-in execution policy gateway, and version-bound Soroban report credentials. The open-source engine remains usable without a wallet or an AI API key.

The initial buyer is a small team shipping a Stellar treasury, payment or transaction-preparation agent. The first use case is release approval, not a universal reputation marketplace. A useful result identifies concrete risky paths and missing evidence, and helps a team demonstrate that a rejected action really was rejected.

## Why Stellar belongs in the critical path

| Primitive | Product use | Concrete benefit | Trust boundary |
|---|---|---|---|
| Soroban `require_auth` | Registry and credential issuer/owner actions | Authorization is attached to invocation arguments, with host-managed signature and replay handling | The application must still define a correct policy |
| Cross-contract invocation | Credential reads completed registry validation and current agent version | A credential cannot mint from a pending or stale validation | Registry and issuer remain trust dependencies |
| Stellar Asset Contract | Existing audit escrow uses the SAC interface | One settlement lifecycle can work with an explicitly configured Stellar asset | Historical testnet evidence uses XLM, not USDC |
| Atomic execution | Escrow payout and fee distribution in one call | Avoid partially distributing funds after successful evaluation | Audit quality is not established by settlement |
| Persistent state and TTL | Report commitments, version records, expiry and revocation | Machine-readable verification without exposing source on-chain | TTL maintenance and restoration are required |
| Fee bumps / relayers | Future sponsored onboarding | Users can authorize actions without maintaining fee infrastructure | Not implemented in this sprint's source; sponsorship costs need quotas |

Other programmable networks can implement analogous systems. The differentiator is a coherent Stellar-native workflow and lower integration burden for Stellar builders, not an assertion that competing networks cannot create NFTs or escrow.

## Proposed 30-day sprint — $5,000 equivalent in XLM

This proposed award funds **future execution and pilot validation**, not reimbursement for changes already made in this repository. Confirm scope and amount with the Chapter Lead before work is represented as award-funded.

| Workstream | Budget | Acceptance evidence |
|---|---:|---|
| Deploy registry v0.2 and credential contract to testnet; verify expiry/revocation/version-change behavior | $1,400 | Contract IDs, WASM hashes, successful transaction IDs and state readbacks |
| Complete signed wallet checkout and funded USDC testnet escrow integration | $1,100 | Exact issuer/asset documented; funded success, rejection and timeout-refund journeys |
| Authorized isolated runtime harness and additional adversarial corpus | $1,200 | Reproducible negative tests, expected outcomes, false-positive/false-negative analysis |
| Three builder pilots, English UX validation and release workflow | $900 | Consented pilot feedback, anonymized before/after findings, usability evidence |
| Reproducible demo, operating guide and handover | $400 | Public source, demo recording, release checklist and final evidence index |
| **Total** | **$5,000** | Chapter-agreed deliverables within 30 days |

Pilot recruitment, three participating teams, and the proposed outcomes are targets, not achieved traction. Mainnet financial safety needs a separate independent review; it is not promised by this budget.

## Success metrics

- Three consenting pilot teams complete a review of an actual versioned agent.
- At least ten completed testnet review/payment/credential workflows, with attributable transaction evidence; no wash activity presented as demand.
- Replayed, cross-network, over-budget and changed-version actions rejected in the published test corpus.
- Every report displays all 24 control areas, including unverified and missing evidence.
- At least one demonstrated source-change invalidation, credential revocation and expired credential.
- Publish known misses and unsupported languages instead of reporting benchmark accuracy without a denominator.

## Demo script

1. Open the English workspace and load the unsafe fixture.
2. Run the review; open a concrete source finding and its remediation.
3. Open Coverage. Explain why located evidence is not a verified defense.
4. Download the exact report and compare its fingerprint in the local verifier.
5. Run the policy lab: over-budget payment, unknown destination, changed source version and emergency stop.
6. Show contract test evidence for immutable report binding, issuer authorization, non-transferability, expiry and revocation.
7. After a new testnet deployment is verified, replace test-output demonstrations with transaction and state evidence. Do not present the old deployment manifest as the new contract release.

## Current program fit

The official Instawards rules describe chapter-led opportunities, a scoped sprint generally within 30 days, and typical initial awards of $1,000–$5,000 equivalent in XLM. Additional awards may reach $15,000 in aggregate and are not automatic. Local engagement and SDF approval matter; a polished application alone is insufficient.

Sources checked 15 October 2026:
- https://stellar.gitbook.io/scf-handbook/scf-awards/instawards/official-rules
- https://communityfund.stellar.org/
- https://developers.stellar.org/docs/build/guides/auth/contract-authorization
- https://developers.stellar.org/docs/tokens/stellar-asset-contract
- https://developers.stellar.org/docs/build/guides/transactions/fee-sponsorship

Owner-specific fields still required: legal applicant name, chapter relationship, team availability, pilot commitments and requested award amount agreed with the Chapter Lead. No such details have been invented.
