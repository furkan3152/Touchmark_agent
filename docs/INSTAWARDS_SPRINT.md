# AgentVeritas — Instawards execution brief

Updated 15 October 2026 against the official program pages. This is a proposed chapter discussion document. No application, eligibility approval, grant, customer traction or SDF endorsement is claimed. The product is a private pilot, not production-ready agent security infrastructure.

## Program requirements verified

The [Instawards overview](https://stellar.gitbook.io/scf-handbook/scf-awards/instawards) describes a chapter-led route rather than a standard open application round. The [official Instawards rules](https://stellar.gitbook.io/scf-handbook/scf-awards/instawards/official-rules), checked on the date above, specify:

- Active local Ambassador Chapter engagement and a concrete Stellar-related deliverable, with measurable outcomes and a proportionate budget.
- A scope and award amount agreed in advance, normally achievable within 30 days or less.
- Lead-assisted submission identifying the assisting Chapter Lead; SDF makes the approval decision. Rolling review is typically 3–5 business days, not a guaranteed deadline.
- Initial awards commonly USD 1,000–5,000 paid in XLM. Selective follow-ons can reach USD 15,000 in aggregate; they are not automatic.
- KYC before disbursement, with deliverables and payment milestones agreed through the program process.

The [general SCF rules](https://stellar.gitbook.io/scf-handbook/scf-awards/official-rules-for-submissions) also apply. They include age 18+, participant/jurisdiction eligibility, an authorized team representative and a two-person team/organization participation provision. The applicant must confirm how these apply; this repository does not establish personal eligibility. They exclude NFT promotion without a real-world use case and arbitrary Stellar data-storage projects. Funding remains discretionary and is not technical approval.

The [Türkiye Chapter page](https://stellar.gitbook.io/ambassador-program/chapters/europe-and-middle-east/turkiye-chapter) provides a local entry point. It lists chapter-led contact/join options; current capacity and the applicant's engagement are unverified. No chapter contact or application has been sent by this work. SCF Build is a separate program; its award limits and round deadlines should not be represented as Instawards terms.

## Product and initial customer

AgentVeritas helps a Stellar agent developer answer: which source version and policy were assessed, what behavior was actually observed, what remains untested, and which authority can still be granted safely enough for the next controlled trial?

The initial service offers eight official specialists under one accountable operator, with `quick`, `standard` and `deep` tiers. Proposed USD prices are 3/19/49; Testnet quotes are 0.1/1/3 faucet XLM. Checkout is not live. Specialist selection defines review focus; it does not imply eight independent validators. See [REVENUE_MODEL.md](REVENUE_MODEL.md).

A practical first user is a team developing a Stellar treasury, payment or transaction-preparation assistant. The first deliverable is a reproducible, version-bound review with explicit evidence gaps. Independent operator admission and a decentralized dispute system are later milestones.

## Existing baseline — not proposed future deliverables

| Completed engineering evidence | Current proof | Boundary |
| --- | --- | --- |
| Registry-bound escrow, report delivery and credential | 20 successful Testnet transactions, 16 readback assertions and 4 rejected mismatch/version simulations | Controlled first-party fixtures; no customer revenue or universal security result |
| Session-authorized agent account | 7 successful Testnet transactions; forbidden recipient, excess cumulative spend and revoked session rejected | Experimental contract, not independently audited production custody |
| Portable capsule and actual isolated execution | 24 microVM cases; bounded multi-turn state; typed assertions and environment rejection checks | Deterministic fixture, no live AI model or trusted tool-enforcement proof |
| Public report artifacts and current-status check | Canonical report hash, HTML/SVG/metadata and dated credential readback | Current status can change; a credential is provenance rather than safety certification |

The exact evidence index and remaining gates are in [OFFICIAL_PILOT_2026-10-15.md](OFFICIAL_PILOT_2026-10-15.md). Self-generated transactions are engineering tests, not demand. The isolated-runner proof and the paid-delivery proof are separate experiments; a unified customer journey still needs verification.

## Why Stellar is part of the product

Soroban authorization and the custom account enforce actual session spending restrictions in the demonstrated path. The registry-bound escrow reads the designated validation and current source version before accepting a report or distributing SAC funds. The credential reads completed registry evidence and current identity. These cross-contract checks make version drift, report substitution and inconsistent settlement machine-rejectable rather than cosmetic report annotations.

The product therefore uses Stellar for authority, settlement and report lifecycle, with source and detailed evidence kept off-chain. It does not depend on promoting a collectible or storing arbitrary documents on-chain. Similar designs can exist on other programmable networks; the defensible benefit is a coherent workflow for Stellar builders, not an unsupported exclusivity claim.

## Proposed next sprint — agree scope and cost with the Chapter Lead

Do not request funding as reimbursement for the completed baseline above. The following is a proposed, bounded 30-day scope. The requested amount is **not finalized**: price the remaining work and provider costs, then agree an appropriate initial award with the Chapter Lead. No payroll rates, vendor quotations or measured margins have been invented.

| Window | Proposed deliverable | Acceptance evidence |
| --- | --- | --- |
| Days 1–5 | Freeze a supported agent adapter, input/retention contract, signed quote structure and failure policy | Reviewed scope; source/plan/asset commitments; known unsupported cases; rejection/refund criteria |
| Days 6–12 | Verify the hosted Standard journey, including wallet funding, isolated execution and report delivery | One reproducible complete run using the same report across runtime evidence, registry, escrow and credential; changed-plan and interruption tests; deployed HTTP transport evidence |
| Days 13–21 | Run consented trials with two external builder teams, if recruited | Versioned submissions, actual usage/support cost, permissioned feedback and reported failures; recruitment shortfalls explicitly recorded |
| Days 22–30 | Publish an evaluation and operating handover | Fixed positive/negative corpus, separate false-positive/false-negative counts, deployment/evidence index, demo and unresolved risk register |

The two-team objective is a target, not achieved traction. Restrict the sprint to Testnet and explicitly supported environments. A new live-model adapter should be included only if its model budget, synthetic fixtures and trusted observation can be completed within the agreed scope; otherwise retain it as a later milestone. Independent validator governance and production financial deployment are outside this first sprint.

## Proposed evidence packet

Provide the repository and commit, the exact Testnet evidence manifests, a short demo, reproducible commands, a truthful architecture/trust-boundary diagram, the scoped backlog and budget assumptions. These are our proposed review materials; the checked Instawards rules do not prescribe a universal video length, mandatory mainnet launch or fixed repository template. Agree the actual packet with the Chapter Lead.

Disclose AI-assisted development and distinguish model-generated hypotheses from tested observations. Present eight official specialist modules, not eight independent auditors. Show `needs_evidence` when that is the result; preserve known misses and unsupported integrations.

Applicant-supplied facts still needed: eligible applicant/team identity and representative, local chapter relationship, available contributors, consented pilot commitments, requested amount and agreed disbursement milestones. No values have been supplied or inferred for those fields.

## Official sources checked on 15 October 2026

- [Instawards overview](https://stellar.gitbook.io/scf-handbook/scf-awards/instawards)
- [Instawards official rules](https://stellar.gitbook.io/scf-handbook/scf-awards/instawards/official-rules)
- [SCF general submission rules](https://stellar.gitbook.io/scf-handbook/scf-awards/official-rules-for-submissions)
- [Stellar Community Fund](https://communityfund.stellar.org/)
- [Türkiye Chapter](https://stellar.gitbook.io/ambassador-program/chapters/europe-and-middle-east/turkiye-chapter)

The program remains documented on those official pages. This does not confirm a local invitation, available funding capacity or acceptance; recheck the rules with the chapter before submission.
