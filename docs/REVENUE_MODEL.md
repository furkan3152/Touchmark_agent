# Revenue model — pay for scope, never for a passing score

These are pilot hypotheses, not live sales offers. Public checkout stays closed until signed settlement and report delivery are verified end to end.

| Product | Proposed price | Scope | Cost discipline |
|---|---:|---|---|
| Quick check | Free | Bounded static review, evidence inventory, report download and local verification | Admission and input bounds; no default external AI spend |
| Release review | 49 USDC / version | Defined automated review, optional AI second opinion, one remediation rerun, report commitment | AI calls capped; exact source scope and exclusions agreed before payment |
| Team | 149 USDC / month | Five release reviews, source-change comparison, CI integration and notifications when implemented | 19 USDC per additional release; no unlimited usage |
| Specialist review | Separately quoted | Independent human review or authorized runtime work | Explicit scope, reviewer identity and delivery criteria |

## Economics to validate

At 49 USDC, a target of 8 USDC total variable cost would leave 41 USDC contribution, or 83.7%, before fixed expenses, tax and support. The 8 USDC is a **planning ceiling**, not a measured cost: for example 2 for model calls, 2 for compute/storage, and 4 for support and settlement overhead. Replace these estimates with measured pilot cost per completed review. Human security audits are not sustainably included at this price.

A fully used Team plan yields 29.80 USDC per included review. At the same 8 USDC variable-cost assumption, contribution is 109 USDC per month, or 73.2%, before fixed costs. Measure actual support load before committing to these prices. Model failures should not consume unlimited retries.

## Payment and delivery contract

1. Bind a quote to the input commitment, policy version, exact asset issuer/contract, amount, expiry and agreed scope.
2. A customer signs the funding invocation in their own wallet. Never request a seed or store a customer key.
3. Funds enter SAC escrow. Requester, provider and evaluator are separate roles.
4. Deliver a report hash and immutable locator, regardless of favorable or unfavorable findings.
5. Evaluator accepts delivery according to the agreed scope; payout and platform fee settle atomically.
6. Exercise the existing deadline/refund path if work is not accepted on time. Dispute resolution and evaluator independence must be clearly explained to customers.
7. Issue the report credential only from a completed registry validation. A paid invoice is never sufficient to mark an agent safe.

The current escrow's 15% fee is a marketplace accounting split, not automatically the software operator's gross margin. For a direct-service business, provider revenue and platform revenue may both belong to the business, but evaluator independence and role-separation rules still apply. No fictional paid auditor swarm or staking yield is claimed.

## Credential design

A unique, non-transferable Soroban report credential is bound to a completed validation request. It carries an owner, issuer, agent ID, version, metadata/endpoint commitments, report hash, score, issuance time and expiry. Owner or issuer can revoke it. Source changes and issuer removal invalidate current status. There is no transfer, approval or burn function.

This is a purpose-built NFT-like credential interface, **not a claim of SEP-41 fungible-token compliance or universal marketplace NFT compatibility**. Wallet display integration is separate work. The business charges for the review and ongoing evidence service, not a collectible or investment promise.

## Growth loop

Use the free review to demonstrate a concrete issue. Convert teams when they need release history and verification. Integrate with CI so a new source digest triggers a fresh review. Sell ongoing team workflow only when comparisons, quotas and notifications actually exist. Public verification of issued credentials should remain free to encourage reuse by Stellar agent marketplaces and operators.
