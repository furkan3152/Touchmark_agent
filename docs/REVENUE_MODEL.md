# Revenue model — official review, priced by scope

Updated 15 October 2026. This is the current pricing proposal and supersedes the older free/release/subscription hypotheses. The catalogue explicitly sets `checkout_enabled: false` and prices `live: false`. No customer revenue, paying users or production checkout is claimed.

## Three proposed tiers

| Tier ID | Product name | Proposed price per review | Testnet quote | Runtime ceiling |
| --- | --- | ---: | ---: | ---: |
| `quick` | Preview | USD 3 | 0.1 faucet XLM | 0; source review only |
| `standard` | Assurance | USD 19 | 1 faucet XLM | Up to 12 isolated cases |
| `deep` | Deep | USD 49 | 3 faucet XLM | Up to 24 isolated cases |

Testnet amounts are functional test quotes, not USD conversions or real monetary prices. The real delivery pilot settled 1 faucet XLM for a bounded static fixture report. It did not establish a production sale or verify every Standard/Deep customer journey. Production asset, issuer/contract, tax treatment and payment terms remain launch decisions.

Every tier runs the baseline source rules and returns a scoped downloadable report. Selecting specialists changes focus and runtime case families; it cannot suppress baseline findings. Standard and Deep require a supported Python entrypoint, a reviewed source-bound plan, explicit execution consent and an enabled isolated runner. Actual cases may be fewer than the ceiling. The catalogue budgets one optional AI second opinion per review; it requires a configured provider and explicit external-processing consent. It is not eight separately operated model audits.

## Eight official specialists

The selectable modules are Intent Analyst (`intent`), Adversarial Examiner (`injection`), Authority Inspector (`tools`), Privacy Examiner (`privacy`), Treasury Inspector (`financial`), Reliability Examiner (`resilience`), Soroban Inspector (`stellar`) and Provenance Examiner (`provenance`). All belong to **Veritas Official**, operated by one platform team. They organize seven baseline source-analysis dimensions. Stellar and provenance modules do not have text behavior packs.

Independent organizations, operator admission, adjudication and multi-operator execution are a later phase. Separate signer keys in the pilot do not make its provider and evaluator independent businesses.

## What the business earns

For the initial direct-service model, the business charges for the agreed review workload and delivery, regardless of whether the report is favorable. No paid removal of findings or security guarantee is included.

The escrow's 15% fee is an **internal allocation**, not the operator's gross margin and not demonstrated income for external validators. In the completed first-party Testnet pilot, 1 XLM was distributed as 0.85 XLM to the official provider and 0.15 XLM to the official treasury; both were controlled by the same operator. This was faucet currency, so it produced no real revenue.

For planning, total first-party service receipts must be counted once. Track refunds, model usage, microVM seconds, storage/egress, support, payment fees and other operating costs separately. Record actual cost per completed tier before estimating contribution margin. No measured unit-cost, margin, customer-volume or recurring-revenue forecast exists yet. Human security review is separately scoped; it is not silently included in USD 3/19/49 automated pricing.

Subscriptions, CI monitoring and an independent-reviewer marketplace may follow demonstrated demand. They are not current paid offers.

## Payment and report delivery

1. Present an expiring quote bound to the exact source, policy, tier, specialist selection, asset contract and integer amount. A prepared plan is not an invoice or proof of funding.
2. Obtain the customer's authorization through their wallet. The disposable Testnet script is not a production customer-key custody design.
3. Create the registry validation request and use that same request ID as the bound escrow job ID. Requester, provider and evaluator addresses must be distinct.
4. Fund escrow, perform the agreed work and publish the exact report bytes. Missing evidence and unfavorable findings remain deliverable outcomes.
5. Submit the report content hash. The escrow checks the assigned registry validator, completed validation, current source version and matching hash; completion also matches the registry score.
6. Settle through evaluator authorization, or use the tested dispute/refund paths. Explain first-party evaluation and acceptance/refund criteria before charging.
7. Deliver JSON plus readable HTML and a report credential when a registry assertion has actually been issued. Verify credential status live; verify payment status from escrow separately.

## Credential and launch boundaries

The Soroban credential is non-transferable and version-bound. Its report hash, owner, issuer, expiry and current status support provenance. It is not an investment product, a transferable collectible, an automatic safety certification or a claim of universal wallet NFT compatibility. Public report verification should remain free.

Before real paid use: verify wallet checkout and the deployed HTTP-to-runtime route together; test tenant isolation, quotas, crash/retry recovery and refund reconciliation; measure costs; document source retention and AI processing; obtain independent review of consequential contracts and operating controls. Use [the official pilot record](OFFICIAL_PILOT_2026-10-15.md) for evidence and gaps. The current release is a private pilot, not production-ready security infrastructure.
