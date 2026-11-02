# Benchmark results (historical)

These runs are kept for the record. They used Claude Sonnet 5.5, before the review's lessons were added and before
the demo moved to Claude Haiku 5.5, and have not been repeated with the current configuration. Current results on
real defects are in [real/README.md](real/README.md).

Live demo (touchmark-stellar.vercel.app, check-ledger mode, Claude Sonnet 5.5), 2026-11-01. Each agent
was audited by its GitHub tree URL with the model review consented; three agents were audited
twice to measure run-to-run agreement. `score.py` matches a finding to a planted defect by file
and line (within 5 lines).

| agent | language | runs | recall (by location) | recall@high | decoy false positives |
| --- | --- | --- | --- | --- | --- |
| invoice-settler | Python | 2 | 3/3, 3/3 | 1.00 | 0 |
| treasury-mcp | TypeScript | 2 | 3/3, 3/3 | 1.00 | 0 |
| payout-relay | Go | 1 | 1/1 | n/a | 1 (see below) |
| escrow-agent | Java | 1 | 3/4 | 0.75 | 0 |
| swap-desk | Kotlin | 2 | 2/3, 3/3 | 1.00 | 0 |
| payroll-agent | C# | 1 | 3/3 | 1.00 | 0 |
| **all 9 runs** | | | **0.92** | **0.95** | **1 hit in 22 decoy checks (0.05)** |

Notes from reading every miss and false positive:

- **The two misses were found, but cited at another line.** Kotlin KT-D3 (unchecked submit result)
  was answered as a failing check S5 at the right line and linked to an earlier finding that
  cited the debit line; Java JV-D4 (unauthenticated delivery webhook) was a failing check A1 at
  `ApiKeyFilter.java:33`, linked to the LLM-recipient finding. Since then a failing check adds its
  own line to the finding it links to, so both are reported at the planted location.
- **The one decoy hit is not a false claim.** It is 1 of the 15 distinct decoys, hit in one run. The finding on payout-relay's receipts route does not
  claim path traversal (the decoy); it says the route needs no authentication and returns creator
  ids and amounts, which is true and was noted as an unlabelled real issue when the agent was
  written. It is rated low.
- **Unlabelled findings** (11 at medium) are mostly incidental real defects of the benchmark code:
  budgets kept only in memory, a monthly counter that never resets, deposits not bound to the
  sender, per-call caps with no cumulative budget.
- **Agreement between runs.** Matched defects: identical on invoice-settler and treasury-mcp,
  2/3 vs 3/3 on swap-desk. Check by check, 59 of 64 ledger answers were the same in both runs;
  the five that differed were borderline judgements (asset handling V5 and network pinning S3
  holds vs fails, tenant isolation A3 not applicable vs fails) and one check (A6) that applied in
  one run only because the file map recorded an outbound call in one run and not the other.
- Every file of every agent was mapped (5-7 files each), every applicable check was answered, and
  each audit cost about 0.5 USD.

## Second round: Stellar criteria in the ledger (same day)

Each ledger pass now carries the Stellar reference text of its checks, and asset identity (V5),
network pinning (S3) and tenant isolation (A3) state when they hold, fail or do not apply. The two
agents whose answers had changed were audited twice more:

| agent | check answers identical, before | after | V5 / S3 / A3 identical after | matched defects identical |
| --- | --- | --- | --- | --- |
| swap-desk (Kotlin) | 18/21 | 21/21 | 3/3 | yes (was 2/3 vs 3/3) |
| treasury-mcp (TypeScript) | 19/21 | 18/21 | 3/3 | yes |

All four runs found every planted defect (with the evidence fix) and hit no decoy. The three
answers that still changed on treasury-mcp were generic checks (V8 and M3: not applicable or not;
A4); not-applicable is now reserved for capabilities absent from the submitted code.

On-chain controls: with a .tmark naming a testnet account whose payments need two of two signers
(master weight 0), the account was read from Horizon (`onchain_authority.account`: found,
`multisig_required_for_payments: true`). The review did not credit the co-signer requirement on
invoice-settler, because that code signs with one key from the environment, which is the
intended behaviour: the fact counts only for code that signs from that account.
