# Real-world fix benchmark

This benchmark holds 38 security or money defects that were fixed in public Stellar-ecosystem repositories:
16 development cases (`cases.json`) and 22 held-out cases (`test_cases.json`). Each case has two commits. The
vulnerable commit is the parent of the fix, and the report should flag the defect there. The fixed commit is the fix
itself, and the report should no longer flag the defect there. So far fixed commits have been audited for eight
held-out cases, the eight run first, chosen for impact before any result was known; the development set's fixed
commits have not been audited. The repositories' own fixes are the ground truth: a case only counts what the
maintainers changed, never what we think is wrong.

`../agents/` and `../labels/` hold the synthetic benchmark, which has planted defects and
decoys. This folder complements it with code that nobody wrote for us.

## Results

Each audit was submitted to the public demo (`run_live.py`) as a user would submit a repository: the GitHub folder
pinned to the commit, model review on, no hint about the case. Model: Claude Haiku 5.5 at medium effort. Every
report is published, one compact file per audit with the commit audited, the defect's lines, the findings that
matched them and all other findings: [`results/heldout`](results/heldout) (run 2),
[`results/heldout-run1`](results/heldout-run1) (run 1), [`results/dev`](results/dev),
[`results/dev-haiku`](results/dev-haiku); [`results/summary.json`](results/summary.json) holds the scores.

The held-out set was run twice. **Run 1** used the auditor of 1–2 November 2026; two infrastructure defects it
exposed were fixed during the run and the affected cases re-run (‡). **Run 2** used the final auditor (commit
`5afdb99`) for every case. Between the runs, the auditor learned to rate an operator's own model or API bills and
third-party API keys apart from funds and signing keys, to read signing and account-authority capabilities as
Stellar ones only, to cite the call site rather than a helper, and to refuse code comments as evidence; one lesson
(rounding direction) was added after run 1 missed `soroswap-pair-fee-floor-rounding` (◊).

| | Run 1 | Run 2 (final auditor) |
|---|---|---|
| Detected | **20 of 22** | **19 of 22** |
| Detected, without the 7 cases marked † | 13 of 15 | 11 of 14 (also without ◊) |
| Fixed commit clean | 6 of 8 | 2 of 3 |

Detected in at least one of the two runs: **21 of 22**. Run 2 missed two cases that run 1 found; the case both runs
missed was a near miss each time (¶). A single Haiku run is not deterministic, so a defect found once can be missed
the next time, and the other way round.

| Case | Repository | Run 1 | Run 2 | Fixed commit clean |
|---|---|---|---|---|
| `sdp-tss-unknown-outcome-unlock-double-pay` † | stellar-disbursement-platform-backend | yes | yes | yes |
| `sdp-sep24-get-transaction-cross-user` † | stellar-disbursement-platform-backend | yes | yes | yes |
| `sdp-payment-cancel-toctou-race` | stellar-disbursement-platform-backend | yes | **no** |  |
| `sdp-apikey-cache-cross-tenant` † | stellar-disbursement-platform-backend | yes | yes |  |
| `sdp-auth-tenant-header-fallback` † ‡ | stellar-disbursement-platform-backend | yes | yes |  |
| `go-recoverysigner-unverified-email` | stellar/go | yes | yes | yes (both runs) |
| `anchor-observer-asset-mismatch-credited` † | java-stellar-anchor-sdk | yes | yes | no § |
| `anchor-strict-send-sendamount-credited` † | java-stellar-anchor-sdk | yes | yes | yes |
| `anchor-sep10-threshold-sign-extension` | java-stellar-anchor-sdk | yes | **no** |  |
| `blend-backstop-share-inflation` | blend-contracts | yes | yes |  |
| `blend-self-liquidation-position-duplication` | blend-contracts | yes | yes |  |
| `soroswap-pair-fee-floor-rounding` ◊ | soroswap/core | **no** | yes |  |
| `soroban-mintlock-limit-not-pinned-to-token` | soroban-examples | yes | yes |  |
| `soroban-lp-deposit-slippage-check` | soroban-examples | yes | yes |  |
| `oz-vault-zero-share-deposit` | OpenZeppelin/stellar-contracts | yes | yes |  |
| `reflector-lastprice-stale` | reflector-contract | yes | yes |  |
| `anchor-server-withdraw-any-payment-completes` † | django-polaris | yes | yes |  |
| `polaris-multisig-deposit-stuck-pending-signatures` | django-polaris | yes | yes |  |
| `jssdk-readchallengetx-no-server-signature` | js-stellar-sdk | yes | yes | yes (both runs) |
| `jssdk-redirect-leaks-custom-auth-headers` | js-stellar-sdk | yes | yes | no (both runs) § |
| `walletsdk-sep10-domain-signer-swaps-tx` ‡ | typescript-wallet-sdk | yes | yes | yes |
| `walletsdk-recovery-duplicate-signers-lockout` | typescript-wallet-sdk | **no** ¶ | **no** ¶ |  |

- † **Not fully independent.** Three of the review's lessons (`unknown-outcome-unlock`, `cross-tenant-lookup`,
  `issuer-and-amount-received` in `backend/app/stellar/lessons.py`) were written with the held-out set in view after
  an earlier run on two of these cases. They are general Stellar rules, but they cover the seven cases marked †.
- ‡ `sdp-auth-tenant-header-fallback` was first missed because a file review cut off by the request time limit was
  never resumed (fixed in `DeepReviewer._unit_todo`); `walletsdk-sep10-domain-signer-swaps-tx` could not be audited
  at first because GitHub folders under `@scope/` were rejected (fixed in `agent_resolver`). Both were re-run;
  run 1 holds the re-runs.
- ◊ Missed in run 1: the fee is floored, so a small swap pays none. The rounding-direction lesson written after
  that miss is in the run 2 auditor, so run 2's detection of this case is not independent either.
- ¶ Both runs flag the same root cause (signer keys returned by recovery servers are added without validation) in
  the same file, 32 lines from the fixed range, outside the 10-line window.
- § The defect itself is no longer reported on the fixed commit, but a different finding sits within 10 lines and
  counts against clearing: for the anchor, deposits are still exempt from the asset check the fix added for
  withdrawals and SEP-31; for js-stellar-sdk, redirect hops are not checked against private addresses (SSRF).
- Fixed commits were audited for the eight cases run first in run 1, chosen for impact before any result was
  known; run 2 re-ran three of them before the deployment's daily token budget ran out.

**Development set (16 cases).** 11 detected with Claude Sonnet 5.5 before the lessons were added
([`results/dev`](results/dev)); **16 of 16** re-run with Claude Haiku 5.5 and the lessons
([`results/dev-haiku`](results/dev-haiku)). These cases were used to find and fix weaknesses, so they are not a
measure of accuracy on unseen code.

**Cost.** About $0.45 of model usage per audit, with prompt caching (from the operator's billing console; not
published).

## Files

| file | contents |
| --- | --- |
| `cases.json` | one entry per case (format below) |
| `test_cases.json` | the held-out set (below) |
| `run_live.py` | audits cases through a deployment's public API and saves the reports |
| `score_real.py` | scores report JSON files against `cases.json` (stdlib only; `--selftest`) |
| `results/heldout/` | held-out set: vulnerable and fixed commits (Claude Haiku 5.5, medium effort) |
| `results/dev/` | development set with Claude Sonnet 5.5, before the lessons were added |
| `results/dev-haiku/` | development set re-run with Claude Haiku 5.5 and the lessons |
| `results/summary.json` | the scores |

## Cases

| id | repo | lang | category | severity | confidence | audit targets |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp-charge-verify-fail-open` | stellar/stellar-mpp-sdk | typescript | unauthorized_payment | critical | high | [vulnerable](https://github.com/stellar/stellar-mpp-sdk/tree/06a65f543d245a064cf9804dcd4283b2e61f6ed2/sdk) / [fixed](https://github.com/stellar/stellar-mpp-sdk/tree/e235310d43b27830bf911c3b66b1452a8b84a28e/sdk) |
| `mpp-charge-feebump-uncapped` | stellar/stellar-mpp-sdk | typescript | economic_loss | high | medium | [vulnerable](https://github.com/stellar/stellar-mpp-sdk/tree/06dcf88a40bf65f0a547af2ee4fd45283154a84d/sdk) / [fixed](https://github.com/stellar/stellar-mpp-sdk/tree/bd5734dcf3d01c15e1a9e4bb2631cd70823c3769/sdk) |
| `mpp-charge-txhash-replay` | stellar/stellar-mpp-sdk | typescript | replay_or_idempotency | critical | medium | [vulnerable](https://github.com/stellar/stellar-mpp-sdk/tree/24d4a9877c2d62d2ec403f6aed20cb84e614802d/sdk) / [fixed](https://github.com/stellar/stellar-mpp-sdk/tree/06dcf88a40bf65f0a547af2ee4fd45283154a84d/sdk) |
| `x402-paywall-retry-resigns` | stellar/x402-stellar | typescript | unauthorized_payment | high | high | [vulnerable](https://github.com/stellar/x402-stellar/tree/a769bc99f8077d342edefbc586971a64154c83bb/packages/paywall) / [fixed](https://github.com/stellar/x402-stellar/tree/a4f19e5f9de9f7416b6590553dceda270c6dbca1/packages/paywall) |
| `asgcard-x402-proof-unverified` | ASGCompute/asgcard-public | typescript | unauthorized_payment | critical | high | [vulnerable](https://github.com/ASGCompute/asgcard-public/tree/d65ed2c8b3c362c3d585b065634a7f1f314fe602/api) / [fixed](https://github.com/ASGCompute/asgcard-public/tree/faca674c24e743dd8cb2f4b28b1aff97a1411499/api) |
| `passkey-update-signer-no-auth` | kalepail/passkey-kit | rust | account_takeover | critical | high | [vulnerable](https://github.com/kalepail/passkey-kit/tree/528926c32675900ec89c19d22934a33fa597ed1f/contracts/smart-wallet) / [fixed](https://github.com/kalepail/passkey-kit/tree/dcc6e3dc9cfd32e64b98f23541cd2d96812b64c4/contracts/smart-wallet) |
| `passkey-sample-policy-per-tx-cap` | kalepail/passkey-kit | rust | economic_loss | high | medium | [vulnerable](https://github.com/kalepail/passkey-kit/tree/73807666f073f08117b0f403f5ded8b846309f9c/contracts) / [fixed](https://github.com/kalepail/passkey-kit/tree/0563520401018a584edf482dd3d4216a5a4a035c/contracts) |
| `oz-delegated-signer-invoker-bypass` | OpenZeppelin/stellar-contracts | rust | control_bypass | critical | high | [vulnerable](https://github.com/OpenZeppelin/stellar-contracts/tree/9cfddbb5b0d158f5ec948d0ad6767383d629d1c4/packages/accounts) / [fixed](https://github.com/OpenZeppelin/stellar-contracts/tree/8e2522065e9bdff639d0532eac03e374af8723f4/packages/accounts) |
| `oz-fee-abstraction-eager-allowance` | OpenZeppelin/stellar-contracts | rust | economic_loss | high | high | [vulnerable](https://github.com/OpenZeppelin/stellar-contracts/tree/7485b449ba0771204b6c0fb3f09f731b499e9580/packages/fee-abstraction) / [fixed](https://github.com/OpenZeppelin/stellar-contracts/tree/7b44552421b1bf772345c6da01826d689a4443cf/packages/fee-abstraction) |
| `one-way-channel-funder-auth` | stellar-experimental/one-way-channel | rust | stellar_protocol_misuse | high | high | [vulnerable](https://github.com/stellar-experimental/one-way-channel/tree/15485466954db234901044f6fcaf3b91d25c0408/contracts) / [fixed](https://github.com/stellar-experimental/one-way-channel/tree/25dea1b303495a7a4184af7605bbb7671ff08da6/contracts) |
| `soneso-sep7-params-after-signature` | Soneso/stellar-agent-wallet | rust | control_bypass | high | high | [vulnerable](https://github.com/Soneso/stellar-agent-wallet/tree/12fb13459f53150a5b669ac55a33cb448a556754/crates/stellar-agent-sep7) / [fixed](https://github.com/Soneso/stellar-agent-wallet/tree/2e74815c0fa3a467954349f4e210aaafc79b94d5/crates/stellar-agent-sep7) |
| `sdp-tss-feebump-replaced-double-pay` | stellar/stellar-disbursement-platform-backend | go | replay_or_idempotency | critical | high | [vulnerable](https://github.com/stellar/stellar-disbursement-platform-backend/tree/b86bb22d469c9a6197ed11f6900ed4bc5104572c/internal/transactionsubmission) / [fixed](https://github.com/stellar/stellar-disbursement-platform-backend/tree/a8af579bc93b719abc2035c7b392810d457e5cf4/internal/transactionsubmission) |
| `sdp-payment-amount-6dp` | stellar/stellar-disbursement-platform-backend | go | stellar_protocol_misuse | medium | high | [vulnerable](https://github.com/stellar/stellar-disbursement-platform-backend/tree/b860c4d58d0091a9ea2170870322088f5417dcdd/internal/transactionsubmission) / [fixed](https://github.com/stellar/stellar-disbursement-platform-backend/tree/5c697f3d3d6b3dafbf11babbe402ed582afd5991/internal/transactionsubmission) |
| `sdp-sep10-no-client-signature` | stellar/stellar-disbursement-platform-backend | go | control_bypass | critical | high | [vulnerable](https://github.com/stellar/stellar-disbursement-platform-backend/tree/05fc5bc2417f8bc6e46c9e29b031b250ab07a7e0/internal/services) / [fixed](https://github.com/stellar/stellar-disbursement-platform-backend/tree/db38aaf9d2eae38ca2017635357ac8a1873076cf/internal/services) |
| `sdp-sponsored-tx-foreign-authorizer` | stellar/stellar-disbursement-platform-backend | go | economic_loss | high | high | [vulnerable](https://github.com/stellar/stellar-disbursement-platform-backend/tree/e8fab3882c7605758d5ac3ee16aea0488c0998d9/internal/transactionsubmission) / [fixed](https://github.com/stellar/stellar-disbursement-platform-backend/tree/76627dfb16d2a3058437aa2e26d6db81d81d1400/internal/transactionsubmission) |
| `polaris-trustline-stuck-execution` | stellar/django-polaris | python | reliability_failure | medium | medium | [vulnerable](https://github.com/stellar/django-polaris/tree/fb462ab62fb9f7bfdef4dca24c34af2526ce2ebd/polaris/polaris) / [fixed](https://github.com/stellar/django-polaris/tree/a0770a12518ec386aedd81963873951ddc578276/polaris/polaris) |

The 16 cases come from 9 repositories and 4 languages: TypeScript 5, Rust 6, Go 4 and Python 1.
12 are high confidence and 4 are medium. Every audited subdir has at most 73 non-test source files and at most 156 files in total
(the largest is django-polaris).

## How the cases were found

1. We cloned the candidate repositories with `git clone --filter=blob:none`. These were
   stellar/x402-stellar, stellar/stellar-mpp-sdk, kalepail/passkey-kit,
   kalepail/stellar-mcp-server, JoseCToscano/stellar-mcp,
   ASGCompute/asgcard-public, stellar-experimental/stellar-raven, Soneso/stellar-agent-wallet,
   OpenZeppelin/stellar-contracts, theahaco/scaffold-stellar and coinbase/x402. We also cloned
   repositories that their READMEs or a GitHub search pointed to:
   stellar-experimental/one-way-channel, kalepail/smart-account-kit, kalepail/superpeach,
   StellarCN/py-stellar-base, stellar/django-polaris and
   stellar/stellar-disbursement-platform-backend.
2. We searched every repository's history with `git log --all -E -i --grep` for
   fix|secur|vuln|validat|check|limit|replay|auth|signature|sanitiz|inject|overflow|race|double|
   idempot|issuer|network|passphrase|expir|nonce|leak|secret. We also read merged PRs titled as
   fixes and audit-remediation commits (for example "Nemesis audit", "Bug Finder", HackerOne,
   "Merge commit from fork").
3. We read each candidate diff and the code before it (`git show SHA^:path`). Every line range
   in `cases.json` was checked against the file at the stated commit. `files` holds ranges in
   the vulnerable commit, and `fixed_files` holds the corresponding ranges in the fixed commit.

## Inclusion rules

A case was kept only when all of the following hold:

- The code before the fix has a concrete, reachable defect of a kind the auditor targets:
  unbounded or unauthorized payment, missing auth or `require_auth`, signing external XDR or
  auth entries without checks, replay or double payment, wrong units, fee or sponsorship abuse,
  a verification that fails open, or state stuck after a failure.
- The fix commit addresses exactly that defect. Its message or PR explains it, and the code
  change removes it.
- The commit is not a refactor, typo, documentation, dependency or test-only change.
- `vulnerable_commit` is the first parent of `fixed_commit` (for a merge, the parent on the
  main line). Both commits are public on GitHub, so the tree URLs above resolve.

We rejected these candidates:

- The fix only adds defence in depth on code that was not exploitable before, such as
  coinbase/x402 #3336 (feeBumpSigner in the safety set) and stellar-mpp-sdk #64 (the RPC
  commitment was already bound-checked), together with e8ca65b.
- The fix leaves the same attack open, such as stellar-mpp-sdk #38, where the sender check
  trusts a credential `source` field the attacker sets. The real fix came later with signed
  push credentials.
- The defect sits in operator-only configuration, such as coinbase/x402 #2530 (parsing the
  operator's price string).
- The impact is cosmetic or limited to UX.

`confidence: medium` marks one of two situations. Either the fix is partial, so the fixed
commit keeps a nearby, related weakness (each such case says so in `notes`), or the impact is
reliability rather than loss of funds.

## Case format

```json
{"id": "...", "repo": "owner/name", "subdir": "path/audited",
 "vulnerable_commit": "<40-hex>", "fixed_commit": "<40-hex>",
 "language": "typescript|rust|go|python",
 "category": "<deep_review.CATEGORIES key>", "accept_categories": ["..."],
 "severity_estimate": "critical|high|medium|low",
 "files": [{"path": "relative/to/subdir", "line_start": 1, "line_end": 9}],
 "fixed_files": [{"path": "...", "line_start": 1, "line_end": 9}],
 "summary": "...", "fix_summary": "...", "evidence_url": "commit or PR URL",
 "confidence": "high|medium", "notes": "optional"}
```

`accept_categories` lists other categories a correct finding could reasonably be filed under,
for example `unauthorized_payment` for an incoming-payment check that fails open. They are
used only for clearing (below) and for `--require-category`.

## Running the audits

`python3 run_live.py vulnerable` (or `fixed`) audits every case through the public demo; add case ids to run a few,
`--cases test_cases.json` for the held-out set and `--out DIR` for the report folder. Or, for each case, audit both
`https://github.com/<repo>/tree/<vulnerable_commit>/<subdir>` and
`https://github.com/<repo>/tree/<fixed_commit>/<subdir>`, and save the report JSON as
`<case_id>.vulnerable.json` and `<case_id>.fixed.json` in one directory. Audit only the
subdir, never the whole repository. Give the auditor no hint about the case.

## Scoring

```
python3 score_real.py --reports DIR            # text summary and per-case results
python3 score_real.py --reports DIR --json     # machine-readable
python3 score_real.py --selftest
```

The script reads the Touchmark report format:

- top-level `findings`, each with `evidence` holding `path:line` or `path:start-end`, or with
  `file` and `line`. Findings whose `kind` is `evidence_gap`, `warning`, `info` or `pass`, or
  whose `is_risk` is false, are ignored.
- `deep_review.ledger.checks` with `id`, `verdict`, `file` and `line`. Only `verdict: "fails"`
  counts. A check's category comes from `audit_ledger.CATALOG`.

Saved job results that nest the report under `report` or `report_json` are unwrapped. Paths
are taken as relative to the audited subdir. A leading `./`, `<subdir>/` or `<repo>/<subdir>/`
is stripped, and suffix matches count.

- **Detects:** the vulnerable-commit report has at least one risk finding or failing ledger
  check citing a listed file within 10 lines of a `files` range. Category is ignored unless
  `--require-category` is set.
- **Clears:** the fixed-commit report has no risk finding or failing check, of the case's
  `category` or `accept_categories`, citing a `fixed_files` range within 10 lines. A finding
  with no category counts against clearing. With `--strict-clear`, a finding of any category
  counts. This makes the rule "no such finding remains" literal, but then unrelated findings
  that happen to sit nearby fail the case.
- The script prints the detection rate (overall, high-confidence only, and critical/high
  only), the clear rate (overall and among detected cases), the count of pairs that are both
  detected and cleared, the per-case hits with their cited locations, and any missing report
  files. `--window N` changes the 10-line tolerance.

A report that flags everything near the defect on both commits detects the case but does not
clear it. Read the detection rate together with the clear rate.

## Caveats

- Some vulnerable commits contain comments that hint at the defect. Examples are the TODO
  "payment proof is accepted at face value" in `asgcard-x402-proof-unverified` and the "FIX-n"
  remarks in the passkey-kit sample policy. These are the projects' own comments and were left
  as they are. Detection on these cases is easier than on the others.
- `sdp-sponsored-tx-foreign-authorizer`: at the fixed commit the validator lives in
  `internal/utils`, which is outside the audited subdir. A report may answer
  "cannot determine" there.
- Several cases are in libraries or SDKs rather than standalone agents (mpp-sdk, OpenZeppelin,
  one-way-channel). The auditor still sees code that verifies or moves value, but its
  operating-model step may be less certain.

## Held-out test set

`test_cases.json` holds a separate **held-out test set** of 22 cases in the same format as `cases.json`.
**These cases must never be used to tune the auditor**: not its prompts, catalog, checks, thresholds or examples, and not
to pick between auditor versions during development. Run them only to measure a frozen auditor, and do not copy their
summaries, file names or code into anything the auditor sees. Tune on `cases.json` only.

Score them with `python3 score_real.py --cases test_cases.json --reports DIR`.

| id | repo | lang | category | severity | confidence |
| --- | --- | --- | --- | --- | --- |
| `sdp-tss-unknown-outcome-unlock-double-pay` | stellar/stellar-disbursement-platform-backend | go | replay_or_idempotency | critical | high |
| `sdp-sep24-get-transaction-cross-user` | stellar/stellar-disbursement-platform-backend | go | cross_user_access | medium | high |
| `sdp-payment-cancel-toctou-race` | stellar/stellar-disbursement-platform-backend | go | reliability_failure | medium | medium |
| `sdp-apikey-cache-cross-tenant` | stellar/stellar-disbursement-platform-backend | go | cross_user_access | critical | high |
| `sdp-auth-tenant-header-fallback` | stellar/stellar-disbursement-platform-backend | go | cross_user_access | high | high |
| `go-recoverysigner-unverified-email` | stellar/go | go | account_takeover | critical | high |
| `anchor-observer-asset-mismatch-credited` | stellar/java-stellar-anchor-sdk | java | unauthorized_payment | critical | high |
| `anchor-strict-send-sendamount-credited` | stellar/java-stellar-anchor-sdk | java | unauthorized_payment | critical | high |
| `anchor-sep10-threshold-sign-extension` | stellar/java-stellar-anchor-sdk | java | control_bypass | high | high |
| `blend-backstop-share-inflation` | blend-capital/blend-contracts | rust | economic_loss | high | high |
| `blend-self-liquidation-position-duplication` | blend-capital/blend-contracts | rust | economic_loss | high | medium |
| `soroswap-pair-fee-floor-rounding` | soroswap/core | rust | economic_loss | medium | medium |
| `soroban-mintlock-limit-not-pinned-to-token` | stellar/soroban-examples | rust | unauthorized_payment | high | high |
| `soroban-lp-deposit-slippage-check` | stellar/soroban-examples | rust | economic_loss | medium | high |
| `oz-vault-zero-share-deposit` | OpenZeppelin/stellar-contracts | rust | economic_loss | high | medium |
| `reflector-lastprice-stale` | reflector-network/reflector-contract | rust | economic_loss | medium | medium |
| `anchor-server-withdraw-any-payment-completes` | stellar/django-polaris | python | unauthorized_payment | critical | high |
| `polaris-multisig-deposit-stuck-pending-signatures` | stellar/django-polaris | python | reliability_failure | medium | medium |
| `jssdk-readchallengetx-no-server-signature` | stellar/js-stellar-sdk | typescript | control_bypass | medium | high |
| `jssdk-redirect-leaks-custom-auth-headers` | stellar/js-stellar-sdk | typescript | secret_exposure | medium | medium |
| `walletsdk-sep10-domain-signer-swaps-tx` | stellar/typescript-wallet-sdk | typescript | foreign_transaction_signing | high | high |
| `walletsdk-recovery-duplicate-signers-lockout` | stellar/typescript-wallet-sdk | typescript | reliability_failure | high | medium |

The 22 cases come from 11 repositories and 5 languages: Rust 7, Go 6, TypeScript 4, Java 3 and Python 2.
14 are high confidence and 8 are medium. Every audited subdir has at most 153 files in total
(the largest is `polaris/polaris`). `language` gains the value `java` for the anchor-platform cases.

### Sources and how they were found

The same method as above: `git clone --filter=blob:none` (stellar/go with `--filter=tree:0`), message search with
`git log -i -E --grep` over fix|secur|vuln|auth|signature|replay|double|race|overflow|validat|check|limit|issuer|
threshold|nonce|expir|reentr|underflow|round|HackerOne|GHSA|audit, reading every candidate diff and the code before it,
and checking every line range with `git show SHA:path` at both commits (`files` at the vulnerable commit,
`fixed_files` at the fixed commit). `vulnerable_commit` is always the first parent of `fixed_commit`.

Repositories: stellar/stellar-disbursement-platform-backend (PRs #1208, #1115, #1245, #1142, #1205),
stellar/java-stellar-anchor-sdk (anchor platform, HackerOne fixes #1967, #1973, #1987), stellar/go
(exp/services/recoverysigner), blend-capital/blend-contracts (audit fixes #195, #196), soroswap/core (#155),
stellar/soroban-examples (#289, #297), OpenZeppelin/stellar-contracts (#883, vault package only),
reflector-network/reflector-contract (OtterSec audit revision), stellar/django-polaris (including the earlier
stellar-anchor-server code in its history), stellar/js-stellar-sdk (GHSA-6cgh-hjpw-q3gq, #1814) and
stellar/typescript-wallet-sdk (#237, #255).

No (repo, fix commit) pair overlaps `cases.json`. Three repositories also appear in the development set
(stellar-disbursement-platform-backend, django-polaris and OpenZeppelin/stellar-contracts); the shared
SDP cases are different defects, and `sdp-tss-unknown-outcome-unlock-double-pay` sits in the same file
(`transaction_worker.go`) as a development case. `sdp-sep24-get-transaction-cross-user` uses as its vulnerable
commit the fixed commit of the development case `sdp-payment-amount-6dp`; the pair is different.

Also searched and rejected (no case kept): py-stellar-base SEP-10 and auth fixes (hardening or functional only),
stellar-mpp-sdk and x402-stellar remaining fixes (operator configuration, UX or already rejected above),
coinbase/x402 (Stellar changes only arrive in squashed upstream syncs), freighter (UX or rendering fixes whose code
is spread over a large UI tree), js-stellar-base, Albedo, Stellar-Wallets-Kit, smart-account-kit, soroswap
burn/klast changes, Blend rounding of one stroop, OZ NFT and SAC-admin fixes (DoS or functional), several
anchor-platform hardening fixes (operator-dependent or bounded impact), and the key-manager twin of
`walletsdk-sep10-domain-signer-swaps-tx` (typescript-wallet-sdk #245; same defect, callback supplied by the integrator).

### Caveats

- `anchor-server-withdraw-any-payment-completes` has a TODO in the vulnerable code that names the missing check.
- Several fixed commits keep the related checks partly outside the audited subdir:
  `sdp-sep24-get-transaction-cross-user` (query in `internal/data`), `sdp-payment-cancel-toctou-race` (caller in
  `internal/services`) and `anchor-strict-send-sendamount-credited` (listener in `platform/`).
- Blend, OpenZeppelin and Reflector fix commits are single-parent commits on merged branches. They are reachable
  from the default branch but not on its first-parent line. `soroswap-pair-fee-floor-rounding` is a merge commit
  scored against its first parent.
- Medium-confidence cases either rest on our own reasoning about exploitability (`blend-self-liquidation-...`,
  `oz-vault-zero-share-deposit`), need a misbehaving third party (`jssdk-redirect-...`, `walletsdk-recovery-...`),
  have reliability rather than direct loss as impact, or are dust-level rounding (`soroswap-...`); see `notes`.
- The TypeScript and Python counts are below the 6 and 3 we aimed for. Few public Stellar TypeScript or Python
  repositories had fixes that met the inclusion rules.
