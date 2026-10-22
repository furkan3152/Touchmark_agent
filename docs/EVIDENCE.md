# Evidence

Touchmark is a security product, so every claim it makes about itself has to be
checkable. This page lists each claim, how to reproduce it, and who has verified it so
far. A claim marked **self-verified** has been checked only by this project.

## Claims ledger

| Claim | How to check it | Verified by | Status |
|---|---|---|---|
| The analysers classify the labelled corpora correctly: 46 cases, 28 TP, 18 TN, 0 FP, 0 FN | `python scripts/evaluate.py` → [`evidence/evaluation.json`](evidence/evaluation.json) (one row per case) | Project | Self-verified. The corpora were written by the maintainers and used during development, so this is a regression measure, not an independent accuracy estimate. |
| On 12 open-source Stellar agents, 199 reported findings were checked by hand: 161 true, 32 partly true, 5 false, 1 unverifiable. Strict precision is 0.81; counting partly true it is 0.97 | Repositories and commits, method, annotation and aggregate numbers: [`evidence/oss-study-commitment.json`](evidence/oss-study-commitment.json). The dataset hash can be recomputed with `scripts/evaluate.py --oss-dataset` | Project, one AI-assisted annotator | Self-verified. **Recall and false negatives are unknown** (there is no exhaustive ground truth), and there is no second annotator. The dataset holds unpublished vulnerabilities and is released after disclosure; its SHA-256 is published now so it cannot be changed later. |
| The credential contract refuses a score below 65, an unapproved or removed validator, and a changed agent | 57 Rust tests (`cargo test --workspace`), named in [ARCHITECTURE.md §3](ARCHITECTURE.md#contract-security-review-self-assessed) | Project | Self-verified on testnet and in unit tests. **Not externally audited. Not deployed on mainnet.** |
| Credentials are issued and read back on Stellar testnet | Demo registry and credential contracts in [`../deployments/demo-testnet.json`](../deployments/demo-testnet.json); every issuance links its four transactions | Ledger (public) | Verifiable by anyone on a testnet explorer |
| A credential is issued to the owner the repository names, and only after that owner signs | The owner's `reg_agent` and the validator's `req_valid`, `respond` and `issue` transactions are listed under `owner_flow_example` in [`../deployments/demo-testnet.json`](../deployments/demo-testnet.json). The credential reads back with the named owner. A registration signed by another account and an unsigned request were refused before submission (`backend/tests/test_demo_ownership.py`) | Ledger (public) and project | Testnet only. Shows control of the repository and of the key, not real-world identity. |
| An agent account enforces session spending limits | 7 testnet transactions in [`../deployments/agent-account-testnet-2026-10-15.json`](../deployments/agent-account-testnet-2026-10-15.json): an authorized transfer, then a forbidden recipient, an over-budget transfer and a revoked key all rejected | Ledger (public) | Testnet only; not externally audited |
| The automatic verifier agrees with hand labels: refutes 3 of 5 false findings, wrongly refutes 0 of 42 true ones, real-vs-false agreement 0.96, Cohen's κ 0.65, 5% unverifiable | `scripts/calibrate_verifier.py` → [`evidence/verifier-calibration.json`](evidence/verifier-calibration.json) (80 findings: all 38 non-true plus 42 random true ones). The first run, before the verifier was fixed, is kept in [`verifier-calibration-v1.json`](evidence/verifier-calibration-v1.json) (1 of 5, κ 0.31) | Project | Self-verified. The fixes were designed after seeing the 38 non-true findings, so those carry over from v1; the 42 true findings in v2 are a fresh sample. The hand labels themselves come from one annotator. |
| Compared with blind hand audits of 23 Stellar agents (13 seen during development, 10 never seen), two rounds. Round 2, after the fixes round 1 led to: of 281 hand-found issues Touchmark reports 246 (critical 8/8, high 61/64, medium 87/93, low 90/116; held-out recall 0.92), up from 220. 0.93 of its own findings are real (0.86 in round 1). With the decision rule in this repository, the pass / needs-fixes verdict matches the hand verdict on 23 of 23 agents in both rounds | Each repository was audited by hand without seeing Touchmark's output. A third reviewer opened the code to label every hand issue (found, weakly found, missed, wrong) and every Touchmark finding (true, extra, overstated, false, duplicate, generic); in round 2 it also re-checked the real defects round 1 found beyond the hand audit. Aggregates only; the rows hold unpublished vulnerabilities | Project, AI-assisted auditors and adjudicator | Self-verified. Round 2 ran before the last rule fixes, so its rule precision (0.73, 20 false) is measured before them; re-running the current rules on the same labels removes 9 of those 20 and loses no true finding. Model-review findings were 0.96 real. As run, round 2 passed one agent with a verifier-confirmed paywall bypass rated medium and left one undecided; the confirmed-bypass rule was added after seeing that, so the 23/23 is on data that informed the rule. |
| When Touchmark rates a finding critical or high, it is real: 75% of critical and 91% of high findings, up from 64% and 76%. Severity matches the hand audit exactly 62% of the time (was 50%) and within one level 95% | Replaying both comparison rounds with the current rules, the verifier's severity and consolidation: rule findings recomputed now, model findings and verifier verdicts from the saved runs. The labels and hand severities come from the adjudication. Decisions still match on 23 of 23 agents | Project | Self-verified, on data that informed the calibration. Round 1 shows the same direction (71% critical, 90% high). Real critical or high issues rated lower than by hand: 13 of 72 in round 2 (11 as run). An impact-fact severity model was tried and removed: it lowered exact agreement to 37%. |
| The same code audited twice gives the same decision | 6 agents re-audited with identical code: decision identical 6/6, score within 4.5 points, rule output identical, high and critical model findings reproduced 21 of 25 (84%), all model findings 40–74% by location | Project | Self-verified. Run-to-run variance sits in low and medium model findings, and in rule severities the verifier lowers by one level when it disputes them. |
| A rule finding the independent verifier refutes is lowered one level and marked disputed, never removed | `AuditSwarm._apply_disputes` and `backend/tests/test_false_alarms.py`: only rule findings, only when the verifier quotes a non-comment line that contradicts the claim | Project | Self-verified. Model-review findings are not lowered by a second model. |
| Real issues are found in real agents | Private reports to 9 maintainers (drafted, not yet sent) | — | **Not yet.** It counts as evidence only once maintainers confirm or fix. |

## Not claimed

- **No external audit.** No third party has audited the contracts or the analysers.
- **No adoption evidence.** The repository is new and not yet indexed by ecosystem
  directories; no outside team uses it yet.
- **No mainnet deployment.** All contract evidence is from testnet.
- **No runtime guarantee.** The analysis is static. A pass means that no actionable risk
  was found in the reviewed code; it does not mean the agent is safe.

## Evaluation method

- **Corpora (public).** Each case is a small agent bundle with a label (`flaw`) and, for
  flawed cases, the finding it must produce (`expected_finding`).
  - A flawed case counts only if that finding is reported.
  - A sound case is a false positive if any high or critical risk, or a `needs_fixes`
    decision, is reported.
- **Open-source study.**
  - Each repository was audited at a pinned commit.
  - Every reported finding was opened at its cited line and labelled TRUE, PARTIAL (real
    but overstated or narrower), FALSE or UNVERIFIABLE, with a written reason.
  - The labelled set is hashed as canonical JSON. The hash and aggregate numbers are
    public, and the rows are released after disclosure.
- **What would make these independent:** a corpus written by someone outside the project,
  a second annotator on the open-source study, and an exhaustive manual review of at
  least a few repositories to measure recall. These are milestones below.

## Evidence milestones

Each milestone is defined by the evidence it produces, so funding can be tied to proof
rather than to features.

| # | Deliverable | Evidence produced | Acceptance |
|---|---|---|---|
| 1 | **Coordinated disclosure** to the 9 maintainers with confirmed issues | Maintainer acknowledgements and fix commits; the study dataset released and matching the published hash | At least 3 maintainers confirm; the dataset hash matches |
| 2 | **Independent benchmark.** At least 30 agents labelled by an outside reviewer, including benign near-misses, plus an exhaustive manual review of 3 repositories | Public dataset, labelling guide and `evaluate.py` output, with precision, recall and false-positive rate | Results published whatever they are, misses included |
| 3 | **External contract audit** of AgentRegistry, AuditCredential, AuditEscrow and AgentAccount | Auditor's report and the fixes | All high and critical issues fixed or accepted in writing |
| 4 | **Governance hardening.** Multisig admin, admin transfer, a validator timelock, ids derived in the contract | Contract tests and a testnet deployment manifest | Tests for each open item in the contract security review |
| 5 | **Outside users.** At least 2 teams audit their own agents and act on the result | Consented before/after reports linked to their commits | Reports and fixes public, with the teams' consent |
