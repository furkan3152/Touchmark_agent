<p align="center">
  <img src="frontend/brand/mark.svg" width="88" alt="Touchmark">
</p>

<h1 align="center">Touchmark</h1>

<p align="center">
  <strong>Security audits for AI agents that hold Stellar authority.</strong><br>
  Touchmark reads an agent's code in any language, checks it against Stellar-specific criteria, has an
  independent model call re-check each medium-or-higher finding, and records a passing result on Stellar as a non-transferable
  credential.
</p>

<p align="center">
  <a href="https://usetouchmark.app"><img src="https://img.shields.io/badge/Live_demo-usetouchmark.app-1d2b4f?style=for-the-badge" alt="Live demo"></a>
  <img src="https://img.shields.io/badge/Stellar-Testnet-e2432a?style=for-the-badge&logo=stellar&logoColor=white" alt="Stellar testnet">
  <a href="https://github.com/furkan3152/Touchmark_agent/actions/workflows/verify.yml"><img src="https://img.shields.io/github/actions/workflow/status/furkan3152/Touchmark_agent/verify.yml?branch=main&style=for-the-badge&label=CI" alt="CI"></a>
  <a href="https://github.com/furkan3152/Touchmark_agent/actions/workflows/ledger.yml"><img src="https://img.shields.io/github/actions/workflow/status/furkan3152/Touchmark_agent/ledger.yml?branch=main&style=for-the-badge&label=Ledger%20proof" alt="Ledger proof"></a>
  <img src="https://img.shields.io/badge/License-Apache_2.0-1f7a5a?style=for-the-badge" alt="License">
</p>

<p align="center">
  <a href="public/media/touchmark-how-to.mp4"><img src="frontend/brand/video-poster.jpg" width="640" alt="Watch: how to use Touchmark"></a><br>
  <sub>▶ <a href="public/media/touchmark-how-to.mp4">How to use Touchmark</a> (1½ min)</sub>
</p>

## Why Stellar needs this

AI agents on Stellar now hold keys, sign XDR, pay x402 and MPP (Machine Payments Protocol) invoices,
authenticate with SEP-10 and drive Soroban contracts. The defects that lose money there are Stellar-specific: a fee bump that lets a payment land
twice, an asset matched by code without its issuer, a path payment credited with the amount sent instead of the
amount received, a SEP-10 verifier that counts the server's own signature, a delegated `__check_auth` signer
satisfied by the invoker. General code scanners do not know these rules. Touchmark is built around them, and
gives the ecosystem a shared, on-chain answer to one question: *has someone checked this agent before it gets
keys?*

## Measured on real Stellar defects

Every case is a security defect that maintainers **fixed upstream** in a public Stellar repository. The audit runs
on the vulnerable commit through the public demo, exactly as a user would. It counts as detected when a risk
finding or failing check cites the defective lines (within 10 lines); the category need not match. Ground truth is
the maintainers' fix, not our opinion.

| Set | Repositories | Detected |
|---|---|---|
| **Held-out: not used to build the auditor** (Claude Haiku 5.5, medium effort; 7 cases later informed lessons, see below) | stellar-disbursement-platform-backend, stellar/go, java-stellar-anchor-sdk, blend-contracts, soroswap/core, soroban-examples, OpenZeppelin stellar-contracts, reflector-contract, js-stellar-sdk, typescript-wallet-sdk, django-polaris | **20 of 22** in run 1, **19 of 22** in run 2 (auditor at `5afdb99`); **21 of 22** found in at least one run |
| Development: used to find and fix weaknesses | stellar-mpp-sdk, x402-stellar, asgcard-public, passkey-kit, OpenZeppelin stellar-contracts, one-way-channel, stellar-disbursement-platform-backend, django-polaris, Soneso stellar-agent-wallet | 11 of 16 with Sonnet 5.5 before the lessons; 16 of 16 re-run with Haiku 5.5 and the lessons |

- A single run is not deterministic: two of the three cases run 2 missed were found in run 1; the
  third is a near miss in both runs (the right root cause, 32 lines from the fixed lines). Seven held-out
  cases are covered by lessons written with that set in view; without them, 13 of 15 (run 1) and 11 of 14 (run 2)
  were detected. Later changes to scoring and rules (after `5afdb99`) have not been re-measured on this set.
- **Fixed commits** were audited for eight cases: 6 reports no longer flag the defect's lines; the other two flag a
  different issue next to them. Every result and caveat is in the [results](research/benchmark/real/README.md#results).
- **Cost:** about **$0.45 of model usage per audit** on these repositories (Claude Haiku at medium effort, with prompt
  caching); about $0.08 for a one-file agent such as the demo examples.
- Every case links the vulnerable and fixed commits, and every report is published, so each result can be checked
  line by line: **[research/benchmark/real](research/benchmark/real/README.md)**. Re-run any case with
  `run_live.py` and score it with `score_real.py`.

## Try it

**[usetouchmark.app](https://usetouchmark.app)**: paste a GitHub repository or folder
pinned to a commit, a `C…` contract, a `G…` account or a registry agent id, and tick the model review.

| An unsafe agent: not yet | The same agent, fixed: touchmarked on Stellar |
|---|---|
| <img src="docs/media/demo-unsafe.png" alt="Unsafe treasury agent: not yet" width="420"> | <img src="docs/media/demo-credential.png" alt="Fixed treasury agent: credential on testnet" width="420"> |

Each finding shows the line it cites and whether the verifier confirmed it, plus a **check ledger** that
answers, question by question, what the code protects and what it does not. Fix, re-audit, and the owner signs
the credential in Freighter.

## How an audit works

```mermaid
flowchart LR
    R["Reference"] --> P["Pin the commit"]
    P --> MAP["Map each selected file<br/>any language"]
    MAP --> LEDGER["Check ledger<br/>28 questions"]
    LEDGER --> CH["Challenge<br/>'holds' answers"] --> UNIT["Focused review of each<br/>file that signs, pays or verifies"]
    UNIT --> VER["Independent verifier"]
    VER --> DEC["pass · needs_fixes ·<br/>needs_evidence"]
    DEC -->|pass| CHAIN["Credential on Stellar"]
```

1. **File map.** Every selected source file is read and recorded with what it does: where it signs, pays, holds
   secrets or verifies signatures. Every claim quotes its line; a quote not in the source is dropped.
2. **Check ledger.** The same 28 questions, most of them Stellar-specific, are asked of every agent with the same
   capabilities, in four groups: value movement; signing, network and submission; access, secrets and entry points;
   model behaviour and intent. *Holds* and *fails* must quote the deciding line.
3. **Challenge.** Twenty of the checks, on funds, signing, access and model behaviour, are re-examined when
   answered *holds*, by a pass whose only job is to find one path where the check does not hold.
4. **Focused file review.** Each file that signs, pays, holds keys or verifies signed input gets its own review,
   with the Stellar criteria and the lessons learned from real defects that match what the file does. The model
   states each function's security invariants and checks them one by one.
5. **Verifier.** A separate, independent model call re-checks each medium-or-higher finding (up to 60 per audit)
   at the cited line without seeing why it was raised. Model-review findings get their severity from facts (what
   is at risk, who can trigger it, which network, whether the code ships), not from the model's choice; rule
   findings carry the rule's severity, which the verifier may lower. Comments in the audited code never count as
   controls.

Data-flow rules for Python and JavaScript/TypeScript and pattern rules for Rust, Go and Solidity run alongside.
Details, limits and the decision rule: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What it checks on Stellar

| Area | Examples |
|---|---|
| Payments | Destination, amount or asset chosen by the model, a request or a memo; caps and budgets that survive restarts; assets matched without issuer; amount received vs. sent; rounding in fees and shares |
| Signing | Foreign XDR, fee bumps and Soroban auth entries signed without inspecting them; raw bytes signed; missing timebounds |
| Submission | `PENDING` or a timeout treated as final; fee-bump re-wraps; retries that pay twice; failure paths that leave state stuck |
| Incoming payments, x402, MPP | Proofs not bound to payer, amount and request; verify without settle; replayable hashes; fee sponsorship without a budget |
| Web authentication | SEP-10/45 challenges signed unchecked; verification that accepts no client signature or counts the server's own |
| Soroban | `require_auth` coverage, `__check_auth` and delegated signers, implicit invoker authorization, upgrade authority, TTL |
| Accounts | Signers and thresholds read from Horizon; SEP-29 memo-required destinations; SEP-1 identity |
| Agent surface | Prompt injection reaching a privileged call, secrets returned to the model, cross-tenant lookups, unauthenticated routes |

## Every audit on the ledger: the assay book

Every audit the demo runs is entered in the **[assay book](https://usetouchmark.app/book)** and stamped on Stellar
testnet. The entry (agent, commit, decision, score, finding counts, the commit of this repository the auditor ran
from, and the SHA-256 of the full report) is hashed,
and that hash is the `MEMO_HASH` of a transaction from the book account. Anyone can count the audits, open any of
them and check them without trusting the server:

```
sha256(canonical entry JSON) == memo of the stamp transaction
entry.report_sha256          == sha256(report JSON)
```

The full report is released for **2 XLM on testnet**: the payer sends it with the memo `tm:` + the first 20 hex of
the entry (Freighter, or any wallet), the server reads the payment back from Horizon, releases the report, and sends
the payer a receipt stamp whose memo is the entry hash. The book page shows the totals (audits, agents, findings, paid reports, XLM
received) and links each row to its transactions. Code: [`assay_book.py`](backend/app/services/assay_book.py).

End-to-end proof: on 2026-11-08 the full user flow (model review, stamp, testnet payment, receipt, report and, for
the passing agent, the credential) ran six times on the public site with a testnet wallet. Check it without trusting
the site:

```bash
python3 scripts/verify_assay.py --ledger --latest 10   # every entry, and the book's totals counted from the ledger
pip install stellar-sdk && python3 scripts/verify_assay.py --verify-archive docs/evidence/e2e-user-flow-2026-11-08.json
```

The book page has a button that does the per-entry check in the visitor's browser: it hashes each entry with Web
Crypto and reads the transactions from Horizon, not from this site. The same check runs every day from GitHub's
runners in the [Ledger proof](.github/workflows/ledger.yml) workflow.

`--ledger` lists every stamp, payment and receipt of the book account straight from Horizon, checks that the site
publishes each stamped entry and that its totals match the ledger's. The record keeps all 25 transactions as signed
envelopes, so after a testnet reset `--verify-archive` still proves offline that the book account signed them. What it
cannot prove: that a report is correct (each finding cites a line in a public commit, which anyone can read), or that
a payer is a distinct person (the six runs were made from one test wallet, as the record says). Record:
[`docs/evidence/e2e-user-flow-2026-11-08.json`](docs/evidence/e2e-user-flow-2026-11-08.json).

## Declare your agent: `.tmark`

A `.tmark` at the repository root states what the agent may do: network, keys and what it signs, spending limits,
recipients, approval and tools. Touchmark holds the code to every claim; a declaration never closes a risk on its
own. **[Build one in the browser](https://usetouchmark.app/guide/tmark#builder)** from a template and
check it live, or start from your code:

```bash
python scripts/tmark.py init path/to/repo    # a valid draft from what the code can do
python scripts/tmark.py check path/to/repo   # lists every error
```

Reference: [docs/TMARK.md](docs/TMARK.md).

## The credential on Stellar

Soroban contracts, not the server, decide whether a credential exists and is still valid. The owner signs the
registration in their own wallet; only an approved validator can complete a validation; the credential binds the
report hash and the agent's version, so a changed agent is no longer current. Scores below 65 are refused;
credentials expire after at most 90 days, cannot be transferred and can be revoked; no contract is upgradeable.
The contracts on testnet are built from this repository: the build is reproducible, and
`python scripts/verify_contracts.py` compares each contract's code hash on the ledger with the deployment manifest
and with the WASM built from `contracts/`. CI runs it on every push.
Contracts: `agent-registry`, `audit-credential`, `audit-escrow`, and `agent-account`, a custom account that gives
an agent session keys limited by recipient, asset, per-call maximum and budget.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/audit_agent.py https://github.com/owner/repo --no-deep      # rules only, no key
ENABLE_DEEP_REVIEW=1 DEEP_REVIEW_MODEL=claude-haiku-5-5 VERIFIER_MODEL=claude-haiku-5-5 ANTHROPIC_API_KEY=... \
  .venv/bin/python scripts/audit_agent.py <ref>                                       # full review, as on the demo
.venv/bin/uvicorn app:app --port 8000                                               # demo at /
.venv/bin/pip install -r backend/requirements-dev.txt && .venv/bin/python -m pytest -q && cargo test --workspace
```

Run locally, the model review stops after `DEEP_REVIEW_TIMEOUT_SECONDS` (240 s by default, at most 900); raise it
for large repositories.

In CI, the composite action ([`action.yml`](action.yml)) runs the deterministic analysis on every push, validates
the `.tmark` and annotates the cited lines:

```yaml
- uses: actions/checkout@<commit-sha>
- uses: furkan3152/Touchmark_agent@<commit-sha>
  with: { fail-on: needs_fixes, annotate: medium }
```

The rules alone never give a pass, so the action's decision is `needs_fixes` or `needs_evidence`: CI never shows a
result that could earn a credential.

## Limits

- A pass means no actionable risk was found in the reviewed code, not that the agent is safe.
- The audit never executes the code it reviews. A testnet execution probe that reproduces fund and key findings
  in a disposable microVM is prototyped in [research/testnet-probe](research/testnet-probe).
- Testnet by default; mainnet needs `ALLOW_MAINNET`. The contracts have a self-assessed review and **no external
  audit yet**. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

[Architecture](docs/ARCHITECTURE.md) · [Evidence](docs/EVIDENCE.md) · [`.tmark`](docs/TMARK.md) · [Benchmark](research/benchmark/real/README.md) · [Deployments](deployments/README.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Apache 2.0](LICENSE)

---

Built by Furkan Akdoğan ([@furkan3152](https://github.com/furkan3152)).
