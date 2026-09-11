# AgentVeritas Stellar

Review an agent's code, permissions and behavior claims before giving it authority on Stellar.

![Stellar](https://img.shields.io/badge/Stellar-Network-black?style=flat&logo=stellar)
![Soroban](https://img.shields.io/badge/Soroban-Smart_Contracts-black?style=flat&logo=rust)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat&logo=python)

## Table of Contents

- [Product and pilot scope](docs/PRODUCT_AND_PILOT.md)
- [Audit Studio](#audit-studio)
- [Project Overview](#project-overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Soroban Contracts](#soroban-contracts)
- [Active Stellar Testnet Release](#active-stellar-testnet-release)
- [SEP Boundaries](#sep-boundaries)
- [Quick Start](#quick-start)
- [Testnet Verification](#testnet-verification)
- [Evidence Levels](#evidence-levels)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Repository Boundary](#repository-boundary)

## Project Overview

- **Name**: AgentVeritas Stellar
- **Purpose**: Evidence-first verification and audit system for AI agents operating on or interacting with the Stellar network
- **Architecture**: Python audit backend + Soroban AgentRegistry contract + optional SAC AuditEscrow contract
- **Independence**: Standalone Stellar product with no cross-chain dependencies
- **Status**: Local public-review prototype and existing Testnet contracts; not a hosted production service

## Audit Studio

At `/`, add a public Stellar account/contract address, import a public GitHub `agent-audit.json`, or upload source files. Describe the intended job and select its capabilities; detailed instructions and tool JSON are optional advanced inputs. No wallet connection or operator key is needed. Try the labeled read-only and unsafe-payment fixtures, inspect the findings, then download the report and reusable input bundle.

Address lookup reads Testnet or Mainnet without signing. Finding an account or contract does **not** identify its owner or prove agent behavior. An address-only submission returns missing evidence, not a source audit. GitHub import reads a bounded root bundle, not an entire repository. Never supply a private key.

The quick check is free. Proposed paid offers are **49 USDC per automated release review** and **149 USDC/month for 10 automated reviews**. They are pilot pricing targets: runtime testing, subscriptions and USDC checkout are not enabled, and no payment is collected.

The Studio runs the existing seven **rule-based analysis modules**, not seven independent human auditors. Python source paths use bounded AST analysis; other languages use heuristics. Uploaded programs are never imported or executed. Source is processed in server memory without persistence or external AI processing. Reports can contain source excerpts: review them before sharing.

The result distinguishes actionable source findings from missing evidence. It does not award a production safety certificate. Runtime execution, owner verification and Soroban publication are separate stages. The original operator workflow remains available at `/operator`; its stored agents, jobs, badges and reports now require operator authentication for reads as well as writes.

See the [bundle/API contract](docs/AUDIT_STUDIO.md), [product and revenue model](docs/PRODUCT_AND_PILOT.md), and [current verification record](docs/VERIFICATION_2026-09-11.md).

## How It Works

The system does not automatically trust an agent's claims. It examines prompts, tool permissions, source code, dependencies, ownership proof, and verifiable Stellar data across seven dimensions:

| Dimension | Weight |
|---|---:|
| Intent | 18% |
| Security | 24% |
| Economic | 14% |
| Compliance | 11% |
| Reliability | 9% |
| Stellar Native | 10% |
| Provenance | 14% |

Each auditor reports completed/error status. Quorum requires exactly seven unique identities and dimensions; timeout, identity/policy mismatch, or duplicate findings fail-close the audit. If no external provider exists, results are not fabricated. CONFIRMED, INFERRED, and SIMULATED evidence grades separately calibrate finding and scenario penalties; claims without evidence text cannot remain CONFIRMED.

Every v2 report carries: Stellar-specific policy version, audit-input SHA-256, finding-set SHA-256, quorum/coverage, external handler list, and a verified|partial|simulated assurance level separate from the badge. If ownership plus real indexer/RPC binding is missing, SAFE is never granted even with a high score. Continuous monitoring alerts on new verified high/critical findings and assurance regression alongside score changes.

DEEP tier traces: untrusted input → command/code execution, untrusted input → Stellar/Soroban transactions, and secret seed → log/network paths with file:line evidence in executable source; separately flags financial controls stated in prompts but not enforced in code. Synthesis Judge combines cross-dimension toxic combinations like network access + code execution + Stellar signing. See [docs/DEEP_AGENT_AUDIT.md](docs/DEEP_AGENT_AUDIT.md).

## Architecture

```text
Studio bundle (public, bounded, stateless)
    └─► seven static dimensions ──► source findings + coverage + exact report download
         No code execution, ownership claim, payment, persistence or chain write

Operator ingestion (authenticated, persistent)
    │
    ▼
secure ingestion ──► parallel audit swarm ──► synthesis judge
    │                                            │
    │                                            ├─► JSON/Markdown report + local CAS/IPFS
    │                                            ├─► offchain badge (evidence boundary explicit)
    │                                            └─► unsigned Soroban response preparation
    │
    └─► G-account ownership: Ed25519
         C-account web auth: SEP-45 compliant provider only

external signer ──► AgentRegistry.respond ──► RPC result + state/event readback
                                                │
                                                └─► only here on-chain confirmed
```

## Soroban Contracts

The workspace contains two contracts:
- **agent-registry**: Owner-bound agent registration, validator allowlist, assigned validator request/response, report hash/URI, reviewer uniqueness, TTL renewal, typed events, SEP-46 metadata, and SEP-48 interface generation.
- **audit-escrow**: Independent from the verification core, optional SEP-41/SAC escrow; requester/provider/evaluator roles, deadline/refund/dispute, and single provider payout.

The backend never stores seeds, never signs transactions, and never submits them. A prepared invocation, transaction hash, or RPC accessibility is not success. `confirmed=true` is only granted when a successful ledger result and expected registry state/event are verified together.

## Active Stellar Testnet Release

Deployed on August 30, 2026 with external Stellar CLI signer:

Read-only re-verification on September 11, 2026 passed all **31** checks in `scripts/verify_testnet_deployment.py`. No new deployment was made for the Studio changes.

| Component | Testnet ID | Evidence |
|---|---|---|
| AgentRegistry | `CBBBUECSLXGXVXYMRYK3BCTL3YYBRWDZGW3RNCH5CWKY6KU6UGE576KT` | Local/on-chain WASM hash match, deploy tx SUCCESS, role and lifecycle readback |
| AuditEscrow | `CD6Q7DJMM3XR7NIBD7XCGQ34GK6UOA5BBUL7BGP5EMYDZ2ZADV37KH7W` | Local/on-chain WASM hash match, deploy tx SUCCESS, funded lifecycle readback |
| Test asset | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` | Native XLM SAC; **not USDC** |

Registry: register → request → respond → review completed. Escrow: create → fund → submit → complete with real 1 XLM (0.15 XLM fee, 0.85 XLM provider payout) verified via event/state readback. Full manifest: `deployments/stellar-testnet.json`

## SEP Boundaries

- **SEP-1**: Planned service discovery; no production domain or published discovery file is claimed
- **SEP-10**: Planned G/M account web sessions; the current operator bearer key is not SEP-10
- **SEP-53 (Final)**: G-account offchain ownership message with prefix + SHA-256 + Ed25519
- **SEP-45 (Draft)**: C-account web auth; does not replace core contract authorization
- **SEP-41/SAC**: Optional escrow asset only
- **SEP-46 & SEP-48**: Contract metadata/spec and standard introspection surface
- **SEP-24, SEP-31 & SEP-38**: Separate anchor/payment module only. Not part of agent validation core.
- **SEP-55 & SEP-58 Draft**: Tracked for future build verification/reproducibility; not claimed as current evidence

Detailed decisions: [docs/STELLAR_ARCHITECTURE_DECISION.md](docs/STELLAR_ARCHITECTURE_DECISION.md)

## Quick Start

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
test -f .env || cp .env.example .env

# Offline verification (no external writes)
STELLAR_NETWORK=offline \
ALLOW_MAINNET=false \
ENABLE_AUDIT_ESCROW=false \
LLM_PROVIDER= \
LLM_API_KEY= \
PINATA_JWT= \
.venv/bin/python -m pytest -q \
  backend/tests/test_audit_studio.py \
  backend/tests/test_deep_agent_audit.py \
  backend/tests/test_api_security.py \
  backend/tests/test_swarm_e2e.py

# Soroban
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
# Contract source is unchanged by the Studio release.
cargo test -p agent-veritas-registry
cargo build --workspace --target wasm32v1-none --release
```

Dev server:
```bash
./scripts/dev.sh
# UI: http://127.0.0.1:8000/
# Operator: http://127.0.0.1:8000/operator
# API: http://127.0.0.1:8000/api/v1
```

Persistent operator endpoints return 503 if `ADMIN_API_KEY` is not set; unauthenticated requests are rejected when it is set. Studio remains usable without that key. Local directory ingestion is disabled by default. `scripts/test.sh` is the separate release-wide check; use targeted tests during development.

## Testnet Verification

```bash
.venv/bin/python -m backend.deploy verify-testnet
.venv/bin/python -m backend.cli events-sync --start-ledger 4419257
.venv/bin/python -m backend.cli chain
```
This evidence is limited to Testnet; it does not imply mainnet readiness, USDC settlement, published SEP-1, or professional audit.

## Evidence Levels

| Level | What it proves | What it does not prove |
|---|---|---|
| Static/local tests | Code paths and invariants work | Deployment or funded transactions |
| WASM build + hash | Compilable artifact | Same as explorer contract |
| Testnet contract ID | An ID is configured | Code/hash match or correct state |
| Successful tx + readback | Specific call and expected effect | Mainnet/production security |
| Funded end-to-end proof | Real asset lifecycle | Safety under all adversarial conditions |

Testnet deployment and native-XLM funded lifecycle are verified; remaining gaps documented in `docs/AUDIT_2026-08-30.md`.

## Project Structure

```text
├── backend/           # Python audit engine
│   ├── app/           # FastAPI application
│   │   ├── swarm/     # Audit swarm (7 auditors + judge)
│   │   ├── stellar/   # Stellar identity, events, RPC
│   │   ├── services/  # Pipeline, escrow, badges
│   │   ├── ingestion/ # Secure agent ingestion
│   │   ├── reporting/ # Report generation, IPFS
│   │   └── compliance/# OFAC screening
│   └── tests/         # Targeted regressions and pipeline tests
├── contracts/         # Soroban smart contracts
│   ├── agent-registry/# Core registry contract
│   └── audit-escrow/  # Optional escrow contract
├── frontend/          # Public Studio + authenticated operator console
├── scripts/           # Dev, test, deploy utilities
├── deployments/       # Testnet deployment manifest
├── docs/              # Architecture docs & audit reports
├── examples/          # Sample agents for testing
├── Cargo.toml         # Rust workspace config
└── .env.example       # Environment template
```

## Documentation

- [Product and Pilot](docs/PRODUCT_AND_PILOT.md) — users, upload flow, revenue hypotheses and 30-day Instawards scope
- [Audit Studio API](docs/AUDIT_STUDIO.md) — bundle format, limits and exact-byte report verification
- [Verification 2026-09-11](docs/VERIFICATION_2026-09-11.md) — changes, evidence and remaining release gates
- [Stellar Architecture Decision](docs/STELLAR_ARCHITECTURE_DECISION.md) — SEP choices and system design rationale
- [Deep Agent Audit](docs/DEEP_AGENT_AUDIT.md) — DEEP tier analysis methodology
- [Audit Report 2026-08-30](docs/AUDIT_2026-08-30.md) — Historical findings and evidence matrix
- [Visual Review](docs/REVIEW_2026-08-30.html) — Readable audit summary
- [Deployment Manifest](deployments/stellar-testnet.json) — Full transaction/ledger/event evidence

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security
See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License
Apache 2.0 — see [LICENSE](LICENSE).

## Repository Boundary
This copy was created without `.env`, `data/`, keystore, or live deployment state. Independence check:
```bash
./scripts/verify_independence.sh
```
