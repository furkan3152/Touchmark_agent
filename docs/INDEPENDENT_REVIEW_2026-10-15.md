# AgentVeritas: evidence, limitations and Stellar direction

> Historical checkpoint. Current official tiers, deployed contracts and verified pilot evidence are documented in [the official pilot release](OFFICIAL_PILOT_2026-10-15.md). Retained audit limitations still apply unless explicitly resolved there.

Review date: 2026-10-15. This is an internal adversarial review with separately assigned reviewers, not an external security firm's audit. The disclosed fixtures are developer-visible. No claim of independent certification or market-wide detection accuracy follows from these results.

## Customer verdict

Useful today for bounded source triage and collecting versioned evidence. Not sufficient as the sole approval to deploy an agent with customer funds, secrets or production tools. Neither a callable, SDK import, manifest, refusal response nor an on-chain report proves a safe autonomous agent. There is no implemented universal agent detector.

| Claim | Current evidence | What remains unproven |
| --- | --- | --- |
| Identify an agent | Checked file map, supported callable signature and framework indicators | Whether the callable reaches the real deployed agent, its model, hidden services and production configuration |
| Find vulnerabilities | Bounded Python dataflow and language-specific static signals | Cross-file flows, dynamic dispatch, arbitrary languages/frameworks, exploitability and completeness |
| Exercise behavior | Disposable microVM executes supplied Python callables with bounded text probes | Live models/tools, persistent multi-turn memory, concurrent tenants and tamper-proof traces |
| Assess controls | 24-area evidence inventory with explicit gaps | Keyword presence and refusals do not verify authorization, egress or spending enforcement |
| Verify a report | Canonical bytes, source/plan hashes and versioned Soroban commitments | Whether the assessment itself is correct or the deployed binary matches all submitted source |
| Decentralize auditing | Contracts can record validators/reviewers and externally signed outcomes | Auditor admission is admin controlled; current service has no independent execution quorum, dispute protocol or open operator network |

## Reproduced defects and changes

1. Noncanonical paths such as `src//main.py` could be analyzed as separate files but overwrite `src/main.py` in the VM. Intake now uses a shared canonical path policy.
2. A dotted filename could import a different module than the declared file. Runtime candidates now require unambiguous module paths and the supervisor verifies the resolved origin before import.
3. Reassigned, deleted or import-rebound entrypoint symbols were advertised as supported. Visible module-scope rebinding is now rejected. Arbitrary dynamic rebinding remains outside this static guarantee.
4. A declared input named `text` did not seed taint while `prompt` did. Blueprint entrypoint parameters now seed external-input analysis regardless of spelling.
5. A local `agents.py` module could be labeled an external agent SDK. Supplied local roots no longer establish that framework indicator.
6. A comment containing `require_auth` or an unrelated protected function could suppress a Soroban authorization gap. Rust comments/literals are masked and public function bodies are considered separately. Helper/control-flow semantics remain unverified; findings are inferred review gaps, not confirmed exploits.
7. Registry invocation descriptions included nonexistent ABI arguments; escrow descriptions omitted roles and committed a URI hash rather than report content. Builders now use actual ordered, typed contract parameters and fail closed on missing inputs. This is still unsigned invocation preparation, not funded checkout or a signed transaction.

The regression suite preserves these counterexamples. No submitted program was executed on the host during discovery/analysis testing.

## Disclosed challenge set

Run `python scripts/evaluate_detection.py` using the project environment. The machine-readable result is `deployments/detection-evaluation-2026-10-15.json`; it includes fixture and analyzer hashes, per-case outcomes and limitations.

The initial post-fix set contains ten source-signal cases: eight expected outcomes matched, and two expected paths were missed. The retained misses are cross-file `eval` flow and dynamically resolved `eval`. Three identity examples remain explicitly **unverified**, including a plain formatter and an SDK import without agent behavior.

**Eight of ten is not 80% agent-security accuracy.** This is a small disclosed regression/challenge set, not a blind representative sample. The labels concern selected source signals, not successful exploits. Real customer evaluation still requires a frozen independent dataset, benign near-misses, multiple frameworks, replayable live tool traces and separate false-positive/false-negative measurements.

## Stellar features: implemented versus proposed

| Feature | Why it matters | Status |
| --- | --- | --- |
| Soroban `Address.require_auth` | Applies transaction authorization to registry, evaluator and owner operations | Existing contracts; synthetic Testnet lifecycle evidence |
| Version-bound registry and revocable credential | Bind a report to a specific source declaration and invalidate stale credentials | Implemented; custom credential, not SEP-50 NFT interoperability |
| SAC / SEP-41 token interface | Atomic escrow fund, settle and refund operations | Contract implemented; real paid USDC checkout not verified |
| Contract events and persistent TTL | Track evidence state and handle archival/lifetime | Implemented; durable multi-operator indexing not delivered |
| SEP-53 | Off-chain G-account message signature | Implemented; does not prove multisig threshold authority or C-account web login |
| SEP-46 / SEP-48 | Metadata and generated interface in contract artifacts | Embedded; not proof of verified source-to-deployed-WASM provenance |
| Authorization-entry inspector | Decode all invocation nodes and check exact token/from/recipient/amount/expiry policy | Read-only prototype; no signature verification, RPC simulation or authorization grant |
| AgentSessionAccount | Enforce a short-lived session's recipient, token and integer spending budget in `__check_auth` | Experimental new contract; local signature/SAC tests, not production or existing Testnet deployment |
| x402 / MPP | Machine-to-machine per-request audit payments; MPP sessions for repeated requests | Official Stellar integrations researched; not enabled in this product |
| SEP-10 / SEP-45 | Web sessions for G accounts / contract accounts | Not implemented end to end |
| SEP-47 / SEP-55 / SEP-58 | Discover deployed contract interfaces and verify build provenance | Recommended next integration; not claimed as implemented |
| Fee sponsorship | Users authorize exact actions while a relayer pays fees | Recommended; no production sponsor/relayer in this release |

The defensible Stellar advantage is the combination of host-checked invocation authorization, custom accounts, SAC asset access and sponsorship in one integration. Escrow, NFTs, simulation and agent payments are not inherently impossible on other chains. A longer SEP list is not a substitute for enforcing a real boundary.

SEP-41, SEP-45, SEP-47, SEP-50, SEP-55 and SEP-58 are Draft in the official directory checked on the review date; draft status must be disclosed and implementations pinned. SEP-46/48 are Active and SEP-53 is Final.

## Toward a decentralized audit infrastructure

The first credible release gate is an exact proposed transfer: inspect its authorization tree, reject a changed recipient or excessive budget in the custom account, and bind the resulting rejection evidence to source, plan, policy, network and transaction commitments. A read-only inspector alone does not enforce this gate.

Next, separate the proposer, isolated runner, independent reviewer and settlement authority. Each result should identify source, plan, adapter/image, test inputs, evidence hash, evaluator and uncertainty. Independent organizations must run separate infrastructure and keys; seven classes in one process are not seven independent validators.

A challenge mechanism needs objective adjudication criteria. A forged hash, mismatched source version or reproducible failed test is different from a subjective model judgment. Do not automatically slash a validator merely because two model outputs disagree. Admin admission, reviewer independence and emergency procedures need explicit governance, including a tested multisig or contract-account policy.

Existing registry `avg_score` is historical across versions. Do not present it as current-version safety. Escrow evaluator acceptance is not yet cryptographically tied to registry acceptance of the same report. These remain integration/release gates, along with deployment provenance, supported framework images, live model brokering, host-observed tool telemetry, distributed quotas and independently reviewed operations.

## Official references

- [Soroban authorization and invocation trees](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization)
- [Custom account example and security constraints](https://developers.stellar.org/docs/build/smart-contracts/example-contracts/complex-account)
- [RPC simulateTransaction: enforce versus record](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction)
- [Stellar agentic payments: x402 and MPP](https://developers.stellar.org/docs/build/agentic-payments)
- [Fee sponsorship choices](https://developers.stellar.org/docs/build/guides/transactions/fee-sponsorship)
- [Official SEP status directory](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/README.md)
- [SEP-58 reproducible build vocabulary](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0058.md)

## Verification record for this change

- 438 Python tests passed, including independent counterexamples, bounded XDR inspection and exact invocation ABI/state handling.
- 38 Rust tests passed across the workspace, including 18 new account tests. The account passed formatting and strict Clippy; release WASM was built. These are local Soroban host tests, not new Testnet deployment evidence.
- The account's actual SAC authorization-entry tests cover replay, altered destination/amount, wrong network/account, host expiry, rotation, revocation, shutdown and rollback. This supplements direct `check_auth` tests; batching/independent review/operational recovery remain release work.
- Local HTTP inspection matched a declared transfer policy and rejected a nested recipient substitution; response hashes and false execution/signature flags were checked.
- In a real disposable microVM, the existing multi-file fixture still ran, while an ambiguous filename-to-module substitution was rejected. See `deployments/runtime-origin-review-2026-10-15.json`.
- New account WASM and source commitments: `deployments/agent-account-local-2026-10-15.json`. No claim of independent reproducible build or deployed source equivalence is made.
- Protected Vercel preview access and the deployed HTTP-to-Sandbox provider path remain unverified; no browser visual QA is claimed by these checks.
