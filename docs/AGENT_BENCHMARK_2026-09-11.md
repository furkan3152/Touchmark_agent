# Source-audit characterization — 2026-09-11

**Result: 7 matching outcomes and 3 detection failures across 10 synthetic cases.** The review engine was not modified to improve these results. All submissions received HTTP 200, seven dimension reports and integrity-checked report bytes. Successful API processing is not successful risk detection.

## Method

Eight new Python agent-adapter source bundles were labeled before the first run: three negative controls and five deliberately risky cases. Two diagnostic follow-ups were added after inspecting the first outcomes and the analyzer's parameter-name handling. This is an in-house, small, non-random characterization set, not independent certification or a representative accuracy benchmark.

Each bundle goes through the real public `POST /api/v1/studio/review` route, without an operator key. No analyzer is mocked; outbound asynchronous HTTP is blocked by the test. Sources are inspected as text, never imported or executed. No real seed, payment, running LLM agent, chain transaction or third-party agent is involved. The payment example uses an injected submission adapter and assumes the declared signing authority; no actual Stellar SDK submission is attempted.

Labels concern one specified source-path category per case. A positive means the category should be present; a negative means that particular request-to-command path is absent in the submitted fixture. They are not whole-agent safe/unsafe labels. Any evidence grade counts as detection; the observed matching categories were all marked `confirmed` by the engine. General `shell=True` warnings are not counted as successful request-to-command tracing.

## Results

| Case | Source behavior / expectation | Target category detected | Priority findings | Result |
|---|---|---|---:|---|
| 01 Ledger Lens | Read supplied balances; no execution sink | No | 0 | Correct negative |
| 02 Fixed Status Helper | Fixed argv, `shell=False`; no request-controlled command | No | 0 | Correct negative |
| 03 Unsafe Ops Assistant | Request command passed directly to `shell=True` | Yes, confirmed | 1 | True positive |
| 04 Unrestricted Treasury | Request payload passed to transaction adapter without checks | Yes, confirmed | 5 | True positive |
| 05 Leaky Wallet Support | Environment seed passed directly to logger | Yes, confirmed | 1 | True positive |
| 06 Modular Ops Assistant | Request command forwarded to a separate helper | Yes, confirmed | 1 | True positive, but name-sensitive |
| 07 Fixed Command After Input | Request value overwritten with a fixed command | No | 0 | Correct negative |
| 08 Modular Wallet Diagnostics | Environment seed forwarded to a separate logging helper | **No** | 0 | **False negative** |
| 09 Renamed Modular Ops | Same behavior as 06; parameter renamed `command` → `value` | **No** | 0 | **False negative** |
| 10 Fixed Modular Status | Only supplied caller passes a fixed string to helper | **Yes, confirmed** | 1 | **False positive** |

Scoped counts: 4 true positives, 2 false negatives, 3 true negatives, 1 false positive. In this particular set, risk recall is **4/6 (66.7%)**, alarm precision **4/5 (80%)**, and negative-control false-positive rate **1/4 (25%)**. These percentages must not be marketed as production accuracy.

The initial eight-case run had one failed expectation. The expanded ten-case run had three: 08, 09 and 10. Their test assertions intentionally remain failing; they are not skipped, marked expected failures, or relabeled to make the output green. This opt-in diagnostic file is separate from the default backend test suite. No full repository suite was run.

## Findings about the auditor

1. **Cross-function secret flow is missed.** The source state does not propagate through `record(logger, secret_seed)` into another file's `logger.info(..., value)`. The same leak is detected when source and sink are local to the function (05).
2. **Parameter names influence evidence beyond what they prove.** In `backend/app/swarm/agentic_paths.py`, selected parameter names are initialized as external input. Thus 06 is detected without proving its caller-to-callee connection; a semantics-preserving rename in 09 loses the finding. In 10, the same rule creates a `confirmed` path despite a fixed supplied caller.
3. **Uncertainty is safer than a false clearance, but still leaves work to users.** Cases 08 and 09 return `needs_evidence`, not a safety approval. They nevertheless miss the specific vulnerability and have zero priority findings. A generic low-confidence shell warning remains in 09; it is not equivalent to tracing the supplied exploit path.
4. **Reports are noisy for small submissions.** Even the read-only case produces 25 total observations, including missing ownership, lockfile, operational and policy evidence. They are not 25 demonstrated vulnerabilities. The UI's priority filtering helps, but relevance filtering and clearer evidence-gap grouping remain important.

Recommended next implementation: bounded interprocedural summaries and import/call resolution; argument/return taint propagation; explicit distinction between proven caller-derived input and name-based assumptions; retain rename-invariance and fixed-caller controls as regressions. Runtime behavior, indirect prompt injection, replay, concurrent spending and real signing still require separate authorized execution tests.

## Reproduce

From the Stellar repository root:

```bash
.venv/bin/python -m pytest examples/studio/benchmark/check_agent_detection.py -q -s --tb=short \
  -k 'not (11-seed or 12-ops or 13-payment or 14-treasury or 15-leaky or 16-network)'
```

The observed exit status is **1**, with **3 failed, 7 passed**. `BENCHMARK_RESULT` lines include each decision, category evidence, counts, report hash and temporary report path. Per-case reports are written to pytest temporary directories. Run IDs/timestamps change, so full report hashes need not remain identical across runs.

- [Fixtures and labels](../examples/studio/benchmark/manifest.json)
- [Machine-readable results](evidence/studio-benchmark-2026-09-11.json)
- Local ignored archive: `data/benchmarks/studio-benchmark-2026-09-11.json`. Each `reports[].report_json` is the exact canonical report string; SHA-256 of its UTF-8 bytes matches the corresponding recorded `report_sha256`. The archive is local evidence, not a public hosted report.

The fixtures are ordinary Studio bundles. To try one through the browser, copy the chosen bundle under the filename `agent-audit.json`, select **Upload files**, and run the review. Do not execute the intentionally unsafe examples or add real credentials.
