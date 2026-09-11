# Synthetic Stellar agent-adapter fixtures

Sixteen source bundles in two diagnostic batches for characterizing the public Studio analyzer. These are constructed examples, not independently operated agents, deployed contracts or a general agent-safety benchmark. Some deliberately contain unsafe source paths; **do not run them or add real credentials**.

`manifest.json` defines the scoped expected category per fixture and explains the two-stage selection. Labels were not changed to match results. Source bundles contain no expected-result hints submitted to the auditor.

Run the original ten-case opt-in check from the repository root:

```bash
.venv/bin/python -m pytest examples/studio/benchmark/check_agent_detection.py -q -s --tb=short \
  -k 'not (11-seed or 12-ops or 13-payment or 14-treasury or 15-leaky or 16-network)'
```

The original baseline has **3 failed / 7 passed**: cross-file secret tracing and parameter-rename detection miss risks, while a fixed caller triggers a false positive. Failures are deliberate evidence of current limitations, not waived acceptance criteria. This file is not in the default backend suite.

The second six-case batch has **2 failed / 4 passed**: import and bound-method aliases obscure specific source paths despite separate generic permission warnings. See its [results and focused command](../../../docs/AGENT_BENCHMARK_ROUND2_2026-09-11.md). The cohorts are deliberately selected diagnostics, not independent accuracy samples.

For the browser, copy one chosen bundle to a file named `agent-audit.json` and upload it through the Studio's file tab. Otherwise a differently named `.json` file is treated as source, not imported as a bundle.

See the [full dated results](../../../docs/AGENT_BENCHMARK_2026-09-11.md) and [machine-readable summary](../../../docs/evidence/studio-benchmark-2026-09-11.json).
