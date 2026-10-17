# Synthetic Stellar agent fixtures

Sixteen constructed agent bundles used as regression checks for the analyser. They are
not operated agents or a general safety benchmark, and several contain deliberately
unsafe code: **do not run them or add real credentials**.

`manifest.json` gives the expected category per fixture. Labels were not changed to match
results. All sixteen pass under the current policy, but the analyser was improved with
them in view, so they measure regressions, not accuracy. The original baselines (3/10
and 2/6 failed) are recorded in [`../../../docs/evidence/studio-benchmark-2026-09-11.json`](../../../docs/evidence/studio-benchmark-2026-09-11.json)
and [`studio-benchmark-round2-2026-09-11.json`](../../../docs/evidence/studio-benchmark-round2-2026-09-11.json).

```bash
.venv/bin/python -m pytest examples/studio/benchmark/check_agent_detection.py -q -s --tb=short
```

For the larger labelled corpora and the evaluation method, see [docs/EVIDENCE.md](../../../docs/EVIDENCE.md).
