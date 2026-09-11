# Agent source-audit benchmark — second batch

Date: 2026-09-11. Six **new** synthetic source bundles, cases 11–16. This is separate from the earlier ten-case result. The engine was not modified for this run.

## Results

| Agent | Submitted behavior | Targeted result | Review decision |
|---|---|---|---|
| SeedShield Support | Reads a signing seed but logs only `[REDACTED]`; returns a presence boolean | Correct: no raw-seed disclosure path flagged | More evidence required |
| OpsAlias Assistant | Calls `os.system` as `launch`, with a request-controlled command | **Missed source path**; generic shell-tool warning remains | Needs fixes |
| PaymentDraft Planner | Returns an unsigned payment preview dictionary, with no submission call | Correct: no financial submission path flagged | More evidence required |
| TreasuryAlias Submitter | Assigns `horizon.submit_transaction` to `dispatch`, then supplies request XDR | **Missed source path**; generic permission/spending warning remains | Needs fixes |
| LeakyTelemetry Reporter | Places an environment signing seed into an outbound HTTP body | **Detected**, with source-line evidence | Needs fixes |
| NetworkReporter | Logs the non-secret `STELLAR_NETWORK` setting | Correct: no seed-disclosure alarm | More evidence required |

**4 matching expectations; 2 failed expectations.** Of three deliberately positive source-path cases, one target path was detected and two were missed. All three scoped negative controls matched their expectations. These are not whole-agent safety labels, and this small, deliberately selected set cannot establish general accuracy.

The two missed paths did **not** receive a safe/pass verdict: separate tool/configuration rules still returned `needs_fixes`. Do not describe them as completely undetected unsafe agents. The limitation is the absence of the requested caller-input-to-operation evidence. Generic permission findings are not a substitute for source-path analysis.

## Evidence and limits

- Six public `POST /api/v1/studio/review` calls completed with HTTP 200 and seven dimension reports. The existing real analyzer ran; it was not mocked.
- The test blocked outbound asynchronous HTTP, verified `runtime_executed=false`, `onchain_confirmed=false`, no external processors, and exact report hashes.
- No fixture program, LLM agent, shell command, telemetry request or Stellar transaction was executed. No real secret or funded account was used. The telemetry hostname is intentionally under `.invalid`.
- TreasuryAlias assumes an injected Horizon-compatible client and externally signed XDR. It demonstrates an application-level unchecked submission path, not theft, ownership of a signing key or bypass of Stellar protocol authorization.
- A presence boolean is deliberately outside SeedShield's raw-seed-disclosure target. PaymentDraft is not certified for every possible downstream consumer or validation requirement.
- The general tool/spending warnings should be interpreted in their declared-permission context; they do not prove that the treasury adapter possesses a signing key.
- All six reports had one of `needs_evidence` or `needs_fixes`, never a runtime safety certificate.

The failure mode is consistent with missing import/bound-method alias resolution. The next engineering change should resolve known aliases before tracing calls, with fixed-input controls and independent evidence grades. No fix is claimed in this report.

## Reproduce this batch only

From the Stellar repository root:

```bash
.venv/bin/python -m pytest examples/studio/benchmark/check_agent_detection.py \
  -q -s --tb=short \
  -k '11-seed or 12-ops or 13-payment or 14-treasury or 15-leaky or 16-network'
```

Observed: **2 failed, 4 passed, 10 deselected**; exit code 1. Failed assertions are retained as evidence, not waived with skips or xfails. A full repository suite was not run.

- [Fixture manifest and pre-labeled expectations](../examples/studio/benchmark/manifest.json)
- [Machine-readable results and hashes](evidence/studio-benchmark-round2-2026-09-11.json)
- [Original ten-case report](AGENT_BENCHMARK_2026-09-11.md)

Full local evidence is stored in ignored `data/benchmarks/studio-benchmark-round2-2026-09-11.json`. Its `reports[].report_json` values preserve the exact original report bytes as UTF-8 strings; each matches its recorded SHA-256. Run timestamps and IDs mean hashes can change on reruns.

To try one in the Studio, copy the selected fixture JSON under the filename `agent-audit.json` and use **Upload files**. Never execute the intentionally risky fixtures or supply real keys.
