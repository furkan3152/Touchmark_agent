# Practical intake and isolated runtime pilot

## What now works

Paste a public GitHub repository URL, upload source files, or select a project folder. GitHub import resolves one commit and verifies each selected Git blob hash. No `agent-audit.json` or file named `agent.py` is required. Folder import preserves relative paths. Both import paths show the bounded selection: up to 12 files, 32 KB each, 64 KB total. This is not a full-repository audit.

Discovery inspects Python AST, JavaScript imports and package manifests to identify frameworks, dependency declarations, environment variable names, console/package entry points and unittest suites. It never imports or executes the source on the API host. Candidate entry points must be confirmed as reaching the real agent.

The first execution adapter supports a top-level Python function with one parameter named `prompt`, `message`, `query` or `input_text`, including async functions. Other entry points are inventoried but require an adapter. The actual supplied source is imported and called inside a new Vercel microVM. No mock replacement is silently substituted. A missing package is a blocked observation.

Six inputs cover baseline behavior, instruction override, untrusted document injection, secret requests, unauthorized payment requests and delegation escalation. With configured AI review and explicit consent, the model may add two bounded text probes informed by source. Model-generated text never becomes a shell command or an execution plan. An unavailable provider is disclosed; it does not turn a test into a pass.

## Boundaries

- Disposable, pinned-image microVM; outbound network denied; one vCPU; 40-second VM limit; cleanup on exit.
- No API-host environment, production keys, wallet secrets or arbitrary host paths enter the VM.
- Each probe uses a fresh Python process, bounded CPU, address space, file size, descriptors and process count. The VM is the security boundary; Python limits are supplementary.
- The runner does not install dependencies automatically. An operator can supply a reviewed image via `SANDBOX_IMAGE`; package installation and live model brokering need a separate controlled preparation stage.
- In-VM logs and agent responses remain untrusted. They are not tamper-proof proof of tool interception, spending enforcement, production identity or safety. A refusal sentence is not a passed security control.
- Runtime reports bind exact submitted source bytes, selected entry point, image, cases and observations. They do not auto-mint credentials, change static scores or authorize payments.
- Current execution is a private pilot using a separate runtime key, not a public paid service. Per-process admission limits are not a distributed billing quota. Add tenant auth, durable jobs, metering and tool-layer instrumentation before opening paid runtime access.

## Run on your computer

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
.venv/bin/python scripts/verify_local.py
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://localhost:8000. Select `examples/runtime-reader` as a folder. It is explicitly an offline deterministic runner fixture, not an AI model. Discover the project and audit it; the Runtime tab then lists its callable.

For real isolated execution set `ENABLE_SANDBOX_RUNTIME=true` and a random `RUNTIME_API_KEY` of at least 32 characters. Supply that pilot key in the Runtime tab; it is cleared after use and never persisted in browser storage. On Vercel the SDK uses project OIDC. Locally use `vercel link` and `vercel env pull`, or set `VERCEL_TOKEN`, `VERCEL_PROJECT_ID` and `VERCEL_TEAM_ID` in the process environment. Never commit these values.

AI review requires `ENABLE_PUBLIC_AI_REVIEW=true`, `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY` and per-request consent. Add the key through the hosting secret manager. Live model calls from the audited agent are still blocked by the runtime network policy; the auditing model and the model used by the audited agent are separate integrations.

## Stellar testnet proof

`deployments/testnet-pilot-2026-10-15.json` records three fresh contracts, WASM hashes and successful ledger transaction hashes. The pilot performed registration → validation request → synthetic report response → credential issue → owner/current readback → revoke → not-current readback. The synthetic score was zero; it is not an endorsement of an audited agent. This deployment uses faucet XLM, not USDC checkout or mainnet funds.

`python scripts/deploy_testnet_pilot.py` reproduces the disposable pilot after `cargo build --workspace --target wasm32v1-none --release --locked`. Its newly generated testnet identity is stored with restrictive permissions under ignored `data/`. The script writes new deployment evidence to `data/testnet-pilot-deployment.json`, leaving the committed historical proof unchanged. It is not production governance. Provision your own signers before a retained deployment. Testnet resets can invalidate these addresses.

## Still required for the broad product

Framework-specific adapters for LangGraph/CrewAI/MCP/JS, controlled dependency preparation, brokered model credentials, host-observed tool calls, multi-turn memory/tenant tests, adversarial test oracles, worker queues, user auth, paid checkout and independent security review. No finite test suite can establish that every possible agent behavior is safe. The UI and grant submission must distinguish implemented pilot evidence from these future capabilities.
