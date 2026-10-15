# Veritas Blueprint v1

Blueprint is AgentVeritas's versioned project mapping protocol. It connects declared intent and component locations to source evidence and a reproducible audit plan. It does not infer an agent from its filename, treat declarations as enforcement, or certify an entire repository from a selected upload.

## Project structure

Use `veritas.json` at the uploaded project root. Existing projects keep their directories: every component uses an exact path relative to that root. The reference project is `examples/blueprint-reader`.

| Path in the reference project | Purpose |
| --- | --- |
| `veritas.json` | Purpose, component map, callable, permission boundaries and custom scenarios |
| `agent/main.py` | Real callable: `respond(message)` |
| `agent/instructions.md` | Intended behavior and limits |
| `agent/tools.py` | Offline fixture tool implementation |
| `agent/policy.json` | Declared tool configuration |

Additional roles are `implementation`, `memory`, `delegate`, `contract`, `test` and `dependency`. Declare only components that exist, include their source, and inspect undeclared surfaces in the report. A missing role means **not declared**, not absent or safe. Multiple roles may refer to one file. Exactly one component must be the entrypoint.

The example is deliberately deterministic. It does not call an LLM or read a real account. Production adapters must invoke the actual agent and its real policy layer; a mock cannot certify production behavior.

## Local workflow

From the AgentVeritas checkout, after installing `backend/requirements-dev.txt`:

```bash
.venv/bin/python scripts/veritas.py init /absolute/path/to/your-agent
.venv/bin/python scripts/veritas.py check /absolute/path/to/your-agent
.venv/bin/python scripts/veritas.py plan /absolute/path/to/your-agent
```

`init` parses source without importing it and writes a draft only if it finds one supported callable. It refuses to overwrite an existing manifest. Review the generated purpose, roles and permission boundaries. An ambiguous project needs an explicit entrypoint using `schemas/veritas-blueprint-v1.schema.json` and the reference manifest. `check` and `plan` print the compiled JSON plan, returning nonzero if the map is blocked or absent. These commands never install packages or run agent code.

In Studio, select the project folder or import a public GitHub repository with a root `veritas.json`. Discovery displays component paths, source hashes, blockers, import edges, declared permission boundaries and planned checks. Legacy projects can download a draft manifest from discovery when one callable is identifiable. Place the reviewed draft in the project root and upload again.

## How resolution works

1. Parse a strict versioned schema. Reject duplicate JSON keys, unknown fields, traversal, hidden/sensitive paths, globs, duplicate IDs and dangling component references.
2. Select exact manifest paths. GitHub import resolves one immutable commit and verifies Git blob hashes. Files outside the declared scope are reported as omitted. Missing references and upload limits remain visible; they do not trigger guessed execution.
3. Hash each supplied component and parse the entrypoint signature. Blueprint v1 runtime accepts an undecorated top-level Python callable with one positional argument, synchronous or asynchronous. Other languages remain source-review inputs and need a future execution adapter.
4. Resolve literal Python imports against supplied modules. Missing relative modules block execution. External/ambiguous imports remain explicit uncertainties. Dynamic imports, resource reads, package initialization effects and external dependencies are not fully resolved by this graph.
5. Generate role-specific checks and declared permission edges. These are a **plan**, not completed security tests. Memory isolation, dependency provenance, signing authorization and other unsupported checks retain `evidence_review_required`.
6. Compute a SHA-256 fingerprint over source, manifest, plan and protocol version. Runtime requires this exact fingerprint; changes require rediscovery. The static report includes the map and runtime evidence references its plan hash.

Pilot scope remains 12 files, 32 KB per file, 64 KB total and bounded Python AST complexity. A declaration may describe a larger project, but missing files or exceeded scope prevent execution. This is not whole-repository coverage. Increase these limits only alongside queued analysis and resource controls.

## Execution and assertions

Runtime stays opt-in and requires a separate pilot key. The actual supplied callable executes in a disposable microVM with denied outbound network, no production credentials, bounded child processes and a fixed supervisor. Relative Python imports resolve within the uploaded project. Missing dependencies or live network/model needs produce blocked or inconclusive evidence; the service does not silently substitute a model or install arbitrary packages.

Six baseline probes cover ordinary behavior, instruction override, retrieved-text injection, secrets, unapproved payments and delegation. Up to two developer scenarios add bounded text input and `contains` / `excludes` expectations. The external evaluator marks each text assertion matched, not matched or not evaluated. Neither matching text nor a refusal proves tool enforcement. AI can propose additional text probes only with configured provider and explicit source-processing consent, within the same eight-case cap.

Permission boundaries describe intended interactions; they do not intercept tool calls. The supplied callable may recognize tests or falsify in-VM telemetry. Cross-tenant memory, multi-turn interactions, actual signer authorization, deployment identity and live tool effects still need dedicated evidence. No runtime observation automatically issues a credential, changes a score or authorizes payment.

## Stellar binding

Blueprint's plan hash is included in the canonical static report and referenced by runtime reports. This allows an operator to bind the exact reviewed evidence to the existing report-hash attestation path. The manifest itself neither mints a credential nor proves ownership. Runtime reports are not automatically anchored by this feature. Credential issuance still requires the existing authorized contract workflow and evidence policy.

## Local verification

```bash
.venv/bin/python scripts/veritas.py check examples/blueprint-reader
.venv/bin/python scripts/verify_local.py
.venv/bin/python -m pytest backend/tests/test_blueprint.py -q
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` on the machine running the server. This verifies the UI/API locally; actual execution additionally needs the Sandbox provider configuration described in `docs/RUNTIME_PILOT.md`.
