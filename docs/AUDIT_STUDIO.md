# Audit Studio

The public Studio is served at `/`. The existing persistent operator UI is `/operator`. This is a separate admission route into the same rule engine, not a second network or a second score generator.

## Input contract

`POST /api/v1/studio/review`, `Content-Type: application/json`. No bearer key is required. Unknown top-level fields are rejected, including `endpoint_url`, owner-verification flags and signing credentials.

Save a bundle as `agent-audit.json` to import it in the browser:

```json
{
  "name": "Ledger reader",
  "network": "testnet",
  "stellar_address": "",
  "source_reference": "",
  "purpose": "Summarize supplied Stellar balances without signing transactions.",
  "system_prompt": "Read only. Never sign, execute code or reveal credentials.",
  "files": {
    "agent.py": "def summarize(balance):\n    return str(balance)\n"
  },
  "tools": [
    {
      "name": "read_balance",
      "scopes": ["read:chain"],
      "requires_signature": false,
      "network_access": false
    }
  ],
  "dependencies": []
}
```

`dependencies` is an array of pinned package/version strings, not an object. `spend_limit_usdc` in tool declarations is a legacy risk-analysis field, **not** a quote or an enforceable onchain allowance. Declare actual tool capabilities; a declaration is not proof that the implementation enforces it.

`network` is `testnet` (default) or `mainnet`; it is included in the input commitment. Optional `stellar_address` accepts checksum-valid public G/C addresses. Optional `source_reference` accepts a public GitHub repository URL. These are submitted associations, **not ownership or deployed-code bindings**. An address-only review accepts missing source but returns `needs_evidence`, with no prioritized source findings. Other submissions require source files or instructions.

## Public intake routes

All three Studio routes share the admission limits below and require no operator key.

| Route | Request | Meaning |
|---|---|---|
| `POST /api/v1/studio/identify` | `address`, `network` | Fixed Horizon account lookup or RPC contract-instance read |
| `POST /api/v1/studio/import` | `repository`: `https://github.com/owner/repository` | Fetch and validate the root `agent-audit.json` on the default branch |
| `POST /api/v1/studio/review` | Version bundle above | Analyze the submitted evidence without network integrations |

Address lookup returns `ledger_presence: found / not_found / unavailable`. An unavailable provider is not treated as a missing address. Archived contract state can be absent from active ledger lookup. `owner_verified` and `agent_verified` remain false even when the address exists. Mainnet lookup is read-only and does not enable operator signing or transaction submission.

GitHub imports use only the fixed `api.github.com/repos/.../contents/agent-audit.json` endpoint with redirects, environment proxies and authentication disabled. Downloads are capped at 128 KiB and validated against the same review schema. Private repositories, arbitrary URLs, branch selectors and whole-repository cloning are not supported. Import does not attest repository ownership or bind a Git commit: the later review commits the actual submitted contents. A missing bundle produces an actionable error and the UI offers a downloadable template or local upload.

## Bounds and isolation

| Limit | Value |
|---|---:|
| HTTP body, checked before JSON parsing | 128 KiB |
| Source files | 12 |
| One source file | 32,000 UTF-8 bytes |
| All source files | 64,000 UTF-8 bytes |
| Prompt | 12,000 characters |
| Tools / dependencies | 20 / 100 |
| Python AST nodes across the bundle / depth | 5,000 / 50 |
| Admission rate | 30 requests/minute per server process |

Paths must be relative, with no hidden segments, backslashes, drive prefixes or case-duplicate filenames. Accepted suffixes: `.py`, `.js`, `.ts`, `.rs`, `.go`, `.json`, `.md`, `.txt`, `.toml`, `.yaml`, `.yml`. Python must parse before review. Filenames and size checks are not a secret detector: never upload credentials.

The review route constructs an in-memory artifact with no callable endpoint or owner signature. A supplied public G/C identifier is only an unverified association. Review force-disables LLM, RPC/Horizon, screening, IPFS and active probes, regardless of operator integration settings. It never calls the persistent pipeline or publishes a report. The separate, user-triggered intake routes do make the bounded external reads described above. `Cache-Control: no-store` applies to responses. The browser does not use local/session storage for source or results. Exported reports contain source excerpts and should be treated as sensitive.

The process-wide limiter is intentionally conservative for the prototype. It is not tenant fairness or distributed abuse protection. Before internet exposure, add reverse-proxy body/read-time limits, per-client quotas, bounded worker concurrency, TLS and a request-log policy excluding bodies. Do not run arbitrary submissions in the API process. Transport/provider logs, OS swap and crash dumps are outside the application's no-persistence guarantee.

## Output and interpretation

The response contains `mode`, `decision`, `priority_finding_ids`, `scope`, `report`, `report_json` and `report_sha256`. `needs_fixes` means a directly evidenced high/critical finding from the source/configuration rules warrants investigation; `needs_evidence` is not a pass. Unverified ownership is an expected gap for this unauthenticated route, not a source defect.

`report_json` is the exact canonical UTF-8 file to download. The browser checks its SHA-256 before displaying the dossier and renders the committed report bytes. Editing inputs invalidates the displayed review. HTTP 413 means the body is too large; 422 identifies an invalid bundle; 429 requests a retry after a minute. Inputs remain available after a failed review.

```bash
sha256sum agent-review.json
```

Compare that result with `report_sha256`. A matching hash proves file integrity only. Source-level `confirmed` findings are not executed exploits. Legacy scenario `passed` values may mean that a defense keyword was present, not that an adversarial runtime test passed.

## Persistent operator reports

Use `Authorization: Bearer <operator key>` for stored agents, jobs, reports, badges, monitoring subscriptions and accounting records. A public Studio request does not create any of these records. Single-operator credentials must never be embedded in a public frontend bundle or query string.

| Route | Meaning |
|---|---|
| `/api/v1/jobs/{id}/report.json` | Mutable lifecycle view, including current attestation metadata |
| `/api/v1/jobs/{id}/report.committed.json` | Original canonical report whose exact hash was used for attestation |
| `/api/v1/jobs/{id}/report.md` | Current human-readable view |

The committed endpoint resolves the local raw CID from the report hash, even if Pinata returned a different public CID, and checks the bytes before returning them. It rejects missing or tampered content; it does not regenerate an allegedly identical report. Later transaction reconciliation must not change the originally committed bytes.

## Targeted verification

```bash
.venv/bin/python -m pytest -q \
  backend/tests/test_studio_intake.py \
  backend/tests/test_audit_studio.py \
  backend/tests/test_deep_agent_audit.py \
  backend/tests/test_api_security.py \
  backend/tests/test_swarm_e2e.py
node --check frontend/studio.js
node --check frontend/app.js
```

Use the two labeled fixtures in `frontend/studio-fixtures.json` as examples, not an accuracy benchmark. The unsafe fixture deliberately exposes a secret to logging, external input to a shell and external input to a Stellar transaction. The reader fixture supplies no signing capability. Broader independent ground truth and runtime testing remain required.
