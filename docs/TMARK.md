# `.tmark`: declare your agent

A `.tmark` file at the root of a repository tells Touchmark, and anyone reading the report, what the agent is and what it is allowed to do. Touchmark then checks the code against each claim.
- A claim the code keeps is shown as declared.
- A claim the code breaks is reported as a risk.
- A declaration never closes a risk on its own.

The format is strict on purpose:
- one JSON object;
- every field has one meaning;
- unknown fields are rejected;
- a file with any error is not used at all.

Schema: [`/schemas/tmark-v1.json`](https://touchmark-stellar.vercel.app/schemas/tmark-v1.json). Editors that read `$schema` (VS Code, JetBrains) validate it as you type.

## Start

```bash
python scripts/tmark.py init path/to/repo    # writes .tmark, pre-filled from what the code can do
python scripts/tmark.py check path/to/repo   # lists every error; Touchmark ignores an invalid file
```

Commit `.tmark` at the root, next to `README.md`. The [GitHub Action](../README.md#in-ci) checks it on every push and annotates each error on the file.

## Example

```json
{
  "$schema": "https://touchmark-stellar.vercel.app/schemas/tmark-v1.json",
  "tmark": "1",
  "agent": {
    "name": "Treasury agent",
    "purpose": "Pays two listed suppliers in XLM on request and reads invoices from one fixed host.",
    "kind": "mcp_server",
    "network": "testnet",
    "discloses_ai": true
  },
  "owner": { "stellar_account": "GDM7FY4WBPRLTY4WYE7FKFHQVUI5FYE3WDLNHTDVNKMJ2VNTTQEPBYZV" },
  "authority": { "holds_keys": true, "key_source": "env", "signs": ["payments"] },
  "limits": {
    "per_payment": { "amount": "500", "asset": "XLM" },
    "recipients": "allowlist",
    "human_approval": "never"
  },
  "tools": [
    { "name": "send_payment", "description": "Pay a listed supplier in XLM, at most 500 per payment",
      "moves_funds": true, "signs": true, "network": true, "max_amount": { "amount": "500", "asset": "XLM" } },
    { "name": "fetch_invoice", "description": "Read an invoice by id from the fixed invoice host",
      "moves_funds": false, "signs": false, "network": true }
  ],
  "forbidden": ["pay anyone who is not in the supplier table"],
  "contact": { "security": "security@example.com" }
}
```

## Fields

| Field | Required | Values | What Touchmark checks |
|---|---|---|---|
| `tmark` | yes | `"1"` or `"1.1"` | A file that uses a 1.1 field or value must say `"1.1"` |
| `agent.name`, `agent.purpose` | yes | text; purpose is 20 to 1000 characters | The purpose is the intent the code is judged against |
| `agent.kind` | yes | `mcp_server`, `autonomous_agent`, `x402_client`, `x402_server`, `sdk`, `skill`, `contract`, `other` | |
| `agent.network` | yes | `testnet`, `mainnet`, `both` | `testnet` with mainnet passphrases or endpoints in code → **network mismatch** |
| `agent.discloses_ai` | no | boolean, default `true` | |
| `owner.stellar_account` | no | a valid `G...` account | The credential is issued to this account after it signs in Freighter |
| `authority.holds_keys` | yes | boolean | `false` while the code loads or uses a key → **authority mismatch** |
| `authority.key_source` | yes | `env`, `kms`, `external_signer`, `wallet_prompt`, `none`; 1.1: `caller_supplied`, `agent_generated` | Must agree with `holds_keys`. `caller_supplied`: the caller passes a secret with each call and the agent keeps none, so loading that key is not an authority mismatch (its path through the model is still checked). `agent_generated`: the agent creates and stores a key itself; `holds_keys` must be `true` |
| `authority.signs` | yes | any of `payments`, `contract_calls`, `account_changes`, `trustlines`, `foreign_transactions`, `messages` | The code signing something not listed → **authority mismatch** |
| `authority.agent_account` | no | `G...` or `C...` | Read from the ledger: signers, thresholds, balances |
| `limits` | when the agent moves funds | | |
| `limits.per_payment`, `limits.per_day` | no | `{amount, asset}` | Missing cap or running total in the paying code → **limit not enforced** |
| `limits.recipients` | yes | `allowlist`, `any`, `none` | `allowlist` without one in code → **limit not enforced** |
| `limits.human_approval` | yes | `always`, `above_limit`, `never` | An approval gate must exist in code |
| `tools[]` | no | `name`, `description`, `moves_funds`, `signs`, `network`, `files` (optional: reads or writes local files), `max_amount` | Compared with the tools the code registers and what each can do. A tool with `moves_funds` or `signs` discloses financial authority |
| `tools[].executes_code` | no (1.1) | boolean | The tool runs a shell command or code. Declared execution is disclosed (no "undeclared capability"), and what runs is still checked for untrusted input |
| `tools[].generated` | no (1.1) | `{pattern, source}`: a glob every generated tool name matches, and what the tools are generated from | A family of tools the code creates at run time (one per contract function). Registered names the pattern matches count as declared |
| `forbidden[]` | no | 8 to 300 characters each | Used as goals the agent must refuse |
| `entrypoints[]` | no | `{path, symbol}` | Marks where outside input enters, for the data-flow analysis |
| `contact.security` | no | email or URL | Shown in the report |

Amounts are decimal strings with up to 7 decimal places, Stellar's precision. Assets are written as `XLM`, `CODE:ISSUER` (with a `G...` issuer) or a `C...` token contract, so a look-alike asset cannot satisfy a limit.

## Version 1.1

1.1 adds only optional fields and values, so every `"1"` file keeps validating unchanged. Use it when a `"1"` file cannot say what the agent does:

```json
{
  "tmark": "1.1",
  "authority": { "holds_keys": true, "key_source": "caller_supplied", "signs": ["payments"] },
  "tools": [
    { "name": "soroban_build", "description": "Run stellar contract build in a local directory",
      "moves_funds": false, "signs": false, "network": false, "files": true, "executes_code": true },
    { "name": "contract_functions", "description": "One tool per function of each registered contract",
      "moves_funds": true, "signs": true, "network": true,
      "generated": { "pattern": "*", "source": "each function of every contract the caller registers" } }
  ]
}
```

## Without committing it

A declaration does not have to be committed to be checked:

- `POST /api/v1/tmark/check` validates a file and returns every error with its field and line, the declaration as Touchmark reads it, and a plain summary.
- `POST /api/v1/tmark/template` drafts a `.tmark` from a repository's code: the tools it registers and what the code in each tool's file can do. Fill in every empty field.
- The home page and Studio accept a pasted or uploaded `.tmark` and audit with it as if it were committed. A repository's own `.tmark` is used when none is supplied; when both exist, the report says which was used and lists where they differ. A supplied declaration never names the owner: only a committed file decides who can receive a credential, and an audit run with a supplied declaration is not credentialed.
- `python scripts/ci_audit.py PATH --tmark FILE` does the same in CI.

## Scope

The audit reads the agent's source and leaves out tests, examples, docs, templates, generators and build output. The report lists what was left out (`repository.excluded_scope`). A declared tool that signs or moves funds, when the analysed code never uses a key the agent holds, is reported as a scope gap (`security-declared-tools-outside-scope`), not as a missing limit: audit the folder that holds that tool directly.

## Older files

`touchmark.json`, `agentveritas.json` and `veritas.json` are still read when there is no `.tmark`, and the report asks you to migrate. When a `.tmark` exists, the older files are ignored.
