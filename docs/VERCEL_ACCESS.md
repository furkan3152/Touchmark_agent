# Vercel connection access diagnosis

Checked on 2026-10-15. This is an access diagnosis, not evidence that the protected deployment has passed an HTTP or browser test.

## Observed access

| Check | Result |
| --- | --- |
| Vercel plugin status | Installed and enabled |
| Connected Vercel username | `archiallearn-7890` |
| Reported default team | `team_LLIu3B0wfSXbN3x0c02qr5D3` (`akdogan1`) |
| Project | `agentveritas-stellar`, `prj_DQwkjnlNmbe4waF8adbfDqCaLNDV` |
| Project read without an explicit team argument | Succeeds |
| Team listing | Empty |
| Explicit owning-team protected-access request | HTTP 403 scope authorization failure |
| Protected URL fetch through the connector | HTTP 403 for protection-bypass read permission |
| Integration configuration metadata, unscoped | Read succeeds; exposes a Neon installation, not the ChatGPT OAuth grant |
| Local Vercel token/OIDC environment variables and ordinary CLI login files | No configured credentials found; only presence was checked |

The first project/team observations come from this development session. The follow-up investigation did not repeat unchanged denied operations. It did not extract connector credentials, disable deployment protection, alter permissions, install another connector or use a browser session.

The successful project read and empty team list establish inconsistent access across operations. They do **not** establish whether the underlying cause is an expired grant, a missing team grant, an account mismatch or a provider-side authorization defect.

## Required next step

The account owner should reauthorize the **existing Vercel connection** through its connection settings, signing in to the Vercel account that can administer `agentveritas-stellar` in `akdogan1`. During Vercel's OAuth consent flow, grant access to that owning team when offered. The current tools do not expose a reconnect or OAuth grant editor; this consent step must happen in the account owner's connection flow.

If the Vercel dashboard presents an installed integration with project-access controls, its documented path is **Integrations → Manage → Access → Manage Access**. Apply that only to the relevant integration if it actually exists there. The observed Neon installation is unrelated and should not be changed. A ChatGPT plugin's “ask before changes” setting is also unrelated to Vercel OAuth scopes.

If no team grant control appears, or reauthorization leaves the same access failure, contact Vercel support with this sanitized diagnosis and the project/team identifiers. Do not repeatedly reconnect or weaken deployment protection as a workaround.

## Verification after the authorization state changes

1. Read the authenticated account and accessible teams; confirm the intended owner and owning team.
2. Read this project using the owning-team scope.
3. Use the connector's protected deployment access flow once. A successful project metadata read alone does not verify protected HTTP access.
4. Run the deployed application checks only after authorized HTTP access succeeds. Until then, report local checks, microVM checks and deployment readiness separately from deployed end-to-end verification.

CLI installation alone is not a remedy: MCP and CLI use separate authentication. A new CLI login would require an independent user-authorized login and should retain the same team/project scope.

## Official references

- [Vercel MCP tools: sign in and grant team access](https://vercel.com/docs/agent-resources/vercel-mcp/tools)
- [Vercel MCP connection and OAuth overview](https://vercel.com/docs/agent-resources/vercel-mcp)
- [Integration permissions and project access](https://vercel.com/docs/integrations/install-an-integration/manage-integrations-reference)
- [Vercel Authentication and deployment access](https://vercel.com/docs/deployment-protection/methods-to-protect-deployments/vercel-authentication)
