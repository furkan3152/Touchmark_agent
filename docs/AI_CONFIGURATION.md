# AI review configuration

The source-review AI is an optional, external second opinion. It is not the agent
under test, and enabling it does not give the isolated runtime network access or
install agent dependencies. Static review remains available without a model.

## Supported connection paths

| Runtime | Authentication | Configuration |
| --- | --- | --- |
| Local or another host | AI Gateway API key | `LLM_PROVIDER=vercel`, `AI_GATEWAY_API_KEY`, explicit `LLM_MODEL` |
| Vercel deployment | Project OIDC token supplied by Vercel | `LLM_PROVIDER=vercel`, explicit `LLM_MODEL`; no model-provider API key required |
| Linked local Vercel project | OIDC from `vercel env pull` | Load the pulled environment explicitly; refresh the token when it expires |
| Direct provider | Provider API key | Supported provider name, `LLM_API_KEY`, provider-specific model ID |

The fixed provider names are `vercel`, `anthropic`, `openai`, `openrouter`,
`deepseek`, `groq`, and `together`. Credentials are sent only to that provider's
fixed HTTPS endpoint. An unknown provider or a different `LLM_BASE_URL` disables
the integration. Redirects and arbitrary local/custom model URLs are not supported.
For Gateway, an explicit `AI_GATEWAY_API_KEY`, then `LLM_API_KEY`, takes precedence
over OIDC; an invalid explicit key does not silently fall back to another credential.

On 2026-10-15 the public Gateway catalog returned `openai/gpt-4.1-mini`, supporting
text, `max_tokens`, and structured output. It is a bounded, inexpensive pilot
choice, not an assertion that it finds every vulnerability. Set `LLM_MODEL`
explicitly; Gateway model IDs include the provider prefix. Recheck the live
catalog before changing models.

## Local setup

Install the repository's existing requirements. In the gitignored `.env` file,
configure these non-secret values:

```dotenv
LLM_PROVIDER=vercel
LLM_MODEL=openai/gpt-4.1-mini
ENABLE_PUBLIC_AI_REVIEW=true
LLM_MAX_INPUT_BYTES=28000
LLM_MAX_OUTPUT_TOKENS=1800
LLM_TIMEOUT_SECONDS=20
LLM_MAX_RESPONSE_BYTES=128000
```

Store `AI_GATEWAY_API_KEY` and a random `AI_REVIEW_API_KEY` of at least 32 characters
in the same private environment or a secret manager. The latter authorizes access
to this application's AI review; it is not a provider key. Do not put either key
in source, URLs, report inputs or chat. The pilot can use the existing runtime key
as its access fallback when the operator has configured that route.

For linked local OIDC instead of a Gateway key:

```bash
vercel link
vercel env pull .env.local
```

Select the existing `agentveritas-stellar` project. The downloaded file is
already ignored by git. OIDC tokens expire after approximately 12 hours during
local development; repeat `vercel env pull` to refresh. Configure the non-secret
values above in the local environment as well. This application normally reads
`.env`, so explicitly load `.env.local` when using the pulled file:

```bash
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --env-file .env.local
```

For `.env`, omit `--env-file .env.local`. A source review needs both
`ai_assistance=true` and `external_processing_consent=true`, together with the
application's private pilot authorization. Provider credentials stay on the
server. The historical name `ENABLE_PUBLIC_AI_REVIEW` is an operator feature
switch; it must not be interpreted as permission for unauthenticated paid calls.

## Explicit connection canary

This command makes at most one model request, with a 64-token output cap and no
customer source. It is an intentional billable check, not an automatic health
probe. It prints safe outcome and usage metadata, never credentials:

```bash
.venv/bin/python - <<'PY'
import asyncio
import json
from backend.app.config import Settings
from backend.app.swarm.llm import LlmClient
settings = Settings()  # Use Settings(_env_file=".env.local") for pulled local OIDC.
print(json.dumps(asyncio.run(LlmClient(settings).check_connection()), indent=2))
PY
```

`connection_verified=true` requires an actual usable provider response. A configured
key, successful deployment or accessible model catalog does not establish that.
Without a credential the result is `not_configured`, `request_sent=false`.
Authentication failure, denied permission, insufficient credit, rate/budget
limits, provider unavailability and invalid output have distinct safe reason codes.
No error response body or authorization header is returned to the caller.

## Vercel deployment

Enable project OIDC and set the non-secret provider/model values above in the
chosen deployment environment. Set `AI_REVIEW_API_KEY` as a sensitive environment
variable, or use the existing private runtime access gate. Redeploy to apply
configuration. Vercel supplies `VERCEL_OIDC_TOKEN`; do not copy a local temporary
OIDC token into permanent project environment variables.

OIDC replaces the authentication key, not billing, team access, Gateway credits
or project budgets. Keep paid review behind authenticated pilot access. Verify
the explicit canary from the deployment's authorized runtime before calling the
connection live. Deployment Protection and application authorization remain
separate controls; a blocked preview request is not a model-provider test.

## Bounds, costs and report meaning

One second opinion makes at most one request, with no automatic retries. By
default the combined input is capped at 28,000 UTF-8 bytes, output at 1,800 tokens,
response body at 128 KB, and elapsed time at 20 seconds. Runtime AI scenario
planning is a separate bounded call and is not included in that single-review
request count. The operator swarm can make additional model requests when
separately enabled; do not use the single-review cap as a deployment-wide cap.

Token limits bound individual requests. They are **not a hard dollar budget**.
Set a Gateway project/API-key or direct-provider budget and monitor billed usage.
The report records actual provider token counts when supplied. `cost_usd` is only
filled when the provider reports a numeric cost; otherwise it remains null. No
estimated or zero price is substituted for unknown billing.

The public catalog listed the pilot model at $0.40 per million input tokens and
$1.60 per million output tokens on 2026-10-15. Those are catalog prices, not a
billing guarantee; routing, service tiers and future pricing can differ.

The model sees redacted, line-numbered source within the byte budget. The report
lists supplied versus omitted lines. Redaction is best effort; explicit external
processing consent is required. Every accepted observation must cite a line that
was actually sent and contain a matching source quotation. Matching the quotation
does not validate the model's interpretation. Observations remain inferred and
never change deterministic scores or authorize a transaction or credential.

- `completed`: at least one source-grounded hypothesis was accepted.
- `no_observations`: the provider returned an empty hypothesis list; no safety conclusion.
- `invalid_response`: all proposed hypotheses failed source grounding.
- `unavailable`: no usable provider review; inspect `provider_call.status`.

## Verification status

Provider transport, error handling, redaction, bounds and grounding are covered
by mocked HTTP regression tests. On 2026-10-15, an explicitly invoked Vercel
Preview build used its own OIDC identity for a real Gateway connection canary and
a separate source review with `openai/gpt-4.1-mini`. Both completed. The private
proof was authenticated, hash-checked and independently denied anonymous access.
See [deployed integration evidence](../deployments/deployed-integrations-2026-10-15.json).

The two calls used 339 provider-reported tokens and reported $0.0002616 in model
cost, excluding Sandbox/build charges. The model's one accepted observation was
a speculative future-risk hypothesis about an ignored prompt parameter, not a
verified vulnerability; it did not change the deterministic score. This confirms
the connection and grounding pipeline, not useful detection accuracy. Protected
deployed HTTP, browser and Freighter journeys remain unverified. Local AI still
requires a separately configured credential; no build identity was exported.

## Official sources

- [Gateway authentication](https://vercel.com/docs/ai-gateway/authentication-and-byok)
- [Gateway OIDC setup and lifetime](https://vercel.com/docs/ai-gateway/authentication-and-byok/oidc)
- [Gateway Chat Completions HTTP API](https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-chat-completions)
- [Live model catalog](https://ai-gateway.vercel.sh/v1/models)
- [Gateway budgets](https://vercel.com/docs/ai-gateway/observability-and-spend/budgets)
