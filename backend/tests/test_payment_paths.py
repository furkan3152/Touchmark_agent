"""x402 / MPP payers and sellers, and fee sponsors: each rule with a vulnerable fixture and a
safe near-miss. Versions come from a synthetic lockfile record (no network)."""

from __future__ import annotations

import asyncio
import json

from backend.app.config import Settings
from backend.app.models import AgentArtifact, SourceKind
from backend.app.services.repo_audit import audit_repository
from backend.app.swarm.agentic_paths import analyse_agentic_paths
from backend.app.swarm.hardening import analyse_hardening, find_credentials


def lock(root: str = "", **versions: str) -> dict:
    """A resolved_versions record with every package locked at the given version."""
    deps = dict(versions)
    return {"importers": {root: {"lockfiles": [f"{root}/package-lock.json".lstrip("/")],
                                 "deps": {n: {"spec": f"^{v}", "version": v} for n, v in deps.items()}}},
            "locked": {f"{root}/package-lock.json".lstrip("/"): {n: [v] for n, v in deps.items()}}}


def unlocked(**specs: str) -> dict:
    return {"importers": {"": {"lockfiles": [], "deps": {n: {"spec": s, "version": None} for n, s in specs.items()}}},
            "locked": {}}


def rule(fid: str) -> str:
    """security-x402-settle-unchecked-1a2b3c4d -> security-x402-settle-unchecked (stable ids)."""
    head, _, tail = fid.rpartition("-")
    return head if len(tail) == 8 and all(c in "0123456789abcdef" for c in tail) else fid


def paths(files: dict, resolved: dict | None = None, **meta) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files,
                             raw_metadata={"resolved_versions": resolved or {}, **meta})
    return {rule(f.id): f for f in analyse_agentic_paths(artifact, "security")}


def hardening(files: dict, **meta) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files, raw_metadata=meta)
    return {rule(f.id): f for f in analyse_hardening(artifact, "security")}


X402 = "security-path-x402-payment-unbounded"
CORE = {"@x402/core": "2.28.0", "@x402/fetch": "2.28.0", "@x402/stellar": "2.28.0"}
PAYER = ('import { x402Client, wrapFetchWithPaymentFromConfig } from "@x402/fetch";\n'
         'import { ExactStellarScheme } from "@x402/stellar/exact/client";\n'
         'export const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "stellar:testnet", '
         'client: new ExactStellarScheme(signer) }] });\n')


# --------------------------------------------------------------------------- (A) x402 payer cap
def test_x402_client_below_the_default_cap_release_pays_what_the_server_asks():
    found = paths({"src/pay.ts": PAYER}, lock(**{"@x402/core": "2.8.0", "@x402/fetch": "2.8.0"}))
    assert found[X402].severity.value == "high" and "2.8.0 installed" in found[X402].evidence


def test_x402_cap_that_depends_on_install_date_is_medium():
    found = paths({"src/pay.ts": PAYER}, unlocked(**{"@x402/core": "^2.17.0", "@x402/fetch": "^2.17.0"}))
    assert found[X402].severity.value == "medium" and "install date" in found[X402].evidence


def test_x402_client_on_a_capped_release_is_not_unbounded():
    config = PAYER.replace("}] });", "}], spendControls: { maxAmountPerPayment: '$0.50' },\n"
                                     "  policies: [(v, reqs) => reqs.filter((r) => ALLOWED.has(r.payTo))] });")
    found = paths({"src/pay.ts": config}, lock(**CORE))
    assert not [f for f in found if "x402" in f]
    # The default cap is a per-call cap: the control rules see it.
    assert "security-path-controls-not-enforced" not in paths({"src/pay.ts": PAYER}, lock(**CORE))


def test_x402_budget_check_before_signing_a_payload_is_not_unbounded():
    tool = ('import { x402Client, x402HTTPClient } from "@x402/core/client";\n'
            'export async function pay(req: any) {\n  if (!budget.check(Number(req.amount))) throw new Error("budget");\n'
            '  return http.createPaymentPayload(req);\n}\n')
    assert X402 not in paths({"src/pay.ts": tool}, lock(**{"@x402/core": "2.17.0"}))


def test_x402_hook_that_compares_the_requirement_amount_caps_the_client():
    old = lock(**{"@x402/core": "2.17.0", "@x402/fetch": "2.17.0"})
    head = ('import { x402Client, wrapFetchWithPayment } from "@x402/fetch";\n'
            'const client = new x402Client();\nclient.register("stellar:*", scheme);\n')
    hook = ('client.onBeforePaymentCreation(async ({ selectedRequirements }): Promise<void | { abort: true }> => {\n'
            '  if (BigInt(selectedRequirements.amount) > MAX_ATOMIC) return { abort: true };\n});\n')
    wrap = "export const pay = wrapFetchWithPayment(fetch, client);\n"
    # A hook registered as a statement of its own configures the client it is called on.
    assert X402 not in paths({"src/pay.ts": head + hook + wrap}, old)
    # A comparison that reads no requirement (or only a type annotation's `<`) is no ceiling.
    retries = hook.replace("BigInt(selectedRequirements.amount) > MAX_ATOMIC", "retries.value > 3")
    assert paths({"src/pay.ts": head + retries + wrap}, old)[X402].severity.value == "high"
    typed = ('client.onBeforePaymentCreation(async ({ amount }: { amount: string }): Promise<void> => '
             'log(amount));\n')
    assert X402 in paths({"src/pay.ts": head + typed + wrap}, old)


def test_x402_controls_switched_off_in_another_module_are_not_a_default_cap():
    files = {"src/client.ts": 'import { x402Client } from "@x402/core/client";\n'
                              'export const client = x402Client.fromConfig({ schemes: [], spendControls: false });\n',
             "src/pay.ts": 'import { wrapFetchWithPayment } from "@x402/fetch";\nimport { client } from "./client";\n'
                           'export const pay = wrapFetchWithPayment(fetch, client);\n'}
    found = paths(files, lock(**CORE))
    assert found["security-x402-spend-controls-disabled"].severity.value == "high"
    assert "security-per-call-cap-only" not in found and "security-path-controls-not-enforced" in found


def test_x402_core_that_refuses_stellar_usdc_is_reported_as_failing_closed():
    found = paths({"src/pay.ts": PAYER}, lock(**{**CORE, "@x402/stellar": "2.17.0"}))
    assert X402 not in found and found["security-x402-stellar-usdc-not-default"].severity.value == "info"


# --------------------------------------------------------------------------- (B) x402 switches
def test_x402_spend_controls_switched_off():
    off = ('import { x402Client } from "@x402/core/client";\n'
           "export const client = x402Client.fromConfig({ schemes: [{ network: 'stellar:testnet', "
           "client: new ExactStellarScheme(signer) }], spendControls: false });\n")
    assert paths({"src/c.ts": off})["security-x402-spend-controls-disabled"].severity.value == "high"
    hooked = off + "client.onBeforePaymentCreation(async ({ selectedRequirements: r }) => ({ abort: true, reason: 'x' }));\n"
    assert paths({"src/c.ts": hooked})["security-x402-spend-controls-disabled"].severity.value == "medium"
    setter = ('import { x402Client } from "@x402/core/client";\n'
              'export const client = new x402Client().register("stellar:*", scheme).setSpendControls(false);\n')
    assert "security-x402-spend-controls-disabled" in paths({"src/c.ts": setter}, lock(**CORE))
    any_asset = off.replace("spendControls: false", "spendControls: { allowedAssets: true }")
    found = paths({"src/c.ts": any_asset}, lock(**CORE))
    assert found["security-x402-any-asset-uncapped"].severity.value == "medium"
    assert "security-x402-spend-controls-disabled" not in found
    # Before 2.23.0 the switch exists in no release: the unbounded payer finding covers the client.
    assert "security-x402-spend-controls-disabled" not in paths({"src/c.ts": off}, lock(**{"@x402/core": "2.8.0"}))
    # Confirmed only on a resolved release that has the switch.
    assert paths({"src/c.ts": off}, lock(**CORE))["security-x402-spend-controls-disabled"].evidence_grade.value == "confirmed"
    assert paths({"src/c.ts": off})["security-x402-spend-controls-disabled"].evidence_grade.value == "inferred"


def test_two_identical_switch_lines_in_one_file_are_one_finding():
    two = ('import { x402Client } from "@x402/core/client";\n'
           'export const a = x402Client.fromConfig({ schemes: A,\n  spendControls: false,\n});\n'
           'export const b = x402Client.fromConfig({ schemes: B,\n  spendControls: false,\n});\n')
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files={"src/c.ts": two},
                             raw_metadata={"resolved_versions": lock(**CORE)})
    found = [f for f in analyse_agentic_paths(artifact, "security") if "spend-controls" in f.id]
    assert len(found) == 1 and "src/c.ts:3" in found[0].evidence and "src/c.ts:6" in found[0].evidence


def test_two_mpp_servers_with_the_same_lines_audit_end_to_end(tmp_path):
    # The orchestrator refuses a verdict with duplicate ids; the audit must still complete.
    root = tmp_path / "agent"
    (root / "src").mkdir(parents=True)
    server = ('  stellar({\n    recipient: process.env.PAY_TO!,\n    currency: CURRENCY,\n  }),\n')
    (root / "src/server.ts").write_text(
        'import { Mppx } from "mppx/server";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
        'const SECRET = process.env.AGENT_SECRET!;\nconst kp = Keypair.fromSecret(SECRET);\n'
        f'export const main = Mppx.create({{ secretKey: SECRET, methods: [\n{server}] }});\n'
        f'export const test = Mppx.create({{ secretKey: SECRET, methods: [\n{server}] }});\n')
    (root / "package.json").write_text(json.dumps({"name": "agent", "dependencies": {"@stellar/mpp": "0.4.0", "mppx": "0.5.5"}}))
    out = asyncio.run(audit_repository(root, name="agent", purpose="", settings=Settings(_env_file=None), deep=False))
    ids = [f["id"] for f in out["report"]["findings"]]
    assert len(ids) == len(set(ids))
    replay = [f for f in out["report"]["findings"] if f["id"].startswith(STORE + "-")]
    assert len(replay) == 1 and "src/server.ts:6" in replay[0]["evidence"] and "src/server.ts:12" in replay[0]["evidence"]
    assert len([i for i in ids if i.startswith("security-mpp-secret-reuses-stellar-seed-")]) == 1


# --------------------------------------------------------------------------- (C, D) MPP
MPP = ('import { Mppx } from "mppx/server";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
       'import { USDC_SAC_TESTNET } from "@stellar/mpp";\n'
       'export const mppx = Mppx.create({ methods: [stellar.charge({ recipient: PAY_TO, currency: USDC_SAC_TESTNET })], '
       'secretKey: process.env.MPP_KEY });\n')
STORE = "security-mpp-replay-store-missing"


def test_mpp_charge_server_without_store_on_a_store_optional_release():
    found = paths({"src/server.ts": MPP}, lock(**{"@stellar/mpp": "0.4.0"}))
    assert found[STORE].severity.value == "medium" and "only testnet" in found[STORE].evidence
    mainnet = MPP.replace("USDC_SAC_TESTNET", "USDC_SAC_MAINNET")
    assert paths({"src/server.ts": mainnet}, lock(**{"@stellar/mpp": "0.3.0"}))[STORE].severity.value == "high"
    # From 0.5.0 the server refuses to start without a store; a store is never a finding.
    assert STORE not in paths({"src/server.ts": MPP}, lock(**{"@stellar/mpp": "0.7.1"}))
    stored = MPP.replace("currency: USDC_SAC_TESTNET", "currency: USDC_SAC_TESTNET, store: redisStore")
    assert STORE not in paths({"src/server.ts": stored}, lock(**{"@stellar/mpp": "0.4.0"}))


def test_mpp_memory_store_is_high_only_with_several_instances():
    memory = MPP.replace('import { stellar }', 'import { stellar, Store }').replace(
        "currency: USDC_SAC_MAINNET", "").replace("currency: USDC_SAC_TESTNET", "currency: USDC_SAC_MAINNET, store: Store.memory()")
    assert paths({"src/server.ts": memory}, lock(**{"@stellar/mpp": "0.7.1"}))[STORE].severity.value == "low"
    found = paths({"src/server.ts": memory}, lock(**{"@stellar/mpp": "0.7.1"}), deployment_markers=["vercel.json"])
    assert found[STORE].severity.value == "high" and "vercel.json" in found[STORE].evidence
    lambda_handler = memory + "export const handler = async (event) => mppx.handle(event);\n"
    assert paths({"src/server.ts": lambda_handler}, lock(**{"@stellar/mpp": "0.7.1"}))[STORE].severity.value == "high"
    # A handler exported by some other module, or a descriptor beside another app, says nothing
    # about how many copies of this server run.
    elsewhere = {"src/server.ts": memory, "scripts/cron.ts": "export const handler = async () => sweep();\n"}
    assert paths(elsewhere, lock(**{"@stellar/mpp": "0.7.1"}))[STORE].severity.value == "low"
    other_app = paths({"src/server.ts": memory}, lock(**{"@stellar/mpp": "0.7.1"}), deployment_markers=["web/vercel.json"])
    assert other_app[STORE].severity.value == "low"
    other_package = paths({"packages/api/src/server.ts": memory}, lock("packages/api", **{"@stellar/mpp": "0.7.1"}),
                          deployment_markers=["vercel.json"])
    assert other_package[STORE].severity.value == "low"


def test_mpp_literal_switches():
    def opts(extra: str, mode: str = "charge") -> str:
        return (f'import {{ stellar }} from "@stellar/mpp/{mode}/server";\n'
                f'export const m = stellar({{ recipient: PAY_TO, network: "stellar:pubnet", store, {extra} }});\n')
    v = lock(**{"@stellar/mpp": "0.7.1"})
    assert paths({"s.ts": opts("allowUnsignedPush: true")}, v)["security-mpp-unsigned-push-enabled"].severity.value == "high"
    assert paths({"s.ts": opts("allowUnsignedPush: false")}, v).keys().isdisjoint({"security-mpp-unsigned-push-enabled"})
    assert "security-mpp-channel-state-unchecked" in paths({"s.ts": opts("checkOnChainState: false", "channel")}, v)
    assert "security-mpp-fee-budget-unbounded" in paths({"s.ts": opts("maxFeeBumpStroops: 50_000_000")}, v)
    assert "security-mpp-fee-budget-unbounded" not in paths({"s.ts": opts("maxFeeBumpStroops: 1_000_000")}, v)
    sponsor = "feePayer: { envelopeSigner: kp, feeBumpSigner: kp }"
    assert "security-mpp-fee-budget-unbounded" in paths({"s.ts": opts(sponsor, "channel")}, v)
    assert "security-mpp-fee-budget-unbounded" not in paths({"s.ts": opts(sponsor + ", feeBudget", "channel")}, v)
    client = ('import { stellar } from "@stellar/mpp/channel/client";\n'
              'export const c = stellar({ commitmentKey: k, allowUnpinnedChannel: true });\n')
    assert paths({"c.ts": client}, v)["security-mpp-unpinned-channel"].severity.value == "high"
    assert "security-mpp-unpinned-channel" not in paths({"c.ts": client.replace("allowUnpinnedChannel: true",
                                                                                "allowedChannels: [CHANNEL]")}, v)
    # The option names alone do nothing outside files that use the SDK.
    assert "security-mpp-unsigned-push-enabled" not in paths({"s.ts": "export const o = { allowUnsignedPush: true };\n"}, v)


def test_mpp_secret_key_fallback_folds_into_default_secret():
    fallback = ('import { Mppx } from "mppx/express";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
                'const KEY = process.env.MPP_CHALLENGE ?? "dev-only";\n'
                'export const mppx = Mppx.create({ secretKey: KEY, methods: [stellar({ recipient: R })] });\n')
    found = hardening({"src/mpp.ts": fallback})
    assert found["security-default-secret"].evidence == "src/mpp.ts:3 secretKey"
    # The existing variable-name rule already reports this line: still one finding, one location.
    named = fallback.replace("MPP_CHALLENGE", "MPP_SECRET_KEY")
    assert hardening({"src/mpp.ts": named})["security-default-secret"].evidence == "src/mpp.ts:3 MPP_SECRET_KEY"
    assert "security-default-secret" not in hardening({"src/mpp.ts": fallback.replace(' ?? "dev-only"', "")})
    # An empty fallback fails closed: mppx refuses a falsy secretKey at start-up.
    assert "security-default-secret" not in hardening({"src/mpp.ts": fallback.replace('"dev-only"', '""')})
    assert "security-default-secret" not in hardening({"src/mpp.ts": fallback.replace('?? "dev-only"', "|| ''")})


def test_mpp_secret_that_is_the_stellar_seed_is_low():
    reuse = ('import { Mppx } from "mppx/server";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
             'const SECRET = process.env.AGENT_SECRET!;\nconst kp = Keypair.fromSecret(SECRET);\n'
             'export const mppx = Mppx.create({ methods: [stellar({ recipient: kp.publicKey() })], secretKey: SECRET });\n')
    assert hardening({"src/s.ts": reuse})["security-mpp-secret-reuses-stellar-seed"].severity.value == "low"
    own = reuse.replace("secretKey: SECRET", "secretKey: process.env.MPP_KEY")
    assert "security-mpp-secret-reuses-stellar-seed" not in hardening({"src/s.ts": own})


# --------------------------------------------------------------------------- (E) Stellar CLI
def test_committed_cli_identity_seed_phrase():
    from stellar_sdk.sep.mnemonic import Language, StellarMnemonic
    phrase = StellarMnemonic(Language.ENGLISH).generate(256)
    found = find_credentials(".stellar/identity/agent.toml", f'seed_phrase = "{phrase}"\n'.encode())
    assert found == [".stellar/identity/agent.toml:1 (Stellar CLI identity seed phrase, redacted)"]
    finding = hardening({}, committed_credentials=found)["security-committed-credential"]
    assert finding.severity.value == "medium"
    placeholder = b'seed_phrase = "word word word word word word word word word word word word"\n'
    assert find_credentials(".config/stellar/identity/a.toml", placeholder) == []
    assert find_credentials("notes/agent.toml", f'seed_phrase = "{phrase}"\n'.encode()) == []


def test_cli_auto_sign_in_an_agent_tool():
    tool = ('import { execFileSync } from "node:child_process";\n'
            'server.tool("invoke", "invoke", { fn: z.string() }, async ({ fn }) =>\n'
            '  execFileSync("stellar", ["contract", "invoke", "--id", ID, "--auto-sign", "--", fn]));\n')
    assert paths({"src/t.ts": tool})["security-cli-auto-sign"].severity.value == "medium"
    fixed = ('import { execFileSync } from "node:child_process";\n'
             'export const bump = () => execFileSync("stellar", ["contract", "invoke", "--id", ID, "--auto-sign", "--", "bump"]);\n')
    assert paths({"src/t.ts": fixed})["security-cli-auto-sign"].severity.value == "low"
    assert "security-cli-auto-sign" not in paths({"src/t.ts": tool.replace('"--auto-sign", ', "")})


# --------------------------------------------------------------------------- item 08: sellers
SELLER = ('import express from "express";\nconst app = express();\n'
          'app.get("/quote", async (req, res) => {\n'
          "  const p = JSON.parse(atob(req.header('PAYMENT-SIGNATURE')));\n"
          "  const r = await fetch(`${FAC}/settle`, { method: 'POST', body: JSON.stringify({ paymentPayload: p, "
          "paymentRequirements: p.accepted }) });\n"
          '  if (r.ok) return proxy(req, res);\n  return res.status(402).json({});\n});\n')


def test_payer_chosen_requirements_and_unchecked_settlement():
    found = paths({"src/server.ts": SELLER})
    assert found["security-x402-requirements-from-payer"].severity.value == "critical"
    assert found["security-x402-settle-unchecked"].severity.value == "high"


def test_settlement_success_checked_before_serving_is_safe():
    safe = ('import express from "express";\nconst app = express();\n'
            'app.get("/quote", async (req, res) => {\n'
            "  const payload = decodePaymentSignatureHeader(req.header('PAYMENT-SIGNATURE'));\n"
            "  const s = await facilitator.settle(payload, ROUTES['GET /quote'].accepts);\n"
            '  if (!s.success || !s.transaction) return res.status(402).json(s);\n  return proxy(req, res);\n});\n')
    assert not [f for f in paths({"src/server.ts": safe}) if "x402" in f]
    # Requirements the payer chose, compared field by field with the server's, are bound.
    bound = SELLER.replace("  const r = await", "  if (p.accepted.payTo !== PAY_TO || p.accepted.amount !== PRICE) "
                                                "return res.status(402).end();\n  const r = await")
    assert "security-x402-requirements-from-payer" not in paths({"src/server.ts": bound})


def test_helper_that_reports_success_only_by_http_status_is_unchecked():
    helper = ('async function settle(paymentPayload: unknown, paymentRequirements: unknown) {\n'
              '  const out = await fetch(`${FAC}/settle`, { method: "POST", body: JSON.stringify({ paymentPayload, paymentRequirements }) });\n'
              '  if (!out.ok) return { ok: false };\n  const d = await out.json();\n'
              '  return { ok: true, id: d.transaction };\n}\n')
    handler = ('export async function GET(req: Request) {\n'
               '  const header = req.headers.get("X-PAYMENT");\n  const payload = JSON.parse(atob(header));\n'
               '  const paid = await settle(payload, REQUIREMENTS);\n'
               '  if (!paid.ok) return new Response("pay", { status: 402 });\n'
               '  return fetch(UPSTREAM);\n}\n')
    files = {"src/app/api/data/route.ts": helper + handler}
    assert paths(files)["security-x402-settle-unchecked"].severity.value == "high"
    # A helper whose discriminator is set from success counts as the check.
    checked = helper.replace("  return { ok: true,", "  if (!d.success) return { ok: false };\n  return { ok: true,")
    assert "security-x402-settle-unchecked" not in paths({"src/app/api/data/route.ts": checked + handler})


SETTLE_HEAD = ('import express from "express";\nimport { decodePaymentSignatureHeader } from "@x402/core/http";\n'
               'const app = express();\nconst FAC = process.env.FAC_URL;\n')


def test_reading_the_facilitator_response_is_not_serving_the_resource():
    handler = (SETTLE_HEAD + 'app.get("/quote", async (req, res) => {\n'
               '  const payload = decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE"));\n'
               '  const response = await fetch(`${FAC}/settle`, { method: "POST", body: JSON.stringify({ paymentPayload: payload, '
               'paymentRequirements: REQS }) });\n  const result = await response.json();\n'
               '  if (!result.success) return res.status(402).json({ error: "settle failed" });\n'
               '  return res.json({ quote: 42 });\n});\n')
    assert "security-x402-settle-unchecked" not in paths({"src/server.ts": handler})
    helper = (SETTLE_HEAD + 'async function settle(payload) {\n'
              '  const res = await fetch(`${FAC}/settle`, { method: "POST", body: JSON.stringify({ paymentPayload: payload, '
              'paymentRequirements: REQS }) });\n  const data = await res.json();\n'
              '  if (!data.success) throw new Error("settlement failed");\n  return data;\n}\n'
              'app.get("/quote", async (req, res) => {\n'
              '  const paid = await settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")));\n'
              '  return res.json({ quote: 42, tx: paid.transaction });\n});\n')
    assert "security-x402-settle-unchecked" not in paths({"src/server.ts": helper})
    # The facilitator URL held in a constant is still a settle call.
    unchecked = helper.replace("fetch(`${FAC}/settle`", "fetch(SETTLE_URL").replace(
        "const FAC = process.env.FAC_URL;\n", "const FAC = process.env.FAC_URL;\nconst SETTLE_URL = `${FAC}/settle`;\n").replace(
        '  if (!data.success) throw new Error("settlement failed");\n', "")
    assert paths({"src/server.ts": unchecked})["security-x402-settle-unchecked"].severity.value == "high"


def test_a_log_request_before_the_success_check_serves_nothing():
    handler = (SETTLE_HEAD + 'app.get("/quote", async (req, res) => {\n'
               '  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")), REQS);\n'
               '  await fetch(process.env.AUDIT_URL, { method: "POST", body: JSON.stringify({ event: "settle", s }) });\n'
               '  if (!s.success) return res.status(402).end();\n  res.json({ quote: 42 });\n});\n')
    assert "security-x402-settle-unchecked" not in paths({"src/server.ts": handler})
    # Forwarding to the paid upstream with the settlement never checked is still a delivery.
    proxied = handler.replace("  if (!s.success) return res.status(402).end();\n  res.json({ quote: 42 });\n",
                              "  return res.json(await (await fetch(UPSTREAM)).json());\n")
    assert "security-x402-settle-unchecked" in paths({"src/server.ts": proxied})


def test_a_settle_method_that_is_not_a_facilitator_is_not_a_payment_settlement():
    channel = ('import { stellar } from "@stellar/mpp/channel/server";\nimport express from "express";\nconst app = express();\n'
               'app.post("/close", async (req, res) => {\n'
               '  const result = await channelServer.settle(req.body.channelId, req.body.amount);\n'
               '  res.json({ closed: true, hash: result.hash });\n});\n')
    assert "security-x402-settle-unchecked" not in paths({"src/channel.ts": channel})


def test_facilitator_relay_is_not_a_resource_server():
    relay = ('import { NextResponse } from "next/server";\nimport { x402Facilitator } from "@x402/core/facilitator";\n'
             'export async function POST(req: Request) {\n'
             '  const { paymentPayload, paymentRequirements } = await req.json();\n'
             '  const result = await facilitator.settle(paymentPayload, paymentRequirements);\n'
             '  return NextResponse.json(result);\n}\n')
    assert not [f for f in paths({"src/app/api/pay/route.ts": relay}) if "x402" in f]


VERIFY_ONLY = ('import { verifier } from "./verifier";\n'
               'export function paywall() {\n  return async (req: any, res: any, next: any) => {\n'
               "    const xdr = req.headers['x-payment'];\n"
               '    const result = await verifier.verifyEnvelope(xdr, { payee: R });\n'
               '    if (!result.verified) return res.status(402).json(result);\n    next();\n  };\n}\n')


def test_verified_but_never_settled_payment():
    assert paths({"src/middleware.ts": VERIFY_ONLY})["security-x402-verify-without-settle"].severity.value == "high"
    submitted = VERIFY_ONLY.replace("    next();", "    await server.sendTransaction(TransactionBuilder.fromXDR(xdr, NET));\n    next();")
    assert "security-x402-verify-without-settle" not in paths({"src/middleware.ts": submitted})
    deferred = VERIFY_ONLY.replace("    next();", "    res.on('finish', () => settleLater(xdr));\n    next();")
    assert "security-x402-verify-without-settle" not in paths({"src/middleware.ts": deferred})
    # Handing an error to the next middleware serves nothing.
    failing = VERIFY_ONLY.replace("    next();", "    next(new Error('settlement is not implemented'));")
    assert "security-x402-verify-without-settle" not in paths({"src/middleware.ts": failing})


PROOF = ('export async function verifyHash(txHash: string, options: { memo?: string }) {\n'
         '  const tx = await server.transactions().transaction(txHash).call();\n'
         '  if (!tx.successful) return false;\n  CHECKS\n  return true;\n}\n'
         'app.get("/paid", async (req, res) => {\n'
         "  const hash = req.headers['x-payment'];\n  STORE\n"
         '  if (!(await verifyHash(hash, {}))) return res.status(402).end();\n  res.json(DATA);\n});\n')


def proof(checks: str = "", store: str = "") -> str:
    return PROOF.replace("CHECKS", checks).replace("STORE", store)


def test_transaction_hash_proof_bindings():
    rule = "security-tx-hash-proof-unbound"
    assert paths({"src/pay.ts": proof()})[rule].severity.value == "high"
    used = "if (usedHashes.has(hash)) return res.status(402).end();\n  usedHashes.add(hash);"
    # A store but nothing ties the payment to this request or bounds its age: past payments pass.
    assert paths({"src/pay.ts": proof(store=used)})[rule].severity.value == "high"
    age = "if (Date.now() - Date.parse(tx.created_at) > MAX_AGE_MS) return false;"
    assert paths({"src/pay.ts": proof(age, used)})[rule].severity.value == "medium"
    memo = "if (tx.memo !== CHALLENGE_ID) return false;"
    assert paths({"src/pay.ts": proof(memo, used)})[rule].severity.value == "low"
    assert rule not in paths({"src/pay.ts": proof(memo + "\n  " + age, used)})
    # A check guarded by an option no caller passes never runs.
    optional = "if (options.memo && tx.memo !== options.memo) return false;\n  " + age
    assert paths({"src/pay.ts": proof(optional, used)})[rule].severity.value == "medium"
    # Looking a transaction up for display is not a paywall.
    explorer = ('app.get("/tx/:hash", async (req, res) => {\n'
                '  res.json(await server.transactions().transaction(req.params.hash).call());\n});\n')
    assert rule not in paths({"src/explorer.ts": explorer})
    # A payer reading a 402 and checking its own payment is not a paywall either.
    payer = ('export async function payAndCheck(url: string) {\n  const res = await fetch(url);\n'
             '  if (res.status === 402) {\n    const hash = res.headers.get("x-payment-response");\n'
             '    return server.transactions().transaction(hash).call();\n  }\n}\n')
    assert rule not in paths({"src/payer.ts": payer})


# --------------------------------------------------------------------------- item 12: sponsors
SPONSOR = ('import { Keypair, TransactionBuilder, Operation, rpc } from "@stellar/stellar-sdk";\n'
           'const feePayer = Keypair.fromSecret(process.env.FEE_PAYER_SECRET);\n'
           'app.post("/submit", async (req, res) => {\n'
           '  const clientTx = TransactionBuilder.fromXDR(req.body.xdr, NET);\n'
           '  GUARDS\n  const op = clientTx.operations[0];\n'
           '  const account = await server.getAccount(feePayer.publicKey());\n'
           '  const tx = new TransactionBuilder(account, { fee: FEE, networkPassphrase: NET })\n'
           '    .addOperation(Operation.invokeHostFunction({ func: op.func, auth: op.auth, source: op.source }))\n'
           '    SOROBAN.build();\n'
           '  tx.sign(feePayer);\n  res.json(await server.sendTransaction(tx));\n});\n')
GUARDS = ("if (clientTx.source !== PLACEHOLDER_SOURCE || clientTx.operations.length !== 1) throw new Error('drift');\n"
          "  if (clientTx.operations[0].source !== undefined) throw new Error('op source');\n"
          "  for (const e of clientTx.operations[0].auth) if (e.credentials().switch() !== "
          "xdr.SorobanCredentialsType.sorobanCredentialsAddress()) throw new Error('cred');")


def sponsor(guards: str = "", fee: str = "clientTx.fee", soroban: str = ".setSorobanData(clientTx.toEnvelope().v1().tx().ext().sorobanData())\n    ") -> str:
    return SPONSOR.replace("GUARDS", guards).replace("FEE", fee).replace("SOROBAN", soroban)


def test_sponsor_rebuild_gaps_attach_to_the_signing_finding():
    found = paths({"src/relay.ts": sponsor()})
    signing = found["security-path-external-transaction-signed"]
    assert "R1 credential type" in signing.detail and "R2 source pin" in signing.detail and "R3 client-chosen fee" in signing.detail
    assert not [f for f in found if "sponsor" in f]  # one finding per defect


def test_guarded_sponsor_with_its_own_fee_is_safe():
    found = paths({"src/relay.ts": sponsor(GUARDS, "BASE_FEE", "")})
    assert not {"security-path-external-transaction-signed", "security-path-untrusted-to-financial-sink",
                "security-path-controls-not-enforced"} & set(found)
    assert not [f for f in found if "sponsor" in f]


def test_sponsor_guards_must_check_the_client_envelope_in_code():
    # Look-alikes: a request field named source, and a logging helper that reads credentials.
    lookalike = sponsor("", "BASE_FEE", "").replace(
        'app.post("/submit", async (req, res) => {\n',
        'import { describeAuth } from "./auth";\napp.post("/submit", async (req, res) => {\n'
        '  if (req.body.source === "cli") log("cli client");\n').replace(
        "  const account =", "  log(describeAuth(op.auth));\n  const account =")
    auth = 'export function describeAuth(entries) {\n  return entries.map((e) => e.credentials().switch().name).join(",");\n}\n'
    found = paths({"src/relay.ts": lookalike, "src/auth.ts": auth})
    assert "R1 credential type" in found["security-path-untrusted-to-financial-sink"].detail
    # The guide's checks left as comments check nothing.
    comments = ("// SECURITY: Verify the transaction source is not the fee-payer\n"
                "  // if (clientTx.source === feePayer.publicKey()) throw; check e.credentials().switch()\n")
    found = paths({"src/relay.ts": sponsor(comments, "BASE_FEE", "")})
    assert found["security-path-untrusted-to-financial-sink"].severity.value == "high"
    # Checks in a throwing helper the handler calls count.
    helper = ("function pin(tx) {\n  if (tx.source !== PLACEHOLDER_SOURCE) throw new Error('source');\n"
              "  const op = tx.operations[0];\n  if (op.source) throw new Error('op source');\n"
              "  if (!op.auth.every((e) => e.credentials().switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress()))\n"
              "    throw new Error('credentials');\n}\n")
    found = paths({"src/relay.ts": helper + sponsor("pin(clientTx);", "BASE_FEE", "")})
    assert not {"security-path-external-transaction-signed", "security-path-untrusted-to-financial-sink"} & set(found)
    asserted = helper.replace("if (op.source) throw new Error('op source');", "assert(!op.source);")
    found = paths({"src/relay.ts": asserted + sponsor("pin(clientTx);", "BASE_FEE", "")})
    assert not {"security-path-external-transaction-signed", "security-path-untrusted-to-financial-sink"} & set(found)
    # `if (!op.source) throw` requires an operation source instead of forbidding one.
    inverted = helper.replace("if (op.source) throw", "if (!op.source) throw")
    found = paths({"src/relay.ts": inverted + sponsor("pin(clientTx);", "BASE_FEE", "")})
    signed = [f for f in found.values() if f.id in {"security-path-external-transaction-signed",
                                                     "security-path-untrusted-to-financial-sink"}]
    assert signed and any("R2 source pin" in f.detail for f in signed)


def test_guarded_sponsor_does_not_hide_a_separate_payment_from_input():
    refund = ("const refund = new TransactionBuilder(await server.getAccount(feePayer.publicKey()), { fee: BASE_FEE, "
              "networkPassphrase: NET }).addOperation(Operation.payment({ destination: req.body.refundTo, "
              "asset: Asset.native(), amount: req.body.refund })).setTimeout(30).build();\n"
              "  refund.sign(feePayer);\n  await server.sendTransaction(refund);\n")
    guarded = sponsor(GUARDS, "BASE_FEE", "").replace("  res.json(await server.sendTransaction(tx));\n",
                                                       "  res.json(await server.sendTransaction(tx));\n  " + refund)
    found = paths({"src/relay.ts": guarded})
    evidence = found["security-path-untrusted-to-financial-sink"].evidence
    assert "refund.sign(feePayer)" in evidence and "tx.sign(feePayer)" not in evidence


def test_guarded_sponsor_that_takes_the_client_fee_is_medium():
    found = paths({"src/relay.ts": sponsor(GUARDS)})
    assert found["security-path-sponsor-fee-from-client"].severity.value == "medium"
    assert not {"security-path-external-transaction-signed", "security-path-untrusted-to-financial-sink"} & set(found)


def test_fee_bump_with_an_input_fee():
    tool = ('server.tool("bump", "fee bump", { innerXdr: z.string(), feeArg: z.string().optional() }, '
            'async ({ innerXdr, feeArg }) => {\n  const kp = Keypair.fromSecret(process.env.SPONSOR_SECRET);\n'
            '  const inner = new Transaction(innerXdr, NET);\n'
            '  const fb = TransactionBuilder.buildFeeBumpTransaction(kp.publicKey(), feeArg || "100", inner, NET);\n'
            '  fb.sign(kp);\n  return horizon.submitTransaction(fb);\n});\n')
    found = paths({"src/t.ts": tool})
    assert found["security-path-fee-bump-unbounded"].severity.value == "medium"
    # The outer signature covers the fee only: it is not a signature over foreign operations.
    assert "security-path-external-transaction-signed" not in found
    assert "security-path-fee-bump-unbounded" not in paths({"src/t.ts": tool.replace('feeArg || "100"', '"100"')})
    # A fee read from the ledger is not one the caller chooses.
    ledger = tool.replace('feeArg || "100"', "recent.records[0].max_fee").replace(
        "  const inner =", "  const recent = await horizon.transactions().limit(1).call();\n  const inner =")
    assert "security-path-fee-bump-unbounded" not in paths({"src/t.ts": ledger})
    stored = tool.replace("new Transaction(innerXdr, NET)", "await store.load(innerXdr)")
    assert "security-path-fee-bump-unbounded" not in paths({"src/t.ts": stored})
    python = ('import os\nfrom stellar_sdk import Keypair, TransactionBuilder, TransactionEnvelope\nfrom mcp import tool\n'
              'KP = Keypair.from_secret(os.environ["SPONSOR_SECRET"])\n@tool\ndef bump(inner_xdr: str, fee: int):\n'
              '    inner = TransactionEnvelope.from_xdr(inner_xdr, NET)\n'
              '    fb = TransactionBuilder.build_fee_bump_transaction(KP.public_key, fee, inner, NET)\n'
              '    fb.sign(KP)\n    return server.submit_transaction(fb)\n')
    assert "security-path-fee-bump-unbounded" in paths({"t.py": python})
    assert "security-path-fee-bump-unbounded" not in paths({"t.py": python.replace("KP.public_key, fee,", "KP.public_key, 100,")})


# --------------------------------------------------------------------------- review fixes
SIGNED = {"security-path-external-transaction-signed", "security-path-untrusted-to-financial-sink"}


def test_sponsor_comparisons_that_reject_nothing_are_not_guards():
    # A logging helper that compares every field, and ifs that only count a metric.
    describe = ("function describe(tx) {\n  const op = tx.operations[0];\n"
                "  return { sponsored: tx.source === PLACEHOLDER_SOURCE, opSource: op.source === undefined ? 'none' : 'set',\n"
                "           creds: op.auth.filter((e) => e.credentials().switch() === "
                "xdr.SorobanCredentialsType.sorobanCredentialsAddress()).length };\n}\n")
    found = paths({"src/relay.ts": describe + sponsor("logger.info(describe(clientTx));", "BASE_FEE", "")})
    assert found["security-path-untrusted-to-financial-sink"].severity.value == "high"
    assert "security-path-controls-not-enforced" in found
    metrics = ("if (clientTx.source === PLACEHOLDER_SOURCE) metrics.placeholder += 1;\n"
               "  if (clientTx.operations[0].source === undefined) metrics.noOpSource += 1;\n"
               "  for (const e of clientTx.operations[0].auth) if (e.credentials().switch() === "
               "xdr.SorobanCredentialsType.sorobanCredentialsAddress()) metrics.address += 1;")
    found = paths({"src/relay.ts": sponsor(metrics, "BASE_FEE", "")})
    assert found["security-path-untrusted-to-financial-sink"].severity.value == "high"
    # Skipping a bad entry (`continue`) still signs the envelope that holds it.
    skipped = GUARDS.replace("throw new Error('cred');", "continue;")
    assert SIGNED & set(paths({"src/relay.ts": sponsor(skipped, "BASE_FEE", "")}))


def test_sponsor_guards_that_gate_the_signing_count():
    validator = ("function sponsorable(tx) {\n  const op = tx.operations[0];\n"
                 "  return tx.source === PLACEHOLDER_SOURCE && op.source === undefined && op.auth.every((e) => "
                 "e.credentials().switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress());\n}\n")
    # The validator's verdict gates the path: in the condition, or through a variable.
    gated = paths({"src/relay.ts": validator + sponsor("if (!sponsorable(clientTx)) throw new Error('bad');", "BASE_FEE", "")})
    assert not SIGNED & set(gated)
    held = "const ok = sponsorable(clientTx);\n  if (!ok) return res.status(400).end();"
    assert not SIGNED & set(paths({"src/relay.ts": validator + sponsor(held, "BASE_FEE", "")}))
    # Called and ignored, it checks nothing.
    ignored = paths({"src/relay.ts": validator + sponsor("sponsorable(clientTx);", "BASE_FEE", "")})
    assert SIGNED & set(ignored)
    # A check that encloses the signing holds for it.
    enclosing = sponsor("", "BASE_FEE", "").replace("  tx.sign(feePayer);\n  res.json(await server.sendTransaction(tx));\n",
                                                   "  if (sponsorable(clientTx)) {\n    tx.sign(feePayer);\n"
                                                   "    res.json(await server.sendTransaction(tx));\n  }\n")
    assert not SIGNED & set(paths({"src/relay.ts": validator + enclosing}))


S1_HEAD = ('import express from "express";\nimport { isDeepStrictEqual } from "node:util";\n'
           'import { decodePaymentSignatureHeader } from "@x402/core/http";\nconst app = express();\n')
S1_BODY = ('app.get("/q", async (req, res) => {\n'
           '  const p = decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE"));\n  GUARD\n'
           '  const s = await facilitator.settle(p, p.accepted);\n'
           '  if (!s.success) return res.status(402).end();\n  res.json({ quote: 42 });\n});\n')


def test_requirements_matched_against_the_server_are_bound():
    def s1(guard: str) -> dict:
        return paths({"src/server.ts": S1_HEAD + S1_BODY.replace("GUARD", guard)})
    rule = "security-x402-requirements-from-payer"
    assert s1("")[rule].severity.value == "critical"
    for guard in ("if (!isDeepStrictEqual(p.accepted, ROUTES.quote)) return res.status(402).end();",
                  "if (!_.isEqual(p.accepted, ROUTES.quote)) return res.status(402).end();",
                  "const m = findMatchingRequirements(ROUTES.quote, p);\n  if (!m) return res.status(402).end();"):
        assert rule not in s1(guard), guard
    # A match nobody acts on binds nothing.
    assert rule in s1("log(isDeepStrictEqual(p.accepted, ROUTES.quote));")
    assert rule in s1("const m = findMatchingRequirements(ROUTES.quote, p);\n  log(m);")


def test_proof_checks_in_a_throwing_helper_count():
    rule = "security-tx-hash-proof-unbound"
    helper = ('function assertBound(tx: any, challenge: Challenge) {\n'
              '  if (tx.memo !== challenge.memo) throw new Error("memo");\n'
              '  if (tx.source_account !== challenge.payer) throw new Error("payer");\n'
              '  if (Date.now() - Date.parse(tx.created_at) > MAX_AGE_MS) throw new Error("old");\n}\n'
              'export async function verifyHash(txHash: string, challenge: Challenge) {\n'
              '  const tx = await server.transactions().transaction(txHash).call();\n'
              '  if (!tx.successful) return false;\n  assertBound(tx, challenge);\n  return true;\n}\n')
    handler = ('app.get("/paid", async (req, res) => {\n'
               "  const hash = req.headers['x-payment'];\n"
               '  if (usedHashes.has(hash)) return res.status(402).end();\n'
               '  const challenge = await challenges.take(req.query.id);\n'
               '  if (!(await verifyHash(hash, challenge))) return res.status(402).end();\n'
               '  usedHashes.add(hash);\n  res.json(DATA);\n});\n')
    assert rule not in paths({"src/pay.ts": helper + handler})
    no_age = helper.replace('  if (Date.now() - Date.parse(tx.created_at) > MAX_AGE_MS) throw new Error("old");\n', "")
    assert paths({"src/pay.ts": no_age + handler})[rule].severity.value == "low"
    # A cache sweep's TTL comparison in a helper is not an age check on the proof.
    sweep = ('function sweep() {\n  for (const [k, r] of seen) if (Date.now() - r.timestamp > TTL) seen.delete(k);\n}\n'
             'export async function verifyHash(txHash: string, challenge: Challenge) {\n  sweep();\n'
             '  const tx = await server.transactions().transaction(txHash).call();\n'
             '  if (tx.memo !== challenge.memo) return false;\n  return tx.successful;\n}\n')
    found = paths({"src/pay.ts": sweep + handler})
    assert found[rule].severity.value == "low" and "age check" in found[rule].evidence


def test_a_throwing_settlement_validator_is_a_check():
    head = (SETTLE_HEAD + 'function ensureSettled(s: SettleResponse) {\n  if (!s.success) throw new PaymentError(s.errorReason);\n}\n'
            'async function ensureSettledLater(s: SettleResponse) {\n  if (!s.success) throw new PaymentError("x");\n}\n'
            'function logSettled(s: SettleResponse) {\n  if (!s.success) console.warn("unpaid");\n}\n')
    body = ('app.get("/q", async (req, res) => {\n'
            '  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")), REQS);\n'
            '  CHECK\n  res.json({ quote: 42 });\n});\n')
    rule = "security-x402-settle-unchecked"
    assert rule not in paths({"src/server.ts": head + body.replace("CHECK", "ensureSettled(s);")})
    assert rule not in paths({"src/server.ts": head + body.replace("CHECK", "await ensureSettledLater(s);")})
    # A helper that only logs, or an async one nobody awaits, stops nothing.
    assert rule in paths({"src/server.ts": head + body.replace("CHECK", "logSettled(s);")})
    assert rule in paths({"src/server.ts": head + body.replace("CHECK", "ensureSettledLater(s);")})


def test_a_settlement_report_in_any_shape_is_not_a_resource():
    rule = "security-x402-settle-unchecked"
    relay = (SETTLE_HEAD + 'app.post("/api/pay", async (req, res) => {\n'
             '  const payload = decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE"));\n'
             '  const r = await fetch(`${FAC}/settle`, { method: "POST", body: JSON.stringify({ paymentPayload: payload, '
             'paymentRequirements: REQS }) });\n  res.json(await r.json());\n});\n')
    assert rule not in paths({"src/server.ts": relay})
    fields = (SETTLE_HEAD + 'app.post("/pay", async (req, res) => {\n'
              '  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")), REQS);\n'
              '  res.json({ success: s.success, transaction: s.transaction, errorReason: s.errorReason });\n});\n')
    assert rule not in paths({"src/server.ts": fields})
    # The paid answer beside the transaction hash is a resource served unchecked.
    served = fields.replace("res.json({ success: s.success,", "res.json({ quote: 42,")
    assert paths({"src/server.ts": served})[rule].severity.value == "high"


def test_settle_needs_the_payers_payload_or_an_x402_object_not_a_name():
    rule = "security-x402-settle-unchecked"
    channel = ('import { stellar } from "@stellar/mpp/channel/server";\nimport express from "express";\nconst app = express();\n'
               'app.post("/close", async (req, res) => {\n'
               '  const result = await paymentChannel.settle(req.body.channelId, req.body.amount);\n'
               '  res.json({ closed: true, data: DATA, hash: result.hash });\n});\n')
    assert rule not in paths({"src/channel.ts": channel})
    client = ('import express from "express";\nimport { HTTPFacilitatorClient } from "@x402/core/server";\nconst app = express();\n'
              'const fac = new HTTPFacilitatorClient({ url: FAC });\n'
              'app.post("/q", async (req, res) => {\n  const s = await fac.settle(req.body.payload, REQS);\n'
              '  res.json({ quote: 42 });\n});\n')
    assert paths({"src/server.ts": client})[rule].severity.value == "high"


def test_a_payment_settled_by_a_later_step_of_the_route_is_not_unsettled():
    rule = "security-x402-verify-without-settle"
    settle = ('export function settleFirst() {\n  return async (req: any, res: any, next: any) => {\n'
              '    const sent = await server.sendTransaction(TransactionBuilder.fromXDR(req.paymentXdr, NET));\n'
              '    if (sent.status !== "PENDING") return res.status(402).end();\n    next();\n  };\n}\n')
    paywall = VERIFY_ONLY.replace("    next();", "    req.paymentXdr = xdr;\n    next();")
    app = ('import express from "express";\nimport { paywall } from "./paywall";\nimport { settleFirst } from "./settle";\n'
           'const app = express();\napp.get("/data", paywall(), settleFirst(), (req, res) => res.json(DATA));\n')
    assert rule not in paths({"src/paywall.ts": paywall, "src/settle.ts": settle, "src/app.ts": app})
    # Outside a known route, a module that reads the field the verifier set and submits it.
    assert rule not in paths({"src/paywall.ts": paywall, "src/settle.ts": settle})
    # A route whose other steps settle nothing still serves an unsettled payment.
    other = app.replace("settleFirst()", "logRequest()").replace('import { settleFirst } from "./settle";',
                                                                    'import { logRequest } from "./log";')
    log = 'export function logRequest() {\n  return (req: any, res: any, next: any) => { console.log(req.path); next(); };\n}\n'
    found = paths({"src/paywall.ts": paywall, "src/settle.ts": settle, "src/log.ts": log, "src/app.ts": other})
    assert found[rule].severity.value == "high"


X402_OLD = lock(**{"@x402/core": "2.17.0", "@x402/fetch": "2.17.0"})
X402_HEAD = ('import { x402Client, wrapFetchWithPayment } from "@x402/fetch";\n'
             'const client = new x402Client();\nclient.register("stellar:*", scheme);\n')
X402_WRAP = "export const pay = wrapFetchWithPayment(fetch, client);\n"


def test_named_x402_hooks_and_policies_cap_the_client():
    named_hook = ('async function capHook({ selectedRequirements }) {\n'
                  '  if (BigInt(selectedRequirements.amount) > MAX_ATOMIC) return { abort: true };\n}\n'
                  'client.onBeforePaymentCreation(capHook);\n')
    assert X402 not in paths({"src/pay.ts": X402_HEAD + named_hook + X402_WRAP}, X402_OLD)
    named_policy = ('const underCap = (v, reqs) => reqs.filter((r) => BigInt(r.amount) <= MAX_ATOMIC);\n'
                    'client.registerPolicy(underCap);\n')
    assert X402 not in paths({"src/pay.ts": X402_HEAD + named_policy + X402_WRAP}, X402_OLD)
    imported = {"src/policy.ts": 'export function underCap(v, reqs) {\n  return reqs.filter((r) => BigInt(r.amount) <= MAX);\n}\n',
                "src/pay.ts": X402_HEAD.replace("const client", 'import { underCap } from "./policy";\nconst client')
                + "client.registerPolicy(underCap);\n" + X402_WRAP}
    assert X402 not in paths(imported, X402_OLD)


def test_x402_policies_that_bound_nothing_are_not_ceilings():
    for extra in ("client.registerPolicy((v, reqs) => [...reqs].sort((a, b) => (BigInt(a.amount) < BigInt(b.amount) ? -1 : 1)));\n",
                  "client.registerPolicy((v, reqs) => reqs.filter((r) => BigInt(r.amount) > 0n));\n",
                  "client.onBeforePaymentCreation(async ({ selectedRequirements: r }) => { if (BigInt(r.amount) > BIG) "
                  "console.warn('large'); });\n"):
        assert paths({"src/pay.ts": X402_HEAD + extra + X402_WRAP}, X402_OLD)[X402].severity.value == "high", extra
    config = ('import { x402Client, wrapFetchWithPayment } from "@x402/fetch";\n'
              'const client = x402Client.fromConfig({ schemes: [{ network: "stellar:pubnet", client: scheme }], POL });\n' + X402_WRAP)
    for pol in ("policies: []", "policies: [(v, reqs) => reqs.filter((r) => r.network === 'stellar:pubnet')]"):
        assert X402 in paths({"src/pay.ts": config.replace("POL", pol)}, X402_OLD), pol
    capped = "policies: [(v, reqs) => reqs.filter((r) => r.network === 'stellar:pubnet' && BigInt(r.amount) <= MAX)]"
    assert X402 not in paths({"src/pay.ts": config.replace("POL", capped)}, X402_OLD)


def test_mpp_network_markers_in_comments_and_tests_do_not_move_the_severity():
    v = lock(**{"@stellar/mpp": "0.4.0"})
    mainnet_comment = paths({"src/server.ts": "// mainnet later: https://horizon.stellar.org\n" + MPP}, v)
    assert mainnet_comment[STORE].severity.value == "medium"
    beside = {"src/server.ts": MPP, "src/server.test.ts": 'import { STELLAR_PUBNET } from "@stellar/mpp";\n'
                                                           'expect(n).not.toBe(STELLAR_PUBNET);\n'}
    assert paths(beside, v)[STORE].severity.value == "medium"
    from_env = MPP.replace("import { USDC_SAC_TESTNET } from \"@stellar/mpp\";\n", "").replace(
        "currency: USDC_SAC_TESTNET", "currency: process.env.USDC, network: process.env.NETWORK")
    assert paths({"src/server.ts": "// e.g. NETWORK=stellar:testnet for local runs\n" + from_env}, v)[STORE].severity.value == "high"


def test_mpp_secret_key_is_resolved_in_scope_outside_comments_and_strings():
    imports = 'import { Mppx } from "mppx/server";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
    shadowed = imports + ('function dev() { const KEY = "local-dev-only"; return KEY; }\n'
                          'export function prod() { const KEY = requireEnv("MPP_SECRET"); '
                          'return Mppx.create({ secretKey: KEY, methods: [] }); }\n')
    assert "security-default-secret" not in hardening({"src/mpp.ts": shadowed})
    template = imports + ('export const README = `Mppx.create({ secretKey: "your-key-here" })`;\n'
                          'export const m = Mppx.create({ secretKey: requireEnv("K"), methods: [] });\n')
    assert "security-default-secret" not in hardening({"src/mpp.ts": template})
    comment = imports + ('const SECRET = process.env.MPP_KEY!;\n// Keypair.fromSecret(SECRET) would be wrong here\n'
                         'export const m = Mppx.create({ secretKey: SECRET, methods: [] });\n')
    assert "security-mpp-secret-reuses-stellar-seed" not in hardening({"src/mpp.ts": comment})
    # The same key from the same environment variable is the seed.
    env = imports + ('const KEY = process.env.STELLAR_SECRET!;\nconst kp = Keypair.fromSecret(process.env.STELLAR_SECRET);\n'
                     'export const m = Mppx.create({ secretKey: KEY, methods: [] });\n')
    assert hardening({"src/mpp.ts": env})["security-mpp-secret-reuses-stellar-seed"].severity.value == "low"


def test_replicas_count_only_for_the_service_that_runs_the_server():
    memory = ('import { stellar, Store } from "@stellar/mpp/charge/server";\n'
              'export const m = stellar({ recipient: R, network: "stellar:pubnet", store: Store.memory() });\n')
    v = lock(**{"@stellar/mpp": "0.7.1"})
    worker = "services:\n  api:\n    build: .\n  worker:\n    image: worker\n    deploy:\n      replicas: 3\n"
    assert paths({"src/server.ts": memory, "docker-compose.yml": worker}, v)[STORE].severity.value == "low"
    api = "services:\n  api:\n    build: .\n    deploy:\n      replicas: 3\n  worker:\n    image: worker\n"
    found = paths({"src/server.ts": memory, "docker-compose.yml": api}, v)
    assert found[STORE].severity.value == "high" and "docker-compose.yml" in found[STORE].evidence
    command = "services:\n  api:\n    image: node:22\n    command: node dist/server.js\n    deploy:\n      replicas: 2\n"
    assert paths({"src/server.ts": memory, "docker-compose.yml": command}, v)[STORE].severity.value == "high"
    k8s = "kind: Deployment\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n        - name: db\n          image: postgres\n"
    assert paths({"src/server.ts": memory, "k8s/db.yaml": k8s}, v)[STORE].severity.value == "low"


def test_only_a_registered_abort_hook_lowers_switched_off_spend_controls():
    off = ('import { x402Client } from "@x402/core/client";\n'
           "// TODO: add onBeforePaymentCreation returning { abort: true }\n"
           "export const client = x402Client.fromConfig({ schemes: [], spendControls: false });\n")
    assert paths({"src/c.ts": off})["security-x402-spend-controls-disabled"].severity.value == "high"
    named = off + ("async function refuse({ selectedRequirements }) {\n"
                   "  if (selectedRequirements.network !== NET) return { abort: true, reason: 'net' };\n}\n"
                   "client.onBeforePaymentCreation(refuse);\n")
    assert paths({"src/c.ts": named})["security-x402-spend-controls-disabled"].severity.value == "medium"


def test_mpp_fee_ceiling_in_any_number_form():
    v = lock(**{"@stellar/mpp": "0.7.1"})

    def fee(literal: str) -> dict:
        return paths({"s.ts": 'import { stellar } from "@stellar/mpp/charge/server";\n'
                              f'export const m = stellar({{ recipient: R, network: "stellar:pubnet", store, '
                              f'maxFeeBumpStroops: {literal} }});\n'}, v)
    for literal in ("1e9", "0x5F5E100", "100_000_000n", "50000000.5"):
        assert "security-mpp-fee-budget-unbounded" in fee(literal), literal
    for literal in ("1e6", "0x10", "1_000_000n"):
        assert "security-mpp-fee-budget-unbounded" not in fee(literal), literal


# --------------------------------------------------------------------------- integrator calibrations
def test_browser_wallet_clients_may_switch_spend_controls_off():
    # A paywall in the browser: the person sees the amount and approves it in the wallet.
    browser = ('import { useState } from "react";\nimport { x402Client } from "@x402/core/client";\n'
               'export function payer(wallet) {\n  const c = new x402Client().setSpendControls(false);\n'
               '  c.register("stellar:*", schemeFor(wallet));\n  return c;\n}\n')
    rule = "security-x402-spend-controls-disabled"
    assert rule not in paths({"packages/paywall/src/pay.ts": browser}, lock(**CORE))
    plain = browser.replace('import { useState } from "react";\n', "")
    assert rule not in paths({"packages/paywall/src/browser/pay.ts": plain}, lock(**CORE))
    assert rule not in paths({"src/pay.ts": '"use client";\n' + plain}, lock(**CORE))
    kit = 'import { StellarWalletsKit } from "@creit.tech/stellar-wallets-kit";\n' + plain
    assert rule not in paths({"src/pay.ts": kit}, lock(**CORE))
    # An unattended server or CLI client still fires.
    assert paths({"src/agent.ts": plain}, lock(**CORE))[rule].severity.value == "high"


def test_other_x402_libraries_keep_the_plain_payment_rule():
    other = ('const lib = req("x402-otherchain");\n'
             'export const http = lib.wrapAxiosWithPayment(axios.create({ baseURL: BASE }), account);\n')
    found = paths({"tools/pay.mjs": other})
    assert found[X402].severity.value == "high" and "[external -> <module>]" in found[X402].evidence
    assert "@x402/core" not in found[X402].evidence and "could not be established" not in found[X402].detail
    # Beside an @x402 client, both are reported in one finding, each with its own evidence.
    both = paths({"tools/pay.mjs": other, "src/pay.ts": PAYER}, unlocked(**{"@x402/core": "^2.17.0", "@x402/fetch": "^2.17.0"}))
    assert both[X402].severity.value == "high"
    assert "[external -> <module>]" in both[X402].evidence and "install date" in both[X402].evidence


def test_a_fee_bump_keeps_the_origin_of_its_inner_transaction():
    bump = ('import { TransactionBuilder, Keypair } from "@stellar/stellar-sdk";\n'
            'export function sponsorFee(inner: any, signer: Keypair, passphrase: string) {\n'
            '  const outer = TransactionBuilder.buildFeeBumpTransaction(signer, "2000", inner, passphrase);\n'
            '  outer.sign(signer);\n  return outer;\n}\n')
    vault = ('import { TransactionBuilder, Contract, nativeToScVal, Keypair, rpc } from "@stellar/stellar-sdk";\n'
             'import { sponsorFee } from "./bump";\nconst KEY = Keypair.fromSecret(process.env.VAULT_SECRET);\n'
             'export async function withdraw(args: { vault: string; amount: bigint }) {\n'
             '  const server = new rpc.Server(RPC_URL);\n'
             '  const op = new Contract(args.vault).call("withdraw", nativeToScVal(args.amount));\n'
             '  const tx = new TransactionBuilder(await server.getAccount(KEY.publicKey()), { fee: "100", networkPassphrase: NET })'
             '.addOperation(op).setTimeout(30).build();\n  const ready = await server.prepareTransaction(tx);\n  ready.sign(KEY);\n'
             '  return server.sendTransaction(sponsorFee(ready, KEY, NET));\n}\n')
    evidence = paths({"src/bump.ts": bump, "src/vault.ts": vault})["security-path-untrusted-to-financial-sink"].evidence
    assert "`outer.sign(signer);` [caller -> sponsorFee]" in evidence


# --------------------------------------------------------------------------- second review pass
VALIDATOR = ("function isSponsorable(tx) {\n  const op = tx.operations[0];\n"
             "  return tx.source === PLACEHOLDER_SOURCE && tx.operations.length === 1 && op.source === undefined && "
             "op.auth.every((e) => e.credentials().switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress());\n}\n")


def test_an_awaited_async_validator_gates_the_sponsor():
    validator = VALIDATOR.replace("function isSponsorable", "async function isSponsorable")
    for guard in ("if (!await isSponsorable(clientTx)) throw new Error('bad');",
                  "if (!(await isSponsorable(clientTx))) return res.status(400).end();",
                  "const ok = await isSponsorable(clientTx);\n  if (!ok) return res.status(400).end();"):
        assert not SIGNED & set(paths({"src/relay.ts": validator + sponsor(guard, "BASE_FEE", "")})), guard
    # Not awaited, it returns a Promise, which is always truthy: nothing is refused.
    for guard in ("if (!isSponsorable(clientTx)) throw new Error('bad');", "assert(isSponsorable(clientTx));",
                  "const ok = isSponsorable(clientTx);\n  if (!ok) return res.status(400).end();"):
        assert SIGNED & set(paths({"src/relay.ts": validator + sponsor(guard, "BASE_FEE", "")})), guard


def test_a_throw_that_a_catch_carries_on_from_checks_nothing_after_the_try():
    swallowed = "try {\n  " + GUARDS + "\n  } catch (e) { logger.warn(e); }"
    found = paths({"src/relay.ts": sponsor(swallowed, "BASE_FEE", "")})
    assert SIGNED & set(found) and "security-path-controls-not-enforced" in found
    helper = GUARDS.replace("clientTx", "tx")
    throwing = "async function assertSponsorable(tx) {\n  " + helper + "\n}\n"
    caught = "try {\n  await assertSponsorable(clientTx);\n  } catch (e) { logger.warn(e); }"
    assert SIGNED & set(paths({"src/relay.ts": throwing + sponsor(caught, "BASE_FEE", "")}))
    # A catch that refuses, or a rethrow, still stops the request.
    for catch in ("return res.status(400).end();", "logger.warn(e); throw e;"):
        refused = "try {\n  " + GUARDS + "\n  } catch (e) { " + catch + " }"
        assert not SIGNED & set(paths({"src/relay.ts": sponsor(refused, "BASE_FEE", "")})), catch
    # Signing inside the same try runs only past the checks.
    inside = sponsor(GUARDS, "BASE_FEE", "").replace("  const clientTx = TransactionBuilder.fromXDR(req.body.xdr, NET);\n",
                                                     "  const clientTx = TransactionBuilder.fromXDR(req.body.xdr, NET);\n  try {\n")
    inside = inside.replace("  res.json(await server.sendTransaction(tx));\n});\n",
                            "  res.json(await server.sendTransaction(tx));\n  } catch (e) { logger.warn(e); }\n});\n")
    assert not SIGNED & set(paths({"src/relay.ts": inside}))


def test_an_inline_some_check_of_the_credentials_keeps_the_sponsor_rule():
    some = ("if (clientTx.source !== PLACEHOLDER_SOURCE || clientTx.operations.length !== 1) return res.status(400).end();\n"
            "  if (clientTx.operations[0].source !== undefined) return res.status(400).end();\n"
            "  if (clientTx.operations[0].auth.some((e) => e.credentials().switch() !== "
            "xdr.SorobanCredentialsType.sorobanCredentialsAddress())) return res.status(400).end();")
    assert not [f for f in paths({"src/relay.ts": sponsor(some, "BASE_FEE", "")}) if f in SIGNED or "controls" in f]
    logged = some.replace("return res.status(400).end();", "logger.warn('bad');")
    assert SIGNED & set(paths({"src/relay.ts": sponsor(logged, "BASE_FEE", "")}))


def test_a_requirements_match_binds_only_where_it_holds():
    def s1(body: str) -> dict:
        return paths({"src/server.ts": S1_HEAD + body})
    rule = "security-x402-requirements-from-payer"
    for guard in ("if (isDeepStrictEqual(p.accepted, ROUTES.quote)) console.log('match');",
                  "const m = findMatchingRequirements(ROUTES.quote, p);\n  if (m) logger.info('matched');",
                  "if (p.accepted.amount === ROUTES.quote.amount) console.log('same');",
                  "const label = isDeepStrictEqual(p.accepted, ROUTES.quote) ? 'match' : 'other';\n  log(label);"):
        assert s1(S1_BODY.replace("GUARD", guard))[rule].severity.value == "critical", guard
    # Settled inside the branch where the match holds.
    enclosed = ('app.get("/q", async (req, res) => {\n'
                '  const p = decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE"));\n'
                '  if (isDeepStrictEqual(p.accepted, ROUTES.quote)) {\n    const s = await facilitator.settle(p, p.accepted);\n'
                '    if (!s.success) return res.status(402).end();\n    return res.json({ quote: 42 });\n  }\n'
                '  res.status(402).end();\n});\n')
    assert rule not in s1(enclosed)
    assert s1(enclosed.replace("if (isDeepStrictEqual", "if (!isDeepStrictEqual"))[rule].severity.value == "critical"


def test_x402_ceilings_in_every_refusing_shape():
    helpers = "function isAffordable(r) { return BigInt(r.amount) <= MAX; }\nfunction onStellar(r) { return r.network === NET; }\n"
    capped = ("client.registerPolicy((v, reqs) => reqs.filter(isAffordable));\n",
              "client.registerPolicy((v, reqs) => reqs.filter((r) => isAffordable(r)));\n",
              "client.registerPolicy((v, reqs) => { if (reqs.some((r) => BigInt(r.amount) > MAX)) throw new Error('over'); return reqs; });\n",
              "client.registerPolicy((v, reqs) => { for (const r of reqs) { if (BigInt(r.amount) > MAX) throw new Error('over'); } return reqs; });\n",
              "client.registerPolicy((v, reqs) => { if (reqs.some((r) => BigInt(r.amount) > MAX)) return []; return reqs; });\n",
              "client.onBeforePaymentCreation(async (ctx) => (BigInt(ctx.selectedRequirements.amount) > MAX ? { abort: true } : undefined));\n",
              "client.onBeforePaymentCreation(async (ctx) => { if (BigInt(ctx.selectedRequirements.amount) <= MAX) return; return { abort: true }; });\n")
    for extra in capped:
        assert X402 not in paths({"src/pay.ts": helpers + X402_HEAD + extra + X402_WRAP}, X402_OLD), extra
    uncapped = ("client.registerPolicy((v, reqs) => reqs.filter(onStellar));\n",
                "client.registerPolicy((v, reqs) => [reqs.find((r) => BigInt(r.amount) <= MAX) ?? reqs[0]]);\n",
                "client.registerPolicy((v, reqs) => { if (reqs.every((r) => BigInt(r.amount) > MAX)) throw new Error('x'); return reqs; });\n",
                "client.registerPolicy((v, reqs) => { if (reqs.some((r) => BigInt(r.amount) > MAX)) console.warn('x'); return reqs; });\n",
                "client.onBeforePaymentCreation(async (ctx) => (BigInt(ctx.selectedRequirements.amount) < MIN ? { abort: true } : undefined));\n",
                "client.onBeforePaymentCreation(async (ctx) => { if (BigInt(ctx.selectedRequirements.amount) <= MAX) return; log('big'); });\n")
    for extra in uncapped:
        assert paths({"src/pay.ts": helpers + X402_HEAD + extra + X402_WRAP}, X402_OLD)[X402].severity.value == "high", extra
    # A ternary hook can refuse: switched-off spend controls drop to medium.
    off = ('import { x402Client } from "@x402/core/client";\n'
           "export const client = x402Client.fromConfig({ schemes: [], spendControls: false });\n")
    ternary = off + "client.onBeforePaymentCreation(async (ctx) => (ctx.selectedRequirements.network !== NET ? { abort: true } : undefined));\n"
    assert paths({"src/c.ts": ternary})["security-x402-spend-controls-disabled"].severity.value == "medium"


def test_only_a_settle_or_submit_call_settles_a_verified_payment():
    rule = "security-x402-verify-without-settle"
    paywall = VERIFY_ONLY.replace("    next();", "    req.paymentXdr = xdr;\n    next();")
    head = 'import express from "express";\nimport { paywall } from "./paywall";\nimport { step } from "./step";\nconst app = express();\n'
    steps = {"finish hook that logs": "res.on('finish', () => console.log(req.path, res.statusCode));",
             "Promise.allSettled": "await Promise.allSettled([stats.incr(req.path)]);"}
    for name, body in steps.items():
        step = ("export function step() {\n  return async (req: any, res: any, next: any) => {\n    " + body + "\n    next();\n  };\n}\n")
        for app in ('app.use(step());\napp.get("/data", paywall(), (req, res) => res.json(DATA));\n',
                    'app.get("/data", paywall(), step(), (req, res) => res.json(DATA));\n'):
            found = paths({"src/paywall.ts": paywall, "src/step.ts": step, "src/app.ts": head + app})
            assert found[rule].severity.value == "high", (name, app)
    # Outside a route: a module that reads the field but submits something else settles nothing.
    refund = 'export async function refund(req) {\n  log(req.paymentXdr);\n  await server.sendTransaction(buildRefund());\n}\n'
    assert paths({"src/paywall.ts": paywall, "src/wallet.ts": refund})[rule].severity.value == "high"
    held = ('export async function settle(req) {\n  const tx = TransactionBuilder.fromXDR(req.paymentXdr, NET);\n'
            '  return server.sendTransaction(tx);\n}\n')
    assert rule not in paths({"src/paywall.ts": paywall, "src/settle.ts": held})


def test_an_imported_facilitator_and_a_validator_that_throws_on_success():
    rule = "security-x402-settle-unchecked"
    fac = 'import { HTTPFacilitatorClient } from "@x402/core/server";\nexport const facilitator = new HTTPFacilitatorClient({ url: FAC_URL });\n'
    app = ('import express from "express";\nimport { facilitator } from "./fac";\n'
           'import { decodePaymentSignatureHeader } from "@x402/core/http";\nconst app = express();\n'
           'app.post("/q", async (req, res) => {\n  const s = await facilitator.settle(req.body.paymentPayload, REQS);\n'
           '  res.json({ quote: 42 });\n});\n')
    assert paths({"src/fac.ts": fac, "src/app.ts": app})[rule].severity.value == "high"
    body = ('app.get("/q", async (req, res) => {\n'
            '  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")), REQS);\n'
            '  check(s);\n  res.json({ quote: 42 });\n});\n')
    for helper in ("function check(s) { if (s.success) throw new Error('already'); }\n",
                   "function check(s) { if (s.success === true) throw new Error('already'); }\n",
                   "function check(s) { assert(!s.success); }\n"):
        assert paths({"src/server.ts": SETTLE_HEAD + helper + body})[rule].severity.value == "high", helper
    for helper in ("function check(s) { if (s.success === false) throw new Error('unpaid'); }\n",
                   "function check(s) { if (s.success) { log('ok'); } else { throw new Error('unpaid'); } }\n",
                   "function check({ success }) { if (!success) throw new Error('unpaid'); }\n"):
        assert rule not in paths({"src/server.ts": SETTLE_HEAD + helper + body}), helper


def test_v1_x402_wrappers_cap_by_release():
    fetch = 'import { wrapFetchWithPayment } from "x402-fetch";\nexport const pay = wrapFetchWithPayment(fetch, wallet);\n'
    assert X402 not in paths({"src/pay.ts": fetch}, lock(**{"x402-fetch": "1.2.0"}))
    assert X402 not in paths({"src/pay.ts": fetch})
    axios = 'import { withPaymentInterceptor } from "x402-axios";\nexport const api = withPaymentInterceptor(axios.create(), wallet);\n'
    assert X402 not in paths({"src/pay.ts": axios}, lock(**{"x402-axios": "1.2.1"}))
    old = paths({"src/pay.ts": axios}, lock(**{"x402-axios": "1.2.0"}))[X402]
    assert old.severity.value == "high" and "no default cap before 1.2.1" in old.evidence
    assert paths({"src/pay.ts": axios})[X402].severity.value == "medium"
    explicit = axios.replace("wallet)", "wallet, 50000n)")
    assert X402 not in paths({"src/pay.ts": explicit}, lock(**{"x402-axios": "1.2.0"}))


def test_a_browser_page_is_not_a_node_tool_or_a_key_holder():
    client = ('import { x402Client, wrapFetchWithPayment } from "@x402/fetch";\nIMPORTS'
              'const client = new x402Client().setSpendControls(false);\nclient.register("stellar:*", scheme);\n'
              'export const pay = wrapFetchWithPayment(fetch, client);\n')
    rule = "security-x402-spend-controls-disabled"
    tool = client.replace("IMPORTS", 'import { chromium } from "playwright";\n')
    assert paths({"src/tools/browser/pay.ts": tool}, lock(**CORE))[rule].severity.value == "high"
    keyed = client.replace("IMPORTS", 'import React from "react";\nimport { Keypair } from "@stellar/stellar-sdk";\n'
                                      'const kp = Keypair.fromSecret(process.env.S);\n')
    assert paths({"src/agent.ts": keyed}, lock(**CORE))[rule].severity.value == "high"
    assert rule not in paths({"src/pay.ts": client.replace("IMPORTS", 'import { useState } from "react";\n')}, lock(**CORE))


def test_a_wallet_signed_browser_payment_is_not_the_projects_signing_authority():
    from backend.app.swarm.codeflow import analyse_code
    page = ('import { useState } from "react";\nimport { x402Client } from "@x402/core/client";\n'
            'export async function pay(walletSigner, required) {\n  const client = new x402Client();\n'
            '  client.register("stellar:*", new ExactStellarScheme(walletSigner));\n'
            '  return client.createPaymentPayload(required);\n}\n')
    profile = analyse_code({"packages/paywall/src/browser/pay.ts": page})
    assert profile.has("delegated_signing") and not profile.has("stellar_signing") and profile.has("payment")
    agent = page.replace('import { useState } from "react";\n', "")
    assert analyse_code({"src/agent/pay.ts": agent}).has("stellar_signing")


def test_a_tooling_script_a_person_runs_at_a_prompt_is_low():
    script = ('import { wrapAxiosWithPayment } from "x402-otherchain";\nPROMPT\n'
              'export const api = wrapAxiosWithPayment(axios.create(), account);\n')
    prompted = paths({"tools/pay.mjs": script.replace("PROMPT", "process.stdin.setRawMode(true);")})[X402]
    assert prompted.severity.value == "low" and "a script a person runs at a prompt" in prompted.evidence
    assert paths({"tools/pay.mjs": script.replace("PROMPT", "")})[X402].severity.value == "high"
    assert paths({"src/pay.mjs": script.replace("PROMPT", "process.stdin.setRawMode(true);")})[X402].severity.value == "high"
    question = 'import readline from "node:readline";\nrl.question("Secret key: ", go);'
    assert paths({"tools/pay.mjs": script.replace("PROMPT", question)})[X402].severity.value == "low"
    assert paths({"tools/pay.mjs": script.replace("PROMPT", "await llm.question(task);")})[X402].severity.value == "high"


def test_image_only_replicated_workloads_may_run_the_server():
    memory = ('import { stellar, Store } from "@stellar/mpp/charge/server";\n'
              'export const m = stellar({ recipient: R, network: "stellar:pubnet", store: Store.memory() });\n')
    v = lock(**{"@stellar/mpp": "0.7.1"})
    k8s = ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n"
           "        - name: api\n          image: org/api:1\n")
    found = paths({"src/server.ts": memory, "k8s/api.yaml": k8s}, v)
    assert found[STORE].severity.value == "high" and "k8s/api.yaml" in found[STORE].evidence
    compose = "services:\n  api:\n    image: org/api:latest\n    deploy:\n      replicas: 3\n"
    assert paths({"src/server.ts": memory, "docker-compose.yml": compose}, v)[STORE].severity.value == "high"
    stock = compose.replace("org/api:latest", "bitnami/redis:7")
    assert paths({"src/server.ts": memory, "docker-compose.yml": stock}, v)[STORE].severity.value == "low"


# --------------------------------------------------------------------------- third review pass
def test_a_payment_settled_through_a_variable_or_a_helper_is_settled():
    rule = "security-x402-verify-without-settle"
    paywall = VERIFY_ONLY.replace("    next();", "    req.paymentXdr = xdr;\n    next();")
    two_hop = ('export function settleFirst() {\n  return async (req: any, res: any, next: any) => {\n'
               '    const xdr = req.paymentXdr;\n    const tx = TransactionBuilder.fromXDR(xdr, NET);\n'
               '    const sent = await server.sendTransaction(tx);\n'
               '    if (sent.status !== "PENDING") return res.status(402).end();\n    next();\n  };\n}\n')
    assert rule not in paths({"src/paywall.ts": paywall, "src/settle.ts": two_hop})
    step = ('import { submitPayment } from "./chain";\n'
            'export function chargeFirst() {\n  return async (req: any, res: any, next: any) => {\n'
            '    const ok = await submitPayment(req.paymentXdr);\n'
            '    if (!ok) return res.status(402).end();\n    next();\n  };\n}\n')
    chain = ('export async function submitPayment(xdr: string) {\n'
             '  const sent = await server.sendTransaction(TransactionBuilder.fromXDR(xdr, NET));\n'
             '  return sent.status === "PENDING";\n}\n')
    assert rule not in paths({"src/paywall.ts": paywall, "src/charge.ts": step, "src/chain.ts": chain})
    app = ('import express from "express";\nimport { paywall } from "./paywall";\nimport { chargeFirst } from "./charge";\n'
           'const app = express();\napp.get("/data", paywall(), chargeFirst(), (req, res) => res.json(DATA));\n')
    assert rule not in paths({"src/paywall.ts": paywall, "src/charge.ts": step, "src/chain.ts": chain, "src/app.ts": app})
    # A helper that is handed the payment and submits something else settles nothing.
    refund = chain.replace("TransactionBuilder.fromXDR(xdr, NET)", "buildRefund()").replace("{\n", "{\n  log(xdr);\n", 1)
    assert paths({"src/paywall.ts": paywall, "src/charge.ts": step, "src/chain.ts": refund})[rule].severity.value == "high"
    # A step named after settling that only logs settles nothing.
    named = step.replace("chargeFirst", "settleFirst").replace("const ok = await submitPayment(req.paymentXdr);", "const ok = log(req.paymentXdr);")
    found = paths({"src/paywall.ts": paywall, "src/charge.ts": named, "src/chain.ts": chain,
                   "src/app.ts": app.replace("chargeFirst", "settleFirst")})
    assert found[rule].severity.value == "high"


def test_requirements_matched_before_an_else_branch_settle_are_bound():
    rule = "security-x402-requirements-from-payer"
    head = SETTLE_HEAD.replace('const app', 'import { isDeepStrictEqual } from "node:util";\nconst app')
    settle = ("    const s = await facilitator.settle(p, p.accepted);\n    if (!s.success) return res.status(402).end();\n"
              "    res.json({ quote: 42 });\n")
    for check in ("!isDeepStrictEqual(p.accepted, ROUTES.quote)", "p.accepted.amount !== R.amount || p.accepted.payTo !== R.payTo"):
        handler = (head + 'app.get("/q", async (req, res) => {\n'
                   '  const p = decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE"));\n'
                   f"  if ({check}) {{\n    return res.status(402).end();\n  }} else {{\n{settle}  }}\n}});\n")
        assert rule not in paths({"src/server.ts": handler}), check
    # The else branch of a match runs where the requirements do not match.
    inverted = handler.replace("if (p.accepted.amount !== R.amount || p.accepted.payTo !== R.payTo) {\n    return res.status(402).end();",
                               "if (isDeepStrictEqual(p.accepted, ROUTES.quote)) {\n    log('match');")
    assert paths({"src/server.ts": inverted})[rule].severity.value == "critical"


def test_a_settle_validator_that_returns_early_or_needs_another_condition():
    rule = "security-x402-settle-unchecked"
    body = ('app.get("/q", async (req, res) => {\n'
            '  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header("PAYMENT-SIGNATURE")), REQS);\n'
            '  ensure(s);\n  res.json({ quote: 42 });\n});\n')
    for helper in ("function ensure(s) { if (s.success) return; throw new Error(s.errorReason); }\n",
                   "function ensure(s) { if (s.success) return; log(s); throw new Error(s.errorReason); }\n",
                   "function ensure(s) { if (s && !s.success) throw new Error('unpaid'); }\n"):
        assert rule not in paths({"src/server.ts": SETTLE_HEAD + helper + body}), helper
    for helper in ("function ensure(s) { if (!s.success) return; throw new Error('paid'); }\n",
                   "function ensure(s) { if (!s.success && strict) throw new Error('unpaid'); }\n",
                   "function ensure(s) { if (s.success || lenient) return; throw new Error('unpaid'); }\n"):
        assert paths({"src/server.ts": SETTLE_HEAD + helper + body})[rule].severity.value == "high", helper


def test_an_async_throwing_sponsor_helper_counts_only_when_awaited():
    throwing = "async function assertSponsorable(tx) {\n  " + GUARDS.replace("clientTx", "tx") + "\n}\n"
    for guard in ("await assertSponsorable(clientTx);", "await Promise.all([assertSponsorable(clientTx), audit(clientTx)]);"):
        assert not SIGNED & set(paths({"src/relay.ts": throwing + sponsor(guard, "BASE_FEE", "")})), guard
    # Not awaited (or settled whatever happens), its rejection stops nothing: the sponsor signs
    # whatever came in.
    for guard in ("assertSponsorable(clientTx);", "await Promise.allSettled([assertSponsorable(clientTx)]);"):
        assert SIGNED & set(paths({"src/relay.ts": throwing + sponsor(guard, "BASE_FEE", "")})), guard


def test_x402_policies_that_fall_back_or_check_something_else_cap_nothing():
    helpers = ("function isAffordable(r) { return BigInt(r.amount) <= MAX; }\n"
               "function amountOk(a) { return BigInt(a) <= MAX; }\n")
    uncapped = ("client.registerPolicy((v, reqs) => { for (const p of history) { if (BigInt(p.amount) > MAX) throw new Error('x'); } return reqs; });\n",
                "client.registerPolicy((v, reqs) => reqs.filter((r) => isAffordable(budget)));\n",
                "client.registerPolicy((v, reqs) => { const ok = reqs.filter((r) => BigInt(r.amount) <= MAX); return ok.length ? ok : reqs; });\n",
                "client.registerPolicy((v, reqs) => { const c = reqs.find((r) => BigInt(r.amount) <= MAX); return c ? [c] : reqs; });\n")
    for extra in uncapped:
        assert paths({"src/pay.ts": helpers + X402_HEAD + extra + X402_WRAP}, X402_OLD)[X402].severity.value == "high", extra
    capped = ("client.registerPolicy((v, reqs) => { const sorted = [...reqs].sort(byAmount); for (const r of sorted) { if (BigInt(r.amount) > MAX) throw new Error('x'); } return reqs; });\n",
              "client.registerPolicy((v, reqs) => reqs.filter((r) => amountOk(r.amount)));\n",
              "client.registerPolicy((v, reqs) => { const ok = reqs.filter((r) => BigInt(r.amount) <= MAX); return ok.length ? ok : []; });\n",
              "client.registerPolicy((v, reqs) => { if (!reqs.length) return reqs; return reqs.filter((r) => BigInt(r.amount) <= MAX); });\n")
    for extra in capped:
        assert X402 not in paths({"src/pay.ts": helpers + X402_HEAD + extra + X402_WRAP}, X402_OLD), extra


def test_an_agent_chat_loop_in_a_tools_directory_is_not_an_attended_script():
    agent = ('import readline from "node:readline";\n' + X402_HEAD + X402_WRAP
             + 'const rl = readline.createInterface({ input: process.stdin, output: process.stdout });\n'
             'rl.question("Ask the agent: ", async (q) => console.log(await agent.run(q, { tools: [pay] })));\n')
    for path in ("src/tools/pay.ts", "tools/pay.ts", "scripts/pay.ts"):
        assert paths({path: agent}, X402_OLD)[X402].severity.value == "high", path
    keyed = agent.replace("Ask the agent: ", "Stellar secret key: ")
    assert paths({"tools/pay.ts": keyed}, X402_OLD)[X402].severity.value == "low"
    assert paths({"src/tools/pay.ts": keyed}, X402_OLD)[X402].severity.value == "high"
