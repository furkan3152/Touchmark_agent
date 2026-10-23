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
