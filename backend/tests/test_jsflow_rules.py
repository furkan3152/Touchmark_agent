"""JS/TS data-flow behaviours found on real agents (each was a miss or a false positive)."""

from __future__ import annotations

import asyncio

from backend.app.config import Settings
from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.codeflow import analyse_code
from backend.app.swarm.stellar_native import StellarNativeAuditor


def flows(files):
    return sorted({(f.category, ",".join(sorted(f.labels))) for f in analyse_code(files).flows})


def categories(files):
    return {f.category for f in analyse_code(files).flows}


def test_secret_keys_passed_through_the_model_are_reported():
    tool = ('server.tool("pay", "pay", { to: z.string(), secretKey: z.string() }, async ({ to, secretKey }) => {\n'
            '  return send(Keypair.fromSecret(secretKey), to);\n});\n')
    assert "secret_via_model" in categories({"a.ts": tool})
    # Operator configuration in the second handler parameter is not model input.
    kit = ('export const t = { name: "pay", description: "pay", inputSchema: S,\n'
           '  async execute(input, config) { return Keypair.fromSecret(config.secretKey).publicKey(); } };\n')
    assert "secret_via_model" not in categories({"a.ts": kit})


def test_x402_wrapper_without_a_ceiling_lets_the_server_set_the_payment():
    unbounded = ('import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";\n'
                 'export const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: N, client: c }] });\n')
    bounded = ('import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";\n'
               'export const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: N, client: c }], maxValue: 100000n });\n')
    assert "x402_unbounded" in categories({"a.ts": unbounded})
    assert "x402_unbounded" not in categories({"a.ts": bounded})


def test_browser_wallet_signing_and_relay_are_not_agent_authority():
    dapp = ('import { signTransaction } from "@stellar/freighter-api";\n'
            'export async function pay(from: string, to: string, amount: string) {\n'
            '  const tx = new TransactionBuilder(await horizon.loadAccount(from), o)\n'
            '    .addOperation(Operation.payment({ destination: to, asset, amount })).build();\n'
            '  const { signedTxXdr } = await signTransaction(tx.toXDR(), { networkPassphrase: N });\n'
            '  return horizon.submitTransaction(TransactionBuilder.fromXDR(signedTxXdr, N));\n}\n')
    hook = ('export function Panel() {\n  const { signTransaction } = useWallet();\n'
            '  async function go(xdr: string) { return signTransaction(xdr, N); }\n  return go;\n}\n')
    assert flows({"a.ts": dapp}) == [] and flows({"b.tsx": hook}) == []


def test_unpassed_option_properties_are_not_tainted():
    files = {"client.ts": 'export async function call(options: { serviceId: string; base?: string }) {\n'
                          '  const base = options.base ?? process.env.ROUTER_URL;\n'
                          '  return fetch(`${base}/services/${options.serviceId}`);\n}\n',
             "tool.ts": 'import { call } from "./client";\n'
                        'server.tool("svc", "call", { id: z.string() }, async (args) => call({ serviceId: args.id }));\n'}
    assert "ssrf" not in categories(files)
    files["tool.ts"] = files["tool.ts"].replace("call({ serviceId: args.id })", "call({ serviceId: args.id, base: args.id })")
    assert "ssrf" in categories(files)


def test_script_path_from_argv_is_not_user_input():
    code = ('import fs from "fs";\nimport path from "path";\n'
            'const DIR = path.dirname(path.resolve(process.argv[1]));\n'
            'export function load() { return fs.readFileSync(path.join(DIR, "data.json"), "utf8"); }\n')
    assert "path_traversal" not in categories({"a.ts": code})
    assert "path_traversal" in categories({"a.ts": code.replace("process.argv[1]", "process.argv[2]")})


def test_shell_command_options_are_not_the_command():
    code = ('import { execSync } from "child_process";\n'
            'export function install(dir: string) { return execSync("npm install --omit=dev", { cwd: dir }); }\n')
    assert "command" not in categories({"a.ts": code})


def test_payment_verification_must_check_success():
    verify = ('export async function verifyPayment(hash: string, payTo: string, amount: string) {\n'
              '  const tx = await server.transactions().transaction(hash).call();\n'
              '  const ops = await server.operations().forTransaction(hash).call();\n'
              '  const p = ops.records.find((o) => o.type === "payment");\n'
              '  return p && p.to === payTo && Number(p.amount) >= Number(amount);\n}\n')

    def fired(code):
        artifact = AgentArtifact(source_kind=SourceKind.REPO, name="gw", code_files={"src/verify.ts": code})
        found, _, _ = asyncio.run(StellarNativeAuditor(Settings(_env_file=None)).analyse(artifact, True))
        return any(f.id == "stellar_native-payment-success-unchecked" for f in found)
    assert fired(verify)
    assert not fired(verify.replace("const ops", "if (!tx.successful) return false;\n  const ops"))


def test_ssrf_pinned_to_a_checked_address_is_controlled():
    guard = ('import { BlockList } from "node:net";\n'
             'const blocked = new BlockList(); blocked.addSubnet("10.0.0.0", 8);\n'
             'export async function resolvePublic(host: string) { const a = await lookup(host);\n'
             '  if (blocked.check(a.address)) throw new Error("private"); return a; }\n')
    route = ('import { request as httpsRequest } from "node:https";\n'
             'import { resolvePublic } from "./guard";\n'
             'app.post("/fetch", async (req, res) => {\n'
             '  const url = new URL(req.body.url);\n'
             '  const dest = await resolvePublic(url.hostname);\n'
             '  httpsRequest(url, { lookup: (_h, _o, cb) => cb(null, dest.address, dest.family) });\n'
             '});\n')
    assert "ssrf" not in categories({"src/guard.ts": guard, "src/route.ts": route})
    # A custom lookup with no address check anywhere is not a control.
    assert "ssrf" in categories({"src/route.ts": route.replace('import { resolvePublic } from "./guard";\n', "")})


def test_many_anonymous_functions_on_one_line_terminate():
    code = ("export function f(t: any) {\n"
            "  return t.undo.filter((s) => !s.some((x) => g(x))).map((s) => s.map((x) => h(x, t)));\n}\n")
    assert analyse_code({"a.ts": code}).analysed_files == ["a.ts"]


def test_builtin_calls_never_resolve_to_a_project_method_of_the_same_name():
    store = ("export class Store {\n  parse(row: any) { return row; }\n}\n"
             'server.tool("save", "save", {}, async (args) => new Store().parse(args));\n')
    script = ('import { execFileSync } from "node:child_process";\n'
              'const manifest = JSON.parse(readFileSync("package.json", "utf8"));\n'
              'execFileSync("npm", ["run", "build", "-w", manifest.name]);\n')
    assert "command" not in categories({"src/store.ts": store, "tooling/build.mjs": script})


def test_path_confined_in_a_conditional_expression_is_controlled():
    server = ('import { readFile } from "node:fs/promises";\nimport { resolve, sep } from "node:path";\n'
              'const root = resolve("dist");\n'
              'const safe = (p: string) => { const t = resolve(root, `.${p}`); return t.startsWith(`${root}${sep}`) ? t : null; };\n'
              'app.get("/*", async (req, res) => { const f = safe(req.path); if (!f) return; res.send(await readFile(f)); });\n')
    assert "path_traversal" not in categories({"serve.ts": server})
    assert "path_traversal" in categories({"serve.ts": server.replace("t.startsWith(`${root}${sep}`)", "t.length > 0")})


def test_wallet_standard_signing_is_a_wallet_prompt():
    code = ('export async function execute(wallet: any, account: any, request: any) {\n'
            '  const signOnly = wallet.features["solana:signTransaction"];\n'
            '  return signOnly.signTransaction({ account, transaction: request.transaction });\n}\n')
    assert "foreign_signing" not in categories({"exec.ts": code})


def test_arrow_functions_declared_inside_functions_are_resolved():
    src = ('import { readFile } from "node:fs/promises";\nimport { resolve } from "node:path";\n'
           'export function start(root: string) {\n'
           '  const safePath = (p: string) => { const t = resolve(root, p); return t.startsWith(root) ? t : null; };\n'
           '  app.get("/*", async (req, res) => { const f = safePath(req.path); if (f) await readFile(f); });\n}\n')
    assert "path_traversal" not in categories({"s.ts": src})
    assert "path_traversal" in categories({"s.ts": src.replace("t.startsWith(root)", "t.length > 0")})


def test_model_supplied_key_used_by_a_service_method_is_reported():
    service = ('export class Classic {\n  async pay(params: any) {\n'
               '    const { to, secretKey } = Schema.parse(params);\n    return sign(Keypair.fromSecret(secretKey), to);\n  }\n}\n')
    tools = ('const classic = new Classic();\n'
             'server.tool("pay", "pay", {}, async (args) => classic.pay(args));\n')
    assert "secret_via_model" in categories({"src/classic.ts": service, "src/tools.ts": tools})
    # A stored record that model-chosen ids touched is not a key the model supplied.
    store = ('export function webhookSecret(record: any) { return openSecret(record.sealedSecret); }\n'
             'server.tool("hook", "hook", {}, async (args) => webhookSecret(lookup(args.id)));\n')
    assert "secret_via_model" not in categories({"src/store.ts": store})


def test_either_branch_of_a_disjunction_must_confine_the_path():
    src = ('import { readFile } from "node:fs/promises";\nimport { resolve, sep } from "node:path";\n'
           'export function start(root: string) {\n'
           '  const safePath = (p: string) => { const t = resolve(root, p); return COND ? t : null; };\n'
           '  app.get("/*", async (req, res) => { const f = safePath(req.path); if (f) await readFile(f); });\n}\n')
    assert "path_traversal" not in categories({"s.ts": src.replace("COND", "t === root || t.startsWith(`${root}${sep}`)")})
    assert "path_traversal" in categories({"s.ts": src.replace("COND", "t.length > 1 || t.startsWith(`${root}${sep}`)")})


def test_masked_secrets_in_logs_are_not_secret_output():
    code = ('function maskSecret(s: string) { return s ? `${s.slice(0, 4)}...` : "(not set)"; }\n'
            'console.log(`secret: ${maskSecret(process.env.STELLAR_SECRET_KEY)}`);\n')
    assert not categories({"cli.ts": code}) & {"secret_possible", "secret_to_log", "secret_exfiltration"}


def test_signers_supplied_by_the_caller_are_delegated_not_agent_authority():
    sdk = ('export async function executeStep(signers: any, payload: any) {\n'
           '  for (const transaction of payload.transactions) {\n'
           '    const evm = signers.evm as EvmSigner;\n    await evm.sendTransaction(transaction);\n'
           '    await signers.solana.signAndSendTransaction(transaction);\n  }\n}\n')
    assert not categories({"execute.ts": sdk}) & {"financial", "foreign_signing"}
    # A key this code holds is the agent's own authority.
    agent = ('const kp = Keypair.fromSecret(process.env.AGENT_SECRET);\n'
             'app.post("/sign", async (req, res) => { const tx = TransactionBuilder.fromXDR(req.body.xdr, NET);\n'
             '  tx.sign(kp); res.json(await server.submitTransaction(tx)); });\n')
    assert "foreign_signing" in categories({"agent.ts": agent})
