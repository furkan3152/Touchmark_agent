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
