"""Soroban authorization entries: blind trees, expirations and web-auth challenges (swarm/auth_rules.py)."""

from __future__ import annotations

from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.agentic_paths import analyse_agentic_paths
from backend.app.swarm.auth_rules import classify_expiration
from backend.app.swarm.hardening import analyse_hardening

SIGNED = "security-path-external-transaction-signed"
FINANCIAL = "security-path-untrusted-to-financial-sink"
EXPIRY = "security-auth-expiration-wide"


def rule(fid: str) -> str:
    head, _, tail = fid.rpartition("-")
    return head if len(tail) == 8 and all(c in "0123456789abcdef" for c in tail) else fid


def paths(files: dict) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files, raw_metadata={})
    return {rule(f.id): f for f in analyse_agentic_paths(artifact, "security")}


def hardening(files: dict) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files, raw_metadata={})
    return {rule(f.id): f for f in analyse_hardening(artifact, "security")}


# ----------------------------------------------------------------- blind trees (JS)
_INVOKE = """
import { Contract, Keypair, TransactionBuilder, authorizeEntry, rpc } from '@stellar/stellar-sdk';
const kp = Keypair.fromSecret(process.env.AGENT_SECRET!);
const server = new rpc.Server(process.env.RPC_URL!);
server2.tool('invoke', { contractId: z.string(), fn: z.string() }, async (args) => {
  const account = await server.getAccount(kp.publicKey());
  const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: PASS })
    .addOperation(new Contract(args.contractId).call(args.fn)).setTimeout(30).build();
  const sim = await server.simulateTransaction(tx);
  const latest = (await server.getLatestLedger()).sequence;
  const signed = [];
  for (const e of sim.result.auth) {
    CHECK
    signed.push(await authorizeEntry(e, kp, latest + 5000, PASS));
  }
  return signed;
});
"""


def test_a_tree_simulated_for_a_model_chosen_contract_is_signed_blind():
    found = paths({"src/invoke.ts": _INVOKE.replace("CHECK", "")})
    finding = found[SIGNED]
    assert finding.severity.value == "high" and "src/invoke.ts:14" in finding.evidence
    assert "simulating a contract" in finding.detail and "5000 ledgers" in finding.detail
    assert EXPIRY not in found  # merged into the signing finding: one finding per defect


def test_an_inspected_tree_is_not_reported():
    check = ("const inv = e.rootInvocation();\n"
             "    if (inv.subInvocations().length !== 0 ||\n"
             "        Address.fromScAddress(inv.function().contractFn().contractAddress()).toString() !== USDC_SAC ||\n"
             "        inv.function().contractFn().functionName().toString() !== 'transfer') throw new Error('tree');")
    found = paths({"src/invoke.ts": _INVOKE.replace("CHECK", check).replace("latest + 5000", "latest + 12")})
    assert SIGNED not in found and EXPIRY not in found


def test_an_operator_contract_adds_no_tree_evidence():
    fixed = _INVOKE.replace("new Contract(args.contractId).call(args.fn)", "new Contract(ESCROW_ID).call('release')")
    found = paths({"src/invoke.ts": fixed.replace("CHECK", "").replace("latest + 5000", "latest + 100")})
    assert SIGNED not in found and EXPIRY not in found


_SCHEME = """
import { contract, nativeToScVal } from '@stellar/stellar-sdk';
export class ExactStellarScheme {
  constructor(private readonly signer: Signer, private readonly rpcConfig?: RpcConfig) {}
  async createPaymentPayload(x402Version: number, paymentRequirements: PaymentRequirements) {
    const { network, payTo, asset, amount, maxTimeoutSeconds } = paymentRequirements;
    const latest = await getRpcClient(network, this.rpcConfig).getLatestLedger();
    const maxLedger = latest.sequence + Math.ceil(maxTimeoutSeconds / 5);
    const tx = await contract.AssembledTransaction.build({
      contractId: asset, method: 'transfer', args: [nativeToScVal(payTo, { type: 'address' })],
      networkPassphrase: getNetworkPassphrase(network), rpcUrl: getRpcUrl(network, this.rpcConfig),
    });
    await tx.signAuthEntries({ address: this.signer.address, signAuthEntry: this.signer.signAuthEntry, expiration: maxLedger });
    return { x402Version, payload: { transaction: tx.built!.toXDR() } };
  }
}
"""


def test_a_vendored_x402_scheme_signs_the_tree_of_the_asset_the_402_names():
    found = paths({"src/stellar/scheme.ts": _SCHEME})
    finding = found[SIGNED]
    assert finding.severity.value == "high" and "src/stellar/scheme.ts:13" in finding.evidence
    assert "maxTimeoutSeconds" in finding.detail and EXPIRY not in found
    pinned = _SCHEME.replace("contractId: asset", "contractId: USDC_SAC")
    assert SIGNED not in paths({"src/stellar/scheme.ts": pinned})


def test_auth_entry_callbacks_take_the_receivers_taint():
    callback = ("server.tool('sign', { xdr: z.string() }, async ({ xdr }) => {\n"
                "  const tx = client.txFromXDR(xdr);\n"
                "  await tx.signAuthEntries({ address: kp.publicKey(), authorizeEntry: async (entry) => "
                "authorizeEntry(entry, kp, ledger + 100, PASS) });\n});\n")
    assert "src/sign.ts:3" in paths({"src/sign.ts": callback})[SIGNED].evidence


# ----------------------------------------------------------------- blind trees (Python)
_PY = '''
import requests
from stellar_sdk import Keypair, SorobanServer, TransactionBuilder
from stellar_sdk.auth import authorize_entry

def pay(url: str):
    accepted = requests.get(url).json()["accepts"][0]
    kp = Keypair.from_secret(os.environ["AGENT_SECRET"])
    server = SorobanServer(RPC)
    timeout = int(accepted.get("maxTimeoutSeconds", 300))
    until = server.get_latest_ledger().sequence + timeout // 5
    tx = (TransactionBuilder(source_account=NULL_ACCOUNT, network_passphrase=PASS, base_fee=100)
          .append_invoke_contract_function_op(contract_id=CONTRACT, function_name="transfer", parameters=[])
          .build())
    prepared = server.prepare_transaction(tx)
    op = prepared.transaction.operations[0]
    op.auth = [authorize_entry(e, kp, until, PASS) for e in op.auth]
    return prepared.to_xdr()
'''


def test_python_entries_of_a_contract_the_402_names_are_signed_blind():
    found = paths({"client.py": _PY.replace("CONTRACT", 'accepted["asset"]')})
    finding = found[FINANCIAL]
    assert finding.severity.value == "high" and "simulating a contract" in finding.detail
    assert "maxTimeoutSeconds" in finding.detail and EXPIRY not in found


def test_python_entries_of_the_agents_own_contract_add_nothing():
    own = _PY.replace("CONTRACT", "ESCROW_ID").replace("timeout // 5", "100")
    found = paths({"client.py": own})
    assert EXPIRY not in found and all("simulating a contract" not in f.detail for f in found.values())


# ----------------------------------------------------------------- expiration
def test_expiration_classes():
    def resolve(table):
        return lambda name: table.get(name)
    assert classify_expiration("latest + 100", resolve({})) is None
    assert classify_expiration("ledger.sequence + 500", resolve({})).severity.value == "low"
    assert classify_expiration("seq + LEDGERS", resolve({"LEDGERS": "5_000"})).severity.value == "medium"
    assert classify_expiration("(Date.now() / 5) | 0", resolve({})).severity.value == "low"
    assert classify_expiration("latest + windowLedgers(req.maxTimeoutSeconds)",
                               resolve({"windowLedgers": "function windowLedgers(s) { return Math.min(Math.ceil(s / 5), 60); }"})) is None
    assert classify_expiration("latest + Math.ceil(timeout / 5)", resolve({"timeout": "requirements.maxTimeoutSeconds"})) \
        .severity.value == "low"


def test_a_wall_clock_expiration_in_a_wallet_is_low():
    wallet = ("export class KeypairWallet {\n  async signAuthEntry(entry, opts) {\n"
              "    const validUntilLedger = (Date.now() / 5) | 0;\n"
              "    return authorizeEntry(entry, this.keypair, validUntilLedger, opts.networkPassphrase);\n  }\n}\n")
    assert paths({"src/wallet.ts": wallet})[EXPIRY].severity.value == "low"


def test_rust_signature_expiration_from_the_payers_timeout_is_low():
    rust = ("pub fn sign(requirements: &Requirements, latest_ledger: u32) {\n"
            "    let signature_expiration_ledger = compute(latest_ledger, requirements.max_timeout_seconds);\n"
            "    creds.signature_expiration_ledger = signature_expiration_ledger;\n}\n"
            "fn compute(latest: u32, timeout: u32) -> u32 { latest.saturating_add(timeout.div_ceil(5)) }\n"
            "#[cfg(test)]\nmod tests { fn t() { let c = X { signature_expiration_ledger: latest + 99_999 }; } }\n")
    finding = hardening({"crates/x402/src/exact.rs": rust})[EXPIRY]
    assert finding.severity.value == "low" and "exact.rs:2" in finding.evidence
    clamped = rust.replace("timeout.div_ceil(5)", "timeout.div_ceil(5).min(MAX_LEDGERS)")
    assert EXPIRY not in hardening({"crates/x402/src/exact.rs": clamped})
    fixture = "fn t() { let c = X { signature_expiration_ledger: 9_999, nonce: 1 }; }\n"
    assert EXPIRY not in hardening({"crates/x402/src/exact.rs": fixture})


# ----------------------------------------------------------------- SEP-10 / SEP-45
_SEP10 = """
server.tool('sep10', { domain: z.string() }, async ({ domain }) => {
  const toml = await fetchText(`https://${domain}/.well-known/stellar.toml`);
  const webAuthEndpoint = parseToml(toml, 'WEB_AUTH_ENDPOINT');
  const url = new URL(webAuthEndpoint);
  url.searchParams.set('account', kp.publicKey());
  const challenge = await fetchJson(url.toString());
  const tx = new Transaction(challenge.transaction, PASS);
  tx.sign(kp);
  return fetchJson(webAuthEndpoint, { method: 'POST', body: JSON.stringify({ transaction: tx.toXDR() }) });
});
"""


def test_a_sep10_challenge_signed_unchecked_is_high():
    finding = paths({"src/tools/seps.ts": _SEP10})["security-sep10-challenge-unchecked"]
    assert finding.severity.value == "high" and "src/tools/seps.ts:9" in finding.evidence


def test_a_sep10_challenge_read_by_the_sdk_is_not_reported():
    read = _SEP10.replace("const tx = new Transaction(challenge.transaction, PASS);",
                          "const { tx } = WebAuth.readChallengeTx(challenge.transaction, SIGNING_KEY, PASS, domain, host);")
    assert "security-sep10-challenge-unchecked" not in paths({"src/tools/seps.ts": read})
    wallet = _SEP10.replace("tx.sign(kp);", "await freighter.signTransaction(tx.toXDR(), { networkPassphrase: PASS });")
    assert "security-sep10-challenge-unchecked" not in paths({"src/tools/seps.ts": wallet})


_SEP45 = """
export async function login(contractAccount: string) {
  const res = await fetch(`${WEB_AUTH_FOR_CONTRACTS_ENDPOINT}?account=${contractAccount}`);
  const { authorization_entries } = await res.json();
  return Promise.all(authorization_entries.map((x: string) =>
    authorizeEntry(xdr.SorobanAuthorizationEntry.fromXDR(x, 'base64'), kp, latest + 10, PASS)));
}
"""


def test_sep45_entries_signed_without_the_client_checks_are_high():
    # The entries come from the server's response, so the signing flow already reports them:
    # the missing SEP-45 checks join that finding (one finding per defect).
    finding = paths({"src/sep45.ts": _SEP45})[SIGNED]
    assert finding.severity.value == "high" and "SEP-45 authorization entry: nothing checks web_auth_verify" in finding.detail
    alone = _SEP45.replace("const { authorization_entries } = await res.json();", "const authorization_entries = CACHED;")
    assert paths({"src/sep45.ts": alone})["security-sep45-entries-unchecked"].severity.value == "high"
    check = ("function check(x) { const e = xdr.SorobanAuthorizationEntry.fromXDR(x, 'base64');\n"
             "  const f = e.rootInvocation().function().contractFn();\n"
             "  if (e.rootInvocation().subInvocations().length || f.functionName().toString() !== 'web_auth_verify'\n"
             "      || Address.fromScAddress(f.contractAddress()).toString() !== toml.WEB_AUTH_CONTRACT_ID) throw 0;\n"
             "  return e; }\n")
    called = _SEP45.replace("authorizeEntry(xdr.SorobanAuthorizationEntry.fromXDR(x, 'base64')", "authorizeEntry(check(x)")
    assert paths({"src/sep45.ts": called + check}) == {}
    # The same check in a function the signing code never calls inspects nothing signed here.
    assert SIGNED in paths({"src/sep45.ts": _SEP45 + check})


def test_a_sep45_finding_is_not_folded_into_a_lower_signing_finding():
    # A public function whose callers are unseen: the signing finding is LOW (origin
    # unresolved), so the SEP-45 HIGH stands on its own instead of being lowered with it.
    public = ("const ENDPOINT = toml.WEB_AUTH_FOR_CONTRACTS_ENDPOINT;\n"
              "export async function signEntries(authorization_entries: string[], kp: Keypair, latest: number) {\n"
              "  return Promise.all(authorization_entries.map((x: string) =>\n"
              "    authorizeEntry(xdr.SorobanAuthorizationEntry.fromXDR(x, 'base64'), kp, latest + 10, PASS)));\n}\n")
    found = paths({"src/sep45.ts": public})
    assert found["security-sep45-entries-unchecked"].severity.value == "high"


# ----------------------------------------------------------------- review fixes
_TOOL = """
import { authorizeEntry, xdr, Keypair } from '@stellar/stellar-sdk';
const kp = Keypair.fromSecret(process.env.AGENT_SECRET!);
server.tool('sign_entry', { entry: z.string() }, async ({ entry }) => {
  const e = xdr.SorobanAuthorizationEntry.fromXDR(entry, 'base64');
  NOTE
  const signed = await authorizeEntry(e, kp, latest + 12, PASS);
  return signed.toXDR('base64');
});
"""


def test_naming_the_tree_parts_in_comments_or_logs_is_not_an_inspection():
    assert paths({"src/t.ts": _TOOL.replace("NOTE", "")})[SIGNED].severity.value == "high"
    for note in ("// TODO: check subInvocations, contractAddress and functionName",
                 "const f = e.rootInvocation().function().contractFn();\n"
                 "  console.log(f.contractAddress(), f.functionName(), e.rootInvocation().subInvocations().length);",
                 "const msg = 'subInvocations contractAddress functionName';",
                "const f = e.rootInvocation().function().contractFn();\n"
                "  if (!e.rootInvocation().subInvocations() || !f.contractAddress() || !f.functionName()) throw 0;"):
        assert paths({"src/t.ts": _TOOL.replace("NOTE", note)})[SIGNED].severity.value == "high", note
    compared = ("const f = e.rootInvocation().function().contractFn();\n"
                "  const contract = Address.fromScAddress(f.contractAddress()).toString();\n"
                "  if (e.rootInvocation().subInvocations().length !== 0 || contract !== USDC_SAC\n"
                "      || !ALLOWED.includes(f.functionName().toString())) throw new Error('tree');")
    assert SIGNED not in paths({"src/t.ts": _TOOL.replace("NOTE", compared)})


def test_python_tree_checks_must_compare_in_the_signing_function_or_its_helpers():
    py = ("import os\nfrom stellar_sdk import Keypair\nfrom stellar_sdk.auth import authorize_entry\n"
          "from stellar_sdk.xdr import SorobanAuthorizationEntry\nkp = Keypair.from_secret(os.environ['AGENT_SECRET'])\n"
          "NOTE\n@mcp.tool()\ndef sign_entry(entry_xdr: str) -> str:\n"
          "    entry = SorobanAuthorizationEntry.from_xdr(entry_xdr)\n    CALL\n"
          "    return authorize_entry(entry, kp, 1000, PASS).to_xdr()\n")
    helper = ("def check(entry):\n    inv = entry.root_invocation\n    fn = inv.function.contract_fn\n"
              "    if inv.sub_invocations or fn.function_name.sc_symbol != b'transfer' "
              "or fn.contract_address != USDC_ADDRESS:\n        raise ValueError('tree')\n")
    plain = py.replace("CALL", "pass")
    assert paths({"agent.py": plain.replace("NOTE", "")})[FINANCIAL].severity.value == "high"
    assert FINANCIAL in paths({"agent.py": plain.replace("NOTE", "# TODO: verify sub_invocations, contract_address, function_name")})
    assert FINANCIAL in paths({"agent.py": plain.replace("NOTE", helper)})  # defined, never called
    assert FINANCIAL not in paths({"agent.py": py.replace("NOTE", helper).replace("CALL", "check(entry)")})


def test_an_entry_the_code_builds_with_no_sub_invocations_is_not_external():
    built = ("import { Address, Contract, Operation, authorizeEntry, xdr } from '@stellar/stellar-base';\n"
             "export class Signer {\n  async sign(intent) {\n"
             "    const op = new Contract(intent.asset).call('transfer', Address.fromString(intent.payTo).toScVal());\n"
             "    const invocation = op.body().invokeHostFunctionOp().hostFunction().invokeContract();\n"
             "    const unsigned = new xdr.SorobanAuthorizationEntry({ credentials: CREDS,\n"
             "      rootInvocation: new xdr.SorobanAuthorizedInvocation({\n"
             "        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(\n"
             "          xdr.InvokeContractArgs.fromXDR(invocation.toXDR())),\n        subInvocations: [] }) });\n"
             "    const o = Operation.invokeHostFunction({ func: F, auth: [unsigned] });\n"
             "    const entry = (Operation.fromXDRObject(o) as any).auth?.[0];\n"
             "    return authorizeEntry(entry, this.kp, latest + 12, PASS);\n  }\n}\n")
    assert SIGNED not in paths({"src/sign.ts": built})
    parsed = built.replace("xdr.InvokeContractArgs.fromXDR(invocation.toXDR())", "xdr.InvokeContractArgs.fromXDR(intent.call)")
    assert SIGNED in paths({"src/sign.ts": parsed})  # the root call is whatever the caller sent


def test_helper_bodies_do_not_set_the_expiration():
    wallet = """
import { authorizeEntry } from '@stellar/stellar-sdk';
async function latestLedger(server) {
  BODY
  return (await r.json()).sequence;
}
export class Wallet {
  async signAuthEntry(entry, opts) {
    const latest = await latestLedger(this.server);
    return authorizeEntry(entry, this.keypair, latest + 12, opts.networkPassphrase);
  }
}
"""
    for body in ("const r = await fetch(server.url, { signal: AbortSignal.timeout(1000 + 9000) });",
                 "const r = await fetch(server.url); console.log(new Date().toISOString());",
                 "const r = await fetch(server.url); const requirements = 1;"):
        assert EXPIRY not in paths({"src/wallet.ts": wallet.replace("BODY", body)}), body
    py = ("import time\nfrom stellar_sdk.auth import authorize_entry\n"
          "def get_latest_ledger(server):\n    started = time.time()\n    return server.get_latest_ledger().sequence\n\n"
          "def sign(entry, kp, server):\n    return authorize_entry(entry, kp, get_latest_ledger(server) + 12, PASS)\n")
    assert EXPIRY not in paths({"agent.py": py})
    # What the helper returns still counts.
    far = py.replace("return server.get_latest_ledger().sequence", "return server.get_latest_ledger().sequence + 5000")
    assert paths({"agent.py": far})[EXPIRY].severity.value == "medium"
    assert classify_expiration("latest + 12", lambda n: {"latest": "await latestLedger(this.server)",
                                                         "latestLedger": "(await r.json()).sequence"}.get(n)) is None
    assert classify_expiration("latest + Math.ceil((deadline - Date.now()) / 5000)", lambda n: None) is None


def test_authorize_invocation_takes_the_expiry_second_and_the_tree_third():
    # stellar-base: authorizeInvocation(signer, validUntilLedgerSeq, invocation, publicKey, passphrase)
    tool = ("server.tool('auth', { inv: z.string() }, async ({ inv }) => {\n"
            "  const invocation = xdr.SorobanAuthorizedInvocation.fromXDR(inv, 'base64');\n"
            "  return authorizeInvocation(kp, latest + 5000, invocation, kp.publicKey(), PASS);\n});\n")
    found = paths({"src/auth.ts": tool})
    assert found[SIGNED].severity.value == "high" and found[EXPIRY].severity.value == "medium"
    own = tool.replace("xdr.SorobanAuthorizedInvocation.fromXDR(inv, 'base64')", "OWN_INVOCATION")
    assert SIGNED not in paths({"src/auth.ts": own.replace("({ inv })", "({ amount })")})


def test_an_x402_scheme_registered_by_a_reported_wrapper_joins_that_finding():
    wrapper = ("import { wrapFetchWithPayment, x402Client } from '@x402/fetch';\n"
               "import { ExactStellarScheme } from './stellar/scheme';\n"
               "const client = new x402Client().register('stellar:*', new ExactStellarScheme(signer));\n"
               "export const paidFetch = wrapFetchWithPayment(fetch, client);\n")
    files = {"mcp/package.json": "{}", "mcp/src/index.ts": wrapper, "mcp/src/stellar/scheme.ts": _SCHEME}
    found = paths(files)
    x402 = found["security-path-x402-payment-unbounded"]
    assert SIGNED not in found and EXPIRY not in found  # one finding per defect
    assert "mcp/src/stellar/scheme.ts:13" in x402.detail and "maxTimeoutSeconds" in x402.detail
