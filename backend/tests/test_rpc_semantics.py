"""Stellar SDK semantics: RPC results read as final or misread, string durabilities, removed
symbols, v3-only transaction meta, oversized amounts, skipped memo checks, payments released
after a broadcast and transactions with no time bounds. Each rule has a vulnerable fixture
and a safe near miss; SDK versions come from a synthetic lockfile record."""

from __future__ import annotations

from backend.app.config import Settings
from backend.app.models import AgentArtifact, SourceKind
from backend.app.stellar import sdk_semantics as sdk
from backend.app.swarm.hardening import analyse_hardening
from backend.app.swarm.sdk_rules import rpc_findings
from backend.app.swarm.stellar_native import StellarNativeAuditor


def rule(fid: str) -> str:
    head, _, tail = fid.rpartition("-")
    return head if len(tail) == 8 and all(c in "0123456789abcdef" for c in tail) else fid


def npm(version: str = "14.6.1", package: str = "@stellar/stellar-sdk") -> dict:
    return {"importers": {"": {"lockfiles": ["package-lock.json"],
                               "deps": {package: {"spec": f"^{version}", "version": version}}}},
            "locked": {"package-lock.json": {package: [version]}}}


def pypi(spec: str = "==13.1.0") -> dict:
    return {"importers": {"": {"lockfiles": [], "deps": {"stellar-sdk": {"spec": spec, "version": None}}}}, "locked": {}}


def native(files: dict, resolved: dict | None = None) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files,
                             raw_metadata={"resolved_versions": resolved or {}})
    return {rule(f.id): f for f in rpc_findings(artifact, StellarNativeAuditor(Settings(_env_file=None)))}


def hardening(files: dict) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files, raw_metadata={})
    return {rule(f.id): f for f in analyse_hardening(artifact, "security")}


MISREAD = "stellar_native-rpc-response-misread"
FINAL = "stellar_native-rpc-send-treated-as-final"
RETRY = "security-retry-may-pay-twice"
EXPIRY = "security-transaction-never-expires"

PY_HEAD = '''from stellar_sdk import Keypair, TransactionBuilder
from stellar_sdk.soroban_server import SorobanServer
from stellar_sdk.soroban_rpc import SendTransactionStatus, GetTransactionStatus

soroban = SorobanServer("https://soroban-testnet.stellar.org")
'''


# ----------------------------------------------------------------------------- tables
def test_tables_name_the_fields_each_release_defines():
    assert sdk.py_field_missing("send", "error", None, "16.0.0")
    assert not sdk.py_field_missing("send", "error_result_xdr", None, "13.1.0")
    # simulate_transaction lost `cost` in 12.0.0: missing on 13.1.0, present on 11.0.0.
    assert sdk.py_field_missing("simulate", "cost", "==13.1.0", "13.1.0")
    assert not sdk.py_field_missing("simulate", "cost", "==11.0.0", "11.0.0")
    # Unknown version: a field is missing only if no verified release has it.
    assert not sdk.py_field_missing("simulate", "cost", None, None)
    assert not sdk.py_field_missing("get", "model_dump", None, None)


# ----------------------------------------------------------------------------- K2
def test_python_status_compared_with_a_string_and_a_missing_field_are_reported():
    source = PY_HEAD + '''def pay(kp, tx):
    tx.sign(kp)
    resp = soroban.send_transaction(tx)
    if resp.status == "PENDING":
        return poll(resp.hash)
    raise RuntimeError(resp.error)
'''
    found = native({"agent.py": source}, pypi())
    assert found[MISREAD].severity.value == "medium"
    assert "agent.py:9" in found[MISREAD].evidence and "agent.py:11" in found[MISREAD].evidence
    assert "stellar-sdk 13.1.0" in found[MISREAD].evidence


def test_python_enum_comparison_and_declared_fields_are_not_reported():
    source = PY_HEAD + '''def pay(kp, tx):
    tx.sign(kp)
    resp = soroban.send_transaction(tx)
    if resp.status == SendTransactionStatus.PENDING:
        result = soroban.poll_transaction(resp.hash)
        return result.status == GetTransactionStatus.SUCCESS
    raise RuntimeError(resp.error_result_xdr)
'''
    assert MISREAD not in native({"agent.py": source}, pypi())


def test_a_name_reused_for_a_contract_data_read_takes_the_kind_of_its_own_assignment():
    source = PY_HEAD + '''def run(action, kp, tx, key):
    if action == "read":
        result = soroban.get_contract_data("C", key)
        return result.val
    tx.sign(kp)
    sent = soroban.send_transaction(tx)
    result = soroban.poll_transaction(sent.hash)
    return result.ledger
'''
    assert MISREAD not in native({"agent.py": source}, pypi())


def test_a_projects_own_rpc_client_is_not_judged_by_the_sdk_tables():
    source = '''from stellar_sdk.soroban_server import SorobanServer

class RpcClient:
    def get_transaction(self, h):
        return {"status": "SUCCESS"}

def check(rpc, h):
    r = rpc.get_transaction(h)
    return r.status == "SUCCESS"
'''
    assert MISREAD not in native({"agent.py": source}, pypi())


# ----------------------------------------------------------------------------- K7
def test_durability_passed_as_a_string_is_reported():
    source = PY_HEAD + '''def read(contract_id, key, durability: str = "persistent"):
    return soroban.get_contract_data(contract_id, key, durability=durability)
'''
    found = native({"agent.py": source}, pypi())
    assert found["stellar_native-rpc-durability-as-string"].severity.value == "low"


def test_durability_enum_is_not_reported():
    source = PY_HEAD + '''from stellar_sdk.soroban_server import Durability
def read(contract_id, key):
    return soroban.get_contract_data(contract_id, key, durability=Durability.PERSISTENT)
'''
    assert "stellar_native-rpc-durability-as-string" not in native({"agent.py": source}, pypi())


# ----------------------------------------------------------------------------- K1
TS_HEAD = 'import { rpc, TransactionBuilder } from "@stellar/stellar-sdk";\nconst server = new rpc.Server(process.env.RPC_URL!);\n'


def test_a_pending_send_that_marks_an_order_paid_is_reported():
    source = TS_HEAD + '''export async function checkout(order: string, tx: any) {
  const r = await server.sendTransaction(tx);
  if (r.status === "PENDING") {
    await markPaid(order, r.hash);
    return { ok: true };
  }
}
'''
    found = native({"src/pay.ts": source}, npm())
    assert found[FINAL].severity.value == "medium"
    assert "@stellar/stellar-sdk 14.6.1" in found[FINAL].evidence


def test_a_send_that_is_polled_is_not_reported():
    source = TS_HEAD + '''export async function checkout(order: string, tx: any) {
  const r = await server.sendTransaction(tx);
  const f = await server.pollTransaction(r.hash);
  if (f.status !== rpc.Api.GetTransactionStatus.SUCCESS) throw new Error("failed");
  await markPaid(order, r.hash);
}
'''
    assert FINAL not in native({"src/pay.ts": source}, npm())


def test_a_hash_returned_to_a_caller_that_polls_is_not_reported():
    submit = TS_HEAD + '''export async function submitSigned(tx: any) {
  const response = await server.sendTransaction(tx);
  if (response.status !== "PENDING") throw new Error(String(response.status));
  return { hash: response.hash };
}
export async function waitFor(hash: string) {
  return server.getTransaction(hash);
}
'''
    caller = '''import { submitSigned, waitFor } from "./submit";
export async function sign(tx: any) {
  const { hash } = await submitSigned(tx);
  const result = await waitFor(hash);
  return result;
}
'''
    assert FINAL not in native({"src/submit.ts": submit, "src/signer.ts": caller}, npm())


def test_a_hash_returned_to_a_caller_that_stores_it_is_reported_low():
    anchor = TS_HEAD + '''export async function anchor(tx: any): Promise<string | null> {
  const sent = await server.sendTransaction(tx);
  if (sent.status !== "PENDING") return null;
  return sent.hash;
}
'''
    route = '''import { anchor } from "./anchor";
export async function POST(req: any) {
  const txHash = await anchor(req.tx);
  await db.update(records).set({ txHash });
  return Response.json({ txHash });
}
'''
    found = native({"src/anchor.ts": anchor, "src/route.ts": route}, npm())
    assert found[FINAL].severity.value == "low"


def test_a_tool_that_hands_back_only_the_hash_is_low_and_one_that_reports_the_status_or_pending_is_not():
    tool = TS_HEAD + '''server2.registerTool("invoke", {}, async (args: any) => {
  const submission = await server.sendTransaction(args.tx);
  return { content: [{ type: "text", text: JSON.stringify({ hash: submission.hash }) }] };
});
'''
    assert native({"src/tools.ts": tool}, npm())[FINAL].severity.value == "low"
    # The RPC's own status (PENDING, DUPLICATE, TRY_AGAIN_LATER, ERROR) tells the caller it is not final.
    status = tool.replace("{ hash: submission.hash }", "{ status: submission.status, hash: submission.hash }")
    assert FINAL not in native({"src/tools.ts": status}, npm())
    logged = tool.replace("  return {", '  console.log("sent", submission.status);\n  return {')
    assert FINAL not in native({"src/tools.ts": logged}, npm())
    honest = tool.replace("hash: submission.hash", 'note: "submitted, still pending", hash: submission.hash')
    assert FINAL not in native({"src/tools.ts": honest}, npm())


def test_only_a_stellar_rpc_client_is_an_rpc_send():
    evm = '''import { JsonRpcProvider } from "ethers";
import { markPaid } from "./orders";
const rpcClient = new JsonRpcClient(process.env.EVM_URL);
export async function payOrder(order: any, signedTx: string) {
  const r = await rpcClient.sendTransaction(signedTx);
  await markPaid(order, r.hash);
}
'''
    assert FINAL not in native({"src/evm.ts": evm}, npm())
    # A name alone does not make a Stellar RPC client, even in a Stellar file.
    named = 'import { Keypair } from "@stellar/stellar-sdk";\n' + evm
    assert FINAL not in native({"src/evm.ts": named}, npm())
    # A client built in the project's clients module is one.
    clients = 'import { rpc } from "@stellar/stellar-sdk";\nexport const stellar = { rpc: new rpc.Server(process.env.RPC_URL!) };\n'
    pay = '''import { TransactionBuilder } from "@stellar/stellar-sdk";
import { stellar } from "./clients";
export async function payOrder(order: any, tx: any) {
  const r = await stellar.rpc.sendTransaction(tx);
  await markPaid(order, r.hash);
}
'''
    assert native({"src/clients.ts": clients, "src/pay.ts": pay}, npm())[FINAL].severity.value == "medium"


def test_an_evm_wallet_send_transaction_is_not_an_rpc_send():
    source = '''export async function approve(signer: any) {
  const hash = await signer.sendTransaction({ to: "0x1", data: "0x" });
  await db.insert(approvals).values({ hash });
}
'''
    assert FINAL not in native({"src/permit.ts": source}, npm())


# ----------------------------------------------------------------------------- K1b
def test_not_failed_read_as_success_is_reported_and_a_poll_loop_is_not():
    weak = TS_HEAD + '''export async function settled(hash: string) {
  const r = await server.getTransaction(hash);
  return { success: r.status !== "FAILED" };
}
'''
    assert native({"src/check.ts": weak}, npm())["stellar_native-rpc-outcome-not-success-checked"].severity.value == "medium"
    loop = TS_HEAD + '''export async function settled(hash: string) {
  let r: any;
  for (let i = 0; i < 30; i++) {
    r = await server.getTransaction(hash);
    if (r.status !== "NOT_FOUND") break;
  }
  if (!r || r.status !== "SUCCESS") throw new Error("not confirmed");
}
'''
    assert "stellar_native-rpc-outcome-not-success-checked" not in native({"src/check.ts": loop}, npm())


# ----------------------------------------------------------------------------- K4, K5
def test_skipped_memo_check_is_reported():
    source = 'import { Horizon } from "@stellar/stellar-sdk";\nconst h = new Horizon.Server("https://horizon.stellar.org");\n' \
             'export const send = (tx: any) => h.submitTransaction(tx, { skipMemoRequiredCheck: true });\n'
    assert "stellar_native-memo-required-check-skipped" in native({"src/send.ts": source}, npm())
    assert "stellar_native-memo-required-check-skipped" not in native(
        {"src/send.ts": source.replace("true", "false")}, npm())


def test_trustline_limit_above_int64_stroops_is_reported_and_the_maximum_is_not():
    source = 'import { Operation, Asset } from "@stellar/stellar-sdk";\n' \
             'export const trust = (asset: Asset, limit?: string) => Operation.changeTrust({ asset, limit: limit || "9223372036854775807" });\n'
    assert native({"src/trust.ts": source}, npm())["stellar_native-amount-above-int64"].severity.value == "low"
    assert "stellar_native-amount-above-int64" not in native(
        {"src/trust.ts": source.replace("9223372036854775807", sdk.MAX_AMOUNT)}, npm())
    py = 'from stellar_sdk import TransactionBuilder\ndef trust(b, asset):\n    return b.append_change_trust_op(asset=asset, limit="922337203686")\n'
    assert "stellar_native-amount-above-int64" in native({"trust.py": py}, pypi())


# ----------------------------------------------------------------------------- K6
def test_soroban_rpc_import_on_a_release_without_it_is_reported():
    source = 'export async function notify() {\n  const { SorobanRpc } = await import("@stellar/stellar-sdk");\n' \
             '  return new SorobanRpc.Server("https://soroban-testnet.stellar.org");\n}\n'
    assert "stellar_native-sdk-removed-symbol" in native({"src/notify.ts": source}, npm("14.6.1"))
    assert "stellar_native-sdk-removed-symbol" not in native({"src/notify.ts": source}, npm("12.3.0"))


def test_rpc_aliased_as_soroban_rpc_is_not_a_removed_symbol():
    source = 'import { rpc as SorobanRpc } from "@stellar/stellar-sdk";\nexport const s = new SorobanRpc.Server("https://x");\n'
    assert "stellar_native-sdk-removed-symbol" not in native({"src/rpc.ts": source}, npm("14.6.1"))


# ----------------------------------------------------------------------------- K8
def test_meta_read_as_v3_after_a_submit_is_reported_and_a_v4_branch_is_not():
    source = '''import { xdr, scValToNative } from "@stellar/stellar-sdk";
export async function invoke(signed: string) {
  const res = await submitToRelayer(signed);
  const meta = xdr.TransactionMeta.fromXDR(res.resultMetaXdr, "base64");
  return scValToNative(meta.v3().sorobanMeta()!.returnValue());
}
'''
    found = native({"src/invoke.ts": source}, npm())
    assert found["stellar_native-transaction-meta-v3-only"].severity.value == "medium"
    branched = source.replace("meta.v3().sorobanMeta()", "(meta.switch() === 4 ? meta.v4() : meta.v3()).sorobanMeta()")
    assert "stellar_native-transaction-meta-v3-only" not in native({"src/invoke.ts": branched}, npm())


# ----------------------------------------------------------------------------- K3 (retry may pay twice)
PY_CLI = '''import subprocess

class Client:
    def invoke(self, fn, args, send=None):
        cmd = build_cmd(fn, args, send)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    def create(self, amount):
        return self.invoke("create", [("amount", str(amount))])


def build_cmd(fn, args, send=None):
    cmd = ["stellar", "contract", "invoke", "--id", "C", "--network", "testnet"]
    if send:
        cmd += ["--send", send]
    return cmd + ["--", fn]
'''


def test_a_claim_released_after_a_cli_submission_fails_is_reported():
    flow = '''from escrow.chain import Client

def execute(repo, client: Client, intent_id, amount):
    if not repo.claim_escrow(intent_id):
        return None
    try:
        result = client.create(amount)
    except Exception:
        repo.release_escrow_claim(intent_id)
        raise
    return result
'''
    found = hardening({"escrow/chain.py": PY_CLI, "escrow/flow.py": flow})
    assert found[RETRY].severity.value == "medium" and "escrow/flow.py:8" in found[RETRY].evidence
    # Typed as a Protocol: its stub stands for the classes that implement the method.
    protocol = "from typing import Protocol\n\nclass Chain(Protocol):\n    def create(self, amount): ...\n"
    typed = flow.replace("from escrow.chain import Client", "from escrow.port import Chain").replace("client: Client", "client: Chain")
    assert RETRY in hardening({"escrow/chain.py": PY_CLI, "escrow/port.py": protocol, "escrow/flow.py": typed})
    # An unknown receiver is not resolved by method name: `client.create` could be anything.
    untyped = flow.replace("client: Client", "client")
    assert RETRY not in hardening({"escrow/chain.py": PY_CLI, "escrow/flow.py": untyped})


def test_a_method_name_shared_with_a_submitting_class_is_not_a_submission():
    limits = '''import sqlite3

class SpendLimits:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)

    def reserve(self, amount):
        cur = self.conn.cursor()
        try:
            cur.execute("UPDATE budget SET reserved = reserved + ?", (amount,))
            self.conn.commit()
        except Exception:
            self.release_budget(amount)
            raise

    def release_budget(self, amount):
        self.conn.execute("UPDATE budget SET reserved = reserved - ?", (amount,))
'''
    submitter = '''from stellar_sdk import Server

class Submitter:
    def __init__(self, url):
        self.server = Server(url)

    def execute(self, envelope):
        return self.server.submit_transaction(envelope)
'''
    assert RETRY not in hardening({"agent/limits.py": limits, "agent/submitter.py": submitter})
    # The same release around a call that does reach the submitting class is reported.
    owned = limits.replace("import sqlite3\n", "import sqlite3\nfrom agent.submitter import Submitter\n") \
        .replace("        self.conn = sqlite3.connect(path)\n", "        self.conn = sqlite3.connect(path)\n        self.chain = Submitter(URL)\n") \
        .replace("            cur.execute(\"UPDATE budget SET reserved = reserved + ?\", (amount,))\n",
                 "            self.chain.execute(envelope)\n")
    assert RETRY in hardening({"agent/limits.py": owned, "agent/submitter.py": submitter})
    ts_limits = TS_HEAD + '''export class Limits {
  async reserve(db: any, amount: string) {
    try {
      await db.execute("UPDATE budget SET reserved = reserved + ?", [amount]);
    } catch (e) {
      await this.releaseBudget(amount);
      throw e;
    }
  }
  async releaseBudget(amount: string) {}
}
'''
    ts_submitter = TS_HEAD + "export class Submitter {\n  async execute(tx: any) { return server.sendTransaction(tx); }\n}\n"
    assert RETRY not in hardening({"src/limits.ts": ts_limits, "src/submitter.ts": ts_submitter})
    ts_owned = ts_limits.replace("async reserve(db: any, amount: string)", "async reserve(db: Submitter, amount: string)")
    assert RETRY in hardening({"src/limits.ts": ts_owned, "src/submitter.ts": ts_submitter})


def test_a_release_only_for_errors_raised_before_the_send_is_not_reported():
    flow = '''def execute(repo, client, intent_id, amount):
    try:
        result = client.create(amount)
    except (ValueError, KeyError):
        repo.release_escrow_claim(intent_id)
        raise
    return result
'''
    assert RETRY not in hardening({"escrow/chain.py": PY_CLI, "escrow/flow.py": flow})


def test_js_reservation_released_after_an_rpc_send_is_reported_and_a_transmitted_flag_is_not():
    vulnerable = TS_HEAD + '''export async function pay(tx: any, reservationId: string) {
  try {
    const r = await server.sendTransaction(tx);
    return await server.pollTransaction(r.hash);
  } catch (err) {
    await budget.releaseReservation(reservationId);
    throw err;
  }
}
'''
    assert RETRY in hardening({"src/pay.ts": vulnerable})
    flagged = TS_HEAD + '''export async function pay(tx: any, reservationId: string) {
  let transmitted = false;
  try {
    transmitted = true;
    const r = await server.sendTransaction(tx);
    return r.hash;
  } catch (err) {
    if (!transmitted) await budget.releaseReservation(reservationId);
    throw err;
  }
}
'''
    assert RETRY not in hardening({"src/pay.ts": flagged})


def test_a_paid_request_repeated_by_an_attempt_loop_is_reported():
    source = '''import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
function payingFetch() {
  return wrapFetchWithPaymentFromConfig(fetch, { schemes: [] });
}
export async function call(url: string) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const paid = payingFetch();
    try {
      const res = await paid(url);
      if (!res.ok) throw new Error(String(res.status));
      return await res.json();
    } catch (err) {
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
}
'''
    assert RETRY in hardening({"src/client.ts": source})
    once = source.replace("await new Promise((r) => setTimeout(r, 1000 * attempt));", "throw err;")
    assert RETRY not in hardening({"src/client.ts": once})


# ----------------------------------------------------------------------------- K9 (never expires)
def test_python_transaction_built_and_signed_without_time_bounds_is_low():
    source = '''from stellar_sdk import Keypair, Server, TransactionBuilder, Network
def submit(horizon, kp, ops):
    account = horizon.load_account(kp.public_key)
    builder = TransactionBuilder(source_account=account, network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE, base_fee=100)
    for op in ops:
        op(builder)
    tx = builder.build()
    tx.sign(kp)
    return horizon.submit_transaction(tx)
'''
    found = hardening({"tools.py": source})
    assert found[EXPIRY].severity.value == "low"
    timed = source.replace("tx = builder.build()", "tx = builder.set_timeout(60).build()")
    assert EXPIRY not in hardening({"tools.py": timed})
    chained = source.replace("tx = builder.build()", "tx = builder.add_time_bounds(0, 0).build()")
    assert EXPIRY in hardening({"tools.py": chained})  # explicit infinite bounds: the existing medium rule


# ----------------------------------------------------------------------------- K6 (BigInt to JSON)
def test_contract_result_serialised_without_a_bigint_replacer_is_reported():
    source = '''import { scValToNative } from "@stellar/stellar-sdk";
export function render(value: any) {
  const parsed = scValToNative(value);
  return JSON.stringify(parsed);
}
'''
    assert native({"src/render.ts": source}, npm())["stellar_native-bigint-to-json"].severity.value == "low"
    replacer = source.replace("JSON.stringify(parsed)", 'JSON.stringify(parsed, (_k, v) => (typeof v === "bigint" ? v.toString() : v))')
    assert "stellar_native-bigint-to-json" not in native({"src/render.ts": replacer}, npm())
    patched = source + "(BigInt.prototype as any).toJSON = function () { return this.toString(); };\n"
    assert "stellar_native-bigint-to-json" not in native({"src/render.ts": patched}, npm())


# ----------------------------------------------------------------------------- review near misses
def test_a_send_wrapped_in_a_helper_that_polls_is_not_reported():
    source = TS_HEAD + '''async function waitForConfirmation(p: Promise<any>) {
  const r = await p;
  return server.pollTransaction(r.hash);
}
export async function pay(order: string, tx: any) {
  const res = await waitForConfirmation(server.sendTransaction(tx));
  if (res.status === "SUCCESS") await markPaid(order, res.txHash);
}
'''
    assert FINAL not in native({"src/pay.ts": source}, npm())
    library = source.replace("waitForConfirmation(server", "waitForTx(server")
    assert FINAL not in native({"src/pay.ts": library}, npm())  # a library wrapper named for waiting: unknown
    labelled = source.replace("waitForConfirmation(server.sendTransaction(tx))", 'runRpc(server.sendTransaction(tx), "pay")') \
        + 'async function runRpc(p: Promise<any>, label: string) { return await p; }\n'
    assert native({"src/pay.ts": labelled}, npm())[FINAL].severity.value == "medium"


def test_a_hash_recorded_as_pending_is_not_reported():
    source = TS_HEAD + '''export async function pay(order: string, tx: any) {
  const sent = await server.sendTransaction(tx);
  await db.payments.insert({ order, hash: sent.hash, status: "pending" });
}
'''
    assert FINAL not in native({"src/pay.ts": source}, npm())
    settled = source.replace('status: "pending"', 'status: "paid"')
    assert native({"src/pay.ts": settled}, npm())[FINAL].severity.value == "medium"


def test_sends_mapped_in_a_batch_and_polled_afterwards_are_not_reported():
    source = TS_HEAD + '''export async function payAll(txs: any[]) {
  const sent = await Promise.all(txs.map(async (tx) => {
    return server.sendTransaction(tx);
  }));
  for (const s of sent) {
    await server.pollTransaction(s.hash);
  }
  return sent;
}
'''
    assert FINAL not in native({"src/batch.ts": source}, npm())


def test_a_polling_flag_followed_by_a_success_check_is_not_reported():
    flag = TS_HEAD + '''export async function wait(hash: string) {
  for (let i = 0; i < 10; i++) {
    const r = await server.getTransaction(hash);
    const finished = r.status !== rpc.Api.GetTransactionStatus.NOT_FOUND;
    if (finished) {
      if (r.status !== rpc.Api.GetTransactionStatus.SUCCESS) throw new Error("failed");
      return r;
    }
  }
  throw new Error("timeout");
}
'''
    pair = TS_HEAD + '''export async function check(hash: string) {
  const r = await server.getTransaction(hash);
  return { done: r.status !== "NOT_FOUND", ok: r.status === "SUCCESS" };
}
'''
    found = native({"src/wait.ts": flag, "src/check.ts": pair}, npm())
    assert "stellar_native-rpc-outcome-not-success-checked" not in found
    verdict = pair.replace('ok: r.status === "SUCCESS"', 'paid: r.status !== "FAILED"')
    assert "stellar_native-rpc-outcome-not-success-checked" in native({"src/check.ts": verdict}, npm())


def test_a_transmitted_flag_on_an_object_or_an_exception_type_test_guards_the_release():
    field = TS_HEAD + '''export class Payer {
  private transmitted = false;
  async pay(tx: any, reservation: string) {
    try {
      this.transmitted = true;
      await server.sendTransaction(tx);
    } catch (e) {
      if (!this.transmitted) await this.budget.release(reservation);
      throw e;
    }
  }
}
'''
    ctx = TS_HEAD + '''export async function pay(state: any, tx: any) {
  const ctx = { sent: false };
  try {
    ctx.sent = true;
    await server.sendTransaction(tx);
  } catch (e) {
    if (!ctx.sent) await releaseReservation(state.reservation);
    throw e;
  }
}
'''
    py = PY_HEAD + '''class BeforeBroadcast(Exception):
    pass

def pay(repo, tx, claim):
    try:
        soroban.send_transaction(tx)
    except Exception as e:
        if isinstance(e, BeforeBroadcast):
            repo.release_claim(claim)
        raise
'''
    assert RETRY not in hardening({"src/payer.ts": field, "src/ctx.ts": ctx, "agent.py": py})
    unguarded = py.replace("        if isinstance(e, BeforeBroadcast):\n            repo.release_claim(claim)",
                           "        repo.release_claim(claim)")
    assert RETRY in hardening({"agent.py": unguarded})


def test_a_builder_handed_to_a_helper_module_that_sets_the_timeout_is_not_reported():
    agent = '''from stellar_sdk import TransactionBuilder, Keypair
from helpers import add_ops

def pay(server, kp, account):
    builder = TransactionBuilder(account, "Test", base_fee=100)
    add_ops(builder)
    tx = builder.build()
    tx.sign(kp)
    return server.submit_transaction(tx)
'''
    helpers = 'def add_ops(builder):\n    builder.set_timeout(30)\n    builder.append_payment_op("G", "1")\n'
    assert EXPIRY not in hardening({"agent.py": agent, "helpers.py": helpers})
    assert EXPIRY in hardening({"agent.py": agent, "helpers.py": helpers.replace("    builder.set_timeout(30)\n", "")})


def test_low_rule_near_misses_are_not_reported():
    converted = '''import { scValToNative } from "@stellar/stellar-sdk";
export function show(x: any) { const n = scValToNative(x); return JSON.stringify({ n: String(n), m: n.toString() }); }
'''
    stripe = 'export function f() { return stripe.payment({ amount: "99999999999999999999" }); }\n'
    typed = 'import type { SorobanRpc } from "@stellar/stellar-sdk";\n' \
            'export function f(x: SorobanRpc.Api.GetTransactionResponse) { return x; }\n'
    found = native({"src/show.ts": converted, "src/stripe.ts": stripe, "src/types.ts": typed}, npm())
    assert not {"stellar_native-bigint-to-json", "stellar_native-amount-above-int64", "stellar_native-sdk-removed-symbol"} & set(found)
    py = 'import stripe\ndef charge():\n    return stripe.Charge.create(amount="99999999999999999999")\n'
    assert "stellar_native-amount-above-int64" not in native({"billing.py": py + "import stellar_sdk\n"}, pypi())


def test_every_sdk_finding_names_the_resolved_release():
    weak = TS_HEAD + '''export async function settled(hash: string) {
  const r = await server.getTransaction(hash);
  return { success: r.status !== "FAILED" };
}
'''
    found = native({"src/check.ts": weak}, npm())
    assert "@stellar/stellar-sdk 14.6.1" in found["stellar_native-rpc-outcome-not-success-checked"].evidence


def test_the_source_index_is_shared_by_copies_of_the_same_files():
    from backend.app.swarm.source_index import index_for
    files = {"src/a.ts": TS_HEAD}
    assert index_for(files) is index_for(dict(files))
    assert index_for({"src/a.ts": TS_HEAD + "\n"}) is not index_for(files)


def test_sdk_rules_skip_python_too_complex_to_parse():
    # CPython raises MemoryError ("parser stack overflowed") for `a{{{...`, not SyntaxError.
    deep = "x = a" + "{" * 3000 + "\n"
    assert native({"agent.py": deep, "src/a.ts": TS_HEAD}, npm()) == {}
