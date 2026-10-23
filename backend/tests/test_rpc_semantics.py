"""Stellar SDK semantics: RPC results read as final or misread, string durabilities, removed
symbols, v3-only transaction meta, oversized amounts, skipped memo checks, payments released
after a broadcast and transactions with no time bounds. Each rule has a vulnerable fixture
and a safe near miss; SDK versions come from a synthetic lockfile record."""

from __future__ import annotations

import time

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


def test_a_status_handed_on_next_to_a_paid_write_or_a_success_label_is_still_reported():
    checkout = TS_HEAD + '''export async function checkout(orderId: string, tx: any) {
  const sent = await server.sendTransaction(tx);
  console.log("send status", sent.status);
  await db.orders.update({ id: orderId, paid: true, hash: sent.hash });
}
'''
    # Logging the status does not undo the write that marks the order paid.
    assert native({"src/checkout.ts": checkout}, npm())[FINAL].severity.value == "medium"
    returned = checkout.replace('  console.log("send status", sent.status);\n', "").replace(
        "hash: sent.hash });\n", "hash: sent.hash });\n  return { status: sent.status };\n")
    assert native({"src/checkout.ts": returned}, npm())[FINAL].severity.value == "medium"
    # A tool that hands back the status but calls the outcome a success is not the decided case.
    tool = TS_HEAD + '''server2.registerTool("invoke", {}, async (args: any) => {
  const submission = await server.sendTransaction(args.tx);
  return { success: true, status: "confirmed", rpcStatus: submission.status, hash: submission.hash };
});
'''
    assert native({"src/tools.ts": tool}, npm())[FINAL].severity.value == "low"
    labelled = tool.replace('success: true, status: "confirmed", rpcStatus', "status")
    assert FINAL not in native({"src/tools.ts": labelled}, npm())
    # A status logged, or returned on another branch, does not hide a return that says confirmed.
    mcp = TS_HEAD + "server2.tool('submit', {}, async (args: any) => {\n" \
                    "  const r = await server.sendTransaction(args.tx);\n  BODY\n});\n"
    for body in ("console.log('sent', r.status);\n  return { content: [{ type: 'text', text: `Payment confirmed: ${r.hash}` }] };",
                 "if (r.status !== 'PENDING') return { content: [{ type: 'text', text: JSON.stringify({ status: r.status }) }] };\n"
                 "  return { content: [{ type: 'text', text: 'Payment complete: ' + r.hash }] };"):
        assert native({"src/tools.ts": mcp.replace("BODY", body)}, npm())[FINAL].severity.value == "low", body
    # An instruction or an error next to the status is not a claim that the outcome is final.
    for extra in ("next: 'Call get_transaction with this hash to confirm the result'",
                  "error: r.errorResult ? 'Transaction failed to complete' : null",
                  "note: r.status === 'ERROR' ? 'Payment was not successful' : ''"):
        body = "return { content: [{ type: 'text', text: JSON.stringify({ status: r.status, hash: r.hash, " + extra + " }) }] };"
        assert FINAL not in native({"src/tools.ts": mcp.replace("BODY", body)}, npm()), extra


def test_rpc_clients_from_the_rpc_entry_point_a_destructured_class_or_a_factory_are_rpc_sends():
    body = '''export async function checkout(order: string, tx: any) {
  const r = await SEND(tx);
  await markPaid(order, r.hash);
}
'''
    heads = {
        "server": 'import { Server } from "@stellar/stellar-sdk/rpc";\nconst server = new Server(process.env.RPC_URL!);\n',
        "client": 'import { rpc } from "@stellar/stellar-sdk";\nconst { Server: RpcServer } = rpc;\n'
                  'const client = new RpcServer(process.env.RPC_URL!);\n',
        "rpcServer": 'import { rpc } from "@stellar/stellar-sdk";\n'
                     'function getRpc() { return new rpc.Server(process.env.RPC_URL!); }\nconst rpcServer = getRpc();\n',
        "chain": 'import { rpc } from "@stellar/stellar-sdk";\n'
                 'async function connect(url: string): Promise<rpc.Server> { return makeIt(url); }\nconst chain = await connect(URL);\n',
    }
    for name, head in heads.items():
        assert native({"src/pay.ts": head + body.replace("SEND", f"{name}.sendTransaction")}, npm())[FINAL].severity.value == "medium", name
    # A factory of something else, or a `Server` from another package, is not one.
    other = 'import { Server } from "./mock";\nimport { Keypair } from "@stellar/stellar-sdk";\nconst server = new Server(URL);\n'
    assert FINAL not in native({"src/pay.ts": other + body.replace("SEND", "server.sendTransaction")}, npm())
    horizon = 'import { Horizon } from "@stellar/stellar-sdk";\nfunction getRpc() { return new Horizon.Server(URL); }\n' \
              'const rpcServer = getRpc();\n'
    assert FINAL not in native({"src/pay.ts": horizon + body.replace("SEND", "rpcServer.sendTransaction")}, npm())
    # A factory method called on `this`.
    payer = '''import { rpc } from "@stellar/stellar-sdk";
export class Payer {
  private rpc: any;
  private makeRpc() { return new rpc.Server(process.env.RPC_URL!); }
  async init() { this.rpc = await this.makeRpc(); }
  async checkout(order: string, tx: any) {
    const r = await this.rpc.sendTransaction(tx);
    await markPaid(order, r.hash);
  }
}
'''
    assert native({"src/pay.ts": payer}, npm())[FINAL].severity.value == "medium"


def test_k1_costs_grow_with_the_sends_not_with_sends_times_function_size():
    started = time.perf_counter()
    sends = TS_HEAD + "export async function s(tx: any) {\n" + "".join(
        f"  const r{i} = await server.sendTransaction(tx);\n  console.log(r{i}.status);\n  await markPaid(r{i}.hash);\n"
        for i in range(1500)) + "}\n"
    assert native({"src/a.ts": sends}, npm())[FINAL].severity.value == "medium"
    # Many distinct receivers: the project's client bindings are read once, not once per name.
    receivers = TS_HEAD + "".join(f"export async function s{i}(tx: any) {{ const r = await rpc{i}.sendTransaction(tx); "
                                  f"await markPaid(r.hash); }}\n" for i in range(3000))
    assert FINAL not in native({f"src/m{k}.ts": receivers.replace("function s", f"function s{k}_") for k in range(3)}, npm())
    # One name reused by every send, and a getTransaction per send: still one walk per function.
    reused = TS_HEAD + "export async function s(tx: any) {\n  let r: any;\n" + "".join(
        "  r = await server.sendTransaction(tx);\n  await markPaid(r.hash);\n"
        "  const g = await server.getTransaction(r.hash);\n  if (g.status !== 'FAILED') ok();\n" for _ in range(1500)) + "}\n"
    native({"src/r.ts": reused}, npm())
    assert time.perf_counter() - started < 10


def test_k1_costs_stay_linear_in_nested_functions():
    # Each nested function sends, marks paid, calls the next one with the result, or reads a
    # getTransaction status under one shared name. Uses, callers, polling callees and status
    # tests are read from per-file indexes, and no tree-sitter parent lookup (whose cost is the
    # node's depth) runs per send: 1,500 levels took minutes before.
    depth = 1500
    started = time.perf_counter()
    nested = TS_HEAD + "".join(f"async function g{i}(tx: any) {{ const r{i} = await server.sendTransaction(tx); "
                               f"await markPaid(r{i}.hash);\n" for i in range(depth)) + "}\n" * depth
    assert native({"src/a.ts": nested}, npm())[FINAL].severity.value == "medium"
    calls = TS_HEAD + "".join(f"async function g{i}(tx: any) {{ const r{i} = await server.sendTransaction(tx); "
                              f"await g{i + 1}(r{i}.hash);\n" for i in range(depth)) + "}\n" * depth
    assert FINAL not in native({"src/b.ts": calls}, npm())
    statuses = TS_HEAD + "".join(f"async function g{i}(h: any) {{ const r = await server.getTransaction(h); "
                                 f"const ok{i} = r.status !== 'FAILED';\n" for i in range(depth)) + "}\n" * depth
    assert "stellar_native-rpc-outcome-not-success-checked" in native({"src/c.ts": statuses}, npm())
    assert time.perf_counter() - started < 10


def test_k1b_judges_a_status_test_against_the_binding_it_reads():
    # The inner function binds its own `r` and compares it with SUCCESS; the outer test reads
    # the outer `r`, which nothing compares with SUCCESS.
    source = TS_HEAD + '''export async function outer(h: string) {
  const r = await server.getTransaction(h);
  const done = r.status !== "FAILED";
  async function inner(k: string) {
    const r = await server.getTransaction(k);
    const landed = r.status !== "FAILED";
    if (r.status === "SUCCESS") return landed;
  }
  return done;
}
'''
    found = native({"src/c.ts": source}, npm())["stellar_native-rpc-outcome-not-success-checked"]
    assert "src/c.ts:5" in found.evidence and "src/c.ts:8" not in found.evidence


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
    # A name bound to an RPC client in one file and to an EVM provider in another: in the second
    # file its own binding wins.
    stellar = 'import { rpc } from "@stellar/stellar-sdk";\nexport const client = new rpc.Server(process.env.RPC_URL!);\n'
    multichain = '''import { ethers } from "ethers";
import { Keypair } from "@stellar/stellar-sdk";
const client = new ethers.JsonRpcProvider(URL);
export async function payEvm(order: string, tx: any) {
  const r = await client.sendTransaction(tx);
  await markPaid(order, r.hash);
}
'''
    assert FINAL not in native({"src/stellar.ts": stellar, "src/evm.ts": multichain}, npm())
    same = multichain.replace("new ethers.JsonRpcProvider(URL)", "new rpc.Server(URL)").replace(
        'import { Keypair } from "@stellar/stellar-sdk";', 'import { Keypair, rpc } from "@stellar/stellar-sdk";')
    assert native({"src/stellar.ts": stellar, "src/evm.ts": same}, npm())[FINAL].severity.value == "medium"


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
    # Typed as a Protocol: its stub stands for the classes the project builds where the
    # Protocol is expected (a factory, an annotated name, an argument) or that subclass it.
    protocol = "from typing import Protocol\n\nclass Chain(Protocol):\n    def create(self, amount): ...\n"
    typed = flow.replace("from escrow.chain import Client", "from escrow.port import Chain").replace("client: Client", "client: Chain")
    for wiring in ("from escrow.chain import Client\n\ndef make_chain() -> Chain:\n    return Client()\n",
                   "from escrow.chain import Client\n\ndef make_chain():\n    chain: Chain = Client()\n    return chain\n",
                   "from escrow.chain import Client\nfrom escrow.flow import execute\n\ndef main(repo):\n"
                   "    client = Client()\n    return execute(repo, client, 'i1', 5)\n"):
        files = {"escrow/chain.py": PY_CLI, "escrow/port.py": protocol, "escrow/flow.py": typed, "escrow/main.py": wiring}
        assert RETRY in hardening(files), wiring
    subclass = PY_CLI.replace("import subprocess\n", "import subprocess\nfrom escrow.port import Chain\n").replace("class Client:", "class Client(Chain):")
    assert RETRY in hardening({"escrow/chain.py": subclass, "escrow/port.py": protocol, "escrow/flow.py": typed})
    # A class that only shares the method name does not stand for the Protocol.
    assert RETRY not in hardening({"escrow/chain.py": PY_CLI, "escrow/port.py": protocol, "escrow/flow.py": typed})
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
    # A database cursor typed as a Protocol with an `execute` stub stands for no submitting class.
    cursor = '''from typing import Protocol


class Cursor(Protocol):
    def execute(self, sql: str): ...


class Budget:
    def charge(self, cur: Cursor, amount):
        self.reserve_budget(amount)
        try:
            cur.execute("UPDATE budget SET spent = spent + 1")
        except Exception:
            self.release_budget(amount)
            raise
'''
    assert RETRY not in hardening({"agent/limits.py": cursor, "agent/submitter.py": submitter})
    # The same Protocol does stand for the submitting class once the project passes one for it.
    wired = cursor + "\n\ndef run(budget: Budget, url):\n    budget.charge(Submitter(url), 5)\n"
    wired = "from agent.submitter import Submitter\n" + wired
    assert RETRY in hardening({"agent/limits.py": wired, "agent/submitter.py": submitter})


def test_a_protocol_parameter_stands_only_for_classes_passed_to_its_own_function():
    # The submitting class is passed to another function or method that only shares the name
    # (and the parameter position or keyword) of the one whose parameter is typed as the
    # Protocol: the database cursor still stands for no submitting class.
    chain = '''from stellar_sdk import Server

class Submitter:
    def __init__(self):
        self.server = Server("https://horizon-testnet.stellar.org")

    def execute(self, envelope):
        return self.server.submit_transaction(envelope)
'''
    limits = '''from typing import Protocol


class Cursor(Protocol):
    def execute(self, sql: str): ...


class Budget:
    def charge(self, cur: Cursor, amount):
        self.reserve_budget(amount)
        try:
            cur.execute("UPDATE budget SET spent = spent + 1")
        except Exception:
            self.release_budget(amount)
            raise


def settle(cur: Cursor, amount):
    reserve_budget(amount)
    try:
        cur.execute("UPDATE budget SET spent = spent + 1")
    except Exception:
        release_budget(amount)
        raise
'''
    wallet = "\n\nclass Wallet:\n    def charge(self, submitter: Submitter, amount):\n        return submitter.execute(amount)\n"
    for wiring in (wallet + "\n\ndef run(wallet: Wallet):\n    wallet.charge(Submitter(), 5)\n",
                   wallet + "\n\ndef run(wallet: Wallet):\n    s = Submitter()\n    wallet.charge(s, 5)\n",
                   wallet.replace("submitter", "cur") + "\n\ndef run(wallet: Wallet):\n    wallet.charge(cur=Submitter(), amount=5)\n",
                   wallet + "\n\ndef run(wallet):\n    wallet.charge(Submitter(), 5)\n",  # receiver unknown
                   wallet + "\n    def run(self):\n        self.charge(Submitter(), 5)\n",
                   "\n\ndef settle(sub: Submitter, amount):\n    return sub.execute(amount)\n\n\ndef run():\n    settle(Submitter(), 5)\n",
                   # Two classes named Budget: the call may run either, so it says nothing.
                   wallet.replace("Wallet", "Budget") + "\n\ndef run():\n    Budget().charge(Submitter(), 5)\n"):
        assert RETRY not in hardening({"agent/chain.py": chain + wiring, "agent/limits.py": limits}), wiring
    # Passed to the function whose parameter is typed as the Protocol, through a call that
    # resolves to it, the submitting class does stand for the Protocol.
    for wiring in ("\nfrom agent.limits import Budget\n\ndef run():\n    s = Submitter()\n    Budget().charge(s, 5)\n",
                   "\nfrom agent.limits import Budget\n\ndef run(budget: Budget):\n    budget.charge(cur=Submitter(), amount=5)\n",
                   "\nfrom agent.limits import settle\n\ndef run():\n    settle(Submitter(), 5)\n",
                   "\nfrom agent import limits\n\ndef settle(sub: Submitter):\n    return sub\n\n\n"
                   "def run():\n    limits.settle(Submitter(), 5)\n"):
        assert hardening({"agent/chain.py": chain + wiring, "agent/limits.py": limits})[RETRY].severity.value == "medium", wiring


def test_k3_passed_classes_resolve_each_file_imports_once():
    # Every call that passes a project class is resolved through its receiver once a Protocol
    # is in play; the receiver's imports come from one index per file, not one scan of the
    # module body per receiver name (3,000 receivers over 20,000 statements took 9 s).
    started = time.perf_counter()
    body = "from typing import Protocol\nclass P(Protocol):\n    def go(self, tx): ...\n" + \
        "".join(f"v{i} = {i}\n" for i in range(20000)) + \
        "class C:\n    def take(self, p, tx):\n        return p\n\nclass D:\n    pass\n\ndef wire(tx):\n" + \
        "".join(f"    c{i}.take(D(), tx)\n" for i in range(3000)) + \
        "def run(c: P, tx):\n    try:\n        return c.go(tx)\n    except Exception:\n        release(tx)\n        raise\n"
    assert RETRY not in hardening({"agent/a.py": "from stellar_sdk import Server\n" + body})
    assert time.perf_counter() - started < 6


def test_a_release_around_a_module_instance_an_inline_client_or_a_dotted_module_call_is_reported():
    chain = '''from stellar_sdk import Server

class StellarClient:
    def __init__(self, url="https://horizon-testnet.stellar.org"):
        self.server = Server(url)

    def pay(self, envelope):
        return self.server.submit_transaction(envelope)

def submit_payment(envelope):
    return Server("https://horizon-testnet.stellar.org").submit_transaction(envelope)

client = StellarClient()
'''
    flow = '''HEAD
def execute(budget, intent_id, envelope, amount):
    budget.reserve(intent_id, amount)
    try:
        return CALL
    except Exception:
        budget.release(intent_id, amount)
        raise
'''
    for head, call in (("from agent.chain import client", "client.pay(envelope)"),
                       ("from agent.chain import StellarClient", "StellarClient().pay(envelope)"),
                       ("import agent.chain", "agent.chain.submit_payment(envelope)")):
        files = {"agent/chain.py": chain, "agent/flow.py": flow.replace("HEAD", head).replace("CALL", call)}
        assert hardening(files)[RETRY].severity.value == "medium", call
    # An instance of a class that does not submit is not a send.
    quiet = chain.replace("client = StellarClient()", "class Ledger:\n    def pay(self, envelope):\n        return envelope\n\n"
                                                      "client = Ledger()")
    files = {"agent/chain.py": quiet, "agent/flow.py": flow.replace("HEAD", "from agent.chain import client")
             .replace("CALL", "client.pay(envelope)")}
    assert RETRY not in hardening(files)
    service = TS_HEAD + '''export class StellarService {
  async pay(tx: any) { return server.sendTransaction(tx); }
}
export const stellarService = new StellarService();
'''
    ts_flow = '''HEAD
export async function execute(budget: any, id: string, tx: any) {
  await budget.reserve(id);
  try {
    return await CALL;
  } catch (e) {
    await budget.release(id);
    throw e;
  }
}
'''
    for head, call in (('import { stellarService } from "./chain";', "stellarService.pay(tx)"),
                       ('import { StellarService } from "./chain";', "new StellarService().pay(tx)")):
        files = {"src/chain.ts": service, "src/flow.ts": ts_flow.replace("HEAD", head).replace("CALL", call)}
        assert hardening(files)[RETRY].severity.value == "medium", call
    ledger = service.replace("return server.sendTransaction(tx);", "return tx;")
    files = {"src/chain.ts": ledger, "src/flow.ts": ts_flow.replace("HEAD", 'import { stellarService } from "./chain";')
             .replace("CALL", "stellarService.pay(tx)")}
    assert RETRY not in hardening(files)


def test_k3_resolution_reads_each_name_once_per_project():
    started = time.perf_counter()
    head = "from stellar_sdk import Server\n"
    files = {f"agent/m{k}.py": head + "".join(f"class I{k}_{i}:\n    def go(self, tx):\n        return I{k}_{(i + 1) % 1500}().go(tx)\n"
                                              for i in range(1500)) for k in range(3)}
    files["agent/run.py"] = head + '''from typing import Protocol

class P(Protocol):
    def go(self, tx): ...

def run(c: P, budget, tx):
    try:
        return c.go(tx)
    except Exception:
        budget.release_reserved(tx)
        raise
'''
    assert RETRY not in hardening(files)
    ts = TS_HEAD + "".join(f"class C{i} {{ async go(tx: any): Promise<any> {{ return new C{(i + 1) % 2500}().go(tx); }} }}\n"
                           for i in range(2500)) + '''export async function run(c: C0, budget: any, tx: any) {
  try { return await c.go(tx); } catch (e) { await budget.releaseReserved(tx); throw e; }
}
'''
    assert RETRY not in hardening({"src/a.ts": ts})
    assert time.perf_counter() - started < 15


def test_k3_receiver_classes_are_read_once_per_function_and_file():
    # One function with thousands of distinct receivers, each call in a try block that
    # releases: the receiver's class comes from one index per function (Python) or per file
    # (JavaScript), not one walk or two regex scans per name (2,000 receivers took 80 s).
    count = 3000
    started = time.perf_counter()
    py = "from stellar_sdk import Server\nclass C:\n    def go(self, tx):\n        return 1\n\ndef run(tx):\n" + "".join(
        f"    try:\n        c{i}.go(tx)\n    except Exception:\n        release(tx)\n        raise\n" for i in range(count))
    assert RETRY not in hardening({"agent/a.py": py})
    ts = TS_HEAD + "class C { go(tx: any) { return 1; } }\nexport async function run(tx: any) {\n" + "".join(
        f"  try {{ await c{i}.go(tx); }} catch (e) {{ await release(tx); throw e; }}\n" for i in range(count)) + "}\n"
    assert RETRY not in hardening({"src/a.ts": ts})
    paid = TS_HEAD + "export async function run(tx: any) {\n" + "".join(
        f"  try {{ await f{i}(tx); }} catch (e) {{ await release(tx); throw e; }}\n" for i in range(count)) + "}\n"
    assert RETRY not in hardening({"src/b.ts": paid})
    assert time.perf_counter() - started < 10
    # The receiver index still resolves a built and a typed receiver.
    service = TS_HEAD + "export class Payer { async go(tx: any) { return server.sendTransaction(tx); } }\n"
    for line in ("  const p = new Payer();\n", ""):
        flow = service + "export async function run(tx: any, q: Payer) {\n" + line + \
            f"  try {{ await {'p' if line else 'q'}.go(tx); }} catch (e) {{ await releaseBudget(tx); throw e; }}\n}}\n"
        assert RETRY in hardening({"src/c.ts": flow}), line


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
    # The flow analysis and the hardening rules skip it too: the audit goes on.
    from backend.app.swarm.codeflow import analyse_code
    assert "agent.py" in analyse_code({"agent.py": deep, "pay.py": "x = 1\n"}).unparsed
    assert isinstance(hardening({"agent.py": deep, "pay.py": "x = 1\n"}), dict)
