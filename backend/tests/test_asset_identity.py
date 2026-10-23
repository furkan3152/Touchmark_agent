"""Payment address and asset identity: invalid StrKey literals, MPP's broken mainnet SAC
constants, an account used as an x402 asset, a payee that falls back to the null account, a
missing issuer that becomes XLM, an amount the cap and the signer parse differently, and
received payments accepted by asset code alone. Each rule has a vulnerable fixture and a safe
near miss. Keys are generated per test."""

from __future__ import annotations

import time

from stellar_sdk import Keypair

from backend.app.models import AgentArtifact, SourceKind
from backend.app.stellar.canonical import USDC_ISSUER, USDC_SAC, strkey_valid
from backend.app.swarm.asset_rules import NULL_ACCOUNT
from backend.app.swarm.hardening import analyse_hardening


def rule(fid: str) -> str:
    head, _, tail = fid.rpartition("-")
    return head if len(tail) == 8 and all(c in "0123456789abcdef" for c in tail) else fid


def hardening(files: dict, resolved: dict | None = None) -> dict:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files,
                             raw_metadata={"resolved_versions": resolved or {}})
    return {rule(f.id): f for f in analyse_hardening(artifact, "security")}


def lock(package: str, version: str) -> dict:
    return {"importers": {"": {"lockfiles": ["package-lock.json"],
                               "deps": {package: {"spec": f"^{version}", "version": version}}}},
            "locked": {"package-lock.json": {package: [version]}}}


def broken(value: str) -> str:
    """The same StrKey with its last character changed: a checksum failure."""
    bad = value[:-1] + ("A" if value[-1] != "A" else "B")
    assert not strkey_valid(bad)
    return bad


STRKEY = "security-strkey-invalid"
LOOKALIKE = USDC_SAC["testnet"][:-4] + "USDC" + "A"  # 57 characters, ends in USDC


# ----------------------------------------------------------------------------- A1
def test_a_look_alike_asset_default_used_in_requirements_is_low():
    # Low wherever it is used: the SDK rejects an invalid StrKey, so nothing is paid to it.
    config = f"export const config = {{\n  usdcToken:\n    process.env.USDC_TOKEN ||\n    '{LOOKALIKE}',\n}};\n"
    route = 'import { config } from "./config";\nexport const accepts = { scheme: "exact", asset: config.usdcToken, payTo: "x" };\n'
    found = hardening({"src/config.ts": config, "src/route.ts": route})
    assert found[STRKEY].severity.value == "low" and "57 characters" in found[STRKEY].evidence


def test_an_unused_exported_constant_with_a_bad_checksum_is_low():
    source = f"export const USDC_TESTNET_ID = '{broken(USDC_SAC['testnet'])}';\n"
    assert hardening({"src/constants.ts": source})[STRKEY].severity.value == "low"


def test_valid_network_keyed_maps_and_examples_are_not_reported():
    keyed = (f"const USDC: Record<string, string> = {{ 'stellar:pubnet': '{USDC_SAC['mainnet']}', "
             f"'stellar:testnet': '{USDC_SAC['testnet']}' }};\nexport const asset = USDC[process.env.NETWORK!];\n")
    example = f"export const schema = {{ examples: {{ input: {{ account_id: '{broken(Keypair.random().public_key)}' }} }} }};\n"
    jsx = f"export const Field = () => <input placeholder=\"{broken(Keypair.random().public_key)}\" />;\n"
    found = hardening({"src/assets.ts": keyed, "src/schemas.ts": example, "src/Field.tsx": jsx})
    assert STRKEY not in found


def test_rust_doc_comments_and_test_modules_are_not_reported():
    bad = broken(Keypair.random().public_key)
    source = (f"/// Example: `{bad}`\npub fn parse(s: &str) -> bool {{ s.len() == 56 }}\n"
              f"#[cfg(test)]\nmod tests {{\n    const ADDR: &str = \"{bad}\";\n}}\n")
    assert STRKEY not in hardening({"crates/wallet/src/lib.rs": source})
    live = f"pub const TREASURY: &str = \"{bad}\";\npub fn pay() -> &'static str {{ TREASURY }}\n"
    assert hardening({"crates/wallet/src/lib.rs": live})[STRKEY].severity.value == "low"


def test_rust_literals_in_comments_raw_strings_and_test_items_are_not_reported():
    good, bad = Keypair.random().public_key, broken(Keypair.random().public_key)
    trailing = f"pub const TREASURY: &str = \"{good}\"; // rotated from \"{bad}\" in May\npub fn t() -> &'static str {{ TREASURY }}\n"
    block = f"/*\n   old treasury:\n   \"{bad}\"\n*/\npub const T: &str = \"{good}\";\n"
    raw = f"pub const HELP: &str = r#\"usage: pay --to \"{bad}\"\"#;\n"
    cfg = (f"#[cfg(any(test, feature = \"testutils\"))]\npub mod fixtures {{\n    pub const ADDR: &str = \"{bad}\";\n}}\n"
           f"pub const T: &str = \"{good}\";\n")
    for name, source in (("trailing", trailing), ("block", block), ("raw", raw), ("cfg", cfg)):
        assert STRKEY not in hardening({"crates/wallet/src/lib.rs": source}), name
    # Code after a test module is still read.
    after = cfg + f"pub const PAYEE: &str = \"{bad}\";\n"
    assert "lib.rs:6" in hardening({"crates/wallet/src/lib.rs": after})[STRKEY].evidence


def test_placeholder_addresses_and_benchmark_suites_are_not_reported():
    stub = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234"
    assert not strkey_valid(stub)
    payload = f'export const payload = {{ destination: "{stub}", amount: "1" }};\nimport {{ Asset }} from "@stellar/stellar-sdk";\n'
    assert STRKEY not in hardening({"src/client.ts": payload})
    bad = broken(Keypair.random().public_key)
    suite = f'import {{ Asset }} from "@stellar/stellar-sdk";\nexport const payload = {{ destination: "{bad}" }};\n'
    assert STRKEY not in hardening({"web/src/area/devx/suites/sdk-client.ts": suite, "bench/pay.ts": suite})
    assert STRKEY in hardening({"src/client.ts": suite})


def test_python_docstrings_are_not_reported_and_constants_are():
    bad = broken(Keypair.random().public_key)
    doc = f'def pay(destination):\n    """Pay, e.g. destination="{bad}"."""\n    return destination\n'
    assert STRKEY not in hardening({"agent.py": doc})
    assert STRKEY in hardening({"agent.py": f'MERCHANT = "{bad}"\n'})


def test_mpp_mainnet_constant_import_on_a_broken_release_is_reported():
    source = 'import { USDC_SAC_MAINNET } from "@stellar/mpp";\nexport const currency = USDC_SAC_MAINNET;\n'
    found = hardening({"src/charge.ts": source}, lock("@stellar/mpp", "0.7.1"))
    assert found["security-sac-constant-invalid"].severity.value == "medium"
    testnet = source.replace("USDC_SAC_MAINNET", "USDC_SAC_TESTNET")
    assert "security-sac-constant-invalid" not in hardening({"src/charge.ts": testnet}, lock("@stellar/mpp", "0.7.1"))


# ----------------------------------------------------------------------------- A2
def test_an_account_as_the_x402_asset_is_low_and_a_contract_is_not():
    account = Keypair.random().public_key
    source = f"export const accepts = {{ scheme: 'exact', payTo: '{account}', asset: '{account}', amount: '100' }};\n"
    assert hardening({"src/route.ts": source})["security-payment-asset-is-account"].severity.value == "low"
    fixed = source.replace(f"asset: '{account}'", f"asset: '{USDC_SAC['testnet']}'")
    assert "security-payment-asset-is-account" not in hardening({"src/route.ts": fixed})


# ----------------------------------------------------------------------------- A3
NULL_PAYEE = "security-payee-defaults-to-null-account"


def test_a_payee_that_falls_back_to_the_null_account_is_reported():
    source = (f"const DEFAULT_SELLER_ADDRESS = '{NULL_ACCOUNT}';\n"
              "const sellerAddress = process.env.SELLER_ADDRESS ?? DEFAULT_SELLER_ADDRESS;\n"
              "export const routes = { '/paid': { accepts: { scheme: 'exact', payTo: sellerAddress, price: '0.01' } } };\n")
    assert hardening({"src/server.ts": source})[NULL_PAYEE].severity.value == "medium"
    py = f'import os\nPAY_TO = os.getenv("PAY_TO", "{NULL_ACCOUNT}")\n'
    assert NULL_PAYEE in hardening({"server.py": py})


def test_a_null_account_simulation_source_is_not_reported():
    source = (f"const SIM_SOURCE = '{NULL_ACCOUNT}';\n"
              "export const source = process.env.SIMULATION_SOURCE ?? SIM_SOURCE;\n")
    assert NULL_PAYEE not in hardening({"src/sim.ts": source})


# ----------------------------------------------------------------------------- A4
FALLBACK = "security-missing-issuer-pays-xlm"


PAY_WITH = ('export function pay(code: string, issuer: string | undefined, to: string, amount: string) {\n'
            '  return Operation.payment({ destination: to, asset: ASSET(code, issuer), amount });\n}\n')


def test_a_credit_code_without_issuer_becoming_xlm_is_reported():
    ts = ('import { Asset, Operation } from "@stellar/stellar-sdk";\n'
          'export function parseAsset(code: string, issuer?: string): Asset {\n'
          '  if (code === "XLM" || !issuer) {\n    return Asset.native();\n  }\n  return new Asset(code, issuer);\n}\n')
    assert hardening({"src/amm.ts": ts + PAY_WITH.replace("ASSET", "parseAsset")})[FALLBACK].severity.value == "medium"
    py = ('from stellar_sdk import Asset\n'
          'def to_asset(asset_code, asset_issuer=None):\n'
          '    if asset_code.upper() == "XLM" or asset_issuer is None:\n        return Asset.native()\n'
          '    return Asset(asset_code, asset_issuer)\n'
          'def sell(builder, code, issuer, amount, price):\n'
          '    selling = to_asset(code, issuer)\n'
          '    builder.append_manage_sell_offer_op(selling=selling, buying=Asset.native(), amount=amount, price=price)\n')
    assert FALLBACK in hardening({"tools.py": py})
    ternary = ('import { Asset, Operation } from "@stellar/stellar-sdk";\n'
               'export const toAsset = (p: any) => (p.asset_code && p.asset_issuer ? new Asset(p.asset_code, p.asset_issuer) : Asset.native());\n'
               'export const op = (p: any) => Operation.changeTrust({ asset: toAsset(p) });\n')
    assert FALLBACK in hardening({"src/build.ts": ternary})
    local = ('import { Asset, Operation } from "@stellar/stellar-sdk";\nfunction paymentOp(p: any) {\n  let asset: Asset;\n'
             '  if (p.asset_code && p.asset_issuer) {\n    asset = new Asset(p.asset_code, p.asset_issuer);\n  } else {\n'
             '    asset = Asset.native();\n  }\n  return Operation.payment({ destination: p.to, asset, amount: p.amount });\n}\n')
    assert FALLBACK in hardening({"src/build_transaction.ts": local})


def test_a_native_fallback_that_reaches_no_classic_operation_is_not_reported():
    # Contract arguments must be ScVal (an Asset makes the build throw) and a log pays nothing.
    ts = ('import { Asset, Operation } from "@stellar/stellar-sdk";\n'
          'function parseAsset(code: string, issuer?: string): Asset {\n'
          '  if (code === "XLM" || !issuer) return Asset.native();\n  return new Asset(code, issuer);\n}\n'
          'export function swap(input: any) {\n'
          '  return Operation.invokeContractFunction({ contract: input.pool, function: "swap",\n'
          '    args: [parseAsset(input.offer, input.offerIssuer), parseAsset(input.want, input.wantIssuer)] });\n}\n'
          'export function reserves(code: string, issuer?: string) {\n'
          '  const asset = parseAsset(code, issuer);\n  logger.debug({ asset: asset.getCode() }, "reading reserves");\n}\n')
    assert FALLBACK not in hardening({"src/amm.ts": ts})
    assert FALLBACK in hardening({"src/amm.ts": ts + PAY_WITH.replace("ASSET", "parseAsset")})
    unused = ('from stellar_sdk import Asset\ndef to_asset(code, issuer=None):\n'
              '    if issuer is None:\n        return Asset.native()\n    return Asset(code, issuer)\n')
    assert FALLBACK not in hardening({"assets.py": unused})


def test_native_only_for_xlm_with_a_missing_issuer_rejected_is_not_reported():
    ts = ('import { Asset } from "@stellar/stellar-sdk";\n'
          'export function parseAsset(code: string, issuer?: string): Asset {\n'
          '  if (code === "XLM") return Asset.native();\n'
          '  if (!issuer) throw new Error("issuer required");\n  return new Asset(code, issuer);\n}\n')
    assert FALLBACK not in hardening({"src/amm.ts": ts})
    both = ts.replace('if (code === "XLM") return Asset.native();', 'if (code === "XLM" && !issuer) return Asset.native();')
    assert FALLBACK not in hardening({"src/amm.ts": both})


# ----------------------------------------------------------------------------- A5
DUAL = "security-amount-parsed-two-ways"
PAYER = '''import { ExactStellarScheme } from "@x402/stellar/exact/client";
const PRICE_CAP = 0.5;
export async function pay(scheme: ExactStellarScheme, req: any) {
  if (parseFloat(req.amount) / 1e7 > PRICE_CAP) throw new Error("over cap");
  return scheme.createPaymentPayload(2, req);
}
'''


def test_a_cap_on_parse_float_and_a_payload_signed_from_the_string_is_high():
    found = hardening({"src/pay.ts": PAYER})
    assert found[DUAL].severity.value == "high"


def test_the_amount_validated_as_digits_first_is_not_reported():
    safe = PAYER.replace('  if (parseFloat', '  if (!/^\\d+$/.test(req.amount)) throw new Error("bad amount");\n  if (parseFloat')
    assert DUAL not in hardening({"src/pay.ts": safe})


def test_a_cap_and_a_signer_in_other_functions_are_followed():
    budget = ('export class Budget {\n  assertWithin(value: string): void {\n    const n = parseFloat(value);\n'
              '    if (n > this.limit) throw new Error("over budget");\n  }\n}\n')
    stroops = ('export function toStroops(v: string): string {\n  const [intPart] = v.split(".");\n'
               '  const head = intPart || "0";\n  return (BigInt(head) * 10000000n).toString();\n}\n')
    tool = ('import { toStroops } from "./stroops";\n'
            'server.tool("send", {}, async ({ value, to }: any) => {\n  budget.assertWithin(value);\n'
            '  return signTransfer({ amount: toStroops(value), to });\n});\n')
    found = hardening({"src/budget.ts": budget, "src/stroops.ts": stroops, "src/send.ts": tool})
    assert found[DUAL].severity.value == "high"
    # The cap reads a value already converted with BigInt: both sides agree.
    converted = tool.replace("budget.assertWithin(value)", "budget.assertWithin(fromStroops(BigInt(value)))")
    assert DUAL not in hardening({"src/budget.ts": budget, "src/stroops.ts": stroops, "src/send.ts": converted})


# ----------------------------------------------------------------------------- A6
CODE_ONLY = "security-asset-checked-by-code-only"


def test_a_code_fallback_or_ed_with_the_full_asset_is_reported():
    source = """export async function verifyReceipt(base: string, id: string, expected: string, payee: string) {
  const page = await (await fetch(`${base}/transactions/${id}/operations`)).json();
  return page._embedded.records.some((rec: any) => {
    const full = `${rec.asset_code}:${rec.asset_issuer}`;
    return rec.to === payee && (full === expected || rec.asset_code === expected);
  });
}
"""
    found = hardening({"src/receipts.ts": source})
    assert found[CODE_ONLY].severity.value == "medium"
    fixed = source.replace(" || rec.asset_code === expected", "")
    assert CODE_ONLY not in hardening({"src/receipts.ts": fixed})


def test_a_literal_code_check_without_issuer_is_high_and_balance_lookups_are_exempt():
    receipt = '''export async function confirmDeposit(horizon: any, hash: string) {
  const ops = await horizon.operations().forTransaction(hash).call();
  const p = ops.records.find((op: any) => op.type === "payment");
  if (!p || p.asset_code !== "USDC") throw new Error("unpaid");
  return p.amount;
}
'''
    assert hardening({"src/deposit.ts": receipt})[CODE_ONLY].severity.value == "high"
    issuer = receipt.replace('p.asset_code !== "USDC"', f'p.asset_code !== "USDC" || p.asset_issuer !== "{USDC_ISSUER["mainnet"]}"')
    assert CODE_ONLY not in hardening({"src/deposit.ts": issuer})
    balance = '''export async function getUsdcBalance(horizon: any, account: string) {
  const acct = await horizon.loadAccount(account);
  const verified = await horizon.payments().forAccount(account).call();
  return acct.balances.find((b: any) => b.asset_code === "USDC")?.balance ?? "0";
}
'''
    assert CODE_ONLY not in hardening({"src/balance.ts": balance})


def test_python_receipt_checked_by_code_is_reported():
    source = '''def verify_payment(server, tx_hash):
    for op in server.operations().for_transaction(tx_hash).call()["_embedded"]["records"]:
        if op["asset_code"] == "USDC":
            return True
    return False
'''
    assert hardening({"verify.py": source})[CODE_ONLY].severity.value == "high"
    fixed = source.replace('op["asset_code"] == "USDC"', 'op["asset_code"] == "USDC" and op["asset_issuer"] == ISSUER')
    assert CODE_ONLY not in hardening({"verify.py": fixed})


def test_code_only_receipts_and_queued_payments_count_as_payment_bypasses():
    from backend.app.models import Finding, Severity
    from backend.app.swarm.policy import payment_bypass

    def finding(fid: str) -> Finding:
        return Finding(id=fid, dimension="security", severity=Severity.MEDIUM, title="t", detail="d")
    assert payment_bypass(finding("security-asset-checked-by-code-only"))
    assert payment_bypass(finding("stellar_native-rpc-send-treated-as-final-1a2b3c4d"))
    assert not payment_bypass(finding("security-strkey-invalid-1a2b3c4d"))
    assert not payment_bypass(finding("security-sac-constant-invalid-1a2b3c4d"))


# ----------------------------------------------------------------------------- review near misses
def test_a_function_too_deep_to_unparse_does_not_stop_the_audit():
    """ast.parse accepts a 600-term `+` chain that ast.unparse cannot print (RecursionError)."""
    chain = " + ".join(['"="'] * 600)
    py = (f'from stellar_sdk import Asset\ndef banner():\n    return {chain}\n'
          f'def verify_payment(server, h):\n    banner_text = {chain}\n'
          '    for op in server.operations().for_transaction(h).call()["_embedded"]["records"]:\n'
          '        if op["asset_code"] == "USDC":\n            return True\n    return False\n'
          f'def to_asset(code, issuer=None):\n    if issuer is None or ({chain}) == code:\n        return Asset.native()\n'
          '    return Asset(code, issuer)\n')
    js_chain = " || ".join(f'code === "X{i}"' for i in range(1500))
    ts = (f'import {{ Asset }} from "@stellar/stellar-sdk";\nexport function a(code: string, issuer?: string) {{\n'
          f'  if ({js_chain} || !issuer) return Asset.native();\n  return new Asset(code, issuer);\n}}\n')
    found = hardening({"agent.py": py, "src/asset.ts": ts})
    assert found[CODE_ONLY].severity.value == "high"


def test_amount_positivity_checks_and_minimums_are_not_spending_caps():
    head = 'import { nativeToScVal } from "@stellar/stellar-sdk";\nexport async function pay(req: any) {\n  const amount = req.amount;\n'
    tail = '  return nativeToScVal(amount, { type: "i128" });\n}\n'
    for check in ('  if (isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) throw new Error("positive");\n',
                  '  if (!(parseFloat(amount) > 0)) throw new Error("bad");\n',
                  '  if (parseFloat(amount) < MIN_AMOUNT) throw new Error("too small");\n',
                  # A sound cap through Number (which parses hex as BigInt does), and parseFloat only warns.
                  '  if (Number(amount) > MAX) throw new Error("cap");\n  if (parseFloat(amount) > 50) console.warn("large");\n'):
        assert DUAL not in hardening({"src/pay.ts": head + check + tail}), check
    capped = head + '  if (parseFloat(amount) <= this.remaining) {\n    return nativeToScVal(amount, { type: "i128" });\n  }\n' \
                    '  throw new Error("over budget");\n}\n'
    assert hardening({"src/pay.ts": capped})[DUAL].severity.value == "high"


def test_a_dual_parse_in_an_example_drops_one_level():
    assert hardening({"examples/pay.ts": PAYER})[DUAL].severity.value == "medium"


def test_native_after_a_guard_that_rejects_credit_codes_without_issuer_is_not_reported():
    nested = ('import { Asset } from "@stellar/stellar-sdk";\nexport function toAsset(code: string, issuer?: string) {\n'
              '  if (!issuer) {\n    if (code.toUpperCase() !== "XLM") throw new Error("issuer required for " + code);\n'
              '    return Asset.native();\n  }\n  return new Asset(code, issuer);\n}\n')
    early = ('import { Asset } from "@stellar/stellar-sdk";\nexport function toAsset(code: string, issuer?: string) {\n'
             '  if (code !== "XLM" && !issuer) throw new Error("issuer required");\n'
             '  return !issuer ? Asset.native() : new Asset(code, issuer);\n}\n')
    py = ('from stellar_sdk import Asset\ndef to_asset(code, issuer=None):\n    if issuer is None:\n'
          '        if code != "XLM":\n            raise ValueError("issuer required")\n        return Asset.native()\n'
          '    return Asset(code, issuer)\n')
    assert FALLBACK not in hardening({"src/a.ts": nested, "src/b.ts": early, "assets.py": py})
    # A guard that does not cover a credit code without issuer leaves the fallback reported.
    weak = early.replace('if (code !== "XLM" && !issuer)', 'if (code === "")')
    assert FALLBACK in hardening({"src/b.ts": weak + PAY_WITH.replace("ASSET", "toAsset")})


def test_an_issuer_compared_in_a_helper_counts_and_get_code_fallbacks_are_reported():
    helper = """export async function verifyPayment(h: string, txHash: string, expected: any) {
  const ops = await (await fetch(`${h}/transactions/${txHash}/operations`)).json();
  for (const op of ops._embedded.records) {
    if (op.asset_code === expected.code && sameIssuer(op, expected)) return true;
  }
  return false;
}
function sameIssuer(op: any, expected: any) { return op["asset_issuer"] === expected["issuer"]; }
"""
    assert CODE_ONLY not in hardening({"src/verify.ts": helper})
    envelope = """export async function verifyEnvelope(h: string, txHash: string, expectedAsset: string) {
  const tx = await (await fetch(`${h}/transactions/${txHash}`)).json();
  for (const op of tx.operations) {
    const full = `${op.asset.getCode()}:${op.asset.getIssuer()}`;
    const ok = full === expectedAsset || (op.asset.getCode && op.asset.getCode() === expectedAsset);
    if (ok) return { verified: true };
  }
  return { verified: false };
}
"""
    assert hardening({"src/verify.ts": envelope})[CODE_ONLY].severity.value == "medium"


def test_a_payment_history_display_is_not_a_receipt_check():
    history = """export async function getRecentPayments(server: any, account: string) {
  const page = await server.payments().forAccount(account).order("desc").limit(20).call();
  return page.records
    .filter((r: any) => r.type === "payment" && r.asset_code === "USDC")
    .map((r: any) => ({ from: r.from, amount: r.amount, incoming: r.to === account }));
}
"""
    assert CODE_ONLY not in hardening({"src/tools/history.ts": history})


def test_base32_credentials_outside_stellar_code_are_not_strkeys():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBV"
    assert not strkey_valid(secret)
    source = (f"export const SESSION_TOKEN = '{secret}';\nexport const CACHE_KEY = 'C{secret[1:]}';\n"
              "export function f() { return SESSION_TOKEN + SESSION_TOKEN + CACHE_KEY; }\n")
    assert STRKEY not in hardening({"src/session.ts": source})


def test_null_payee_evidence_names_no_severity():
    py = f'import os\nPAY_TO = os.getenv("PAY_TO", "{NULL_ACCOUNT}")\n'
    assert "Severity" not in hardening({"server.py": py})[NULL_PAYEE].evidence


def test_a_cap_written_as_a_long_sum_neither_crashes_nor_hides_the_dual_parse():
    """A 1,500-term bound used to recurse once per term in _positive_literal (RecursionError)."""
    bound = "+".join(["1"] * 1500)
    pay = (f"export async function pay(amount) {{\n  if (parseFloat(amount) > {bound}) throw new Error('cap');\n"
           "  return BigInt(amount);\n}\n")
    started = time.perf_counter()
    found = hardening({"src/pay.js": pay})
    assert found[DUAL].severity.value == "high" and time.perf_counter() - started < 5


def test_many_amount_arguments_in_one_function_cost_little():
    """Each amount-named argument used to re-walk the function and build a fresh regex (65 s
    for 2,000 of them); only values that can reach parseFloat and a BigInt sink are judged."""
    logs = "\n".join(f"  log(req.amount{i});" for i in range(2000))
    pay = f"export function f(req) {{\n  const cap = parseFloat(req.amount);\n{logs}\n  return BigInt(req.amount);\n}}\n"
    parsed = "\n".join(f"  if (parseFloat(req.amount{i}) > 5) log(BigInt(req.amount{i}));" for i in range(2000))
    for name, text in (("src/logs.js", pay), ("src/parsed.js", f"export function g(req) {{\n{parsed}\n}}\n")):
        started = time.perf_counter()
        hardening({name: text})
        assert time.perf_counter() - started < 5, name


def test_evidence_quotes_the_line_the_parser_numbered():
    """tree-sitter counts rows at \\n only; splitting on U+2028, \\f or a bare \\r quoted another line."""
    bad = broken(Keypair.random().public_key)
    for sep in (" ", "\x0c", "\r", "\x85"):
        source = (f'import {{ Asset }} from "@stellar/stellar-sdk";\nconst LABEL = "a{sep}b";\nconst other = 1;\n'
                  f'export const PAY_TO = "{bad}";\n')
        evidence = hardening({"src/config.js": source})[STRKEY].evidence
        assert "src/config.js:4" in evidence and "PAY_TO" in evidence, repr(sep)


def test_a_helper_of_the_same_name_in_another_file_is_not_its_caller():
    amm = ('import { Asset, Operation } from "@stellar/stellar-sdk";\n'
           'function parseAsset(code: string, issuer?: string): Asset {\n'
           '  if (code === "XLM" || !issuer) return Asset.native();\n  return new Asset(code, issuer);\n}\n'
           'export function swap(input: any) {\n'
           '  return Operation.invokeContractFunction({ contract: input.pool, function: "swap", args: [parseAsset(input.a, input.b)] });\n}\n')
    claim = ('import { Asset, Operation } from "@stellar/stellar-sdk";\n'
             'function parseAsset(s: string): Asset { const [code, issuer] = s.split(":"); return new Asset(code, issuer); }\n'
             'export function claim(p: any) {\n  return Operation.createClaimableBalance({ asset: parseAsset(p.asset), amount: p.amount, claimants: [] });\n}\n')
    assert FALLBACK not in hardening({"src/amm.ts": amm, "src/claim.ts": claim})
    exported = amm.replace("function parseAsset", "export function parseAsset")
    user = ('import { Operation } from "@stellar/stellar-sdk";\nimport { parseAsset } from "./amm";\n'
            'export const pay = (p: any) => Operation.payment({ destination: p.to, asset: parseAsset(p.code, p.issuer), amount: p.amount });\n')
    assert FALLBACK in hardening({"src/amm.ts": exported, "src/pay.ts": user})
