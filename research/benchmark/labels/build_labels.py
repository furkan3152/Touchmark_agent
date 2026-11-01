#!/usr/bin/env python3
"""Regenerate labels/<agent>.json from text anchors so line numbers stay exact.

Each location is (file, start_anchor, end_anchor). The start line is the first line
containing start_anchor (after skipping `nth` earlier matches); the end line is the first
line at or after the start that contains end_anchor (or the start line when end_anchor is
None). Run after editing any agent source:  python3 labels/build_labels.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "agents"
LABELS = ROOT / "labels"
TOLERANCE = 5


def locate(agent: str, file: str, start: str, end: str | None = None, nth: int = 0) -> dict:
    lines = (AGENTS / agent / file).read_text().splitlines()
    hits = [i for i, line in enumerate(lines) if start in line]
    if len(hits) <= nth:
        sys.exit(f"{agent}/{file}: start anchor not found: {start!r}")
    s = hits[nth]
    e = s
    if end is not None:
        for i in range(s, len(lines)):
            if end in lines[i]:
                e = i
                break
        else:
            sys.exit(f"{agent}/{file}: end anchor not found: {end!r}")
    return {"file": file, "line_start": s + 1, "line_end": e + 1}


def defect(agent, id, category, severity, summary, loc, accept=(), alt=()):
    d = {"id": id, "category": category, "severity": severity, **locate(agent, *loc), "summary": summary,
         "accept_categories": list(accept)}
    if alt:
        d["alt_locations"] = [locate(agent, *a) for a in alt]
    return d


def decoy(agent, id, why, loc, control):
    d = {"id": id, **locate(agent, *loc), "why_safe": why}
    c = locate(agent, *control)
    d["control_file"], d["control_line"] = c["file"], c["line_start"]
    return d


def build() -> dict[str, dict]:
    out: dict[str, dict] = {}

    a = "invoice-settler"
    out[a] = {"agent": a, "language": "python", "defects": [
        defect(a, "PY-D1", "unauthorized_payment", "critical",
               "POST /v1/refunds has no require_api_key dependency; destination and amount come from the request body "
               "and are paid from the settlement account with no bound, allowlist or vendor policy.",
               ("app/main.py", '@app.post("/v1/refunds")', 'return {"customer"'),
               accept=["control_bypass", "economic_loss"],
               alt=[("app/ledger.py", "def send_refund", "return self._submit_payment(destination")]),
        defect(a, "PY-D2", "replay_or_idempotency", "high",
               "Settlement checks invoice.status == 'open', awaits the payment in a worker thread, and only then marks it "
               "paid; two concurrent settle calls both pass the check and pay the vendor twice (monthly cap is also read "
               "before either write).",
               ("app/main.py", 'if invoice.status != "open":', 'invoice.status = "paid"'),
               accept=["reliability_failure", "economic_loss", "control_bypass"]),
        defect(a, "PY-D3", "stellar_protocol_misuse", "medium",
               "Deposit verification matches the incoming payment by asset_code 'USDC' only, without the issuer, so a "
               "payment of a worthless self-issued USDC credits the customer balance.",
               ("app/ledger.py", 'if op.get("asset_code") == self._settings.usdc_code:', None),
               accept=["economic_loss", "control_bypass", "unauthorized_payment"]),
    ], "decoys": [
        decoy(a, "PY-K1", "Seed comes from the environment as a SecretStr and is never returned; /healthz exposes only "
              "the public key.",
              ("app/ledger.py", "Keypair.from_secret(", None),
              ("app/config.py", "signing_secret: SecretStr", None)),
        decoy(a, "PY-K2", "Vendor payments are bound by policy.enforce_vendor_payment: vendor allowlist supplies the "
              "destination, amount is parsed and capped per invoice and per month.",
              ("app/ledger.py", "def pay_vendor", "return self._submit_payment(vendor.address"),
              ("app/policy.py", "vendor = VENDORS.get(vendor_id)", None)),
        decoy(a, "PY-K3", "Accounting webhook body is only accepted after an HMAC-SHA256 check with compare_digest in "
              "auth.verify_signature; it only records invoices and never pays.",
              ("app/main.py", '@app.post("/v1/webhooks/accounting")', 'return {"received"'),
              ("app/auth.py", "if not hmac.compare_digest(provided, expected):", None)),
    ]}

    a = "treasury-mcp"
    out[a] = {"agent": a, "language": "typescript", "defects": [
        defect(a, "TS-D1", "foreign_transaction_signing", "critical",
               "sign_transaction tool parses a caller-supplied XDR envelope and signs and submits it with the treasury "
               "key without inspecting operations, source, destination or amount.",
               ("src/index.ts", '"sign_transaction",', "signAndSubmit(tx)"),
               accept=["unauthorized_payment", "account_takeover", "control_bypass"]),
        defect(a, "TS-D2", "control_bypass", "high",
               "Daily budget is checked with canSpend before the awaited payment and recorded with recordSpend only after "
               "it; concurrent pay calls all pass the in-memory check and overspend the budget (budget also resets on restart).",
               ("src/index.ts", "if (!budget.canSpend(usd))", "budget.recordSpend(usd);"),
               accept=["economic_loss", "unauthorized_payment", "replay_or_idempotency", "reliability_failure"],
               alt=[("src/budget.ts", "export function canSpend", "export function recordSpend")]),
        defect(a, "TS-D3", "secret_exposure", "high",
               "export_config returns every STELLAR_* environment variable to the model, which includes "
               "STELLAR_AGENT_SECRET (the treasury signing seed).",
               ("src/index.ts", 'server.tool("export_config"', "return text({ treasury"),
               accept=["intent_mismatch"]),
    ], "decoys": [
        decoy(a, "TS-K1", "approve_settlement signs an external XDR only after assertSettlementOnly checks source, "
              "expiry, fee, a single payment op, destination == settlement account, USDC with issuer and amount cap.",
              ("src/index.ts", '"approve_settlement",', "signAndSubmit(tx)"),
              ("src/settlement.ts", "if (op.destination !== config.settlementAccount", None)),
        decoy(a, "TS-K2", "Price fetch goes to a fixed host from config; the path segment is restricted to "
              "[A-Z0-9]{1,12} and URL-encoded, so the caller cannot redirect the request.",
              ("src/index.ts", "const res = await fetch(", None),
              ("src/index.ts", "if (!/^[A-Z0-9]{1,12}$/.test(code))", None)),
    ]}

    a = "payout-relay"
    out[a] = {"agent": a, "language": "go", "defects": [
        defect(a, "GO-D1", "replay_or_idempotency", "medium",
               "Payouts are marked paid inside one DB transaction that is committed only after the whole batch; if a later "
               "payment or MarkPaid fails the function returns, the deferred Rollback undoes the 'paid' rows of payments "
               "already submitted, and the next run pays them again.",
               ("payout.go", "hash, err := r.payer.Pay(", "return results, tx.Commit()"),
               accept=["reliability_failure", "economic_loss"],
               alt=[("payout.go", "defer tx.Rollback()", None)]),
    ], "decoys": [
        decoy(a, "GO-K1", "Destination is the creator's verified address from the database and the amount passes "
              "Policy.Check (per-payout and daily caps, valid strkey, verified flag) before signing.",
              ("payout.go", "tx, err = tx.Sign(network.PublicNetworkPassphrase", "resp, err := p.client.SubmitTransaction(tx)"),
              ("policy.go", "if amount.Cmp(p.MaxPerPayout) > 0 {", None)),
        decoy(a, "GO-K2", "The paying route is wrapped in requireOperator, which rejects an empty token and compares the "
              "bearer token in constant time.",
              ("main.go", 'mux.Handle("POST /payouts/run"', "})))"),
              ("auth.go", "subtle.ConstantTimeCompare", None)),
        decoy(a, "GO-K3", "Receipt file name is validated as 64 hex characters before filepath.Join, so no traversal.",
              ("receipts.go", "body, err := os.ReadFile(filepath.Join(rc.dir", None),
              ("receipts.go", "if !receiptName.MatchString(hash) {", None)),
    ]}

    a = "escrow-agent"
    j = "src/main/java/com/example/escrow/"
    out[a] = {"agent": a, "language": "java", "defects": [
        defect(a, "JV-D1", "prompt_injection", "critical",
               "releaseOnDelivery pays the payout_address an LLM extracted from an inbound e-mail instead of the escrow's "
               "seller; anyone who writes the e-mail chooses the recipient of the escrowed funds.",
               (j + "EscrowService.java", "String destination = confirmation.payoutAddress()", "gateway.pay(destination"),
               accept=["unauthorized_payment", "intent_mismatch", "control_bypass"],
               alt=[(j + "DeliveryParser.java", "payout_address (the Stellar address", None)]),
        defect(a, "JV-D2", "replay_or_idempotency", "high",
               "Funding proof (txHash) is never recorded or bound to the escrow/buyer; the same payment hash funds any "
               "number of escrows, each of which can then be released.",
               (j + "EscrowService.java", "var payment = gateway.findPayment(txHash, network)", "escrow.status = Status.FUNDED;"),
               accept=["economic_loss", "control_bypass", "unauthorized_payment"]),
        defect(a, "JV-D3", "stellar_protocol_misuse", "high",
               "Funding verification uses the network chosen by the requester; a testnet payment marks a mainnet escrow "
               "FUNDED and release pays real USDC.",
               (j + "StellarGateway.java", "private Server serverFor(String network)", "return publicServer;"),
               accept=["control_bypass", "economic_loss", "ssrf", "unauthorized_payment"],
               alt=[(j + "StellarGateway.java", "Server server = serverFor(network);", None)]),
        defect(a, "JV-D4", "control_bypass", "high",
               "/inbound/delivery-confirmations is excluded from the API key filter and has no signature check, so anyone "
               "can post a 'delivered' e-mail and release any funded escrow.",
               (j + "EscrowController.java", '@PostMapping(value = "/inbound/delivery-confirmations"', "releaseOnDelivery"),
               accept=["unauthorized_payment", "prompt_injection"],
               alt=[(j + "ApiKeyFilter.java", 'startsWith("/inbound/")', None)]),
    ], "decoys": [
        decoy(a, "JV-K1", "Release route is behind ApiKeyFilter and EscrowService.release requires the authenticated "
              "buyer and FUNDED status, and pays the stored seller.",
              (j + "EscrowController.java", '@PostMapping("/escrows/{id}/release")', "escrows.release(id, buyer(request))"),
              (j + "EscrowService.java", "if (!escrow.buyer.equals(buyer)) {", None)),
        decoy(a, "JV-K2", "Asset comparison checks both code and issuer.",
              (j + "AssetPolicy.java", "return expected.getCode().equals(credit.getCode())", "expected.getIssuer().equals"),
              (j + "AssetPolicy.java", "expected.getIssuer().equals(credit.getIssuer())", None)),
        decoy(a, "JV-K3", "The API key is sent only to a fixed api.openai.com URL and never logged or returned.",
              (j + "DeliveryParser.java", '.header("Authorization", "Bearer " + apiKey)', None),
              (j + "DeliveryParser.java", 'URI.create("https://api.openai.com', None)),
    ]}

    a = "swap-desk"
    k = "src/main/kotlin/com/example/swapdesk/"
    out[a] = {"agent": a, "language": "kotlin", "defects": [
        defect(a, "KT-D1", "economic_loss", "high",
               "The customer is credited the requested expectedOut instead of the amount actually received, and destMin "
               "is derived from expectedOut and slippageBps from the request; slippageBps=10000 with an inflated "
               "expectedOut mints balance from the omnibus account.",
               (k + "SwapService.kt", "balances.credit(userId, destKey, expectedOut)", None),
               accept=["stellar_protocol_misuse", "control_bypass", "unauthorized_payment"],
               alt=[(k + "SwapService.kt", "val destMin = expectedOut.multiply", ".setScale(7, RoundingMode.DOWN)")]),
        defect(a, "KT-D2", "cross_user_access", "critical",
               "Withdraw route debits the userId from the path, not the JWT subject; any customer can withdraw another "
               "customer's balance to their own address.",
               (k + "Routes.kt", 'post("/users/{userId}/withdraw")', "service.withdraw(userId"),
               accept=["unauthorized_payment", "control_bypass"]),
        defect(a, "KT-D3", "reliability_failure", "medium",
               "submit() ignores SubmitTransactionResponse.isSuccess; a failed swap or withdrawal is treated as done "
               "(balance debited/credited, hash returned).",
               (k + "SwapService.kt", "val response = server.submitTransaction(tx)", "return response.hash"),
               accept=["functional_defect", "economic_loss"]),
    ], "decoys": [
        decoy(a, "KT-K1", "/admin/rebalance is under authenticate(\"ops\"), which only accepts JWTs carrying the ops "
              "role; topUpOmnibus pays only the omnibus account with a bounded amount.",
              (k + "Routes.kt", 'post("/admin/rebalance")', "treasury.topUpOmnibus"),
              (k + "Auth.kt", 'if ("ops" in roles)', None)),
        decoy(a, "KT-K2", "Requester-supplied withdrawal asset code/issuer are resolved through SupportedAssets.require, "
              "which rejects any pair (code and issuer) not in the supported set.",
              (k + "SwapService.kt", "val key = SupportedAssets.require(req.code, req.issuer)", None),
              (k + "Assets.kt", "if (key !in supported) {", None)),
    ]}

    a = "payroll-agent"
    out[a] = {"agent": a, "language": "csharp", "defects": [
        defect(a, "CS-D1", "foreign_transaction_signing", "critical",
               "sign-payload signs arbitrary caller-supplied bytes with the payroll key; a transaction hash or Soroban "
               "auth payload submitted as a 'challenge' authorizes any transaction from the payroll account.",
               ("Program.cs", 'api.MapPost("/agent/tools/sign-payload"', "signature = Convert.ToBase64String"),
               accept=["account_takeover", "unauthorized_payment", "control_bypass"],
               alt=[("StellarSigner.cs", "public byte[] SignRaw", None)]),
        defect(a, "CS-D2", "control_bypass", "medium",
               "Destination allowlist defaults to '*' and CheckDestination returns early on '*', so unless configured the "
               "allowlist allows any destination.",
               ("BatchValidator.cs", 'if (_allowed.Contains("*"))', "return;"),
               accept=["unauthorized_payment"],
               alt=[("BatchValidator.cs", 'public string AllowedDestinations { get; set; } = "*";', None)]),
        defect(a, "CS-D3", "replay_or_idempotency", "high",
               "BatchId is never recorded; re-posting the same batch (or an assistant retry after a timeout) pays every "
               "line again, and limits are per batch only.",
               ("PayrollService.cs", "var lines = validator.Validate(batch);", "return new BatchResult"),
               accept=["reliability_failure", "economic_loss"]),
    ], "decoys": [
        decoy(a, "CS-K1", "The tool returns only the account id (public key), not the seed.",
              ("Program.cs", 'api.MapGet("/agent/tools/payroll-account"', "signer.PublicKey"),
              ("StellarSigner.cs", "public string PublicKey => _keyPair.AccountId;", None)),
        decoy(a, "CS-K2", "Seed is read from the environment at startup, not committed, logged or returned.",
              ("StellarSigner.cs", "_keyPair = KeyPair.FromSecretSeed(", "PAYROLL_SEED is not set"),
              ("StellarSigner.cs", "public string PublicKey => _keyPair.AccountId;", None)),
    ]}
    return out


def ranges(label: dict):
    for d in label["defects"]:
        yield "defect", d["id"], d["file"], d["line_start"], d["line_end"]
        for alt in d.get("alt_locations", []):
            yield "defect", d["id"], alt["file"], alt["line_start"], alt["line_end"]
    for k in label["decoys"]:
        yield "decoy", k["id"], k["file"], k["line_start"], k["line_end"]


def main() -> None:
    labels = build()
    for name, label in labels.items():
        # warn when a defect and a decoy range come within the match tolerance of each other
        rs = list(ranges(label))
        for kind1, id1, f1, s1, e1 in rs:
            for kind2, id2, f2, s2, e2 in rs:
                if kind1 == "defect" and kind2 == "decoy" and f1 == f2 and s1 - TOLERANCE <= e2 and s2 <= e1 + TOLERANCE:
                    gap = max(s1, s2) - min(e1, e2)
                    print(f"note {name}: {id1} {f1}:{s1}-{e1} near {id2} {s2}-{e2} (gap {gap}); nearest wins")
        (LABELS / f"{name}.json").write_text(json.dumps(label, indent=2) + "\n")
        print(f"{name}: {len(label['defects'])} defects, {len(label['decoys'])} decoys")


if __name__ == "__main__":
    main()
