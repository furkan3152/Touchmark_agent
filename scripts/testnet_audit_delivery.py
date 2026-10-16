#!/usr/bin/env python3
"""Real Testnet audit delivery using first-party official service identities.

Two stages: --prepare-report writes a genuine static report for our checked-in
fixture. Publish that exact file, then --run --report-url HTTPS_URL verifies its
bytes and executes the bound-registry escrow lifecycle with faucet XLM only.

No mainnet option exists. Signing keys stay in ignored owner-only data files;
public evidence contains addresses, hashes, transaction IDs and readbacks only.
This smoke test is not the customer-facing production payment service.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests
from stellar_sdk import Account, Address, Asset, Keypair, Network, SorobanServer, TransactionBuilder, scval, xdr
from stellar_sdk.contract import AssembledTransaction, ContractClient
from stellar_sdk.contract.exceptions import SimulationFailedError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RPC = "https://soroban-testnet.stellar.org"
HORIZON = "https://horizon-testnet.stellar.org"
NETWORK = Network.TESTNET_NETWORK_PASSPHRASE
DATE = "2026-10-15"
EVIDENCE = ROOT / "deployments" / f"testnet-audit-delivery-{DATE}.json"
HISTORICAL = ROOT / "deployments" / "testnet-pilot-2026-10-15.json"
IDENTITIES = ROOT / "data" / "testnet-audit-delivery-identities.json"
ADMIN_KEY = ROOT / "data" / "testnet-pilot-identity.json"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jsonable(value):
    if isinstance(value, Address):
        return value.address
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def save(evidence):
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    temporary = EVIDENCE.with_suffix(".tmp")
    temporary.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(EVIDENCE)


def load_evidence():
    if EVIDENCE.exists():
        value = json.loads(EVIDENCE.read_text())
        if value.get("network") != "testnet" or value.get("network_passphrase") != NETWORK:
            raise RuntimeError("Evidence is not bound to Stellar Testnet")
        return value
    return {
        "schema": "agentveritas.testnet-audit-delivery/v1",
        "network": "testnet", "network_passphrase": NETWORK,
        "rpc": RPC, "horizon": HORIZON,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "operating_model": "Official first-party requester/provider/evaluator identities; distinct keys, one operator. Not independent validators.",
        "status": "report_preparation",
        "transactions": [], "negative_simulations": [], "checks": [],
        "asset": {"code": "XLM", "decimals": 7, "kind": "testnet_faucet_native_xlm", "contract_id": Asset.native().contract_id(NETWORK)},
        "limitations": [
            "Testnet faucet currency only; no real money or Mainnet transactions.",
            "The report is a genuine bounded static review of our deterministic fixture; no AI model or agent runtime was executed by this pilot.",
            "The credential records the issuer's scoped audit assertion and exact report hash; it is not a universal security guarantee.",
            "Requester, provider, evaluator and admin are controlled by the same official pilot operator. Cryptographic role separation is not organizational independence.",
            "Negative checks are RPC simulations rejected before submission, explicitly separate from successful ledger transactions.",
        ],
    }


async def prepare_report():
    from backend.app.config import Settings
    from backend.app.services.studio import ReviewRequest, review_source
    from backend.app.services.discovery import source_digest
    from backend.app.reporting.generator import canonical_json

    evidence = load_evidence()
    if evidence.get("report"):
        report = evidence["report"]
        assert digest((ROOT / report["path"]).read_bytes()) == report["sha256"]
        print(json.dumps({"report_path": report["path"], "report_sha256": report["sha256"], "status": "already_prepared"}), flush=True)
        return
    folder = ROOT / "examples" / "blueprint-reader"
    blueprint = json.loads((folder / "veritas.json").read_text())
    paths = ["veritas.json"] + [c["path"] for c in blueprint["components"]]
    files = {path: (folder / path).read_text() for path in paths}
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    request = ReviewRequest(
        name=blueprint["name"], purpose=blueprint["purpose"], files=files,
        source_reference="https://github.com/furkan3152/agentveritas-stellar", source_revision=revision,
    )
    settings = Settings(
        stellar_network="offline", llm_provider="", llm_api_key="", pinata_jwt="",
        screening_provider="none", enable_ofac_screening=False,
        data_dir=str(ROOT / "data" / "testnet-report-generation"), _env_file=None,
    )
    result = await review_source(request, settings)
    # The report itself contains its scope. This explicit pilot provenance must
    # be included BEFORE hashing/publishing, never appended after commitment.
    report = result["report"]
    report["delivery_pilot"] = {
        "kind": "official_first_party_testnet_static_review",
        "fixture_path": "examples/blueprint-reader",
        "agent_runtime_executed": False, "ai_model_invoked": False,
        "source_sha256": source_digest(files),
        "credential_meaning": "Version-bound report provenance, not a safety certification.",
    }
    encoded = canonical_json(report).encode("utf-8")
    report_hash = digest(encoded)
    path = ROOT / "deployments" / "reports" / f"{report_hash}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    evidence["report"] = {
        "path": str(path.relative_to(ROOT)), "sha256": report_hash,
        "source_sha256": source_digest(files), "source_revision": revision,
        "blueprint_sha256": digest(files["veritas.json"].encode()),
        "bytes": len(encoded), "decision": result["decision"],
        "overall_score": report["result"]["overall_score"],
        "contract_score": int(round(report["result"]["overall_score"])),
        "scope": "bounded_static_source_review", "runtime_executed": False,
        "ai_model_invoked": False, "controls_verified": [],
    }
    evidence["status"] = "awaiting_report_publication"
    save(evidence)
    print(json.dumps({"report_path": str(path.relative_to(ROOT)), "report_sha256": report_hash, "decision": result["decision"], "score": evidence["report"]["contract_score"]}), flush=True)


def keys():
    # Never serialize these Keypairs into public evidence or print their repr.
    if not ADMIN_KEY.is_file():
        raise RuntimeError("The ignored Testnet pilot identity file is required")
    original = json.loads(ADMIN_KEY.read_text())
    historical = json.loads(HISTORICAL.read_text())
    admin = Keypair.from_secret(original["admin"])
    treasury = Keypair.from_secret(original["treasury"])
    if admin.public_key != historical["admin"] or treasury.public_key != historical["treasury"]:
        raise RuntimeError("Public historical deployment does not match the local Testnet keys")
    if not IDENTITIES.exists():
        IDENTITIES.parent.mkdir(parents=True, exist_ok=True)
        values = {role: Keypair.random().secret for role in ("requester", "provider", "evaluator")}
        fd = os.open(IDENTITIES, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump(values, file)
    os.chmod(IDENTITIES, 0o600)
    values = json.loads(IDENTITIES.read_text())
    result = {role: Keypair.from_secret(values[role]) for role in ("requester", "provider", "evaluator")}
    result.update(admin=admin, treasury=treasury)
    if len({key.public_key for key in result.values()}) != len(result):
        raise RuntimeError("Every pilot role must have a distinct address")
    return result


class Pilot:
    def __init__(self, evidence, identities):
        self.evidence = evidence
        self.identities = identities
        self.server = SorobanServer(RPC)
        if self.server.get_network().passphrase != NETWORK:
            raise RuntimeError("RPC network does not match the hard-coded Testnet passphrase")
        self.roles = {role: key.public_key for role, key in identities.items()}
        if evidence.get("roles") and evidence["roles"] != self.roles:
            raise RuntimeError("Persisted pilot roles differ from local identities")
        self.evidence["roles"] = self.roles
        save(self.evidence)

    def fund_accounts(self):
        for role, address in self.roles.items():
            response = requests.get(f"{HORIZON}/accounts/{address}", timeout=20)
            if response.status_code == 404:
                response = requests.get("https://friendbot.stellar.org", params={"addr": address}, timeout=45)
            response.raise_for_status()
            print(f"Testnet account ready: {role}", flush=True)

    def record_transaction(self, label, kind, function, role, tx):
        response = tx.get_transaction_response
        sent = tx.send_transaction_response
        if response.status.value != "SUCCESS":
            raise RuntimeError("Submitted Testnet transaction did not return SUCCESS")
        row = {
            "label": label, "contract": kind, "function": function, "signer_role": role,
            "hash": sent.hash, "status": response.status.value, "ledger": response.ledger,
            "fee_charged_atomic": str(xdr.TransactionResult.from_xdr(response.result_xdr).fee_charged.int64),
            "explorer_url": f"https://stellar.expert/explorer/testnet/tx/{sent.hash}",
        }
        self.evidence["transactions"].append(row)
        save(self.evidence)
        print(f"{label}: SUCCESS {sent.hash}", flush=True)

    def done(self, label):
        return any(tx["label"] == label and tx["status"] == "SUCCESS" for tx in self.evidence["transactions"])

    def invoke(self, label, kind, function, args, role="admin", *, write=True):
        if write and self.done(label):
            return None
        contract = self.evidence["contracts"][kind]["id"]
        key = self.identities[role]
        tx = ContractClient(contract, RPC, NETWORK).invoke(
            function, args, source=key.public_key, signer=key,
            transaction_timeout=180, submit_timeout=45,
        )
        if not write:
            return jsonable(scval.to_native(tx.result()))
        value = tx.sign_and_submit(force=True)
        self.record_transaction(label, kind, function, role, tx)
        return jsonable(scval.to_native(value))

    def reject(self, label, kind, function, args, role, *, expected_code):
        for check in self.evidence["negative_simulations"]:
            if check["label"] == label:
                if expected_code not in check["contract_error_codes"]:
                    raise RuntimeError("Saved negative evidence lacks the expected contract error")
                check["expected_contract_error_code"] = expected_code
                save(self.evidence)
                return
        contract = self.evidence["contracts"][kind]["id"]
        key = self.identities[role]
        try:
            ContractClient(contract, RPC, NETWORK).invoke(function, args, source=key.public_key, signer=key)
        except SimulationFailedError as exc:
            # Only a contract-level error counts, never an RPC/network failure.
            matches = re.findall(r"Error\(Contract,\s*#?(\d+)\)", str(exc))
            if not matches or expected_code not in {int(value) for value in matches}:
                raise RuntimeError("Negative simulation failed without the expected contract error") from None
            self.evidence["negative_simulations"].append({
                "label": label, "contract": kind, "function": function,
                "rejected": True, "stage": "rpc_simulation_before_submission",
                "contract_error_codes": sorted(set(int(value) for value in matches)),
                "expected_contract_error_code": expected_code,
                "transaction_submitted": False,
            })
            save(self.evidence)
            print(f"{label}: rejected before submission", flush=True)
            return
        raise RuntimeError(f"Required negative simulation unexpectedly succeeded: {label}")

    def check(self, label, condition, actual):
        if not condition:
            raise RuntimeError(f"Readback assertion failed: {label}")
        self.evidence["checks"] = [row for row in self.evidence["checks"] if row["label"] != label]
        self.evidence["checks"].append({"label": label, "ok": True, "actual": jsonable(actual)})
        save(self.evidence)

    def balance(self, address):
        token = ContractClient(self.evidence["asset"]["contract_id"], RPC, NETWORK)
        value = token.invoke("balance", [scval.to_address(address)], source=self.roles["admin"]).result()
        return scval.from_int128(value)

    def deploy_bound_escrow(self):
        historical = json.loads(HISTORICAL.read_text())
        contracts = self.evidence.setdefault("contracts", {})
        contracts.setdefault("registry", historical["contracts"]["registry"])
        contracts.setdefault("credential", historical["contracts"]["credential"])
        if "escrow" in contracts:
            return
        wasm_path = ROOT / "target" / "wasm32v1-none" / "release" / "agent_veritas_escrow.wasm"
        wasm = wasm_path.read_bytes()
        if b"get_registry" not in wasm or b"get_binding" not in wasm:
            raise RuntimeError("Rebuild the registry-bound escrow WASM before deployment")
        wasm_hash = digest(wasm)
        admin = self.identities["admin"]
        if not self.done("escrow_upload"):
            builder = TransactionBuilder(Account(admin.public_key, 0), NETWORK).append_upload_contract_wasm_op(wasm).set_timeout(180)
            tx = AssembledTransaction(builder, self.server, admin, submit_timeout=45).simulate()
            uploaded = tx.sign_and_submit(force=True)
            self.check("escrow.uploaded_wasm", scval.from_bytes(uploaded).hex() == wasm_hash, wasm_hash)
            self.record_transaction("escrow_upload", "escrow", "upload_contract_wasm", "admin", tx)
        constructors = [
            scval.to_address(admin.public_key), scval.to_address(self.evidence["asset"]["contract_id"]),
            scval.to_address(self.roles["treasury"]), scval.to_uint32(1500), scval.to_address(contracts["registry"]["id"]),
        ]
        salt = bytes.fromhex(self.evidence.setdefault("escrow_deployment_salt", os.urandom(32).hex()))
        save(self.evidence)
        builder = TransactionBuilder(Account(admin.public_key, 0), NETWORK).append_create_contract_op(
            bytes.fromhex(wasm_hash), admin.public_key, constructors, salt
        ).set_timeout(180)
        tx = AssembledTransaction(builder, self.server, admin, submit_timeout=45).simulate()
        created = tx.sign_and_submit(force=True)
        contract = scval.from_address(created).address
        contracts["escrow"] = {
            "id": contract, "wasm_sha256": wasm_hash,
            "wasm_path": str(wasm_path.relative_to(ROOT)), "constructor_atomic": True,
            "registry_bound": True, "registry": contracts["registry"]["id"],
            "constructor_argument_order": ["admin", "token", "fee_to", "fee_bps", "registry"],
        }
        self.record_transaction("escrow_deploy", "escrow", "create_contract", "admin", tx)

    def verify_contract_wasm(self):
        for name, contract in self.evidence["contracts"].items():
            key = xdr.LedgerKey(
                xdr.LedgerEntryType.CONTRACT_DATA,
                contract_data=xdr.LedgerKeyContractData(
                    Address(contract["id"]).to_xdr_sc_address(),
                    xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
                    xdr.ContractDataDurability.PERSISTENT,
                ),
            )
            response = self.server.get_ledger_entries([key])
            if not response.entries or len(response.entries) != 1:
                raise RuntimeError("Contract instance was not found on Testnet")
            data = xdr.LedgerEntryData.from_xdr(response.entries[0].xdr)
            actual = data.contract_data.val.instance.executable.wasm_hash.hash.hex()
            self.check(f"{name}.onchain_wasm_sha256", actual == contract["wasm_sha256"], actual)

    def lifecycle(self, report_url):
        evidence = self.evidence
        report = evidence["report"]
        contracts = evidence["contracts"]
        address = lambda role: scval.to_address(self.roles[role])
        b32 = lambda value: scval.to_bytes(bytes.fromhex(value))
        source_hash, meta_hash = report["source_sha256"], report["blueprint_sha256"]
        report_hash, score = report["sha256"], report["contract_score"]
        ids = evidence.setdefault("ids", {name: os.urandom(32).hex() for name in ("agent", "request", "stale_agent", "stale_request")})
        evidence["token_id"] = ids["request"]
        save(evidence)
        self.invoke("enable_official_validator", "registry", "set_valid", [address("admin"), address("provider"), scval.to_bool(True)])
        bound = self.invoke("read_bound_registry", "escrow", "get_registry", [], write=False)
        self.check("escrow.registry_binding", bound == contracts["registry"]["id"], bound)

        def register_and_fund(prefix, agent, request, amount):
            self.invoke(f"{prefix}.register", "registry", "reg_agent", [address("requester"), b32(agent), scval.to_string(report_url), b32(meta_hash), b32(source_hash), scval.to_uint32(1)], "requester")
            self.invoke(f"{prefix}.request", "registry", "req_valid", [address("requester"), b32(request), b32(agent), address("provider")], "requester")
            deadline_key = f"{prefix}_deadline"
            if deadline_key not in evidence:
                evidence[deadline_key] = self.server.get_latest_ledger().sequence + 1440
                save(evidence)
            self.invoke(f"{prefix}.create", "escrow", "create", [address("requester"), b32(request), address("provider"), address("evaluator"), scval.to_int128(amount), scval.to_uint32(evidence[deadline_key])], "requester")
            self.invoke(f"{prefix}.fund", "escrow", "fund", [address("requester"), b32(request)], "requester")
            self.invoke(f"{prefix}.respond", "registry", "respond", [address("provider"), b32(request), scval.to_uint32(score), scval.to_string(report_url), b32(report_hash)], "provider")

        amount = 10_000_000  # 1 faucet XLM, never USDC or a production price.
        register_and_fund("delivery", ids["agent"], ids["request"], amount)
        self.reject("wrong_report_hash_rejected", "escrow", "submit", [address("provider"), b32(ids["request"]), scval.to_bytes(bytes([97]) * 32)], "provider", expected_code=15)
        self.invoke("delivery.submit", "escrow", "submit", [address("provider"), b32(ids["request"]), b32(report_hash)], "provider")
        self.reject("score_mismatch_rejected", "escrow", "complete", [address("evaluator"), b32(ids["request"]), scval.to_uint32((score + 1) % 101)], "evaluator", expected_code=9)
        if not self.done("delivery.complete"):
            evidence["settlement_balances_before"] = {role: self.balance(self.roles[role]) for role in ("provider", "treasury")}
            save(evidence)
        self.invoke("delivery.complete", "escrow", "complete", [address("evaluator"), b32(ids["request"]), scval.to_uint32(score)], "evaluator")
        if "settlement_balances_after" not in evidence:
            evidence["settlement_balances_after"] = {role: self.balance(self.roles[role]) for role in ("provider", "treasury")}
            save(evidence)
        after = evidence["settlement_balances_after"]
        fee = amount * 1500 // 10_000
        before = evidence["settlement_balances_before"]
        self.check("settlement.provider_exact_payout", after["provider"] - before["provider"] == amount - fee, after["provider"] - before["provider"])
        self.check("settlement.treasury_exact_fee", after["treasury"] - before["treasury"] == fee, after["treasury"] - before["treasury"])
        evidence["settlement"] = {"amount_atomic": str(amount), "fee_atomic": str(fee), "provider_payout_atomic": str(amount - fee), "fee_bps": 1500}
        expiry = evidence.setdefault("credential_expires_at", int(time.time()) + 7 * 86400)
        save(evidence)
        self.invoke("delivery.issue_credential", "credential", "issue", [b32(ids["request"]), scval.to_uint64(expiry)], "provider")
        validation = self.invoke("read_validation", "registry", "get_valid", [b32(ids["request"])], write=False)
        job = self.invoke("read_escrow", "escrow", "get_job", [b32(ids["request"])], write=False)
        credential = self.invoke("read_credential", "credential", "get", [b32(ids["request"])], write=False)
        owner = self.invoke("read_credential_owner", "credential", "owner_of", [b32(ids["request"])], write=False)
        current = self.invoke("read_current", "credential", "is_current", [b32(ids["request"])], write=False)
        self.check("delivery.same_content_hash", validation["rep_hash"] == job["del_hash"] == credential["report_hash"] == report_hash, report_hash)
        self.check("delivery.same_report_uri", credential["report_uri"] == report_url, credential["report_uri"])
        self.check("delivery.same_score", validation["score"] == job["score"] == credential["score"] == score, score)
        self.check("delivery.escrow_complete", job["state"] == ["Complete"], job["state"])
        self.check("delivery.credential_owner", owner == self.roles["requester"], owner)
        self.check("delivery.credential_current", current is True, current)
        evidence["readbacks"] = {"validation": validation, "escrow": job, "credential": credential}
        save(evidence)

        # A separate funded job changes source version after submission. It must
        # not settle or mint a credential; dispute/refund must remain possible.
        register_and_fund("stale", ids["stale_agent"], ids["stale_request"], 2_500_000)
        self.invoke("stale.submit", "escrow", "submit", [address("provider"), b32(ids["stale_request"]), b32(report_hash)], "provider")
        changed_hash = digest(b"AgentVeritas version-drift negative fixture; unreviewed source version 2")
        self.invoke("stale.change_version", "registry", "upd_agent", [address("requester"), b32(ids["stale_agent"]), scval.to_string(report_url), b32(meta_hash), b32(changed_hash), scval.to_uint32(2)], "requester")
        self.reject("stale_version_settlement_rejected", "escrow", "complete", [address("evaluator"), b32(ids["stale_request"]), scval.to_uint32(score)], "evaluator", expected_code=16)
        self.reject("stale_version_credential_rejected", "credential", "issue", [b32(ids["stale_request"]), scval.to_uint64(expiry)], "provider", expected_code=3)
        self.invoke("stale.dispute", "escrow", "dispute", [address("evaluator"), b32(ids["stale_request"])], "evaluator")
        if not self.done("stale.refund"):
            evidence["refund_balance_before"] = self.balance(self.roles["requester"])
            save(evidence)
        self.invoke("stale.refund", "escrow", "refund", [address("requester"), b32(ids["stale_request"])], "requester")
        if "refund_balance_after" not in evidence:
            evidence["refund_balance_after"] = self.balance(self.roles["requester"])
            save(evidence)
        refund_fee = int(next(tx["fee_charged_atomic"] for tx in evidence["transactions"] if tx["label"] == "stale.refund"))
        returned = evidence["refund_balance_after"] - evidence["refund_balance_before"] + refund_fee
        self.check("refund.exact_return_after_transaction_fee", returned == 2_500_000, returned)
        refunded = self.invoke("read_refund", "escrow", "get_job", [b32(ids["stale_request"])], write=False)
        self.check("refund.state", refunded["state"] == ["Refunded"], refunded["state"])
        remaining = self.balance(contracts["escrow"]["id"])
        self.check("escrow.no_remaining_funds", remaining == 0, remaining)
        evidence["readbacks"]["refunded_stale_job"] = refunded
        evidence["status"] = "verified"
        evidence["verified_at"] = datetime.now(timezone.utc).isoformat()
        save(evidence)


def execute(report_url):
    evidence = load_evidence()
    if not evidence.get("report"):
        raise RuntimeError("Run --prepare-report first")
    if not report_url:
        report_url = evidence["report"].get("uri", "")
    parsed = urlparse(report_url)
    # This pilot publishes only our own report; no arbitrary URL or redirect fetch.
    if parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com" or not parsed.path.startswith("/furkan3152/agentveritas-stellar/"):
        raise RuntimeError("Report URL must be this repository's HTTPS raw GitHub file")
    response = requests.get(report_url, timeout=20, allow_redirects=False)
    response.raise_for_status()
    report = evidence["report"]
    if len(response.content) > 500_000 or digest(response.content) != report["sha256"]:
        raise RuntimeError("Published report bytes do not match the local committed report")
    if digest((ROOT / report["path"]).read_bytes()) != report["sha256"]:
        raise RuntimeError("Local report changed after hash commitment")
    report["uri"] = report_url
    report["public_bytes_verified_at"] = datetime.now(timezone.utc).isoformat()
    evidence["status"] = "executing_testnet"
    save(evidence)
    pilot = Pilot(evidence, keys())
    pilot.fund_accounts()
    pilot.deploy_bound_escrow()
    pilot.verify_contract_wasm()
    pilot.lifecycle(report_url)
    print(json.dumps({"status": evidence["status"], "evidence": str(EVIDENCE.relative_to(ROOT)), "transaction_count": len(evidence["transactions"]), "negative_simulation_count": len(evidence["negative_simulations"])}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-report", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--report-url", default="")
    args = parser.parse_args()
    if args.prepare_report:
        asyncio.run(prepare_report())
    else:
        execute(args.report_url)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # SDK error objects may include serialized requests. Never print them or
        # key material. Fail closed; inspect only safe status locally if needed.
        print(f"Pilot stopped without claiming completion ({type(exc).__name__}).", file=sys.stderr)
        raise SystemExit(1) from None
