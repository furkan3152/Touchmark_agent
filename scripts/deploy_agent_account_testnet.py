"""Deploy and exercise the bounded agent account on TESTNET only.

Disposable credentials stay in gitignored data/ with mode 0600. Public evidence
separates successful ledger transactions from rejected enforcing simulations.
No production credentials, assets, or networks are accepted by this script.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from stellar_sdk import Account, Asset, Keypair, Network, SorobanServer, TransactionBuilder, scval
from stellar_sdk.auth import authorization_payload_hash
from stellar_sdk.contract import AssembledTransaction, ContractClient
from stellar_sdk.contract.exceptions import SimulationFailedError
from stellar_sdk.soroban_rpc import AuthMode, SendTransactionStatus

ROOT = Path(__file__).resolve().parents[1]
RPC = "https://soroban-testnet.stellar.org"
NETWORK = Network.TESTNET_NETWORK_PASSPHRASE
KEY_PATH = ROOT / "data/agent-account-testnet-identity.json"
PROGRESS = ROOT / "data/agent-account-testnet-progress.json"
EVIDENCE = ROOT / "deployments/agent-account-testnet-2026-10-15.json"
WASM_PATH = ROOT / "target/wasm32v1-none/release/agent_veritas_account.wasm"
EXPECTED_WASM = "0996a395ec14d4ce0ff144ed136e1f8adb4aa15828849082e9cc0eed1f0cd23f"
DOMAIN = b"AgentVeritas/session/v1\0"


def json_write(path: Path, value: dict) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def faucet(public_key: str) -> None:
    response = requests.get(f"https://horizon-testnet.stellar.org/accounts/{public_key}", timeout=20)
    if response.status_code == 404:
        response = requests.get("https://friendbot.stellar.org", params={"addr": public_key}, timeout=30)
    response.raise_for_status()


def main() -> None:
    wasm = WASM_PATH.read_bytes()
    digest = hashlib.sha256(wasm).hexdigest()
    if digest != EXPECTED_WASM:
        raise RuntimeError("WASM differs from the reviewed/tested artifact. Re-verify before deployment.")
    KEY_PATH.parent.mkdir(exist_ok=True)
    if not KEY_PATH.exists():
        keys = {name: Keypair.random().secret for name in ("owner", "session", "recipient")}
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(keys, stream)
    os.chmod(KEY_PATH, 0o600)
    keys = json.loads(KEY_PATH.read_text())
    owner, session, recipient = (Keypair.from_secret(keys[name]) for name in ("owner", "session", "recipient"))
    manifest = json.loads(PROGRESS.read_text()) if PROGRESS.exists() else {
        "schema": "agentveritas.agent-account-testnet.v1",
        "network": "testnet", "rpc": RPC, "network_passphrase": NETWORK,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "owner": owner.public_key, "recipient": recipient.public_key,
        "session_public_key": session.public_key,
        "wasm_sha256": digest, "transactions": [], "checks": [],
        "asset": {"code": "XLM", "decimals": 7, "contract_id": Asset.native().contract_id(NETWORK)},
        "status": "in_progress",
        "limitations": [
            "Disposable testnet identities and native test XLM only.",
            "Not independently audited and not a production wallet or agent-security certificate.",
            "Rejected enforcing simulations are not submitted failed ledger transactions.",
            "Session is revoked and remaining account funds recovered after the test.",
        ],
    }
    if manifest["owner"] != owner.public_key or manifest["wasm_sha256"] != digest:
        raise RuntimeError("Progress belongs to another identity or artifact; do not overwrite it.")
    if manifest["status"] == "verified":
        if not EVIDENCE.exists():
            json_write(EVIDENCE, manifest)
        print("Existing verified TESTNET evidence:", EVIDENCE, flush=True)
        return
    if any(tx["status"] != "SUCCESS" for tx in manifest["transactions"]):
        raise RuntimeError("An earlier submitted transaction needs reconciliation before retrying.")

    def save() -> None:
        json_write(PROGRESS, manifest)

    def submit(tx: AssembledTransaction, label: str):
        if tx._needs_preparation:
            tx.prepare()
        tx.sign(force=True)
        tx.send_transaction_response = tx.server.send_transaction(tx.built_transaction)
        response = tx.send_transaction_response
        record = {"action": label, "hash": response.hash, "status": response.status.value}
        manifest["transactions"].append(record)
        save()  # retain a pending transaction hash before waiting; never silently resubmit
        if response.status != SendTransactionStatus.PENDING:
            raise RuntimeError(f"Testnet rejected submission for {label}; inspect public progress hash.")
        value = tx.submit()
        record.update(status=tx.get_transaction_response.status.value, ledger=tx.get_transaction_response.ledger)
        save()
        print(label, record["status"], record["hash"], flush=True)
        return value

    def invoke(contract_id: str, function: str, args: list, label: str | None = None):
        tx = ContractClient(contract_id, RPC, NETWORK).invoke(
            function, args, source=owner.public_key, signer=owner,
            submit_timeout=45, use_upgraded_auth=False,
        )
        return submit(tx, label) if label else tx.result()

    def done(label: str) -> bool:
        return any(item["action"] == label and item["status"] == "SUCCESS" for item in manifest["transactions"])

    faucet(owner.public_key)
    faucet(recipient.public_key)
    server = SorobanServer(RPC)
    if server.get_network().passphrase != NETWORK:
        raise RuntimeError("RPC network mismatch; refusing to deploy.")
    latest = server.get_latest_ledger()
    manifest["network_protocol"] = latest.protocol_version
    save()

    if not done("upload_wasm"):
        builder = TransactionBuilder(Account(owner.public_key, 0), NETWORK).append_upload_contract_wasm_op(wasm).set_timeout(180)
        value = submit(AssembledTransaction(builder, server, owner, submit_timeout=45, use_upgraded_auth=False).simulate(), "upload_wasm")
        assert scval.from_bytes(value).hex() == digest
    if "contract_id" not in manifest:
        if done("deploy_account"):
            raise RuntimeError("Deployment succeeded before its address was checkpointed. Reconcile its recorded transaction.")
        builder = TransactionBuilder(Account(owner.public_key, 0), NETWORK).append_create_contract_op(
            bytes.fromhex(digest), owner.public_key, [scval.to_address(owner.public_key)], os.urandom(32),
        ).set_timeout(180)
        value = submit(AssembledTransaction(builder, server, owner, submit_timeout=45, use_upgraded_auth=False).simulate(), "deploy_account")
        manifest["contract_id"] = scval.from_address(value).address
        save()
    account = manifest["contract_id"]
    token = manifest["asset"]["contract_id"]
    assert scval.from_address(invoke(account, "owner", [])).address == owner.public_key

    def balance() -> int:
        return scval.from_int128(invoke(token, "balance", [scval.to_address(account)]))

    def current_session() -> dict:
        # Option<Session> is the struct itself when Some, void when None.
        return scval.from_struct(invoke(account, "session", []))

    if not done("fund_account"):
        assert balance() == 0
        invoke(token, "transfer", [scval.to_address(owner.public_key), scval.to_address(account), scval.to_int128(10_000_000)], "fund_account")
    if not done("open_session"):
        expires = server.get_latest_ledger().sequence + 1000
        manifest["policy"] = {
            "per_call_limit_stroops": 2_500_000, "total_limit_stroops": 4_000_000,
            "expires_ledger": expires, "recipient": recipient.public_key, "token": token,
        }
        value = invoke(account, "open_session", [scval.to_struct({
            "public_key": scval.to_bytes(session.raw_public_key()), "token": scval.to_address(token),
            "recipient": scval.to_address(recipient.public_key), "per_call_limit": scval.to_int128(2_500_000),
            "total_limit": scval.to_int128(4_000_000), "expires_ledger": scval.to_uint32(expires),
        })], "open_session")
        manifest["session_id"] = scval.from_uint64(value)
        save()
    session_id = manifest["session_id"]

    def sign_entry(preimage):
        payload = authorization_payload_hash(preimage)
        message = DOMAIN + session_id.to_bytes(8, "big") + payload
        return scval.to_struct({"session_id": scval.to_uint64(session_id), "signature": scval.to_bytes(session.sign(message))})

    def transfer_candidate(to: str, amount: int):
        tx = ContractClient(token, RPC, NETWORK).invoke(
            "transfer", [scval.to_address(account), scval.to_address(to), scval.to_int128(amount)],
            source=owner.public_key, signer=owner, submit_timeout=45,
            auth_mode=AuthMode.RECORD, use_upgraded_auth=False,
        )
        tx.sign_auth_entries(sign_entry, address=account, valid_until_ledger_sequence=min(
            manifest["policy"]["expires_ledger"] - 1, server.get_latest_ledger().sequence + 100,
        ))
        tx.auth_mode = AuthMode.ENFORCE
        return tx

    if not done("authorized_session_transfer"):
        assert scval.from_int128(current_session()["spent"]) == 0
        candidate = transfer_candidate(recipient.public_key, 2_000_000)
        candidate.prepare()
        submit(candidate, "authorized_session_transfer")
    if not done("recover_remaining"):
        assert balance() == 8_000_000
        assert scval.from_int128(current_session()["spent"]) == 2_000_000

    def assert_rejected(label: str, to: str, amount: int, error_code: int):
        if any(check["id"] == label for check in manifest["checks"]):
            return
        before = balance()
        tx = transfer_candidate(to, amount)
        unsigned_hash = tx.built_transaction.hash_hex()
        try:
            tx.prepare()
        except SimulationFailedError:
            error = tx.simulation.error or ""
            if f"Error(Contract, #{error_code})" not in error:
                raise RuntimeError(f"Unexpected enforcing failure for {label}: {error}") from None
            assert balance() == before
            assert scval.from_int128(current_session()["spent"]) == 2_000_000
            manifest["checks"].append({
                "id": label, "result": "rejected", "method": "signed_rpc_enforce_simulation",
                "expected_contract_error": error_code, "error": error,
                "simulated_transaction_hash": unsigned_hash, "latest_ledger": tx.simulation.latest_ledger,
                "account_balance_unchanged": True, "spent_counter_unchanged": True,
            })
            save()
            print(label, "REJECTED", f"Contract #{error_code}", flush=True)
            return
        raise RuntimeError(f"Security assertion failed: {label} was authorized.")

    assert_rejected("forbidden_recipient", owner.public_key, 1_000_000, 9)
    assert_rejected("cumulative_budget_exceeded", recipient.public_key, 2_500_000, 11)
    if not done("revoke_session"):
        invoke(account, "revoke_session", [scval.to_uint64(session_id)], "revoke_session")
    assert_rejected("revoked_session", recipient.public_key, 1_000_000, 8)
    if not done("recover_remaining"):
        invoke(account, "recover", [scval.to_address(token), scval.to_int128(balance())], "recover_remaining")
    session_state = current_session()
    assert scval.from_bool(session_state["revoked"]) is True
    assert balance() == 0
    manifest.update(
        status="verified", verified_at=datetime.now(timezone.utc).isoformat(),
        owner_readback_verified=True, final_account_balance_stroops=0,
        final_session_revoked=True, final_session_spent_stroops=scval.from_int128(session_state["spent"]),
        authorized_transfer_stroops=2_000_000,
    )
    save()
    if EVIDENCE.exists():
        raise RuntimeError("Public evidence already exists; refusing to overwrite history.")
    json_write(EVIDENCE, manifest)
    print("Verified public TESTNET evidence:", EVIDENCE, flush=True)


if __name__ == "__main__":
    main()
