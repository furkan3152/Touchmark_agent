"""Deploy the public demo registry and credential contracts on Stellar TESTNET.

One Friendbot-funded operator is registry admin and the only approved validator. Its
secret stays in gitignored data/demo-operator.json (mode 0600); the public manifest goes
to deployments/demo-testnet.json. Never mainnet. Run from the repository root after
building the WASM files (cargo build --release --target wasm32v1-none).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import requests
from stellar_sdk import Keypair, Network, SorobanServer, scval
from stellar_sdk.contract import ContractClient

RPC = "https://soroban-testnet.stellar.org"
NETWORK = Network.TESTNET_NETWORK_PASSPHRASE
KEY = Path("data/demo-operator.json")
MANIFEST = Path("deployments/demo-testnet.json")
WASM = Path("target/wasm32v1-none/release")


def operator() -> Keypair:
    KEY.parent.mkdir(exist_ok=True)
    if not KEY.exists():
        fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"secret": Keypair.random().secret}, handle)
    keypair = Keypair.from_secret(json.loads(KEY.read_text())["secret"])
    account = requests.get(f"https://horizon-testnet.stellar.org/accounts/{keypair.public_key}", timeout=20)
    if account.status_code == 404:
        requests.get("https://friendbot.stellar.org", params={"addr": keypair.public_key}, timeout=60).raise_for_status()
    return keypair


def main() -> None:
    admin = operator()
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {
        "schema": "agentveritas.demo-deployment.v1", "network": "testnet", "rpc": RPC,
        "network_passphrase": NETWORK, "operator": admin.public_key, "contracts": {}, "transactions": [],
        "purpose": "Public demo: audit a reference, then issue a credential for a passing report. "
                   "One operator is admin and validator; agent ownership is not verified.",
    }
    if manifest["operator"] != admin.public_key:
        raise SystemExit("deployments/demo-testnet.json belongs to another operator identity.")

    def save() -> None:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    server = SorobanServer(RPC)
    for name, filename in (("registry", "agent_veritas_registry.wasm"), ("credential", "agent_veritas_credential.wasm")):
        if name in manifest["contracts"]:
            continue
        constructor = ([scval.to_address(admin.public_key)] if name == "registry"
                       else [scval.to_address(manifest["contracts"]["registry"]["id"])])
        wasm = (WASM / filename).read_bytes()
        wasm_hash = ContractClient.upload_contract_wasm(wasm, admin.public_key, admin, server, network_passphrase=NETWORK)
        assert wasm_hash.hex() == hashlib.sha256(wasm).hexdigest()
        contract = ContractClient.create_contract(wasm_hash, admin.public_key, admin, server,
                                                  constructor_args=constructor, network_passphrase=NETWORK)
        manifest["contracts"][name] = {"id": contract, "wasm_sha256": wasm_hash.hex()}
        save()
        print(name, contract, flush=True)
    if not manifest.get("validator_enabled"):
        client = ContractClient(manifest["contracts"]["registry"]["id"], RPC, NETWORK)
        address = scval.to_address(admin.public_key)
        tx = client.invoke("set_valid", [address, address, scval.to_bool(True)], source=admin.public_key,
                           signer=admin, submit_timeout=60)
        tx.sign_and_submit()
        manifest["transactions"].append({"function": "set_valid", "hash": tx.send_transaction_response.hash})
        manifest["validator_enabled"] = True
        save()
    print("Demo contracts ready:", MANIFEST, flush=True)


if __name__ == "__main__":
    main()
