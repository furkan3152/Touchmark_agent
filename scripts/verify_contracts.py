#!/usr/bin/env python3
"""Check that the contracts the demo uses on Stellar testnet are built from this repository.

    scripts/build_contracts.sh
    python scripts/verify_contracts.py            # ledger == manifest == this source
    python scripts/verify_contracts.py --ledger   # ledger == manifest only (no Rust toolchain)

For each contract in a deployment manifest three SHA-256 values must be equal:

  ledger    the code hash of the contract instance, read from Soroban RPC
  manifest  wasm_sha256 in the manifest
  source    the WASM built from contracts/ with the pinned toolchain and Cargo.lock

The build is reproducible, so equal hashes mean the code that runs on the ledger is the code in
this repository. Exits 1 on any difference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from stellar_sdk import Address, xdr

ROOT = Path(__file__).resolve().parents[1]
WASM_DIR = ROOT / "target/wasm32v1-none/release"
# manifest, then the WASM file each of its contracts is built to
MANIFESTS = {
    "deployments/demo-testnet.json": {"registry": "agent_veritas_registry.wasm",
                                      "credential": "agent_veritas_credential.wasm"},
    "deployments/agent-account-testnet-2026-10-15.json": {"agent_account": "agent_veritas_account.wasm"},
}


def contracts(manifest: dict) -> dict[str, dict]:
    if "contracts" in manifest:
        return manifest["contracts"]
    return {"agent_account": {"id": manifest["contract_id"], "wasm_sha256": manifest["wasm_sha256"]}}


def ledger_hash(rpc: str, contract_id: str) -> str:
    key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        contract=Address(contract_id).to_xdr_sc_address(),
        key=xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
        durability=xdr.ContractDataDurability.PERSISTENT))
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries", "params": {"keys": [key.to_xdr()]}})
    request = urllib.request.Request(rpc, body.encode(), {"Content-Type": "application/json", "User-Agent": "touchmark-verify/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        entries = json.load(response)["result"].get("entries") or []
    if not entries:
        return "not on the ledger"
    data = xdr.LedgerEntryData.from_xdr(entries[0]["xdr"])
    return data.contract_data.val.instance.executable.wasm_hash.hash.hex()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", action="store_true", help="compare the ledger with the manifests only")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args()

    rows, failed = [], False
    for path, files in MANIFESTS.items():
        manifest = json.loads((ROOT / path).read_text())
        for name, contract in contracts(manifest).items():
            row = {"manifest_file": path, "contract": name, "id": contract["id"],
                   "manifest": contract["wasm_sha256"], "ledger": ledger_hash(manifest["rpc"], contract["id"])}
            if not args.ledger:
                wasm = WASM_DIR / files[name]
                row["source"] = hashlib.sha256(wasm.read_bytes()).hexdigest() if wasm.exists() else "not built"
            row["ok"] = len({row[k] for k in ("manifest", "ledger", "source") if k in row}) == 1
            failed |= not row["ok"]
            rows.append(row)

    if args.json:
        print(json.dumps({"ok": not failed, "contracts": rows}, indent=2))
    else:
        for row in rows:
            print(f"{'ok  ' if row['ok'] else 'FAIL'} {row['contract']:<14}{row['id']}")
            for k in ("ledger", "manifest", "source"):
                if k in row:
                    print(f"       {k:<9}{row[k]}")
        print("FAILED" if failed else f"{len(rows)} contracts: the ledger, the manifests"
              + ("" if args.ledger else " and this source") + " agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
