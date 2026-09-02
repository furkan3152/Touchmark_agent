"""Soroban build/hash and active Testnet release verifier.

Backend does not hold deploy keys. Signed deployment is executed via the external Stellar CLI signer;
this module produces the build/hash and calls the read-only release verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "wasm32v1-none" / "release"
WASMS = {
    "agent_registry": TARGET / "agent_veritas_registry.wasm",
    "audit_escrow": TARGET / "agent_veritas_escrow.wasm",
}


def build() -> int:
    completed = subprocess.run(
        ["cargo", "build", "--workspace", "--target", "wasm32v1-none", "--release"],
        cwd=ROOT,
        check=False,
    )
    if completed.returncode:
        return completed.returncode
    return show_hashes()


def show_hashes() -> int:
    missing = [str(path) for path in WASMS.values() if not path.exists()]
    if missing:
        print("WASM not found; run `python -m backend.deploy build` first.")
        return 1
    for name, path in WASMS.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{name:<16} sha256:{digest}  {path.relative_to(ROOT)}")
    print("Note: WASM hash is not proof of deployment or successful invocation.")
    return 0


def verify_testnet() -> int:
    script = ROOT / "scripts" / "verify_testnet_deployment.py"
    return subprocess.run([sys.executable, str(script)], cwd=ROOT, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentveritas-stellar-build")
    parser.add_argument("command", choices=("build", "hashes", "verify-testnet"))
    args = parser.parse_args()
    if args.command == "build":
        return build()
    if args.command == "verify-testnet":
        return verify_testnet()
    return show_hashes()


if __name__ == "__main__":
    raise SystemExit(main())
