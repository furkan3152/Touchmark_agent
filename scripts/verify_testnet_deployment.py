#!/usr/bin/env python3
"""Aktif Stellar Testnet release kanıtını salt-okunur olarak yeniden doğrula.

Manifest veya contract ID tek başına yeterli sayılmaz. Bu kontrol yerel WASM
hash'ini, zincirdeki WASM hash'ini, rol/state readback'lerini, escrow bakiyesini
ve manifestteki tüm transaction'ların Horizon sonucunu birlikte doğrular.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deployments" / "stellar-testnet.json"
CLI_CONFIG = ROOT / "data" / "stellar-cli"


def stellar(*args: str) -> str:
    completed = subprocess.run(
        ["stellar", "--config-dir", str(CLI_CONFIG), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"stellar CLI başarısız: {message}")
    return completed.stdout.strip()


def invoke(contract_id: str, function: str, *args: str) -> Any:
    output = stellar(
        "contract",
        "invoke",
        "--id",
        contract_id,
        "--source",
        "av-admin",
        "--network",
        "testnet",
        "--send",
        "no",
        "--quiet",
        "--",
        function,
        *args,
    )
    return json.loads(output)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def transactions(value: Any, prefix: str = "") -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    if isinstance(value, dict):
        if value.get("tx_hash"):
            found.append((prefix.rstrip("."), value))
        for key, item in value.items():
            found.extend(transactions(item, f"{prefix}{key}."))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(transactions(item, f"{prefix}{index}."))
    return found


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("schema") != "agentveritas.stellar.testnet-deployment.v1":
        raise RuntimeError("beklenmeyen deployment manifest şeması")
    if manifest.get("network", {}).get("name") != "Stellar Testnet":
        raise RuntimeError("yalnız Stellar Testnet manifesti doğrulanabilir")

    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, actual: Any = None) -> None:
        checks.append({"name": name, "ok": bool(ok), "actual": actual})

    roles = manifest["roles"]
    expected_roles = {
        "admin_requester_fee_recipient": "av-admin",
        "validator_provider": "av-provider",
        "reviewer_evaluator": "av-evaluator",
    }
    for field, identity in expected_roles.items():
        address = stellar("keys", "address", identity)
        check(f"role.{field}", address == roles[field], address)

    contracts = manifest["contracts"]
    for name, item in contracts.items():
        local_hash = sha256(ROOT / item["wasm_path"])
        chain_hash = stellar(
            "contract", "info", "hash", "--id", item["contract_id"],
            "--network", "testnet", "--quiet",
        )
        check(f"{name}.local_hash", local_hash == item["local_wasm_sha256"], local_hash)
        check(f"{name}.onchain_hash", chain_hash == local_hash, chain_hash)

    registry = contracts["agent_registry"]["contract_id"]
    escrow = contracts["audit_escrow"]["contract_id"]
    provider = roles["validator_provider"]
    evaluator = roles["reviewer_evaluator"]
    lifecycle = manifest["agent_validation_lifecycle"]
    funded = manifest["funded_escrow_lifecycle"]

    check(
        "registry.validator_role",
        invoke(registry, "is_valid", "--validator", provider) is True,
    )
    check(
        "registry.reviewer_role",
        invoke(registry, "is_reviewer", "--reviewer", evaluator) is True,
    )
    validation = invoke(registry, "get_valid", "--req_id", lifecycle["request_id"])
    check("registry.validation_state", validation.get("state") == "Complete", validation)
    check(
        "registry.report_hash",
        validation.get("rep_hash") == lifecycle["report_hash"],
        validation.get("rep_hash"),
    )
    average = invoke(registry, "avg_score", "--agent_id", lifecycle["agent_id"])
    check("registry.average_score", average == 89, average)

    job = invoke(escrow, "get_job", "--job_id", funded["job_id"])
    check("escrow.state", job.get("state") == "Complete", job)
    check("escrow.score", job.get("score") == 94, job.get("score"))
    balance = json.loads(
        stellar(
            "token", "balance", "--id", "native", "--account", escrow,
            "--network", "testnet", "--output", "json", "--quiet",
        )
    )
    check("escrow.balance_after_settlement", balance.get("balance") == "0", balance)

    horizon = manifest["network"]["horizon_url"].rstrip("/")
    with httpx.Client(timeout=20.0) as client:
        for label, record in transactions(manifest):
            tx_hash = record["tx_hash"]
            response = client.get(f"{horizon}/transactions/{tx_hash}")
            if response.status_code != 200:
                check(f"tx.{label}", False, response.status_code)
                continue
            data = response.json()
            matches = bool(
                data.get("successful") is True
                and data.get("hash") == tx_hash
                and int(data.get("ledger", -1)) == int(record.get("ledger", -2))
            )
            check(
                f"tx.{label}",
                matches,
                {"successful": data.get("successful"), "ledger": data.get("ledger")},
            )

    failed = [item for item in checks if not item["ok"]]
    print(
        json.dumps(
            {
                "ok": not failed,
                "network": "Stellar Testnet",
                "checks": len(checks),
                "failed": failed,
                "registry": registry,
                "escrow": escrow,
                "funded_asset": "native XLM SAC (not USDC)",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
