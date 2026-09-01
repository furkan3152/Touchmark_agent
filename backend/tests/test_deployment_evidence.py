from __future__ import annotations

import json

from backend.app.config import Settings
from backend.app.services.chain_status import ChainStatusService


def _manifest(path, registry: str, escrow: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "agentveritas.stellar.testnet-deployment.v1",
                "network": {"passphrase": "Test SDF Network ; September 2015"},
                "contracts": {
                    "agent_registry": {
                        "contract_id": registry,
                        "hash_match": True,
                        "local_wasm_sha256": "11" * 32,
                        "onchain_wasm_sha256": "11" * 32,
                        "deploy": {"tx_hash": "22" * 32},
                    },
                    "audit_escrow": {
                        "contract_id": escrow,
                        "hash_match": True,
                        "local_wasm_sha256": "33" * 32,
                        "onchain_wasm_sha256": "33" * 32,
                        "deploy": {"tx_hash": "44" * 32},
                    },
                },
                "asset": {"kind": "native_xlm_sac", "contract_id": "C" + "C" * 55},
            }
        )
    )


def test_deployment_requires_manifest_hash_id_and_live_success(tmp_path, run):
    registry = "C" + "A" * 55
    escrow = "C" + "B" * 55
    manifest = tmp_path / "deployment.json"
    _manifest(manifest, registry, escrow)
    settings = Settings(
        stellar_network="testnet",
        stellar_rpc_url="https://rpc.invalid",
        agent_registry_contract_id=registry,
        audit_escrow_contract_id=escrow,
        sac_contract_id="C" + "C" * 55,
        deployment_manifest=str(manifest),
        event_database=str(tmp_path / "events.db"),
        data_dir=str(tmp_path / "data"),
        _env_file=None,
    )

    class SuccessfulRpc:
        async def get_transaction(self, tx_hash):
            assert tx_hash in {"22" * 32, "44" * 32}
            return {"status": "SUCCESS", "ledger": 123}

    result = run(ChainStatusService(settings, rpc=SuccessfulRpc()).deployed_contracts())
    rows = {row["key"]: row for row in result["contracts"]}
    assert rows["agent_registry"]["onchain_verified"] is True
    assert rows["audit_escrow"]["onchain_verified"] is True
    assert rows["sac"]["deterministic_native_sac"] is True


def test_configured_id_mismatch_stays_unverified(tmp_path, run):
    registry = "C" + "A" * 55
    manifest = tmp_path / "deployment.json"
    _manifest(manifest, registry, "C" + "B" * 55)
    settings = Settings(
        stellar_network="testnet",
        stellar_rpc_url="https://rpc.invalid",
        agent_registry_contract_id="C" + "D" * 55,
        deployment_manifest=str(manifest),
        event_database=str(tmp_path / "events.db"),
        data_dir=str(tmp_path / "data"),
        _env_file=None,
    )

    class MustNotCallRpc:
        async def get_transaction(self, _):
            raise AssertionError("ID mismatch halinde RPC kanıtı kabul edilmemeli")

    result = run(ChainStatusService(settings, rpc=MustNotCallRpc()).deployed_contracts())
    rows = {row["key"]: row for row in result["contracts"]}
    assert rows["agent_registry"]["onchain_verified"] is False
    assert rows["agent_registry"]["manifest_id_match"] is False
