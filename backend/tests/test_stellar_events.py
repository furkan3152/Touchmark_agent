from __future__ import annotations

from backend.app.stellar.events import StellarEventStore
from backend.app.models import Attestation
from backend.app.config import Settings
from backend.app.services.chain_status import ChainStatusService


def test_event_store_deduplicates_and_persists_cursor(tmp_path):
    path = tmp_path / "events.db"
    store = StellarEventStore(path)
    event = {
        "id": "0001-0002",
        "type": "contract",
        "ledger": 123,
        "contractId": "C" + "A" * 55,
        "topic": ["agent_ver", "responded"],
        "value": {"score": 88},
        "txHash": "ab" * 32,
        "inSuccessfulContractCall": True,
    }
    assert store.ingest_page("registry", [event], "cursor-1") == 1
    assert store.ingest_page("registry", [event], "cursor-2") == 0

    reopened = StellarEventStore(path)
    assert reopened.cursor("registry") == "cursor-2"
    assert reopened.status()["events"] == 1
    responses = reopened.confirmed_responses("C" + "A" * 55)
    assert len(responses) == 1
    assert responses[0]["value"] == {"score": 88}
    assert responses[0]["confirmed"] is True


def test_event_store_rejects_failed_or_wrong_contract_events(tmp_path):
    store = StellarEventStore(tmp_path / "events.db")
    registry = "C" + "A" * 55
    failed = {
        "id": "failed",
        "type": "contract",
        "contractId": registry,
        "topic": ["agent_ver", "responded"],
        "value": {"score": 100},
        "inSuccessfulContractCall": False,
    }
    wrong = {
        "id": "wrong",
        "type": "contract",
        "contractId": "C" + "B" * 55,
        "topic": ["agent_ver", "responded"],
        "value": {"score": 100},
        "inSuccessfulContractCall": True,
    }
    assert store.ingest_page("registry", [failed, wrong], "cursor", {registry}) == 0
    assert store.status()["events"] == 0


def test_attestation_confirmation_requires_matching_event_and_success_tx(tmp_path, run):
    registry = "C" + "A" * 55
    request_id = "11" * 32
    report_hash = "22" * 32
    tx_hash = "33" * 32
    settings = Settings(
        stellar_network="offline",
        stellar_rpc_url="https://rpc.invalid",
        agent_registry_contract_id=registry,
        data_dir=str(tmp_path / "data"),
        event_database=str(tmp_path / "events.db"),
        _env_file=None,
    )

    class SuccessfulRpc:
        async def get_transaction(self, supplied_hash):
            assert supplied_hash == tx_hash
            return {"status": "SUCCESS"}

    service = ChainStatusService(settings, rpc=SuccessfulRpc())
    service.events.ingest_page(
        "agent-registry",
        [{
            "id": "response-event",
            "type": "contract",
            "ledger": 456,
            "contractId": registry,
            "topic": ["agent_ver", "responded", request_id, "44" * 32],
            "value": {"rep_hash": report_hash, "score": 88},
            "txHash": tx_hash,
            "inSuccessfulContractCall": True,
        }],
        "cursor",
        {registry},
    )
    attestation = Attestation(
        mode="prepared",
        registry_contract_id=registry,
        request_id=request_id,
        report_hash=report_hash,
    )
    proof = run(service.confirm_attestation(attestation))
    assert proof["confirmed"] is True
    assert proof["tx_hash"] == tx_hash
    assert proof["ledger"] == 456
