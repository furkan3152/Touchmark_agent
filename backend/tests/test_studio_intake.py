"""Self-service Stellar intake at the public HTTP boundary."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from stellar_sdk import Keypair, xdr

from backend.app import api

ADDRESS = Keypair.from_raw_ed25519_seed(bytes([7]) * 32).public_key


def test_public_address_lookup_is_read_only_and_not_an_agent_endorsement(monkeypatch):
    async def respond(self, request, **kwargs):
        assert request.method == "GET"
        assert str(request.url) == f"https://horizon-testnet.stellar.org/accounts/{ADDRESS}"
        return httpx.Response(200, json={"account_id": ADDRESS, "sequence": "123"}, request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/identify", json={"address": ADDRESS, "network": "testnet"})
    assert response.status_code == 200
    data = response.json()
    assert data["ledger_presence"] == "found"
    assert data["owner_verified"] is False
    assert data["agent_verified"] is False
    assert data["requires_source"] is True
    assert data["kind"] == "account"


def test_github_bundle_import_uses_only_the_fixed_public_github_endpoint(monkeypatch):
    bundle = {"name": "Reader", "purpose": "Summarize Stellar balances", "files": {"agent.py": "def read():\n    return 1\n"}}
    async def respond(self, request, **kwargs):
        assert str(request.url) == "https://api.github.com/repos/example/reader/contents/agent-audit.json"
        assert "authorization" not in request.headers
        return httpx.Response(200, content=json.dumps(bundle).encode(), request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/import", json={"repository": "https://github.com/example/reader"})
    assert response.status_code == 200
    assert response.json()["bundle"]["files"] == bundle["files"]
    assert response.json()["source"] == "https://github.com/example/reader"


def test_address_only_review_preserves_network_without_inventing_source_evidence():
    body = {"name": "Stellar agent", "purpose": "Review this Stellar agent", "stellar_address": ADDRESS, "network": "testnet"}
    with TestClient(api.app) as client:
        first = client.post("/api/v1/studio/review", json=body)
        second = client.post("/api/v1/studio/review", json={**body, "network": "mainnet"})
    assert first.status_code == second.status_code == 200
    report = first.json()["report"]
    assert report["subject"]["stellar_address"] == ADDRESS
    assert report["subject"]["network"] == "testnet"
    assert report["result"]["coverage"]["surface_coverage"]["surfaces"]["implementation"] is False
    assert report["input_hash"] != second.json()["report"]["input_hash"]
    assert first.json()["decision"] == "needs_evidence"


@pytest.mark.parametrize("reference", ["http://127.0.0.1/internal", "https://github.com.evil.test/owner/repo", "https://user:password@github.com/owner/repo"])
def test_import_rejects_non_public_github_locations_before_network(reference, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Invalid reference reached the network")
    monkeypatch.setattr(httpx.AsyncClient, "send", forbidden)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/import", json={"repository": reference})
    assert response.status_code == 422


@pytest.mark.parametrize("address", ["S" + "A" * 55, "G" + "A" * 55])
def test_secret_or_bad_checksum_is_rejected(address):
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/identify", json={"address": address})
    assert response.status_code == 422


def test_missing_contract_is_not_reported_as_deployed(monkeypatch):
    contract = "CBBBUECSLXGXVXYMRYK3BCTL3YYBRWDZGW3RNCH5CWKY6KU6UGE576KT"
    async def respond(self, request, **kwargs):
        body = json.loads(request.content)
        assert body["method"] == "getLedgerEntries"
        key = xdr.LedgerKey.from_xdr(body["params"]["keys"][0])
        assert key.contract_data.key.type == xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE
        return httpx.Response(200, json={"result": {"entries": [], "latestLedger": 1}}, request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/identify", json={"address": contract})
    assert response.status_code == 200
    assert response.json()["ledger_presence"] == "not_found"


def test_upstream_failure_remains_unknown_not_found(monkeypatch):
    async def respond(self, request, **kwargs):
        return httpx.Response(503, request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/identify", json={"address": ADDRESS})
    assert response.status_code == 200
    assert response.json()["ledger_presence"] == "unavailable"
