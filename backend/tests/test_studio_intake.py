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


def test_github_import_pins_commit_and_checks_blob_integrity(monkeypatch):
    import base64
    from hashlib import sha1
    raw = b'def answer(prompt):\n    return "Read only"\n'
    blob_sha = sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    revision = "a" * 40
    async def respond(self, request, **kwargs):
        assert request.url.host == 'api.github.com'
        assert "authorization" not in request.headers
        url = str(request.url)
        if url.endswith('/commits/HEAD'): data = {'sha': revision}
        elif url.endswith(f'/git/trees/{revision}?recursive=1'):
            data = {'tree': [{'type': 'blob', 'mode': '100644', 'path': 'src/reader.py', 'sha': blob_sha, 'size': len(raw)}]}
        elif url.endswith('/git/blobs/' + blob_sha):
            data = {'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
        else: raise AssertionError(url)
        return httpx.Response(200, json=data, request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/import", json={"repository": "https://github.com/example/reader"})
    assert response.status_code == 200, response.text
    assert response.json()["bundle"]["files"] == {'src/reader.py': raw.decode()}
    assert response.json()["revision"] == revision
    assert response.json()['discovery']['entrypoints'][0]['id'] == 'src/reader.py:answer'


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


def test_import_skips_complex_source_instead_of_rejecting_whole_project(monkeypatch):
    import base64
    from hashlib import sha1
    source = {'main.py': b'x = 1\n' * 1800, 'reader.py': b'def answer(prompt):\n return "read only"\n'}
    blobs = {sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest(): (name, raw) for name, raw in source.items()}
    async def respond(self, request, **kwargs):
        url = str(request.url)
        if url.endswith('/commits/HEAD'): data = {'sha': 'b' * 40}
        elif '/git/trees/' in url:
            data = {'tree': [{'type': 'blob', 'mode': '100644', 'path': name, 'sha': sha, 'size': len(raw)} for sha,(name,raw) in blobs.items()]}
        else:
            raw = blobs[url.rsplit('/',1)[1]][1]
            data = {'encoding':'base64', 'content':base64.b64encode(raw).decode()}
        return httpx.Response(200, json=data, request=request)
    monkeypatch.setattr(httpx.AsyncClient, 'send', respond)
    with TestClient(api.app) as client:
        response = client.post('/api/v1/studio/import', json={'repository':'https://github.com/example/reader'})
    assert response.status_code == 200
    assert list(response.json()['bundle']['files']) == ['reader.py']
    assert response.json()['import_scope']['omitted_paths'] == ['main.py']
    assert response.json()['import_scope']['omitted_reasons']
