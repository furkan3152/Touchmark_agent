"""Public Studio contracts: bounded, private-by-default source review."""

from hashlib import sha256
import json
from pathlib import Path
import pytest
import httpx

from fastapi.testclient import TestClient

from backend.app import api


def bundle():
    return {
        "name": "Payment assistant",
        "purpose": "Prepare Stellar payments from customer requests.",
        "system_prompt": "Ask for approval before submitting a payment.",
        "files": {"agent.py": 'def pay():\n    payload = request.json()\n    soroban.invoke_contract(payload)\n'},
        "tools": [{"name": "pay", "scopes": ["sign:tx"], "requires_signature": True}],
    }


def test_public_source_review_produces_a_downloadable_evidence_report():
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/review", json=bundle())
    assert response.status_code == 200
    result = response.json()
    assert result["mode"] == "source_review"
    assert result["scope"]["runtime_executed"] is False
    assert result["scope"]["onchain_confirmed"] is False
    assert result["scope"]["persisted"] is False
    assert result["scope"]["external_processors"] == []
    assert result["decision"] == "needs_fixes"
    assert len(result["report"]["auditors"]) == 7
    assert any(f["id"] == "security-path-untrusted-to-financial-sink" for f in result["report"]["findings"])
    assert json.loads(result["report_json"]) == result["report"]
    assert result["report_sha256"] == sha256(result["report_json"].encode()).hexdigest()
    assert result["report"]["agent"]["owner_verified"] is False


@pytest.mark.parametrize("files", [
    {"../agent.py": "print('no')"},
    {".env": "DO_NOT_UPLOAD=credentials"},
    {"agent.py": "x" * 33_000},
    {"agent.py": "\n".join("x = 1" for _ in range(1500))},
])
def test_studio_rejects_unsafe_or_excessive_source_bundles(files):
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/review", json={**bundle(), "files": files})
    assert response.status_code == 422


def test_studio_limits_body_before_json_decoding():
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/review", content=b"x" * 131073)
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"


def test_home_opens_studio_and_preserves_operator_console():
    with TestClient(api.app) as client:
        home = client.get("/")
        operator = client.get("/operator")
    assert home.status_code == 200
    assert 'id="review-form"' in home.text
    assert operator.status_code == 200
    assert 'id="reportCard"' in operator.text


def test_read_only_fixture_needs_evidence_not_a_fabricated_critical_fix():
    fixtures = json.loads((Path(__file__).resolve().parents[2] / "frontend/studio-fixtures.json").read_text())
    with TestClient(api.app) as client:
        response = client.post("/api/v1/studio/review", json=fixtures["reader"])
    assert response.status_code == 200
    assert response.json()["decision"] == "needs_evidence"
    assert response.json()["priority_finding_ids"] == []


def test_studio_keeps_source_out_of_integrations_and_persistent_lists(settings, monkeypatch):
    monkeypatch.setattr(api, "settings", settings.model_copy(update={
        "admin_api_key": "studio-test-only", "llm_provider": "openrouter",
        "llm_api_key": "test-key-not-real", "enable_active_agent_probes": True,
        "screening_provider": "chainalysis", "screening_api_key": "test-key-not-real",
    }))

    async def no_network(*args, **kwargs):
        raise AssertionError("A source review must not contact an external service")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_network)
    headers = {"Authorization": "Bearer studio-test-only"}
    with TestClient(api.app) as client:
        before = client.get("/api/v1/agents", headers=headers).json()
        response = client.post("/api/v1/studio/review", json=bundle())
        after = client.get("/api/v1/agents", headers=headers).json()
    assert response.status_code == 200
    assert before == after
    assert response.json()["report"]["result"]["external_processors"] == []


def test_source_commitment_preserves_uploaded_whitespace():
    original = bundle()
    modified = {**original, "files": {"agent.py": original["files"]["agent.py"] + "\n"}}
    with TestClient(api.app) as client:
        first = client.post("/api/v1/studio/review", json=original)
        second = client.post("/api/v1/studio/review", json=modified)
    assert first.status_code == second.status_code == 200
    assert first.json()["report"]["input_hash"] != second.json()["report"]["input_hash"]
