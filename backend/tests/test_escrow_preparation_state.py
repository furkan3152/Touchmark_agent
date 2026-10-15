"""Preparation failure is not a signature request or an indeterminate payment."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from stellar_sdk import StrKey

from backend.app import api
from backend.app.models import AgentArtifact, AuditReport, AuditTier, JobState, SourceKind
from backend.app.services.escrow import ExternalSignatureRequired, InvocationPreparationBlocked
from backend.app.services.pipeline import AuditPipeline
from backend.app.services.store import Store

REQUESTER, PROVIDER, EVALUATOR = [StrKey.encode_ed25519_public_key(bytes([i]) * 32) for i in (3, 4, 5)]


@pytest.fixture
def payment_pipeline(settings, monkeypatch):
    configured = settings.model_copy(update={
        "stellar_network": "testnet", "enable_audit_escrow": True,
        "audit_escrow_contract_id": StrKey.encode_contract(bytes([1]) * 32),
        "sac_contract_id": StrKey.encode_contract(bytes([2]) * 32),
        "admin_api_key": "test-only-operator-key",
    })
    pipeline = AuditPipeline(configured)
    artifact = AgentArtifact(source_kind=SourceKind.WIZARD, name="Fixture agent")
    pipeline.store.put_agent(artifact)
    monkeypatch.setattr(api, "settings", configured)
    monkeypatch.setattr(api, "pipeline", pipeline)
    api._operator_requests.clear()
    return pipeline, artifact


def fully_prepared_job(pipeline, artifact):
    job = pipeline.create_job(artifact.id, AuditTier.BASIC, REQUESTER)
    job.escrow = pipeline.escrow.open(
        job.id, job.tier, REQUESTER, provider=PROVIDER, evaluator=EVALUATOR,
        amount_atomic=20_000_000, deadline=987654,
    )
    job.state = JobState.CREATED
    job.error = ""
    pipeline.store.put_job(job)
    return job


def test_preparation_state_survives_storage_and_does_not_run_swarm(payment_pipeline, run):
    pipeline, artifact = payment_pipeline
    job = pipeline.create_job(artifact.id, AuditTier.BASIC, REQUESTER)
    assert job.state is JobState.PREPARATION_BLOCKED
    assert job.escrow.tx_ref == ""
    with pytest.raises(InvocationPreparationBlocked):
        run(pipeline.fund_job(job.id, REQUESTER))
    with pytest.raises(InvocationPreparationBlocked):
        run(pipeline.run_job(job.id))
    restored = Store(pipeline.settings).get_job(job.id)
    assert restored.state is JobState.PREPARATION_BLOCKED
    assert restored.report is None
    assert restored.escrow.funded is False
    assert restored.escrow.tx_hashes == {}


@pytest.mark.parametrize("route", ["create", "fund", "run", "validation"])
def test_http_preparation_failures_return_blocked_with_no_invocation(payment_pipeline, route):
    pipeline, artifact = payment_pipeline
    job = pipeline.create_job(artifact.id, AuditTier.BASIC, REQUESTER)
    calls = {
        "create": ("/api/v1/jobs", {"agent_id": artifact.id, "requester": REQUESTER}),
        "fund": (f"/api/v1/jobs/{job.id}/fund", {"funder": REQUESTER}),
        "run": (f"/api/v1/jobs/{job.id}/run", {}),
        "validation": ("/api/v1/validation/requests", {"agent_id": artifact.id, "requester": REQUESTER}),
    }
    path, payload = calls[route]
    with TestClient(api.app) as client:
        response = client.post(path, json=payload, headers={"Authorization": "Bearer test-only-operator-key"})
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["state"] == "preparation_blocked"
    assert detail["invocation"] == ""
    assert "provider" in detail["reason"]
    persisted = pipeline.store.get_job(detail["job_id"])
    assert persisted.state is JobState.PREPARATION_BLOCKED
    assert persisted.report is None


def test_valid_prepared_invocation_still_requests_signature(payment_pipeline, run):
    pipeline, artifact = payment_pipeline
    job = fully_prepared_job(pipeline, artifact)
    with pytest.raises(ExternalSignatureRequired) as caught:
        run(pipeline.fund_job(job.id, REQUESTER))
    assert not isinstance(caught.value, InvocationPreparationBlocked)
    assert job.state is JobState.AWAITING_SIGNATURE
    with TestClient(api.app) as client:
        response = client.post(
            f"/api/v1/jobs/{job.id}/fund", json={"funder": REQUESTER},
            headers={"Authorization": "Bearer test-only-operator-key"},
        )
    detail = response.json()["detail"]
    assert response.status_code == 409
    assert detail["state"] == "awaiting_signature"
    assert detail["invocation"]
    assert job.escrow.funded is False


def test_settlement_missing_provider_is_blocked_not_indeterminate(payment_pipeline, monkeypatch, run):
    pipeline, artifact = payment_pipeline
    job = fully_prepared_job(pipeline, artifact)
    # Simulate a readback-confirmed fund solely to reach the settlement branch.
    job.escrow.funded = True
    job.state = JobState.FUNDED

    async def fake_audit(*args):
        return AuditReport(job_id=job.id, agent_id=artifact.id, agent_name=artifact.name, tier=job.tier)

    monkeypatch.setattr(pipeline.swarm, "run", fake_audit)
    result = run(pipeline.run_job(job.id))
    assert result.state is JobState.PREPARATION_BLOCKED
    assert result.report is not None
    assert result.escrow.tx_ref == ""
    assert result.escrow.settled is False
    assert "provider" in result.error


@pytest.mark.parametrize("requester, expected", [("", JobState.PREPARATION_BLOCKED), (REQUESTER, JobState.AWAITING_SIGNATURE)])
def test_refund_preparation_and_signature_states_are_distinct(payment_pipeline, monkeypatch, run, requester, expected):
    pipeline, artifact = payment_pipeline
    job = fully_prepared_job(pipeline, artifact)
    job.escrow.funded = True
    job.escrow.funder = requester
    job.state = JobState.FUNDED

    async def failing_audit(*args):
        raise RuntimeError("fixture audit failure")

    monkeypatch.setattr(pipeline.swarm, "run", failing_audit)
    result = run(pipeline.run_job(job.id))
    assert result.state is expected
    assert result.escrow.settled is False
    assert bool(result.escrow.tx_ref) is (expected is JobState.AWAITING_SIGNATURE)
