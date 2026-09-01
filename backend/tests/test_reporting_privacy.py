from backend.app.models import AgentArtifact, AuditReport, AuditTier, SourceKind
from backend.app.reporting.generator import report_to_dict


def test_private_report_masks_local_source_reference():
    secret_path = "/home/alice/private-client/internal-agent"
    artifact = AgentArtifact(
        source_kind=SourceKind.REPO,
        source_ref=secret_path,
        name="private-agent",
        privacy_mode=True,
    )
    report = AuditReport(
        job_id="job-test",
        agent_id=artifact.id,
        agent_name=artifact.name,
        tier=AuditTier.BASIC,
    )

    payload = report_to_dict(report, artifact)
    assert secret_path not in repr(payload)
    assert payload["agent"]["source_ref"].startswith("[privacy-mode:")


def test_public_report_keeps_source_reference():
    artifact = AgentArtifact(
        source_kind=SourceKind.REPO,
        source_ref="https://example.invalid/public-agent",
        name="public-agent",
        privacy_mode=False,
    )
    report = AuditReport(
        job_id="job-test",
        agent_id=artifact.id,
        agent_name=artifact.name,
        tier=AuditTier.BASIC,
    )

    assert report_to_dict(report, artifact)["agent"]["source_ref"] == artifact.source_ref
