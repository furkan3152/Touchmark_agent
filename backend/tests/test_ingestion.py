"""Ingestion tests — normalization of 4 loading paths into a single AgentArtifact."""

from __future__ import annotations

import base64
import io
import zipfile

import pytest

from backend.app.ingestion import IngestionService, IngestRequest
from backend.app.ingestion.templates import TEMPLATES, list_templates
from backend.app.models import SourceKind

ADDR = "GCIUWCHH4IDGEUSF4XU5SBEIL7IG6CIJ7SSMJOWYS7WXONDBI3BVU44T"


# ------------------------------------------------------------------ validasyon
def test_onchain_requires_identifier():
    with pytest.raises(ValueError):
        IngestRequest(kind="onchain_address")


def test_onchain_rejects_bad_strkey_checksum():
    with pytest.raises(ValueError, match="checksum"):
        IngestRequest(kind="onchain_address", address="G" + "A" * 55)


def test_repo_requires_source():
    with pytest.raises(ValueError):
        IngestRequest(kind="repo")


def test_endpoint_requires_url():
    with pytest.raises(ValueError):
        IngestRequest(kind="endpoint")


def test_wizard_requires_template_or_prompt():
    with pytest.raises(ValueError):
        IngestRequest(kind="wizard")


# ---------------------------------------------------------------- 1) on-chain
def test_ingest_onchain_address(settings, run):
    svc = IngestionService(settings)
    artifact = run(svc.ingest(IngestRequest(kind="onchain_address", address=ADDR)))

    assert artifact.source_kind is SourceKind.ONCHAIN_ADDRESS
    assert artifact.agent_wallet == ADDR
    # RPC/Horizon yok → veri uydurulmaz.
    assert artifact.onchain.data_source == "none"


def test_offline_onchain_activity_is_not_invented(settings, run):
    svc = IngestionService(settings)
    a = run(svc.ingest(IngestRequest(kind="onchain_address", address=ADDR)))
    b = run(svc.ingest(IngestRequest(kind="onchain_address", address=ADDR)))
    assert a.onchain.tx_count == b.onchain.tx_count == 0
    assert a.onchain.top_counterparty_share == b.onchain.top_counterparty_share == 0.0
    assert a.onchain.data_source == b.onchain.data_source == "none"


# -------------------------------------------------------------------- 2) repo
def test_ingest_local_path_reads_code(settings, run, repo_root):
    svc = IngestionService(settings)
    artifact = run(
        svc.ingest(
            IngestRequest(kind="repo", local_path=str(repo_root / "examples" / "vulnerable_agent"))
        )
    )

    assert artifact.source_kind is SourceKind.REPO
    assert artifact.code_files, "kod dosyaları okunmalı"
    assert artifact.system_prompt, "system prompt bulunmalı"
    assert artifact.dependencies, "requirements.txt parse edilmeli"


def test_ingest_safe_agent_manifest(settings, run, repo_root):
    svc = IngestionService(settings)
    artifact = run(
        svc.ingest(IngestRequest(kind="repo", local_path=str(repo_root / "examples" / "safe_agent")))
    )
    assert artifact.name != "unnamed-agent"
    assert artifact.tools, "agent.json içindeki araçlar okunmalı"


def test_ingest_zip_base64(settings, run):
    buf = io.BytesIO()
    manifest = (
        '{"name":"Zip Agent","description":"test",'
        '"system_prompt":"You are a careful agent. Never move funds without approval.",'
        '"capabilities":["report"],"tools":[{"name":"read","scopes":["read:data"]}]}'
    )
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("agent.json", manifest)
        zf.writestr("main.py", "def run():\n    return 1\n")
    payload = base64.b64encode(buf.getvalue()).decode()

    svc = IngestionService(settings)
    artifact = run(svc.ingest(IngestRequest(kind="repo", zip_base64=payload)))

    assert artifact.name == "Zip Agent"
    assert "main.py" in " ".join(artifact.code_files)


def test_missing_local_path_raises(settings, run):
    svc = IngestionService(settings)
    with pytest.raises(Exception):
        run(svc.ingest(IngestRequest(kind="repo", local_path="/tmp/kesinlikle-yok-12345")))


# --------------------------------------------------------------- 4) sihirbaz
@pytest.mark.parametrize("key", list(TEMPLATES))
def test_all_templates_ingest(settings, run, key):
    svc = IngestionService(settings)
    artifact = run(svc.ingest(IngestRequest(kind="wizard", template=key)))

    assert artifact.source_kind is SourceKind.WIZARD
    assert artifact.system_prompt
    assert artifact.declared_capabilities


def test_wizard_user_input_overrides_template(settings, run):
    svc = IngestionService(settings)
    artifact = run(
        svc.ingest(
            IngestRequest(
                kind="wizard",
                template="trading_agent",
                name="Benim Ajanım",
                agent_wallet=ADDR,
                domain="trading",
            )
        )
    )
    assert artifact.name == "Benim Ajanım"
    assert artifact.agent_wallet == ADDR
    assert artifact.domain == "trading"


def test_template_listing_shape():
    rows = list_templates()
    assert rows
    for row in rows:
        assert {"key", "name", "description", "capabilities"} <= set(row)


# --------------------------------------------------------------- text surface
def test_text_surface_includes_prompt_and_code(settings, run, repo_root):
    svc = IngestionService(settings)
    artifact = run(
        svc.ingest(
            IngestRequest(kind="repo", local_path=str(repo_root / "examples" / "vulnerable_agent"))
        )
    )
    surface = artifact.text_surface()
    assert artifact.system_prompt[:30] in surface
    assert len(surface) > 200
