"""Ingestion girdi kapısı testleri — yol kaçışı, sır dosyaları, SSRF.

Bu testler `backend/app/ingestion/guards.py` içindeki iki değişmezi kilitler:

1. `local_path` proje kökünün dışına çıkamaz ve kök içinde olsa dahi sır
   taşıyan yolları (operatör keystore'u) okumaz.
2. `repo_url` / `endpoint_url` yalnızca http/https ve yalnızca genel internet
   adreslerini hedefleyebilir.

Hiçbiri ağa çıkmaz: DNS çözümleyici enjekte edilir.
"""

from __future__ import annotations

import base64
import io
import socket
import zipfile

import pytest

from backend.app.config import Settings
from backend.app.ingestion import IngestionService, IngestRequest
from backend.app.ingestion.guards import (
    IngestGuardError,
    guard_cid,
    guard_remote_url,
    resolve_ingest_path,
)


# --------------------------------------------------------------- yerel yollar
def test_path_within_root_is_accepted(tmp_path):
    (tmp_path / "agent").mkdir()
    assert resolve_ingest_path("agent", tmp_path) == (tmp_path / "agent").resolve()


def test_absolute_path_outside_root_is_rejected(tmp_path):
    with pytest.raises(IngestGuardError, match="kökün dışında"):
        resolve_ingest_path("/etc", tmp_path)


def test_dotdot_escape_is_rejected(tmp_path):
    (tmp_path / "inner").mkdir()
    with pytest.raises(IngestGuardError, match="kökün dışında"):
        resolve_ingest_path("inner/../../..", tmp_path)


def test_symlink_pointing_outside_root_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside_target"
    outside.mkdir(exist_ok=True)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(IngestGuardError, match="kökün dışında"):
        resolve_ingest_path("link", root)


def test_missing_directory_is_rejected(tmp_path):
    with pytest.raises(IngestGuardError, match="bulunamadı"):
        resolve_ingest_path("yok-boyle-bir-dizin", tmp_path)


def test_file_instead_of_directory_is_rejected(tmp_path):
    (tmp_path / "agent.json").write_text("{}")
    with pytest.raises(IngestGuardError, match="dizin olmalı"):
        resolve_ingest_path("agent.json", tmp_path)


# ------------------------------------------------------------ sır dosyaları
def test_keystore_is_not_read_as_agent_code(settings, run, tmp_path):
    """Regresyon: `local_path=data/keystore` operatör özel anahtarını okuyordu."""
    root = tmp_path / "proj"
    keystore = root / "data" / "keystore"
    keystore.mkdir(parents=True)
    (keystore / "attestor.json").write_text('{"private_key": "0xdeadbeef"}')
    (root / "agent.json").write_text('{"name":"Kapı Testi","capabilities":["x"]}')

    scoped = settings.model_copy(update={"ingest_root": str(root)})
    artifact = run(IngestionService(scoped).ingest(IngestRequest(kind="repo", local_path=".")))

    joined = " ".join(artifact.code_files) + " ".join(artifact.code_files.values())
    assert "attestor.json" not in joined
    assert "0xdeadbeef" not in joined


def test_secret_names_are_case_insensitive_and_env_templates_remain_auditable(
    settings, run, tmp_path
):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "agent.json").write_text('{"name":"Case Guard"}')
    (root / ".ENV.PRODUCTION").write_text("API_KEY=must-not-leak")
    (root / "Signer.JSON").write_text('{"secret":"must-not-leak"}')
    (root / "operator.PEM").write_text("must-not-leak")
    (root / ".env.example").write_text("API_KEY=")

    scoped = settings.model_copy(update={"ingest_root": str(root)})
    artifact = run(IngestionService(scoped).ingest(IngestRequest(kind="repo", local_path=".")))

    assert ".env.example" in artifact.code_files
    assert ".ENV.PRODUCTION" not in artifact.code_files
    assert "Signer.JSON" not in artifact.code_files
    assert "operator.PEM" not in artifact.code_files
    assert "must-not-leak" not in " ".join(artifact.code_files.values())


def test_local_path_can_be_disabled(settings, run, tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "agent.json").write_text("{}")
    scoped = settings.model_copy(
        update={"ingest_root": str(root), "allow_local_path_ingest": False}
    )
    with pytest.raises(IngestGuardError, match="kapalı"):
        run(IngestionService(scoped).ingest(IngestRequest(kind="repo", local_path=".")))


def test_ingest_root_defaults_to_project_root():
    """Varsayılan kök proje köküdür — `examples/` denetlenebilir kalmalı."""
    s = Settings(_env_file=None, stellar_network="offline")
    assert (s.ingest_root_path / "examples").is_dir()
    assert (s.ingest_root_path / "backend" / "app").is_dir()


# ---------------------------------------------------------------------- SSRF
def _resolver_for(ip: str):
    """`socket.getaddrinfo` yerine sabit IP döndüren test çözümleyicisi."""

    def _resolve(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return _resolve


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/api/v1/chain/wallet",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/",
        "http://[::1]/",
    ],
)
def test_internal_targets_are_rejected(url):
    with pytest.raises(IngestGuardError, match="iç ağ adresi"):
        guard_remote_url(url, resolver=_resolver_for("127.0.0.1"))


def test_public_target_is_accepted():
    assert guard_remote_url(
        "https://example.com/agent.zip", resolver=_resolver_for("93.184.216.34")
    )


def test_dns_rebinding_to_private_ip_is_rejected():
    """Genel görünen bir isim özel IP'ye çözümlenirse reddedilir."""
    with pytest.raises(IngestGuardError, match="iç ağ adresi"):
        guard_remote_url("https://evil.example.com/x", resolver=_resolver_for("10.1.2.3"))


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://x/1", "ftp://host/f", "/etc/passwd"]
)
def test_non_http_schemes_are_rejected(url):
    with pytest.raises(IngestGuardError, match="desteklenmeyen şema"):
        guard_remote_url(url, resolver=_resolver_for("93.184.216.34"))


def test_credentials_in_url_are_rejected():
    with pytest.raises(IngestGuardError, match="kimlik bilgisi"):
        guard_remote_url(
            "https://user:pass@example.com/x", resolver=_resolver_for("93.184.216.34")
        )


def test_endpoint_ingest_rejects_internal_url(settings, run):
    svc = IngestionService(settings)
    with pytest.raises(IngestGuardError):
        run(svc.ingest(IngestRequest(kind="endpoint", endpoint_url="http://127.0.0.1:8000/")))


# ----------------------------------------------------------------- IPFS CID
@pytest.mark.parametrize("cid", ["../../etc/passwd", "abc/../def", "", "a b"])
def test_bad_cid_is_rejected(cid):
    with pytest.raises(IngestGuardError, match="geçersiz IPFS CID"):
        guard_cid(cid)


def test_good_cid_is_accepted():
    cid = "bafkreiabqxh6tvb4yyin2iq4sstjr7jcrctmzkfm6l6hmc2o32pyoaoq6q"
    assert guard_cid(cid) == cid


# ------------------------------------------------------------------- zip yolu
def test_zip_path_traversal_entries_are_skipped(settings, run):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "agent.json", '{"name":"Zip Kapı","capabilities":["x"],"system_prompt":"careful"}'
        )
        zf.writestr("../../../etc/passwd.txt", "root:x:0:0")
        zf.writestr("keystore/attestor.json", '{"private_key":"0xbad"}')
        zf.writestr("main.py", "def run():\n    return 1\n")
    payload = base64.b64encode(buf.getvalue()).decode()

    artifact = run(IngestionService(settings).ingest(
        IngestRequest(kind="repo", zip_base64=payload)
    ))

    names = " ".join(artifact.code_files)
    assert "main.py" in names
    assert "passwd" not in names
    assert "attestor.json" not in names
    assert "0xbad" not in " ".join(artifact.code_files.values())


def test_zip_secret_names_are_case_insensitive(settings, run):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("agent.json", '{"name":"Zip Case Guard"}')
        zf.writestr(".ENV.PRODUCTION", "TOKEN=must-not-leak")
        zf.writestr("Keys/Operator.PEM", "must-not-leak")
        zf.writestr("STELLAR-CLI/identity.toml", "secret=must-not-leak")
    payload = base64.b64encode(buf.getvalue()).decode()

    artifact = run(
        IngestionService(settings).ingest(IngestRequest(kind="repo", zip_base64=payload))
    )
    assert set(artifact.code_files) == {"agent.json"}


def test_invalid_zip_gives_clear_error(settings, run):
    svc = IngestionService(settings)
    with pytest.raises(IngestGuardError):
        run(svc.ingest(IngestRequest(kind="repo", zip_base64="bu-base64-degil!!")))

