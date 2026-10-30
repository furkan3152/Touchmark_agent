"""Names from before the AgentVeritas -> Touchmark rename keep working as fallbacks."""
from __future__ import annotations

import json

from backend.app.config import Settings, default_database_url
from backend.app.ingestion.service import IngestionService


def _settings(**values) -> Settings:
    return Settings(_env_file=None, stellar_network="offline", **values)


def test_database_defaults_to_touchmark_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert default_database_url() == "sqlite:///./data/touchmark.db"
    assert _settings(database_url="").database_url == "sqlite:///./data/touchmark.db"


def test_existing_legacy_database_stays_in_use(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "agentveritas-stellar.db").write_bytes(b"")
    assert default_database_url() == "sqlite:///./data/agentveritas-stellar.db"
    assert _settings(database_url="  ").database_url == "sqlite:///./data/agentveritas-stellar.db"


def test_docker_legacy_database_stays_in_use(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "agentveritas.db").write_bytes(b"")
    assert default_database_url() == "sqlite:///./data/agentveritas.db"


def test_new_database_wins_over_legacy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "agentveritas-stellar.db").write_bytes(b"")
    (tmp_path / "data" / "touchmark.db").write_bytes(b"")
    assert default_database_url() == "sqlite:///./data/touchmark.db"


def test_explicit_database_url_is_kept(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "agentveritas.db").write_bytes(b"")
    assert _settings(database_url="sqlite:////srv/custom.db").database_url == "sqlite:////srv/custom.db"


def test_agent_manifest_read_from_touchmark_json_and_legacy_name():
    for name in ("touchmark.json", "agentveritas.json"):
        files = {name: json.dumps({"name": "reader", "capabilities": ["read"]})}
        assert IngestionService._parse_manifest(files)["name"] == "reader"
