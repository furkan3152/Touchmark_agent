import json

import pytest

from backend.app.config import Settings
from backend.app.services.store import Store


def _settings(tmp_path):
    settings = Settings(stellar_network="offline", data_dir=str(tmp_path / "data"),
                        event_database=str(tmp_path / "events.db"), _env_file=None)
    settings.data_path.mkdir(parents=True, exist_ok=True)
    return settings


def test_unreadable_state_refuses_to_start_instead_of_erasing_it(tmp_path):
    settings = _settings(tmp_path)
    path = settings.data_path / "state.json"
    path.write_text("{truncated")
    with pytest.raises(RuntimeError, match="unreadable"):
        Store(settings)
    assert path.read_text() == "{truncated"


def test_backup_is_used_when_primary_is_corrupt(tmp_path):
    settings = _settings(tmp_path)
    store = Store(settings)
    store.flush()
    store.flush()  # second write rotates the first into the backup
    (settings.data_path / "state.json").write_text("{truncated")
    assert json.loads((settings.data_path / "state.json.bak").read_text()) == {
        "agents": {}, "jobs": {}, "subscriptions": {}}
    Store(settings)  # loads the backup instead of failing


def test_records_that_fail_validation_are_preserved_on_save(tmp_path):
    settings = _settings(tmp_path)
    path = settings.data_path / "state.json"
    raw = {"agents": {}, "jobs": {"legacy": {"unexpected": "shape"}}, "subscriptions": {}}
    path.write_text(json.dumps(raw))
    store = Store(settings)
    assert store.get_job("legacy") is None
    store.flush()
    assert json.loads(path.read_text())["jobs"]["legacy"] == {"unexpected": "shape"}
    assert (path.stat().st_mode & 0o777) == 0o600
