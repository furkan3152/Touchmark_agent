"""Test fixture'ları — tüm dış servisler kapalı, tamamen deterministik mod."""

from __future__ import annotations

import asyncio
import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from backend.app.config import Settings

# Test modülleri `backend.app.api`yi import ederken oluşan global servisler de
# repo veya kullanıcı `.env` veri yoluna yazmamalıdır. Fixture'dan önce güvenli,
# süreç-özel yollar kurulur ve Python kapanışında temizlenir.
_TEST_PROCESS_DATA = Path(tempfile.mkdtemp(prefix="agentveritas-stellar-pytest-"))
os.environ["DATA_DIR"] = str(_TEST_PROCESS_DATA)
os.environ["EVENT_DATABASE"] = str(_TEST_PROCESS_DATA / "events.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_PROCESS_DATA / 'agentveritas.db'}"
atexit.register(shutil.rmtree, _TEST_PROCESS_DATA, ignore_errors=True)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Tamamen çevrimdışı: LLM / RPC / IPFS / screening kapalı.

    `stellar_network="offline"` seçilir; testler RPC/Horizon'a çıkmaz.
    """
    return Settings(
        llm_provider="",
        llm_api_key="",
        stellar_network="offline",
        stellar_rpc_url="",
        pinata_jwt="",
        screening_provider="none",
        allow_local_path_ingest=True,
        data_dir=str(tmp_path / "data"),
        event_database=str(tmp_path / "events.db"),
        _env_file=None,
    )


@pytest.fixture
def testnet_settings(tmp_path) -> Settings:
    """Gerçek Stellar testnet profili (yalnızca okuma; testler doğrudan kullanmaz)."""
    return Settings(
        llm_provider="",
        stellar_network="testnet",
        pinata_jwt="",
        screening_provider="none",
        allow_local_path_ingest=True,
        data_dir=str(tmp_path / "data"),
        event_database=str(tmp_path / "events.db"),
        _env_file=None,
    )


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def run() -> callable:
    """Senkron testlerden coroutine çalıştırmak için küçük yardımcı."""

    def _run(coro):
        return asyncio.run(coro)

    return _run
