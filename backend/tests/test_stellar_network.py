from __future__ import annotations

import pytest

from backend.app.config import Settings
from backend.app.stellar.networks import NetworkGuardError, resolve_network


def test_testnet_profile_has_official_passphrase():
    network = resolve_network("testnet")
    assert network.passphrase == "Test SDF Network ; September 2015"
    assert network.is_testnet is True


def test_mainnet_is_fail_closed():
    with pytest.raises(NetworkGuardError, match="mainnet kilitli"):
        resolve_network("mainnet")


def test_backend_never_claims_chain_submission(tmp_path):
    settings = Settings(
        stellar_network="testnet",
        agent_registry_contract_id="C" + "A" * 55,
        data_dir=str(tmp_path / "data"),
        event_database=str(tmp_path / "events.db"),
        _env_file=None,
    )
    assert settings.rpc_enabled is True
    assert settings.chain_enabled is False
    assert settings.external_signing_required is True

