"""Every canonical contract id is recomputed from its asset and network, never trusted as
copied text."""

from __future__ import annotations

from stellar_sdk import Asset

from backend.app.stellar import canonical


def test_contract_ids_are_the_assets_on_their_network():
    for network, passphrase in (("mainnet", canonical.MAINNET_PASSPHRASE), ("testnet", canonical.TESTNET_PASSPHRASE)):
        assert Asset("USDC", canonical.USDC_ISSUER[network]).contract_id(passphrase) == canonical.USDC_SAC[network]
        assert Asset.native().contract_id(passphrase) == canonical.XLM_SAC[network]
        assert canonical.network_of(canonical.USDC_SAC[network]) == network
        assert canonical.canonical_asset(canonical.USDC_SAC[network]) == ("USDC", network)


def test_strkey_check_rejects_look_alikes():
    assert canonical.strkey_valid(canonical.USDC_SAC["testnet"])
    look_alike = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWUIE3USSTHZX5ACUSDC"   # right shape, bad checksum
    assert canonical.STRKEY_SHAPE.fullmatch(look_alike) and not canonical.strkey_valid(look_alike)
    assert not canonical.strkey_valid(canonical.USDC_SAC["mainnet"][:-1])
