from __future__ import annotations

import base64

from stellar_sdk import Keypair

from backend.app.stellar.ownership import canonical_message, sep53_payload_hash, verify_owner

PASSPHRASE = "Test SDF Network ; September 2015"


def test_sep53_official_ascii_vector():
    """SEP-53 Final'daki kanonik ASCII vektörüyle byte uyumluluğu."""
    address = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L"
    signature = base64.b64decode(
        "fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA=="
    )
    Keypair.from_public_key(address).verify(sep53_payload_hash("Hello, World!"), signature)


def test_g_account_ed25519_proof():
    keypair = Keypair.random()
    agent = "C" + "A" * 55
    message = canonical_message(agent, keypair.public_key, PASSPHRASE)
    signature = base64.b64encode(keypair.sign(sep53_payload_hash(message))).decode()
    result = verify_owner(agent, keypair.public_key, signature, PASSPHRASE)
    assert result.verified is True
    assert result.recovered == keypair.public_key


def test_signature_is_bound_to_network_passphrase():
    keypair = Keypair.random()
    message = canonical_message("agent", keypair.public_key, PASSPHRASE)
    signature = base64.b64encode(keypair.sign(sep53_payload_hash(message))).decode()
    result = verify_owner("agent", keypair.public_key, signature, "Public Global Stellar Network")
    assert result.verified is False


def test_c_account_requires_sep45():
    result = verify_owner("agent", "C" + "A" * 55, "c2ln", PASSPHRASE)
    assert result.verified is False
    assert "SEP-45" in result.evidence
