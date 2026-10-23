"""The assets and network markers a Stellar payment is checked against.

An agent that pays in USDC has to name one specific asset: code USDC from Circle's issuer,
or that asset's Stellar Asset Contract (SAC) on the network it signs for. A look-alike code,
an unchecked issuer or the other network's contract id is a different asset. Every contract
id here is derived, not copied: ``Asset(code, issuer).contract_id(passphrase)`` gives the same
value, and backend/tests/test_canonical.py recomputes each one.
"""

from __future__ import annotations

import re

from stellar_sdk import StrKey

MAINNET_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"
#: CAIP-2 ids that x402 and MPP use for Stellar networks.
CAIP2 = {"mainnet": "stellar:pubnet", "testnet": "stellar:testnet"}

USDC_ISSUER = {"mainnet": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
               "testnet": "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"}
USDC_SAC = {"mainnet": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
            "testnet": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"}
XLM_SAC = {"mainnet": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
           "testnet": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"}

#: Values that only exist on one network: seeing one in code says which network it uses.
NETWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "mainnet": (MAINNET_PASSPHRASE, CAIP2["mainnet"], USDC_ISSUER["mainnet"], USDC_SAC["mainnet"],
                XLM_SAC["mainnet"], "horizon.stellar.org", "mainnet.sorobanrpc.com", "soroban-rpc.mainnet"),
    "testnet": (TESTNET_PASSPHRASE, CAIP2["testnet"], USDC_ISSUER["testnet"], USDC_SAC["testnet"],
                XLM_SAC["testnet"], "horizon-testnet.stellar.org", "soroban-testnet.stellar.org",
                "friendbot.stellar.org"),
}

#: A string literal shaped like a StrKey: account (G), contract (C), muxed account (M) or seed (S).
STRKEY_SHAPE = re.compile(r"\b[GCMS][A-Z2-7]{54,68}\b")
_STRKEY_LENGTH = {"G": 56, "C": 56, "S": 56, "M": 69}


def network_of(value: str) -> str | None:
    """'mainnet' or 'testnet' when the value is a marker of one network."""
    for network, markers in NETWORK_MARKERS.items():
        if value in markers:
            return network
    return None


def strkey_valid(value: str) -> bool:
    """Whether a G/C/M/S string is a well-formed StrKey (length, version byte and checksum)."""
    checks = {"G": StrKey.is_valid_ed25519_public_key, "C": StrKey.is_valid_contract,
              "M": StrKey.is_valid_med25519_public_key, "S": StrKey.is_valid_ed25519_secret_seed}
    check = checks.get(value[:1])
    return bool(check and len(value) == _STRKEY_LENGTH[value[0]] and check(value))


def canonical_asset(value: str) -> tuple[str, str] | None:
    """(asset, network) for a known SAC id or USDC issuer, e.g. ('USDC', 'testnet')."""
    for network in ("mainnet", "testnet"):
        if value in (USDC_SAC[network], USDC_ISSUER[network]):
            return "USDC", network
        if value == XLM_SAC[network]:
            return "XLM", network
    return None
