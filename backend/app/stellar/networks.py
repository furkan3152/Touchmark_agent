"""Stellar ağ profilleri ve mainnet güvenlik kilidi."""

from __future__ import annotations

from dataclasses import dataclass


class NetworkGuardError(ValueError):
    pass


@dataclass(frozen=True)
class StellarNetwork:
    key: str
    name: str
    passphrase: str
    rpc_url: str
    horizon_url: str
    explorer: str
    friendbot_url: str = ""
    is_testnet: bool = False

    def explorer_account(self, account: str) -> str:
        return f"{self.explorer}/account/{account}" if self.explorer and account else ""

    def explorer_contract(self, contract_id: str) -> str:
        return f"{self.explorer}/contract/{contract_id}" if self.explorer and contract_id else ""

    def explorer_transaction(self, tx_hash: str) -> str:
        return f"{self.explorer}/tx/{tx_hash}" if self.explorer and tx_hash else ""


OFFLINE = "offline"
TESTNET = "testnet"
MAINNET = "mainnet"

NETWORKS = {
    OFFLINE: StellarNetwork(OFFLINE, "Offline", "", "", "", "", is_testnet=True),
    TESTNET: StellarNetwork(
        TESTNET,
        "Stellar Testnet",
        "Test SDF Network ; September 2015",
        "https://soroban-testnet.stellar.org",
        "https://horizon-testnet.stellar.org",
        "https://stellar.expert/explorer/testnet",
        "https://friendbot.stellar.org",
        True,
    ),
    MAINNET: StellarNetwork(
        MAINNET,
        "Stellar Mainnet",
        "Public Global Stellar Network ; September 2015",
        "https://mainnet.sorobanrpc.com",
        "https://horizon.stellar.org",
        "https://stellar.expert/explorer/public",
    ),
}


def resolve_network(key: str, *, allow_mainnet: bool = False) -> StellarNetwork:
    normalized = (key or "").strip().lower()
    if normalized not in NETWORKS:
        raise NetworkGuardError(f"bilinmeyen Stellar ağı: {key}")
    if normalized == MAINNET and not allow_mainnet:
        raise NetworkGuardError("Stellar mainnet kilitli; ALLOW_MAINNET=true açıkça gerekli")
    return NETWORKS[normalized]
