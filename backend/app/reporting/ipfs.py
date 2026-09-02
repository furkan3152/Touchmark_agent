"""IPFS yayımlayıcı.

PINATA_JWT varsa gerçek pinleme yapar; yoksa raporu yerel content-addressed store'a
yazar ve CIDv1-benzeri deterministik bir tanımlayıcı üretir. Her iki durumda da
rapor hash'i zincire yazılabilir ve doğrulanabilir.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

import httpx

from ..config import Settings

# multihash: sha2-256 (0x12), length 32 (0x20)
MULTIHASH_PREFIX = bytes([0x12, 0x20])
# CIDv1 prefix: version 1 (0x01) + raw codec (0x55)
CIDV1_PREFIX = bytes([0x01, 0x55])
B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def _base32_lower(data: bytes) -> str:
    encoded = base64.b32encode(data).decode().rstrip("=").lower()
    return encoded


def local_cid(payload: bytes) -> str:
    """Deterministik, doğrulanabilir yerel tanımlayıcı (CIDv1 raw sha2-256 formatı)."""
    digest = hashlib.sha256(payload).digest()
    raw = CIDV1_PREFIX + MULTIHASH_PREFIX + digest
    return "b" + _base32_lower(raw)


class IpfsPublisher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def store_dir(self) -> Path:
        d = self.settings.data_path / "reports"
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(d, 0o700)
        return d

    async def publish(self, name: str, content: str) -> tuple[str, str]:
        """(cid, uri) döndürür. Pinata varsa gerçek IPFS, yoksa yerel CAS."""
        payload = content.encode("utf-8")
        cid = local_cid(payload)

        # her durumda yerel kopya (denetlenebilirlik ve yeniden servis için)
        local_copy = self.store_dir / f"{cid}.json"
        local_copy.write_bytes(payload)
        os.chmod(local_copy, 0o600)

        if self.settings.ipfs_enabled:
            pinned = await self._pin_to_pinata(name, payload)
            if pinned:
                return pinned, f"{self.settings.ipfs_gateway.rstrip('/')}/{pinned}"

        return cid, f"local-cas://reports/{cid}"

    async def _pin_to_pinata(self, name: str, payload: bytes) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "https://api.pinata.cloud/pinning/pinFileToIPFS",
                    headers={"Authorization": f"Bearer {self.settings.pinata_jwt}"},
                    files={"file": (name, payload, "application/json")},
                )
                resp.raise_for_status()
                return resp.json().get("IpfsHash")
        except Exception:
            return None

    def read(self, cid: str) -> str | None:
        path = self.store_dir / f"{cid}.json"
        if path.exists():
            return path.read_text()
        return None
