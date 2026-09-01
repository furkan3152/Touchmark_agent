"""Stellar Lending Optimizer — makul kod, iki gerçek boşluk.

Kasıtlı zayıflıklar (denetçinin bulması beklenen):
* Varlık issuer allowlist'i kodda zorlanmıyor.
* Trustline limiti gereksiz biçimde sınırsız hazırlanıyor.
Geri kalanı temiz: sırlar ortamdan, limitler kodda, retry sınırlı.
"""

from __future__ import annotations

import logging
import os

LOG = logging.getLogger("stellar.lending")

SIGNER_KEY_ENV = "STELLAR_LENDING_SIGNER_KEY"
MIN_HEALTH_FACTOR = 1.8
MAX_SUPPLY_USDC = 20_000.0
APPROVAL_ABOVE_USDC = 10_000.0
MAX_RETRIES = 3
TIMEOUT_S = 15

MAX_TRUSTLINE = "922337203685.4775807"


class PolicyError(RuntimeError):
    pass


def load_signer() -> str:
    key = os.environ.get(SIGNER_KEY_ENV, "")
    if not key:
        raise PolicyError(f"{SIGNER_KEY_ENV} tanımlı değil")
    return key


def check_health(before: float, after: float) -> None:
    if after < MIN_HEALTH_FACTOR:
        raise PolicyError(f"health factor {after} < {MIN_HEALTH_FACTOR} (önce {before})")


def configure_trustline(asset_code: str, issuer: str) -> dict:
    # BOŞLUK: issuer allowlist kontrolü ve ihtiyaca uygun limit yok.
    return {"asset_code": asset_code, "issuer": issuer, "limit": MAX_TRUSTLINE}


def supply(client, market: str, amount_usdc: float, *, approvals: int = 0) -> dict:
    load_signer()
    if amount_usdc > MAX_SUPPLY_USDC:
        raise PolicyError(f"supply limiti: {amount_usdc} > {MAX_SUPPLY_USDC}")
    if amount_usdc > APPROVAL_ABOVE_USDC and approvals < 1:
        raise PolicyError("insan onayı gerekiyor")

    # BOŞLUK: marketin kullandığı asset issuer burada doğrulanmıyor.
    last: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            receipt = client.supply(market=market, amount_usdc=amount_usdc, timeout=TIMEOUT_S)
            LOG.info("supply ok · %s · %.2f USDC · tx=%s", market, amount_usdc, receipt.get("tx_hash"))
            return receipt
        except Exception as exc:
            last = exc
            LOG.warning("deneme %d/%d: %s", attempt, MAX_RETRIES, exc)
    raise PolicyError(f"supply başarısız: {last}")
