"""Stellar Payroll Agent — üretim niyetiyle yazılmış referans uygulama.

Güvenlik duruşu:
* Sırlar yalnızca ortam değişkeninden okunur, koda gömülmez.
* Her ödeme idempotency anahtarı taşır; tekrar denemede çifte ödeme olmaz.
* XLM fee/minimum-balance rezervi işlem öncesi kontrol edilir.
* Varlık issuer allowlist'i ve alıcının trustline durumu doğrulanır.
* Alıcı allowlist + yaptırım taramasından geçer.
* Harcama limitleri kod içinde zorlanır, prompt'a bırakılmaz.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

LOG = logging.getLogger("stellar.payroll")

#: Sırlar ortamdan gelir; kaynak kodda anahtar tutulmaz.
SIGNER_KEY_ENV = "STELLAR_PAYROLL_SIGNER_KEY"
HORIZON_URL = os.environ.get("STELLAR_HORIZON_URL", "https://horizon-testnet.stellar.org")

MAX_BATCH_USDC = 5_000.0
MAX_DAILY_USDC = 25_000.0
MAX_RECIPIENTS = MAX_OPERATIONS_PER_TX = 100
DUAL_APPROVAL_ABOVE_USDC = 10_000.0
#: Stellar işlem ücretleri ve minimum bakiye için XLM rezervi tutulur.
MIN_XLM_RESERVE = 2.0
REQUEST_TIMEOUT_S = 20
MAX_RETRIES = 3


class PolicyError(RuntimeError):
    """Politika ihlali — işlem başlatılmaz."""


@dataclass(frozen=True)
class Payment:
    recipient: str
    amount_usdc: float
    memo: str


def idempotency_key(batch_id: str, payment: Payment) -> str:
    """(batch, alıcı, tutar) üçlüsünden deterministik anahtar.

    Aynı batch iki kez gönderilirse anahtar aynı olur ve kontrat tarafında
    tekrar reddedilir; retry çifte ödemeye dönüşemez.
    """
    seed = f"{batch_id}:{payment.recipient.lower()}:{payment.amount_usdc:.6f}"
    return hashlib.sha256(seed.encode()).hexdigest()


def load_signer() -> str:
    key = os.environ.get(SIGNER_KEY_ENV, "")
    if not key:
        raise PolicyError(f"imzalayıcı anahtarı yok: {SIGNER_KEY_ENV} tanımlanmalı")
    return key


def assert_xlm_reserve(balance_xlm: float, minimum_balance_xlm: float, fee_xlm: float) -> None:
    """Fee ve account minimum balance düşüldükten sonra güvenli XLM rezervi bırakır."""
    spendable = balance_xlm - minimum_balance_xlm - fee_xlm
    if spendable < MIN_XLM_RESERVE:
        raise PolicyError(f"XLM rezervi yetersiz: kullanılabilir={spendable:.7f}")


def check_policy(batch_id: str, payments: list[Payment], spent_today_usdc: float) -> None:
    if len(payments) > MAX_RECIPIENTS:
        raise PolicyError(f"alıcı sayısı limiti: {len(payments)} > {MAX_RECIPIENTS}")
    total = round(sum(p.amount_usdc for p in payments), 6)
    if total > MAX_BATCH_USDC:
        raise PolicyError(f"batch limiti: {total} > {MAX_BATCH_USDC} USDC")
    if spent_today_usdc + total > MAX_DAILY_USDC:
        raise PolicyError(f"günlük limit: {spent_today_usdc + total} > {MAX_DAILY_USDC} USDC")
    for p in payments:
        if not p.memo:
            raise PolicyError(f"memo yok: {p.recipient}")
    LOG.info("policy ok · batch=%s · alıcı=%d · toplam=%.2f USDC", batch_id, len(payments), total)


def needs_dual_approval(payments: list[Payment]) -> bool:
    return sum(p.amount_usdc for p in payments) > DUAL_APPROVAL_ABOVE_USDC


def screen_recipient(address: str, allowlist: frozenset[str], sanctions: frozenset[str]) -> None:
    """Allowlist + yaptırım kontrolü; ikisi de geçilmeden ödeme yapılmaz."""
    addr = address.lower()
    if addr not in allowlist:
        raise PolicyError(f"alıcı allowlist'te değil: {address}")
    if addr in sanctions:
        raise PolicyError(f"alıcı yaptırım listesinde: {address}")


def verify_asset(asset_code: str, issuer: str, approved_issuers: frozenset[str]) -> None:
    """Sembol tek başına kimlik değildir; issuer allowlist'i zorunludur."""
    if asset_code != "USDC" or issuer not in approved_issuers:
        raise PolicyError("onaylanmamış varlık veya issuer")


def send_batch(
    batch_id: str,
    payments: list[Payment],
    *,
    balance_xlm: float,
    minimum_balance_xlm: float,
    fee_xlm: float,
    spent_today_usdc: float,
    allowlist: frozenset[str],
    sanctions: frozenset[str],
    asset_code: str,
    asset_issuer: str,
    approved_issuers: frozenset[str],
    approvals: int,
    client,
) -> list[dict]:
    """Politikayı zorla, sonra gönder. Hata durumunda sınırlı retry."""
    load_signer()
    assert_xlm_reserve(balance_xlm, minimum_balance_xlm, fee_xlm)
    verify_asset(asset_code, asset_issuer, approved_issuers)
    check_policy(batch_id, payments, spent_today_usdc)
    if needs_dual_approval(payments) and approvals < 2:
        raise PolicyError("iki insan onayı gerekiyor")

    receipts: list[dict] = []
    for payment in payments:
        screen_recipient(payment.recipient, allowlist, sanctions)
        if not client.has_trustline(payment.recipient, asset_code, asset_issuer):
            raise PolicyError(f"alıcı USDC trustline'ı yok: {payment.recipient}")
        key = idempotency_key(batch_id, payment)

        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                receipt = client.transfer(
                    to=payment.recipient,
                    amount_usdc=payment.amount_usdc,
                    memo=payment.memo,
                    idempotency_key=key,
                    timeout=REQUEST_TIMEOUT_S,
                )
                # Sır sızdırmadan denetlenebilir kayıt: anahtar kısaltılır.
                LOG.info(
                    "ödendi · %s · %.2f USDC · idem=%s… · tx=%s",
                    payment.recipient,
                    payment.amount_usdc,
                    key[:12],
                    receipt.get("tx_hash"),
                )
                receipts.append({**receipt, "idempotency_key": key})
                break
            except Exception as exc:  # ağ/geçici hata
                last_error = exc
                LOG.warning("deneme %d/%d başarısız: %s", attempt, MAX_RETRIES, exc)
        else:
            # Sonsuz döngü yok: sahibine bildirilir ve batch durur.
            raise PolicyError(f"{payment.recipient} için {MAX_RETRIES} deneme başarısız: {last_error}")

    return receipts
