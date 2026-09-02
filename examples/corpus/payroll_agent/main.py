"""Stellar Payroll Agent — reference implementation written with production intent.

Security posture:
* Secrets are only read from environment variables, never embedded in code.
* Each payment carries an idempotency key; retries do not result in double payments.
* XLM fee/minimum-balance reserve is checked before the transaction.
* Asset issuer allowlist and recipient's trustline status are verified.
* Recipient passes allowlist + sanction screening.
* Spending limits are enforced in code, not left to the prompt.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

LOG = logging.getLogger("stellar.payroll")

#: Secrets come from the environment; no keys are kept in the source code.
SIGNER_KEY_ENV = "STELLAR_PAYROLL_SIGNER_KEY"
HORIZON_URL = os.environ.get("STELLAR_HORIZON_URL", "https://horizon-testnet.stellar.org")

MAX_BATCH_USDC = 5_000.0
MAX_DAILY_USDC = 25_000.0
MAX_RECIPIENTS = MAX_OPERATIONS_PER_TX = 100
DUAL_APPROVAL_ABOVE_USDC = 10_000.0
#: XLM reserve is maintained for Stellar transaction fees and minimum balance.
MIN_XLM_RESERVE = 2.0
REQUEST_TIMEOUT_S = 20
MAX_RETRIES = 3


class PolicyError(RuntimeError):
    """Policy violation — transaction will not be initiated."""


@dataclass(frozen=True)
class Payment:
    recipient: str
    amount_usdc: float
    memo: str


def idempotency_key(batch_id: str, payment: Payment) -> str:
    """Deterministic key from the (batch, recipient, amount) tuple.

    If the same batch is sent twice, the key will be the same and will be
    rejected again on the contract side; a retry cannot result in a double payment.
    """
    seed = f"{batch_id}:{payment.recipient.lower()}:{payment.amount_usdc:.6f}"
    return hashlib.sha256(seed.encode()).hexdigest()


def load_signer() -> str:
    key = os.environ.get(SIGNER_KEY_ENV, "")
    if not key:
        raise PolicyError(f"no signer key: {SIGNER_KEY_ENV} must be defined")
    return key


def assert_xlm_reserve(balance_xlm: float, minimum_balance_xlm: float, fee_xlm: float) -> None:
    """Leaves a secure XLM reserve after deducting the fee and account minimum balance."""
    spendable = balance_xlm - minimum_balance_xlm - fee_xlm
    if spendable < MIN_XLM_RESERVE:
        raise PolicyError(f"insufficient XLM reserve: available={spendable:.7f}")


def check_policy(batch_id: str, payments: list[Payment], spent_today_usdc: float) -> None:
    if len(payments) > MAX_RECIPIENTS:
        raise PolicyError(f"recipient count limit: {len(payments)} > {MAX_RECIPIENTS}")
    total = round(sum(p.amount_usdc for p in payments), 6)
    if total > MAX_BATCH_USDC:
        raise PolicyError(f"batch limit: {total} > {MAX_BATCH_USDC} USDC")
    if spent_today_usdc + total > MAX_DAILY_USDC:
        raise PolicyError(f"daily limit: {spent_today_usdc + total} > {MAX_DAILY_USDC} USDC")
    for p in payments:
        if not p.memo:
            raise PolicyError(f"missing memo: {p.recipient}")
    LOG.info("policy ok · batch=%s · recipients=%d · total=%.2f USDC", batch_id, len(payments), total)


def needs_dual_approval(payments: list[Payment]) -> bool:
    return sum(p.amount_usdc for p in payments) > DUAL_APPROVAL_ABOVE_USDC


def screen_recipient(address: str, allowlist: frozenset[str], sanctions: frozenset[str]) -> None:
    """Allowlist + sanction check; payment is not made unless both are passed."""
    addr = address.lower()
    if addr not in allowlist:
        raise PolicyError(f"recipient not in allowlist: {address}")
    if addr in sanctions:
        raise PolicyError(f"recipient is on sanction list: {address}")


def verify_asset(asset_code: str, issuer: str, approved_issuers: frozenset[str]) -> None:
    """Symbol alone is not identity; an issuer allowlist is mandatory."""
    if asset_code != "USDC" or issuer not in approved_issuers:
        raise PolicyError("unapproved asset or issuer")


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
    """Enforce policy, then send. Limited retry on error."""
    load_signer()
    assert_xlm_reserve(balance_xlm, minimum_balance_xlm, fee_xlm)
    verify_asset(asset_code, asset_issuer, approved_issuers)
    check_policy(batch_id, payments, spent_today_usdc)
    if needs_dual_approval(payments) and approvals < 2:
        raise PolicyError("requires two human approvals")

    receipts: list[dict] = []
    for payment in payments:
        screen_recipient(payment.recipient, allowlist, sanctions)
        if not client.has_trustline(payment.recipient, asset_code, asset_issuer):
            raise PolicyError(f"recipient lacks USDC trustline: {payment.recipient}")
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
                # Auditable record without leaking secrets: key is truncated.
                LOG.info(
                    "paid · %s · %.2f USDC · idem=%s… · tx=%s",
                    payment.recipient,
                    payment.amount_usdc,
                    key[:12],
                    receipt.get("tx_hash"),
                )
                receipts.append({**receipt, "idempotency_key": key})
                break
            except Exception as exc:  # network/transient error
                last_error = exc
                LOG.warning("attempt %d/%d failed: %s", attempt, MAX_RETRIES, exc)
        else:
            # No infinite loop: owner is notified and batch stops.
            raise PolicyError(f"{MAX_RETRIES} attempts failed for {payment.recipient}: {last_error}")

    return receipts
