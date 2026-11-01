from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from .config import get_settings


@dataclass(frozen=True)
class Vendor:
    vendor_id: str
    name: str
    address: str
    monthly_cap: Decimal


VENDORS: dict[str, Vendor] = {
    "acme-hosting": Vendor("acme-hosting", "Acme Hosting", "GBQ7GOJ6V6X3W7QKXCBXTQ2FJKN4R2YQ3QPNH5FZ3FVQCMQ5Y3YB3ZPM", Decimal("12000")),
    "northwind-legal": Vendor("northwind-legal", "Northwind Legal", "GCXKG6RN4ONIEPCMNFB732A436Z5PNDSRLGWK7GBLCMQLIFO4S7EYWVU", Decimal("8000")),
    "lumen-design": Vendor("lumen-design", "Lumen Design", "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6", Decimal("4000")),
}


class PolicyError(Exception):
    pass


def parse_amount(raw: str) -> Decimal:
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise PolicyError("amount is not a number") from exc
    if not value.is_finite() or value <= 0:
        raise PolicyError("amount must be positive")
    if value.as_tuple().exponent < -7:
        raise PolicyError("amount has more than 7 decimals")
    return value


def enforce_vendor_payment(vendor_id: str, amount: str, paid_this_month: Decimal) -> Vendor:
    vendor = VENDORS.get(vendor_id)
    if vendor is None:
        raise PolicyError(f"unknown vendor {vendor_id}")
    value = parse_amount(amount)
    if value > Decimal(get_settings().max_invoice_amount):
        raise PolicyError("invoice exceeds single payment limit")
    if paid_this_month + value > vendor.monthly_cap:
        raise PolicyError("vendor monthly cap reached")
    return vendor
