import threading
from dataclasses import dataclass, field
from decimal import Decimal


@dataclass
class Invoice:
    invoice_id: str
    vendor_id: str
    amount: str
    status: str = "open"
    tx_hash: str | None = None


@dataclass
class Store:
    invoices: dict[str, Invoice] = field(default_factory=dict)
    balances: dict[str, Decimal] = field(default_factory=dict)
    credited: set[str] = field(default_factory=set)
    monthly_paid: dict[str, Decimal] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_invoice(self, invoice: Invoice) -> None:
        with self.lock:
            self.invoices.setdefault(invoice.invoice_id, invoice)

    def credit(self, customer_id: str, tx_hash: str, amount: Decimal) -> bool:
        with self.lock:
            if tx_hash in self.credited:
                return False
            self.credited.add(tx_hash)
            self.balances[customer_id] = self.balances.get(customer_id, Decimal(0)) + amount
            return True


store = Store()
