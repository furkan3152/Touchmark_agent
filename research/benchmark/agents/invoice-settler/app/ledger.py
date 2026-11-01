import logging
from decimal import Decimal

from stellar_sdk import Asset, Keypair, Server, TransactionBuilder

from . import policy
from .config import get_settings

log = logging.getLogger("settler.ledger")


class Ledger:
    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._server = Server(horizon_url=settings.horizon_url)
        self._keypair = Keypair.from_secret(settings.signing_secret.get_secret_value())
        self._usdc = Asset(settings.usdc_code, settings.usdc_issuer)

    @property
    def address(self) -> str:
        return self._keypair.public_key

    def pay_vendor(self, vendor_id: str, amount: str, invoice_id: str, paid_this_month: Decimal) -> str:
        vendor = policy.enforce_vendor_payment(vendor_id, amount, paid_this_month)
        return self._submit_payment(vendor.address, amount, f"inv:{invoice_id}")

    def _submit_payment(self, destination: str, amount: str, memo: str) -> str:
        source = self._server.load_account(self._keypair.public_key)
        tx = (
            TransactionBuilder(
                source_account=source,
                network_passphrase=self._settings.network_passphrase,
                base_fee=self._settings.base_fee,
            )
            .append_payment_op(destination=destination, asset=self._usdc, amount=amount)
            .add_text_memo(memo[:28])
            .set_timeout(120)
            .build()
        )
        tx.sign(self._keypair)
        response = self._server.submit_transaction(tx)
        log.info("submitted %s to %s amount=%s", response["hash"], destination, amount)
        return response["hash"]

    def send_refund(self, destination: str, amount: str, reference: str) -> str:
        return self._submit_payment(destination, amount, f"refund:{reference}")

    def find_deposit(self, tx_hash: str) -> dict | None:
        ops = self._server.operations().for_transaction(tx_hash).call()
        for op in ops["_embedded"]["records"]:
            if op.get("type") != "payment":
                continue
            if op.get("to") != self._keypair.public_key:
                continue
            if op.get("asset_code") == self._settings.usdc_code:
                return {"from": op["from"], "amount": op["amount"], "hash": tx_hash}
        return None
