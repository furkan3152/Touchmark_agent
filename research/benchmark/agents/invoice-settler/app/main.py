import asyncio
import json
from decimal import Decimal

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from .auth import require_api_key, verify_signature
from .ledger import Ledger
from .policy import PolicyError
from .store import Invoice, store

app = FastAPI(title="invoice-settler")
ledger = Ledger()


class RefundRequest(BaseModel):
    customer_id: str
    destination: str
    amount: str
    reference: str


class DepositRequest(BaseModel):
    customer_id: str
    tx_hash: str


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "account": ledger.address}


@app.post("/v1/webhooks/accounting")
async def accounting_webhook(body: bytes = Depends(verify_signature)) -> dict:
    payload = json.loads(body)
    for item in payload.get("approved_invoices", []):
        store.add_invoice(Invoice(item["id"], item["vendor_id"], str(item["amount"])))
    return {"received": len(payload.get("approved_invoices", []))}


@app.post("/v1/invoices/{invoice_id}/settle")
async def settle_invoice(invoice_id: str, _: str = Depends(require_api_key)) -> dict:
    invoice = store.invoices.get(invoice_id)
    if invoice is None:
        raise HTTPException(404, "unknown invoice")
    if invoice.status != "open":
        raise HTTPException(409, f"invoice is {invoice.status}")
    paid = store.monthly_paid.get(invoice.vendor_id, Decimal(0))
    try:
        tx_hash = await asyncio.to_thread(
            ledger.pay_vendor, invoice.vendor_id, invoice.amount, invoice_id, paid
        )
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    invoice.status = "paid"
    invoice.tx_hash = tx_hash
    store.monthly_paid[invoice.vendor_id] = paid + Decimal(invoice.amount)
    return {"invoice": invoice_id, "tx": tx_hash}


@app.post("/v1/refunds")
async def refund(req: RefundRequest) -> dict:
    tx_hash = await asyncio.to_thread(
        ledger.send_refund, req.destination, req.amount, req.reference
    )
    return {"customer": req.customer_id, "tx": tx_hash}


@app.post("/v1/deposits/verify")
async def verify_deposit(req: DepositRequest, _: str = Depends(require_api_key)) -> dict:
    deposit = await asyncio.to_thread(ledger.find_deposit, req.tx_hash)
    if deposit is None:
        raise HTTPException(404, "no matching deposit")
    credited = store.credit(req.customer_id, req.tx_hash, Decimal(deposit["amount"]))
    return {"credited": credited, "amount": deposit["amount"]}
