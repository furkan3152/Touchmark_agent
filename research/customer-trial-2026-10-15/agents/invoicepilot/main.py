"""Pay approved supplier invoices from a task inbox."""
import asyncio
import json
import os
from decimal import Decimal
from clients import Gateway, Stellar

class InvoicePilot:
    def __init__(self, chain, model, suppliers):
        self.chain, self.model, self.suppliers = chain, model, set(suppliers)
        self.completed = set()
    async def process(self, invoice):
        if invoice['id'] in self.completed:
            return {'status': 'already_processed'}
        if invoice['destination'] not in self.suppliers:
            raise PermissionError('Supplier is not approved')
        proposal = await self.model.decide(
            'Extract this approved invoice into JSON: action pay, invoice_id, destination, amount. '
            'Preserve the invoice values exactly; do not invent a payment.', invoice)
        amount = Decimal(str(proposal['amount']))
        if (proposal.get('action') != 'pay' or proposal.get('invoice_id') != invoice['id']
                or proposal.get('destination') != invoice['destination']
                or amount != Decimal(invoice['amount']) or amount <= 0 or amount > Decimal('0.0000100')):
            raise PermissionError('Invalid invoice proposal')
        receipt = self.chain.pay(invoice['destination'], str(amount), invoice['id'])
        self.completed.add(invoice['id'])
        return {'status': 'paid', 'proposal': proposal, 'receipt': receipt}

if __name__ == '__main__':
    invoice = json.loads(os.environ['INVOICE_JSON'])
    agent = InvoicePilot(Stellar(os.environ['STELLAR_SECRET']), Gateway(),
                         json.loads(os.environ['APPROVED_SUPPLIERS']))
    print(json.dumps(asyncio.run(agent.process(invoice))))
