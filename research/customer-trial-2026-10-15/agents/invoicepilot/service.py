"""Batch invoice service with a process-lifetime instance and approved supplier aliases."""
import asyncio
import json
import os
from clients import Gateway, Stellar
from main import InvoicePilot

_agent = None

def respond(text):
    global _agent
    command = json.loads(text)
    if not isinstance(command, dict) or command.get('operation') != 'pay_batch':
        raise ValueError('Expected a pay_batch command')
    invoices = command['invoices']
    if not isinstance(invoices, list) or not 1 <= len(invoices) <= 10:
        raise ValueError('A batch must contain one to ten invoices')
    suppliers = json.loads(os.environ['APPROVED_SUPPLIERS'])
    if _agent is None:
        _agent = InvoicePilot(Stellar(os.environ['STELLAR_SECRET']), Gateway(), suppliers.values())
    async def execute():
        results = []
        for item in invoices:
            invoice = {'id': item['id'], 'destination': suppliers[item['supplier']],
                'amount': item['amount'], 'description': item.get('description', '')}
            results.append(await _agent.process(invoice))
        return {'results': results}
    return json.dumps(asyncio.run(execute()))
