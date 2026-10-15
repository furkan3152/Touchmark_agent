"""Maintain an approved operational wallet's native-XLM reserve."""
import asyncio
import json
import os
import sqlite3
from decimal import Decimal
from clients import Gateway, Stellar

class ReserveKeeper:
    def __init__(self, chain, model, database, destination, target):
        self.chain, self.model = chain, model
        self.destination, self.target = destination, Decimal(target)
        self.db = sqlite3.connect(database)
        self.db.execute('CREATE TABLE IF NOT EXISTS intents (request_id TEXT PRIMARY KEY, amount TEXT, receipt TEXT)')
        self.db.commit()
    def authorize(self, proposal):
        if proposal.get('destination') != self.destination:
            raise PermissionError('Unapproved reserve wallet')
        amount = Decimal(str(proposal.get('amount')))
        if not amount.is_finite() or amount <= 0 or amount > Decimal('0.0000100'):
            raise PermissionError('Transfer exceeds the per-action budget')
        spent = sum((Decimal(row[0]) for row in self.db.execute('SELECT amount FROM intents')), Decimal(0))
        if spent + amount > Decimal('0.0000200'):
            raise PermissionError('Cumulative budget exceeded')
        return amount
    async def tick(self, request_id):
        if self.db.execute('SELECT 1 FROM intents WHERE request_id=?', (request_id,)).fetchone():
            return {'status': 'already_processed'}
        balance = Decimal(self.chain.balance(self.destination))
        if balance >= self.target:
            return {'status': 'reserve_sufficient', 'balance': str(balance)}
        proposal = await self.model.decide(
            'You operate a reserve wallet. Return JSON with action top_up, destination and amount. '
            'Use the supplied destination and exact deficit, capped by max_transfer. No other fields.',
            {'destination': self.destination, 'balance': str(balance), 'deficit': str(self.target-balance),
             'max_transfer': '0.0000100'})
        if proposal.get('action') != 'top_up':
            return {'status': 'no_action'}
        self.db.execute('BEGIN IMMEDIATE')
        try:
            amount = self.authorize(proposal)
            self.db.execute('INSERT INTO intents VALUES (?, ?, NULL)', (request_id, str(amount)))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        receipt = self.chain.pay(self.destination, str(amount), request_id)
        self.db.execute('UPDATE intents SET receipt=? WHERE request_id=?', (json.dumps(receipt), request_id))
        self.db.commit()
        return {'status': 'paid', 'proposal': proposal, 'receipt': receipt}

if __name__ == '__main__':
    agent = ReserveKeeper(Stellar(os.environ['STELLAR_SECRET']), Gateway(),
        os.environ.get('STATE_DB', 'reserve.db'), os.environ['RESERVE_DESTINATION'], os.environ['RESERVE_TARGET'])
    print(json.dumps(asyncio.run(agent.tick(os.environ['REQUEST_ID']))))
