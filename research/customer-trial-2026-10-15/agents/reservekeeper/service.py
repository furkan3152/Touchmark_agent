"""Public JSON command interface; all transfers use the real business implementation."""
import asyncio
import json
import os
from clients import Gateway, Stellar
from main import ReserveKeeper

def respond(text):
    command = json.loads(text)
    if not isinstance(command, dict) or command.get('operation') != 'rebalance':
        raise ValueError('Expected a rebalance command')
    request_id = command['request_id']
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 28:
        raise ValueError('A bounded request identifier is required')
    agent = ReserveKeeper(Stellar(os.environ['STELLAR_SECRET']), Gateway(),
        os.environ['STATE_DB'], os.environ['RESERVE_DESTINATION'], os.environ['RESERVE_TARGET'])
    try:
        return json.dumps(asyncio.run(agent.tick(request_id)))
    finally:
        agent.db.close()
