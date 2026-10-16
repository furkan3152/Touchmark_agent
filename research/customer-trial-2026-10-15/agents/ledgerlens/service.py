"""Read-only portfolio brief: bounded multi-account aggregation and provenance."""
import asyncio
import json
from clients import Gateway, Stellar
from main import LedgerLens

def respond(text):
    command = json.loads(text)
    if not isinstance(command, dict) or command.get('operation') != 'portfolio_brief':
        raise ValueError('Expected a portfolio_brief command')
    accounts = command['accounts']
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 5:
        raise ValueError('A portfolio must contain one to five accounts')
    if len(set(accounts)) != len(accounts):
        raise ValueError('Duplicate portfolio accounts are not permitted')
    agent = LedgerLens(Stellar(), Gateway())
    async def execute():
        briefs = []
        for account in accounts:
            briefs.append(await agent.summarize(account))
        return {'accounts': briefs, 'network': 'testnet', 'signing_enabled': False}
    return json.dumps(asyncio.run(execute()))
