"""Small production-shaped clients, pinned to disposable Stellar Testnet accounts."""
import json
import os
from decimal import Decimal
import httpx
from stellar_sdk import Asset, Keypair, Network, Server, TransactionBuilder
from stellar_sdk.client.requests_client import RequestsClient

class Gateway:
    def __init__(self):
        self.usage = []
    async def decide(self, instruction, context):
        token = os.environ.get('AI_GATEWAY_API_KEY') or os.environ['VERCEL_OIDC_TOKEN']
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
            response = await client.post('https://ai-gateway.vercel.sh/v1/chat/completions',
                headers={'Authorization': 'Bearer ' + token}, json={
                    'model': 'openai/gpt-4.1-mini', 'max_tokens': 400,
                    'response_format': {'type': 'json_object'},
                    'messages': [{'role': 'system', 'content': instruction},
                                 {'role': 'user', 'content': json.dumps(context)}]})
            response.raise_for_status()
            body = response.json()
        self.usage.append(body.get('usage', {}))
        choice = body['choices'][0]
        if choice.get('finish_reason') != 'stop':
            raise ValueError('Model response did not complete')
        return json.loads(choice['message']['content'])

class Stellar:
    def __init__(self, seed=None):
        self.key = Keypair.from_secret(seed) if seed else None
        self.server = Server('https://horizon-testnet.stellar.org',
            client=RequestsClient(num_retries=0, request_timeout=15, post_timeout=30))
    def balance(self, account):
        state = self.server.accounts().account_id(account).call()
        return next(row['balance'] for row in state['balances'] if row['asset_type'] == 'native')
    def recent(self, account):
        page = self.server.transactions().for_account(account).order(desc=True).limit(5).call()
        return [{'hash': row['hash'], 'successful': row['successful'],
                 'memo': row.get('memo', ''), 'ledger': row['ledger']} for row in page['_embedded']['records']]
    def pay(self, destination, amount, reference):
        if self.key is None:
            raise PermissionError('No signing identity is configured')
        value = Decimal(amount)
        # This example is intentionally testnet-only and cannot move meaningful value.
        if not value.is_finite() or value <= 0 or value > Decimal('0.0000200'):
            raise ValueError('Disposable example amount out of bounds')
        account = self.server.load_account(self.key.public_key)
        tx = (TransactionBuilder(account, Network.TESTNET_NETWORK_PASSPHRASE, base_fee=100)
              .append_payment_op(destination, Asset.native(), format(value, '.7f'))
              .add_text_memo(reference[:28]).set_timeout(60).build())
        tx.sign(self.key)
        result = self.server.submit_transaction(tx)
        if result.get('successful') is not True or result['hash'] != tx.hash_hex():
            raise RuntimeError('Payment was not confirmed')
        return {'hash': result['hash'], 'ledger': result['ledger'], 'successful': True,
                'destination': destination, 'amount': format(value, '.7f'), 'reference': reference}
