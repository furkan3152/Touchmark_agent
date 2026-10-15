"""HTTP -> real identity/store/worker -> report boundary with explicit chain fixtures."""
import base64
from hashlib import sha256
import time
from types import SimpleNamespace

import httpx
import pytest
from stellar_sdk import Keypair

from backend.app import api
from backend.app.config import Settings
from backend.app.services import audit_orders as orders, testnet_checkout as checkout
from backend.app.services.audit_product import audit_engagement
from backend.app.stellar.ownership import sep53_payload_hash


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    key = Keypair.random()
    settings = Settings(_env_file=None, stellar_network='testnet', enable_ofac_screening=False,
        runtime_api_key='private-pilot-' * 4, checkout_quote_signing_key='server-quotes-' * 4,
        enable_official_orders=True, official_orders_storage_durable=True,
        enable_testnet_order_settlement=True, official_provider_secret='configured',
        official_evaluator_secret='configured', blob_read_write_token='configured', blob_store_id='configured')
    store = orders.AuditOrderStore(tmp_path / 'orders.sqlite')
    state = {'escrow': 'absent', 'calls': 0}

    async def snapshot(rpc, quote, manifest):
        state['calls'] += 1
        value = {'ledger': 5_200_000, 'account': {'sequence': 2, 'balance': 100_000_000}}
        if state['escrow'] == 'absent':
            return value
        identity = {'version': 1, 'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256}
        return {**value, 'agent': {**identity, 'owner': key.public_key, 'active': True,
                'meta_uri': 'urn:veritas:plan:' + quote.plan_sha256},
            'validation': {**identity, 'agent_id': quote.agent_id, 'requester': key.public_key,
                'validator': quote.provider, 'state': ['Pending']},
            'job': {'requester': key.public_key, 'provider': quote.provider, 'evaluator': quote.evaluator,
                'amount': int(quote.amount_atomic), 'fee_bps': quote.fee_bps, 'fee_to': quote.treasury,
                'deadline': 5_200_000 + checkout.DEADLINE_LEDGERS, 'state': [state['escrow']]},
            'binding': {**identity, 'agent_id': quote.agent_id, 'owner': key.public_key}}

    monkeypatch.setattr(api, 'settings', settings)
    monkeypatch.setattr(checkout, '_snapshot', snapshot)
    monkeypatch.setattr(api.app.state, 'official_fulfillment',
        SimpleNamespace(store=store, health={'running': True}), raising=False)
    monkeypatch.setattr(api.app, 'middleware_stack', None)
    return key, settings, store, state


@pytest.mark.anyio
async def test_http_private_order_identity_funding_worker_report_and_recovery(boundary, monkeypatch):
    key, settings, store, state = boundary
    headers = {'Authorization': 'Bearer ' + settings.runtime_api_key}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        engagement = {'source': {'name': 'HTTP reader', 'purpose': 'Read a fixed public balance.',
            'network': 'testnet', 'files': {'agent.py': 'def answer(prompt):\n    return "12.50 XLM"\n'}}, 'tier_id': 'quick'}
        plan = (await client.post('/api/v1/studio/plan', json=engagement)).json()
        engagement['plan_sha256'] = plan['plan_sha256']
        submission = {'engagement': engagement, 'requester': key.public_key,
            'storage_consent': True, 'auto_settlement_consent': True, 'publication_consent': True}
        assert (await client.post('/api/v1/studio/orders', json=submission)).status_code == 401
        missing = await client.post('/api/v1/studio/orders', headers=headers, json=submission)
        assert missing.status_code == 422 and state['calls'] == 0
        challenge = (await client.post('/api/v1/studio/orders/challenge', headers=headers, json=submission)).json()
        signed = {**submission, 'wallet_proof': {'challenge': challenge['challenge'],
            'challenge_signature': challenge['challenge_signature'],
            'wallet_signature': base64.b64encode(key.sign(sep53_payload_hash(challenge['message']))).decode()}}
        response = await client.post('/api/v1/studio/orders', headers=headers, json=signed)
        assert response.status_code == 200, response.text
        created = response.json()
        path = '/api/v1/studio/orders/' + created['order_id']
        private = {**headers, 'X-Order-Token': created['order_token']}
        assert (await client.get(path, headers=headers)).status_code == 404
        pending = await client.get(path + '/result', headers=private)
        assert pending.status_code == 409 and 'no-store' in pending.headers['cache-control']
        assert (await client.post('/api/v1/studio/orders', headers=headers, json=signed)).status_code == 422
        state['escrow'] = 'Funded'
        activated = await client.post(path + '/activate', headers=private)
        assert activated.json()['status'] == 'queued'

        async def publish(order, result):
            return {'visibility': 'private', 'verified': True,
                'report_sha256': result['report_sha256'], 'report_uri': 'https://fixture.invalid/' + result['report_sha256']}

        async def settle(order, result, publication):
            return {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
                'request_id': order['id'], 'agent_id': order['quote']['agent_id'], 'token_id': order['id'],
                'report_sha256': result['report_sha256'], 'report_uri': publication['report_uri'],
                'credential_contract_id': checkout.PINNED_CONTRACTS['credential'],
                'escrow_contract_id': checkout.PINNED_CONTRACTS['escrow'], 'owner': key.public_key,
                'is_current': True, 'payment_state': 'Complete', 'checked_at_ledger': 5_200_100,
                'independent_evaluator': False}

        result = await orders.run_order_once(store, 'http-test', settings=settings, executor=audit_engagement,
            publisher=publish, chain_adapter=settle)
        assert result['status'] == 'delivered'
        summary = (await client.get(path, headers=private)).json()
        report = (await client.get(path + '/result', headers=private)).json()
        assert summary['delivery']['report_sha256'] == sha256(report['report_json'].encode()).hexdigest()
        assert report['report']['engagement']['plan_sha256'] == plan['plan_sha256']
        # Lost private receipt is recovered only using a fresh wallet-signed scope.
        challenge = (await client.post('/api/v1/studio/orders/challenge', headers=headers, json=submission)).json()
        signed['wallet_proof'] = {'challenge': challenge['challenge'], 'challenge_signature': challenge['challenge_signature'],
            'wallet_signature': base64.b64encode(key.sign(sep53_payload_hash(challenge['message']))).decode()}
        recovered = await client.post('/api/v1/studio/orders/recover', headers=headers, json=signed)
        assert recovered.status_code == 200, recovered.text
        assert recovered.json()['status'] == 'delivered'
        assert (await client.get(path, headers=private)).status_code == 404
        assert (await client.get(path, headers={**headers, 'X-Order-Token': recovered.json()['order_token']})).status_code == 200
        # Pausing signing must not strand a customer's private report or wallet
        # recovery; starting/retrying costly work remains unavailable.
        api.app.state.official_fulfillment.health['running'] = False
        monkeypatch.setattr(settings, 'enable_testnet_order_settlement', False)
        monkeypatch.setattr(settings, 'official_provider_secret', '')
        rotated = {**headers, 'X-Order-Token': recovered.json()['order_token']}
        assert (await client.get(path + '/result', headers=rotated)).status_code == 200
        assert (await client.post('/api/v1/studio/orders/challenge', headers=headers, json=submission)).status_code == 200
        assert (await client.post(path + '/activate', headers=rotated)).status_code == 503


@pytest.mark.anyio
async def test_stateless_service_does_not_accept_order_or_funding(boundary, monkeypatch):
    _, settings, _, _ = boundary
    monkeypatch.setattr(settings, 'stateless_studio', True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        capability = (await client.get('/api/v1/studio/orders/capabilities')).json()
        assert not capability['available'] and not capability['automatic_settlement']
        assert capability['storage_mode'] == 'unavailable'
        response = await client.post('/api/v1/studio/orders/challenge', content=b' ' * 131073,
            headers={'Content-Type': 'application/json'})
        assert response.status_code == 413
