"""Independent order boundary regressions; no submitted code is executed here."""
import json
import secrets

import pytest

from backend.app.config import Settings
from backend.app.reporting.generator import canonical_json
from backend.app.services import audit_orders as orders
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_product import EngagementRequest, build_plan
from backend.app.services.studio import ReviewRequest


WALLET = 'GD2M2PJ67RBTFEBPSRX4PAWTBAOGUR5OLZ5OVD6HECXFI5ERCRMB7ZBI'
LEDGER = 5_200_000


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    config = Settings(_env_file=None, stellar_network='testnet',
        runtime_api_key='independent-pilot-client-token-' * 2,
        checkout_quote_signing_key='independent-server-signing-key-' * 2)
    store = orders.AuditOrderStore(tmp_path / 'private' / 'orders.sqlite')
    chain = {'state': 'absent', 'ledger': LEDGER, 'calls': 0}

    async def snapshot(rpc, quote, manifest):
        chain['calls'] += 1
        value = {'ledger': chain['ledger'], 'account': {'sequence': 11, 'balance': 100_000_000}}
        if chain['state'] == 'absent':
            return value
        value.update(agent={'owner': WALLET, 'version': 1, 'active': True,
            'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256,
            'meta_uri': 'urn:veritas:plan:' + quote.plan_sha256},
            validation={'agent_id': quote.agent_id, 'version': 1,
                'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256,
                'requester': WALLET, 'validator': quote.provider, 'state': ['Pending']},
            job={'requester': WALLET, 'provider': quote.provider, 'evaluator': quote.evaluator,
                'amount': int(quote.amount_atomic), 'deadline': LEDGER + checkout.DEADLINE_LEDGERS,
                'fee_bps': quote.fee_bps, 'fee_to': quote.treasury, 'state': [chain['state']]},
            binding={'agent_id': quote.agent_id, 'owner': WALLET, 'version': 1,
                'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256})
        return value

    monkeypatch.setattr(checkout, '_snapshot', snapshot)
    # Wallet cryptography has its own suite; these tests isolate the durable order
    # and chain-binding boundary after successful identity verification.
    monkeypatch.setattr(orders, '_verify_identity', lambda *_: None)

    def submission(suffix='one'):
        engagement = EngagementRequest(source=ReviewRequest(name='Reader ' + suffix,
            purpose='Return a fixed public fixture value.',
            files={'agent.py': 'def answer(prompt):\n    return "Public balance: 12"\n# ' + suffix}))
        engagement.plan_sha256 = build_plan(engagement, config)['plan_sha256']
        return orders.OrderSubmission(engagement=engagement, requester=WALLET,
            storage_consent=True, auto_settlement_consent=True, publication_consent=True,
            wallet_proof={'challenge': {'nonce': secrets.token_hex(32)}})

    return config, store, chain, submission


@pytest.mark.anyio
async def test_order_capability_is_not_reusable_for_a_second_order_before_rpc(boundary):
    config, store, chain, submission = boundary
    first = await orders.create_order(submission('one'), config, store)
    second = await orders.create_order(submission('two'), config, store)
    before = chain['calls']
    for token in (first['order_token'], '0' * 64, second['order_id']):
        with pytest.raises(orders.OrderError, match='capability'):
            await orders.activate_order(second['order_id'], token, config, store)
        with pytest.raises(orders.OrderError, match='capability'):
            store.result(second['order_id'], token)
    assert chain['calls'] == before
    assert 'order_token' not in store.get(first['order_id'], first['order_token'])
    with store._connect() as db:
        raw = dict(db.execute('SELECT * FROM audit_orders WHERE id=?', (first['order_id'],)).fetchone())
    assert first['order_token'] not in json.dumps(raw)


@pytest.mark.anyio
async def test_valid_hmac_for_different_source_cannot_activate_order(boundary):
    config, store, chain, submission = boundary
    first = await orders.create_order(submission('one'), config, store)
    alternate = submission('two')
    chain['state'] = 'Funded'

    async def changed_reader(request, settings):
        return await checkout.prepare_checkout(checkout.CheckoutRequest(
            engagement=alternate.engagement, requester=WALLET), settings)

    with pytest.raises(orders.OrderError, match='exact acknowledged order'):
        await orders.activate_order(first['order_id'], first['order_token'], config, store,
                                    checkout_reader=changed_reader)
    assert store.get(first['order_id'], first['order_token'])['status'] == 'awaiting_payment'


@pytest.mark.anyio
async def test_paid_order_uses_fresh_quote_after_original_quote_expires(boundary, monkeypatch):
    config, store, chain, submission = boundary
    now = [1_800_000_000]
    monkeypatch.setattr(checkout.time, 'time', lambda: now[0])
    created = await orders.create_order(submission(), config, store)
    old_quote = store._private(created['order_id'])['quote']
    now[0] += checkout.QUOTE_SECONDS + 60
    chain['state'] = 'Funded'
    activated = await orders.activate_order(created['order_id'], created['order_token'], config, store)
    fresh_quote = store._private(created['order_id'])['quote']
    assert activated['status'] == 'queued' and activated['payment_confirmed']
    assert old_quote['expires_at'] < now[0] < fresh_quote['expires_at']
    assert fresh_quote['request_id'] == old_quote['request_id']


@pytest.mark.anyio
async def test_expired_funded_order_never_calls_executor(boundary):
    config, store, chain, submission = boundary
    created = await orders.create_order(submission(), config, store)
    chain['state'] = 'Funded'
    await orders.activate_order(created['order_id'], created['order_token'], config, store)
    chain['ledger'] = LEDGER + checkout.DEADLINE_LEDGERS
    called = []

    async def forbidden(*args):
        called.append(True)
        raise AssertionError('Expired escrow must not reach paid computation/publication/signing.')

    outcome = await orders.run_order_once(store, 'independent-review', settings=config,
        executor=forbidden, publisher=forbidden, chain_adapter=forbidden)
    assert called == []
    assert outcome['status'] == 'failed' and outcome['failure_code'] == 'payment_recheck_failed'


@pytest.mark.anyio
async def test_tampered_persisted_source_stops_before_rpc_and_executor(boundary):
    config, store, chain, submission = boundary
    created = await orders.create_order(submission(), config, store)
    chain['state'] = 'Funded'
    await orders.activate_order(created['order_id'], created['order_token'], config, store)
    private = store._private(created['order_id'])
    private['engagement']['source']['files']['agent.py'] += '\n# substituted private source'
    with store._connect(write=True) as db:
        db.execute('UPDATE audit_orders SET engagement_json=? WHERE id=?',
                   (canonical_json(private['engagement']), created['order_id']))
    before, calls = chain['calls'], []

    async def forbidden(*args):
        calls.append(True)
        raise AssertionError('Modified order content must never execute or settle.')

    outcome = await orders.run_order_once(store, 'independent-review', settings=config,
        executor=forbidden, publisher=forbidden, chain_adapter=forbidden)
    assert chain['calls'] == before and calls == []
    assert outcome['failure_code'] == 'payment_recheck_failed'
    assert 'substituted private source' not in canonical_json(outcome)


def test_delivery_for_another_credential_cannot_mark_order_delivered():
    order_id = 'a' * 64
    quote = {'agent_id': 'b' * 64, 'requester': WALLET, 'contracts': checkout.PINNED_CONTRACTS}
    order = {'id': order_id, 'quote': quote, 'checked_ledger': LEDGER}
    result = {'report_sha256': 'c' * 64,
              'report_json': json.dumps({'review_decision': 'pass', 'result': {'overall_score': 80.0}})}
    publication = {'report_uri': 'https://reports.example/private/' + result['report_sha256']}
    delivery = {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
        'request_id': order_id, 'agent_id': quote['agent_id'], 'report_sha256': result['report_sha256'],
        'report_uri': publication['report_uri'], 'credential_contract_id': quote['contracts']['credential'],
        'escrow_contract_id': quote['contracts']['escrow'], 'owner': WALLET, 'is_current': True,
        'payment_state': 'Complete', 'independent_evaluator': False, 'checked_at_ledger': LEDGER + 1,
        'token_id': 'd' * 64}
    with pytest.raises(orders.OrderError, match='exact report'):
        orders._validate_delivery(delivery, order, result, publication)
    delivery['token_id'] = order_id
    orders._validate_delivery(delivery, order, result, publication)


def test_failing_audit_delivery_must_not_claim_a_credential():
    order_id = 'a' * 64
    quote = {'agent_id': 'b' * 64, 'requester': WALLET, 'contracts': checkout.PINNED_CONTRACTS}
    order = {'id': order_id, 'quote': quote, 'checked_ledger': LEDGER}
    result = {'report_sha256': 'c' * 64,
              'report_json': json.dumps({'review_decision': 'needs_fixes', 'result': {'overall_score': 39.0}})}
    publication = {'report_uri': 'https://reports.example/private/' + result['report_sha256']}
    delivery = {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
        'request_id': order_id, 'agent_id': quote['agent_id'], 'report_sha256': result['report_sha256'],
        'report_uri': publication['report_uri'], 'credential_contract_id': quote['contracts']['credential'],
        'escrow_contract_id': quote['contracts']['escrow'], 'owner': WALLET, 'is_current': True,
        'payment_state': 'Complete', 'independent_evaluator': False, 'checked_at_ledger': LEDGER + 1,
        'token_id': order_id}
    with pytest.raises(orders.OrderError, match='exact report'):
        orders._validate_delivery(delivery, order, result, publication)
    delivery.update(is_current=False, token_id=None)
    orders._validate_delivery(delivery, order, result, publication)


@pytest.mark.anyio
@pytest.mark.parametrize('unverified', [None, 0, {}, ''])
async def test_private_publication_requires_positive_authenticated_verification(unverified):
    from backend.app.services.order_settlement import TestnetOrderSettlement
    adapter = object.__new__(TestnetOrderSettlement)
    adapter.base = 'https://store.private.blob.vercel-storage.com/reports'

    async def incomplete_verifier(*args):
        return unverified

    adapter.publication_verifier = incomplete_verifier
    digest = 'a' * 64
    publication = {'report_sha256': digest, 'report_uri': adapter.base + '/' + digest + '.json',
                   'visibility': 'private', 'verified': True}
    with pytest.raises(ValueError, match='readback'):
        await adapter._publication({}, publication, b'{}', digest)


@pytest.mark.anyio
async def test_missing_wallet_proof_is_rejected_before_checkout_rpc(boundary, monkeypatch):
    from backend.app.services.order_identity import verify_order_identity
    config, store, chain, submission = boundary
    monkeypatch.setattr(orders, '_verify_identity', verify_order_identity)
    with pytest.raises(ValueError, match='ownership proof'):
        await orders.create_order(submission(), config, store)
    assert chain['calls'] == 0
