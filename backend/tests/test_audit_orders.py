"""Durable orchestration tests. Wallet signatures have separate identity tests.

No network, customer-code execution, publication or transaction signing occurs.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
import secrets
import time

import pytest
from pydantic import ValidationError

from backend.app.config import Settings
from backend.app.services import audit_orders as orders
from backend.app.services import order_settlement as settlement
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_product import EngagementRequest, audit_engagement, build_plan
from backend.app.services.studio import ReviewRequest

WALLET = 'GD2M2PJ67RBTFEBPSRX4PAWTBAOGUR5OLZ5OVD6HECXFI5ERCRMB7ZBI'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def config():
    return Settings(_env_file=None, stellar_network='testnet', runtime_api_key='private-pilot-key-' * 3,
        checkout_quote_signing_key='server-only-quote-key-' * 3, enable_ofac_screening=False)


@pytest.fixture(autouse=True)
def isolate_identity(monkeypatch):
    # This suite exercises order state, not the independently tested wallet challenge.
    monkeypatch.setattr(orders, '_verify_identity', lambda submission, settings: None)


def submission(config, suffix=''):
    engagement = EngagementRequest(source=ReviewRequest(name='Reader', purpose='Read only the fixed public balance.',
        files={'agent.py': 'def answer(prompt):\n    return "Public balance: 12"\n' + suffix}))
    engagement.plan_sha256 = build_plan(engagement, config)['plan_sha256']
    return orders.OrderSubmission(engagement=engagement, requester=WALLET, storage_consent=True,
        auto_settlement_consent=True, publication_consent=True,
        wallet_proof={'challenge': {'nonce': secrets.token_hex(32)}})


class LiveCheckout:
    def __init__(self):
        self.state, self.ledger, self.deadline, self.calls = 'absent', 5_200_000, 5_217_280, 0

    async def __call__(self, request, settings):
        self.calls += 1
        plan = build_plan(request.engagement, settings)
        manifest = checkout._deployment()
        source, scope = plan['plan']['source_sha256'], plan['plan_sha256']
        agent, req = checkout._ids(request.requester, source, scope, request.engagement.tier_id, manifest)
        now = int(time.time())
        quote = checkout.Quote(requester=request.requester, tier_id=request.engagement.tier_id,
            source_sha256=source, plan_sha256=scope, agent_id=agent, request_id=req,
            amount_atomic=checkout.PRICES[request.engagement.tier_id], contracts=checkout.PINNED_CONTRACTS,
            provider=manifest['roles']['provider'], evaluator=manifest['roles']['evaluator'],
            treasury=manifest['roles']['treasury'], deadline_ledger=self.deadline,
            issued_at=now, expires_at=now + 600)
        return {'quote': quote.model_dump(), 'quote_signature': checkout._signature(quote, settings),
                'payment_confirmed': self.state in {'Funded', 'Submitted', 'Disputed', 'Complete'},
                'chain': {'ledger': self.ledger, 'escrow_state': self.state}}


async def setup_order(tmp_path, config, *, clock=time.time, suffix=''):
    store = orders.AuditOrderStore(tmp_path / 'private' / 'orders.sqlite', clock=clock)
    live = LiveCheckout()
    created = await orders.create_order(submission(config, suffix), config, store, checkout_reader=live)
    return store, live, created


async def activate(store, live, created, config):
    live.state = 'Funded'
    return await orders.activate_order(created['order_id'], created['order_token'], config, store, checkout_reader=live)


async def publisher(order, result):
    return {'report_uri': 'https://private.example.invalid/report/' + result['report_sha256'],
            'report_sha256': result['report_sha256'], 'visibility': 'private', 'verified': True}


async def chain(order, result, publication):
    return {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
            'request_id': order['id'], 'agent_id': order['quote']['agent_id'],
            'report_sha256': result['report_sha256'], 'report_uri': publication['report_uri'],
            'token_id': order['id'], 'credential_contract_id': checkout.PINNED_CONTRACTS['credential'],
            'escrow_contract_id': checkout.PINNED_CONTRACTS['escrow'], 'owner': WALLET,
            'is_current': True, 'checked_at_ledger': 5_200_100, 'payment_state': 'Complete',
            'independent_evaluator': False, 'transactions': []}


async def run(store, live, config, **adapters):
    return await orders.run_order_once(store, 'test-worker', settings=config,
        executor=adapters.get('executor', audit_engagement), publisher=adapters.get('publisher', publisher),
        chain_adapter=adapters.get('chain_adapter', chain), checkout_reader=live)


def test_consent_and_ephemeral_storage_fail_closed(tmp_path, config, monkeypatch):
    payload = submission(config).model_dump()
    for name in ('storage_consent', 'auto_settlement_consent', 'publication_consent'):
        with pytest.raises(ValidationError, match='explicit consent'):
            orders.OrderSubmission.model_validate({**payload, name: False})
    with pytest.raises(orders.OrderError, match='persistent storage'):
        orders.AuditOrderStore(tmp_path / 'production.sqlite', deployment='production')
    with pytest.raises(orders.OrderError, match='persistent storage'):
        orders.AuditOrderStore('/workspace/scratch/transient-orders.sqlite', deployment='production', durable_storage=True)
    with pytest.raises(orders.OrderError, match='on-disk'):
        orders.AuditOrderStore(':memory:')
    monkeypatch.setenv('VERCEL', '1')
    with pytest.raises(orders.OrderError, match='serverless'):
        orders.AuditOrderStore(tmp_path / 'vercel.sqlite', durable_storage=True)


@pytest.mark.anyio
async def test_private_creation_survives_restart_and_never_reveals_capability(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    assert created['status'] == 'awaiting_payment'
    assert not created['payment_confirmed']
    assert len(created['order_token']) == 64
    reopened = orders.AuditOrderStore(store.path)
    summary = reopened.get(created['order_id'], created['order_token'])
    assert summary['order_id'] == created['order_id']
    assert not {'order_token', 'engagement', 'source', 'result', 'lease_token'} & summary.keys()
    assert created['order_token'].encode() not in store.path.read_bytes()
    assert os.stat(store.path).st_mode & 0o777 == 0o600
    with pytest.raises(orders.OrderError, match='already exists'):
        await orders.create_order(submission(config), config, store, checkout_reader=live)


@pytest.mark.anyio
async def test_fresh_wallet_recovery_rotates_capability_without_resetting_order(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    await activate(store, live, created, config)
    before = store.get(created['order_id'], created['order_token'])
    proof = submission(config)
    recovered = await orders.recover_order(proof, config, store)
    assert recovered['order_id'] == created['order_id'] and recovered['status'] == before['status']
    assert recovered['order_token'] != created['order_token']
    assert recovered['attempts'] == before['attempts']
    with pytest.raises(orders.OrderError, match='Invalid order capability'):
        store.get(created['order_id'], created['order_token'])
    with pytest.raises(orders.OrderError, match='already been consumed'):
        await orders.recover_order(proof, config, store)
    with pytest.raises(orders.OrderError, match='exact wallet-approved'):
        await orders.recover_order(submission(config, '# wrong scope\n'), config, store)
    assert store.get(created['order_id'], recovered['order_token'])['payment_confirmed']


@pytest.mark.anyio
async def test_creation_proof_cannot_be_replayed_to_rotate_capability(tmp_path, config):
    store = orders.AuditOrderStore(tmp_path / 'orders.sqlite')
    live, original = LiveCheckout(), submission(config)
    created = await orders.create_order(original, config, store, checkout_reader=live)
    with pytest.raises(orders.OrderError, match='already been consumed'):
        await orders.recover_order(original, config, store)
    assert store.get(created['order_id'], created['order_token'])['status'] == 'awaiting_payment'


@pytest.mark.anyio
async def test_capability_required_before_rpc_or_private_result(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    calls = live.calls
    for token in ['', '0' * 64, None, created['order_token'] + 'a']:
        with pytest.raises(orders.OrderError, match='Invalid order capability'):
            await orders.activate_order(created['order_id'], token, config, store, checkout_reader=live)
        with pytest.raises(orders.OrderError, match='Invalid order capability'):
            store.result(created['order_id'], token)
    assert live.calls == calls


@pytest.mark.anyio
async def test_payment_creation_and_activation_fail_closed(tmp_path, config):
    store = orders.AuditOrderStore(tmp_path / 'orders.sqlite')
    live = LiveCheckout()
    for state in ('Funded', 'Submitted', 'Complete', 'Refunded'):
        live.state = state
        with pytest.raises(orders.OrderError, match='before funding'):
            await orders.create_order(submission(config), config, store, checkout_reader=live)
    live.state = 'absent'
    created = await orders.create_order(submission(config), config, store, checkout_reader=live)
    pending = await orders.activate_order(created['order_id'], created['order_token'], config, store, checkout_reader=live)
    assert pending['status'] == 'awaiting_payment' and store.claim('worker') is None
    live.state = 'Disputed'
    with pytest.raises(orders.OrderError, match='Disputed'):
        await orders.activate_order(created['order_id'], created['order_token'], config, store, checkout_reader=live)


@pytest.mark.anyio
async def test_forged_or_inconsistent_payment_receipt_never_queues(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    live.state = 'Funded'
    async def forged(request, cfg):
        result = await live(request, cfg)
        result['quote']['amount_atomic'] = '1'
        return result
    with pytest.raises(ValueError, match='signature'):
        await orders.activate_order(created['order_id'], created['order_token'], config, store, checkout_reader=forged)
    async def inconsistent(request, cfg):
        result = await live(request, cfg)
        result['chain']['escrow_state'] = 'Created'
        return result
    with pytest.raises(orders.OrderError, match='inconsistent'):
        await orders.activate_order(created['order_id'], created['order_token'], config, store, checkout_reader=inconsistent)
    assert store.claim('no-paid-worker') is None


@pytest.mark.anyio
async def test_retry_budget_cannot_be_reset_by_activation(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    store.max_attempts = 2
    async def broken(*args):
        raise TimeoutError()
    for _ in range(2):
        await activate(store, live, created, config)
        failed = await run(store, live, config, executor=broken)
        assert failed['status'] == 'failed'
    assert not failed['retryable']
    with pytest.raises(orders.OrderError, match='retry limit'):
        await activate(store, live, created, config)
    assert store.claim('cannot-reset') is None


@pytest.mark.anyio
async def test_expired_checkout_quote_is_refreshed_for_still_funded_order(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    with store._connect(write=True) as db:
        original = json.loads(db.execute('SELECT quote_json FROM audit_orders').fetchone()[0])
        original['issued_at'], original['expires_at'] = 1, 601
        db.execute('UPDATE audit_orders SET quote_json=?', (json.dumps(original),))
    result = await activate(store, live, created, config)
    assert result['status'] == 'queued' and result['payment_confirmed']
    assert store._private(created['order_id'])['quote']['expires_at'] > int(time.time())


@pytest.mark.anyio
async def test_private_scheduler_recovers_payment_without_browser_capability(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    pending = await orders.reconcile_pending_orders(store, config, checkout_reader=live)
    assert pending[0]['status'] == 'awaiting_payment'
    live.state = 'Funded'
    recovered = await orders.reconcile_pending_orders(store, config, checkout_reader=live)
    assert recovered[0]['status'] == 'queued'
    assert recovered[0]['order_id'] == created['order_id']
    assert await orders.reconcile_pending_orders(store, config, checkout_reader=live) == []


@pytest.mark.anyio
async def test_reconciliation_failure_backoff_does_not_starve_later_funded_order(tmp_path, config):
    now = [1000.0]
    store, live, first = await setup_order(tmp_path, config, clock=lambda: now[0])
    now[0] += 1
    second_request = submission(config, '# later\n')
    second = await orders.create_order(second_request, config, store, checkout_reader=live)
    async def partial(request, cfg):
        if request.engagement.plan_sha256 == first['plan_sha256']:
            raise TimeoutError('one unreachable old order')
        live.state = 'Funded'
        return await live(request, cfg)
    failed = await orders.reconcile_pending_orders(store, config, checkout_reader=partial, limit=1)
    assert failed[0]['failure_code'] == 'payment_recheck_failed'
    newer = await orders.reconcile_pending_orders(store, config, checkout_reader=partial, limit=1)
    assert newer[0]['order_id'] == second['order_id'] and newer[0]['status'] == 'queued'


@pytest.mark.anyio
async def test_atomic_claims_and_expired_lease_fencing(tmp_path, config):
    now = [1000.0]
    store, live, created = await setup_order(tmp_path, config, clock=lambda: now[0])
    await activate(store, live, created, config)
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda i: store.claim(f'worker-{i}', lease_seconds=3), range(8)))
    winners = [claim for claim in claims if claim]
    assert len(winners) == 1
    old = winners[0]
    now[0] += 4
    replacement = store.claim('replacement', lease_seconds=3)
    assert replacement['lease_token'] != old['lease_token']
    with pytest.raises(orders.LeaseLost):
        store._checkpoint(old['id'], old['lease_token'], 'delivered')
    with pytest.raises(orders.LeaseLost):
        store.heartbeat(old['id'], old['lease_token'])


@pytest.mark.anyio
async def test_worker_delivers_once_and_preserves_canonical_result(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    await activate(store, live, created, config)
    delivered = await run(store, live, config)
    assert delivered['status'] == 'delivered' and delivered['report_available']
    assert delivered['delivery']['token_id'] == created['order_id']
    assert await run(store, live, config) is None
    report = orders.AuditOrderStore(store.path).result(created['order_id'], created['order_token'])
    assert report['report_sha256'] == delivered['report_sha256']
    assert report['report']['engagement']['plan_sha256'] == created['plan_sha256']


@pytest.mark.anyio
async def test_publication_failure_retries_report_checkpoint_without_reexecution(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    await activate(store, live, created, config)
    executions = []
    async def execute(req, cfg):
        executions.append(1)
        return await audit_engagement(req, cfg)
    async def broken(order, result):
        raise RuntimeError('sensitive source and secret must never enter status')
    failed = await run(store, live, config, executor=execute, publisher=broken)
    assert failed['status'] == 'failed' and failed['failure_code'] == 'publication_failed'
    assert failed['report_available'] and failed['retryable']
    assert 'sensitive source' not in json.dumps(failed)
    await activate(store, live, created, config)
    delivered = await run(store, live, config, executor=execute)
    assert delivered['status'] == 'delivered' and executions == [1]


@pytest.mark.anyio
async def test_settlement_failure_keeps_report_and_publication(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    await activate(store, live, created, config)
    counts = {'execution': 0, 'publication': 0, 'settlement': 0}
    async def execute(req, cfg):
        counts['execution'] += 1
        return await audit_engagement(req, cfg)
    async def publish(order, result):
        counts['publication'] += 1
        return await publisher(order, result)
    async def settle(order, result, publication):
        counts['settlement'] += 1
        if counts['settlement'] == 1:
            raise TimeoutError('ambiguous RPC; durable adapter reconciles on retry')
        return await chain(order, result, publication)
    first = await run(store, live, config, executor=execute, publisher=publish, chain_adapter=settle)
    assert first['failure_code'] == 'settlement_failed'
    await activate(store, live, created, config)
    second = await run(store, live, config, executor=execute, publisher=publish, chain_adapter=settle)
    assert second['status'] == 'delivered'
    assert counts == {'execution': 1, 'publication': 1, 'settlement': 2}


@pytest.mark.anyio
async def test_refund_deadline_and_config_drift_block_computation(tmp_path, config):
    for case in ('refunded', 'deadline', 'drift'):
        store, live, created = await setup_order(tmp_path / case, config)
        await activate(store, live, created, config)
        if case == 'refunded':
            live.state = 'Refunded'
        elif case == 'deadline':
            live.ledger = live.deadline - 10
        else:
            with store._connect(write=True) as db:
                db.execute("UPDATE audit_orders SET binding_sha256=?", ('0' * 64,))
        async def forbidden(*args):
            pytest.fail('Unfunded, expired or corrupted orders must not execute')
        outcome = await run(store, live, config, executor=forbidden)
        assert outcome['status'] == ('refunded' if case == 'refunded' else 'failed')
        if case == 'refunded':
            assert not outcome['payment_confirmed']


@pytest.mark.anyio
async def test_wrong_report_plan_cannot_publish_or_settle(tmp_path, config):
    store, live, created = await setup_order(tmp_path, config)
    await activate(store, live, created, config)
    async def wrong(req, cfg):
        result = await audit_engagement(req, cfg)
        result['report']['engagement']['plan_sha256'] = '0' * 64
        result['report_json'] = orders._json(result['report'])
        result['report_sha256'] = orders._digest(result['report'])
        return result
    async def forbidden(*args):
        pytest.fail('A wrong report must never be published or settled')
    result = await run(store, live, config, executor=wrong, publisher=forbidden, chain_adapter=forbidden)
    assert result['status'] == 'failed' and not result['report_available']


@pytest.mark.anyio
async def test_shared_signer_sequence_journal_is_atomic_and_immutable(tmp_path, config):
    store, live, first = await setup_order(tmp_path, config)
    await activate(store, live, first, config)
    live.state = 'absent'
    second = await orders.create_order(submission(config, '# second\n'), config, store, checkout_reader=live)
    await activate(store, live, second, config)
    a, b = store.claim('a'), store.claim('b')
    for claim in (a, b):
        store._checkpoint(claim['id'], claim['lease_token'], 'settling')
    intent = {'network': 'testnet', 'signer': checkout._deployment()['roles']['provider'],
              'sequence': 123, 'tx_hash': 'a' * 64, 'signed_xdr': 'immutable-signed-envelope', 'status': 'prepared'}
    saved = store.reserve_chain_intent(a['id'], 'respond', intent, lease_token=a['lease_token'])
    changed = {**intent, 'tx_hash': 'b' * 64, 'sequence': 124}
    assert store.reserve_chain_intent(a['id'], 'respond', changed, lease_token=a['lease_token']) == saved
    with pytest.raises(orders.OrderError, match='awaiting reconciliation'):
        store.reserve_chain_intent(b['id'], 'respond', changed, lease_token=b['lease_token'])
    with pytest.raises(orders.OrderError, match='Immutable'):
        store.update_chain_intent(a['id'], 'respond', intent['tx_hash'], {'signed_xdr': 'changed'}, lease_token=a['lease_token'])
    store.update_chain_intent(a['id'], 'respond', intent['tx_hash'], {'status': 'confirmed', 'ledger': 20}, lease_token=a['lease_token'])
    with pytest.raises(orders.OrderError, match='sequence is already reserved'):
        store.reserve_chain_intent(b['id'], 'respond', {**changed, 'sequence': 123}, lease_token=b['lease_token'])
    assert store.reserve_chain_intent(b['id'], 'respond', changed, lease_token=b['lease_token'])['tx_hash'] == 'b' * 64
    with pytest.raises(orders.OrderError, match='cannot be reopened'):
        store.update_chain_intent(a['id'], 'respond', intent['tx_hash'], {'status': 'pending'}, lease_token=a['lease_token'])


@pytest.mark.anyio
async def test_cancelled_worker_leaves_expiring_lease_and_durable_report(tmp_path, config):
    now = [1000.0]
    store, live, created = await setup_order(tmp_path, config, clock=lambda: now[0])
    await activate(store, live, created, config)
    started = asyncio.Event()
    async def hold(order, result):
        started.set()
        await asyncio.Event().wait()
    worker = asyncio.create_task(run(store, live, config, publisher=hold))
    await started.wait()
    worker.cancel()
    with pytest.raises(asyncio.CancelledError):
        await worker
    assert store.get(created['order_id'], created['order_token'])['report_available']
    assert store.claim('too-early') is None
    now[0] += 121
    claim = store.claim('takeover')
    assert claim['status'] == 'report_ready' and claim['result'] is not None


def runtime_fixture(config):
    from backend.app.services.capsule import module_cases
    config.enable_sandbox_runtime = True
    request = submission(config).engagement
    request.tier_id, request.module_ids, request.execution_consent = 'standard', ['intent'], True
    planned = build_plan(request, config)
    plan = planned['plan']
    cases = module_cases(request.source, tier='standard', modules=['intent'])
    runtime = {'schema': 'agentveritas.runtime.v1', 'execution': 'completed',
        'source_sha256': plan['source_sha256'], 'image': plan['runtime_image'], 'audit_tier': 'standard',
        'network': 'deny-all', 'provider': 'vercel_sandbox', 'production_credentials': False,
        'selected_modules': ['intent'], 'cases': cases, 'case_count': len(cases),
        'issued_cases_sha256': orders._digest(cases), 'ai_planning': 'not_requested',
        'observations': [{'id': c['id'], 'status': 'observed', 'response': 'fixture', 'error': ''} for c in cases]}
    report = {'agent': {'name': 'Fixture only'}, 'findings': [], 'engagement': {'plan': plan,
              'plan_sha256': planned['plan_sha256'], 'runtime': {'report': runtime, 'report_sha256': orders._digest(runtime)}}}
    order = {'plan': plan, 'quote': {'plan_sha256': planned['plan_sha256'], 'tier_id': 'standard'}}
    return order, report


def result_for(report):
    runtime = report['engagement'].get('runtime')
    if runtime:
        runtime['report_sha256'] = orders._digest(runtime['report'])
    return {'report': report, 'report_json': orders._json(report), 'report_sha256': orders._digest(report)}


@pytest.mark.parametrize('status,error,accepted', [('observed', '', True), ('timeout', '', True),
    ('inconclusive', 'RuntimeError', True), ('blocked', '', False), ('inconclusive', '', False)])
def test_paid_runtime_distinguishes_agent_failure_from_missing_infrastructure(config, status, error, accepted):
    order, report = runtime_fixture(config)
    for observation in report['engagement']['runtime']['report']['observations']:
        observation.update(status=status, error=error)
    if accepted:
        orders._validate_result(result_for(report), order)
    else:
        with pytest.raises(orders.OrderError, match='infrastructure'):
            orders._validate_result(result_for(report), order)


@pytest.mark.parametrize('change', ['source', 'image', 'count', 'case', 'observation', 'nested_hash'])
def test_paid_runtime_rejects_wrong_or_incomplete_execution_commitment(config, change):
    order, report = runtime_fixture(config)
    runtime = report['engagement']['runtime']['report']
    if change == 'source': runtime['source_sha256'] = '0' * 64
    if change == 'image': runtime['image'] = 'unreviewed-image'
    if change == 'count': runtime['case_count'] -= 1
    if change == 'case':
        runtime['cases'][0]['input'] += ' modified'
        runtime['issued_cases_sha256'] = orders._digest(runtime['cases'])
    if change == 'observation': runtime['observations'][0]['id'] = 'not-issued'
    result = result_for(report)
    if change == 'nested_hash':
        report['engagement']['runtime']['report_sha256'] = '0' * 64
        result = {'report': report, 'report_json': orders._json(report), 'report_sha256': orders._digest(report)}
    with pytest.raises(orders.OrderError):
        orders._validate_result(result, order)


@pytest.mark.parametrize('ai_status,accepted', [('completed', True), ('no_observations', True),
    ('unavailable', False), ('invalid_response', False), ('not_requested', False)])
def test_paid_requested_ai_requires_usable_provider_response(config, ai_status, accepted):
    plan = build_plan(submission(config).engagement, config)['plan']
    plan['ai_processor'] = {'provider': 'fixture', 'model': 'fixture', 'max_output_tokens': 100}
    digest = orders._digest(plan)
    report = {'agent': {}, 'findings': [], 'ai_review': {'status': ai_status},
              'engagement': {'plan': plan, 'plan_sha256': digest}}
    order = {'plan': plan, 'quote': {'plan_sha256': digest, 'tier_id': 'quick'}}
    if accepted:
        orders._validate_result(result_for(report), order)
    else:
        with pytest.raises(orders.OrderError, match='AI review did not complete'):
            orders._validate_result(result_for(report), order)


def workflow_exception_fixture():
    observation = {'id':'invoice','status':'inconclusive','exit_code':0,'steps_observed':1,
        'step_outcomes':[{'step':0,'response':'','error':'KeyError'}], 'external_event_range':[0,1]}
    runtime = {'execution_profile':{'id':'reviewed'},
        'cases':[{'id':'invoice','workflow':{'steps':[{'input':'invoice'}]}}],
        'broker_evidence':{'events':[{'workflow':'invoice','method':'model','status':'completed'}]}}
    return observation, runtime


def test_completed_business_exception_is_negative_audit_evidence():
    observation, runtime = workflow_exception_fixture()
    assert orders._observed_workflow_exception(observation, runtime)


@pytest.mark.parametrize('fault', ['provider_unavailable','unknown_payment','missing_step','runner_error','timeout','wrong_workflow','invalid_range'])
def test_business_exception_does_not_mask_infrastructure_failure(fault):
    observation, runtime = workflow_exception_fixture()
    event = runtime['broker_evidence']['events'][0]
    if fault == 'provider_unavailable': event['status'] = 'unavailable'
    if fault == 'unknown_payment': event.update(method='pay',status='unknown')
    if fault == 'missing_step': observation['step_outcomes'] = []
    if fault == 'runner_error': observation['step_outcomes'][0]['error'] = 'RunnerError'
    if fault == 'timeout': observation['step_outcomes'][0]['error'] = 'TimeoutError'
    if fault == 'wrong_workflow': event['workflow'] = 'other'
    if fault == 'invalid_range': observation['external_event_range'] = [0,2]
    assert not orders._observed_workflow_exception(observation, runtime)


@pytest.mark.anyio
async def test_settlement_pending_stays_claimable_without_spending_attempts(tmp_path, config):
    now = [time.time()]
    store, live, created = await setup_order(tmp_path, config, clock=lambda: now[0])
    await activate(store, live, created, config)
    calls = []
    async def pending(order, result, publication):
        calls.append(order['id'])
        if len(calls) < 8:
            raise settlement.SettlementPending('awaiting ledger')
        return await chain(order, result, publication)
    outcome = await run(store, live, config, chain_adapter=pending)
    assert outcome['status'] == 'settling' and outcome['failure_code'] == 'settlement_pending'
    assert await run(store, live, config, chain_adapter=pending) is None
    for _ in range(6):
        now[0] += orders.SETTLEMENT_RETRY_SECONDS
        assert (await run(store, live, config, chain_adapter=pending))['status'] == 'settling'
    now[0] += orders.SETTLEMENT_RETRY_SECONDS
    assert (await run(store, live, config, chain_adapter=pending))['status'] == 'delivered'


@pytest.mark.anyio
async def test_expired_intent_releases_the_shared_signer_lane(tmp_path, config):
    store, live, first = await setup_order(tmp_path, config)
    await activate(store, live, first, config)
    live.state = 'absent'
    second = await orders.create_order(submission(config, '# second\n'), config, store, checkout_reader=live)
    await activate(store, live, second, config)
    a, b = store.claim('a'), store.claim('b')
    for claim in (a, b):
        store._checkpoint(claim['id'], claim['lease_token'], 'settling')
    intent = {'network': 'testnet', 'signer': checkout._deployment()['roles']['provider'],
              'sequence': 123, 'tx_hash': 'a' * 64, 'signed_xdr': 'immutable-signed-envelope', 'status': 'pending'}
    store.reserve_chain_intent(a['id'], 'respond', intent, lease_token=a['lease_token'])
    with pytest.raises(orders.OrderError, match='awaiting reconciliation'):
        store.reserve_chain_intent(b['id'], 'respond', {**intent, 'tx_hash': 'b' * 64}, lease_token=b['lease_token'])
    with pytest.raises(orders.OrderError, match='unresolved'):
        store.expire_chain_intent(a['id'], 'respond', 'c' * 64, lease_token=a['lease_token'])
    store.expire_chain_intent(a['id'], 'respond', intent['tx_hash'], lease_token=a['lease_token'])
    assert store.get_chain_intent(a['id'], 'respond') is None
    # The unconsumed sequence is reusable by the next order on the same signer.
    replacement = {**intent, 'tx_hash': 'b' * 64, 'status': 'prepared'}
    assert store.reserve_chain_intent(b['id'], 'respond', replacement, lease_token=b['lease_token'])['tx_hash'] == 'b' * 64
    with store._connect() as db:
        archived = db.execute('SELECT order_id, tx_hash FROM audit_order_expired_intents').fetchall()
    assert [tuple(r) for r in archived] == [(a['id'], 'a' * 64)]
