from copy import deepcopy
from hashlib import sha256
import hmac
import json

import httpx
import pytest
from pydantic import ValidationError
from stellar_sdk import TransactionEnvelope, scval, xdr

from backend.app.config import Settings
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_product import EngagementRequest, build_plan
from backend.app.services.studio import ReviewRequest
from backend.app.reporting.generator import canonical_json

NOW = 1_800_000_000
WALLET = 'GD2M2PJ67RBTFEBPSRX4PAWTBAOGUR5OLZ5OVD6HECXFI5ERCRMB7ZBI'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def settings(**kwargs):
    return Settings(_env_file=None, stellar_network='testnet', runtime_api_key='client-access-token-' * 3,
                    checkout_quote_signing_key='separate-server-quote-secret-' * 3, **kwargs)


def request(config=None):
    config = config or settings()
    engagement = EngagementRequest(source=ReviewRequest(name='Reader', purpose='Return only the fixed public balance.',
        files={'agent.py': 'def answer(prompt):\n    return "Public balance: 12"\n'}))
    engagement.plan_sha256 = build_plan(engagement, config)['plan_sha256']
    return checkout.CheckoutRequest(engagement=engagement, requester=WALLET)


def bare_state():
    return {'ledger': 5_200_000, 'account': {'sequence': 12345, 'balance': 100_000_000_000}}


def progression(quote, stage):
    state = bare_state()
    if stage >= 1:
        state['agent'] = {'owner': WALLET, 'version': 1, 'active': True, 'meta_hash': quote.plan_sha256,
                          'end_hash': quote.source_sha256, 'meta_uri': 'urn:veritas:plan:' + quote.plan_sha256}
    if stage >= 2:
        state['validation'] = {'agent_id': quote.agent_id, 'version': 1, 'meta_hash': quote.plan_sha256,
            'end_hash': quote.source_sha256, 'requester': WALLET, 'validator': quote.provider, 'state': ['Pending']}
    if stage >= 3:
        state['job'] = {'requester': WALLET, 'provider': quote.provider, 'evaluator': quote.evaluator,
            'amount': int(quote.amount_atomic), 'deadline': quote.deadline_ledger, 'fee_bps': quote.fee_bps,
            'fee_to': quote.treasury, 'state': ['Created' if stage == 3 else 'Funded']}
        state['binding'] = {'agent_id': quote.agent_id, 'owner': WALLET, 'version': 1,
                           'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256}
    return state


def stub_snapshot(monkeypatch, state=None, stage=0):
    async def reader(rpc, quote, manifest):
        return deepcopy(state) if state is not None else progression(quote, stage)
    monkeypatch.setattr(checkout, '_snapshot', reader)


def simulation_response(error=None, auth=None, fee='1234'):
    resources = xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(1000), xdr.Uint32(0), xdr.Uint32(0))
    data = xdr.SorobanTransactionData(xdr.SorobanTransactionDataExt(0), resources, xdr.Int64(int(fee)))
    response = {'latestLedger': 5_200_001, 'transactionData': data.to_xdr(), 'minResourceFee': fee,
                'results': [{'xdr': scval.to_void().to_xdr(), 'auth': auth or []}]}
    if error:
        response['error'] = error
    return response


@pytest.mark.anyio
async def test_quote_binds_acknowledged_source_plan_wallet_price_and_retries(monkeypatch):
    stub_snapshot(monkeypatch)
    first = await checkout.prepare_checkout(request(), settings(), now=NOW)
    second = await checkout.prepare_checkout(request(), settings(), now=NOW + 30)
    assert first['quote']['agent_id'] == second['quote']['agent_id']
    assert first['quote']['request_id'] == second['quote']['request_id']
    assert first['quote_signature'] != second['quote_signature']
    assert first['quote']['amount_atomic'] == '1000000'
    assert first['next_step'] == 'register'
    assert not first['payment_confirmed']
    changed = request()
    changed.engagement.source.files['agent.py'] += '# changed\n'
    with pytest.raises(ValueError, match='acknowledge'):
        await checkout.prepare_checkout(changed, settings(), now=NOW)
    changed.engagement.plan_sha256 = build_plan(changed.engagement, settings())['plan_sha256']
    revised = await checkout.prepare_checkout(changed, settings(), now=NOW)
    assert revised['quote']['request_id'] != first['quote']['request_id']


@pytest.mark.anyio
async def test_server_quote_key_is_distinct_from_client_api_key(monkeypatch):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    forged = checkout.CheckoutStepRequest(quote=result['quote'], quote_signature=result['quote_signature'], step='register')
    config = settings()
    config.checkout_quote_signing_key = config.runtime_api_key
    with pytest.raises(ValueError, match='must differ'):
        checkout._signature(forged.quote, config)
    client_key = hmac.new(config.runtime_api_key.encode(), b'veritas.testnet-checkout.quote/v1', sha256).digest()
    forged.quote_signature = hmac.new(client_key, canonical_json(forged.quote.model_dump()).encode(), sha256).hexdigest()
    with pytest.raises(ValueError, match='signature'):
        await checkout.prepare_checkout_step(forged, settings(), now=NOW)


@pytest.mark.anyio
@pytest.mark.parametrize('field,value', [('amount_atomic', '1'), ('source_sha256', 'a' * 64),
    ('requester', 'GB6M2BNKWTFIHWBGM7LYGZ3ZIICQZJGQ6DXAFQUKU36RILZ3IYSA55UE'),
    ('evaluator', WALLET), ('deadline_ledger', 1)])
async def test_quote_tampering_rejected_before_rpc(monkeypatch, field, value):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    result['quote'][field] = value
    async def forbidden(*args):
        pytest.fail('Invalid quotes must not make RPC calls')
    monkeypatch.setattr(checkout, '_snapshot', forbidden)
    with pytest.raises(ValueError, match='signature'):
        await checkout.prepare_checkout_step(checkout.CheckoutStepRequest(
            quote=result['quote'], quote_signature=result['quote_signature'], step='register'), settings(), now=NOW)


@pytest.mark.anyio
async def test_quote_expiry_and_network_fail_closed(monkeypatch):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    step = checkout.CheckoutStepRequest(quote=result['quote'], quote_signature=result['quote_signature'], step='register')
    for timestamp in [NOW - 1, NOW + 600]:
        with pytest.raises(ValueError, match='expired'):
            await checkout.prepare_checkout_step(step, settings(), now=timestamp)
    config = settings()
    config.stellar_network = 'mainnet'
    with pytest.raises(ValueError, match='testnet'):
        await checkout.prepare_checkout(request(), config, now=NOW)
    config = settings()
    config.checkout_quote_signing_key = ''
    with pytest.raises(ValueError, match='server-only'):
        await checkout.prepare_checkout(request(), config, now=NOW)
    invalid = result['quote'] | {'network': 'mainnet'}
    with pytest.raises(ValidationError):
        checkout.Quote.model_validate(invalid)


@pytest.mark.anyio
async def test_official_roles_cannot_register_customer_checkout(monkeypatch):
    request_ = request()
    request_.requester = checkout._deployment()['roles']['provider']
    with pytest.raises(ValueError, match='distinct'):
        await checkout.prepare_checkout(request_, settings(), now=NOW)


@pytest.mark.anyio
@pytest.mark.parametrize('stage,step,method', [(0, 'register', 'reg_agent'), (1, 'request', 'req_valid'),
                                            (2, 'create', 'create'), (3, 'fund', 'fund')])
async def test_each_step_builds_exact_unsigned_wallet_transaction(monkeypatch, stage, step, method):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    stub_snapshot(monkeypatch, stage=stage)
    calls = []
    def rpc(req):
        body = json.loads(req.content)
        calls.append(body)
        assert str(req.url) == checkout.RPC_URL
        assert body['method'] == 'simulateTransaction'
        assert body['params']['authMode'] == 'record'
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': 1, 'result': simulation_response()})
    prepared = await checkout.prepare_checkout_step(checkout.CheckoutStepRequest(
        quote=result['quote'], quote_signature=result['quote_signature'], step=step), settings(),
        transport=httpx.MockTransport(rpc), now=NOW)
    envelope = TransactionEnvelope.from_xdr(prepared['unsigned_xdr'], checkout.PASSPHRASE)
    assert envelope.signatures == []
    assert envelope.transaction.source.account_id == WALLET
    assert envelope.transaction.sequence == 12346
    assert envelope.transaction.preconditions.time_bounds.max_time == NOW + 120
    assert prepared['transaction_hash'] == envelope.hash_hex()
    assert prepared['fee_atomic'] == '1334'
    assert prepared['simulation']['is_payment_confirmation'] is False
    assert len(envelope.transaction.operations) == len(calls) == 1
    invocation = envelope.transaction.operations[0].host_function.invoke_contract
    assert invocation.function_name.sc_symbol.decode() == method
    args = [checkout._native(scval.to_native(v)) for v in invocation.args]
    assert args[0] == WALLET
    if step == 'create':
        assert args[1] == result['quote']['request_id']
        assert args[2:4] == [result['quote']['provider'], result['quote']['evaluator']]
        assert args[4] == 1_000_000
    if step == 'register':
        assert args[3:5] == [result['quote']['plan_sha256'], result['quote']['source_sha256']]


@pytest.mark.anyio
async def test_funding_confirmation_requires_exact_live_job(monkeypatch):
    stub_snapshot(monkeypatch, stage=4)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    assert result['payment_confirmed'] is True
    assert result['status'] == 'funded' and result['next_step'] is None
    quote = checkout.Quote.model_validate(result['quote'])
    state = progression(quote, 4)
    for target, field, value in [('job', 'provider', WALLET), ('job', 'amount', 1),
                                 ('binding', 'end_hash', 'a' * 64), ('agent', 'version', 2)]:
        bad = deepcopy(state)
        bad[target][field] = value
        stub_snapshot(monkeypatch, state=bad)
        with pytest.raises(ValueError):
            await checkout.prepare_checkout(request(), settings(), now=NOW)
    state['job']['state'] = ['Refunded']
    stub_snapshot(monkeypatch, state=state)
    refunded = await checkout.prepare_checkout(request(), settings(), now=NOW)
    assert refunded['status'] == 'refunded' and not refunded['payment_confirmed']


@pytest.mark.anyio
async def test_simulation_failure_and_excessive_fee_never_return_xdr(monkeypatch):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    step = checkout.CheckoutStepRequest(quote=result['quote'], quote_signature=result['quote_signature'], step='register')
    for response in [simulation_response(error='failed'), simulation_response(fee='20000001'),
                     simulation_response() | {'restorePreamble': {'minResourceFee': '10',
                     'transactionData': simulation_response()['transactionData']}}]:
        transport = httpx.MockTransport(lambda _: httpx.Response(200, json={'result': response}))
        with pytest.raises(ValueError):
            await checkout.prepare_checkout_step(step, settings(), transport=transport, now=NOW)


@pytest.mark.anyio
async def test_wrong_step_and_unfunded_wallet_do_not_simulate(monkeypatch):
    stub_snapshot(monkeypatch)
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    step = checkout.CheckoutStepRequest(quote=result['quote'], quote_signature=result['quote_signature'], step='fund')
    with pytest.raises(ValueError, match='currently payable'):
        await checkout.prepare_checkout_step(step, settings(), now=NOW)
    stub_snapshot(monkeypatch, state={'ledger': 5_200_000})
    result = await checkout.prepare_checkout(request(), settings(), now=NOW)
    assert result['status'] == 'wallet_unfunded'
    assert not result['payment_confirmed']


@pytest.mark.anyio
async def test_rpc_has_fixed_origin_no_redirects_and_bounded_responses():
    for response in [httpx.Response(302, headers={'location': 'http://localhost/secret'}),
                     httpx.Response(200, content=b'x' * 512_001),
                     httpx.Response(200, json={'error': {'message': 'failure'}})]:
        rpc = checkout._RPC(httpx.MockTransport(lambda _: response))
        try:
            with pytest.raises(ValueError):
                await rpc.call('getNetwork')
        finally:
            await rpc.close()
