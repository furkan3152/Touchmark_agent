"""Refund tests use real XDR encoding and fake RPC; no signing or submission."""
from copy import deepcopy
import json

import httpx
import pytest
from stellar_sdk import Address, Keypair, TransactionEnvelope, scval, xdr

from backend.app.services import audit_orders as orders
from backend.app.services import order_refunds as refunds
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_product import EngagementRequest
from backend.app.services.studio import ReviewRequest


NOW = 1_800_000_000
DEADLINE = 5_210_000
WALLET = 'GD2M2PJ67RBTFEBPSRX4PAWTBAOGUR5OLZ5OVD6HECXFI5ERCRMB7ZBI'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def refund_case():
    manifest = checkout._deployment()
    quote = checkout.Quote(requester=WALLET, tier_id='quick', source_sha256='a' * 64,
        plan_sha256='b' * 64, agent_id='c' * 64, request_id='d' * 64,
        amount_atomic='1000000', contracts=checkout.PINNED_CONTRACTS,
        provider=manifest['roles']['provider'], evaluator=manifest['roles']['evaluator'],
        treasury=manifest['roles']['treasury'], deadline_ledger=DEADLINE,
        issued_at=NOW - 10000, expires_at=NOW - 9400)
    order = {'id': quote.request_id, 'requester': WALLET, 'quote': quote.model_dump()}
    state = {'ledger': DEADLINE, 'account': 12345, 'instance': {'Token': checkout.NATIVE_SAC},
        'job': {'requester': WALLET, 'provider': quote.provider, 'evaluator': quote.evaluator,
            'amount': int(quote.amount_atomic), 'deadline': DEADLINE, 'fee_bps': quote.fee_bps,
            'fee_to': quote.treasury, 'state': ['Funded']}}
    return order, state


def simulation(*, fee='1234', auth=None):
    resources = xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(1000), xdr.Uint32(0), xdr.Uint32(0))
    data = xdr.SorobanTransactionData(xdr.SorobanTransactionDataExt(0), resources, xdr.Int64(int(fee)))
    return {'latestLedger': DEADLINE, 'transactionData': data.to_xdr(), 'minResourceFee': fee,
            'results': [{'xdr': scval.to_void().to_xdr(), 'auth': auth or []}]}


def snapshot_reader(state):
    async def read(*args, **kwargs):
        return deepcopy(state)
    return read


def simulation_transport(response=None, calls=None):
    def respond(request):
        assert str(request.url) == checkout.RPC_URL
        body = json.loads(request.content)
        assert body['method'] == 'simulateTransaction' and body['params']['authMode'] == 'record'
        if calls is not None:
            calls.append(body)
        return httpx.Response(200, json={'result': response if response is not None else simulation()})
    return httpx.MockTransport(respond)


@pytest.mark.anyio
@pytest.mark.parametrize('state,ledger', [('Funded', DEADLINE), ('Submitted', DEADLINE + 1),
                                        ('Disputed', DEADLINE - 200)])
async def test_eligible_refund_is_exact_unsigned_requester_call(refund_case, state, ledger):
    order, snapshot = refund_case
    snapshot['job']['state'], snapshot['ledger'] = [state], ledger
    calls = []
    result = await refunds.prepare_order_refund(order, snapshot_reader=snapshot_reader(snapshot),
        transport=simulation_transport(calls=calls), now=NOW)
    tx = TransactionEnvelope.from_xdr(result['unsigned_xdr'], checkout.PASSPHRASE)
    assert tx.signatures == [] and len(tx.transaction.operations) == 1
    assert tx.transaction.source.account_id == WALLET and tx.transaction.sequence == 12346
    assert tx.transaction.preconditions.time_bounds.max_time == NOW + 120
    call = tx.transaction.operations[0].host_function.invoke_contract
    assert Address.from_xdr_sc_address(call.contract_address).address == checkout.PINNED_CONTRACTS['escrow']
    assert call.function_name.sc_symbol == b'refund'
    assert [checkout._native(scval.to_native(v)) for v in call.args] == [WALLET, order['id']]
    assert result['transaction_hash'] == tx.hash_hex() and result['fee_atomic'] == '1334'
    assert result['refund_confirmed'] is False and result['simulation']['is_payment_confirmation'] is False
    assert len(calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize('state,ledger', [('Created', DEADLINE + 100), ('Funded', DEADLINE - 1),
    ('Submitted', DEADLINE - 1), ('Complete', DEADLINE + 100), ('Refunded', DEADLINE + 100), ('Unknown', DEADLINE + 100)])
async def test_early_complete_and_invalid_refunds_never_simulate(refund_case, state, ledger):
    order, snapshot = refund_case
    snapshot['job']['state'], snapshot['ledger'] = [state], ledger
    calls = []
    with pytest.raises(ValueError, match='Refund is available'):
        await refunds.prepare_order_refund(order, snapshot_reader=snapshot_reader(snapshot),
            transport=simulation_transport(calls=calls), now=NOW)
    assert calls == []


@pytest.mark.anyio
@pytest.mark.parametrize('field,value', [('requester', checkout.PINNED_CONTRACTS['registry']),
    ('amount', 1), ('deadline', DEADLINE - 1), ('fee_bps', 0), ('provider', WALLET), ('evaluator', WALLET)])
async def test_mismatched_escrow_snapshot_never_prepares_refund(refund_case, field, value):
    order, snapshot = refund_case
    snapshot['job'][field] = value
    calls = []
    with pytest.raises(ValueError, match='snapshot does not match'):
        await refunds.prepare_order_refund(order, snapshot_reader=snapshot_reader(snapshot),
            transport=simulation_transport(calls=calls), now=NOW)
    assert calls == []


def unsupported_authorization():
    invocation = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
        xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
        contract_fn=xdr.InvokeContractArgs(Address(checkout.PINNED_CONTRACTS['escrow']).to_xdr_sc_address(),
            xdr.SCSymbol(b'refund'), [scval.to_address(WALLET), scval.to_bytes(bytes.fromhex('d' * 64))])), [])
    credentials = xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS,
        address=xdr.SorobanAddressCredentials(Address(WALLET).to_xdr_sc_address(),
            xdr.Int64(1), xdr.Uint32(DEADLINE + 10), scval.to_void()))
    return xdr.SorobanAuthorizationEntry(credentials, invocation).to_xdr()


@pytest.mark.anyio
@pytest.mark.parametrize('failure', ['error', 'restore', 'fee', 'auth', 'no_result'])
async def test_refund_simulation_failure_does_not_return_signable_xdr(refund_case, failure):
    order, snapshot = refund_case
    response = simulation()
    if failure == 'error':
        response['error'] = 'contract rejected'
    elif failure == 'restore':
        response['restorePreamble'] = {'minResourceFee': '10', 'transactionData': response['transactionData']}
    elif failure == 'fee':
        response = simulation(fee=str(checkout.MAX_FEE_ATOMIC + 1))
    elif failure == 'auth':
        response = simulation(auth=[unsupported_authorization()])
    else:
        response['results'] = []
    with pytest.raises(ValueError):
        await refunds.prepare_order_refund(order, snapshot_reader=snapshot_reader(snapshot),
            transport=simulation_transport(response), now=NOW)


def ledger_entries(quote, job, *, wrong_wasm=False, wrong_token=False):
    escrow = Address(checkout.PINNED_CONTRACTS['escrow']).to_xdr_sc_address()
    entries = []

    def contract_entry(key, value):
        ledger_key = checkout._contract_key(checkout.PINNED_CONTRACTS['escrow'], key)
        data = xdr.LedgerEntryData(xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.ContractDataEntry(
            xdr.ExtensionPoint(0), escrow, key, xdr.ContractDataDurability.PERSISTENT, value))
        entries.append({'key': ledger_key, 'xdr': data.to_xdr()})

    wasm = ('00' * 32 if wrong_wasm else checkout._deployment()['contracts']['escrow']['wasm_sha256'])
    storage = xdr.SCMap([xdr.SCMapEntry(scval.to_vec([scval.to_symbol('Token')]),
        scval.to_address(checkout.PINNED_CONTRACTS['registry'] if wrong_token else checkout.NATIVE_SAC))])
    instance = xdr.SCContractInstance(xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,
        xdr.Hash(bytes.fromhex(wasm))), storage)
    contract_entry(xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
                   xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE, instance=instance))
    values = {key: scval.to_address(job[key]) for key in ('requester', 'provider', 'evaluator', 'fee_to')}
    values.update(amount=scval.to_int128(job['amount']), deadline=scval.to_uint32(job['deadline']),
        fee_bps=scval.to_uint32(job['fee_bps']), state=scval.to_vec([scval.to_symbol(job['state'][0])]))
    contract_entry(scval.to_vec([scval.to_symbol('Job'), scval.to_bytes(bytes.fromhex(quote.request_id))]),
                   scval.to_struct(values))
    account = Keypair.from_public_key(quote.requester).xdr_account_id()
    ledger_key = xdr.LedgerKey(xdr.LedgerEntryType.ACCOUNT, account=xdr.LedgerKeyAccount(account)).to_xdr()
    value = xdr.AccountEntry(account, xdr.Int64(100_000_000), xdr.SequenceNumber(xdr.Int64(12345)),
        xdr.Uint32(0), None, xdr.Uint32(0), xdr.String32(b''), xdr.Thresholds(b'\x01\x00\x00\x00'), [], xdr.AccountEntryExt(0))
    entries.append({'key': ledger_key, 'xdr': xdr.LedgerEntryData(xdr.LedgerEntryType.ACCOUNT, account=value).to_xdr()})
    return entries


@pytest.mark.anyio
async def test_stale_or_revoked_registry_source_does_not_block_contract_refund(refund_case):
    order, snapshot = refund_case
    quote = checkout.Quote.model_validate(order['quote'])
    entries = ledger_entries(quote, snapshot['job'])
    seen = []

    def rpc(request):
        assert str(request.url) == checkout.RPC_URL
        body = json.loads(request.content)
        seen.append(body['method'])
        if body['method'] == 'getNetwork':
            result = {'passphrase': checkout.PASSPHRASE}
        elif body['method'] == 'getLedgerEntries':
            # Registry records are deliberately absent/revoked. A refund reads
            # only the escrow's immutable job, reviewed instance, and requester.
            assert set(body['params']['keys']) == {item['key'] for item in entries}
            for key in body['params']['keys']:
                decoded = xdr.LedgerKey.from_xdr(key)
                if decoded.contract_data:
                    assert Address.from_xdr_sc_address(decoded.contract_data.contract).address == checkout.PINNED_CONTRACTS['escrow']
            result = {'latestLedger': DEADLINE, 'entries': entries}
        else:
            assert body['method'] == 'simulateTransaction'
            result = simulation()
        return httpx.Response(200, json={'result': result})

    result = await refunds.prepare_order_refund(order, transport=httpx.MockTransport(rpc), now=NOW)
    assert result['step'] == 'refund' and result['refund_confirmed'] is False
    assert seen == ['getNetwork', 'getLedgerEntries', 'simulateTransaction']


@pytest.mark.anyio
@pytest.mark.parametrize('failure', ['wrong_network', 'wrong_wasm', 'wrong_token', 'duplicate', 'missing_account', 'boolean_ledger'])
async def test_refund_reads_reject_unpinned_or_incomplete_chain_evidence(refund_case, failure):
    order, snapshot = refund_case
    quote = checkout.Quote.model_validate(order['quote'])
    entries = ledger_entries(quote, snapshot['job'], wrong_wasm=failure == 'wrong_wasm', wrong_token=failure == 'wrong_token')
    if failure == 'duplicate':
        entries.append(entries[0])
    if failure == 'missing_account':
        entries.pop()

    def rpc(request):
        method = json.loads(request.content)['method']
        if method == 'getNetwork':
            return httpx.Response(200, json={'result': {'passphrase': 'wrong network' if failure == 'wrong_network' else checkout.PASSPHRASE}})
        assert method == 'getLedgerEntries'
        return httpx.Response(200, json={'result': {'entries': entries, 'latestLedger': True if failure == 'boolean_ledger' else DEADLINE}})

    with pytest.raises(ValueError):
        await refunds._snapshot(quote, transport=httpx.MockTransport(rpc))


def persisted_order(tmp_path, order):
    store = orders.AuditOrderStore(tmp_path / 'orders.sqlite')
    submission = orders.OrderSubmission(requester=WALLET, storage_consent=True, auto_settlement_consent=True,
        publication_consent=True, wallet_proof={'challenge': {'nonce': 'e' * 64}},
        engagement=EngagementRequest(source=ReviewRequest(name='Reader', purpose='Read fixture only.',
            files={'agent.py': 'def answer(prompt):\n    return "12"\n'}), plan_sha256=order['quote']['plan_sha256']))
    created = store._insert(submission, {}, {'quote': order['quote'], 'chain': {'ledger': DEADLINE - 100}})
    return store, created


@pytest.mark.anyio
async def test_refund_reconcile_wrong_capability_stops_before_rpc(refund_case, tmp_path):
    order, _ = refund_case
    store, created = persisted_order(tmp_path, order)

    async def forbidden(*args, **kwargs):
        pytest.fail('An invalid capability must not read private source or call the chain.')

    with pytest.raises(orders.OrderError, match='capability'):
        await refunds.reconcile_order_refund(created['order_id'], '0' * 64, store, snapshot_reader=forbidden)


@pytest.mark.anyio
async def test_pending_refund_reconciliation_never_queues_paid_audit(refund_case, tmp_path):
    order, snapshot = refund_case
    store, created = persisted_order(tmp_path, order)
    result = await refunds.reconcile_order_refund(created['order_id'], created['order_token'], store,
        snapshot_reader=snapshot_reader(snapshot))
    assert result['status'] == 'awaiting_payment' and result['refund_eligible'] is True
    assert result['refund_checked_at_ledger'] == DEADLINE
    assert store.claim('must-not-run') is None


@pytest.mark.anyio
async def test_only_live_refunded_state_cancels_lease_and_records_refund(refund_case, tmp_path):
    order, snapshot = refund_case
    store, created = persisted_order(tmp_path, order)
    with store._connect(write=True) as db:
        db.execute("UPDATE audit_orders SET status='queued',paid=1 WHERE id=?", (created['order_id'],))
    claimed = store.claim('old-worker')
    snapshot['job']['state'] = ['Refunded']
    result = await refunds.reconcile_order_refund(created['order_id'], created['order_token'], store,
        snapshot_reader=snapshot_reader(snapshot))
    assert result['status'] == 'refunded' and result['payment_confirmed'] is False
    assert result['refund_eligible'] is False
    assert store._private(created['order_id'])['lease_token'] is None
    with pytest.raises(orders.LeaseLost):
        store._checkpoint(created['order_id'], claimed['lease_token'], 'report_ready')
