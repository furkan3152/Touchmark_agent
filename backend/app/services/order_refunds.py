"""Prepare requester-signed refunds, including stale/revoked agent versions.

Refund eligibility depends on the escrow's own pinned code and funded snapshot,
not the continuing availability of a registry validator or current agent source.
No customer key is received; simulation is never a refund confirmation.
"""
from __future__ import annotations

import time

from stellar_sdk import Account, Address, Keypair, SorobanServer, TransactionBuilder, scval, xdr
from stellar_sdk.soroban_rpc import SimulateTransactionResponse

from . import testnet_checkout as checkout


async def _snapshot(quote, *, transport=None):
    rpc = checkout._RPC(transport)
    manifest = checkout._deployment()
    try:
        network = await rpc.call('getNetwork', {})
        if network.get('passphrase') != checkout.PASSPHRASE:
            raise ValueError('Refund preparation requires the pinned Stellar Testnet network.')
        address = Address(checkout.PINNED_CONTRACTS['escrow']).to_xdr_sc_address()
        instance_key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA,
            contract_data=xdr.LedgerKeyContractData(address,
                xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
                xdr.ContractDataDurability.PERSISTENT)).to_xdr()
        account = Keypair.from_public_key(quote.requester).xdr_account_id()
        keys = {instance_key: 'instance',
            checkout._record_key(checkout.PINNED_CONTRACTS['escrow'], 'Job', scval.to_bytes(bytes.fromhex(quote.request_id))): 'job',
            xdr.LedgerKey(xdr.LedgerEntryType.ACCOUNT, account=xdr.LedgerKeyAccount(account)).to_xdr(): 'account'}
        raw = await rpc.call('getLedgerEntries', {'keys': list(keys)})
        records = {}
        for item in raw.get('entries', []):
            name = keys.get(item.get('key'))
            if name is None or name in records:
                raise ValueError('Unexpected or duplicate refund ledger record.')
            data = xdr.LedgerEntryData.from_xdr(item['xdr'])
            if name == 'account':
                if not data.account or data.account.account_id != account:
                    raise ValueError('Refund requester account does not match.')
                records[name] = data.account.seq_num.sequence_number.int64
            else:
                expected = xdr.LedgerKey.from_xdr(item['key']).contract_data
                if not data.contract_data or data.contract_data.contract != expected.contract or data.contract_data.key != expected.key:
                    raise ValueError('Refund ledger key does not match.')
                value = data.contract_data.val
                if name == 'instance':
                    instance = value.instance
                    if not instance or not instance.executable.wasm_hash or instance.executable.wasm_hash.hash.hex() != manifest['contracts']['escrow']['wasm_sha256']:
                        raise ValueError('Escrow code differs from the reviewed Testnet deployment.')
                    config = {str(scval.to_native(e.key)[0]): checkout._native(scval.to_native(e.val))
                              for e in (instance.storage.sc_map if instance.storage else [])}
                    if config.get('Token') != checkout.NATIVE_SAC:
                        raise ValueError('Refund escrow token is not the pinned native XLM SAC.')
                    records[name] = config
                else:
                    records[name] = checkout._native(scval.to_native(value))
        if set(records) != {'instance', 'job', 'account'}:
            raise ValueError('Refund records are unavailable or require restoration.')
        ledger = raw.get('latestLedger')
        if type(ledger) is not int or not 0 < ledger < 4294967295:
            raise ValueError('A valid live refund ledger is required.')
        return {'ledger': ledger, **records}
    finally:
        await rpc.close()


async def _bound_snapshot(order: dict, *, transport=None, snapshot_reader=None):
    quote = checkout.Quote.model_validate(order['quote'])
    manifest = checkout._deployment()
    if (quote.contracts != checkout.PINNED_CONTRACTS or quote.requester != order['requester']
            or quote.request_id != order['id'] or quote.provider != manifest['roles']['provider']
            or quote.evaluator != manifest['roles']['evaluator']):
        raise ValueError('The stored refund order is not bound to the pinned official offer.')
    state = await (snapshot_reader or _snapshot)(quote, transport=transport)
    job = state['job']
    expected = {'requester': quote.requester, 'provider': quote.provider, 'evaluator': quote.evaluator,
                'amount': int(quote.amount_atomic), 'deadline': quote.deadline_ledger,
                'fee_bps': quote.fee_bps, 'fee_to': quote.treasury}
    if not isinstance(job, dict) or any(job.get(k) != v for k, v in expected.items()):
        raise ValueError('Escrow refund snapshot does not match the stored order.')
    return quote, state


async def reconcile_order_refund(order_id: str, token: str, store, *, transport=None, snapshot_reader=None):
    store.get(order_id, token)
    quote, state = await _bound_snapshot(store._private(order_id), transport=transport, snapshot_reader=snapshot_reader)
    status = state['job'].get('state')
    with store._connect(write=True) as db:
        row = store._authorized(db, order_id, token)
        if status == ['Refunded']:
            db.execute("""UPDATE audit_orders SET status='refunded',paid=0,checked_ledger=?,
                lease_token=NULL,lease_until=NULL,retryable=0,failure_code=NULL,updated_at=? WHERE id=?""",
                (state['ledger'], store.clock(), order_id))
    result = store.get(order_id, token)
    result['refund_checked_at_ledger'] = state['ledger']
    result['refund_eligible'] = status == ['Disputed'] or (status in (['Funded'], ['Submitted']) and state['ledger'] >= quote.deadline_ledger)
    return result


async def prepare_order_refund(order: dict, *, transport=None, snapshot_reader=None, now=None):
    quote, state = await _bound_snapshot(order, transport=transport, snapshot_reader=snapshot_reader)
    job = state['job']
    status = job.get('state')
    if status != ['Disputed'] and not (status in (['Funded'], ['Submitted']) and state['ledger'] >= quote.deadline_ledger):
        raise ValueError('Refund is available for disputed escrow, or funded/submitted escrow after its ledger deadline. Completed payment cannot be refunded by this contract.')
    timestamp = int(time.time()) if now is None else now
    tx = (TransactionBuilder(Account(quote.requester, state['account']), checkout.PASSPHRASE, base_fee=100)
          .append_invoke_contract_function_op(checkout.PINNED_CONTRACTS['escrow'], 'refund',
              [scval.to_address(quote.requester), scval.to_bytes(bytes.fromhex(quote.request_id))])
          .add_time_bounds(0, timestamp + 120).build())
    rpc = checkout._RPC(transport)
    try:
        raw = await rpc.call('simulateTransaction', {'transaction': tx.to_xdr(), 'authMode': 'record'})
        simulation = SimulateTransactionResponse.model_validate(raw)
        if simulation.error or simulation.restore_preamble or not simulation.transaction_data or len(simulation.results or []) != 1:
            raise ValueError('Refund simulation did not succeed; no signable transaction is returned.')
        for item in simulation.results[0].auth or []:
            if xdr.SorobanAuthorizationEntry.from_xdr(item).credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT:
                raise ValueError('Refund simulation requested unsupported authorization.')
        server = SorobanServer(checkout.RPC_URL)
        try:
            prepared = server.prepare_transaction(tx, simulation)
        finally:
            server.close()
        if prepared.signatures or not 100 <= prepared.transaction.fee <= checkout.MAX_FEE_ATOMIC:
            raise ValueError('Refund simulation returned unsafe transaction fees or signatures.')
        return {'step': 'refund', 'request_id': quote.request_id, 'unsigned_xdr': prepared.to_xdr(),
                'transaction_hash': prepared.hash_hex(), 'network_passphrase': checkout.PASSPHRASE,
                'signer': quote.requester, 'fee_atomic': str(prepared.transaction.fee),
                'expires_at': timestamp + 120, 'refund_confirmed': False,
                'simulation': {'status': 'succeeded', 'ledger': simulation.latest_ledger,
                               'is_payment_confirmation': False, 'authorization': 'source_account'}}
    finally:
        await rpc.close()
