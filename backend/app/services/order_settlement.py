"""First-party Testnet fulfillment with durable, fenced transaction intents.

Only the reviewed Testnet deployment is supported. The customer has already
funded a source-bound job; this adapter cannot sign customer transactions.
Persisting an envelope before broadcast and reconciling live contract state are
required. A send acknowledgement is never treated as delivery evidence.
"""
from __future__ import annotations

import asyncio
from hashlib import sha256
import inspect
import math
import time
from urllib.parse import urlsplit

import httpx
from stellar_sdk import Address, Keypair, TransactionEnvelope, scval, xdr
from stellar_sdk.client.requests_client import RequestsClient
from stellar_sdk.contract import ContractClient
from stellar_sdk import SorobanServer

from ..reporting.generator import canonical_json
from .report_delivery import DeliveryRequest, decode_report
from . import testnet_checkout as checkout

STEPS = ('respond', 'submit', 'complete', 'issue')
TERMINAL = {'confirmed', 'observed', 'failed'}
# Seconds past a signed envelope's max_time before it is treated as unlandable.
EXPIRY_MARGIN = 300


class SettlementPending(ValueError):
    """The immutable intent must be reconciled on a later worker attempt."""


async def _await(value):
    return await value if inspect.isawaitable(value) else value


def _call(step, quote, digest, uri, score, expires_at):
    request = scval.to_bytes(bytes.fromhex(quote.request_id))
    content = scval.to_bytes(bytes.fromhex(digest))
    provider = scval.to_address(quote.provider)
    if step == 'respond':
        return 'registry', 'respond', [provider, request, scval.to_uint32(score), scval.to_string(uri), content], quote.provider
    if step == 'submit':
        return 'escrow', 'submit', [provider, request, content], quote.provider
    if step == 'complete':
        return 'escrow', 'complete', [scval.to_address(quote.evaluator), request, scval.to_uint32(score)], quote.evaluator
    if step == 'issue':
        return 'credential', 'issue', [request, scval.to_uint64(expires_at)], quote.provider
    raise ValueError('Unknown official settlement step.')


def _validate_intent(intent, step, quote, digest, uri, score):
    """Do not trust journal metadata to describe what the signed XDR does."""
    try:
        envelope = TransactionEnvelope.from_xdr(intent['signed_xdr'], checkout.PASSPHRASE)
        expires = intent.get('credential_expires_at', 0)
        kind, function, args, signer = _call(step, quote, digest, uri, score, expires)
        tx = envelope.transaction
        op = tx.operations[0]
        call = op.host_function.invoke_contract
        credentials = [a.credentials.type for a in op.auth]
        expected_type = xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT
        if (intent['tx_hash'] != envelope.hash_hex() or intent['network'] != 'testnet'
                or intent['signer'] != signer or intent['sequence'] != tx.sequence
                or tx.source.account_id != signer or len(tx.operations) != 1 or op.source is not None
                or not call or Address.from_xdr_sc_address(call.contract_address).address != checkout.PINNED_CONTRACTS[kind]
                or call.function_name.sc_symbol.decode() != function
                or [a.to_xdr() for a in call.args] != [a.to_xdr() for a in args]
                or any(c != expected_type for c in credentials)
                or not 100 <= tx.fee <= checkout.MAX_FEE_ATOMIC
                or not tx.preconditions.time_bounds or not tx.preconditions.time_bounds.max_time
                or len(envelope.signatures) != 1
                or (step == 'issue' and (not isinstance(expires, int) or expires <= 0))):
            raise ValueError()
        Keypair.from_public_key(signer).verify(envelope.hash(), envelope.signatures[0].signature)
    except Exception as exc:
        raise ValueError('The persisted Testnet intent does not match this exact report and contract call.') from exc
    return envelope


class TestnetChain:
    """Fixed RPC, bounded requests, no automatic footprint restoration writes."""
    def __init__(self, provider: Keypair, evaluator: Keypair, *, transport=None):
        self.keys = {provider.public_key: provider, evaluator.public_key: evaluator}
        self.transport = transport

    async def snapshot(self, quote):
        rpc = checkout._RPC(self.transport)
        try:
            state = await checkout._snapshot(rpc, quote, checkout._deployment())
            key = checkout._record_key(checkout.PINNED_CONTRACTS['credential'], 'Token',
                                       scval.to_bytes(bytes.fromhex(quote.request_id)))
            result = await rpc.call('getLedgerEntries', {'keys': [key]})
            entries = result.get('entries', [])
            if len(entries) > 1 or (entries and entries[0].get('key') != key):
                raise ValueError('Unexpected credential ledger entry.')
            if entries:
                data = xdr.LedgerEntryData.from_xdr(entries[0]['xdr']).contract_data
                expected = xdr.LedgerKey.from_xdr(key).contract_data
                if not data or data.contract != expected.contract or data.key != expected.key:
                    raise ValueError('Credential ledger entry does not match the requested key.')
                state['credential'] = checkout._native(scval.to_native(data.val))
                current, ledger = await asyncio.to_thread(self._current, quote.request_id, quote.provider)
                state['credential_current'] = current
                state['ledger'] = max(state['ledger'], ledger)
            return state
        finally:
            await rpc.close()

    def _current(self, request_id, source):
        client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
        try:
            contract = ContractClient(checkout.PINNED_CONTRACTS['credential'], checkout.RPC_URL,
                                      checkout.PASSPHRASE, request_client=client)
            tx = contract.invoke('is_current', [scval.to_bytes(bytes.fromhex(request_id))], source=source, restore=False)
            return scval.from_bool(tx.result()), tx.simulation.latest_ledger
        finally:
            client.close()

    async def prepare(self, step, quote, digest, uri, score, expires_at):
        return await asyncio.to_thread(self._prepare, step, quote, digest, uri, score, expires_at)

    def _prepare(self, step, quote, digest, uri, score, expires_at):
        kind, function, args, signer = _call(step, quote, digest, uri, score, expires_at)
        client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
        try:
            contract = ContractClient(checkout.PINNED_CONTRACTS[kind], checkout.RPC_URL,
                                      checkout.PASSPHRASE, request_client=client)
            if contract.server.get_network().passphrase != checkout.PASSPHRASE:
                raise ValueError('Official fulfillment requires the pinned Stellar Testnet network.')
            tx = contract.invoke(function, args, source=signer, signer=self.keys[signer],
                                 transaction_timeout=180, restore=False)
            if tx.simulation.restore_preamble:
                raise ValueError('Contract restoration requires a separate operator action.')
            if tx.needs_non_invoker_signing_by():
                raise ValueError('An unexpected additional contract signer was requested.')
            if not 100 <= tx.built_transaction.transaction.fee <= checkout.MAX_FEE_ATOMIC:
                raise ValueError('Official fulfillment exceeds the Testnet fee cap.')
            tx.sign()
            envelope = tx.built_transaction
            intent = {'network': 'testnet', 'signer': signer, 'sequence': envelope.transaction.sequence,
                      'tx_hash': envelope.hash_hex(), 'signed_xdr': envelope.to_xdr(),
                      'status': 'prepared', 'attempts': 0, 'credential_expires_at': expires_at}
            _validate_intent(intent, step, quote, digest, uri, score)
            return intent
        finally:
            client.close()

    async def status(self, intent):
        return await asyncio.to_thread(self._rpc_tx, intent, False)

    async def expired(self, intent):
        return await asyncio.to_thread(self._expired, intent)

    @staticmethod
    def _expired(intent, now=None):
        """True only when the envelope can never execute: its time bound has passed,
        the network has no receipt and the signer has not consumed its sequence."""
        envelope = TransactionEnvelope.from_xdr(intent['signed_xdr'], checkout.PASSPHRASE)
        max_time = envelope.transaction.preconditions.time_bounds.max_time
        if (now if now is not None else time.time()) < max_time + EXPIRY_MARGIN:
            return False
        client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
        try:
            server = SorobanServer(checkout.RPC_URL, client)
            if server.get_transaction(intent['tx_hash']).status.value != 'NOT_FOUND':
                return False
            return server.load_account(intent['signer']).sequence < intent['sequence']
        finally:
            client.close()

    async def broadcast(self, intent):
        return await asyncio.to_thread(self._rpc_tx, intent, True)

    @staticmethod
    def _rpc_tx(intent, send):
        client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
        try:
            server = SorobanServer(checkout.RPC_URL, client)
            if send:
                response = server.send_transaction(intent['signed_xdr'])
                if response.hash != intent['tx_hash']:
                    raise ValueError('Testnet returned a different transaction identity.')
                return {'status': response.status.value}
            response = server.get_transaction(intent['tx_hash'])
            if response.transaction_hash and response.transaction_hash != intent['tx_hash']:
                raise ValueError('Testnet returned a different transaction receipt identity.')
            if response.status.value == 'SUCCESS' and (not isinstance(response.ledger, int) or response.ledger <= 0):
                raise ValueError('Successful Testnet execution requires a concrete ledger.')
            return {'status': response.status.value, 'ledger': response.ledger}
        finally:
            client.close()


class TestnetOrderSettlement:
    """Async order adapter; store is responsible for durable leases and signer lanes.

    Store interface: get_chain_intent(id, step), reserve_chain_intent(id, step,
    intent, lease_token=...), update_chain_intent(id, step, hash, updates,
    lease_token=...). Reservation must fence shared signer sequences across orders.
    A private publication verifier is a trusted server adapter which retrieves
    bytes using its own server credential, never a client supplied callback.
    """
    __test__ = False

    def __init__(self, store, provider: Keypair, evaluator: Keypair, report_base_url: str,
                 *, publication_verifier=None, allow_local_reports=False, chain=None,
                 transport=None, poll_attempts=8, poll_interval=2):
        manifest = checkout._deployment()
        if (provider.public_key != manifest['roles']['provider']
                or evaluator.public_key != manifest['roles']['evaluator']
                or not provider.can_sign() or not evaluator.can_sign()):
            raise ValueError('Official fulfillment keys must match the pinned Testnet provider and evaluator.')
        self.store, self.manifest = store, manifest
        self.chain = chain or TestnetChain(provider, evaluator, transport=transport)
        self.publication_verifier = publication_verifier
        self.base = report_base_url.rstrip('/')
        parsed = urlsplit(self.base)
        local = allow_local_reports and parsed.hostname in {'localhost', '127.0.0.1', '::1'} and parsed.scheme == 'http'
        if (not self.base or not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment or '%' in self.base or '\\' in self.base
                or any(p in {'.', '..'} for p in parsed.path.split('/'))
                or (not local and (parsed.scheme != 'https' or parsed.port is not None))):
            raise ValueError('Configure a fixed HTTPS immutable report base URL.')
        self.transport = transport
        self.poll_attempts, self.poll_interval = poll_attempts, poll_interval

    async def _publication(self, order, publication, raw, digest):
        expected = self.base + '/' + digest + '.json'
        if (publication.get('report_sha256') != digest or publication.get('report_uri') != expected
                or len(expected.encode()) > 512):
            raise ValueError('Publication must use the configured immutable report commitment path.')
        if publication.get('visibility') == 'private':
            if self.publication_verifier is None:
                raise ValueError('Private reports require an authenticated server publication verifier.')
            verified = await _await(self.publication_verifier(publication, raw))
            if verified is not True:
                raise ValueError('Private report readback did not verify the exact committed bytes.')
        elif publication.get('visibility') == 'public' and order.get('consents', {}).get('public_report_consent') is True:
            async with httpx.AsyncClient(timeout=12, follow_redirects=False, transport=self.transport) as client:
                async with client.stream('GET', expected) as response:
                    response.raise_for_status()
                    if response.status_code != 200:
                        raise ValueError('Immutable report publication did not return canonical bytes.')
                    received = bytearray()
                    async for chunk in response.aiter_bytes():
                        received.extend(chunk)
                        if len(received) > 500_000:
                            raise ValueError('Published report exceeds the size limit.')
            if bytes(received) != raw:
                raise ValueError('Published report bytes do not match the audit commitment.')
        else:
            raise ValueError('Report storage visibility or publication consent is missing.')
        return expected

    def _validate(self, order, result):
        consents = order.get('consents', {})
        if any(consents.get(key) is not True for key in ('auto_settlement_consent', 'storage_consent', 'publication_consent')):
            raise ValueError('Official settlement requires explicit storage and automatic settlement consent.')
        quote = checkout.Quote.model_validate(order['quote'])
        expected_ids = checkout._ids(quote.requester, quote.source_sha256, quote.plan_sha256, quote.tier_id, self.manifest)
        if (quote.contracts != checkout.PINNED_CONTRACTS or quote.amount_atomic != checkout.PRICES[quote.tier_id]
                or (quote.agent_id, quote.request_id) != expected_ids
                or any(getattr(quote, role) != self.manifest['roles'][role] for role in ('provider', 'evaluator', 'treasury'))
                or quote.requester in {quote.provider, quote.evaluator}
                or order.get('id', order.get('order_id')) != quote.request_id
                or not order.get('lease_token')):
            raise ValueError('The stored order is not bound to the pinned official checkout.')
        raw = result['report_json'].encode('utf-8')
        digest = sha256(raw).hexdigest()
        if len(raw) > 500_000 or result.get('report_sha256') != digest or order.get('report_sha256') != digest:
            raise ValueError('The frozen order report does not match its canonical commitment.')
        report = decode_report(DeliveryRequest(report_json=result['report_json'], report_sha256=digest))
        engagement = report.get('engagement', {})
        plan = engagement.get('plan', {})
        if (engagement.get('plan_sha256') != quote.plan_sha256
                or sha256(canonical_json(plan).encode()).hexdigest() != quote.plan_sha256
                or plan.get('source_sha256') != quote.source_sha256
                or plan.get('tier', {}).get('id') != quote.tier_id
                or plan.get('operator', {}).get('id') != 'veritas-official'):
            raise ValueError('The report does not cover the exact paid source and acknowledged plan.')
        value = report.get('result', {}).get('overall_score')
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 100:
            raise ValueError('The report must contain a finite audit score between zero and one hundred.')
        # Existing registry ABI stores u32; retain original score and conversion in receipt.
        return quote, raw, digest, int(round(value)), value

    @staticmethod
    def _state(quote, state, digest, uri, score):
        checkout._assert_bindings(quote, state)
        if any(not state.get(k) for k in ('agent', 'validation', 'job', 'binding')):
            raise ValueError('Official fulfillment requires all funded checkout records.')
        if state.get('credential_instance', {}).get('Registry') != checkout.PINNED_CONTRACTS['registry']:
            raise ValueError('The credential deployment is bound to a different registry.')
        job, validation = state['job'], state['validation']
        stage = job.get('state')
        if stage not in [['Funded'], ['Submitted'], ['Complete']]:
            raise ValueError('The audit escrow is not funded or has entered a dispute/refund state.')
        if stage != ['Complete'] and state['ledger'] >= quote.deadline_ledger:
            raise ValueError('The funded escrow deadline has passed; automatic settlement is blocked.')
        complete = validation.get('state') == ['Complete']
        if complete and any(validation.get(k) != v for k, v in {'rep_hash': digest, 'rep_uri': uri, 'score': score}.items()):
            raise ValueError('The completed registry response commits a different report or score.')
        if stage in [['Submitted'], ['Complete']] and (not complete or job.get('del_hash') != digest):
            raise ValueError('The escrow submission is not the completed report commitment.')
        if stage == ['Complete'] and job.get('score') != score:
            raise ValueError('The settled escrow score differs from the registry report.')
        credential = state.get('credential')
        if credential:
            expected = {'owner': quote.requester, 'issuer': quote.provider, 'agent_id': quote.agent_id,
                        'version': 1, 'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256,
                        'report_hash': digest, 'report_uri': uri, 'score': score, 'revoked': False}
            if any(credential.get(k) != v for k, v in expected.items()) or state.get('credential_current') is not True:
                raise ValueError('The existing credential is stale, revoked, or belongs to another report.')
        return {'respond': complete, 'submit': stage in [['Submitted'], ['Complete']],
                'complete': stage == ['Complete'], 'issue': bool(credential)}

    async def _update(self, order, step, intent, updates):
        return await _await(self.store.update_chain_intent(order['id'], step, intent['tx_hash'], updates,
                                                          lease_token=order['lease_token']))

    async def __call__(self, order, result, publication):
        quote, raw, digest, score, original_score = self._validate(order, result)
        uri = await self._publication(order, publication, raw, digest)
        for step in STEPS:
            state = await self.chain.snapshot(quote)
            completed = self._state(quote, state, digest, uri, score)
            intent = await _await(self.store.get_chain_intent(order['id'], step))
            if intent:
                _validate_intent(intent, step, quote, digest, uri, score)
            if completed[step]:
                if step == 'issue' and intent and state['credential'].get('expires_at') != intent.get('credential_expires_at'):
                    raise ValueError('The issued credential expiry differs from the persisted issuance intent.')
                if intent and intent.get('status') not in TERMINAL:
                    response = await self.chain.status(intent)
                    status = 'confirmed' if response['status'] == 'SUCCESS' else 'observed'
                    await self._update(order, step, intent, {'status': status, 'ledger': response.get('ledger'),
                                                          'verified_at': int(time.time())})
                continue
            if intent and intent.get('status') in TERMINAL:
                raise ValueError('A terminal transaction intent has no matching live contract state; operator review is required.')
            if intent and await self.chain.expired(intent):
                # The envelope can never land; archive it so this order and the signer lane can proceed.
                await _await(self.store.expire_chain_intent(order['id'], step, intent['tx_hash'],
                                                            lease_token=order['lease_token']))
                intent = None
            if not intent:
                candidate = await self.chain.prepare(step, quote, digest, uri, score, int(time.time()) + 7 * 86400)
                intent = await _await(self.store.reserve_chain_intent(order['id'], step, candidate,
                                                                     lease_token=order['lease_token']))
                _validate_intent(intent, step, quote, digest, uri, score)
            response = await self.chain.status(intent)
            if response['status'] == 'FAILED':
                await self._update(order, step, intent, {'status': 'failed', 'ledger': response.get('ledger'), 'error_code': 'chain_failed'})
                raise ValueError('Testnet recorded a failed transaction; operator review is required.')
            if response['status'] != 'SUCCESS':
                # This fenced write must succeed immediately before every broadcast.
                intent = await self._update(order, step, intent, {'status': 'pending',
                    'attempts': int(intent.get('attempts', 0)) + 1, 'submitted_at': int(time.time())})
                try:
                    await self.chain.broadcast(intent)
                except Exception as exc:
                    raise SettlementPending('Testnet broadcast outcome is unknown; reconcile the saved intent before retrying.') from exc
                for _ in range(self.poll_attempts):
                    response = await self.chain.status(intent)
                    if response['status'] != 'NOT_FOUND':
                        break
                    await asyncio.sleep(self.poll_interval)
            if response['status'] == 'FAILED':
                await self._update(order, step, intent, {'status': 'failed', 'ledger': response.get('ledger'), 'error_code': 'chain_failed'})
                raise ValueError('Testnet recorded a failed transaction; operator review is required.')
            if response['status'] != 'SUCCESS':
                raise SettlementPending('The saved Testnet transaction is awaiting confirmed ledger execution.')
            await self._update(order, step, intent, {'status': 'confirmed', 'ledger': response.get('ledger'),
                                                   'verified_at': int(time.time())})
            verified = await self.chain.snapshot(quote)
            if not self._state(quote, verified, digest, uri, score)[step]:
                raise ValueError('The successful transaction did not produce the expected live contract state.')
        state = await self.chain.snapshot(quote)
        if not all(self._state(quote, state, digest, uri, score).values()):
            raise ValueError('The final Testnet delivery is incomplete.')
        transactions = []
        for step in STEPS:
            intent = await _await(self.store.get_chain_intent(order['id'], step))
            if intent:
                transactions.append({'step': step, 'hash': intent['tx_hash'], 'status': intent['status'],
                                     'ledger': intent.get('ledger')})
        return {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
                'request_id': quote.request_id, 'agent_id': quote.agent_id, 'report_sha256': digest,
                'report_uri': uri, 'report_visibility': publication['visibility'], 'token_id': quote.request_id,
                'credential_contract_id': quote.contracts['credential'], 'escrow_contract_id': quote.contracts['escrow'],
                'score': score, 'report_score': original_score, 'score_conversion': 'nearest_integer_ties_to_even',
                'owner': quote.requester, 'is_current': True, 'checked_at_ledger': state['ledger'],
                'credential_expires_at': state['credential']['expires_at'], 'payment_state': 'Complete',
                'transactions': transactions, 'independent_evaluator': False}
