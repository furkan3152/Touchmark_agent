from copy import deepcopy
from hashlib import sha256
import time

import httpx
import pytest
from stellar_sdk import Account, Keypair, TransactionBuilder

from backend.app.reporting.generator import canonical_json
from backend.app.services import order_settlement as settlement
from backend.app.services import testnet_checkout as checkout


@pytest.fixture
def anyio_backend():
    return 'asyncio'


class Journal:
    def __init__(self):
        self.intents = {}
        self.allow_write = True
        self.writes = []

    def get_chain_intent(self, order, step):
        return deepcopy(self.intents.get(step))

    def reserve_chain_intent(self, order, step, intent, *, lease_token):
        assert self.allow_write, 'lease lost'
        self.intents.setdefault(step, deepcopy(intent))
        self.writes.append(('reserve', step))
        return deepcopy(self.intents[step])

    def expire_chain_intent(self, order, step, tx_hash, *, lease_token):
        assert self.allow_write, 'lease lost'
        assert self.intents[step]['tx_hash'] == tx_hash
        del self.intents[step]
        self.writes.append(('expire', step))

    def update_chain_intent(self, order, step, tx_hash, updates, *, lease_token):
        assert self.allow_write, 'lease lost'
        assert self.intents[step]['tx_hash'] == tx_hash
        self.intents[step].update(updates)
        self.writes.append(('update', step, updates['status']))
        return deepcopy(self.intents[step])


class FakeChain:
    def __init__(self, state, provider, evaluator, journal):
        self.state = state
        self.keys = {k.public_key: k for k in (provider, evaluator)}
        self.journal = journal
        self.prepared, self.sent = [], []
        self.receipts = {}
        self.lose_response = False
        self.apply = True
        self.issue_fail = False
        self.fail_prepare = None
        self.unlandable = set()

    async def snapshot(self, quote):
        return deepcopy(self.state)

    async def prepare(self, step, quote, digest, uri, score, expires):
        if self.fail_prepare == step:
            raise ValueError('simulation failed')
        kind, fn, args, signer = settlement._call(step, quote, digest, uri, score, expires)
        tx = (TransactionBuilder(Account(signer, 100 + len(self.prepared)), checkout.PASSPHRASE)
              .append_invoke_contract_function_op(quote.contracts[kind], fn, args).set_timeout(180).build())
        tx.sign(self.keys[signer])
        intent = {'network': 'testnet', 'signer': signer, 'sequence': tx.transaction.sequence,
                  'tx_hash': tx.hash_hex(), 'signed_xdr': tx.to_xdr(), 'status': 'prepared',
                  'attempts': 0, 'credential_expires_at': expires}
        self.prepared.append((step, intent))
        return intent

    async def status(self, intent):
        return self.receipts.get(intent['tx_hash'], {'status': 'NOT_FOUND'})

    async def expired(self, intent):
        return intent['tx_hash'] in self.unlandable

    async def broadcast(self, intent):
        step = next(step for step, value in self.journal.intents.items() if value['tx_hash'] == intent['tx_hash'])
        assert self.journal.intents[step]['status'] == 'pending'
        self.sent.append((step, intent['signed_xdr']))
        if self.apply:
            tx = settlement.TransactionEnvelope.from_xdr(intent['signed_xdr'], checkout.PASSPHRASE)
            args = [checkout._native(settlement.scval.to_native(v)) for v in tx.transaction.operations[0].host_function.invoke_contract.args]
            if step == 'respond':
                self.state['validation'].update(state=['Complete'], score=args[2], rep_uri=args[3], rep_hash=args[4])
            elif step == 'submit':
                self.state['job'].update(state=['Submitted'], del_hash=args[2])
            elif step == 'complete':
                self.state['job'].update(state=['Complete'], score=args[2])
            elif step == 'issue':
                if self.issue_fail:
                    raise OSError('connection reset')
                v = self.state['validation']
                self.state['credential'] = {**self.state['binding'], 'issuer': v['validator'],
                    'report_hash': v['rep_hash'], 'report_uri': v['rep_uri'], 'score': v['score'],
                    'revoked': False, 'expires_at': args[1]}
                self.state['credential_current'] = True
            self.state['ledger'] += 1
            self.receipts[intent['tx_hash']] = {'status': 'SUCCESS', 'ledger': self.state['ledger']}
        if self.lose_response:
            self.lose_response = False
            raise OSError('connection reset after acceptance')
        return {'status': 'PENDING'}


@pytest.fixture
def flow(monkeypatch):
    provider, evaluator, requester = Keypair.random(), Keypair.random(), Keypair.random()
    manifest = checkout._deployment()
    manifest['roles'].update(provider=provider.public_key, evaluator=evaluator.public_key)
    monkeypatch.setattr(checkout, '_deployment', lambda: manifest)
    plan = {'source_sha256': 'a' * 64, 'tier': {'id': 'quick'}, 'operator': {'id': 'veritas-official'}}
    plan_hash = sha256(canonical_json(plan).encode()).hexdigest()
    agent, request = checkout._ids(requester.public_key, plan['source_sha256'], plan_hash, 'quick', manifest)
    quote = checkout.Quote(requester=requester.public_key, tier_id='quick', source_sha256=plan['source_sha256'],
        plan_sha256=plan_hash, agent_id=agent, request_id=request, amount_atomic='1000000',
        contracts=checkout.PINNED_CONTRACTS, provider=provider.public_key, evaluator=evaluator.public_key,
        treasury=manifest['roles']['treasury'], deadline_ledger=10000, issued_at=100, expires_at=700)
    report = {'agent': {'name': 'Our fixture'}, 'findings': [], 'result': {'overall_score': 63.7},
        'engagement': {'plan': plan, 'plan_sha256': plan_hash}, 'review_decision': 'needs_evidence'}
    result = {'report': report, 'report_json': canonical_json(report)}
    result['report_sha256'] = sha256(result['report_json'].encode()).hexdigest()
    order = {'id': request, 'order_id': request, 'quote': quote.model_dump(), 'lease_token': 'private-lease',
        'report_sha256': result['report_sha256'], 'consents': {'storage_consent': True,
        'auto_settlement_consent': True, 'publication_consent': True, 'public_report_consent': True}}
    publication = {'report_sha256': result['report_sha256'], 'visibility': 'public',
        'report_uri': 'https://reports.example/immutable/' + result['report_sha256'] + '.json'}
    identity = {'version': 1, 'meta_hash': plan_hash, 'end_hash': plan['source_sha256']}
    state = {'ledger': 1000, 'credential_instance': {'Registry': quote.contracts['registry']},
        'agent': {**identity, 'owner': quote.requester, 'active': True, 'meta_uri': 'urn:veritas:plan:' + plan_hash},
        'validation': {**identity, 'agent_id': agent, 'requester': quote.requester,
                       'validator': quote.provider, 'state': ['Pending']},
        'job': {'requester': quote.requester, 'provider': quote.provider, 'evaluator': quote.evaluator,
            'amount': 1000000, 'deadline': 10000, 'fee_bps': 1500, 'fee_to': quote.treasury, 'state': ['Funded']},
        'binding': {**identity, 'agent_id': agent, 'owner': quote.requester}}
    journal = Journal()
    chain = FakeChain(state, provider, evaluator, journal)
    transport = httpx.MockTransport(lambda req: httpx.Response(200, content=result['report_json'].encode()))
    adapter = settlement.TestnetOrderSettlement(journal, provider, evaluator, 'https://reports.example/immutable',
                                               chain=chain, transport=transport, poll_attempts=1, poll_interval=0)
    return adapter, order, result, publication, chain, journal


@pytest.mark.anyio
async def test_exact_flow_expired_checkout_quote_allowed_and_idempotent(flow):
    adapter, order, result, publication, chain, journal = flow
    receipt = await adapter(order, result, publication)
    assert receipt['status'] == 'delivered' and receipt['payment_state'] == 'Complete'
    assert receipt['score'] == 64 and receipt['report_score'] == 63.7
    assert receipt['token_id'] == order['id']
    assert receipt['report_sha256'] != sha256(publication['report_uri'].encode()).hexdigest()
    assert [s for s, _ in chain.sent] == ['respond', 'submit', 'complete', 'issue']
    assert all(i['status'] == 'confirmed' for i in journal.intents.values())
    assert all(t['status'] == 'confirmed' for t in receipt['transactions'])
    assert (await adapter(order, result, publication))['status'] == 'delivered'
    assert len(chain.sent) == len(chain.prepared) == 4


@pytest.mark.anyio
async def test_lost_send_response_reconciles_without_duplicate_call(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.lose_response = True
    with pytest.raises(settlement.SettlementPending):
        await adapter(order, result, publication)
    assert journal.intents['respond']['status'] == 'pending'
    receipt = await adapter(order, result, publication)
    assert receipt['status'] == 'delivered'
    assert [s for s, _ in chain.sent].count('respond') == 1


@pytest.mark.anyio
async def test_pending_retries_identical_envelope_and_never_claims_delivery(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.apply = False
    for _ in range(2):
        with pytest.raises(settlement.SettlementPending):
            await adapter(order, result, publication)
    assert len(chain.prepared) == 1
    assert chain.sent[0] == chain.sent[1]
    assert journal.intents['respond']['status'] == 'pending'


@pytest.mark.anyio
async def test_write_failure_or_lost_lease_before_send_never_broadcasts(flow):
    adapter, order, result, publication, chain, journal = flow
    journal.allow_write = False
    with pytest.raises(AssertionError, match='lease lost'):
        await adapter(order, result, publication)
    assert not chain.sent


@pytest.mark.anyio
async def test_settled_but_issue_pending_is_not_delivered_and_retry_does_not_pay_again(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.issue_fail = True
    with pytest.raises(settlement.SettlementPending):
        await adapter(order, result, publication)
    assert chain.state['job']['state'] == ['Complete']
    assert not chain.state.get('credential')
    chain.issue_fail = False
    assert (await adapter(order, result, publication))['status'] == 'delivered'
    assert [s for s, _ in chain.sent].count('complete') == 1
    assert [s for s, _ in chain.prepared].count('issue') == 1


@pytest.mark.anyio
@pytest.mark.parametrize('mutation', ['missing_binding', 'unfunded', 'disputed', 'refunded', 'expired', 'stale_version', 'registry'])
async def test_invalid_chain_state_never_signs(flow, mutation):
    adapter, order, result, publication, chain, journal = flow
    if mutation == 'missing_binding':
        del chain.state['binding']
    elif mutation in {'unfunded', 'disputed', 'refunded'}:
        chain.state['job']['state'] = [{'unfunded': 'Created', 'disputed': 'Disputed', 'refunded': 'Refunded'}[mutation]]
    elif mutation == 'expired':
        chain.state['ledger'] = order['quote']['deadline_ledger']
    elif mutation == 'stale_version':
        chain.state['agent']['version'] += 1
    else:
        chain.state['credential_instance']['Registry'] = order['quote']['contracts']['escrow']
    with pytest.raises(ValueError):
        await adapter(order, result, publication)
    assert not chain.prepared and not chain.sent


@pytest.mark.anyio
@pytest.mark.parametrize('mutation', ['bytes', 'plan', 'score_bool', 'score_infinite', 'consent', 'price', 'contract', 'uri'])
async def test_bad_report_quote_or_publication_never_signs(flow, mutation):
    adapter, order, result, publication, chain, journal = flow
    if mutation == 'bytes':
        result['report_json'] += ' '
    elif mutation in {'plan', 'score_bool', 'score_infinite'}:
        if mutation == 'plan':
            result['report']['engagement']['plan']['source_sha256'] = 'b' * 64
        else:
            result['report']['result']['overall_score'] = True if mutation == 'score_bool' else float('inf')
        result['report_json'] = canonical_json(result['report'])
        result['report_sha256'] = order['report_sha256'] = sha256(result['report_json'].encode()).hexdigest()
    elif mutation == 'consent':
        order['consents']['auto_settlement_consent'] = False
    elif mutation == 'price':
        order['quote']['amount_atomic'] = '1'
    elif mutation == 'contract':
        order['quote']['contracts']['escrow'] = order['quote']['contracts']['registry']
    else:
        publication['report_uri'] = 'http://169.254.169.254/latest/meta-data'
    with pytest.raises(ValueError):
        await adapter(order, result, publication)
    assert not chain.prepared and not chain.sent


@pytest.mark.anyio
async def test_private_report_requires_authenticated_readback(flow):
    adapter, order, result, publication, chain, journal = flow
    publication['visibility'] = 'private'
    with pytest.raises(ValueError, match='authenticated'):
        await adapter(order, result, publication)
    assert not chain.prepared
    async def verify(publication_, raw):
        assert publication_ == publication and raw == result['report_json'].encode()
        return True
    adapter.publication_verifier = verify
    assert (await adapter(order, result, publication))['report_visibility'] == 'private'


@pytest.mark.anyio
async def test_public_redirect_or_changed_bytes_rejected(flow):
    adapter, order, result, publication, chain, journal = flow
    for response in [httpx.Response(302, headers={'Location': 'http://127.0.0.1/secret'}), httpx.Response(200, content=b'{}')]:
        adapter.transport = httpx.MockTransport(lambda req: response)
        with pytest.raises((ValueError, httpx.HTTPError)):
            await adapter(order, result, publication)
    assert not chain.sent


@pytest.mark.anyio
async def test_corrupted_saved_intent_rejected(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.apply = False
    with pytest.raises(settlement.SettlementPending):
        await adapter(order, result, publication)
    journal.intents['respond']['tx_hash'] = 'f' * 64
    before = len(chain.sent)
    with pytest.raises(ValueError, match='persisted Testnet intent'):
        await adapter(order, result, publication)
    assert len(chain.sent) == before


@pytest.mark.anyio
async def test_history_missing_uses_observed_not_fabricated_success(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.lose_response = True
    with pytest.raises(settlement.SettlementPending):
        await adapter(order, result, publication)
    chain.receipts.clear()
    receipt = await adapter(order, result, publication)
    assert receipt['transactions'][0]['status'] == 'observed'
    assert receipt['transactions'][0]['ledger'] is None
    assert [s for s, _ in chain.sent].count('respond') == 1


@pytest.mark.anyio
async def test_unlandable_pending_intent_is_archived_and_replaced(flow):
    adapter, order, result, publication, chain, journal = flow
    chain.apply = False
    with pytest.raises(settlement.SettlementPending):
        await adapter(order, result, publication)
    stuck = journal.intents['respond']
    assert stuck['status'] == 'pending'
    chain.unlandable.add(stuck['tx_hash'])
    chain.apply = True
    receipt = await adapter(order, result, publication)
    assert receipt['status'] == 'delivered'
    assert ('expire', 'respond') in journal.writes
    assert journal.intents['respond']['tx_hash'] != stuck['tx_hash']
    assert [s for s, _ in chain.prepared].count('respond') == 2


def test_envelope_is_not_expired_before_its_time_bound(flow, monkeypatch):
    adapter, order, result, publication, chain, journal = flow
    tx = (TransactionBuilder(Account(Keypair.random().public_key, 7), checkout.PASSPHRASE)
          .append_manage_data_op('k', b'v').set_timeout(180).build())
    intent = {'signed_xdr': tx.to_xdr(), 'tx_hash': tx.hash_hex(), 'signer': tx.transaction.source.account_id,
              'sequence': tx.transaction.sequence}
    def offline(*args, **kwargs):
        pytest.fail('No RPC call is needed while the time bound is open')
    monkeypatch.setattr(settlement, 'SorobanServer', offline)
    max_time = tx.transaction.preconditions.time_bounds.max_time
    assert settlement.TestnetChain._expired(intent, now=max_time + settlement.EXPIRY_MARGIN - 1) is False

    class Server:
        def __init__(self, sequence, status='NOT_FOUND'):
            self.sequence, self.status = sequence, status
        def __call__(self, *args):
            return self
        def get_transaction(self, tx_hash):
            return type('R', (), {'status': type('S', (), {'value': self.status})})()
        def load_account(self, signer):
            return Account(signer, self.sequence)
    late = max_time + settlement.EXPIRY_MARGIN
    monkeypatch.setattr(settlement, 'SorobanServer', Server(intent['sequence'] - 1))
    assert settlement.TestnetChain._expired(intent, now=late) is True
    monkeypatch.setattr(settlement, 'SorobanServer', Server(intent['sequence']))
    assert settlement.TestnetChain._expired(intent, now=late) is False
    monkeypatch.setattr(settlement, 'SorobanServer', Server(intent['sequence'] - 1, 'FAILED'))
    assert settlement.TestnetChain._expired(intent, now=late) is False
