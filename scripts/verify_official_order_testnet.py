#!/usr/bin/env python3
"""Real local official-order pilot on pinned Stellar Testnet, using our fixture.

Creates a SEP-53-bound order, signs the four requester checkout calls, reopens the
private database, runs the ordinary worker and verifies retry idempotency. The
only source is the checked-in blueprint-reader example. Private identity files,
capabilities, signed transaction journals, and canonical report stay in ignored
storage. Public evidence contains commitments and real chain receipts only.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
from stellar_sdk import Keypair, SorobanServer, TransactionEnvelope
from stellar_sdk.client.requests_client import RequestsClient
from backend.app.config import Settings
from backend.app.reporting.generator import canonical_json
from backend.app.services.audit_orders import AuditOrderStore, OrderSubmission, create_order, activate_order, run_order_once
from backend.app.services.audit_product import EngagementRequest, audit_engagement, build_plan
from backend.app.services.order_identity import make_order_challenge
from backend.app.stellar.ownership import sep53_payload_hash
from backend.app.services.studio import ReviewRequest
from backend.app.services import testnet_checkout as checkout
from scripts.fulfill_testnet_order import build_adapters

PRIVATE = ROOT / 'data/official-order-pilot-state.json'
DATABASE = ROOT / 'data/official-order-pilot.db'
EVIDENCE = ROOT / 'deployments/official-order-pilot-2026-10-15.json'


def save_private(state):
    tmp = PRIVATE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(canonical_json(state))
    os.replace(tmp, PRIVATE)


def save_evidence(value):
    tmp = EVIDENCE.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(tmp, EVIDENCE)


def config(keys):
    return Settings(_env_file=None, stellar_network='testnet', llm_provider='', llm_api_key='',
        enable_official_orders=True, enable_testnet_order_settlement=True,
        official_orders_database=str(DATABASE), official_provider_secret=keys['provider'].secret,
        official_evaluator_secret=keys['evaluator'].secret,
        runtime_api_key=(ROOT / 'data/runtime-pilot-key.txt').read_text().strip(),
        checkout_quote_signing_key=(ROOT / 'data/checkout-quote-signing.key').read_text().strip(),
        blob_store_id='store_EVlQaNdD2T85Necg',
        blob_read_write_token=(ROOT / 'data/blob-read-write.token').read_text().strip(),
        official_report_base_url='https://evlqandd2t85necg.private.blob.vercel-storage.com/reports',
        data_dir=str(ROOT / 'data/official-order-pilot-audit'),
        enable_sandbox_runtime=False, allow_external_llm_for_private_audits=False,
        enable_public_ai_review=False)


def fixture(settings):
    base = ROOT / 'examples/blueprint-reader'
    blueprint = json.loads((base / 'veritas.json').read_text())
    files = {p: (base / p).read_text() for p in ['veritas.json'] + [c['path'] for c in blueprint['components']]}
    source = ReviewRequest(name='Official order pilot: private report delivery',
        purpose=blueprint['purpose'], files=files,
        source_reference='https://github.com/furkan3152/agentveritas-stellar',
        source_revision='830091f9e3ea261951af7be1fe947d3c738f404e')
    request = EngagementRequest(source=source, tier_id='quick', execution_consent=False)
    request.plan_sha256 = build_plan(request, settings)['plan_sha256']
    return request


async def rpc(server, method, *args):
    return await asyncio.to_thread(getattr(server, method), *args)


async def checkout_transaction(step, quote_response, settings, requester, state, evidence, server,
                               *, persist_state=save_private, persist_evidence=save_evidence):
    row = state.setdefault('checkout_intents', {}).get(step)
    if row is None:
        prepared = await checkout.prepare_checkout_step(checkout.CheckoutStepRequest(
            quote=quote_response['quote'], quote_signature=quote_response['quote_signature'], step=step), settings)
        tx = TransactionEnvelope.from_xdr(prepared['unsigned_xdr'], checkout.PASSPHRASE)
        if tx.hash_hex() != prepared['transaction_hash'] or tx.transaction.source.account_id != requester.public_key:
            raise ValueError('Prepared checkout identity mismatch')
        tx.sign(requester)
        row = {'step': step, 'tx_hash': tx.hash_hex(), 'signed_xdr': tx.to_xdr(), 'status': 'prepared'}
        state['checkout_intents'][step] = row
        persist_state(state)
    observed = await rpc(server, 'get_transaction', row['tx_hash'])
    if observed.status.value == 'NOT_FOUND':
        submitted = await rpc(server, 'send_transaction', row['signed_xdr'])
        if submitted.hash != row['tx_hash']:
            raise ValueError('Unexpected Testnet hash')
        for _ in range(25):
            observed = await rpc(server, 'get_transaction', row['tx_hash'])
            if observed.status.value != 'NOT_FOUND':
                break
            await asyncio.sleep(2)
    if observed.status.value != 'SUCCESS':
        raise ValueError('Testnet checkout transaction is not confirmed')
    row.update(status='SUCCESS', ledger=observed.ledger)
    persist_state(state)
    public = {'step': step, 'hash': row['tx_hash'], 'status': 'SUCCESS', 'ledger': observed.ledger,
              'signer_role': 'requester', 'explorer_url': 'https://stellar.expert/explorer/testnet/tx/' + row['tx_hash']}
    evidence['checkout_transactions'] = [t for t in evidence['checkout_transactions'] if t['step'] != step] + [public]
    persist_evidence(evidence)
    print(json.dumps({'step': 'checkout_' + step, 'status': 'SUCCESS', 'hash': row['tx_hash']}), flush=True)


async def main(*, resume_published=False):
    key_values = json.loads((ROOT / 'data/testnet-audit-delivery-identities.json').read_text())
    keys = {role: Keypair.from_secret(key_values[role]) for role in ('requester', 'provider', 'evaluator')}
    settings = config(keys)
    manifest = checkout._deployment()
    if any(keys[role].public_key != manifest['roles'][role] for role in keys):
        raise ValueError('Pilot identities mismatch')
    state = json.loads(PRIVATE.read_text()) if PRIVATE.exists() else {}
    evidence = json.loads(EVIDENCE.read_text()) if EVIDENCE.exists() else {
        'schema': 'veritas.official-order-pilot/v1', 'network': 'testnet',
        'network_passphrase': checkout.PASSPHRASE, 'status': 'in_progress',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'fixture': 'examples/blueprint-reader', 'tier_id': 'quick', 'amount_atomic': checkout.PRICES['quick'],
        'asset': 'testnet_faucet_XLM', 'contracts': manifest['contracts'], 'roles': manifest['roles'],
        'checkout_transactions': [], 'checks': [],
        'limitations': ['First-party requester, provider and evaluator share one operator; they are not independent validators.',
            'This owned fixture received the quick tier static audit. No AI model or runtime execution is claimed.',
            'The report is stored privately; its SHA-256 and token-free private URI are public on Testnet.',
            'Local SQLite worker proof is not evidence of a durable serverless production queue.',
            'A current audit credential records scoped provenance, not a guarantee of security.']}
    store = AuditOrderStore(DATABASE)
    if not state.get('engagement'):
        state['engagement'] = fixture(settings).model_dump(mode='json')
        save_private(state)
    engagement = EngagementRequest.model_validate(state['engagement'])
    if not state.get('order_id'):
        submission = OrderSubmission(engagement=engagement, requester=keys['requester'].public_key,
            storage_consent=True, auto_settlement_consent=True, publication_consent=True)
        challenge = make_order_challenge(submission, settings)
        submission.wallet_proof = {'challenge': challenge['challenge'],
            'challenge_signature': challenge['challenge_signature'],
            'wallet_signature': base64.b64encode(keys['requester'].sign(sep53_payload_hash(challenge['message']))).decode()}
        created = await create_order(submission, settings, store)
        state.update(order_id=created['order_id'], order_token=created['order_token'])
        save_private(state)
        evidence['order_id'] = created['order_id']
        evidence['checks'].append({'id': 'sep53_requester_order_scope', 'passed': True})
        save_evidence(evidence)
    request = checkout.CheckoutRequest(engagement=engagement, requester=keys['requester'].public_key)
    client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
    server = SorobanServer(checkout.RPC_URL, client)
    try:
        for _ in range(4):
            quote = await checkout.prepare_checkout(request, settings)
            step = quote['next_step']
            if step is None:
                break
            await checkout_transaction(step, quote, settings, keys['requester'], state, evidence, server)
        live = await checkout.prepare_checkout(request, settings)
        if not live['payment_confirmed']:
            raise ValueError('Live funded escrow required')
    finally:
        client.close()
    # Reconstruct the store after all requester transactions: no in-memory payment
    # acknowledgement or client claim is passed into activation or the worker.
    store = AuditOrderStore(DATABASE)
    activated = await activate_order(state['order_id'], state['order_token'], settings, store)
    if 'restart_before_activation' not in {c['id'] for c in evidence['checks']}:
        evidence['checks'].extend([
            {'id': 'restart_before_activation', 'passed': True, 'payment_confirmed': activated['payment_confirmed']},
            {'id': 'funded_escrow_reloaded_from_testnet', 'passed': True, 'ledger': live['chain']['ledger']}])
        save_evidence(evidence)
    publisher, adapter = build_adapters(settings, store)

    async def forbidden_new_work(*args):
        raise ValueError('Resume mode permits no new audit execution or artifact upload.')

    if resume_published:
        note = ('The fixed owned-fixture report was published separately after a privacy review and exact-byte checks, '
                'then checkpointed. The resumed worker forbade new execution or upload. This pilot includes operator intervention.')
        if note not in evidence['limitations']:
            evidence['limitations'].append(note)
            save_evidence(evidence)
        publication = json.loads((ROOT / 'data/official-order-owned-fixture-publication.json').read_text())
        frozen = store.result(state['order_id'], state['order_token'])
        await publisher.verify(publication, frozen['report_json'].encode())
        private = store._private(state['order_id'])
        if not private['publication']:
            lease = store.claim('verified-owned-fixture-publication-checkpoint', lease_seconds=180)
            if not lease or lease['id'] != state['order_id'] or lease['report_sha256'] != publication['report_sha256']:
                raise ValueError('The verified publication has no matching frozen order lease.')
            store._checkpoint(lease['id'], lease['lease_token'], 'settling', publication=publication, release=True)
    result = await run_order_once(store, 'actual-private-order-pilot', settings=settings,
        executor=forbidden_new_work if resume_published else audit_engagement,
        publisher=forbidden_new_work if resume_published else publisher.publish,
        chain_adapter=adapter, lease_seconds=180)
    summary = store.get(state['order_id'], state['order_token'])
    if summary['status'] != 'delivered':
        evidence.update(status='blocked', failure_code=summary.get('failure_code'))
        save_evidence(evidence)
        print(json.dumps({'status': summary['status'], 'failure_code': summary.get('failure_code')}), flush=True)
        return 2
    private = store._private(state['order_id'])
    frozen_report = store.result(state['order_id'], state['order_token'])
    proof = summary['delivery']
    if sha256(frozen_report['report_json'].encode()).hexdigest() != proof['report_sha256']:
        raise ValueError('Report commitment mismatch')
    await publisher.verify(private['publication'], frozen_report['report_json'].encode())
    async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
        unauthenticated = await client.get(proof['report_uri'])
        if unauthenticated.status_code != 403:
            raise ValueError('Private report unexpectedly accessible without authorization')
    before = {step: store.get_chain_intent(state['order_id'], step)['tx_hash'] for step in ('respond', 'submit', 'complete', 'issue')}
    store = AuditOrderStore(DATABASE)
    if await run_order_once(store, 'actual-private-order-pilot-repeat', settings=settings,
        executor=audit_engagement, publisher=publisher.publish, chain_adapter=adapter) is not None:
        raise ValueError('Delivered order was unexpectedly claimed again')
    after = {step: store.get_chain_intent(state['order_id'], step)['tx_hash'] for step in before}
    if before != after:
        raise ValueError('Retry replaced a chain intent')
    try:
        store.result(state['order_id'], '0' * 64)
    except ValueError:
        capability_rejected = True
    else:
        raise ValueError('Invalid capability exposed private report')
    evidence.update(status='verified', checked_at=datetime.now(timezone.utc).isoformat(),
        delivery=proof, report={'sha256': proof['report_sha256'], 'uri': proof['report_uri'],
            'visibility': 'private', 'bytes': len(frozen_report['report_json'].encode()),
            'source_sha256': private['quote']['source_sha256'], 'plan_sha256': private['quote']['plan_sha256'],
            'runtime_executed': False, 'ai_model_invoked': False,
            'review_decision': frozen_report['report']['review_decision']},
        settlement_transactions=proof['transactions'])
    existing = {c['id'] for c in evidence['checks']}
    checks = [
        ('canonical_report_commitment', True), ('authenticated_private_blob_readback', True),
        ('unauthenticated_report_access_denied', unauthenticated.status_code == 403),
        ('registry_report_source_plan_score_binding', True), ('escrow_payment_complete', proof['payment_state'] == 'Complete'),
        ('current_owner_bound_credential', proof['is_current'] and proof['owner'] == keys['requester'].public_key),
        ('restart_does_not_rerun_paid_work', True), ('transaction_intents_unchanged_on_retry', before == after),
        ('wrong_capability_cannot_read_report', capability_rejected)]
    evidence['checks'].extend({'id': key, 'passed': value} for key, value in checks if key not in existing)
    evidence.pop('failure_code', None)
    save_evidence(evidence)
    print(json.dumps({'status': 'verified', 'order_id': state['order_id'], 'report_sha256': proof['report_sha256'],
                      'checkout_transactions': len(evidence['checkout_transactions']),
                      'settlement_transactions': len(proof['transactions']), 'checks': len(evidence['checks'])}), flush=True)
    return 0


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--resume-published', action='store_true',
                            help='Only verify the previously published fixed fixture and settle; no execution or upload.')
        args = parser.parse_args()
        raise SystemExit(asyncio.run(main(resume_published=args.resume_published)))
    except Exception as exc:
        # No SDK payload or private configuration is exposed by a failed pilot.
        print(json.dumps({'status': 'blocked', 'error_type': type(exc).__name__,
                          'reason': 'Pilot verification requires operator inspection; no success is claimed.'}), flush=True)
        raise SystemExit(2)
