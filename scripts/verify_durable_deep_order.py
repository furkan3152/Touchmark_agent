#!/usr/bin/env python3
"""Owned Testnet Deep order on a Drive-mounted trusted operator worker.

Customer business code only runs in a separate deny-all child microVM. This
worker receives server credentials; never use it to execute uploaded code.
The mount and immutable run claim are created by verify_durable_worker.py.
"""
import argparse
import asyncio
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stellar_sdk import Keypair, SorobanServer
from stellar_sdk.client.requests_client import RequestsClient
from backend.app.config import Settings
from backend.app.reporting.generator import canonical_json
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_orders import AuditOrderStore, OrderSubmission, create_order, activate_order, run_order_once
from backend.app.services.audit_product import EngagementRequest, audit_engagement, build_plan
from backend.app.services.capsule import parse_capsule
from backend.app.services.order_identity import make_order_challenge
from backend.app.stellar.ownership import sep53_payload_hash
from scripts.fulfill_testnet_order import build_adapters
from scripts.verify_official_order_testnet import checkout_transaction


def write_private(path, value):
    temp = path.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(canonical_json(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


async def verify(run_id, restart_only=False):
    directory = Path('/vercel/order-data') / run_id
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path, evidence_path = directory/'state.json', directory/'proof.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {
        'schema': 'veritas.durable-deep-order/v1', 'run_id': run_id, 'network': 'testnet',
        'status': 'in_progress', 'fixture': 'invoicepilot', 'checkout_transactions': [], 'checks': [],
        'limitations': ['Owned first-party Testnet trial; not independent validation.',
            'Declared client adapters are instrumented; native transport implementation is outside execution scope.',
            'Drive persistence across two worker VMs is not a public production queue or backup SLA.',
            'A current audit credential records findings and scope, not a safety approval.']}
    persist = lambda value: write_private(state_path, value)
    publish = lambda value: write_private(evidence_path, value)
    settings = Settings(_env_file=None, enable_official_orders=True, enable_testnet_order_settlement=True,
        enable_sandbox_runtime=True, enable_brokered_runtime=True, official_orders_storage_durable=True,
        official_orders_database=str(directory/'orders.db'), data_dir=str(directory/'audit'),
        enable_ofac_screening=False)
    keys = {role: Keypair.from_secret(os.environ[name]) for role, name in {
        'requester':'TRIAL_REQUESTER_SECRET', 'provider':'OFFICIAL_PROVIDER_SECRET',
        'evaluator':'OFFICIAL_EVALUATOR_SECRET'}.items()}
    if any(keys[role].public_key != checkout._deployment()['roles'][role] for role in keys):
        raise ValueError('Owned Testnet identity mismatch')
    store = AuditOrderStore(settings.official_orders_database, deployment='persistent-worker', durable_storage=True)
    publisher, adapter = build_adapters(settings, store)
    if restart_only:
        summary = store.get(state['order_id'], state['order_token'])
        if summary['status'] != 'delivered':
            raise ValueError('Persisted order is not delivered')
        before = {s:store.get_chain_intent(state['order_id'],s)['tx_hash'] for s in ('respond','submit','complete','issue')}
        async def forbidden(*args):
            raise ValueError('Restart verification must not execute or publish again')
        if await run_order_once(store, 'restart-proof', settings=settings, executor=forbidden,
                                publisher=forbidden, chain_adapter=adapter) is not None:
            raise ValueError('Delivered order claimed twice')
        after = {s:store.get_chain_intent(state['order_id'],s)['tx_hash'] for s in before}
        if before != after:
            raise ValueError('Transaction intent changed')
        frozen = store.result(state['order_id'], state['order_token'])
        if sha256(frozen['report_json'].encode()).hexdigest() != summary['delivery']['report_sha256']:
            raise ValueError('Durable report bytes changed')
        evidence['checks'].append({'id':'fresh_vm_same_drive_no_reexecution', 'passed':True})
        evidence['status'] = 'verified'
        publish(evidence)
        return
    if not state.get('engagement'):
        cap = parse_capsule((ROOT/'research/workflow-trial-2026-10-15/invoicepilot.veritas').read_bytes())
        request = EngagementRequest(capsule=cap.model_dump(mode='json'), tier_id='deep', module_ids=cap.audit.modules,
            execution_consent=True, ai_assistance=True, external_processing_consent=True)
        plan = build_plan(request, settings)
        if plan['plan']['blockers']:
            raise ValueError('Deep order preflight blocked')
        request.plan_sha256 = plan['plan_sha256']
        state['engagement'] = request.model_dump(mode='json')
        persist(state)
    request = EngagementRequest.model_validate(state['engagement'])
    if not state.get('order_id'):
        submission = OrderSubmission(engagement=request, requester=keys['requester'].public_key,
            storage_consent=True, auto_settlement_consent=True, publication_consent=True)
        challenge = make_order_challenge(submission, settings)
        submission.wallet_proof = {'challenge':challenge['challenge'], 'challenge_signature':challenge['challenge_signature'],
            'wallet_signature':base64.b64encode(keys['requester'].sign(sep53_payload_hash(challenge['message']))).decode()}
        created = await create_order(submission, settings, store)
        state.update(order_id=created['order_id'], order_token=created['order_token'])
        persist(state)
        evidence['order_id'] = created['order_id']
        evidence['checks'].append({'id':'sep53_requester_order_scope', 'passed':True})
        publish(evidence)
    checkout_request = checkout.CheckoutRequest(engagement=request, requester=keys['requester'].public_key)
    client = RequestsClient(num_retries=0, request_timeout=12, post_timeout=12)
    try:
        server = SorobanServer(checkout.RPC_URL, client)
        for _ in range(4):
            quote = await checkout.prepare_checkout(checkout_request, settings)
            if quote['next_step'] is None:
                break
            await checkout_transaction(quote['next_step'], quote, settings, keys['requester'], state, evidence, server,
                                       persist_state=persist, persist_evidence=publish)
        live = await checkout.prepare_checkout(checkout_request, settings)
        if not live['payment_confirmed']:
            raise ValueError('Funded escrow not observed')
    finally:
        client.close()
    store = AuditOrderStore(settings.official_orders_database, deployment='persistent-worker', durable_storage=True)
    await activate_order(state['order_id'], state['order_token'], settings, store)
    publisher, adapter = build_adapters(settings, store)
    await run_order_once(store, 'durable-deep-proof', settings=settings, executor=audit_engagement,
                         publisher=publisher.publish, chain_adapter=adapter, lease_seconds=600)
    summary = store.get(state['order_id'], state['order_token'])
    if summary['status'] != 'delivered':
        evidence.update(status='incomplete', failure_code=summary.get('failure_code'))
        publish(evidence)
        raise ValueError('Deep order not delivered')
    frozen = store.result(state['order_id'], state['order_token'])
    await publisher.verify(store._private(state['order_id'])['publication'], frozen['report_json'].encode())
    runtime = frozen['report']['engagement']['runtime']['report']
    if runtime['case_count'] != 5 or not any(o['status']=='needs_investigation' for o in runtime['observations']):
        raise ValueError('Actual Deep findings missing')
    write_private(directory/'audit.json', frozen)
    evidence.update(status='delivered_pending_restart', delivery=summary['delivery'],
        report_sha256=frozen['report_sha256'], review_decision=frozen['report']['review_decision'],
        runtime_cases=runtime['case_count'], observations=runtime['observations'],
        broker_evidence=runtime['broker_evidence'], ai_status=frozen['report']['ai_review']['status'])
    evidence['checks'].extend({'id':name,'passed':True} for name in (
        'funded_escrow_read_from_testnet','actual_isolated_business_execution','known_restart_defect_observed',
        'canonical_private_report_verified','settlement_and_owner_bound_credential'))
    publish(evidence)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--restart-only', action='store_true')
    args = parser.parse_args()
    import re
    if not re.fullmatch(r'[a-z0-9-]{8,80}', args.run_id):
        parser.error('Invalid run identity')
    try:
        asyncio.run(verify(args.run_id, args.restart_only))
        print(json.dumps({'status':'completed', 'restart_only':args.restart_only}))
    except Exception as exc:
        import traceback
        print(json.dumps({'status':'incomplete', 'error':type(exc).__name__,
            'frames':[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-4:]]}))
        raise SystemExit(1) from None
