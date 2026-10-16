"""Private, durable single-host official orders with leased, resumable workers.

This is a local SQLite worker, not a durable queue for Vercel Functions. Production
requires an operator-attested persistent volume, backups and a continuously running
worker. Serverless/temporary storage is rejected. Creation additionally requires a
scope-bound wallet proof; subsequent access requires the private order capability.

Callbacks execute at least once after a crash. Publication and settlement MUST be
idempotent by order ID/report hash. Chain envelopes must be journaled before send.
The module never imports or executes customer source; the executor must use the
existing isolated runtime. Reports may contain source excerpts, hence separate
explicit private-publication consent; only hashes and the private URI go onchain. Source and capabilities are never public artifacts.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Callable

from pydantic import model_validator
from stellar_sdk import StrKey

from ..reporting.generator import canonical_json
from .audit_product import EngagementRequest, build_plan
from .order_settlement import SettlementPending
from .report_delivery import DeliveryRequest, decode_report
from .testnet_checkout import (CheckoutRequest, CheckoutStepRequest, Quote,
                              _deployment, _verify_quote, prepare_checkout)

STATUSES = ('awaiting_payment', 'queued', 'running', 'report_ready', 'settling',
            'delivered', 'failed', 'refunded')
MIN_EXECUTION_LEDGERS = 120
SETTLEMENT_RETRY_SECONDS = 30
_HEX = re.compile(r'^[a-f0-9]{64}$')
_CHAIN_STEPS = {'respond', 'submit', 'complete', 'issue'}


class OrderError(ValueError):
    pass


class LeaseLost(OrderError):
    pass


class OrderSubmission(CheckoutRequest):
    storage_consent: bool = False
    auto_settlement_consent: bool = False
    publication_consent: bool = False
    wallet_proof: dict | None = None

    @model_validator(mode='after')
    def consents(self):
        if not (self.storage_consent and self.auto_settlement_consent and self.publication_consent):
            raise ValueError('Private source storage, automatic Testnet settlement and private report publication with a public onchain commitment each require explicit consent.')
        return self


def _verify_identity(submission, settings):
    # Imported lazily: the challenge module consumes the public submission DTO.
    from .order_identity import verify_order_identity
    verify_order_identity(submission, settings)


def _json(value) -> str:
    encoded = canonical_json(value)
    # Reject non-finite values, including ones in adapter receipts.
    json.loads(encoded, parse_constant=lambda _: (_ for _ in ()).throw(OrderError('Non-finite order artifact.')))
    if len(encoded.encode()) > 2_000_000:
        raise OrderError('Order artifact exceeds the bounded storage limit.')
    return encoded


def _digest(value) -> str:
    return sha256(_json(value).encode()).hexdigest()


def _capability(token: str) -> str:
    return sha256(token.encode()).hexdigest() if isinstance(token, str) else '0' * 64


class AuditOrderStore:
    """One private database on a persistent local filesystem; no public listing.

    get/result require the per-order capability even when an API pilot key exists.
    Underscored reads and lease/journal methods are worker-internal interfaces.
    durable_storage is an operator attestation, not automatic backup verification.
    """

    def __init__(self, path: str | Path, *, deployment='local', durable_storage=False,
                 clock: Callable[[], float] = time.time, max_attempts=5):
        raw = str(path)
        if raw == ':memory:' or raw.startswith('file:'):
            raise OrderError('Orders require a private on-disk database.')
        self.path = Path(path).absolute()
        if self.path.is_symlink():
            raise OrderError('An order database cannot be a symlink.')
        self.path = self.path.resolve()
        if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
            raise OrderError('Local SQLite orders are disabled in ephemeral serverless deployments; use a persistent worker service.')
        temporary = any(self.path.is_relative_to(root) for root in
                        (Path('/tmp'), Path('/var/tmp'), Path('/dev/shm'),
                         Path('/workspace/scratch'), Path('/var/task'), Path('/var/runtime')))
        if deployment != 'local' and (not durable_storage or temporary):
            raise OrderError('Production orders require explicitly configured persistent storage outside temporary directories.')
        if not 1 <= max_attempts <= 100:
            raise OrderError('Invalid worker retry limit.')
        self.clock, self.max_attempts = clock, max_attempts
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self._connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS audit_orders (
                    id TEXT PRIMARY KEY, capability_hash TEXT NOT NULL,
                    requester TEXT NOT NULL, status TEXT NOT NULL,
                    engagement_json TEXT NOT NULL, plan_json TEXT NOT NULL,
                    quote_json TEXT NOT NULL, binding_sha256 TEXT NOT NULL,
                    consents_json TEXT NOT NULL, checked_ledger INTEGER NOT NULL,
                    paid INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
                    lease_token TEXT, lease_until REAL, retry_at REAL NOT NULL DEFAULT 0,
                    result_json TEXT, publication_json TEXT, delivery_json TEXT,
                    failure_code TEXT, retryable INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_order_chain_intents (
                    order_id TEXT NOT NULL REFERENCES audit_orders(id),
                    step TEXT NOT NULL, tx_hash TEXT NOT NULL, intent_json TEXT NOT NULL,
                    network TEXT NOT NULL, signer TEXT NOT NULL, sequence INTEGER NOT NULL,
                    status TEXT NOT NULL, PRIMARY KEY(order_id, step), UNIQUE(network,signer,sequence));
                CREATE TABLE IF NOT EXISTS audit_order_expired_intents (
                    order_id TEXT NOT NULL REFERENCES audit_orders(id), step TEXT NOT NULL,
                    tx_hash TEXT PRIMARY KEY, intent_json TEXT NOT NULL, expired_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_order_used_proofs (
                    nonce TEXT PRIMARY KEY, requester TEXT NOT NULL, consumed_at REAL NOT NULL);
            ''')

    @contextmanager
    def _connect(self, *, write=False):
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _authorized(db, order_id, token):
        row = db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone()
        expected = row['capability_hash'] if row else '0' * 64
        valid = hmac.compare_digest(expected, _capability(token))
        if not row or not valid or not isinstance(token, str) or not _HEX.fullmatch(token):
            raise OrderError('Invalid order capability.')
        return dict(row)

    @staticmethod
    def _summary(row):
        quote = json.loads(row['quote_json'])
        return {'order_id': row['id'], 'request_id': row['id'], 'requester': row['requester'],
                'status': row['status'], 'plan_sha256': quote['plan_sha256'],
                'source_sha256': quote['source_sha256'], 'created_at': row['created_at'],
                'updated_at': row['updated_at'], 'attempts': row['attempts'],
                'report_available': row['result_json'] is not None,
                'report_sha256': json.loads(row['result_json'])['report_sha256'] if row['result_json'] else None,
                'payment_confirmed': bool(row['paid']), 'checked_at_ledger': row['checked_ledger'],
                'failure_code': row['failure_code'], 'retryable': bool(row['retryable']),
                'delivery': json.loads(row['delivery_json']) if row['delivery_json'] else None}

    def get(self, order_id: str, order_token: str) -> dict:
        with self._connect() as db:
            return self._summary(self._authorized(db, order_id, order_token))

    def result(self, order_id: str, order_token: str) -> dict:
        with self._connect() as db:
            row = self._authorized(db, order_id, order_token)
            if row['result_json'] is None:
                raise OrderError('The committed report is not ready.')
            return json.loads(row['result_json'])

    def _private(self, order_id: str) -> dict:
        with self._connect() as db:
            row = db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone()
        if not row:
            raise OrderError('Unknown worker order.')
        value = dict(row)
        for field in ('engagement', 'plan', 'quote', 'consents', 'result', 'publication', 'delivery'):
            encoded = value.pop(field + '_json')
            value[field] = json.loads(encoded) if encoded is not None else None
        value.pop('capability_hash')
        value['order_id'] = value['id']
        value['report_sha256'] = value['result']['report_sha256'] if value['result'] else None
        return value

    def _insert(self, submission: OrderSubmission, plan: dict, live: dict) -> dict:
        quote = live['quote']
        token, now = secrets.token_hex(32), self.clock()
        engagement = submission.engagement.model_dump(mode='json')
        consents = {key: getattr(submission, key) for key in
                    ('storage_consent', 'auto_settlement_consent', 'publication_consent')}
        binding = _digest({'engagement': engagement, 'plan': plan, 'requester': quote['requester'], 'consents': consents})
        with self._connect(write=True) as db:
            if db.execute('SELECT 1 FROM audit_orders WHERE id=?', (quote['request_id'],)).fetchone():
                raise OrderError('This order already exists. Resume with its private order capability; it cannot be replaced.')
            self._consume_proof(db, submission)
            db.execute('''INSERT INTO audit_orders
                (id, capability_hash, requester, status, engagement_json, plan_json, quote_json,
                 binding_sha256, consents_json, checked_ledger, created_at, updated_at)
                 VALUES (?,?,?,'awaiting_payment',?,?,?,?,?,?,?,?)''',
                (quote['request_id'], _capability(token), quote['requester'], _json(engagement), _json(plan),
                 _json(quote), binding, _json(consents), live['chain']['ledger'], now, now))
        return {**self.get(quote['request_id'], token), 'order_token': token}

    def _consume_proof(self, db, submission):
        proof = submission.wallet_proof or {}
        nonce = proof.get('challenge', {}).get('nonce', '')
        if not isinstance(nonce, str) or not _HEX.fullmatch(nonce):
            raise OrderError('A fresh verified wallet proof nonce is required.')
        try:
            db.execute('INSERT INTO audit_order_used_proofs VALUES (?,?,?)', (nonce, submission.requester, self.clock()))
        except sqlite3.IntegrityError as exc:
            raise OrderError('This wallet proof has already been consumed. Sign a fresh challenge.') from exc

    def _recover(self, submission):
        engagement = _json(submission.engagement.model_dump(mode='json'))
        consents = _json({key: getattr(submission, key) for key in
                         ('storage_consent', 'auto_settlement_consent', 'publication_consent')})
        token = secrets.token_hex(32)
        with self._connect(write=True) as db:
            row = db.execute('''SELECT * FROM audit_orders WHERE requester=? AND engagement_json=? AND consents_json=?''',
                             (submission.requester, engagement, consents)).fetchone()
            if not row:
                raise OrderError('No stored order matches this exact wallet-approved submission.')
            self._consume_proof(db, submission)
            db.execute('UPDATE audit_orders SET capability_hash=?,updated_at=? WHERE id=?', (_capability(token), self.clock(), row['id']))
        return {**self.get(row['id'], token), 'order_token': token}

    @staticmethod
    def _lease(db, order_id, lease_token, now, *, settling=False):
        row = db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone()
        if (not row or not isinstance(lease_token, str) or not row['lease_token']
                or not hmac.compare_digest(row['lease_token'], lease_token)
                or row['lease_until'] <= now or (settling and row['status'] != 'settling')):
            raise LeaseLost('Worker lease is no longer current.')
        return dict(row)

    def claim(self, worker_id: str, *, lease_seconds=120) -> dict | None:
        if not worker_id or len(worker_id) > 100 or not 3 <= lease_seconds <= 3600:
            raise OrderError('Invalid worker or lease duration.')
        now, token = self.clock(), secrets.token_hex(32)
        with self._connect(write=True) as db:
            db.execute("""UPDATE audit_orders SET status='failed',failure_code='retry_limit',retryable=0,
                lease_token=NULL,lease_until=NULL,updated_at=? WHERE status IN ('queued','running','report_ready','settling')
                AND attempts>=? AND (lease_until IS NULL OR lease_until<=?)""", (now, self.max_attempts, now))
            row = db.execute("""SELECT * FROM audit_orders WHERE status IN ('queued','running','report_ready','settling')
                AND attempts<? AND retry_at<=? AND (lease_until IS NULL OR lease_until<=?)
                ORDER BY created_at,id LIMIT 1""", (self.max_attempts, now, now)).fetchone()
            if not row:
                return None
            stage = 'settling' if row['publication_json'] else 'report_ready' if row['result_json'] else 'running'
            db.execute('''UPDATE audit_orders SET status=?,lease_token=?,lease_until=?,attempts=attempts+1,
                failure_code=NULL,retryable=0,updated_at=? WHERE id=?''',
                (stage, token, now + lease_seconds, now, row['id']))
        return self._private(row['id'])

    def heartbeat(self, order_id, lease_token, *, lease_seconds=120):
        if not 3 <= lease_seconds <= 3600:
            raise OrderError('Invalid lease duration.')
        now = self.clock()
        with self._connect(write=True) as db:
            self._lease(db, order_id, lease_token, now)
            db.execute('UPDATE audit_orders SET lease_until=?,updated_at=? WHERE id=?', (now + lease_seconds, now, order_id))

    def _checkpoint(self, order_id, lease_token, status, *, result=None, publication=None, delivery=None,
                    failure_code=None, retryable=False, release=False, retry_delay=0, keep_attempt=False):
        if status not in STATUSES:
            raise OrderError('Unknown order status.')
        now = self.clock()
        with self._connect(write=True) as db:
            row = self._lease(db, order_id, lease_token, now)
            values = {'result_json': _json(result) if result is not None else row['result_json'],
                      'publication_json': _json(publication) if publication is not None else row['publication_json'],
                      'delivery_json': _json(delivery) if delivery is not None else row['delivery_json']}
            if status == 'refunded':
                db.execute('UPDATE audit_orders SET paid=0 WHERE id=?', (order_id,))
            if keep_attempt:
                # Waiting on ledger confirmation is not a failed attempt.
                db.execute('UPDATE audit_orders SET attempts=MAX(attempts-1,0) WHERE id=?', (order_id,))
            db.execute('''UPDATE audit_orders SET status=?,result_json=?,publication_json=?,delivery_json=?,
                failure_code=?,retryable=?,updated_at=?,lease_token=?,lease_until=?,retry_at=? WHERE id=?''',
                (status, *values.values(), failure_code, int(retryable and row['attempts'] < self.max_attempts), now,
                 None if release else lease_token, None if release else row['lease_until'], now + retry_delay, order_id))

    def get_chain_intent(self, order_id, step):
        if step not in _CHAIN_STEPS:
            raise OrderError('Unknown settlement step.')
        with self._connect() as db:
            row = db.execute('SELECT intent_json FROM audit_order_chain_intents WHERE order_id=? AND step=?', (order_id, step)).fetchone()
        return json.loads(row[0]) if row else None

    def reserve_chain_intent(self, order_id, step, intent, *, lease_token):
        if (step not in _CHAIN_STEPS or not isinstance(intent, dict)
                or not _HEX.fullmatch(str(intent.get('tx_hash', '')))
                or intent.get('network') != 'testnet'
                or not StrKey.is_valid_ed25519_public_key(intent.get('signer', ''))
                or type(intent.get('sequence')) is not int or not 0 < intent['sequence'] < 2**63
                or intent.get('status') not in {'prepared', 'pending', 'unknown'}):
            raise OrderError('Invalid settlement intent.')
        encoded = _json(intent)
        if len(encoded) > 200_000:
            raise OrderError('Settlement intent is too large.')
        with self._connect(write=True) as db:
            self._lease(db, order_id, lease_token, self.clock(), settling=True)
            existing = db.execute('SELECT intent_json FROM audit_order_chain_intents WHERE order_id=? AND step=?', (order_id, step)).fetchone()
            if existing:
                return json.loads(existing[0])
            unresolved = db.execute('''SELECT 1 FROM audit_order_chain_intents WHERE network=? AND signer=?
                AND status IN ('prepared','pending','unknown') LIMIT 1''', (intent['network'], intent['signer'])).fetchone()
            if unresolved:
                raise OrderError('Another official transaction is awaiting reconciliation.')
            try:
                db.execute('INSERT INTO audit_order_chain_intents VALUES (?,?,?,?,?,?,?,?)',
                           (order_id, step, intent['tx_hash'], encoded, intent['network'], intent['signer'], intent['sequence'], intent['status']))
            except sqlite3.IntegrityError as exc:
                raise OrderError('This official signer sequence is already reserved.') from exc
            return json.loads(encoded)

    def expire_chain_intent(self, order_id, step, tx_hash, *, lease_token):
        """Archive an unresolved intent the caller proved can never execute."""
        if step not in _CHAIN_STEPS:
            raise OrderError('Unknown settlement step.')
        with self._connect(write=True) as db:
            self._lease(db, order_id, lease_token, self.clock(), settling=True)
            row = db.execute('SELECT tx_hash,intent_json,status FROM audit_order_chain_intents WHERE order_id=? AND step=?',
                             (order_id, step)).fetchone()
            if not row or row['tx_hash'] != tx_hash or row['status'] not in ('prepared', 'pending', 'unknown'):
                raise OrderError('Only an unresolved settlement intent can expire.')
            db.execute('INSERT INTO audit_order_expired_intents VALUES (?,?,?,?,?)',
                       (order_id, step, tx_hash, row['intent_json'], self.clock()))
            db.execute('DELETE FROM audit_order_chain_intents WHERE order_id=? AND step=?', (order_id, step))

    def update_chain_intent(self, order_id, step, tx_hash, updates, *, lease_token):
        if not isinstance(updates, dict) or set(updates) - {'status', 'ledger', 'submitted_at', 'verified_at', 'attempts', 'error_code'}:
            raise OrderError('Immutable settlement intent fields cannot be changed.')
        if 'status' in updates and updates['status'] not in {'prepared', 'pending', 'unknown', 'confirmed', 'observed', 'failed'}:
            raise OrderError('Unknown settlement intent state.')
        with self._connect(write=True) as db:
            self._lease(db, order_id, lease_token, self.clock(), settling=True)
            row = db.execute('SELECT * FROM audit_order_chain_intents WHERE order_id=? AND step=?', (order_id, step)).fetchone()
            if not row or row['tx_hash'] != tx_hash:
                raise OrderError('Settlement transaction hash does not match the reserved intent.')
            if row['status'] in {'confirmed', 'observed', 'failed'} and updates.get('status', row['status']) != row['status']:
                raise OrderError('A terminal settlement intent cannot be reopened.')
            intent = {**json.loads(row['intent_json']), **updates}
            db.execute('UPDATE audit_order_chain_intents SET intent_json=?,status=? WHERE order_id=? AND step=?',
                       (_json(intent), intent['status'], order_id, step))
        return intent


async def _live(request: CheckoutRequest, settings, reader) -> tuple[dict, dict]:
    plan = build_plan(request.engagement, settings)
    if plan['plan']['blockers'] or request.engagement.plan_sha256 != plan['plan_sha256']:
        raise OrderError('The acknowledged plan changed or is blocked; restore its approved configuration before resuming.')
    # The reader is a trusted server adapter, never data supplied by the HTTP caller.
    live = await reader(request, settings)
    quote = Quote.model_validate(live['quote'])
    _verify_quote(CheckoutStepRequest(quote=quote, quote_signature=live['quote_signature'], step='register'),
                  settings, _deployment(), int(time.time()))
    if (quote.requester != request.requester or quote.plan_sha256 != plan['plan_sha256']
            or quote.source_sha256 != plan['plan']['source_sha256'] or quote.tier_id != request.engagement.tier_id):
        raise OrderError('Live checkout is not bound to this exact acknowledged order.')
    chain = live.get('chain', {})
    if type(chain.get('ledger')) is not int or chain['ledger'] <= 0:
        raise OrderError('Live payment verification did not return a ledger.')
    state = chain.get('escrow_state')
    if state not in {'absent', 'Created', 'Funded', 'Submitted', 'Disputed', 'Complete', 'Refunded'}:
        raise OrderError('Live payment verification returned an unknown escrow state.')
    paid = state in {'Funded', 'Submitted', 'Disputed', 'Complete'}
    if live.get('payment_confirmed') is not paid:
        raise OrderError('Live payment confirmation is inconsistent.')
    live['quote'] = quote.model_dump()
    return plan['plan'], live


async def create_order(submission: OrderSubmission, settings, store: AuditOrderStore, *, checkout_reader=prepare_checkout) -> dict:
    _verify_identity(submission, settings)
    request = CheckoutRequest(engagement=submission.engagement, requester=submission.requester)
    plan, live = await _live(request, settings, checkout_reader)
    if live['chain']['escrow_state'] not in {'absent', 'Created'}:
        raise OrderError('Create and retain a private order capability before funding; existing paid or refunded jobs require operator recovery.')
    if live['chain']['ledger'] >= live['quote']['deadline_ledger']:
        raise OrderError('The escrow deadline has expired.')
    return store._insert(submission, plan, live)


async def recover_order(submission: OrderSubmission, settings, store: AuditOrderStore) -> dict:
    """Rotate a lost capability using a fresh exact-scope wallet proof, atomically.

    Does not reset attempts, payment, leases, source, artifacts or settlement state.
    Used challenges are retained so signed messages cannot rotate the token twice.
    Recovery needs no RPC and remains possible while pinned execution config drifts.
    """
    _verify_identity(submission, settings)
    return store._recover(submission)


async def activate_order(order_id: str, order_token: str, settings, store: AuditOrderStore, *, checkout_reader=prepare_checkout) -> dict:
    # Capability check precedes source access and any external RPC.
    store.get(order_id, order_token)
    return await _activate_stored(order_id, settings, store, checkout_reader=checkout_reader, order_token=order_token)


async def _activate_stored(order_id: str, settings, store: AuditOrderStore, *, checkout_reader, order_token=None) -> dict:
    """Private worker entry: only an already-owned, stored submission can resume."""
    order = store._private(order_id)
    request = CheckoutRequest(engagement=EngagementRequest.model_validate(order['engagement']), requester=order['requester'])
    plan, live = await _live(request, settings, checkout_reader)
    if live['quote']['request_id'] != order_id or _json(plan) != _json(order['plan']):
        raise OrderError('Stored order and live checkout commitment differ.')
    now = store.clock()
    with store._connect(write=True) as db:
        row = (store._authorized(db, order_id, order_token) if order_token is not None else
               dict(db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone()))
        if row['lease_until'] is not None and row['lease_until'] > now:
            return store._summary(row)
        state, status = live['chain']['escrow_state'], row['status']
        if status == 'delivered':
            return store._summary(row)
        if state == 'Refunded':
            status = 'refunded'
        elif state == 'Disputed':
            raise OrderError('Disputed escrow requires operator resolution; no worker is queued.')
        elif state in {'Funded', 'Submitted', 'Complete'}:
            if state != 'Funded' and not row['result_json']:
                raise OrderError('Existing settlement has no local report checkpoint; operator reconciliation is required.')
            if state != 'Complete' and live['quote']['deadline_ledger'] - live['chain']['ledger'] < (MIN_EXECUTION_LEDGERS if not row['result_json'] else 1):
                raise OrderError('Insufficient escrow lifetime remains; no paid computation is started. Inspect the refund path.')
            if row['attempts'] >= store.max_attempts:
                raise OrderError('Worker retry limit reached; operator recovery is required.')
            status = 'settling' if row['publication_json'] else 'report_ready' if row['result_json'] else 'queued'
        elif row['paid']:
            raise OrderError('Previously confirmed payment disappeared; operator reconciliation is required.')
        db.execute('''UPDATE audit_orders SET status=?,quote_json=?,checked_ledger=?,paid=?,
            failure_code=NULL,retryable=0,lease_token=NULL,lease_until=NULL,retry_at=0,updated_at=? WHERE id=?''',
            (status, _json(live['quote']), live['chain']['ledger'], int(live['payment_confirmed']), now, order_id))
    with store._connect() as db:
        row = dict(db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone())
    return store._summary(row)


async def reconcile_pending_orders(store: AuditOrderStore, settings, *, checkout_reader=prepare_checkout, limit=10) -> list[dict]:
    """Private scheduler: recover payment after a browser closes or disconnects.

    No new source or public address is accepted here. Each candidate was already
    wallet-approved, stored with consent and assigned its private capability.
    Never expose this internal reconciliation operation as an unauthenticated API.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise OrderError('Invalid reconciliation batch size.')
    with store._connect() as db:
        ids = [row[0] for row in db.execute("""SELECT id FROM audit_orders WHERE status='awaiting_payment'
            AND retry_at<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY updated_at,id LIMIT ?""",
            (store.clock(), store.clock(), limit))]
    outcomes = []
    for order_id in ids:
        try:
            outcomes.append(await _activate_stored(order_id, settings, store, checkout_reader=checkout_reader))
        except Exception:
            # Keep the saved order; transient RPC outages must not invent payment.
            with store._connect(write=True) as db:
                db.execute("""UPDATE audit_orders SET retry_at=?,updated_at=?
                    WHERE id=? AND status='awaiting_payment'""", (store.clock() + 30, store.clock(), order_id))
            outcomes.append({'order_id': order_id, 'status': 'awaiting_payment', 'failure_code': 'payment_recheck_failed'})
    return outcomes


def _observed_workflow_exception(observation, runtime):
    """A completed runner may report a real agent exception as negative evidence.

    Missing runner output, provider failures and ambiguous side effects must not
    become paid fulfillment merely because an error string exists in VM output.
    """
    if not runtime.get('execution_profile') or observation.get('exit_code') != 0:
        return False
    case = next((c for c in runtime.get('cases', []) if c.get('id') == observation.get('id')), {})
    steps = case.get('workflow', {}).get('steps', [])
    outcomes = observation.get('step_outcomes')
    if (not steps or not isinstance(outcomes, list) or len(outcomes) != len(steps)
            or observation.get('steps_observed') != len(steps)
            or any(not isinstance(o, dict) or o.get('step') != i for i, o in enumerate(outcomes))):
        return False
    errors = [o.get('error') for o in outcomes if o.get('error')]
    agent_errors = {'KeyError','ValueError','PermissionError','TypeError','AssertionError',
                    'IndexError','AttributeError','ZeroDivisionError','RuntimeError'}
    if not errors or any(error not in agent_errors for error in errors):
        return False
    bounds = observation.get('external_event_range')
    events = runtime.get('broker_evidence', {}).get('events')
    if (not isinstance(events, list) or not isinstance(bounds, list) or len(bounds) != 2
            or any(type(i) is not int for i in bounds) or not 0 <= bounds[0] <= bounds[1] <= len(events)):
        return False
    return all(isinstance(event, dict) and event.get('workflow') == observation['id']
               and event.get('status') in {'completed','confirmed','denied'}
               for event in events[bounds[0]:bounds[1]])


def _validate_result(result, order):
    if not isinstance(result, dict):
        raise OrderError('Executor returned no canonical report.')
    report = decode_report(DeliveryRequest(report_json=result.get('report_json', ''), report_sha256=result.get('report_sha256', '')))
    if result.get('report') != report:
        raise OrderError('Executor report object and canonical bytes differ.')
    engagement = report.get('engagement', {})
    if (engagement.get('plan_sha256') != order['quote']['plan_sha256']
            or _json(engagement.get('plan')) != _json(order['plan'])
            or _digest(engagement.get('plan')) != order['quote']['plan_sha256']):
        raise OrderError('Executor report is not bound to the paid plan.')
    plan = order['plan']
    if plan.get('ai_processor') and report.get('ai_review', {}).get('status') not in {'completed', 'no_observations'}:
        raise OrderError('The requested AI review did not complete; provider failure cannot settle a paid audit.')
    if order['quote']['tier_id'] != 'quick':
        envelope = engagement.get('runtime')
        runtime = envelope.get('report') if isinstance(envelope, dict) else None
        if (not isinstance(runtime, dict) or _digest(runtime) != envelope.get('report_sha256')
                or runtime.get('schema') != 'agentveritas.runtime.v1' or runtime.get('execution') != 'completed'
                or runtime.get('source_sha256') != plan['source_sha256']
                or runtime.get('image') != plan['runtime_image']
                or runtime.get('audit_tier') != order['quote']['tier_id']
                or runtime.get('network') != 'deny-all' or runtime.get('provider') != 'vercel_sandbox'
                or runtime.get('production_credentials') is not False
                or sorted(runtime.get('selected_modules') or []) != sorted(m['id'] for m in plan['modules'])):
            raise OrderError('The requested isolated runtime evidence is missing or bound to a different execution.')
        cases, observations = runtime.get('cases'), runtime.get('observations')
        count = plan['planned_runtime_cases']
        if (not isinstance(cases, list) or not isinstance(observations, list)
                or not count <= len(cases) <= plan['budgets']['runtime_cases']
                or len(cases) != len(observations) or runtime.get('case_count') != len(cases)
                or _digest(cases) != runtime.get('issued_cases_sha256')
                or _digest(cases[:count]) != plan['runtime_cases_sha256']
                or any(not isinstance(c, dict) or not isinstance(o, dict) or c.get('id') != o.get('id')
                       for c, o in zip(cases, observations))):
            raise OrderError('The runtime evidence does not cover the committed issued case pack.')
        # Agent exceptions/timeouts are legitimate failure observations. Missing
        # dependencies/environment or absent telemetry are not paid fulfillment.
        for observation in observations:
            status = observation.get('status')
            if status in {'observed', 'needs_investigation', 'timeout'}:
                continue
            if status == 'inconclusive':
                if runtime.get('execution_profile'):
                    if _observed_workflow_exception(observation, runtime):
                        continue
                elif isinstance(observation.get('error'), str) and observation['error']:
                    continue
            raise OrderError('Runtime infrastructure or missing telemetry blocked the requested case pack.')
        if plan.get('ai_generated_cases_max', 0) and runtime.get('ai_planning') not in {'completed', 'skipped_case_budget'}:
            raise OrderError('The requested AI runtime planning did not complete.')
        if plan.get('execution_profile'):
            profile = runtime.get('execution_profile', {})
            external = runtime.get('broker_evidence', {})
            if (profile.get('sha256') != plan['execution_profile']['sha256']
                    or profile.get('id') != plan['execution_profile']['id']
                    or not isinstance(external.get('events'), list)
                    or _digest(external['events']) != external.get('sha256')):
                raise OrderError('Broker evidence is missing or belongs to a different execution profile.')
    _json(result)


def _validate_publication(publication, result):
    if (not isinstance(publication, dict) or publication.get('report_sha256') != result['report_sha256']
            or publication.get('visibility') != 'private' or publication.get('verified') is not True or not isinstance(publication.get('report_uri'), str)
            or not 1 <= len(publication['report_uri']) <= 2000):
        raise OrderError('Publisher did not confirm the exact consented report commitment.')


def _validate_delivery(delivery, order, result, publication):
    quote = order['quote']
    expected = {'schema': 'veritas.testnet-order-delivery/v1', 'status': 'delivered', 'network': 'testnet',
                'request_id': order['id'], 'agent_id': quote['agent_id'], 'report_sha256': result['report_sha256'],
                'report_uri': publication['report_uri'], 'credential_contract_id': quote['contracts']['credential'],
                'escrow_contract_id': quote['contracts']['escrow'], 'owner': quote['requester'],
                'is_current': True, 'payment_state': 'Complete', 'independent_evaluator': False}
    if (not isinstance(delivery, dict) or any(delivery.get(k) != v for k, v in expected.items())
            or delivery.get('is_current') is not True or delivery.get('independent_evaluator') is not False
            or delivery.get('token_id') != order['id']
            or type(delivery.get('checked_at_ledger')) is not int or delivery['checked_at_ledger'] < order['checked_ledger']):
        raise OrderError('Settlement adapter did not verify this exact report, owner and completed escrow.')


async def run_order_once(store: AuditOrderStore, worker_id: str, *, settings, executor,
                         publisher, chain_adapter, checkout_reader=prepare_checkout, lease_seconds=120) -> dict | None:
    """Claim one job and resume persisted stages. Call only from a private worker.

    executor(request, settings), publisher(order, result), and
    chain_adapter(order, result, publication) are async trusted adapters. The latter
    must read back completed escrow/current credential before returning delivered.
    No adapter receives an order access token. A failure stores a generic stage code
    (never exception text or customer content); capability activation retries.
    """
    order = store.claim(worker_id, lease_seconds=lease_seconds)
    if order is None:
        return None
    order_id, token = order['id'], order['lease_token']
    stage = 'payment_recheck'

    async def renew():
        while True:
            await asyncio.sleep(lease_seconds / 3)
            store.heartbeat(order_id, token, lease_seconds=lease_seconds)

    async def process():
        nonlocal order, stage
        request = CheckoutRequest(engagement=EngagementRequest.model_validate(order['engagement']), requester=order['requester'])
        if _digest({'engagement': order['engagement'], 'plan': order['plan'], 'requester': order['requester'], 'consents': order['consents']}) != order['binding_sha256']:
            raise OrderError('Stored order artifact commitment is inconsistent.')
        plan, live = await _live(request, settings, checkout_reader)
        if live['quote']['request_id'] != order_id or _json(plan) != _json(order['plan']):
            raise OrderError('Worker configuration drifted from the acknowledged plan.')
        with store._connect(write=True) as db:
            store._lease(db, order_id, token, store.clock())
            db.execute('''UPDATE audit_orders SET quote_json=?,checked_ledger=?,paid=?,updated_at=? WHERE id=?''',
                       (_json(live['quote']), live['chain']['ledger'], int(live['payment_confirmed']), store.clock(), order_id))
        order = store._private(order_id)
        state = live['chain']['escrow_state']
        if state == 'Refunded':
            store._checkpoint(order_id, token, 'refunded', release=True)
            return
        if not live['payment_confirmed'] or state == 'Disputed':
            raise OrderError('Escrow is not available for this audit.')
        if not order['result'] and (state != 'Funded' or live['quote']['deadline_ledger'] - live['chain']['ledger'] < MIN_EXECUTION_LEDGERS):
            raise OrderError('Insufficient funded escrow lifetime remains for execution.')
        if order['result'] is None:
            stage = 'execution'
            result = await executor(request.engagement, settings)
            _validate_result(result, order)
            store._checkpoint(order_id, token, 'report_ready', result=result)
            order = store._private(order_id)
        else:
            _validate_result(order['result'], order)
        if order['publication'] is None:
            stage = 'publication'
            if not all(order['consents'].values()):
                raise OrderError('Required order consent is missing.')
            publication = await publisher(order, order['result'])
            _validate_publication(publication, order['result'])
            store._checkpoint(order_id, token, 'settling', publication=publication)
            order = store._private(order_id)
        else:
            _validate_publication(order['publication'], order['result'])
        stage = 'settlement'
        store._checkpoint(order_id, token, 'settling')
        delivery = await chain_adapter(order, order['result'], order['publication'])
        _validate_delivery(delivery, order, order['result'], order['publication'])
        store._checkpoint(order_id, token, 'delivered', delivery=delivery, release=True)

    heartbeat = asyncio.create_task(renew())
    processing = asyncio.create_task(process())
    try:
        done, _ = await asyncio.wait({heartbeat, processing}, return_when=asyncio.FIRST_COMPLETED)
        if heartbeat in done:
            await heartbeat  # A lost lease cancels local work and prohibits checkpoint writes.
        await processing
    except LeaseLost:
        return {'order_id': order_id, 'status': 'lease_lost'}
    except asyncio.CancelledError:
        # Leave the lease to expire; another worker reconciles durable checkpoints.
        raise
    except SettlementPending:
        # Keep the order claimable so a later worker pass reconciles or expires the saved intent.
        try:
            store._checkpoint(order_id, token, 'settling', failure_code='settlement_pending', release=True,
                              retry_delay=SETTLEMENT_RETRY_SECONDS, keep_attempt=True)
        except LeaseLost:
            return {'order_id': order_id, 'status': 'lease_lost'}
    except Exception:
        try:
            store._checkpoint(order_id, token, 'failed', failure_code=stage + '_failed', retryable=True, release=True)
        except LeaseLost:
            return {'order_id': order_id, 'status': 'lease_lost'}
    finally:
        heartbeat.cancel()
        processing.cancel()
        await asyncio.gather(heartbeat, processing, return_exceptions=True)
    with store._connect() as db:
        row = dict(db.execute('SELECT * FROM audit_orders WHERE id=?', (order_id,)).fetchone())
    return store._summary(row)
