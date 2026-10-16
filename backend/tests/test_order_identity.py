"""Real Ed25519 order proofs; source is data and never imported or executed."""
import base64
from hashlib import sha256

import pytest
from pydantic import ValidationError
from stellar_sdk import Keypair

from backend.app.config import Settings
from backend.app.reporting.generator import canonical_json
from backend.app.services import audit_orders as orders
from backend.app.services import order_identity as identity
from backend.app.services import testnet_checkout as checkout
from backend.app.services.audit_product import EngagementRequest, build_plan
from backend.app.services.studio import ReviewRequest


NOW = 1_800_000_000


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def proof_case():
    key = Keypair.random()
    settings = Settings(_env_file=None, stellar_network='testnet',
        runtime_api_key='public-pilot-access-' * 3,
        checkout_quote_signing_key='server-only-identity-signing-' * 3)
    engagement = EngagementRequest(source=ReviewRequest(name='Public Reader',
        purpose='Read the fixed public balance.', files={'reader.py': 'def answer(prompt):\n    return "12"\n'}))
    engagement.plan_sha256 = build_plan(engagement, settings)['plan_sha256']
    submission = orders.OrderSubmission(engagement=engagement, requester=key.public_key,
        storage_consent=True, auto_settlement_consent=True, publication_consent=True)
    return key, settings, submission


def sign(submission, key, settings):
    challenge = identity.make_order_challenge(submission, settings, now=NOW)
    # Hash independently of the application helper, using the SEP-53 prefix.
    digest = sha256(b'Stellar Signed Message:\n' + challenge['message'].encode('utf-8')).digest()
    submission.wallet_proof = {'challenge': challenge['challenge'],
        'challenge_signature': challenge['challenge_signature'],
        'wallet_signature': base64.b64encode(key.sign(digest)).decode('ascii')}
    return challenge


def test_real_sep53_proof_binds_full_private_order_and_returns_no_source(proof_case):
    key, settings, submission = proof_case
    response = sign(submission, key, settings)
    identity.verify_order_identity(submission, settings, now=NOW)
    challenge = response['challenge']
    assert response['signature_standard'] == 'SEP-53'
    assert challenge['expires_at'] - challenge['issued_at'] == 300
    assert len(challenge['nonce']) == 64 and int(challenge['nonce'], 16) >= 0
    assert challenge['submission_sha256'] == sha256(canonical_json(
        submission.model_dump(mode='json', exclude={'wallet_proof'})).encode()).hexdigest()
    assert 'def answer' not in response['message']
    assert key.secret not in canonical_json(response)


@pytest.mark.parametrize('offset', [-1, 300, 301, 10000])
def test_proof_not_valid_before_issue_or_after_expiry(proof_case, offset):
    key, settings, submission = proof_case
    sign(submission, key, settings)
    with pytest.raises(ValueError, match='unexpired requester ownership'):
        identity.verify_order_identity(submission, settings, now=NOW + offset)


@pytest.mark.parametrize('field', ['source', 'purpose', 'modules', 'tier', 'plan',
                                   'storage_consent', 'auto_settlement_consent', 'publication_consent'])
def test_original_wallet_signature_cannot_authorize_changed_scope_or_consent(proof_case, field):
    key, settings, submission = proof_case
    sign(submission, key, settings)
    if field == 'source':
        submission.engagement.source.files['reader.py'] += '# substituted source\n'
    elif field == 'purpose':
        submission.engagement.source.purpose = 'Move treasury funds.'
    elif field == 'modules':
        submission.engagement.module_ids = ['financial']
    elif field == 'tier':
        submission.engagement.tier_id = 'deep'
    elif field == 'plan':
        submission.engagement.plan_sha256 = 'f' * 64
    else:
        setattr(submission, field, False)
    with pytest.raises(ValueError, match='exact order'):
        identity.verify_order_identity(submission, settings, now=NOW)


@pytest.mark.parametrize('field,value', [('nonce', 'a' * 64), ('domain', 'other-service'),
    ('network_passphrase', 'Public Global Stellar Network ; September 2015'),
    ('issued_at', NOW + 1), ('expires_at', NOW + 299), ('submission_sha256', '0' * 64)])
def test_wallet_signature_does_not_replace_server_challenge_authentication(proof_case, field, value):
    key, settings, submission = proof_case
    sign(submission, key, settings)
    submission.wallet_proof['challenge'][field] = value
    # Even an owner signature over an altered challenge cannot replace server HMAC.
    message = identity._message(submission.wallet_proof['challenge'])
    digest = sha256(b'Stellar Signed Message:\n' + message.encode()).digest()
    submission.wallet_proof['wallet_signature'] = base64.b64encode(key.sign(digest)).decode()
    with pytest.raises(ValueError, match='ownership proof'):
        identity.verify_order_identity(submission, settings, now=NOW)


def test_another_wallet_cannot_sign_a_requester_challenge(proof_case):
    _, settings, submission = proof_case
    sign(submission, Keypair.random(), settings)
    with pytest.raises(ValueError, match='ownership proof'):
        identity.verify_order_identity(submission, settings, now=NOW)


@pytest.mark.parametrize('mutation', ['extra_proof', 'extra_challenge', 'missing_nonce',
                                    'bool_timestamp', 'nonbase64', 'short_signature', 'raw_message_signature'])
def test_proof_schema_and_signature_encoding_fail_closed(proof_case, mutation):
    key, settings, submission = proof_case
    response = sign(submission, key, settings)
    proof = submission.wallet_proof
    if mutation == 'extra_proof':
        proof['verified'] = True
    elif mutation == 'extra_challenge':
        proof['challenge']['verified'] = True
    elif mutation == 'missing_nonce':
        del proof['challenge']['nonce']
    elif mutation == 'bool_timestamp':
        proof['challenge']['issued_at'] = True
    elif mutation == 'nonbase64':
        proof['wallet_signature'] = 'not-a-base64-signature!'
    elif mutation == 'short_signature':
        proof['wallet_signature'] = base64.b64encode(b'x' * 63).decode()
    else:
        proof['wallet_signature'] = base64.b64encode(key.sign(response['message'].encode())).decode()
    with pytest.raises(ValueError, match='ownership proof'):
        identity.verify_order_identity(submission, settings, now=NOW)


def test_no_acknowledged_plan_cannot_obtain_identity_challenge(proof_case):
    _, settings, submission = proof_case
    submission.engagement.plan_sha256 = None
    with pytest.raises(ValueError, match='Acknowledge'):
        identity.make_order_challenge(submission, settings, now=NOW)
    with pytest.raises(ValidationError):
        orders.OrderSubmission.model_validate({**submission.model_dump(), 'public_report_consent': True})


@pytest.mark.anyio
async def test_real_proof_is_consumed_and_fresh_recovery_rotates_only_access(proof_case, tmp_path, monkeypatch):
    key, settings, submission = proof_case
    monkeypatch.setattr(identity.time, 'time', lambda: NOW)
    reads = []

    async def snapshot(*args):
        reads.append(True)
        return {'ledger': 5_200_000, 'account': {'sequence': 42, 'balance': 100_000_000}}

    monkeypatch.setattr(checkout, '_snapshot', snapshot)
    store = orders.AuditOrderStore(tmp_path / 'private-orders.sqlite')
    sign(submission, key, settings)
    created = await orders.create_order(submission, settings, store)
    previous = store._private(created['order_id'])
    with pytest.raises(orders.OrderError, match='already exists'):
        await orders.create_order(submission, settings, store)
    with pytest.raises(orders.OrderError, match='already been consumed'):
        await orders.recover_order(submission, settings, store)
    sign(submission, key, settings)
    before = len(reads)
    recovered = await orders.recover_order(submission, settings, store)
    assert len(reads) == before
    assert recovered['order_id'] == created['order_id'] and recovered['order_token'] != created['order_token']
    with pytest.raises(orders.OrderError, match='capability'):
        store.get(created['order_id'], created['order_token'])
    current = store._private(created['order_id'])
    for field in ('engagement', 'plan', 'quote', 'binding_sha256', 'attempts', 'paid', 'status', 'result'):
        assert current[field] == previous[field]
    with pytest.raises(orders.OrderError, match='already been consumed'):
        await orders.recover_order(submission, settings, store)
    assert store.get(recovered['order_id'], recovered['order_token'])['status'] == 'awaiting_payment'
