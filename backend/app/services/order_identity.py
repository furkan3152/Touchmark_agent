"""Short-lived, scope-bound SEP-53 master-key proof for private pilot orders.

This verifies possession of the G-address signing key, not a SEP-10 session,
multisig threshold, contract account or ongoing wallet authorization. Funding
still requires a separate, valid requester transaction on Stellar Testnet.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import hmac
import secrets
import time

from stellar_sdk import Keypair

from ..reporting.generator import canonical_json
from ..stellar.ownership import sep53_payload_hash
from .testnet_checkout import PASSPHRASE, _key

DOMAIN = 'agentveritas-stellar:official-order:v1'
LIFETIME = 300


def _submission(submission) -> dict:
    return submission.model_dump(mode='json', exclude={'wallet_proof'})


def _message(challenge: dict) -> str:
    return ('AgentVeritas official audit order\n'
            'Purpose: prove control of the requester signing key for this private audit order.\n'
            'This message does not authorize a payment.\n' + canonical_json(challenge))


def _signature(challenge, settings):
    key = hmac.new(_key(settings), DOMAIN.encode(), sha256).digest()
    return hmac.new(key, canonical_json(challenge).encode(), sha256).hexdigest()


def make_order_challenge(submission, settings, *, now=None) -> dict:
    timestamp = int(time.time()) if now is None else int(now)
    if submission.engagement.plan_sha256 is None:
        raise ValueError('Acknowledge the audit plan before proving requester ownership.')
    challenge = {
        'domain': DOMAIN, 'network_passphrase': PASSPHRASE,
        'requester': submission.requester,
        'plan_sha256': submission.engagement.plan_sha256,
        'submission_sha256': sha256(canonical_json(_submission(submission)).encode()).hexdigest(),
        'nonce': secrets.token_hex(32), 'issued_at': timestamp, 'expires_at': timestamp + LIFETIME,
    }
    return {'message': _message(challenge), 'challenge': challenge,
            'challenge_signature': _signature(challenge, settings),
            'signature_standard': 'SEP-53', 'network': 'testnet'}


def verify_order_identity(submission, settings, *, now=None) -> None:
    timestamp = int(time.time()) if now is None else int(now)
    proof = submission.wallet_proof
    try:
        if not isinstance(proof, dict) or set(proof) != {'challenge', 'challenge_signature', 'wallet_signature'}:
            raise ValueError()
        c = proof['challenge']
        if not isinstance(c, dict) or set(c) != {'domain', 'network_passphrase', 'requester', 'plan_sha256', 'submission_sha256', 'nonce', 'issued_at', 'expires_at'}:
            raise ValueError()
        if (c['domain'] != DOMAIN or c['network_passphrase'] != PASSPHRASE
                or c['requester'] != submission.requester
                or c['plan_sha256'] != submission.engagement.plan_sha256
                or c['submission_sha256'] != sha256(canonical_json(_submission(submission)).encode()).hexdigest()
                or type(c['issued_at']) is not int or type(c['expires_at']) is not int
                or c['expires_at'] - c['issued_at'] != LIFETIME
                or not c['issued_at'] <= timestamp < c['expires_at']
                or not isinstance(c['nonce'], str) or len(c['nonce']) != 64
                or not isinstance(proof['challenge_signature'], str)
                or not hmac.compare_digest(_signature(c, settings), proof['challenge_signature'])):
            raise ValueError()
        raw = base64.b64decode(proof['wallet_signature'], validate=True)
        if len(raw) != 64:
            raise ValueError()
        Keypair.from_public_key(submission.requester).verify(sep53_payload_hash(_message(c)), raw)
    except Exception as exc:
        raise ValueError('A valid, unexpired requester ownership proof for this exact order is required.') from exc
