"""Pinned Testnet checkout: signed quotes, live state and unsigned wallet XDR only.

A simulation is not a payment. This module has no signing or submission path.
The first-party provider still has to deliver and attest the requested audit.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
from pathlib import Path
import time
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from stellar_sdk import Account, Address, Keypair, Network, SorobanServer, StrKey, TransactionBuilder, scval, xdr
from stellar_sdk.soroban_rpc import SimulateTransactionResponse

from ..reporting.generator import canonical_json
from .audit_product import EngagementRequest, TierID, build_plan, normalize

RPC_URL = 'https://soroban-testnet.stellar.org'
PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
PILOT_PATH = Path(__file__).resolve().parents[3] / 'deployments/testnet-audit-delivery-2026-10-15.json'
PRICES = {'quick': '1000000', 'standard': '10000000', 'deep': '30000000'}
PINNED_CONTRACTS = {
    'registry': 'CANHPHK5BGUDSQ6AUJQC7AWTAWBHBQVBRP2HB5ZU4HNBCGHSFOBO5DXH',
    'escrow': 'CD4OOPXGVL64YSUVZWDBAM2AATNITI5DKY4HXRALYUURH27MQZNF2O4V',
    'credential': 'CAPYQST5PLKLYYNSAM5QXNPVPJID776BALTW5LUVCCESJZKRBEZ2BKSZ',
}
NATIVE_SAC = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC'
MAX_FEE_ATOMIC = 20_000_000
QUOTE_SECONDS = 600
DEADLINE_LEDGERS = 17_280  # Approximately one day; ledger time is not a wall-clock guarantee.
StepID = Literal['register', 'request', 'create', 'fund']
STEPS = [('register', 'Register committed agent version'), ('request', 'Request official validation'),
         ('create', 'Create source-bound escrow'), ('fund', 'Fund Testnet audit escrow')]
LIMITS = [
    'Testnet XLM has no monetary value. Network transaction fees are additional to the audit amount.',
    'Prepared or simulated transactions are not payment confirmation. Only a live bound escrow state confirms funding.',
    'Provider and evaluator are first-party identities controlled by one operator; they are not independent reviewers.',
    'Funding activates only a matching saved official order on a configured persistent worker. A credential requires completed report and chain verification.',
    'Keep the acknowledged source and plan. Only their commitments are written onchain; private source is not published.',
    'Use the private order refund action for disputed escrow, or eligible funded/submitted escrow after its ledger deadline; a separate wallet signature and submission are required.',
]


class CheckoutRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    engagement: EngagementRequest
    requester: str = Field(min_length=56, max_length=56)

    @field_validator('requester')
    @classmethod
    def account(cls, value):
        if not StrKey.is_valid_ed25519_public_key(value):
            raise ValueError('Use a public G-address of a Testnet wallet, never a secret seed.')
        return value


class Quote(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema: Literal['veritas.testnet-checkout/v1'] = 'veritas.testnet-checkout/v1'
    requester: str = Field(min_length=56, max_length=56)
    tier_id: TierID
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    plan_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    agent_id: str = Field(pattern=r'^[a-f0-9]{64}$')
    request_id: str = Field(pattern=r'^[a-f0-9]{64}$')
    amount_atomic: str = Field(pattern=r'^[0-9]{1,10}$')
    asset: Literal['XLM'] = 'XLM'
    decimals: Literal[7] = 7
    network: Literal['testnet'] = 'testnet'
    network_passphrase: Literal['Test SDF Network ; September 2015'] = PASSPHRASE
    contracts: dict[str, str] = Field(min_length=3, max_length=3)
    provider: str = Field(min_length=56, max_length=56)
    evaluator: str = Field(min_length=56, max_length=56)
    treasury: str = Field(min_length=56, max_length=56)
    fee_bps: Literal[1500] = 1500
    deadline_ledger: int = Field(gt=0, le=4294967295)
    issued_at: int = Field(gt=0)
    expires_at: int = Field(gt=0)


class CheckoutStepRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    quote: Quote
    quote_signature: str = Field(pattern=r'^[a-f0-9]{64}$')
    step: StepID


def _deployment() -> dict:
    manifest = json.loads(PILOT_PATH.read_text())
    if (manifest.get('status') != 'verified' or manifest.get('network') != 'testnet'
            or manifest.get('network_passphrase') != PASSPHRASE
            or {k: v['id'] for k, v in manifest['contracts'].items()} != PINNED_CONTRACTS
            or manifest['asset']['contract_id'] != NATIVE_SAC):
        raise ValueError('The pinned Testnet deployment is unavailable or has changed.')
    return manifest


def _key(settings) -> bytes:
    if settings.stellar_network != 'testnet':
        raise ValueError('Wallet checkout requires STELLAR_NETWORK=testnet.')
    if len(settings.checkout_quote_signing_key) < 32:
        raise ValueError('Checkout requires a server-only CHECKOUT_QUOTE_SIGNING_KEY of at least 32 characters.')
    if hmac.compare_digest(settings.checkout_quote_signing_key, settings.runtime_api_key):
        raise ValueError('The server-only quote signing key must differ from the client API access token.')
    return hmac.new(settings.checkout_quote_signing_key.encode(), b'veritas.testnet-checkout.quote/v1', sha256).digest()


def _signature(quote: Quote, settings) -> str:
    return hmac.new(_key(settings), canonical_json(quote.model_dump()).encode(), sha256).hexdigest()


def _ids(requester: str, source: str, plan: str, tier: str, manifest: dict) -> tuple[str, str]:
    identity = {'domain': 'veritas.checkout.agent/v1', 'network': 'testnet', 'requester': requester,
                'source_sha256': source, 'plan_sha256': plan, 'registry': PINNED_CONTRACTS['registry']}
    agent_id = sha256(canonical_json(identity).encode()).hexdigest()
    request = {'domain': 'veritas.checkout.request/v1', 'agent_id': agent_id, 'plan_sha256': plan,
               'tier': tier, 'amount_atomic': PRICES[tier], 'contracts': PINNED_CONTRACTS,
               'provider': manifest['roles']['provider'], 'evaluator': manifest['roles']['evaluator']}
    return agent_id, sha256(canonical_json(request).encode()).hexdigest()


class _RPC:
    def __init__(self, transport=None):
        self.client = httpx.AsyncClient(timeout=12, follow_redirects=False, transport=transport)

    async def close(self):
        await self.client.aclose()

    async def call(self, method: str, params=None) -> dict:
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
        try:
            async with self.client.stream('POST', RPC_URL, json=body) as response:
                response.raise_for_status()
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 512_000:
                        raise ValueError('Testnet RPC response exceeded the bounded checkout limit.')
            data = json.loads(raw)
            if data.get('error') or not isinstance(data.get('result'), dict):
                raise ValueError('Testnet RPC could not verify this checkout.')
            return data['result']
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ValueError('Testnet RPC is unavailable; no payment or transaction success is claimed.') from exc


def _contract_key(contract: str, key: xdr.SCVal) -> str:
    return xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA,
        contract_data=xdr.LedgerKeyContractData(Address(contract).to_xdr_sc_address(), key,
                                               xdr.ContractDataDurability.PERSISTENT)).to_xdr()


def _record_key(contract: str, kind: str, value: xdr.SCVal) -> str:
    return _contract_key(contract, scval.to_vec([scval.to_symbol(kind), value]))


def _native(value):
    if isinstance(value, Address):
        return value.address
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [_native(item) for item in value]
    if isinstance(value, dict):
        return {key: _native(item) for key, item in value.items()}
    return value


async def _snapshot(rpc: _RPC, quote: Quote, manifest: dict) -> dict:
    network = await rpc.call('getNetwork')
    if network.get('passphrase') != PASSPHRASE:
        raise ValueError('The RPC did not attest the Testnet network passphrase.')
    instance_key = xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE)
    keys = {name + '_instance': _contract_key(contract, instance_key) for name, contract in PINNED_CONTRACTS.items()}
    keys.update({
        'agent': _record_key(PINNED_CONTRACTS['registry'], 'Agent', scval.to_bytes(bytes.fromhex(quote.agent_id))),
        'validation': _record_key(PINNED_CONTRACTS['registry'], 'Valid', scval.to_bytes(bytes.fromhex(quote.request_id))),
        'validator_enabled': _record_key(PINNED_CONTRACTS['registry'], 'IsVal', scval.to_address(quote.provider)),
        'job': _record_key(PINNED_CONTRACTS['escrow'], 'Job', scval.to_bytes(bytes.fromhex(quote.request_id))),
        'binding': _record_key(PINNED_CONTRACTS['escrow'], 'Binding', scval.to_bytes(bytes.fromhex(quote.request_id))),
        'account': xdr.LedgerKey(xdr.LedgerEntryType.ACCOUNT,
            account=xdr.LedgerKeyAccount(Keypair.from_public_key(quote.requester).xdr_account_id())).to_xdr(),
    })
    result = await rpc.call('getLedgerEntries', {'keys': list(keys.values())})
    ledger = int(result.get('latestLedger', 0))
    if not 0 < ledger < 4294967295 - DEADLINE_LEDGERS:
        raise ValueError('Testnet did not return a usable live ledger.')
    reverse = {value: key for key, value in keys.items()}
    records = {}
    for item in result.get('entries', []):
        name = reverse.get(item.get('key'))
        if name is None or name in records:
            raise ValueError('Unexpected or duplicate Testnet ledger entry.')
        data = xdr.LedgerEntryData.from_xdr(item['xdr'])
        if name == 'account':
            if not data.account or data.account.account_id != Keypair.from_public_key(quote.requester).xdr_account_id():
                raise ValueError('The Testnet account record does not match the requester.')
            records[name] = {'sequence': data.account.seq_num.sequence_number.int64, 'balance': data.account.balance.int64}
        else:
            expected_key = xdr.LedgerKey.from_xdr(item['key']).contract_data
            if not data.contract_data or data.contract_data.contract != expected_key.contract or data.contract_data.key != expected_key.key:
                raise ValueError('The Testnet contract record does not match the requested key.')
            value = data.contract_data.val
            if name.endswith('_instance'):
                instance = value.instance
                contract_name = name.removesuffix('_instance')
                if not instance or not instance.executable.wasm_hash or instance.executable.wasm_hash.hash.hex() != manifest['contracts'][contract_name]['wasm_sha256']:
                    raise ValueError('The deployed Testnet contract code differs from the reviewed manifest.')
                records[name] = {str(scval.to_native(entry.key)[0]): _native(scval.to_native(entry.val))
                                 for entry in (instance.storage.sc_map if instance.storage else [])}
            else:
                records[name] = _native(scval.to_native(value))
    if any(name + '_instance' not in records for name in PINNED_CONTRACTS):
        raise ValueError('A pinned Testnet contract is unavailable or needs restoration.')
    escrow = records['escrow_instance']
    expected_config = {'Registry': PINNED_CONTRACTS['registry'], 'Token': NATIVE_SAC,
                       'FeeTo': quote.treasury, 'FeeBps': quote.fee_bps}
    if any(escrow.get(k) != v for k, v in expected_config.items()):
        raise ValueError('Live escrow settlement configuration differs from this quote.')
    if records.get('validator_enabled') is not True:
        raise ValueError('The official provider is not an enabled registry validator.')
    return {'ledger': ledger, **records}


def _assert_bindings(quote: Quote, state: dict, *, allow_existing_deadline=False):
    agent = state.get('agent')
    validation = state.get('validation')
    job = state.get('job')
    identity = {'version': 1, 'meta_hash': quote.plan_sha256, 'end_hash': quote.source_sha256}
    def matches(record, expected):
        return isinstance(record, dict) and all(record.get(k) == v for k, v in expected.items())
    if agent and not matches(agent, {**identity, 'owner': quote.requester, 'active': True,
                                    'meta_uri': 'urn:veritas:plan:' + quote.plan_sha256}):
        raise ValueError('The onchain agent identity no longer matches the acknowledged audit scope.')
    if validation and (not agent or not matches(validation, {**identity, 'agent_id': quote.agent_id,
            'requester': quote.requester, 'validator': quote.provider}) or validation.get('state') not in [['Pending'], ['Complete']]):
        raise ValueError('The registry validation is not bound to this requester, provider and agent version.')
    expected_job = {'requester': quote.requester, 'provider': quote.provider, 'evaluator': quote.evaluator,
                    'amount': int(quote.amount_atomic), 'fee_bps': quote.fee_bps, 'fee_to': quote.treasury}
    if not allow_existing_deadline:
        expected_job['deadline'] = quote.deadline_ledger
    if job and (not validation or not matches(job, expected_job) or not matches(state.get('binding'),
            {**identity, 'agent_id': quote.agent_id, 'owner': quote.requester})):
        raise ValueError('The escrow job does not match this quote and registry snapshot.')
    if state.get('binding') and not job:
        raise ValueError('The escrow binding is incomplete; no payable checkout is prepared.')


def _progress(quote: Quote, state: dict) -> dict:
    job_state = (state.get('job') or {}).get('state', ['absent'])
    if not isinstance(job_state, list) or len(job_state) != 1 or job_state[0] not in {'absent', 'Created', 'Funded', 'Submitted', 'Disputed', 'Complete', 'Refunded'}:
        raise ValueError('Unknown escrow state; no payable checkout is prepared.')
    job_state = job_state[0]
    paid = job_state in {'Funded', 'Submitted', 'Disputed', 'Complete'}
    complete = [bool(state.get('agent')), bool(state.get('validation')), bool(state.get('job')), paid]
    index = next((i for i, done in enumerate(complete) if not done), None)
    status = 'ready'
    next_step = STEPS[index][0] if index is not None else None
    if job_state == 'Refunded':
        status, next_step = 'refunded', None
    elif paid:
        status = 'settled' if job_state == 'Complete' else 'funded'
    elif not state.get('account'):
        status = 'wallet_unfunded'
    elif state['ledger'] >= quote.deadline_ledger:
        status, next_step = 'deadline_expired', None
    return {'status': status, 'next_step': next_step,
        'steps': [{'id': id, 'label': label, 'state': 'complete' if complete[i] else
                   'blocked' if status in {'wallet_unfunded', 'deadline_expired', 'refunded'} else 'pending'}
                  for i, (id, label) in enumerate(STEPS)],
        'chain': {'ledger': state['ledger'], 'wallet_funded': bool(state.get('account')),
                  'registry_state': (state.get('validation') or {}).get('state', ['absent'])[0],
                  'escrow_state': job_state},
        'payment_confirmed': paid, 'limitations': LIMITS}


async def prepare_checkout(request: CheckoutRequest, settings, *, transport=None, now=None) -> dict:
    _key(settings)
    manifest = _deployment()
    if request.requester in {manifest['roles']['provider'], manifest['roles']['evaluator']}:
        raise ValueError('The requester wallet must be distinct from the official provider and evaluator.')
    planned = build_plan(request.engagement, settings)
    if planned['plan']['blockers']:
        raise ValueError(' '.join(planned['plan']['blockers']))
    if request.engagement.plan_sha256 != planned['plan_sha256']:
        raise ValueError('Review and acknowledge the current audit plan before checkout.')
    source, _, _ = normalize(request.engagement)
    if source.network != 'testnet':
        raise ValueError('Only a Testnet engagement can use this checkout.')
    if request.engagement.tier_id != 'quick' and not request.engagement.execution_consent:
        raise ValueError('A runtime tier requires explicit isolated execution consent before checkout.')
    timestamp = int(time.time()) if now is None else now
    source_hash, plan_hash = planned['plan']['source_sha256'], planned['plan_sha256']
    agent_id, request_id = _ids(request.requester, source_hash, plan_hash, request.engagement.tier_id, manifest)
    quote = Quote(requester=request.requester, tier_id=request.engagement.tier_id,
        source_sha256=source_hash, plan_sha256=plan_hash, agent_id=agent_id, request_id=request_id,
        amount_atomic=PRICES[request.engagement.tier_id], contracts=PINNED_CONTRACTS,
        provider=manifest['roles']['provider'], evaluator=manifest['roles']['evaluator'],
        treasury=manifest['roles']['treasury'], deadline_ledger=1, issued_at=timestamp, expires_at=timestamp + QUOTE_SECONDS)
    rpc = _RPC(transport)
    try:
        state = await _snapshot(rpc, quote, manifest)
    finally:
        await rpc.close()
    _assert_bindings(quote, state, allow_existing_deadline=True)
    quote.deadline_ledger = int(state['job']['deadline']) if state.get('job') else state['ledger'] + DEADLINE_LEDGERS
    _assert_bindings(quote, state)
    payload = quote.model_dump()
    return {'quote': payload, 'quote_signature': _signature(quote, settings),
            'quote_sha256': sha256(canonical_json(payload).encode()).hexdigest(), **_progress(quote, state)}


def _verify_quote(request: CheckoutStepRequest, settings, manifest: dict, timestamp: int):
    quote = request.quote
    if not hmac.compare_digest(_signature(quote, settings), request.quote_signature):
        raise ValueError('Checkout quote signature is invalid; request a fresh server quote.')
    if not quote.issued_at <= timestamp < quote.expires_at or quote.expires_at - quote.issued_at != QUOTE_SECONDS:
        raise ValueError('Checkout quote expired; refresh the quote and live chain state.')
    if not StrKey.is_valid_ed25519_public_key(quote.requester):
        raise ValueError('The quote requester is not a public G-address.')
    if (quote.contracts != PINNED_CONTRACTS or quote.amount_atomic != PRICES[quote.tier_id]
            or quote.provider != manifest['roles']['provider'] or quote.evaluator != manifest['roles']['evaluator']
            or quote.treasury != manifest['roles']['treasury']
            or (quote.agent_id, quote.request_id) != _ids(quote.requester, quote.source_sha256, quote.plan_sha256, quote.tier_id, manifest)):
        raise ValueError('Checkout quote no longer matches the fixed official Testnet offer.')


def _transaction(quote: Quote, step: StepID, sequence: int, expires_at: int):
    owner = scval.to_address(quote.requester)
    req = scval.to_bytes(bytes.fromhex(quote.request_id))
    agent = scval.to_bytes(bytes.fromhex(quote.agent_id))
    calls = {
        'register': ('registry', 'reg_agent', [owner, agent, scval.to_string('urn:veritas:plan:' + quote.plan_sha256),
            scval.to_bytes(bytes.fromhex(quote.plan_sha256)), scval.to_bytes(bytes.fromhex(quote.source_sha256)), scval.to_uint32(1)]),
        'request': ('registry', 'req_valid', [owner, req, agent, scval.to_address(quote.provider)]),
        'create': ('escrow', 'create', [owner, req, scval.to_address(quote.provider), scval.to_address(quote.evaluator),
            scval.to_int128(int(quote.amount_atomic)), scval.to_uint32(quote.deadline_ledger)]),
        'fund': ('escrow', 'fund', [owner, req]),
    }
    contract, method, args = calls[step]
    return (TransactionBuilder(Account(quote.requester, sequence), PASSPHRASE, base_fee=100)
            .append_invoke_contract_function_op(PINNED_CONTRACTS[contract], method, args)
            .add_time_bounds(0, expires_at).build())


async def prepare_checkout_step(request: CheckoutStepRequest, settings, *, transport=None, now=None) -> dict:
    manifest = _deployment()
    timestamp = int(time.time()) if now is None else now
    _verify_quote(request, settings, manifest, timestamp)
    quote = request.quote
    rpc = _RPC(transport)
    try:
        state = await _snapshot(rpc, quote, manifest)
        _assert_bindings(quote, state)
        progress = _progress(quote, state)
        if progress['status'] != 'ready' or progress['next_step'] != request.step:
            raise ValueError('This step is not currently payable; refresh the quote to read live progress.')
        expires_at = min(quote.expires_at, timestamp + 120)
        unsigned = _transaction(quote, request.step, state['account']['sequence'], expires_at)
        raw = await rpc.call('simulateTransaction', {'transaction': unsigned.to_xdr(), 'authMode': 'record'})
        simulation = SimulateTransactionResponse.model_validate(raw)
        if simulation.error or simulation.restore_preamble or not simulation.transaction_data or len(simulation.results or []) != 1:
            raise ValueError('Testnet simulation failed or requires restoration; no signable transaction is returned.')
        for auth in simulation.results[0].auth or []:
            credentials = xdr.SorobanAuthorizationEntry.from_xdr(auth).credentials
            if credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT:
                raise ValueError('This checkout requires additional authorization that the wallet flow does not support.')
        # Public SDK assembler. Supplying the response means no additional RPC call.
        server = SorobanServer(RPC_URL)
        try:
            prepared = server.prepare_transaction(unsigned, simulation)
        finally:
            server.close()
        if prepared.signatures or prepared.transaction.fee > MAX_FEE_ATOMIC or prepared.transaction.fee < 100:
            raise ValueError('Simulation returned an unsafe transaction fee or unexpected signatures.')
        return {**progress, 'step': request.step, 'unsigned_xdr': prepared.to_xdr(),
                'transaction_hash': prepared.hash_hex(), 'network_passphrase': PASSPHRASE,
                'signer': quote.requester, 'fee_atomic': str(prepared.transaction.fee), 'expires_at': expires_at,
                'simulation': {'status': 'succeeded', 'ledger': simulation.latest_ledger,
                    'authorization': 'source_account', 'is_payment_confirmation': False}}
    finally:
        await rpc.close()
