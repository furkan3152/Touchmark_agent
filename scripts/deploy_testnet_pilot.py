"""Disposable TESTNET deployment and credential lifecycle smoke test.

Uses a new Friendbot-funded identity, kept only in gitignored data/. Never mainnet.
Run from the repository root after building the three WASM files.
"""
from pathlib import Path
import hashlib
import json
import os
import time
import requests
from stellar_sdk import Asset, Keypair, Network, SorobanServer, scval
from stellar_sdk.contract import ContractClient

RPC = 'https://soroban-testnet.stellar.org'
NETWORK = Network.TESTNET_NETWORK_PASSPHRASE
OUTPUT = Path('deployments/testnet-pilot-2026-10-15.json')
KEY = Path('data/testnet-pilot-identity.json')


def main():
    KEY.parent.mkdir(exist_ok=True)
    if KEY.exists():
        keys = json.loads(KEY.read_text())
    else:
        keys = {role: Keypair.random().secret for role in ['admin', 'treasury']}
        fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f: json.dump(keys, f)
    admin, treasury = (Keypair.from_secret(keys[role]) for role in ['admin', 'treasury'])
    # Friendbot is explicitly a testnet faucet; no real currency or wallet is used.
    account = requests.get(f'https://horizon-testnet.stellar.org/accounts/{admin.public_key}', timeout=20)
    if account.status_code == 404:
        funded = requests.get('https://friendbot.stellar.org', params={'addr': admin.public_key}, timeout=30)
        funded.raise_for_status()
    else: account.raise_for_status()
    manifest = json.loads(OUTPUT.read_text()) if OUTPUT.exists() else {
        'network': 'testnet', 'rpc': RPC, 'purpose': 'Disposable pilot; not production governance',
        'admin': admin.public_key, 'treasury': treasury.public_key, 'contracts': {}, 'transactions': [],
        'asset': {'code': 'XLM', 'contract_id': Asset.native().contract_id(NETWORK)},
    }
    def save():
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(json.dumps(manifest, indent=2) + '\n')
    server = SorobanServer(RPC)
    kinds = [('registry', 'agent_veritas_registry.wasm', [scval.to_address(admin.public_key)]),
             ('escrow', 'agent_veritas_escrow.wasm', [scval.to_address(admin.public_key), scval.to_address(manifest['asset']['contract_id']), scval.to_address(treasury.public_key), scval.to_uint32(1500)]),
             ('credential', 'agent_veritas_credential.wasm', None)]
    for name, filename, constructor in kinds:
        if name in manifest['contracts']: continue
        if name == 'credential': constructor = [scval.to_address(manifest['contracts']['registry']['id'])]
        wasm = Path('target/wasm32v1-none/release', filename).read_bytes()
        digest = hashlib.sha256(wasm).hexdigest()
        wasm_hash = ContractClient.upload_contract_wasm(wasm, admin.public_key, admin, server, network_passphrase=NETWORK)
        assert wasm_hash.hex() == digest
        contract = ContractClient.create_contract(wasm_hash, admin.public_key, admin, server, constructor_args=constructor, network_passphrase=NETWORK)
        manifest['contracts'][name] = {'id': contract, 'wasm_sha256': digest, 'constructor_atomic': True}
        save(); print(name, contract, flush=True)
    def invoke(kind, fn, args, *, write=True):
        contract = ContractClient(manifest['contracts'][kind]['id'], RPC, NETWORK)
        tx = contract.invoke(fn, args, source=admin.public_key, signer=admin, submit_timeout=60)
        if not write: return tx.result()
        value = tx.sign_and_submit()
        response = tx.get_transaction_response
        manifest['transactions'].append({'function': fn, 'contract': kind, 'hash': tx.send_transaction_response.hash,
                                         'status': response.status.value, 'ledger': response.ledger})
        save(); print(fn, response.status.value, flush=True)
        return value
    if not manifest.get('credential_lifecycle_verified'):
        # Unique IDs on each retry; previous attempts remain explicit chain history.
        request = os.urandom(32); agent = os.urandom(32)
        manifest["in_progress_token_id"] = request.hex()
        manifest["in_progress_agent_id"] = agent.hex()
        save()
        report = hashlib.sha256(b'AgentVeritas synthetic pilot report; not a real agent certification').digest()
        address = scval.to_address(admin.public_key)
        invoke('registry', 'set_valid', [address, address, scval.to_bool(True)])
        invoke('registry', 'reg_agent', [address, scval.to_bytes(agent), scval.to_string('https://github.com/furkan3152/agentveritas-stellar'), scval.to_bytes(report), scval.to_bytes(report), scval.to_uint32(1)])
        invoke('registry', 'req_valid', [address, scval.to_bytes(request), scval.to_bytes(agent), address])
        invoke('registry', 'respond', [address, scval.to_bytes(request), scval.to_uint32(0), scval.to_string('https://github.com/furkan3152/agentveritas-stellar'), scval.to_bytes(report)])
        invoke('credential', 'issue', [scval.to_bytes(request), scval.to_uint64(int(time.time()) + 3600)])
        assert scval.from_address(invoke('credential', 'owner_of', [scval.to_bytes(request)], write=False)).address == admin.public_key
        assert scval.from_bool(invoke('credential', 'is_current', [scval.to_bytes(request)], write=False)) is True
        invoke('credential', 'revoke', [address, scval.to_bytes(request), scval.to_bytes(hashlib.sha256(b'End of synthetic pilot').digest())])
        assert scval.from_bool(invoke('credential', 'is_current', [scval.to_bytes(request)], write=False)) is False
        manifest.update(credential_lifecycle_verified=True, pilot_token_id=request.hex(), pilot_agent_id=agent.hex(),
                        pilot_report_sha256=report.hex(), note='Synthetic score=0 credential issued, ownership read back, then revoked. Not an audit endorsement.')
        save()
    print('Testnet pilot verified. Public evidence:', OUTPUT, flush=True)


if __name__ == '__main__':
    main()
