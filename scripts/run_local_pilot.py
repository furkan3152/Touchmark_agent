#!/usr/bin/env python3
"""Run the local official Testnet pilot using existing ignored development keys."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Use a port between 1024 and 65535.')
    os.chdir(ROOT)
    if os.getenv('VERCEL'):
        parser.error('This launcher is for local loopback testing, not Vercel Functions.')
    # Key schema is validated below; values are never printed or accepted from browsers.
    identities = json.loads((ROOT / 'data/testnet-audit-delivery-identities.json').read_text())
    from stellar_sdk import Keypair
    from backend.app.services.testnet_checkout import _deployment
    roles = _deployment()['roles']
    resolved = {}
    for value in identities.values():
        if isinstance(value, str) and value.startswith('S'):
            try:
                key = Keypair.from_secret(value)
            except Exception:
                continue
            for role in ('provider', 'evaluator'):
                if key.public_key == roles[role]:
                    resolved[role] = value
    if set(resolved) != {'provider', 'evaluator'}:
        parser.error('The local identity file does not contain the pinned Testnet service identities.')
    os.environ.update({
        'STATELESS_STUDIO': 'false', 'STELLAR_NETWORK': 'testnet', 'ALLOW_MAINNET': 'false',
        'ENABLE_OFFICIAL_ORDERS': 'true', 'OFFICIAL_ORDERS_STORAGE_DURABLE': 'false',
        'OFFICIAL_ORDERS_LOCAL_PILOT': 'true',
        'ENABLE_TESTNET_ORDER_SETTLEMENT': 'true',
        'OFFICIAL_ORDERS_DATABASE': str(ROOT / 'data/local-official-orders.db'),
        'OFFICIAL_PROVIDER_SECRET': resolved['provider'], 'OFFICIAL_EVALUATOR_SECRET': resolved['evaluator'],
        'RUNTIME_API_KEY': (ROOT / 'data/runtime-pilot-key.txt').read_text().strip(),
        'CHECKOUT_QUOTE_SIGNING_KEY': (ROOT / 'data/checkout-quote-signing.key').read_text().strip(),
        'BLOB_READ_WRITE_TOKEN': (ROOT / 'data/blob-read-write.token').read_text().strip(),
        'BLOB_STORE_ID': 'store_EVlQaNdD2T85Necg', 'ENABLE_OFAC_SCREENING': 'false',
    })
    print(f'Official Testnet pilot: http://127.0.0.1:{args.port}. Keep this process and its private data directory available.')
    print('Pilot access key is in data/runtime-pilot-key.txt. Wallet seeds never belong in the browser.')
    import uvicorn
    uvicorn.run('backend.app.api:app', host='127.0.0.1', port=args.port)


if __name__ == '__main__':
    main()
