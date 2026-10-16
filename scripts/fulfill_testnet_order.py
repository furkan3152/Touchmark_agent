#!/usr/bin/env python3
"""Run one private, persistent official Testnet audit order.

The customer first creates an order, signs the four checkout transactions, and
activates the funded order. This process executes only the existing acknowledged
audit plan, publishes the private canonical report, and reconciles delivery.
It cannot sign customer checkout transactions and has no Mainnet option.

Enable ENABLE_OFFICIAL_ORDERS and ENABLE_TESTNET_ORDER_SETTLEMENT explicitly.
Configure a private Blob store, CHECKOUT_QUOTE_SIGNING_KEY and the provider /
evaluator secrets in the process environment. For the existing local disposable
pilot only, --identity-file data/testnet-audit-delivery-identities.json may supply
those two identities instead. No key or order capability is written to output.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from stellar_sdk import Keypair
from backend.app.config import Settings
from backend.app.services.audit_orders import AuditOrderStore, run_order_once
from backend.app.services.audit_product import audit_engagement
from backend.app.services.order_publication import PrivateReportPublisher
from backend.app.services.order_settlement import TestnetOrderSettlement


def build_adapters(settings, store):
    if settings.stellar_network != 'testnet' or not settings.enable_official_orders or not settings.enable_testnet_order_settlement:
        raise ValueError('Explicit official-order and settlement flags on Stellar Testnet are required.')
    try:
        provider = Keypair.from_secret(settings.official_provider_secret)
        evaluator = Keypair.from_secret(settings.official_evaluator_secret)
    except Exception:
        raise ValueError('The official Testnet provider and evaluator secrets are not configured.') from None
    publisher = PrivateReportPublisher(settings)
    expected_base = publisher.origin + '/reports'
    if settings.official_report_base_url.rstrip('/') != expected_base:
        raise ValueError('The immutable report base URL must match the configured private Blob store.')
    adapter = TestnetOrderSettlement(store, provider, evaluator, expected_base,
                                    publication_verifier=publisher.verify)
    return publisher, adapter


def _pilot_keys(path, settings):
    info = path.stat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 4096:
        raise ValueError('Pilot identity file must be a small owner-only regular file.')
    identities = json.loads(path.read_text())
    settings.official_provider_secret = identities['provider']
    settings.official_evaluator_secret = identities['evaluator']


async def main(args):
    settings = Settings()
    if args.database:
        settings.official_orders_database = str(args.database.resolve())
    if args.identity_file:
        _pilot_keys(args.identity_file.absolute(), settings)
    store = AuditOrderStore(settings.official_orders_database,
                            durable_storage=settings.official_orders_storage_durable)
    publisher, adapter = build_adapters(settings, store)
    result = await run_order_once(store, args.worker_id, settings=settings, executor=audit_engagement,
                                  publisher=publisher.publish, chain_adapter=adapter, lease_seconds=180)
    evidence = {'schema': 'veritas.official-order-worker-run/v1', 'network': 'testnet',
                'status': result['status'] if result else 'idle',
                'order_id': result['order_id'] if result else None,
                'report_sha256': result.get('report_sha256') if result else None,
                'failure_code': result.get('failure_code') if result else None,
                'delivery': result.get('delivery') if result else None}
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.receipt.with_suffix('.tmp')
        temporary.write_text(json.dumps(evidence, indent=2) + '\n')
        os.replace(temporary, args.receipt)
    print(json.dumps(evidence), flush=True)
    return 0 if evidence['status'] in {'delivered', 'idle'} else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, help='Existing private official-order SQLite database.')
    parser.add_argument('--identity-file', type=Path, help='Owner-only ignored disposable Testnet identity file.')
    parser.add_argument('--worker-id', default='local-official-testnet-worker')
    parser.add_argument('--receipt', type=Path, help='Write sanitized delivery evidence; no source, report bytes, capabilities or keys.')
    try:
        raise SystemExit(asyncio.run(main(parser.parse_args())))
    except Exception:
        # SDK/provider exceptions can contain request bodies or sensitive input.
        print(json.dumps({'status': 'blocked', 'network': 'testnet',
                          'reason': 'Official order worker configuration or private storage could not be verified.'}), flush=True)
        raise SystemExit(2)
