"""Composition of the persistent private Testnet order service.

Run alongside the operator API on a persistent host. The Vercel Studio is
stateless and advertises this service as unavailable until such a host exists.
"""
from __future__ import annotations

import asyncio
import logging
import os

from stellar_sdk import Keypair

from .audit_orders import AuditOrderStore, run_order_once, reconcile_pending_orders
from .audit_product import audit_engagement
from .order_publication import PrivateReportPublisher
from .order_settlement import TestnetOrderSettlement

logger = logging.getLogger('agentveritas.orders')


def order_capabilities(settings) -> dict:
    reason = ''
    if settings.stateless_studio or os.environ.get('VERCEL'):
        reason = 'Automatic orders require a persistent worker service; this Studio deployment is stateless.'
    elif not settings.enable_official_orders or not (settings.official_orders_storage_durable or settings.official_orders_local_pilot):
        reason = 'The persistent official order service has not been enabled.'
    elif settings.stellar_network != 'testnet' or not settings.enable_testnet_order_settlement:
        reason = 'Official automatic fulfillment is restricted to the configured Testnet pilot.'
    elif (len(settings.runtime_api_key) < 32 or len(settings.checkout_quote_signing_key) < 32
          or settings.runtime_api_key == settings.checkout_quote_signing_key):
        reason = 'Separate pilot access and server quote credentials are required.'
    elif not all((settings.official_provider_secret, settings.official_evaluator_secret,
                  settings.blob_read_write_token, settings.blob_store_id)):
        reason = 'Official signing identities and private report storage must be configured.'
    return {'available': not reason, 'automatic_settlement': not reason,
            'storage_mode': ('local_sqlite_pilot' if settings.official_orders_local_pilot else 'durable_sqlite') if not reason else 'unavailable',
            'reason': reason, 'network': 'testnet', 'report_visibility': 'private',
            'wallet_ownership_required': True, 'independent_operators': False}


class OfficialFulfillment:
    def __init__(self, settings):
        capability = order_capabilities(settings)
        if not capability['available']:
            raise ValueError(capability['reason'])
        self.settings = settings
        self.publisher = PrivateReportPublisher(settings)
        self.store = AuditOrderStore(settings.official_orders_database,
            deployment='local' if settings.official_orders_local_pilot else 'persistent',
            durable_storage=settings.official_orders_storage_durable)
        self.settlement = TestnetOrderSettlement(
            self.store, Keypair.from_secret(settings.official_provider_secret),
            Keypair.from_secret(settings.official_evaluator_secret),
            self.publisher.origin + '/reports', publication_verifier=self.publisher.verify)
        self.health = {'running': False, 'last_stage': None, 'errors': 0}
        self._last_reconcile = 0.0

    async def run_once(self):
        import time
        if time.monotonic() - self._last_reconcile >= 30:
            await reconcile_pending_orders(self.store, self.settings, limit=5)
            self._last_reconcile = time.monotonic()
        result = await run_order_once(self.store, 'official-local-worker', settings=self.settings,
                                     executor=audit_engagement, publisher=self.publisher.publish,
                                     chain_adapter=self.settlement)
        if result:
            self.health['last_stage'] = result['status']
        return result

    async def run(self):
        self.health['running'] = True
        try:
            while True:
                try:
                    result = await self.run_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.health['errors'] += 1
                    logger.warning('Official worker cycle failed; private details omitted.')
                    result = None
                await asyncio.sleep(1 if result else 5)
        finally:
            self.health['running'] = False
