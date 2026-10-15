#!/usr/bin/env python3
"""Separate Quick source-review order for the frozen customer-shaped InvoicePilot.

Reuses the ordinary paid order verification driver with isolated journals.
Deep execution remains inconclusive; this order never claims otherwise.
"""
import asyncio
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import verify_official_order_testnet as driver
from backend.app.services.capsule import parse_capsule,seal_capsule
from backend.app.services.audit_product import EngagementRequest,build_plan
BASE=ROOT/'research/customer-trial-2026-10-15'
driver.PRIVATE=ROOT/'data/customer-trial-order-state.json'
driver.DATABASE=ROOT/'data/customer-trial-order.db'
driver.EVIDENCE=BASE/'results/official-order.json'

def customer_request(settings):
    capsule=parse_capsule((BASE/'invoicepilot.veritas').read_bytes()).model_dump(mode='json')
    capsule['audit']['tier']='quick'
    capsule=seal_capsule(capsule)
    request=EngagementRequest(capsule=capsule.model_dump(mode='json'),tier_id='quick',module_ids=capsule.audit.modules)
    request.plan_sha256=build_plan(request,settings)['plan_sha256']
    return request

driver.fixture=customer_request
original_save=driver.save_evidence

def save_evidence(value):
    value['schema']='veritas.customer-trial-order/v1'
    value['fixture']='research/customer-trial-2026-10-15/invoicepilot.veritas (separately sealed Quick tier)'
    value['limitations']=[s.replace('This owned fixture received the quick tier static audit.', 'The frozen InvoicePilot source received a separately scoped Quick static audit.') for s in value['limitations']]
    value['limitations'].append('The separate Deep trial observed 0 successful agent responses. This credential does not certify behavioral safety.') if not any('separate Deep trial' in s for s in value['limitations']) else None
    original_save(value)
driver.save_evidence=save_evidence
if __name__=='__main__':
    try:
        raise SystemExit(asyncio.run(driver.main()))
    except Exception as exc:
        print(json.dumps({'status':'blocked','error_type':type(exc).__name__}))
        raise SystemExit(2) from None
