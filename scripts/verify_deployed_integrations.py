#!/usr/bin/env python3
"""Explicit one-off Preview build canary; never runs at application startup.

Uses the build's own Vercel OIDC identity. No credentials leave that environment.
The private proof records actual AI and Python Sandbox results, not browser QA.
Invoke only with --run-id. An immutable run claim prevents repeated expenditure,
including after an interrupted build; use a new run ID for an authorized retry.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


async def private_read(uri: str, token: str) -> bytes | None:
    """Only callers construct the fixed private URI; never follow a redirect."""
    async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
        async with client.stream('GET', uri, params={'cache': '0'}, headers={
            'Authorization': f'Bearer {token}', 'Accept': 'application/json', 'Accept-Encoding': 'identity',
        }) as response:
            if response.status_code == 404:
                return None
            if (response.status_code != 200
                    or response.headers.get('content-type', '').split(';', 1)[0].strip() != 'application/json'
                    or response.headers.get('content-encoding', 'identity') != 'identity'):
                raise RuntimeError('Private canary proof could not be read.')
            data = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=8192):
                if len(data) + len(chunk) > 500_000:
                    raise RuntimeError('Private canary proof exceeds the bounded read limit.')
                data.extend(chunk)
            return bytes(data)


async def put_private(client, path: str, encoded: bytes, origin: str, token: str) -> None:
    uri = f'{origin}/{path}'
    try:
        uploaded = await asyncio.wait_for(client.put(path, encoded, access='private',
            content_type='application/json', add_random_suffix=False, overwrite=False, multipart=False), timeout=30)
    except Exception:
        # A network timeout may have happened after the write; reconcile exact bytes.
        if await private_read(uri, token) != encoded:
            raise RuntimeError('Private canary proof publication failed.') from None
        return
    if uploaded.url != uri or uploaded.pathname != path:
        raise RuntimeError('Private canary upload returned an unexpected location.')
    if await private_read(uri, token) != encoded:
        raise RuntimeError('Private canary proof readback did not match.')


async def verify(run_id):
    from vercel.blob import AsyncBlobClient
    from backend.app.config import Settings
    from backend.app.services.audit_product import EngagementRequest, audit_engagement, build_plan
    from backend.app.services.capsule import parse_capsule
    from backend.app.services.studio import ReviewRequest, review_source
    from backend.app.swarm.llm import LlmClient
    from backend.app.reporting.generator import canonical_json
    from backend.app.services.order_publication import PrivateReportPublisher

    if not isinstance(run_id, str) or not re.fullmatch(r'[a-z0-9-]{8,80}', run_id):
        raise RuntimeError('A bounded, explicit canary run ID is required.')
    if os.getenv('VERCEL') != '1' or os.getenv('VERCEL_ENV') != 'preview' or not os.getenv('VERCEL_OIDC_TOKEN'):
        raise RuntimeError('This canary requires an authorized Vercel Preview build identity.')
    settings = Settings(_env_file=None, llm_max_output_tokens=600, enable_ofac_screening=False)
    if not settings.blob_read_write_token:
        raise RuntimeError('Connect the private verification store before running a build canary.')
    # Binds the static Blob credential to the explicitly configured private store
    # and rejects SDK endpoint overrides before the credential is used.
    origin = PrivateReportPublisher(settings).origin
    path = f'verification/{run_id}.json'
    async with AsyncBlobClient(token=settings.blob_read_write_token) as client:
        existing = await private_read(f'{origin}/{path}', settings.blob_read_write_token)
        if existing is not None:
            saved = json.loads(existing)
            if saved.get('schema') != 'veritas.deployed-integrations/v1' or saved.get('run_id') != run_id:
                raise RuntimeError('Existing private canary proof does not match this run.')
            print('Integration canary already has a persisted proof; no calls repeated.')
            return
        # Claim before model/VM work. Incomplete/interrupted runs need a NEW,
        # explicitly authorized run ID; deployment retries never spend twice.
        claim_path = f'verification/{run_id}.claim.json'
        claim_uri = f'{origin}/{claim_path}'
        claim = canonical_json({'schema': 'veritas.integration-canary-claim/v1',
            'run_id': run_id, 'created_at': datetime.now(timezone.utc).isoformat(),
            'commit': os.getenv('VERCEL_GIT_COMMIT_SHA', '')}).encode()
        try:
            claimed = await asyncio.wait_for(client.put(claim_path, claim, access='private',
                content_type='application/json', add_random_suffix=False, overwrite=False, multipart=False), timeout=30)
        except Exception:
            prior = await private_read(claim_uri, settings.blob_read_write_token)
            if prior is not None:
                prior_claim = json.loads(prior)
                if prior_claim.get('schema') == 'veritas.integration-canary-claim/v1' and prior_claim.get('run_id') == run_id:
                    print('Integration canary is already claimed; no paid calls repeated. Inspect its proof or use a new authorized run ID.')
                    return
            raise RuntimeError('Integration canary claim could not be established.') from None
        if claimed.url != claim_uri or claimed.pathname != claim_path or await private_read(claim_uri, settings.blob_read_write_token) != claim:
            raise RuntimeError('Integration canary claim readback did not match.')
        proof = {'schema': 'veritas.deployed-integrations/v1', 'run_id': run_id,
                 'created_at': datetime.now(timezone.utc).isoformat(),
                 'execution_environment': 'vercel_preview_build',
                 'commit': os.getenv('VERCEL_GIT_COMMIT_SHA', ''),
                 'deployment_url': os.getenv('VERCEL_URL', ''),
                 'browser_verified': False, 'payment_flow_verified': False,
                 'fixture_only': True, 'secrets_exported': False}
        try:
            proof['ai_connection'] = await LlmClient(settings).check_connection()
            if proof['ai_connection']['connection_verified']:
                source = ReviewRequest(name='Owned integration canary', network='testnet',
                    purpose='Return a fixed public balance and never sign transactions.',
                    files={'agent.py': 'def answer(prompt):\n    return "Public balance: 12.50 XLM"\n'},
                    ai_assistance=True, external_processing_consent=True)
                result = await review_source(source, settings)
                proof['ai_review'] = result['report']['ai_review']
                proof['ai_report_sha256'] = result['report_sha256']
        except Exception as exc:
            proof['ai_error'] = type(exc).__name__
        try:
            capsule = parse_capsule((ROOT / 'examples/balance-reader.veritas').read_text())
            request = EngagementRequest(capsule=capsule.model_dump(mode='json'),
                tier_id=capsule.audit.tier, module_ids=capsule.audit.modules, execution_consent=True)
            request.plan_sha256 = build_plan(request, settings)['plan_sha256']
            result = await audit_engagement(request, settings)
            runtime = result['report']['engagement']['runtime']
            proof['runtime'] = {'report_sha256': runtime['report_sha256'], **runtime['report']}
            proof['audit_report_sha256'] = result['report_sha256']
        except Exception as exc:
            proof['runtime_error'] = type(exc).__name__
        ai_ok = proof.get('ai_connection', {}).get('connection_verified') is True
        review_ok = proof.get('ai_review', {}).get('status') in {'completed', 'no_observations'}
        runtime = proof.get('runtime', {})
        observations = runtime.get('observations', [])
        runtime_ok = (runtime.get('execution') == 'completed' and runtime.get('network') == 'deny-all'
                      and runtime.get('production_credentials') is False and len(observations) == 12
                      and len(runtime.get('cases', [])) == 12
                      and all(item.get('status') == 'observed' for item in observations))
        proof['runtime_successful_responses'] = sum(item.get('status') == 'observed' for item in observations)
        proof['status'] = 'verified' if ai_ok and review_ok and runtime_ok else 'incomplete'
        encoded = canonical_json(proof).encode()
        await put_private(client, path, encoded, origin, settings.blob_read_write_token)
        # No URLs with tokens, model prompts or credentials in build logs.
        print(json.dumps({'integration_canary': proof['status'], 'run_id': run_id,
                          'ai_connection': ai_ok, 'ai_review': review_ok, 'runtime': runtime_ok,
                          'proof_sha256': sha256(encoded).hexdigest()}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]{8,80}', args.run_id):
        parser.error('Use a bounded, unique lowercase run ID.')
    try:
        asyncio.run(asyncio.wait_for(verify(args.run_id), timeout=240))
    except Exception:
        # Remote exceptions can carry request details. Never emit them in build logs.
        print(json.dumps({'integration_canary': 'incomplete', 'run_id': args.run_id,
                          'reason': 'Canary execution or private proof persistence failed; no credentials were logged.'}))
        raise SystemExit(1) from None
