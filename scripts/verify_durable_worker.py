#!/usr/bin/env python3
"""Explicit owned Preview canary: paid Deep audit and cross-VM persistence.

Only reviewed operator code runs in the parent VM with server credentials.
Customer code is executed by workflow_runtime in a different credential-free VM.
No ports are exposed, no tokens are returned, and an immutable claim prevents
accidental repeated paid runs. Drives remain for operator reconciliation.
"""
import argparse
import asyncio
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.app.config import Settings
from backend.app.reporting.generator import canonical_json
from backend.app.services.order_publication import PrivateReportPublisher
from scripts.verify_deployed_integrations import private_read, put_private


def operator_archive():
    files = [ROOT/'requirements.txt']
    for prefix in ('backend','scripts','deployments'):
        files.extend(p for p in (ROOT/prefix).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and 'tests' not in p.parts
                     and p.suffix in {'.py','.json','.lock'})
    files.append(ROOT/'research/workflow-trial-2026-10-15/invoicepilot.veritas')
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for path in sorted(set(files)):
            if path.is_symlink():
                raise ValueError('Symlink in operator source')
            archive.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
    return buffer.getvalue()


async def verify(run_id, attempt_id=None):
    if os.getenv('VERCEL_ENV')!='preview' or not os.getenv('VERCEL_OIDC_TOKEN'):
        raise ValueError('Preview build identity required')
    from vercel import sandbox as provider
    from vercel.blob import AsyncBlobClient
    settings = Settings(_env_file=None)
    publisher = PrivateReportPublisher(settings)
    origin, token = publisher.origin, settings.blob_read_write_token
    prefix = 'verification/'+(attempt_id or run_id)
    # Allowlist only operator service credentials, never forward the build env wholesale.
    names = ['VERCEL_OIDC_TOKEN','VERCEL_PROJECT_ID','VERCEL_TEAM_ID','BLOB_READ_WRITE_TOKEN',
        'BLOB_STORE_ID','LLM_PROVIDER','LLM_MODEL','LLM_BASE_URL','ALLOW_EXTERNAL_LLM_FOR_PRIVATE_AUDITS',
        'RUNTIME_API_KEY','CHECKOUT_QUOTE_SIGNING_KEY','AUDIT_TESTNET_FUNDING_SECRET',
        'OFFICIAL_PROVIDER_SECRET','OFFICIAL_EVALUATOR_SECRET','TRIAL_REQUESTER_SECRET']
    env = {n:os.environ[n] for n in names if os.environ.get(n)}
    required = ['OFFICIAL_PROVIDER_SECRET','OFFICIAL_EVALUATOR_SECRET','TRIAL_REQUESTER_SECRET',
                'CHECKOUT_QUOTE_SIGNING_KEY','RUNTIME_API_KEY','BLOB_READ_WRITE_TOKEN']
    if any(not env.get(n) for n in required):
        raise ValueError('Missing operator-only trial configuration')
    env.update(STELLAR_NETWORK='testnet', OFFICIAL_REPORT_BASE_URL=origin+'/reports',
        BLOB_STORE_ID=settings.blob_store_id, ALLOW_EXTERNAL_LLM_FOR_PRIVATE_AUDITS='true')
    archive = operator_archive()
    proof = {'schema':'veritas.durable-worker-canary/v1','run_id':run_id,'status':'incomplete',
             'commit':os.getenv('VERCEL_GIT_COMMIT_SHA'),'sessions':[]}
    async with AsyncBlobClient(token=token) as client:
        if await private_read(origin+'/'+prefix+'.claim.json', token) is not None:
            print('Run already claimed; no repeated expenditure.'); return
        await client.put(prefix+'.claim.json',canonical_json(proof).encode(),access='private',
            content_type='application/json',add_random_suffix=False,overwrite=False,multipart=False)
        try:
            drive, created = await provider.get_or_create_drive(name='av-'+run_id, max_size_bytes=1_073_741_824, region='iad1')
            if attempt_id and created:
                raise ValueError('Recovery requires the existing persistent drive')
            for restart in (False, True):
                async with provider.create_sandbox(name='av-'+run_id+('-restart' if restart else '-work'),
                    image=settings.sandbox_image, persistent=False, execution_time_limit=1000,
                    resources=provider.SandboxResources(vcpus=1), region='iad1',
                    mounts={'/vercel/order-data':drive}) as box:
                    async with box.fs.open('/vercel/operator.tar.gz','wb') as stream:
                        await stream.write(archive)
                    setup = await box.run_process('sh',['-c',
                        'mkdir -p /vercel/operator && tar -xzf /vercel/operator.tar.gz -C /vercel/operator && uv venv --python 3.12.12 /vercel/operator-venv && uv pip install --python /vercel/operator-venv/bin/python -r /vercel/operator/requirements.txt'],
                        env={'UV_PYTHON_INSTALL_DIR':'/vercel/python'}, capture_output=True, kill_after=180)
                    if setup.returncode != 0:
                        raise ValueError('Trusted operator dependency setup failed')
                    args = ['/vercel/operator/scripts/verify_durable_deep_order.py','--run-id',run_id]
                    if restart: args.append('--restart-only')
                    process = await box.run_process('/vercel/operator-venv/bin/python',args,
                        cwd='/vercel/operator',env=env,capture_output=True,kill_after=780)
                    # The script emits sanitized fixed-schema diagnostics, never SDK payloads.
                    diagnostics=[]
                    for line in process.stdout.splitlines()[-12:]:
                        try: item=json.loads(line)
                        except ValueError: continue
                        if isinstance(item,dict):
                            diagnostics.append({k:item[k] for k in ('status','error','frames','restart_only','step','hash') if k in item})
                    proof['sessions'].append({'restart':restart,'exit_code':process.returncode,'diagnostics':diagnostics})
                    for suffix in ('proof','audit'):
                        path=f'/vercel/order-data/{run_id}/{suffix}.json'
                        try:
                            async with box.fs.open(path,'rb') as stream: raw=await stream.read(500_001)
                        except (FileNotFoundError, provider.SandboxPathNotFoundError): continue
                        if len(raw)>500_000:raise ValueError('Trial evidence exceeds bound')
                        await put_private(client,prefix+'-'+suffix+('-restart' if restart else '')+'.json',raw,origin,token)
                    await put_private(client,prefix+('-restart-checkpoint.json' if restart else '-checkpoint.json'),canonical_json(proof).encode(),origin,token)
                    if process.returncode != 0:
                        raise ValueError('Trusted Deep worker did not finish')
            proof['status']='verified'
        except Exception as exc:
            import traceback
            proof.update(error=type(exc).__name__,frames=[{'file':Path(f.filename).name,'line':f.lineno}
                for f in traceback.extract_tb(exc.__traceback__)[-4:]])
        await put_private(client,prefix+'.json',canonical_json(proof).encode(),origin,token)
        print(json.dumps({'durable_deep_order':proof['status'],'run_id':run_id}))
        if proof['status']!='verified':raise RuntimeError('Incomplete durable worker proof')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run-id',required=True);parser.add_argument('--attempt-id');args=parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]{8,64}',args.run_id):parser.error('Invalid ID')
    if args.attempt_id and not re.fullmatch(r'[a-z0-9-]{8,64}',args.attempt_id):parser.error('Invalid attempt ID')
    try:asyncio.run(asyncio.wait_for(verify(args.run_id,args.attempt_id),timeout=1900))
    except Exception as exc:
        print(json.dumps({'status':'incomplete','error':type(exc).__name__}));raise SystemExit(1) from None
