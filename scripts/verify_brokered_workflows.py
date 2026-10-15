#!/usr/bin/env python3
"""Explicit Preview build verification of normal product workflow audits."""
import argparse,asyncio,json,os,re,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.verify_deployed_integrations import private_read,put_private
async def verify(run_id):
 from vercel.blob import AsyncBlobClient
 from backend.app.config import Settings
 from backend.app.services.order_publication import PrivateReportPublisher
 from backend.app.reporting.generator import canonical_json
 from backend.app.services.capsule import parse_capsule
 from backend.app.services.audit_product import EngagementRequest,build_plan,audit_engagement
 if os.getenv('VERCEL_ENV')!='preview' or not os.getenv('VERCEL_OIDC_TOKEN'):raise ValueError('Preview build identity required')
 settings=Settings(_env_file=None,enable_sandbox_runtime=True,enable_brokered_runtime=True,llm_max_output_tokens=1800,enable_ofac_screening=False)
 origin=PrivateReportPublisher(settings).origin;token=settings.blob_read_write_token;prefix='verification/'+run_id
 proof={'schema':'veritas.brokered-trial/v1','run_id':run_id,'created_at':datetime.now(timezone.utc).isoformat(),'commit':os.getenv('VERCEL_GIT_COMMIT_SHA'),'audits':{}}
 async with AsyncBlobClient(token=token) as client:
  if await private_read(origin+'/'+prefix+'.claim.json',token) is not None:
   print('Run already claimed; no repeated expenditure.');return
  await client.put(prefix+'.claim.json',canonical_json({'run_id':run_id,'commit':proof['commit']}).encode(),access='private',content_type='application/json',add_random_suffix=False,overwrite=False,multipart=False)
  for name in ('reservekeeper','invoicepilot','ledgerlens'):
   stage='plan'
   try:
    cap=parse_capsule((ROOT/'research/workflow-trial-2026-10-15'/f'{name}.veritas').read_bytes())
    req=EngagementRequest(capsule=cap.model_dump(mode='json'),tier_id='deep',module_ids=cap.audit.modules,execution_consent=True,ai_assistance=True,external_processing_consent=True)
    plan=build_plan(req,settings);req.plan_sha256=plan['plan_sha256']
    proof['audits'][name]={'plan_sha256':req.plan_sha256,'blockers':plan['plan']['blockers']}
    stage='audit'
    result=await audit_engagement(req,settings)
    stage='persist'
    await put_private(client,prefix+'-'+name+'.json',canonical_json(result).encode(),origin,token)
    rt=result['report']['engagement']['runtime']['report']
    proof['audits'][name].update(report_sha256=result['report_sha256'],runtime={k:rt[k] for k in ['case_count','observations','execution_profile','broker_evidence']})
    print(json.dumps({'agent':name,'status':'recorded','cases':rt['case_count']}),flush=True)
   except Exception as exc:
    import traceback
    frames=[{'file':Path(x.filename).name,'line':x.lineno} for x in traceback.extract_tb(exc.__traceback__)[-4:]]
    proof['audits'].setdefault(name,{}).update(error=type(exc).__name__,stage=stage,frames=frames)
    # Only local fixed validation messages; never remote payloads or credentials.
    if type(exc) is ValueError and len(str(exc))<300:proof['audits'][name]['reason']=str(exc)
    print(json.dumps({'agent':name,'status':'incomplete','stage':stage,'error':type(exc).__name__}),flush=True)
   await put_private(client,prefix+'-'+name+'-checkpoint.json',canonical_json(proof['audits'][name]).encode(),origin,token)
  await put_private(client,prefix+'.json',canonical_json(proof).encode(),origin,token)
  print('Brokered trial proof saved.')
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--run-id',required=True);args=parser.parse_args()
 if not re.fullmatch(r'[a-z0-9-]{8,80}',args.run_id):parser.error('Invalid ID')
 try:asyncio.run(asyncio.wait_for(verify(args.run_id),timeout=1800))
 except Exception as exc:
  print(json.dumps({'status':'incomplete','error':type(exc).__name__}));raise SystemExit(1) from None
