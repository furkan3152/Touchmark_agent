"""Brokered Python business workflows in disposable deny-all microVMs."""
import asyncio,json
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from .execution_contract import RUNTIME_ROOT,workflow_cases,preflight,profile_digest
from .execution_broker import ExecutionBroker,evaluate_workflow
from .discovery import source_digest,safe_source_path
from .capsule import digest
from ..reporting.generator import canonical_json

async def read_bounded(box,path,limit):
    async with box.fs.open(path,'rb') as stream:raw=await stream.read(limit+1)
    if len(raw)>limit:raise ValueError('Sandbox output exceeded its bound.')
    return raw

async def prepare_profile(box,provider):
    # No customer source or credential exists in the VM while setup has egress.
    # Hash-locked binary wheels only; no sdist setup.py/build hooks.
    await box.fs.write_text('/vercel/runtime.lock',(RUNTIME_ROOT/'python312-stellar.lock').read_text())
    command=await box.run_process('sh',['-c',
        'uv venv --python 3.12.12 /vercel/venv && uv pip install --python /vercel/venv/bin/python --require-hashes --only-binary :all: -r /vercel/runtime.lock'],
        env={'UV_PYTHON_INSTALL_DIR':'/vercel/python'},kill_after=150,capture_output=True)
    if command.returncode!=0:raise ValueError('Reviewed runtime profile could not be provisioned.')
    await box.update_network_policy(provider.NetworkPolicy.deny_all())
    result=await box.run_process('/vercel/venv/bin/python',['-I','-c',
        'import sys,importlib.metadata,json;print(json.dumps({"python":".".join(map(str,sys.version_info[:2])),"stellar-sdk":importlib.metadata.version("stellar-sdk"),"httpx":importlib.metadata.version("httpx")}))'],capture_output=True,kill_after=5)
    if result.returncode!=0:raise ValueError('Runtime preflight failed.')
    actual=json.loads(result.stdout)
    if actual!={'python':'3.12','stellar-sdk':'16.0.0','httpx':'0.28.1'}:raise ValueError('Runtime image failed its version contract.')
    return actual

async def run_workflows(request,settings,spec,entry,plan,capsule_plan,provider):
    from .capsule import capsule_from_context
    capsule=capsule_from_context(request.source,request.audit_context)
    failures=preflight(spec,capsule,settings)
    if failures:raise ValueError(' '.join(failures))
    if any(w.model_reply is None for w in spec.workflows) and not request.source.external_processing_consent:
        raise ValueError('Live model tool calls require external processing consent.')
    run_id=uuid4().hex;cases=workflow_cases(spec);observations=[]
    broker=ExecutionBroker(spec,settings,capsule)
    setup_policy=provider.NetworkPolicy.custom(allow={h:() for h in ('github.com','objects.githubusercontent.com','release-assets.githubusercontent.com','pypi.org','files.pythonhosted.org')})
    try:
        async with asyncio.timeout(180+115*len(cases)):
            async with provider.create_sandbox(name='av-'+run_id,persistent=False,
                execution_time_limit=180+115*len(cases),image=settings.sandbox_image,
                network_policy=setup_policy,resources=provider.SandboxResources(vcpus=1)) as box:
                prepared=await prepare_profile(box,provider)
                # Fund only after the actual executable/dependencies have passed preflight.
                await broker.prepare()
                await box.fs.mkdir('/vercel/project');await box.fs.mkdir('/vercel/ipc')
                await box.fs.write_text('/vercel/workflow_probe.py',(RUNTIME_ROOT/'workflow_probe.py').read_text())
                for path,content in request.source.files.items():
                    if not safe_source_path(path):raise ValueError('Unsafe source path')
                    await box.fs.mkdir(str(Path('/vercel/project')/Path(path).parent))
                    await box.fs.write_text('/vercel/project/'+path,content)
                for workflow in spec.workflows:
                    broker.begin(workflow)
                    # Each workflow starts with a fresh business target while
                    # retaining its own disk across the declared restart steps.
                    from decimal import Decimal
                    current = await asyncio.to_thread(broker.balance, broker.recipient.public_key)
                    broker.replacements['$target'] = str(Decimal(current) + Decimal('0.0000100'))
                    state='/vercel/state/'+workflow.id
                    await box.fs.mkdir(state)
                    environment=broker.resolve(spec.environment)
                    environment={k:v.replace('$state',state+'/state.db') for k,v in environment.items()}
                    config={'entrypoint':entry,'bindings':[x.model_dump() for x in spec.bindings],
                        'steps':broker.resolve([s.model_dump(mode='json') for s in workflow.steps]),
                        'environment':environment,'public_accounts':broker.public_accounts}
                    await box.fs.write_text('/vercel/workflow-input.json',json.dumps(config))
                    await box.fs.write_text('/vercel/ipc/request.json','null')
                    command=asyncio.create_task(box.run_process('sh',['-c',
                        'ulimit -f 2048; exec /vercel/venv/bin/python -I /vercel/workflow_probe.py > /vercel/workflow-output.json 2>/vercel/workflow-error.txt'],
                        kill_after=110,capture_output=False))
                    seen=set()
                    try:
                        while not command.done():
                            raw=await read_bounded(box,'/vercel/ipc/request.json',16000)
                            try:message=json.loads(raw)
                            except ValueError:message=None
                            if isinstance(message,dict) and message.get('id') not in seen:
                                response=await broker.handle(message)
                                seen.add(message['id'])
                                await box.fs.write_text('/vercel/ipc/response.json',json.dumps(response))
                            await asyncio.sleep(.15)
                        completed=await command
                        if completed.returncode!=0:raise ValueError('Workflow runner did not complete.')
                        raw=json.loads(await read_bounded(box,'/vercel/workflow-output.json',32000))
                        responses=raw['responses']
                        if not isinstance(responses,list) or [r.get('step') for r in responses]!=list(range(len(workflow.steps))):raise ValueError('Invalid workflow response envelope')
                    finally:
                        if not command.done():command.cancel()
                        await asyncio.gather(command,return_exceptions=True)
                    events=broker.events[broker.start:]
                    assertions=evaluate_workflow(workflow,responses,events)
                    outcomes=[]
                    for s,r in zip(workflow.steps,responses):
                        outcomes.append(r.get('error')==s.expected_error and (r.get('error') is not None or bool(r.get('response'))))
                    status='observed' if all(outcomes) else 'inconclusive'
                    if status=='observed' and any(x['result']=='not_matched' for x in assertions):status='needs_investigation'
                    observations.append({'id':workflow.id,'module':workflow.module,'status':status,
                        'response':responses[-1].get('response',''),'step_responses':[x.get('response','') for x in responses],
                        'step_outcomes':responses,'steps_observed':len(responses),'assertion':None,'assertions':assertions,
                        'external_event_range':[broker.start,len(broker.events)],'exit_code':0,'runtime_verified_control':False})
                sandbox_name=box.name
        report={'schema':'agentveritas.runtime.v1','run_id':run_id,'created_at':datetime.now(timezone.utc).isoformat(),
            'source_sha256':source_digest(request.source.files),'source_revision':request.source.source_revision,
            'entrypoint':entry,'provider':'vercel_sandbox','blueprint_plan_sha256':plan['blueprint'].get('plan_sha256'),
            'blueprint_status':plan['blueprint']['status'],'audit_tier':request.audit_tier,'selected_modules':request.modules,
            'case_count':len(cases),'issued_cases_sha256':digest(cases),'cases':cases,'ai_planning':'skipped_case_budget',
            'capsule_plan_sha256':capsule_plan['plan_sha256'],'capsule_sha256':capsule_plan['capsule_sha256'],'policy_sha256':capsule_plan['policy_sha256'],
            'sandbox_name':sandbox_name,'image':settings.sandbox_image,'execution':'completed','network':'deny-all','production_credentials':False,
            'observations':observations,'controls_verified':[], 'environment_contract':capsule.environment.model_dump(),
            'execution_profile':{'id':spec.profile,'sha256':profile_digest(),'preflight':prepared,'instrumentation':[x.model_dump() for x in spec.bindings]},
            'broker_evidence':{'events':broker.events,'sha256':digest(broker.events),'public_accounts':broker.public_accounts,'model_calls':broker.model_calls,'payment_reservations':broker.payments,'reserved_stroops':broker.spent},
            'external_processors':[f'{settings.llm_provider}:{settings.llm_model}','stellar_testnet'],
            'limits':['Declared client classes were replaced by broker adapters; native client implementation is not behaviorally certified.',
                'Host broker observes its own calls and Testnet receipts; VM responses and source-level call attribution remain untrusted.',
                'Sampled workflows and restarts do not prove complete security or coverage of concurrent execution.',
                'Faults and model fixtures are explicitly labeled; they are not live provider observations.',
                'Only operator-created Testnet accounts are available; no production key enters the VM.',
                'A matched business invariant is scoped evidence, never a universal safety guarantee.']}
        encoded=canonical_json(report);return {'report':report,'report_json':encoded,'report_sha256':sha256(encoded.encode()).hexdigest()}
    finally:broker.close()
