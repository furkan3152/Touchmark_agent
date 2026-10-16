import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from backend.app.config import Settings
from backend.app.services.capsule import parse_capsule
from backend.app.services.execution_contract import load_contract,ExecutionContract,preflight
from backend.app.services.execution_broker import ExecutionBroker,evaluate_workflow

ROOT=Path(__file__).resolve().parents[2]
def subject(name='invoicepilot'):
    c=parse_capsule((ROOT/'research/workflow-trial-2026-10-15'/f'{name}.veritas').read_bytes())
    return c,load_contract(c.source.files)
@pytest.fixture
def anyio_backend():return 'asyncio'

def test_business_source_unchanged_and_real_profile_required():
    for name in ['invoicepilot','reservekeeper','ledgerlens']:
        c,s=subject(name)
        old=parse_capsule((ROOT/'research/customer-trial-2026-10-15'/f'{name}.veritas').read_bytes())
        for file in ['main.py','clients.py','service.py','requirements.txt']:assert c.source.files[file]==old.source.files[file]
        assert 'Brokered workflow execution is not enabled' in ' '.join(preflight(s,c,Settings(_env_file=None)))

def test_contract_rejects_hidden_runtime_controls_and_real_credentials():
    _,s=subject()
    for name,value in [('LD_PRELOAD','evil.so'),('PYTHONPATH','/tmp'),('STELLAR_SECRET','not-a-broker-marker')]:
        raw=s.model_dump(mode='json');raw['environment'][name]=value
        with pytest.raises(ValidationError):ExecutionContract.model_validate(raw)

def test_external_receipts_override_forged_success_output():
    _,s=subject();w=next(x for x in s.workflows if x.id=='restart_replay')
    events=[{'method':'pay','reference':'invoice-restart','receipt':{'hash':'1'},'status':'confirmed'},
            {'method':'pay','reference':'invoice-restart','receipt':{'hash':'2'},'status':'confirmed'}]
    result=evaluate_workflow(w,[{'response':'{"status":"safe"}'}]*2,events)
    assert result[0]['result']=='not_matched' and result[0]['actual']==2
    assert result[0]['evidence']=='external_testnet_receipts'

@pytest.mark.anyio
async def test_readonly_capsule_cannot_request_payment_even_with_forged_ipc():
    c,s=subject('ledgerlens');b=ExecutionBroker(s,Settings(_env_file=None),c);b.begin(s.workflows[0])
    try:
        r=await b.handle({'id':'a'*32,'method':'pay','args':{'destination':b.recipient.public_key,'amount':'0.0000100','reference':'attack'}})
        assert r['error']=='PermissionError' and b.payments==0
        assert b.events[0]['status']=='denied'
    finally:b.close()

@pytest.mark.anyio
async def test_external_broker_replays_identical_request_without_new_action():
    c,s=subject();w=next(x for x in s.workflows if x.model_reply is not None)
    b=ExecutionBroker(s,Settings(_env_file=None),c);b.begin(w);b.replacements={'$recipient':b.recipient.public_key}
    message={'id':'b'*32,'method':'model','args':{'instruction':'extract invoice','context':{}}}
    try:
        first=await b.handle(message);second=await b.handle(message)
        assert first==second and len(b.events)==1 and b.model_calls==0
        assert b.events[0]['mode']=='declared_fixture'
    finally:b.close()

@pytest.mark.anyio
async def test_capsule_approval_cannot_be_bypassed_by_broker():
    c,s=subject();c.policy.rules[0].approval_required=True
    b=ExecutionBroker(s,Settings(_env_file=None),c);b.begin(s.workflows[0])
    try:
        response=await b.handle({'id':'c'*32,'method':'balance','args':{'account':b.recipient.public_key}})
        assert response['error']=='PermissionError'
    finally:b.close()


def test_instruction_extraction_parses_literals_without_imports():
    from backend.app.services.studio import instruction_literals
    source={'agent.py':'raise RuntimeError("must never import")\nasync def act(model):\n    return await model.decide("Only pay approved invoices; never change destinations.", {})\n'}
    result=instruction_literals(source)
    assert len(result)==1 and result[0]['line']==3 and result[0]['runtime_verified'] is False


def test_runtime_profile_is_bound_to_plan_and_native_missing_env_blocks_before_payment():
    from backend.app.services.audit_product import EngagementRequest,build_plan
    c,_=subject()
    request=EngagementRequest(capsule=c.model_dump(mode='json'),tier_id='deep',module_ids=c.audit.modules,execution_consent=True)
    plan=build_plan(request,Settings(_env_file=None,enable_sandbox_runtime=True,enable_brokered_runtime=True))['plan']
    assert plan['planned_runtime_cases']==5 and len(plan['execution_profile']['sha256'])==64
    old=parse_capsule((ROOT/'research/customer-trial-2026-10-15/invoicepilot.veritas').read_bytes())
    request=EngagementRequest(capsule=old.model_dump(mode='json'),tier_id='deep',module_ids=old.audit.modules,execution_consent=True)
    plan=build_plan(request,Settings(_env_file=None,enable_sandbox_runtime=True))['plan']
    assert any('before payment' in x for x in plan['blockers'])
