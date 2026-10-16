from hashlib import sha256

import pytest
from stellar_sdk import Keypair, StrKey

from backend.app.config import Settings
from backend.app.services.audit_product import EngagementRequest, audit_engagement, build_plan, catalogue
from backend.app.services.studio import ReviewRequest
from backend.app.services.report_delivery import DeliveryRequest, CredentialReference, deliver_report, verify_credential
from backend.app.reporting.generator import canonical_json


@pytest.fixture
def anyio_backend():
    return "asyncio"


def source():
    return ReviewRequest(name='Bounded reader', purpose='Return a fixed public balance without executing user instructions.',
                         files={'agent.py': 'def answer(prompt):\n    return "Public balance: 12.50"\n'})


def settings():
    return Settings(_env_file=None, enable_sandbox_runtime=True, runtime_api_key='x' * 40,
                    enable_ofac_screening=False, stellar_network='offline')


@pytest.mark.anyio
async def test_plan_commitment_binds_scope_source_and_ai_consent():
    request = EngagementRequest(source=source())
    commitment = build_plan(request, settings())['plan_sha256']
    for change in [dict(module_ids=['intent']), dict(tier_id='deep'),
                   dict(source=source().model_copy(update={'purpose': 'A different security purpose entirely.'})),
                   dict(ai_assistance=True, external_processing_consent=True)]:
        revised = request.model_copy(update=change)
        assert build_plan(revised, settings())['plan_sha256'] != commitment
    with pytest.raises(ValueError, match='acknowledge'):
        await audit_engagement(request, settings())


@pytest.mark.anyio
async def test_quick_report_runs_baseline_without_claiming_runtime_or_mint():
    request = EngagementRequest(source=source(), module_ids=['intent', 'tools'])
    request.plan_sha256 = build_plan(request, settings())['plan_sha256']
    result = await audit_engagement(request, settings())
    assert sha256(result['report_json'].encode()).hexdigest() == result['report_sha256']
    engagement = result['report']['engagement']
    assert len(engagement['module_results']) == 2
    assert len(result['report']['auditors']) == 7
    assert not result['scope']['runtime_executed']
    assert engagement['delivery']['status'] == 'not_issued'
    assert all(not m['security_verified'] for m in engagement['module_results'])


@pytest.mark.anyio
async def test_deep_requires_consent_and_calls_selected_runtime():
    request = EngagementRequest(source=source(), tier_id='deep', module_ids=['injection'])
    request.plan_sha256 = build_plan(request, settings())['plan_sha256']
    with pytest.raises(ValueError, match='consent'):
        await audit_engagement(request, settings())
    request.execution_consent = True
    calls = []
    async def runner(req, _settings):
        calls.append(req)
        return {'report': {'observations': [{'id': 'probe', 'module': 'injection', 'status': 'observed'}],
                           'limits': ['Fixture provider; not a real sandbox.']},
                'report_json': '{}', 'report_sha256': sha256(b'{}').hexdigest()}
    result = await audit_engagement(request, settings(), runtime_runner=runner)
    assert calls[0].audit_tier == 'deep'
    assert calls[0].modules == ['injection']
    assert result['scope']['runtime_executed']
    assert result['report']['engagement']['module_results'][0]['runtime'] == 'sampled'


def report_request(name='Reader'):
    report = {'agent': {'name': name}, 'findings': [{'id': 'a', 'title': '<script>alert(1)</script>',
                'evidence': '</pre><img src=x onerror=alert(1)>', 'severity': 'high'}],
              'review_scope': {'analysis': 'Source only', 'limits': ['No execution']}}
    encoded = canonical_json(report)
    return DeliveryRequest(report_json=encoded, report_sha256=sha256(encoded.encode()).hexdigest())


@pytest.mark.anyio
async def test_download_is_unissued_and_escapes_untrusted_source():
    result = await deliver_report(report_request('<img src=x onerror=alert(1)>'))
    assert result['status'] == 'not_issued'
    assert '<script>' not in result['artifacts']['html']
    assert '<img src=x' not in result['artifacts']['svg']
    assert '&lt;script&gt;' in result['artifacts']['html']
    assert result['artifacts']['metadata']['credential'] is None


@pytest.mark.anyio
async def test_report_tampering_and_duplicate_keys_rejected():
    request = report_request()
    with pytest.raises(ValueError, match='commitment'):
        await deliver_report(request.model_copy(update={'report_json': request.report_json + ' '}))
    duplicate = '{"agent":{},"agent":{},"findings":[]}'
    with pytest.raises(ValueError, match='Duplicate'):
        await deliver_report(DeliveryRequest(report_json=duplicate, report_sha256=sha256(duplicate.encode()).hexdigest()))


@pytest.mark.anyio
async def test_credential_verification_requires_known_contract_owner_hash_current(monkeypatch):
    from backend.app.services import report_delivery
    owner = Keypair.random().public_key
    contract = StrKey.encode_contract(bytes([9]) * 32)
    ref = CredentialReference(contract_id=contract, token_id='1' * 64, owner=owner)
    digest = '2' * 64
    monkeypatch.setattr(report_delivery, '_official_contracts', lambda: {contract: owner})
    def reader(_ref, _source):
        return {'owner': owner, 'report_hash': bytes.fromhex(digest)}, True, 12345
    assert (await verify_credential(ref, digest, reader=reader))['status'] == 'current'
    assert (await verify_credential(ref, '3' * 64, reader=reader))['status'] == 'invalid'
    assert (await verify_credential(ref.model_copy(update={'owner': Keypair.random().public_key}), digest, reader=reader))['status'] == 'invalid'
    def expired(_ref, _source):
        return {'owner': owner, 'report_hash': bytes.fromhex(digest)}, False, 12345
    assert (await verify_credential(ref, digest, reader=expired))['status'] == 'invalid'
    monkeypatch.setattr(report_delivery, '_official_contracts', lambda: {})
    assert (await verify_credential(ref, digest, reader=reader))['status'] == 'invalid'


def test_catalogue_prices_are_not_live_payment_claims():
    catalog = catalogue(settings())
    assert len(catalog['modules']) == 8
    assert [t['budgets']['runtime_cases'] for t in catalog['tiers']] == [0, 12, 24]
    assert not catalog['checkout_enabled']
    assert all(not t['price']['live'] for t in catalog['tiers'])


def test_deep_chain_only_selection_is_blocked_before_ai_or_runtime():
    request = EngagementRequest(source=source(), tier_id='deep', module_ids=['stellar'])
    assert any('no Python behavior pack' in b for b in build_plan(request, settings())['plan']['blockers'])


def test_plan_binds_runtime_image():
    request = EngagementRequest(source=source(), tier_id='deep')
    config = settings()
    before = build_plan(request, config)['plan_sha256']
    config.sandbox_image += '-changed'
    assert before != build_plan(request, config)['plan_sha256']


@pytest.mark.anyio
async def test_runtime_operator_cases_match_plan_digest_regardless_of_selection_order():
    from backend.app.services.runtime_audit import RuntimeRequest, plan_cases
    from backend.app.services.discovery import discover_project
    req = EngagementRequest(source=source(), tier_id='standard', module_ids=['resilience', 'privacy', 'intent', 'tools', 'injection'])
    planned = build_plan(req, settings())['plan']
    runtime = RuntimeRequest(source=req.source, entrypoint=planned['entrypoint']['id'],
        audit_tier=req.tier_id, modules=sorted(req.module_ids))
    cases, _ = await plan_cases(runtime, settings(), discover_project(req.source.files))
    assert sha256(canonical_json(cases).encode()).hexdigest() == planned['runtime_cases_sha256']


@pytest.mark.anyio
async def test_blocked_dependency_does_not_claim_sampled_agent():
    request = EngagementRequest(source=source(), tier_id='deep', module_ids=['intent'], execution_consent=True)
    request.plan_sha256 = build_plan(request, settings())['plan_sha256']
    async def blocked(_req, _settings):
        return {'report': {'observations': [{'id': 'baseline', 'module': 'intent', 'status': 'blocked'}], 'limits': []}}
    result = await audit_engagement(request, settings(), runtime_runner=blocked)
    assert result['scope']['runtime_attempted'] is True
    assert result['scope']['runtime_executed'] is False
    assert result['report']['engagement']['module_results'][0]['runtime'] == 'inconclusive'


@pytest.mark.anyio
@pytest.mark.parametrize('field,value', [('review_decision', None), ('review_decision', 'APPROVED_SAFE'),
    ('review_decision', []), ('ai_review', {'status': None}),
    ('ai_review', {'observations': None}), ('engagement', {'runtime': {'report': {'observations': None}}})])
async def test_malformed_or_forged_report_is_rejected(field, value):
    import json
    request = report_request()
    body = json.loads(request.report_json)
    body[field] = value
    encoded = canonical_json(body)
    with pytest.raises(ValueError):
        await deliver_report(DeliveryRequest(report_json=encoded, report_sha256=sha256(encoded.encode()).hexdigest()))


def test_product_http_auth_and_bounds(monkeypatch):
    from fastapi.testclient import TestClient
    import backend.app.api as api
    monkeypatch.setattr(api, 'settings', settings())
    # Isolate this test's process-wide guard counters from other HTTP suites.
    monkeypatch.setattr(api.app, 'middleware_stack', None)
    client = TestClient(api.app)
    body = {'source': source().model_dump(), 'tier_id': 'deep'}
    assert client.post('/api/v1/studio/audit', json=body).status_code == 401
    body['tier_id'] = 'quick'
    body['source']['ai_assistance'] = True
    body['source']['external_processing_consent'] = True
    assert client.post('/api/v1/studio/audit', json=body).status_code == 401
    for path in ['plan', 'audit', 'capsule/import', 'capsule/export', 'delivery']:
        limit = 1_048_576 if path == 'delivery' else 131072
        response = client.post('/api/v1/studio/' + path, content=b'x' * (limit + 1))
        assert response.status_code == 413
        assert response.headers['cache-control'] == 'no-store'


@pytest.mark.anyio
async def test_workflow_report_preserves_external_findings_and_escapes_tool_journal():
    import json
    request = report_request()
    report = json.loads(request.report_json)
    report['engagement'] = {'runtime': {'report': {
        'observations': [{'id':'restart', 'status':'needs_investigation',
            'assertions':[{'kind':'payment_count','result':'not_matched','actual':2,'evidence':'external_broker'}]}],
        'broker_evidence': {'events':[{'workflow':'restart','method':'pay','mode':'live_testnet',
            'status':'confirmed','receipt':{'hash':'<script>untrusted</script>'}}]}}}}
    encoded = canonical_json(report)
    result = await deliver_report(DeliveryRequest(report_json=encoded,report_sha256=sha256(encoded.encode()).hexdigest()))
    html = result['artifacts']['html']
    assert 'Business invariants' in html and 'External tool journal' in html
    assert 'not_matched' in html and 'external_broker' in html and 'live_testnet' in html
    assert '<script>' not in html and '&lt;script&gt;untrusted' in html
    assert 'Native transport code is outside' in html


@pytest.mark.anyio
@pytest.mark.parametrize('body', [
    {'observations':[{'assertions':None}]},
    {'observations':[], 'broker_evidence':{'events':None}},
    {'observations':[], 'broker_evidence':{'events':[{'receipt':'not a receipt'}]}},
])
async def test_malformed_nested_runtime_report_is_rejected(body):
    import json
    report = json.loads(report_request().report_json)
    report['engagement'] = {'runtime':{'report':body}}
    encoded = canonical_json(report)
    with pytest.raises(ValueError, match='Invalid'):
        await deliver_report(DeliveryRequest(report_json=encoded,report_sha256=sha256(encoded.encode()).hexdigest()))
