"""Start the actual ASGI app on loopback and verify a complete HTTP source-review flow."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    env = {**os.environ, 'STELLAR_NETWORK': 'offline', 'ENABLE_SANDBOX_RUNTIME': 'false',
           'STATELESS_STUDIO': 'true', 'ENABLE_PUBLIC_AI_REVIEW': 'false', 'LLM_API_KEY': ''}
    server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', trust_env=False, timeout=30) as client:
            for _ in range(50):
                if server.poll() is not None: raise RuntimeError('Local server exited during startup')
                try:
                    if client.get('/api/v1/health').status_code == 200: break
                except httpx.ConnectError: pass
                time.sleep(.1)
            else: raise RuntimeError('Local server failed to start')
            assert client.get('/').status_code == 200
            assert client.get('/ui/studio.js').status_code == 200
            assert client.get('/ui/checkout.js').status_code == 200
            assert client.get('/ui/vendor/freighter-api-6.0.1.min.js').status_code == 200
            assert client.get('/api/v1/jobs').status_code == 404
            source = {'name': 'Offline reader fixture', 'purpose': 'Summarize balances without signing or moving funds.',
                      'files': {'src/reader.py': (ROOT / 'examples/runtime-reader/main.py').read_text()}}
            plan = client.post('/api/v1/studio/discover', json=source).json()
            assert plan['entrypoints'][0]['id'] == 'src/reader.py:answer'
            response = client.post('/api/v1/studio/review', json=source)
            assert response.status_code == 200, response.text
            value = response.json()
            assert hashlib.sha256(value['report_json'].encode()).hexdigest() == value['report_sha256']
            assert value['report']['discovery']['source_sha256'] == plan['source_sha256']
            assert len(value['report']['assurance']['controls']) == 24
            assert client.post('/api/v1/studio/runtime', json={'source':source,'entrypoint':plan['entrypoints'][0]['id'],'execution_consent':True}).status_code == 401
            example = ROOT / 'examples/blueprint-reader'
            mapped_source = {**source, 'files': {p.relative_to(example).as_posix(): p.read_text() for p in example.rglob('*') if p.is_file()}}
            mapped = client.post('/api/v1/studio/discover', json=mapped_source).json()['blueprint']
            assert mapped['status'] == 'mapped'
            mapped_review = client.post('/api/v1/studio/review', json=mapped_source).json()
            assert mapped_review['report']['discovery']['blueprint']['plan_sha256'] == mapped['plan_sha256']
            assert hashlib.sha256(mapped_review['report_json'].encode()).hexdigest() == mapped_review['report_sha256']
            del mapped_source['files']['agent/tools.py']
            incomplete = client.post('/api/v1/studio/discover', json=mapped_source).json()
            assert incomplete['blueprint']['status'] == 'blocked' and incomplete['entrypoints'] == []
            for name, expected in [('matching-transfer', True), ('nested-recipient-change', False)]:
                auth_request = json.loads((ROOT / 'examples/stellar-authority' / f'{name}.json').read_text())
                inspected = client.post('/api/v1/studio/stellar/inspect-auth', json=auth_request)
                assert inspected.status_code == 200, inspected.text
                evidence = inspected.json()
                assert evidence['report']['matches_declared_policy'] is expected
                assert evidence['report']['signature_verified'] is False
                assert evidence['report']['transaction_executed'] is False
                assert hashlib.sha256(evidence['report_json'].encode()).hexdigest() == evidence['report_sha256']
            catalog = client.get('/api/v1/studio/catalog').json()
            assert len(catalog['modules']) == 8 and len(catalog['tiers']) == 3
            request = {'source': source, 'tier_id': 'quick', 'module_ids': ['intent', 'injection', 'privacy']}
            quote = client.post('/api/v1/studio/plan', json=request)
            assert quote.status_code == 200, quote.text
            request['plan_sha256'] = quote.json()['plan_sha256']
            audit = client.post('/api/v1/studio/audit', json=request)
            assert audit.status_code == 200, audit.text
            completed = audit.json()
            assert len(completed['report']['engagement']['module_results']) == 3
            delivery = client.post('/api/v1/studio/delivery', json={k: completed[k] for k in ['report_json', 'report_sha256']})
            assert delivery.status_code == 200, delivery.text
            assert delivery.json()['status'] == 'not_issued'
            assert 'ORIGIN UNVERIFIED' in delivery.json()['artifacts']['svg']
            package = client.post('/api/v1/studio/capsule/export', json=request)
            assert package.status_code == 200, package.text
            imported = client.post('/api/v1/studio/capsule/import', json={'document':json.dumps(package.json()['capsule'])})
            assert imported.status_code == 200, imported.text
            assert imported.json()['compiled']['plan_sha256'] == package.json()['compiled']['plan_sha256']
            stellar_info = client.get('/.well-known/stellar.toml')
            assert stellar_info.status_code == 200 and stellar_info.headers['access-control-allow-origin'] == '*'
            assert client.post('/api/v1/studio/ai/check').status_code == 401
            assert client.post('/api/v1/studio/checkout', json={'engagement': request,
                'requester': 'GD2M2PJ67RBTFEBPSRX4PAWTBAOGUR5OLZ5OVD6HECXFI5ERCRMB7ZBI'}).status_code == 401
            print(json.dumps({'localhost':f'http://127.0.0.1:{port}', 'source_review':'passed', 'discovery':'passed',
                'blueprint_map_and_missing_file_gate':'passed', 'stellar_authority_policy_and_nested_recipient':'passed',
                'report_integrity':'passed', 'runtime_auth':'passed', 'operator_surface':'hidden', 'controls':24, 'official_plan_audit_delivery':'passed', 'capsule_roundtrip':'passed', 'sep1_info':'passed', 'private_ai_gate':'passed'}))
    finally:
        server.terminate()
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired: server.kill(); server.wait()


if __name__ == '__main__': main()
