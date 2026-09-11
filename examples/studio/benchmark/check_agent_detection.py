"""Opt-in characterization: misses deliberately fail, rather than become xfails.

Run this file explicitly with pytest. It is not in the default backend suite.
Never import or execute the submitted agent sources.
"""
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((Path(__file__).with_name('manifest.json')).read_text())['cases']


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['id'])
def test_agent_risk_is_identified_at_public_review_boundary(case, tmp_path, monkeypatch):
    # Configure before importing the API: no operator data or real .env involved.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('EVENT_DATABASE', str(tmp_path / 'events.db'))
    monkeypatch.setenv('STELLAR_NETWORK', 'offline')

    def no_external_network(*args, **kwargs):
        raise AssertionError('Static review attempted an external HTTP call')

    monkeypatch.setattr(httpx.AsyncClient, 'send', no_external_network)
    from backend.app import api

    bundle = json.loads((ROOT / 'examples/studio/benchmark' / case['bundle']).read_text())
    with TestClient(api.app) as client:
        response = client.post('/api/v1/studio/review', json=bundle)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['scope']['runtime_executed'] is False
    assert result['scope']['onchain_confirmed'] is False
    assert result['scope']['external_processors'] == []
    assert len(result['report']['auditors']) == 7
    raw = result['report_json'].encode()
    assert hashlib.sha256(raw).hexdigest() == result['report_sha256']
    assert json.loads(raw) == result['report']
    (tmp_path / 'report.json').write_bytes(raw)

    matches = [f for f in result['report']['findings'] if f['id'] == case['target_finding']]
    detected = bool(matches)
    summary = {
        'case': case['id'], 'expected_risk': case['expected_risk'],
        'detected': detected, 'target_grades': [f['evidence_grade'] for f in matches],
        'decision': result['decision'], 'priority_count': len(result['priority_finding_ids']),
        'findings_count': len(result['report']['findings']),
        'target_evidence': [f['evidence'] for f in matches],
        'finding_ids': [f['id'] for f in result['report']['findings']],
        'report_sha256': result['report_sha256'], 'report_path': str(tmp_path / 'report.json'),
    }
    print('\nBENCHMARK_RESULT ' + json.dumps(summary, ensure_ascii=False))
    assert detected is case['expected_risk'], case['rationale']
