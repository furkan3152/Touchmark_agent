import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import Settings
from backend.app.services.discovery import discover_project, safe_source_path, source_digest
from backend.app.services.runtime_audit import RuntimeRequest, CASES, run_runtime, assess_observations

SOURCE = {'src/treasury.py': 'import os\nfrom langgraph.graph import StateGraph\nKEY = os.getenv("MODEL_API_KEY")\nasync def answer(prompt):\n    return prompt\n'}


def test_discovery_uses_ast_and_manifests_not_agent_filename():
    plan = discover_project(SOURCE)
    assert plan['frameworks'] == ['LangGraph']
    assert plan['entrypoints'][0]['id'] == 'src/treasury.py:answer'
    assert plan['required_environment_names'] == ['MODEL_API_KEY']
    assert plan['runtime_executed'] is False
    assert discover_project({'agent.py': '# this filename is not evidence'})['entrypoints'] == []
    assert source_digest(SOURCE) != source_digest({**SOURCE, 'readme.md': 'modified'})


@pytest.mark.parametrize('path', ['../x.py', '/x.py', '.env', 'src/.secrets.json', 'node_modules/a.js', 'secrets.json', 'src\\x.py'])
def test_discovery_excludes_sensitive_or_escaping_paths(path):
    assert not safe_source_path(path)


def test_discovery_never_imports_source(tmp_path):
    sentinel = tmp_path / 'executed'
    discover_project({'main.py': f'open({str(sentinel)!r}, "w").write("bad")\ndef answer(prompt):\n return prompt\n'})
    assert not sentinel.exists()


def request(**overrides):
    return RuntimeRequest(source={'name': 'Sample', 'purpose': 'Read balances without moving funds', 'files': SOURCE},
                          entrypoint='src/treasury.py:answer', execution_consent=True, **overrides)


def test_runtime_denies_disabled_or_unrecognized_entry_without_provider():
    with pytest.raises(ValueError, match='not enabled'):
        asyncio.run(run_runtime(request(), Settings(enable_sandbox_runtime=False)))
    value = request(); value.entrypoint = 'src/treasury.py:os.system'
    with pytest.raises(ValueError, match='discovered'):
        asyncio.run(run_runtime(value, Settings(enable_sandbox_runtime=True)))
    value = request(); value.execution_consent = False
    with pytest.raises(ValueError, match='Authorize'):
        asyncio.run(run_runtime(value, Settings(enable_sandbox_runtime=True)))


def test_runtime_auth_is_separate_and_fail_closed(monkeypatch):
    monkeypatch.setattr(api.settings, 'runtime_api_key', 'r' * 40)
    with TestClient(api.app) as client:
        assert client.post('/api/v1/studio/runtime', json=request().model_dump()).status_code == 401
        assert client.post('/api/v1/studio/runtime', json=request().model_dump(), headers={'Authorization': 'Bearer wrong'}).status_code == 401


def test_isolation_cleanup_and_observations_are_not_safety_passes():
    calls, writes = [], {}
    class Box:
        name = 'test-sandbox'
        @property
        def fs(self): return self
        async def mkdir(self, path): pass
        async def write_text(self, path, content): writes[path] = content
        def open(self, path, mode):
            assert path == '/vercel/result.json' and mode == 'rb'
            return self
        async def read(self, size):
            assert size == 100001
            return json.dumps({'observations': [
                {'id': c['id'], 'exit_code': 0, 'agent_output': {'response': 'I refuse AV_OVERRIDE_ACCEPTED'}} for c in CASES]}).encode()
        async def run_process(self, command, args, **kwargs):
            calls.append((command, args, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps({'observations': [
                {'id': c['id'], 'exit_code': 0, 'agent_output': {'response': 'I refuse AV_OVERRIDE_ACCEPTED'}} for c in CASES]}))
        async def __aenter__(self): return self
        async def __aexit__(self, *args): calls.append('cleanup')
    class Provider:
        NetworkPolicy = SimpleNamespace(deny_all=lambda: 'deny-all')
        SandboxResources = lambda **kw: kw
        @staticmethod
        def create_sandbox(**kwargs):
            assert kwargs['persistent'] is False and kwargs['network_policy'] == 'deny-all'
            assert 'env' not in kwargs and 'source' not in kwargs
            return Box()
    value = asyncio.run(run_runtime(request(), Settings(enable_sandbox_runtime=True), provider=Provider))
    assert calls[-1] == 'cleanup'
    assert '/vercel/project/src/treasury.py' in writes
    assert value['report']['controls_verified'] == []
    assert value['report']['observations'][1]['status'] == 'needs_investigation'
    assert hashlib.sha256(value['report_json'].encode()).hexdigest() == value['report_sha256']


def test_missing_dependency_is_blocked_not_passed():
    raw = {'observations': [{'id': c['id'], 'exit_code': 0, 'agent_output': {'blocked': 'missing_dependency', 'dependency': 'langgraph'}} for c in CASES]}
    assert all(x['status'] == 'blocked' for x in assess_observations(raw))
    raw['observations'][0]['id'] = 'forged'
    with pytest.raises(ValueError): assess_observations(raw)
