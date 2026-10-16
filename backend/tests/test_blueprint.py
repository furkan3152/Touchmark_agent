"""Blueprint declarations cannot silently turn incomplete source into executable evidence."""
import asyncio
import base64
from hashlib import sha1
import json
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from backend.app.config import Settings
from backend.app.services.blueprint import compile_blueprint, parse_blueprint
from backend.app.services.discovery import discover_project
from backend.app.services.runtime_audit import RuntimeRequest, run_runtime, plan_cases, assess_observations
from backend.app.services.studio_intake import GitHubRequest, import_github_bundle

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / 'examples/blueprint-reader'


def source():
    return {p.relative_to(EXAMPLE).as_posix(): p.read_text() for p in EXAMPLE.rglob('*') if p.is_file()}


def mutate(files, fn):
    manifest = json.loads(files['veritas.json'])
    fn(manifest)
    return {**files, 'veritas.json': json.dumps(manifest)}


def test_declared_map_checks_arbitrary_parameter_name_and_resolves_relative_import():
    plan = discover_project(source())
    blueprint = plan['blueprint']
    assert blueprint['status'] == 'mapped'
    assert plan['entrypoints'][0]['id'] == 'agent/main.py:respond'
    assert any(e['to'] == 'agent/tools.py' and e['resolution'] == 'supplied_source' for e in blueprint['source_edges'])
    assert blueprint['runtime_verified'] is False
    assert all(c['status'] == 'planned' for c in blueprint['checks'])
    assert all(len(c['content_sha256']) == 64 for c in blueprint['components'])


def test_missing_and_unclassified_source_block_execution_without_fallback():
    files = source(); del files['agent/tools.py']
    plan = discover_project(files)
    assert plan['blueprint']['status'] == 'blocked'
    assert plan['entrypoints'] == []
    assert any('Missing declared file' in x for x in plan['blueprint']['blockers'])
    plan = compile_blueprint({**source(), 'hidden_behavior.py': 'def answer(prompt): return prompt'})
    assert plan['status'] == 'blocked'
    assert plan['unclassified_files'] == ['hidden_behavior.py']


@pytest.mark.parametrize('path', ['../main.py', '/main.py', './main.py', 'src//main.py', 'src/../main.py', '.env', 'secret.json', 'veritas.json', 'src/*.py'])
def test_manifest_rejects_noncanonical_or_sensitive_paths(path):
    files = mutate(source(), lambda m: m['components'][0].update(path=path))
    with pytest.raises(ValueError): parse_blueprint(files['veritas.json'])
    assert compile_blueprint(files)['status'] == 'blocked'


def test_duplicate_json_keys_and_component_references_are_rejected():
    with pytest.raises(ValueError): parse_blueprint('{"protocol":"a","protocol":"b"}')
    for fn in [lambda m: m['components'].append(m['components'][0]),
               lambda m: m['boundaries'][0].update(target='nonexistent'),
               lambda m: m['entrypoint'].update(component='policy')]:
        assert compile_blueprint(mutate(source(), fn))['status'] == 'blocked'


def test_decorated_or_wrong_signature_cannot_masquerade_as_supported_callable():
    for code in ['@decorator\ndef respond(message): return message', 'def respond(a,b): return a', 'def other(message): return message']:
        assert compile_blueprint({**source(), 'agent/main.py': code})['status'] == 'blocked'


def test_plan_fingerprint_binds_source_intent_and_boundaries():
    original = compile_blueprint(source())['plan_sha256']
    assert compile_blueprint(dict(reversed(list(source().items()))))['plan_sha256'] == original
    assert compile_blueprint({**source(), 'agent/instructions.md': 'Changed instructions'})['plan_sha256'] != original
    changed = mutate(source(), lambda m: m['boundaries'][0].update(approval_required=True))
    assert compile_blueprint(changed)['plan_sha256'] != original


def test_ambiguous_discovery_does_not_invent_entrypoint_or_trust_boundaries():
    plan = discover_project({'a.py': 'def first(prompt): return prompt\ndef second(message): return message'})
    assert plan['blueprint_draft']['manifest'] is None
    draft = discover_project({'a.py': 'def first(prompt): return prompt'})['blueprint_draft']
    assert draft['status'] == 'draft_requires_review'
    assert draft['manifest']['boundaries'] == []


def runtime_request(files=None, **extra):
    return RuntimeRequest(source={'name':'Fixture', 'purpose':'Read offline fixtures without moving funds.', 'files':files or source()},
                          entrypoint='agent/main.py:respond', execution_consent=True, **extra)


def test_runtime_rejects_missing_and_stale_plans_before_provider():
    with pytest.raises(ValueError, match='plan changed'):
        asyncio.run(run_runtime(runtime_request(), Settings(enable_sandbox_runtime=True)))
    plan = compile_blueprint(source())
    changed = {**source(), 'agent/instructions.md':'Changed instructions'}
    with pytest.raises(ValueError, match='plan changed'):
        asyncio.run(run_runtime(runtime_request(changed, plan_sha256=plan['plan_sha256']), Settings(enable_sandbox_runtime=True)))
    files = source(); del files['agent/tools.py']
    with pytest.raises(ValueError, match='Blueprint is blocked'):
        asyncio.run(run_runtime(runtime_request(files), Settings(enable_sandbox_runtime=True)))


def test_declared_scenarios_are_bounded_text_assertions_not_control_passes():
    request = runtime_request()
    cases, status = asyncio.run(plan_cases(request, Settings(), discover_project(source())))
    assert len(cases) == 8 and status == 'not_requested'
    raw = {'observations':[{'id':case['id'], 'exit_code':0, 'agent_output':{'response':'Fixture balance: 12.50 XLM. I cannot sign.'}} for case in cases]}
    results = assess_observations(raw, cases)
    assert results[-1]['assertion']['result'] == 'matched'
    assert not any(r['runtime_verified_control'] for r in results)
    raw['observations'][-1]['agent_output']['response'] = 'I signed it.'
    assert assess_observations(raw, cases)[-1]['assertion']['result'] == 'not_matched'


def test_github_manifest_selects_exact_deep_source_before_unrelated_files(monkeypatch):
    files = {**source(), **{f'a{i}.py':'x = 1' for i in range(20)}}
    blobs = {sha1(f'blob {len(v.encode())}\0'.encode() + v.encode()).hexdigest():(k,v.encode()) for k,v in files.items()}
    # Identical blobs may have different paths; build the tree from the files.
    entries = [{'type':'blob','mode':'100644','path':k,'size':len(v.encode()),'sha':sha1(f'blob {len(v.encode())}\0'.encode()+v.encode()).hexdigest()} for k,v in files.items()]
    fetched = []
    async def respond(self, request, **kwargs):
        url = str(request.url)
        if url.endswith('/commits/HEAD'): data = {'sha':'a'*40}
        elif '/git/trees/' in url: data = {'tree':entries}
        else:
            name, raw = blobs[url.rsplit('/',1)[1]]; fetched.append(name)
            data = {'encoding':'base64','content':base64.b64encode(raw).decode()}
        return httpx.Response(200, json=data, request=request)
    monkeypatch.setattr(httpx.AsyncClient, 'send', respond)
    value = asyncio.run(import_github_bundle(GitHubRequest(repository='https://github.com/example/reader')))
    assert value['bundle']['files'] == source()
    assert fetched[0] == 'veritas.json'
    assert value['import_scope']['declared_scope_complete'] is True
    assert value['import_scope']['complete'] is False
    assert value['discovery']['blueprint']['status'] == 'mapped'


def test_cli_checks_without_executing_and_refuses_overwrite_or_symlinks(tmp_path):
    sentinel = tmp_path / 'executed'
    (tmp_path/'main.py').write_text(f'open({str(sentinel)!r}, "w").write("bad")\ndef answer(prompt): return prompt')
    command = [sys.executable, str(ROOT/'scripts/veritas.py')]
    assert subprocess.run([*command, 'init', str(tmp_path)], capture_output=True).returncode == 0
    manifest = (tmp_path/'veritas.json').read_text()
    assert subprocess.run([*command, 'init', str(tmp_path)], capture_output=True).returncode == 1
    assert (tmp_path/'veritas.json').read_text() == manifest
    assert subprocess.run([*command, 'check', str(tmp_path)], capture_output=True).returncode == 0
    assert not sentinel.exists()
    (tmp_path/'main.py').unlink(); (tmp_path/'main.py').symlink_to('/etc/passwd')
    result = subprocess.run([*command, 'check', str(tmp_path)], capture_output=True)
    assert result.returncode == 1 and b'Symlinks' in result.stderr
