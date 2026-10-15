#!/usr/bin/env python3
"""Small, disclosed synthetic challenge set. Never executes submitted source.

This measures specific source signals, not general agent recognition, exploit
success, production safety or independently measured market performance.
Known misses stay in the output rather than being removed to improve the score.
"""
import argparse
import asyncio
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.config import Settings
from backend.app.services.discovery import discover_project
from backend.app.services.studio import ReviewRequest, review_source


def blueprint(code):
    return {'main.py': code, 'veritas.json': json.dumps({
        'protocol':'veritas.blueprint/v1', 'name':'Challenge fixture',
        'purpose':'Evaluate the submitted source input boundary.',
        'components':[{'id':'entry','role':'entrypoint','path':'main.py'}],
        'entrypoint':{'component':'entry','symbol':'respond','adapter':'python_text'}})}


CASES = [
    ('direct_eval', {'main.py':'def answer(prompt):\n return eval(prompt)'}, 'security-path-untrusted-to-command', True),
    ('declared_renamed_input', blueprint('def respond(text):\n return eval(text)'), 'security-path-untrusted-to-command', True),
    ('cross_file_eval', {'main.py':'from worker import run\ndef answer(prompt):\n return run(prompt)', 'worker.py':'def run(value):\n return eval(value)'}, 'security-path-untrusted-to-command', True),
    ('dynamic_dispatch_eval', {'main.py':"def answer(prompt):\n return getattr(__import__('builtins'), 'ev' + 'al')(prompt)"}, 'security-path-untrusted-to-command', True),
    ('safe_formatter', {'main.py':'def answer(prompt):\n return prompt.upper()'}, 'security-path-untrusted-to-command', False),
    ('quoted_attack_text', {'main.py':'def answer(prompt):\n return "eval(prompt) is prohibited"'}, 'security-path-untrusted-to-command', False),
    ('secret_logging', {'main.py':'import os\ndef answer(prompt):\n api_key=os.getenv("MODEL_API_KEY")\n print(api_key)\n return "done"'}, 'security-path-secret-to-exfiltration', True),
    ('ordinary_env_logging', {'main.py':'import os\ndef answer(prompt):\n color=os.getenv("COLOR")\n print(color)\n return "done"'}, 'security-path-secret-to-exfiltration', False),
    ('comment_auth_spoof', {'lib.rs':'pub fn set(env: Env, value: u32) { env.storage().instance().set(&0, &value); } // require_auth is deliberately absent'}, 'stellar-native-auditor-soroban-auth-missing', True),
    ('mixed_auth_functions', {'lib.rs':'pub fn set_owner(env: Env, owner: Address) { owner.require_auth(); env.storage().instance().set(&0, &owner); }\npub fn set_value(env: Env, value: u32) { env.storage().instance().set(&1, &value); }'}, 'stellar-native-auditor-soroban-auth-missing', True),
]


async def evaluate():
    rows = []
    settings = Settings(_env_file=None, stellar_network='offline', llm_provider='', llm_api_key='', enable_public_ai_review=False)
    for name, files, target, expected in CASES:
        result = await review_source(ReviewRequest(name=name, purpose='Inspect a disclosed synthetic challenge without executing it.', files=files), settings)
        ids = [finding['id'] for finding in result['report']['findings']]
        # Auditor IDs may use a stable dimension prefix rather than the class name.
        observed = target in ids or any(i.endswith('-soroban-auth-missing') for i in ids) and target.endswith('-soroban-auth-missing')
        rows.append({'id':name, 'expected_source_signal':expected, 'finding_id':target,
                     'observed':observed, 'outcome':'matched' if observed == expected else 'missed' if expected else 'unexpected_signal',
                     'report_sha256':result['report_sha256']})
    identity = []
    for name,files in [('plain_formatter', {'formatter.py':'def answer(prompt): return prompt.upper()'}),
                       ('framework_import_only', {'main.py':'import langgraph'}),
                       ('declared_echo', blueprint('def respond(text): return text'))]:
        value=discover_project(files)
        identity.append({'id':name, 'identity':value['agent_identity'], 'entrypoint_candidates':len(value['entrypoints'])})
    paths = ['backend/app/services/discovery.py', 'backend/app/services/blueprint.py', 'backend/app/swarm/agentic_paths.py', 'backend/app/swarm/stellar_native.py']
    return {'schema':'agentveritas.synthetic-evaluation.v1', 'dataset':'disclosed-counterexamples-v1',
        'fixture_sha256':sha256(json.dumps(CASES,sort_keys=True).encode()).hexdigest(),
        'analyzer_files_sha256':{p:sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
        'source_checks':rows, 'agent_identity_checks':identity,
        'summary':{'cases':len(rows), 'matched':sum(r['outcome']=='matched' for r in rows),
                   'missed':sum(r['outcome']=='missed' for r in rows), 'unexpected_signals':sum(r['outcome']=='unexpected_signal' for r in rows)},
        'runtime_executed':False, 'llm_used':False,
        'limitations':['Small developer-visible synthetic set, not a blind independent benchmark.',
                      'Expected labels concern specific static source signals, not proven vulnerabilities.',
                      'No real-world precision, recall, agent identification accuracy or safety rate can be inferred.',
                      'Cross-file and dynamic-dispatch cases are intentionally retained to expose gaps.']}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args=parser.parse_args()
    report=asyncio.run(evaluate())
    encoded=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.output: args.output.write_text(encoded)
    else: print(encoded)
