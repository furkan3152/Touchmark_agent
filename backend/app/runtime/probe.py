"""Runs ONLY in a disposable microVM. The host never imports the submitted code.

This is a behavioral sampler, not a tamper-proof trace collector: agent code can
inspect/modify its VM. Evidence is untrusted output and never authorizes money.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile

CHILD = r'''
import asyncio, contextlib, importlib, importlib.util, importlib.metadata, inspect, json, os, resource, sys, types
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
request = json.loads(sys.argv[1])
sys.path.insert(0, '/vercel/project')
sys.path.insert(0, os.path.dirname('/vercel/project/' + request['file']))
try:
    environment = request.get('environment')
    if environment:
        requested_version = environment['python_version']
        current_version = '.'.join(str(x) for x in sys.version_info[:2])
        if not (current_version == requested_version or requested_version == str(sys.version_info.major)):
            print('\nAV_RESULT:' + json.dumps({'blocked': 'python_version_mismatch', 'dependency': 'python:' + current_version}))
            sys.exit(0)
        absent = [name for name in environment['required_environment_names'] if name not in os.environ]
        if absent:
            print('\nAV_RESULT:' + json.dumps({'blocked': 'environment_unavailable', 'dependency': ','.join(absent)[:100]}))
            sys.exit(0)
        for dependency in environment['dependencies']:
            if dependency.get('distribution_sha256'):
                print('\nAV_RESULT:' + json.dumps({'blocked': 'distribution_digest_unverified', 'dependency': dependency['name']}))
                sys.exit(0)
            try: actual = importlib.metadata.version(dependency['name'])
            except importlib.metadata.PackageNotFoundError: actual = None
            if actual != dependency['version']:
                print('\nAV_RESULT:' + json.dumps({'blocked': 'dependency_contract_mismatch', 'dependency': dependency['name']}))
                sys.exit(0)
    package = types.ModuleType('_veritas_submission')
    package.__path__ = ['/vercel/project']
    sys.modules[package.__name__] = package
    module_path = request['file'][:-3].replace('/', '.')
    if module_path.endswith('.__init__'): module_path = module_path[:-9]
    name = package.__name__ + '.' + module_path
    spec = importlib.util.find_spec(name)
    expected_path = '/vercel/project/' + request['file']
    if spec is None or spec.origin != expected_path:
        raise ValueError('Entry module does not resolve to the reviewed source path')
    module = importlib.import_module(name)
    def invoke_steps():
        responses = []
        for text in request.get('steps') or [request['input']]:
            result = getattr(module, request['symbol'])(text)
            if inspect.isawaitable(result): result = asyncio.run(result)
            response = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            responses.append(response[:request.get('output_char_limit', 8000)])
        return responses
    responses = invoke_steps()
    output = {'response': responses[-1]}
    if request.get('steps'): output['step_responses'] = responses
    print('\nAV_RESULT:' + json.dumps(output))
except SystemExit:
    raise
except ModuleNotFoundError as error:
    print('\nAV_RESULT:' + json.dumps({'blocked': 'missing_dependency', 'dependency': str(error.name)[:100]}))
except BaseException as error:
    print('\nAV_RESULT:' + json.dumps({'error': type(error).__name__}))
'''


def main():
    config = json.load(open('/vercel/probe-input.json'))
    observations = []
    for case in config['cases']:
        request = {**config['entrypoint'], 'input': case['input'], 'steps': case.get('steps'),
                   'environment': config.get('environment'), 'output_char_limit': config.get('output_char_limit', 8000)}
        with tempfile.TemporaryFile() as log:
            proc = subprocess.Popen([sys.executable, '-I', '-c', CHILD, json.dumps(request)],
                stdout=log, stderr=log, cwd='/vercel/project', start_new_session=True,
                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8'})
            timed_out = False
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()
            log.seek(0)
            raw = log.read(65536).decode('utf-8', errors='replace')
        outcome = {'id': case['id'], 'exit_code': proc.returncode, 'timed_out': timed_out}
        marker = raw.rfind('AV_RESULT:')
        if marker >= 0:
            try: outcome['agent_output'] = json.loads(raw[marker + 10:].splitlines()[0])
            except (ValueError, IndexError): outcome['output_invalid'] = True
        else:
            outcome['output_invalid'] = True
        observations.append(outcome)
    print(json.dumps({'observations': observations}, ensure_ascii=False))


if __name__ == '__main__':
    main()
