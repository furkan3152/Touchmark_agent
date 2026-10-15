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
import asyncio, contextlib, importlib, inspect, json, os, resource, sys, types
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
request = json.loads(sys.argv[1])
sys.path.insert(0, '/vercel/project')
sys.path.insert(0, os.path.dirname('/vercel/project/' + request['file']))
try:
    package = types.ModuleType('_veritas_submission')
    package.__path__ = ['/vercel/project']
    sys.modules[package.__name__] = package
    module_path = request['file'][:-3].replace('/', '.')
    if module_path.endswith('.__init__'): module_path = module_path[:-9]
    module = importlib.import_module(package.__name__ + '.' + module_path)
    result = getattr(module, request['symbol'])(request['input'])
    if inspect.isawaitable(result): result = asyncio.run(result)
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    print('\nAV_RESULT:' + json.dumps({'response': text[:8000]}))
except ModuleNotFoundError as error:
    print('\nAV_RESULT:' + json.dumps({'blocked': 'missing_dependency', 'dependency': str(error.name)[:100]}))
except BaseException as error:
    print('\nAV_RESULT:' + json.dumps({'error': type(error).__name__}))
'''


def main():
    config = json.load(open('/vercel/probe-input.json'))
    observations = []
    for case in config['cases']:
        request = {**config['entrypoint'], 'input': case['input']}
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
