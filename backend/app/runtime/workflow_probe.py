"""MicroVM-only operator driver. Agent output is untrusted; broker traces are external.

Bindings replace only declared client classes. Never install packages or permit
network from this process. Restart segments preserve disk but not Python memory.
"""
import json,os,subprocess,sys,tempfile,signal

CHILD=r'''
import importlib,inspect,asyncio,json,os,resource,sys,time,uuid
from pathlib import Path
from types import SimpleNamespace
resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024))
resource.setrlimit(resource.RLIMIT_NOFILE,(80,80))
resource.setrlimit(resource.RLIMIT_NPROC,(32,32))
request=json.load(open(sys.argv[1]))
indexes=json.loads(sys.argv[2])
sys.path.insert(0,'/vercel/project')
sys.path.insert(0,os.path.dirname('/vercel/project/'+request['entrypoint']['file']))
def call(method,args):
    ident=uuid.uuid4().hex
    value=json.dumps({'id':ident,'method':method,'args':args})
    if len(value.encode())>16000:raise ValueError('Broker request too large')
    Path('/vercel/ipc/request.tmp').write_text(value)
    os.replace('/vercel/ipc/request.tmp','/vercel/ipc/request.json')
    until=time.monotonic()+28
    while time.monotonic()<until:
        try:
            raw=Path('/vercel/ipc/response.json').read_bytes()
            if len(raw)>32000:raise ValueError('Broker response too large')
            response=json.loads(raw)
            if response['id']==ident:
                if response.get('error'):
                    errors={'PermissionError':PermissionError,'ValueError':ValueError,'TimeoutError':TimeoutError}
                    raise errors.get(response['error'],RuntimeError)('Broker tool call failed')
                return response['result']
        except (FileNotFoundError,json.JSONDecodeError):pass
        time.sleep(.1)
    raise TimeoutError('Broker response deadline')
class Model:
    def __init__(self,*args,**kwargs):self.usage=[]
    async def decide(self,instruction,context):return call('model',{'instruction':instruction,'context':context})
class Chain:
    def __init__(self,seed=None):self.key=SimpleNamespace(public_key=request['public_accounts']['payer']) if seed else None
    def balance(self,account):return call('balance',{'account':account})
    def recent(self,account):return call('recent',{'account':account})
    def pay(self,destination,amount,reference):return call('pay',{'destination':destination,'amount':amount,'reference':reference})
for binding in request['bindings']:
    module=importlib.import_module(binding['module'])
    if not hasattr(module,binding['symbol']):raise ValueError('Declared client symbol absent')
    setattr(module,binding['symbol'],Model if binding['adapter']=='json_model' else Chain)
module=importlib.import_module(request['entrypoint']['file'][:-3].replace('/','.'))
responses=[]
for index in indexes:
    step=request['steps'][index]
    try:
        result=getattr(module,request['entrypoint']['symbol'])(step['input'])
        if inspect.isawaitable(result):result=asyncio.run(result)
        text=result if isinstance(result,str) else json.dumps(result)
        responses.append({'step':index,'response':text[:8000],'error':None})
    except BaseException as exc:
        responses.append({'step':index,'response':'','error':type(exc).__name__})
print('\nAV_RESULT:'+json.dumps(responses))
'''

def main():
    config=json.load(open('/vercel/workflow-input.json'))
    environment={'PATH':'/vercel/venv/bin:/usr/bin:/bin','HOME':'/tmp','LANG':'C.UTF-8',**config['environment']}
    groups=[]
    for i,step in enumerate(config['steps']):
        if not groups or step['restart_before']:groups.append([])
        groups[-1].append(i)
    responses=[]
    for indexes in groups:
        with tempfile.TemporaryFile() as log:
            proc=subprocess.Popen([sys.executable,'-I','-c',CHILD,'/vercel/workflow-input.json',json.dumps(indexes)],
                env=environment,cwd='/vercel/project',stdout=log,stderr=log,start_new_session=True)
            timeout=False
            try:proc.wait(timeout=35*len(indexes))
            except subprocess.TimeoutExpired:timeout=True
            finally:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait()
            log.seek(0);raw=log.read(1_048_576).decode('utf-8',errors='replace')
        found=raw.rfind('AV_RESULT:')
        try:
            values=json.loads(raw[found+10:].splitlines()[0]) if found>=0 and not timeout else None
            if not isinstance(values,list) or [x['step'] for x in values]!=indexes:raise ValueError()
            responses.extend(values)
        except (ValueError,KeyError,TypeError,IndexError):
            responses.extend({'step':i,'response':'','error':'TimeoutError' if timeout else 'RunnerError'} for i in indexes)
    print(json.dumps({'responses':responses}))
if __name__=='__main__':main()
