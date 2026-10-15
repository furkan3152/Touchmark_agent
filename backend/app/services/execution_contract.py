"""Typed brokered-workflow contract embedded in the committed .veritas source.

No shell, package URL, Python expression, arbitrary HTTP endpoint or secret is
accepted. Bindings substitute specified clients; this is declared instrumentation,
not proof that their original transport implementation is safe.
"""
from __future__ import annotations
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT_FILE = 'veritas-runtime.json'
PROFILE = 'python312-stellar-v1'
RUNTIME_ROOT = Path(__file__).parents[1] / 'runtime'

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class Binding(Strict):
    module: str = Field(pattern=r'^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*$')
    symbol: str = Field(pattern=r'^[A-Za-z][A-Za-z0-9_]{0,79}$')
    adapter: Literal['json_model', 'stellar_testnet']

class Step(Strict):
    input: str = Field(min_length=2, max_length=3000)
    restart_before: bool = False
    expected_error: Literal['ValueError','PermissionError','TimeoutError','KeyError'] | None = None

class Invariant(Strict):
    kind: Literal['payment_count', 'no_denied_tool_calls', 'response_json']
    minimum: int = Field(default=0, ge=0, le=4)
    maximum: int = Field(default=0, ge=0, le=4)
    reference: str = Field(default='', max_length=28)
    step: int = Field(default=0, ge=0, le=2)
    path: list[str] = Field(default_factory=list,max_length=6)
    equals: str | bool | int | None = None
    @model_validator(mode='after')
    def valid(self):
        if self.maximum < self.minimum: raise ValueError('Invalid invariant bounds.')
        if any(not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,39}',x) for x in self.path):
            raise ValueError('Use bounded object-key paths.')
        if self.kind == 'response_json' and (not self.path or self.equals is None):
            raise ValueError('Response assertions require a path and a typed expected value.')
        return self

class Workflow(Strict):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,39}$')
    module: Literal['intent','injection','tools','privacy','financial','resilience']
    steps: list[Step] = Field(min_length=1,max_length=3)
    invariants: list[Invariant] = Field(min_length=1,max_length=8)
    payment_fault: Literal['none','before_submit','after_accept'] = 'none'
    model_reply: dict | None = None
    @model_validator(mode='after')
    def bounded(self):
        if len(json.dumps(self.model_reply)) > 4000: raise ValueError('Model fixture exceeds budget.')
        if any(x.step >= len(self.steps) for x in self.invariants): raise ValueError('Invariant step absent.')
        return self

class ExecutionContract(Strict):
    protocol: Literal['veritas.execution/v1']
    profile: Literal['python312-stellar-v1']
    bindings: list[Binding] = Field(min_length=1,max_length=4)
    # Values are public test configuration or typed references; never credentials.
    environment: dict[str,str] = Field(default_factory=dict,max_length=20)
    workflows: list[Workflow] = Field(min_length=1,max_length=12)
    max_model_calls: int = Field(default=6,ge=0,le=12)
    max_payments: int = Field(default=4,ge=0,le=4)
    max_total_stroops: int = Field(default=400,ge=0,le=400)
    @model_validator(mode='after')
    def unique(self):
        if len({x.id for x in self.workflows}) != len(self.workflows): raise ValueError('Duplicate workflow IDs.')
        if len({(x.module,x.symbol) for x in self.bindings}) != len(self.bindings): raise ValueError('Duplicate bindings.')
        for name,value in self.environment.items():
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}',name) or len(value)>1000:
                raise ValueError('Invalid test environment declaration.')
            if name in {'PATH','HOME','SHELL','ENV','BASH_ENV'} or name.startswith(('PYTHON','LD_','UV_')):
                raise ValueError('Runtime control environment variables are operator-owned.')
            if re.search(r'SECRET|TOKEN|PASSWORD|API_KEY',name) and value != '$broker':
                raise ValueError('Only a non-secret broker marker is allowed for credential names.')
        return self


def load_contract(files: dict[str,str]) -> ExecutionContract | None:
    if CONTRACT_FILE not in files: return None
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('Duplicate execution contract key.')
            d[k]=v
        return d
    spec=ExecutionContract.model_validate(json.loads(files[CONTRACT_FILE],object_pairs_hook=unique))
    for binding in spec.bindings:
        if binding.module.replace('.','/')+'.py' not in files:
            raise ValueError('Instrumented module must be present in the committed source.')
    return spec


def profile_digest():
    paths=['python312-stellar.lock','workflow_probe.py']
    values={p:sha256((RUNTIME_ROOT/p).read_bytes()).hexdigest() for p in paths}
    for p in ('execution_contract.py','execution_broker.py','workflow_runtime.py'):
        values[p]=sha256(Path(__file__).with_name(p).read_bytes()).hexdigest()
    return sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()


def workflow_cases(spec):
    return [{'id':w.id,'module':w.module,'input':w.steps[0].input,
        'steps':[s.input for s in w.steps],'workflow':w.model_dump(mode='json')} for w in spec.workflows]


def preflight(spec, capsule, settings):
    failures=[]
    if not settings.enable_brokered_runtime:failures.append('Brokered workflow execution is not enabled on this deployment.')
    if not capsule:failures.append('Brokered execution requires a committed .veritas capsule.')
    else:
        env=capsule.environment
        if env.python_version not in {'3','3.12'}:failures.append('The reviewed execution profile provides Python 3.12 only.')
        approved={'stellar-sdk':'16.0.0','httpx':'0.28.1'}
        if any(approved.get(d.name.lower().replace('_','-'))!=d.version or d.distribution_sha256 for d in env.dependencies):
            failures.append('A declared dependency is outside the reviewed, hash-locked runtime profile.')
        if set(env.required_environment_names)-set(spec.environment):failures.append('Required environment names need explicit broker-safe test configuration.')
        if any(w.module not in capsule.audit.modules for w in spec.workflows):failures.append('Workflow modules must be selected in the capsule.')
    if any(w.model_reply is None for w in spec.workflows) and not settings.llm_enabled:
        failures.append('Live workflow model calls require a configured model provider.')
    return failures
