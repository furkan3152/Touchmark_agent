"""Veritas Blueprint v1: explicit project map -> checked evidence graph -> audit plan.

A declaration is never enforcement evidence. Compilation parses source; it does
not import it, install dependencies, resolve URLs, or execute manifest commands.
"""
from __future__ import annotations

import ast
import json
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

VERSION = 'veritas.blueprint/v1'
ROLES = ('entrypoint', 'implementation', 'instructions', 'tool', 'memory', 'policy', 'delegate', 'contract', 'test', 'dependency')
CHECKS = {
    'entrypoint': ['instruction_override', 'tool_output_injection'],
    'instructions': ['instruction_override', 'secret_request'],
    'tool': ['tool_output_injection', 'unauthorized_payment'],
    'policy': ['unauthorized_payment', 'delegation_escalation'],
    'memory': ['tenant_isolation', 'memory_poisoning'],
    'delegate': ['delegation_escalation'],
    'contract': ['signer_authorization', 'version_binding'],
    'dependency': ['dependency_provenance'],
    'implementation': ['source_path_review'], 'test': ['test_oracle_review'],
}


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Component(Strict):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,47}$')
    role: Literal['entrypoint', 'implementation', 'instructions', 'tool', 'memory', 'policy', 'delegate', 'contract', 'test', 'dependency']
    path: str = Field(min_length=1, max_length=160)
    @field_validator('path')
    @classmethod
    def relative_path(cls, value):
        from .discovery import safe_source_path
        if value == 'veritas.json' or any(c in value for c in '*?[]\x00') or not safe_source_path(value) or str(PurePosixPath(value)) != value:
            raise ValueError('Use an exact canonical relative source path, without globs or hidden files.')
        return value


class Entrypoint(Strict):
    component: str = Field(min_length=1, max_length=48)
    symbol: str = Field(pattern=r'^[A-Za-z][A-Za-z0-9_]{0,79}$')
    adapter: Literal['python_text'] = 'python_text'


class Boundary(Strict):
    source: str = Field(min_length=1, max_length=48)
    target: str = Field(min_length=1, max_length=48)
    permission: Literal['read', 'invoke', 'write', 'delegate', 'sign']
    approval_required: bool = True


class Expectation(Strict):
    operator: Literal['contains', 'excludes']
    value: str = Field(min_length=1, max_length=200)


class Scenario(Strict):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,39}$')
    input: str = Field(min_length=12, max_length=1200)
    expect: Expectation


class Blueprint(Strict):
    protocol: Literal['veritas.blueprint/v1']
    name: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=12, max_length=2000)
    components: list[Component] = Field(min_length=1, max_length=40)
    entrypoint: Entrypoint
    boundaries: list[Boundary] = Field(default_factory=list, max_length=60)
    scenarios: list[Scenario] = Field(default_factory=list, max_length=2)

    @model_validator(mode='after')
    def references(self):
        ids = {c.id for c in self.components}
        if len(ids) != len(self.components): raise ValueError('Component IDs must be unique.')
        if self.entrypoint.component not in ids: raise ValueError('Entrypoint refers to an unknown component.')
        if sum(c.role == 'entrypoint' for c in self.components) != 1:
            raise ValueError('Declare exactly one entrypoint component.')
        if next(c for c in self.components if c.id == self.entrypoint.component).role != 'entrypoint':
            raise ValueError('Entrypoint must reference the entrypoint role.')
        if any(b.source not in ids or b.target not in ids for b in self.boundaries):
            raise ValueError('Every boundary must reference existing components.')
        if len({s.id for s in self.scenarios}) != len(self.scenarios):
            raise ValueError('Scenario IDs must be unique.')
        return self


def parse_blueprint(raw: str) -> Blueprint:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate JSON keys are not allowed.')
            result[key] = value
        return result
    try:
        data = json.loads(raw, object_pairs_hook=unique_pairs)
        return Blueprint.model_validate(data)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('Invalid veritas.json: use the Blueprint v1 schema; paths and component references must be exact.') from exc


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def python_edges(files: dict[str, str]) -> list[dict]:
    """Resolve local absolute/relative imports against supplied paths; retain uncertainty."""
    modules = {p[:-3].replace('/', '.'): p for p in files if p.endswith('.py')}
    modules.update({p[:-12].replace('/', '.'): p for p in files if p.endswith('/__init__.py')})
    edges = []
    for path, content in sorted(files.items()):
        if not path.endswith('.py'): continue
        try: tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError): continue
        package = path.split('/')[:-1]
        for n in ast.walk(tree):
            targets = []
            if isinstance(n, ast.Import): targets = [(a.name, False) for a in n.names]
            elif isinstance(n, ast.ImportFrom):
                if n.level:
                    base = '.'.join(package[:len(package) - n.level + 1]) if n.level <= len(package) else ''
                    module = '.'.join(x for x in (base, n.module) if x)
                    targets = [(module, True)] if n.module or module in modules else []
                    targets += [(module + '.' + a.name if module else a.name, True) for a in n.names
                                if not n.module and module not in modules or module + '.' + a.name in modules]
                elif n.module:
                    targets = [(n.module, False)] + [(n.module + '.' + a.name, False) for a in n.names if n.module + '.' + a.name in modules]
            for module, relative in targets:
                resolved = modules.get(module)
                if not resolved and not relative:
                    # Imports adjacent to the entry module are also common in script projects.
                    resolved = modules.get('.'.join(package + [module]))
                if not module: continue
                edge = {'from': path, 'to': resolved or module, 'line': n.lineno,
                        'kind': 'python_import', 'resolution': 'supplied_source' if resolved else 'unresolved_relative' if relative else 'external_or_missing'}
                if edge not in edges: edges.append(edge)
    return edges


def compile_blueprint(files: dict[str, str]) -> dict:
    from .discovery import source_digest, python_module_path, stable_callable
    source_hash = source_digest(files)
    base = {'protocol': VERSION, 'source_sha256': source_hash, 'runtime_verified': False}
    if 'veritas.json' not in files:
        return {**base, 'status': 'not_declared', 'blockers': [], 'components': [], 'checks': [],
                'note': 'Discovery is provisional. Generate and review a veritas.json project map.'}
    try: manifest = parse_blueprint(files['veritas.json'])
    except ValueError as exc:
        return {**base, 'status': 'blocked', 'blockers': [str(exc)], 'components': [], 'checks': []}
    blockers, components, checks = [], [], []
    declared = {c.path for c in manifest.components}
    for c in manifest.components:
        exists = c.path in files
        if not exists: blockers.append(f'Missing declared file: {c.path}')
        components.append({**c.model_dump(), 'status': 'present' if exists else 'missing',
                           'content_sha256': sha256(files[c.path].encode()).hexdigest() if exists else None})
        for check in CHECKS[c.role]:
            checks.append({'id': check, 'component': c.id, 'path': c.path,
                           'method': 'behavior_probe' if check in {'instruction_override','tool_output_injection','secret_request','unauthorized_payment','delegation_escalation'} else 'evidence_review_required',
                           'status': 'planned' if exists else 'blocked_missing_file'})
    unclassified = sorted(set(files) - declared - {'veritas.json'})
    if unclassified: blockers.append('Classify every supplied file: ' + ', '.join(unclassified))
    entry_component = next(c for c in manifest.components if c.id == manifest.entrypoint.component)
    entry = {'id': f'{entry_component.path}:{manifest.entrypoint.symbol}', 'file': entry_component.path,
             'symbol': manifest.entrypoint.symbol, 'adapter': manifest.entrypoint.adapter,
             'confidence': 'declared_and_checked', 'reason': 'Blueprint entrypoint; source signature checked without execution.'}
    if entry_component.path in files:
        try:
            if not python_module_path(entry_component.path): raise ValueError()
            tree = ast.parse(files[entry_component.path])
            candidates = [n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name == entry['symbol']]
            if len(candidates) != 1: raise ValueError()
            n = candidates[0]; args = n.args
            if not stable_callable(tree, n) or len(args.args + args.posonlyargs) != 1 or args.vararg or args.kwarg or args.kwonlyargs or n.decorator_list:
                raise ValueError()
            entry['line'] = n.lineno
        except (SyntaxError, ValueError, RecursionError):
            blockers.append('Declared entrypoint must be one unrebound, undecorated top-level Python callable taking exactly one positional argument, in an unambiguous Python module path.')
    edges = python_edges(files)
    unresolved = [e for e in edges if e['resolution'] != 'supplied_source']
    if any(e['resolution'] == 'unresolved_relative' for e in unresolved):
        blockers.append('A relative import has no supplied module. Include its source or an explicit package initializer before execution.')
    plan = {**base, 'status': 'blocked' if blockers else 'mapped', 'manifest': manifest.model_dump(),
            'manifest_sha256': _digest(manifest.model_dump()), 'components': components,
            'role_coverage': {role: 'declared' if any(c.role == role for c in manifest.components) else 'not_declared' for role in ROLES},
            'entrypoint': entry, 'boundaries': [b.model_dump() for b in manifest.boundaries],
            'source_edges': edges, 'unresolved_imports': unresolved, 'unclassified_files': unclassified,
            'blockers': blockers, 'checks': checks, 'review_scope': 'supplied_files_only',
            'analysis_limits': ['Python literal imports only; dynamic imports, resource reads and external packages require further evidence.',
                                'Component roles and permission boundaries are developer declarations, not proven call paths or enforced controls.'],
            'note': 'Mapped means references and call shape are checked, not that controls work or the entire repository is covered.'}
    # A reproducible plan fingerprint binds source, declared intent, boundaries and analyzer version.
    plan['plan_sha256'] = _digest(plan)
    return plan


def suggest_blueprint(files: dict[str, str], entrypoints: list[dict]) -> dict:
    candidates = [e for e in entrypoints if e['adapter'] == 'python_text']
    if len(candidates) != 1:
        return {'status': 'needs_entrypoint_choice', 'candidates': [e['id'] for e in candidates], 'manifest': None}
    selected = candidates[0]
    components = []
    for i, path in enumerate(sorted(files)):
        if path == 'veritas.json': continue
        role = 'entrypoint' if path == selected['file'] else 'dependency' if PurePosixPath(path).name in {'requirements.txt','pyproject.toml','package.json'} else 'implementation'
        components.append({'id': 'entry' if role == 'entrypoint' else f'component-{i}', 'role': role, 'path': path})
    return {'status': 'draft_requires_review', 'manifest': {'protocol': VERSION, 'name': 'My agent',
        'purpose': 'Replace this with the actual permitted behavior and scope.', 'components': components,
        'entrypoint': {'component': 'entry', 'symbol': selected['symbol'], 'adapter': 'python_text'},
        'boundaries': [], 'scenarios': []},
        'note': 'Review component roles, intended behavior and trust boundaries before using this draft. No control enforcement was inferred.'}
