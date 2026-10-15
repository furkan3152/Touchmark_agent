"""Bounded, non-executing project discovery. Filenames alone never establish an agent."""
from __future__ import annotations

import ast
import json
import re
import tomllib
from hashlib import sha256
from pathlib import PurePosixPath

FRAMEWORKS = {
    'langgraph': 'LangGraph', 'langchain': 'LangChain', 'crewai': 'CrewAI',
    'autogen': 'AutoGen', 'agents': 'OpenAI Agents SDK', 'pydantic_ai': 'Pydantic AI',
    '@mastra/core': 'Mastra', '@ai-sdk/': 'Vercel AI SDK', 'mcp': 'MCP',
    'stellar_sdk': 'Stellar SDK', '@stellar/stellar-sdk': 'Stellar SDK',
}
EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '.rs', '.go', '.json', '.md', '.txt', '.toml', '.yaml', '.yml'}
EXCLUDED = {'node_modules', 'vendor', 'dist', 'build', 'target', '__pycache__', 'venv', 'coverage'}


def safe_source_path(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name and len(name) <= 160 and not path.is_absolute() and '\\' not in name
                and ':' not in name and all(not p.startswith('.') and p not in EXCLUDED for p in path.parts)
                and path.suffix.lower() in EXTENSIONS
                and not re.search(r'(?i)(?:^|/)(?:credentials|secrets?|id_rsa|service.account)(?:[._-]|$)', name))


def source_digest(files: dict[str, str]) -> str:
    return sha256(json.dumps(files, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def discover_project(files: dict[str, str]) -> dict:
    frameworks, dependencies, env_keys, imports, entrypoints, tests, diagnostics = set(), set(), set(), set(), [], [], []
    for path, content in sorted(files.items()):
        suffix, basename = PurePosixPath(path).suffix, PurePosixPath(path).name
        if suffix == '.py':
            try:
                tree = ast.parse(content)
            except (SyntaxError, ValueError, RecursionError):
                diagnostics.append({'file': path, 'reason': 'Python syntax could not be parsed.'})
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    imports.update(a.name for a in n.names)
                elif isinstance(n, ast.ImportFrom) and n.module:
                    imports.add(n.module)
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {'getenv', 'get'}:
                    if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                        if isinstance(n.func.value, ast.Name) and n.func.value.id == 'os' or isinstance(n.func.value, ast.Attribute) and n.func.value.attr == 'environ':
                            env_keys.add(n.args[0].value[:100])
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith('_'):
                    params = n.args.posonlyargs + n.args.args
                    # A supported call shape, not a claim that this is an agent.
                    if len(params) == 1 and not n.args.vararg and not n.args.kwarg and not n.args.kwonlyargs and params[0].arg in {'prompt', 'message', 'query', 'input_text'}:
                        entrypoints.append({'id': f'{path}:{n.name}', 'file': path, 'symbol': n.name,
                            'adapter': 'python_text', 'line': n.lineno, 'confidence': 'candidate',
                            'reason': 'Top-level single-text-input callable; confirm that it invokes the real agent.'})
            if any(isinstance(n, ast.ClassDef) and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in n.bases) for n in tree.body):
                tests.append({'file': path, 'runner': 'python_unittest'})
        if suffix in {'.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs'}:
            imports.update(re.findall(r'(?:from\s*|require\s*\(\s*|import\s*)[\"\']([^\"\']+)', content))
            env_keys.update(re.findall(r'process\.env\.([A-Z][A-Z0-9_]{1,99})', content))
        try:
            if basename == 'package.json':
                package = json.loads(content)
                for field in ['dependencies', 'devDependencies']:
                    values = package.get(field, {})
                    if isinstance(values, dict): dependencies.update(str(x)[:120] for x in values)
                scripts = package.get('scripts', {})
                if isinstance(scripts, dict):
                    for name in ('start', 'dev', 'test'):
                        if isinstance(scripts.get(name), str):
                            entrypoints.append({'id': f'{path}:script:{name}', 'file': path,
                                'adapter': 'manual', 'confidence': 'declared', 'reason': f'Package script {name}: {scripts[name][:200]}. Requires a reviewed dependency image.'})
            elif basename == 'pyproject.toml':
                package = tomllib.loads(content).get('project', {})
                dependencies.update(str(x)[:120] for x in package.get('dependencies', []) if isinstance(x, str))
                for name, value in package.get('scripts', {}).items():
                    entrypoints.append({'id': f'{path}:script:{name}', 'file': path, 'adapter': 'manual',
                        'confidence': 'declared', 'reason': f'Python console entry point: {str(value)[:200]}'})
            elif basename.startswith('requirements') and suffix == '.txt':
                dependencies.update(line.strip()[:120] for line in content.splitlines() if line.strip() and not line.startswith('#'))
        except (ValueError, TypeError, AttributeError, RecursionError):
            diagnostics.append({'file': path, 'reason': 'Dependency manifest could not be parsed.'})
    for token, label in FRAMEWORKS.items():
        if any(v == token or v.startswith(token + '.') or v.startswith(token + '/') or v.startswith(token + '=') or token.endswith('/') and v.startswith(token) for v in imports | {re.split(r"[<>=~!\[ ]", d)[0].replace("-", "_") for d in dependencies}):
            frameworks.add(label)
    return {'schema': 'agentveritas.discovery.v1', 'source_sha256': source_digest(files),
            'files_inspected': len(files), 'frameworks': sorted(frameworks),
            'dependencies': sorted(dependencies)[:100], 'required_environment_names': sorted(env_keys)[:40],
            'entrypoints': entrypoints[:30], 'test_suites': tests[:12], 'diagnostics': diagnostics,
            'runtime_executed': False, 'next_steps': [
                'Confirm the callable that reaches your real agent, not a mock or policy helper.',
                'Runtime runs in a disposable microVM with no outbound network and no production secrets.',
                'Missing packages or live model access are reported as blocked; no automatic production credentials are used.',
            ]}
