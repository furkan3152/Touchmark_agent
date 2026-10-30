#!/usr/bin/env python3
"""Read-only project discovery; never imports or executes submitted source."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.services.blueprint import parse_blueprint
from backend.app.services.discovery import discover_project, safe_source_path
from backend.app.services.studio import ReviewRequest


def collect(root: Path) -> dict[str, str]:
    manifest_path = root / 'veritas.json'
    if manifest_path.is_symlink():
        raise ValueError('Blueprint must be a regular file, not a symbolic link.')
    if manifest_path.exists():
        if manifest_path.stat().st_size > 32000:
            raise ValueError('Blueprint exceeds 32 KB.')
        manifest = manifest_path.read_text(encoding='utf-8')
        paths = ['veritas.json'] + sorted({c.path for c in parse_blueprint(manifest).components})
    else:
        paths = []
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith('.') and d not in {'node_modules','vendor','dist','build','target','__pycache__','venv','coverage'} and not (Path(directory) / d).is_symlink())
            for name in sorted(names):
                relative = (Path(directory) / name).relative_to(root).as_posix()
                if safe_source_path(relative): paths.append(relative)
            if len(paths) > 12:
                raise ValueError('More than 12 eligible files. Create an explicit veritas.json scope or select a smaller project root.')
    files = {}
    for relative in paths:
        path = root / relative
        if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
            raise ValueError(f'Symlinks are not allowed: {relative}')
        if not path.exists(): continue  # Compiler reports each missing declared file.
        if not path.is_file() or path.stat().st_size > 32000:
            raise ValueError(f'Expected a regular source file up to 32 KB: {relative}')
        files[relative] = path.read_text(encoding='utf-8')
    ReviewRequest(name='Local project', purpose='Inspect local project source and declared boundaries.', files=files)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'check', 'plan'])
    parser.add_argument('project', type=Path)
    args = parser.parse_args()
    root = args.project.resolve()
    try:
        if not root.is_dir(): raise ValueError('Project root must be a directory.')
        if args.command == 'init' and (root / 'veritas.json').exists():
            raise ValueError('veritas.json already exists; refusing to overwrite it.')
        files = collect(root)
        discovery = discover_project(files)
        if args.command == 'init':
            draft = discovery['blueprint_draft']
            if not draft or not draft.get('manifest'):
                raise ValueError('No unique supported entrypoint. Declare the real callable explicitly using the Blueprint schema.')
            if len(files) >= 12 or sum(len(v.encode()) for v in files.values()) + len(json.dumps(draft['manifest'], indent=2).encode()) > 64000:
                raise ValueError('Make room for veritas.json within the 12-file / 64 KB scope limit.')
            with (root / 'veritas.json').open('x', encoding='utf-8') as out:
                out.write(json.dumps(draft['manifest'], indent=2) + '\n')
            print('Created veritas.json draft. Review purpose, component roles and permission boundaries, then run check.')
        else:
            plan = discovery['blueprint']
            print(json.dumps(plan, indent=2, ensure_ascii=False))
            return 0 if plan['status'] == 'mapped' else 1
    except (ValueError, OSError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
