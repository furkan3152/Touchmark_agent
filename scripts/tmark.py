#!/usr/bin/env python3
"""Create, check and print the schema of a .tmark file.

    python scripts/tmark.py init  [REPO]      # write REPO/.tmark, pre-filled from what the code can do
    python scripts/tmark.py check [REPO|FILE] # exit 1 and list every error if the file is not valid
    python scripts/tmark.py schema            # print the JSON Schema
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services import tmark  # noqa: E402


def _init(repo: Path) -> int:
    target = repo / tmark.FILE_NAME
    if target.exists():
        print(f"{target} already exists; edit it, then run: python scripts/tmark.py check {repo}")
        return 1
    from backend.app.services.repo_audit import select_repository
    from backend.app.swarm.codeflow import analyse_code
    files, _ = select_repository(repo)
    caps = set(analyse_code(files).capabilities) if files else set()
    target.write_text(json.dumps(tmark.template(caps), indent=2) + "\n")
    print(f"Wrote {target}. Fill every empty field, then run: python scripts/tmark.py check {repo}")
    return 0


def _check(path: Path) -> int:
    file = path / tmark.FILE_NAME if path.is_dir() else path
    if not file.is_file():
        print(f"No {tmark.FILE_NAME} at {file}")
        return 1
    parsed, errors = tmark.parse(file.read_text(errors="replace"))
    if errors:
        print(f"{file} is not valid; Touchmark will not use it:")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"{file} is valid: {parsed.agent.name} ({parsed.agent.kind}, {parsed.agent.network}).")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"init", "check", "schema"}:
        print(__doc__)
        return 2
    if argv[0] == "schema":
        print(json.dumps(tmark.schema(), indent=2))
        return 0
    target = Path(argv[1] if len(argv) > 1 else ".")
    return _init(target) if argv[0] == "init" else _check(target)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
