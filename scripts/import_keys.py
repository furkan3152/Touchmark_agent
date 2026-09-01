#!/usr/bin/env python3
"""Reads API keys from a text file and imports them into `.env`.

Why a separate tool
-------------------
Manually copying keys into `.env` carries two risks: writing to the wrong line and
leaking the key into the shell history. This tool reads the file, validates it
**without ever printing the values**, and updates only the relevant lines of `.env`.

Usage
--------
    python scripts/import_keys.py --template ~/Masaüstü/agentveritas-keys.txt
    python scripts/import_keys.py ~/Masaüstü/agentveritas-keys.txt --dry-run
    python scripts/import_keys.py ~/Masaüstü/agentveritas-keys.txt

File format (lines starting with `#` are comments):

    ANTHROPIC_API_KEY=sk-ant-...
    PINATA_JWT=eyJ...
    CHAINALYSIS_API_KEY=...

Aliases are supported: simply writing `ANTHROPIC_API_KEY` is enough; the tool
will correctly set `LLM_PROVIDER` and `LLM_API_KEY`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

#: User-typable name → (.env key, additional fields to set alongside)
ALIASES: dict[str, tuple[str, dict[str, str]]] = {
    "ANTHROPIC_API_KEY": ("LLM_API_KEY", {"LLM_PROVIDER": "anthropic"}),
    "CLAUDE_API_KEY": ("LLM_API_KEY", {"LLM_PROVIDER": "anthropic"}),
    "OPENAI_API_KEY": ("LLM_API_KEY", {"LLM_PROVIDER": "openai"}),
    "OPENROUTER_API_KEY": (
        "LLM_API_KEY",
        # OpenRouter model names must be provider-prefixed; we also fix the default
        # so the user doesn't get a 400 error by typing `claude-sonnet-4-…`.
        {"LLM_PROVIDER": "openrouter", "LLM_MODEL": "anthropic/claude-sonnet-4"},
    ),
    "LLM_API_KEY": ("LLM_API_KEY", {}),
    "PINATA_JWT": ("PINATA_JWT", {}),
    "CHAINALYSIS_API_KEY": ("SCREENING_API_KEY", {"SCREENING_PROVIDER": "chainalysis"}),
    "TRM_API_KEY": ("SCREENING_API_KEY", {"SCREENING_PROVIDER": "trm"}),
    "ELLIPTIC_API_KEY": ("SCREENING_API_KEY", {"SCREENING_PROVIDER": "elliptic"}),
    "SCREENING_API_KEY": ("SCREENING_API_KEY", {}),
    # Settings passed through directly
    "LLM_PROVIDER": ("LLM_PROVIDER", {}),
    "LLM_MODEL": ("LLM_MODEL", {}),
    "LLM_BASE_URL": ("LLM_BASE_URL", {}),
    "SCREENING_PROVIDER": ("SCREENING_PROVIDER", {}),
}

#: Known but unused fields. Pinata "Copy All" provides all three values at once;
#: since the JWT covers both, there's no need for key/secret. These should be passed
#: as info, not warnings, otherwise the user might think it's an error.
IGNORED = {
    "API_KEY": "Pinata API Key (JWT is sufficient)",
    "API_SECRET": "Pinata API Secret (JWT is sufficient)",
    "PINATA_API_KEY": "Pinata API Key (JWT is sufficient)",
    "PINATA_API_SECRET": "Pinata API Secret (JWT is sufficient)",
}


def normalise_name(raw: str) -> str:
    """Converts raw input into an alias key.

    When users copy from the provider dashboard, they write formats like `API Key: …`,
    `JWT: …`, `openrouter: …`. Spaces/hyphens are converted to underscores, letters
    to uppercase; thus both `Pinata JWT` and `PINATA_JWT` fall into the same place.
    """
    cleaned = re.sub(r"[\s\-]+", "_", raw.strip())
    cleaned = re.sub(r"[^\w]", "", cleaned).upper()
    # if only "JWT" is written, it implies Pinata (it's our only JWT consumer)
    if cleaned == "JWT":
        return "PINATA_JWT"
    if cleaned in ("OPENROUTER", "OPEN_ROUTER"):
        return "OPENROUTER_API_KEY"
    if cleaned in ("ANTHROPIC", "CLAUDE"):
        return "ANTHROPIC_API_KEY"
    if cleaned == "OPENAI":
        return "OPENAI_API_KEY"
    if cleaned in ("PINATA", "PINATA_JWT_TOKEN"):
        return "PINATA_JWT"
    return cleaned

TEMPLATE = """\
# AgentVeritas — API keys
# Fill out only the lines you have; none of them are mandatory.
# After filling it out:  python scripts/import_keys.py THIS_FILE
# Delete this file after the import is complete.

# --- 1) LLM-as-Judge (qualitative evaluation) ---
# openrouter.ai -> Keys -> Create Key
OPENROUTER_API_KEY=
# Model name (if left empty, anthropic/claude-sonnet-4 is used).
# Free option example: meta-llama/llama-3.3-70b-instruct:free
# LLM_MODEL=

# Alternatives:
# ANTHROPIC_API_KEY=
# OPENAI_API_KEY=

# --- 2) IPFS pinning (free tier: 1 GB) ---
# app.pinata.cloud -> API Keys -> New Key
# Permissions: Selecting Admin is the easiest. If you want a restricted scope, these 3 endpoints suffice:
#   pinFileToIPFS, pinJSONToIPFS, testAuthentication
# After "Create Key", the JWT is shown only once; copy it immediately.
PINATA_JWT=

# --- 3) AML / sanction screening ---
# The OFAC SDN list is ALREADY public and requires no key (free, primary source):
#   python -m backend.cli sanctions --refresh
# The following are only required for indirect exposure analysis (mixer proximity)
# and require a commercial agreement; you can leave them empty.
# CHAINALYSIS_API_KEY=
# TRM_API_KEY=
# ELLIPTIC_API_KEY=
"""


def parse_key_file(path: Path) -> tuple[dict[str, str], list[str]]:
    """Parses the file into `.env` keys. Returns (updates, warnings)."""
    updates: dict[str, str] = {}
    warnings: list[str] = []

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # The separator can be `=` or `:`; lines copied from provider dashboards
        # often come in the `API Key: abc` format. The first occurring separator wins,
        # so `:` in values like `LLM_MODEL=meta-llama/x:free` is not broken.
        eq, colon = line.find("="), line.find(":")
        if eq == -1 and colon == -1:
            warnings.append(f"line {lineno}: no '=' or ':', skipped")
            continue
        cut = eq if colon == -1 else colon if eq == -1 else min(eq, colon)

        name = normalise_name(line[:cut])
        value = line[cut + 1 :].strip().strip('"').strip("'")

        if not value:
            continue  # left empty → do not touch
        if name in IGNORED:
            warnings.append(f"line {lineno}: {IGNORED[name]} — not required, skipped")
            continue
        if name not in ALIASES:
            warnings.append(f"line {lineno}: unknown key {name}, skipped")
            continue

        env_key, extras = ALIASES[name]
        updates[env_key] = value
        for k, v in extras.items():
            # if the user explicitly wrote the provider, do not overwrite it
            updates.setdefault(k, v)

    return updates, warnings


def write_env(updates: dict[str, str]) -> list[str]:
    """Replaces only the lines of the given keys in `.env`."""
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    remaining = dict(updates)
    changed: list[str] = []

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            lines[i] = f"{key}={remaining.pop(key)}"
            changed.append(key)

    for key, value in remaining.items():
        lines.append(f"{key}={value}")
        changed.append(key)

    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Import API keys into .env")
    parser.add_argument("path", nargs="?", help="key file (KEY=value lines)")
    parser.add_argument(
        "--template", metavar="PATH", help="create an empty template file to fill out"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show what would change without writing"
    )
    args = parser.parse_args()

    if args.template:
        target = Path(args.template).expanduser()
        if target.exists():
            print(f"ERROR: {target} already exists, not overwritten.")
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(TEMPLATE, encoding="utf-8")
        target.chmod(0o600)
        print(f"→ template created (permission 0600): {target}")
        print("  Fill it out and run the following command:")
        print(f"    python scripts/import_keys.py {target}")
        return 0

    if not args.path:
        parser.error("provide a key file or use --template")

    path = Path(args.path).expanduser()
    if not path.exists():
        print(f"ERROR: file does not exist: {path}")
        return 1

    updates, warnings = parse_key_file(path)
    for w in warnings:
        print(f"WARNING: {w}")

    if not updates:
        print("No filled keys found to import.")
        return 1

    # Values are never printed; only length information.
    print("\nto be imported:")
    for key in sorted(updates):
        value = updates[key]
        public = key.endswith("PROVIDER") or key in ("LLM_MODEL", "LLM_BASE_URL")
        print(f"  {key:<20} {value if public else f'{len(value)} characters'}")

    if args.dry_run:
        print("\n--dry-run: .env was not modified.")
        return 0

    changed = write_env(updates)
    print(f"\n→ .env updated: {', '.join(sorted(changed))}")
    print("→ to verify: python -m backend.cli integrations")
    print(f"→ import complete; you can now delete the {path} file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
