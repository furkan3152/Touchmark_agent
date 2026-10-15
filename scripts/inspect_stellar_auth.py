#!/usr/bin/env python3
"""Inspect one authorization entry against a declared policy; never sign or submit."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.stellar.auth_inspector import AuthorizationInspectionRequest, inspect_authorization_entry

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('request', type=Path, help='JSON containing entry_xdr and policy')
args = parser.parse_args()
try:
    if args.request.stat().st_size > 100_000:
        raise ValueError('Request exceeds the bounded 100 KB limit.')
    request = AuthorizationInspectionRequest.model_validate_json(args.request.read_text())
    report = inspect_authorization_entry(request)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['matches_declared_policy'] else 1)
except (ValueError, OSError):
    # Validation errors may contain the submitted signed entry; don't echo it.
    print('Invalid request. Provide bounded canonical authorization-entry XDR and an exact transfer policy.', file=sys.stderr)
    raise SystemExit(2)
