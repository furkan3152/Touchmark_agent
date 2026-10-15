"""Deterministic local fixture, not a live AI or Stellar account reader."""
import json
from pathlib import Path
from .tools import fixture_balance


def respond(message):
    root = Path(__file__).parent
    policy = json.loads((root / 'policy.json').read_text())
    instructions = (root / 'instructions.md').read_text()
    if 'balance' in message.lower() and policy['allowed_tools'] == ['fixture_balance']:
        return f"Fixture balance: {fixture_balance()} XLM. No ledger request was made."
    return instructions.strip()
