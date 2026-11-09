#!/usr/bin/env python3
"""Set the assay book account's home domain on Stellar testnet (SEP-1, account side).

usetouchmark.app/.well-known/stellar.toml lists the account under ACCOUNTS; this sets the
account's home_domain to the same domain, so the binding can be checked from both ends.
The operator key is read from DEMO_OPERATOR_SECRET and never printed.

    vercel env pull .env.operator --environment=production
    set -a; . ./.env.operator; set +a
    python scripts/set_home_domain.py            # shows what it would do
    python scripts/set_home_domain.py --submit   # signs and submits, then reads it back
    rm .env.operator
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from stellar_sdk import Keypair, Server, TransactionBuilder

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "usetouchmark.app"
HORIZON = "https://horizon-testnet.stellar.org"
PASSPHRASE = "Test SDF Network ; September 2015"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--submit", action="store_true", help="sign and submit (default: dry run)")
    args = ap.parse_args()

    account = json.loads((ROOT / "deployments/demo-testnet.json").read_text())["operator"]
    secret = os.environ.get("DEMO_OPERATOR_SECRET", "").strip()
    if not secret:
        sys.exit("DEMO_OPERATOR_SECRET is not set.")
    keypair = Keypair.from_secret(secret)
    if keypair.public_key != account:
        sys.exit(f"The key is not the operator's: expected {account}.")

    toml = urllib.request.urlopen(f"https://{DOMAIN}/.well-known/stellar.toml", timeout=20).read().decode()
    if account not in toml:
        sys.exit(f"{DOMAIN}/.well-known/stellar.toml does not list {account}; publish it first.")

    server = Server(HORIZON)
    current = server.accounts().account_id(account).call().get("home_domain")
    print(f"account     {account}\nhome_domain {current!r} -> {DOMAIN!r}")
    if current == DOMAIN:
        print("already set")
        return 0
    if not args.submit:
        print("dry run: add --submit to sign and submit")
        return 0

    tx = (TransactionBuilder(server.load_account(account), network_passphrase=PASSPHRASE, base_fee=100)
          .append_set_options_op(home_domain=DOMAIN).set_timeout(60).build())
    tx.sign(keypair)
    result = server.submit_transaction(tx)
    after = server.accounts().account_id(account).call().get("home_domain")
    print(f"submitted   {result['hash']}\nhome_domain {after!r}")
    return 0 if after == DOMAIN else 1


if __name__ == "__main__":
    raise SystemExit(main())
