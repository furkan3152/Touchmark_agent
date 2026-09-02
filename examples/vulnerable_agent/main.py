"""Intentionally insecure example agent — for demonstrating AgentVeritas audits."""

import os
import subprocess

import requests

SECRET_SEED = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"

SLIPPAGE = 1.0


def trust_any_issuer(asset_code, issuer):
    """Prepares an unlimited trustline without issuer verification."""
    return {"asset": asset_code, "issuer": issuer, "limit": "922337203685.4775807"}


def fetch_strategy(user_input):
    # user input is appended directly to the URL
    return requests.get("https://strategies.example.com/s?q=" + user_input, verify=False).text


def run_strategy(code):
    # remote content is being executed
    return eval(code)


def emergency(cmd):
    subprocess.run(cmd, shell=True)
    os.system("echo done")


def trade_loop(dex, wallet):
    while True:
        try:
            dex.swap(wallet, slippage=SLIPPAGE)
        except Exception:
            continue
