#!/usr/bin/env python3
"""Audit benchmark cases through a Touchmark deployment's public API, the way a user would.

    python3 run_live.py vulnerable|fixed [case_id ...] [--cases cases.json] [--out DIR] [--base URL]

For each case it submits the GitHub folder pinned to the vulnerable (or fixed) commit with model review
consent, follows the streamed request legs until the report is ready, and writes <out>/<case_id>.<side>.json.
A case whose report already exists is skipped, so an interrupted run can be resumed. When the hourly
allowance is used up it waits; when the daily spend cap is reached it stops.

Score the reports with score_real.py. Needs httpx.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
HEADERS = {"Accept": "application/x-ndjson", "Content-Type": "application/json"}


def stream(client: httpx.Client, url: str, body: dict, state: dict) -> dict | None:
    """POST and read the NDJSON stream; return the last terminal event, or None if the stream broke."""
    last = None
    try:
        with client.stream("POST", url, json=body, headers=HEADERS, timeout=httpx.Timeout(30, read=330)) as r:
            if r.status_code != 200:
                return {"type": "http_error", "status": r.status_code, "body": r.read().decode()[:500]}
            for raw in r.iter_lines():
                if not raw.strip():
                    continue
                event = json.loads(raw)
                if event.get("type") == "job":
                    state["job_id"] = event.get("job_id")
                if event.get("type") in ("result", "continue", "busy", "cancelled", "error"):
                    last = event
    except (httpx.HTTPError, json.JSONDecodeError):
        pass
    return last


def audit(base: str, reference: str) -> dict | None:
    """Run one audit to the end; returns the final result event's data, or None."""
    state: dict = {}
    with httpx.Client() as client:
        event = stream(client, f"{base}/api/v1/demo/audit", {"reference": reference, "model_review_consent": True},
                       state)
        for _ in range(40):
            if not event or event.get("type") not in ("busy", "continue") or not state.get("job_id"):
                break
            if event.get("type") == "busy":
                time.sleep(min(30, float(event.get("retry_after", 10))))
            event = stream(client, f"{base}/api/v1/demo/audit/continue", {"job_id": state["job_id"]}, state)
    return (event or {}).get("data") if (event or {}).get("type") == "result" else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("side", choices=("vulnerable", "fixed"))
    ap.add_argument("ids", nargs="*", help="case ids (default: all)")
    ap.add_argument("--cases", type=Path, default=HERE / "cases.json")
    ap.add_argument("--out", type=Path, default=Path("reports"))
    ap.add_argument("--base", default="https://usetouchmark.app")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for case in json.loads(args.cases.read_text()):
        if args.ids and case["id"] not in args.ids:
            continue
        target = args.out / f"{case['id']}.{args.side}.json"
        if target.exists():
            continue
        sha = case["vulnerable_commit"] if args.side == "vulnerable" else case["fixed_commit"]
        reference = f"https://github.com/{case['repo']}/tree/{sha}" + (f"/{case['subdir']}" if case.get("subdir") else "")
        for _ in range(8):
            data = audit(args.base, reference)
            if data is None:
                print(json.dumps({"id": case["id"], "side": args.side, "error": "no result"}), flush=True)
                break
            ai = data.get("ai") or {}
            if ai.get("review") == "rate_limited":
                print(json.dumps({"id": case["id"], "waiting": "hourly allowance"}), flush=True)
                time.sleep(600)
                continue
            if ai.get("stop_reason") in ("daily_cost_cap", "daily_budget"):
                print(json.dumps({"stopped": "daily spend cap reached; run again after 00:00 UTC"}), flush=True)
                return 0
            target.write_text(data["report_json"])
            print(json.dumps({"id": case["id"], "side": args.side, "decision": data.get("decision"),
                              "review": ai.get("review")}), flush=True)
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
