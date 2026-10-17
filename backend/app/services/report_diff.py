"""Compare two audit reports of the same agent: what a fix closed, what it opened."""
from __future__ import annotations

import re


def _key(finding: dict) -> str:
    # Rule ids are stable across commits; model finding ids end in a running number, so
    # they are matched by category and title instead.
    fid = finding["id"]
    if "-ai-" in fid:
        return re.sub(r"-\d+$", "", fid) + "|" + " ".join(finding.get("title", "").lower().split())
    return fid


def _risks(report: dict) -> dict[str, dict]:
    return {_key(f): f for f in report.get("findings", []) if f.get("kind", "risk") == "risk"}


def compare_reports(before: dict, after: dict) -> dict:
    old, new = _risks(before), _risks(after)
    row = lambda f: {"id": f["id"], "severity": f["severity"], "title": f.get("title", "")}  # noqa: E731
    result = lambda r: {"decision": r.get("review_decision") or r.get("result", {}).get("decision"),  # noqa: E731
                        "score": r.get("result", {}).get("overall_score"),
                        "revision": (r.get("repository") or {}).get("revision", "")}
    return {
        "before": result(before), "after": result(after),
        "score_change": round((after["result"]["overall_score"] or 0) - (before["result"]["overall_score"] or 0), 1),
        "closed": [row(f) for k, f in old.items() if k not in new],
        "remaining": [row(f) for k, f in new.items() if k in old],
        "introduced": [row(f) for k, f in new.items() if k not in old],
    }
