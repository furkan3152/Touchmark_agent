#!/usr/bin/env python3
"""Score Touchmark reports against the real-world fix benchmark (cases.json).

    python3 score_real.py --reports DIR [--cases cases.json] [--window 10] [--json]
    python3 score_real.py --selftest

DIR holds <case_id>.vulnerable.json (report on the vulnerable commit) and
<case_id>.fixed.json (report on the fixed commit). Paths in reports are relative to
the case's audited subdir; a leading copy of the subdir, the repo name or "./" is
tolerated.

A vulnerable report DETECTS a case when a risk finding, or a ledger check whose
verdict is "fails", cites one of the case's `files` within WINDOW lines of the
listed range. With --require-category the cited item must also carry the case's
category or one of its accept_categories.

A fixed report CLEARS a case when no risk finding or failing check of the case's
category (or accept_categories) cites one of the case's `fixed_files` (or `files`
when absent) within WINDOW lines. Items with no category count against clearing.
With --strict-clear any category counts.

Stdlib only (Python 3.9+).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

WINDOW = 10
NON_RISK_KINDS = {"evidence_gap", "warning", "info", "pass"}
LOC_RE = re.compile(r"(?P<path>[A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+):(?P<start>\d+)(?:-(?P<end>\d+))?")
AI_ID_RE = re.compile(r"-ai-(?P<cat>[a-z][a-z-]*?)-\d+$")

#: deep_review.CATEGORIES keys (backend/app/services/deep_review.py).
CATEGORIES = {
    "unauthorized_payment", "account_takeover", "foreign_transaction_signing", "secret_exposure",
    "prompt_injection", "code_execution", "ssrf", "path_traversal", "stellar_protocol_misuse",
    "replay_or_idempotency", "control_bypass", "cross_user_access", "intent_mismatch", "economic_loss",
    "reliability_failure", "functional_defect", "dependency_risk",
}

#: Ledger check id -> deep_review category (backend/app/services/audit_ledger.py CATALOG).
CHECK_CATEGORY = {
    "V1": "unauthorized_payment", "V2": "economic_loss", "V3": "economic_loss", "V4": "unauthorized_payment",
    "V5": "stellar_protocol_misuse", "V6": "replay_or_idempotency", "V7": "unauthorized_payment",
    "V8": "economic_loss", "S1": "foreign_transaction_signing", "S2": "foreign_transaction_signing",
    "S3": "stellar_protocol_misuse", "S4": "stellar_protocol_misuse", "S5": "reliability_failure",
    "S6": "account_takeover", "S7": "stellar_protocol_misuse", "S8": "reliability_failure",
    "A1": "control_bypass", "A2": "secret_exposure", "A3": "cross_user_access", "A4": "control_bypass",
    "A5": "code_execution", "A6": "ssrf", "M1": "prompt_injection", "M2": "prompt_injection",
    "M3": "prompt_injection", "M4": "intent_mismatch", "M5": "functional_defect",
}


# ----------------------------------------------------------------------------- report parsing

def unwrap(report) -> dict:
    """Saved job results nest the report under "report" or a "report_json" string."""
    if not isinstance(report, dict):
        return {}
    if isinstance(report.get("findings"), list) or isinstance(report.get("deep_review"), dict):
        return report
    if isinstance(report.get("report"), dict):
        return unwrap(report["report"])
    if isinstance(report.get("report_json"), str):
        try:
            return unwrap(json.loads(report["report_json"]))
        except json.JSONDecodeError:
            pass
    return report


def _locations(item: dict) -> list[tuple[str, int, int]]:
    texts = []
    for key in ("evidence", "location", "locations"):
        value = item.get(key)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, list):
            texts.extend(v if isinstance(v, str) else json.dumps(v) for v in value)
    locs = []
    for text in texts:
        for m in LOC_RE.finditer(text):
            start = int(m["start"])
            locs.append((m["path"].replace("\\", "/"), start, int(m["end"] or start)))
    if item.get("file") and item.get("line"):
        try:
            line = int(item["line"])
            locs.append((str(item["file"]).replace("\\", "/"), line, line))
        except (TypeError, ValueError):
            pass
    return list(dict.fromkeys(locs))


def cited_items(report) -> list[dict]:
    """Every risk finding and every failing ledger check: {source, id, category, locations}."""
    report = unwrap(report)
    items = []
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        risky = bool(f["is_risk"]) if "is_risk" in f else str(f.get("kind", "risk")) not in NON_RISK_KINDS
        if not risky:
            continue
        cat = f.get("category")
        if not cat:
            m = AI_ID_RE.search(str(f.get("id", "")))
            cat = m["cat"].replace("-", "_") if m else None
        items.append({"source": "finding", "id": str(f.get("id", "")), "category": cat,
                      "title": str(f.get("title", ""))[:120], "locations": _locations(f)})
    ledger = (report.get("deep_review") or {}).get("ledger") or {}
    for c in ledger.get("checks") or []:
        if not isinstance(c, dict) or c.get("verdict") != "fails":
            continue
        cid = str(c.get("id") or c.get("check_id") or "")
        items.append({"source": "ledger", "id": cid, "category": CHECK_CATEGORY.get(cid),
                      "title": str(c.get("title", ""))[:120], "locations": _locations(c)})
    return items


# ----------------------------------------------------------------------------- matching

def normalise(path: str, case: dict) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    subdir = case["subdir"].strip("/")
    repo_name = case["repo"].split("/")[-1]
    for prefix in (f"{repo_name}/{subdir}/", f"{subdir}/"):
        idx = path.find(prefix)
        if idx != -1 and (idx == 0 or path[idx - 1] == "/"):
            return path[idx + len(prefix):]
    return path.lstrip("/")


def same_file(cited: str, labelled: str) -> bool:
    return cited == labelled or labelled.endswith("/" + cited) or cited.endswith("/" + labelled)


def hits(items: list[dict], case: dict, ranges: list[dict], window: int, categories: set[str] | None):
    """Items citing a range within the window; categories=None ignores category,
    otherwise an item matches if its category is in the set or is unknown."""
    out = []
    for it in items:
        if categories is not None and it["category"] and it["category"] not in categories:
            continue
        for path, start, end in it["locations"]:
            p = normalise(path, case)
            if any(same_file(p, r["path"]) and start <= r["line_end"] + window and end >= r["line_start"] - window
                   for r in ranges):
                out.append({**it, "cited": f"{p}:{start}" + (f"-{end}" if end != start else "")})
                break
    return out


def case_categories(case: dict) -> set[str]:
    return {case["category"], *case.get("accept_categories", [])}


def score(cases: list[dict], reports: Path, window: int = WINDOW, require_category: bool = False,
          strict_clear: bool = False) -> dict:
    rows = []
    for case in cases:
        row = {"id": case["id"], "repo": case["repo"], "language": case["language"],
               "category": case["category"], "severity": case["severity_estimate"],
               "confidence": case["confidence"], "detected": None, "cleared": None,
               "detect_hits": [], "residual_hits": []}
        cats = case_categories(case)
        vpath = reports / f"{case['id']}.vulnerable.json"
        if vpath.is_file():
            items = cited_items(json.loads(vpath.read_text()))
            h = hits(items, case, case["files"], window, cats if require_category else None)
            row["detected"], row["detect_hits"] = bool(h), h
        fpath = reports / f"{case['id']}.fixed.json"
        if fpath.is_file():
            items = cited_items(json.loads(fpath.read_text()))
            h = hits(items, case, case.get("fixed_files") or case["files"], window, None if strict_clear else cats)
            row["cleared"], row["residual_hits"] = not h, h
        rows.append(row)

    def rate(key, subset=None):
        sel = [r for r in rows if r[key] is not None and (subset is None or subset(r))]
        return (sum(1 for r in sel if r[key]), len(sel))

    paired = [r for r in rows if r["detected"] is not None and r["cleared"] is not None]
    summary = {
        "detection": rate("detected"),
        "detection_high_confidence": rate("detected", lambda r: r["confidence"] == "high"),
        "detection_critical_high": rate("detected", lambda r: r["severity"] in ("critical", "high")),
        "clear": rate("cleared"),
        "clear_given_detected": rate("cleared", lambda r: r["detected"]),
        "fixed_pair": (sum(1 for r in paired if r["detected"] and r["cleared"]), len(paired)),
        "missing_reports": [f"{r['id']}.{k}.json" for r in rows
                            for k, v in (("vulnerable", r["detected"]), ("fixed", r["cleared"])) if v is None],
    }
    return {"window": window, "require_category": require_category, "strict_clear": strict_clear,
            "summary": summary, "cases": rows}


# ----------------------------------------------------------------------------- output

def _pct(pair) -> str:
    num, den = pair
    return f"{num}/{den} ({100 * num / den:.0f}%)" if den else "n/a"


def _mark(v) -> str:
    return "-" if v is None else ("yes" if v else "NO")


def text(result: dict) -> str:
    s = result["summary"]
    out = [f"window={result['window']} require_category={result['require_category']} "
           f"strict_clear={result['strict_clear']}",
           f"detection rate:               {_pct(s['detection'])}",
           f"  high-confidence cases:      {_pct(s['detection_high_confidence'])}",
           f"  critical/high cases:        {_pct(s['detection_critical_high'])}",
           f"clear rate:                   {_pct(s['clear'])}",
           f"  among detected cases:       {_pct(s['clear_given_detected'])}",
           f"detected and cleared (pairs): {_pct(s['fixed_pair'])}", ""]
    out.append(f"{'case':42} {'lang':10} {'sev':8} {'conf':6} {'detected':8} {'cleared':7}")
    for r in result["cases"]:
        out.append(f"{r['id']:42} {r['language']:10} {r['severity']:8} {r['confidence']:6} "
                   f"{_mark(r['detected']):8} {_mark(r['cleared']):7}")
        for h in r["detect_hits"][:3]:
            out.append(f"    + {h['source']} {h['id']} [{h['category']}] {h['cited']} {h['title']}")
        for h in r["residual_hits"][:3]:
            out.append(f"    ! still reported on fixed commit: {h['source']} {h['id']} [{h['category']}] "
                       f"{h['cited']} {h['title']}")
    if s["missing_reports"]:
        out += ["", "missing reports: " + ", ".join(s["missing_reports"])]
    return "\n".join(out)


# ----------------------------------------------------------------------------- self-test

def selftest() -> None:
    case = {"id": "demo", "repo": "o/demo", "subdir": "sdk", "language": "typescript",
            "category": "replay_or_idempotency", "accept_categories": ["unauthorized_payment"],
            "severity_estimate": "high", "confidence": "high",
            "files": [{"path": "src/server.ts", "line_start": 40, "line_end": 50}],
            "fixed_files": [{"path": "src/server.ts", "line_start": 45, "line_end": 70}]}
    case2 = {**case, "id": "demo2", "files": [{"path": "src/other.ts", "line_start": 5, "line_end": 6}],
             "fixed_files": []}
    vuln = {"findings": [
        {"id": "x-ai-replay-or-idempotency-1", "kind": "risk", "evidence": "sdk/src/server.ts:58 `verify`"},
        {"id": "gap", "kind": "evidence_gap", "evidence": "src/other.ts:5"}]}
    fixed = {"findings": [{"id": "f1", "category": "secret_exposure", "kind": "risk",
                           "evidence": "./src/server.ts:60"}],
             "deep_review": {"ledger": {"checks": [
                 {"id": "V6", "verdict": "holds", "file": "src/server.ts", "line": 50},
                 {"id": "A1", "verdict": "fails", "file": "src/server.ts", "line": 200}]}}}
    vuln2 = {"report": {"findings": [], "deep_review": {"ledger": {"checks": [
        {"id": "V7", "verdict": "fails", "file": "demo/sdk/src/other.ts", "line": 14}]}}}}
    fixed2 = {"deep_review": {"ledger": {"checks": [
        {"id": "V6", "verdict": "fails", "file": "src/other.ts", "line": 1}]}}}
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        for name, data in (("demo.vulnerable", vuln), ("demo.fixed", fixed),
                           ("demo2.vulnerable", vuln2), ("demo2.fixed", fixed2)):
            (d / f"{name}.json").write_text(json.dumps(data))
        res = score([case, case2], d)
        by = {r["id"]: r for r in res["cases"]}
        assert by["demo"]["detected"] is True              # 58 is within 10 of 40-50
        assert by["demo"]["cleared"] is True               # secret_exposure is not this case's category
        assert by["demo2"]["detected"] is True             # failing ledger check, prefixed path
        assert by["demo2"]["cleared"] is False             # V6 fails at the same place
        strict = score([case, case2], d, strict_clear=True)
        assert {r["id"]: r for r in strict["cases"]}["demo"]["cleared"] is False
        cat = score([case, case2], d, require_category=True)
        assert {r["id"]: r for r in cat["cases"]}["demo"]["detected"] is True
        tight = score([case, case2], d, window=5)
        assert {r["id"]: r for r in tight["cases"]}["demo"]["detected"] is False
        assert res["summary"]["detection"] == (2, 2) and res["summary"]["fixed_pair"] == (1, 2)
        assert "demo" in text(res)
    real = Path(__file__).resolve().parent / "cases.json"
    if real.is_file():
        seen = set()
        for c in json.loads(real.read_text()):
            assert c["id"] not in seen, c["id"]
            seen.add(c["id"])
            for key in ("repo", "subdir", "vulnerable_commit", "fixed_commit", "language", "category",
                        "severity_estimate", "files", "summary", "fix_summary", "evidence_url", "confidence"):
                assert key in c, f"{c['id']}: missing {key}"
            assert re.fullmatch(r"[0-9a-f]{40}", c["vulnerable_commit"]) and re.fullmatch(r"[0-9a-f]{40}", c["fixed_commit"])
            assert c["confidence"] in ("high", "medium"), c["id"]
            assert case_categories(c) <= CATEGORIES, f"{c['id']}: unknown category"
            for r in c["files"] + c.get("fixed_files", []):
                assert 1 <= r["line_start"] <= r["line_end"], f"{c['id']}: bad range {r}"
    print("selftest passed")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", type=Path, default=Path(__file__).resolve().parent / "cases.json")
    ap.add_argument("--reports", type=Path, help="directory of <case_id>.vulnerable.json / <case_id>.fixed.json")
    ap.add_argument("--window", type=int, default=WINDOW, help="line tolerance (default 10)")
    ap.add_argument("--require-category", action="store_true",
                    help="detection also needs the case's category or an accepted one")
    ap.add_argument("--strict-clear", action="store_true", help="any finding at the fixed location blocks clearing")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    if not args.reports:
        ap.error("--reports is required")
    result = score(json.loads(args.cases.read_text()), args.reports, args.window, args.require_category,
                   args.strict_clear)
    print(json.dumps(result, indent=2) if args.json else text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
