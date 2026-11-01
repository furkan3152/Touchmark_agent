#!/usr/bin/env python3
"""Score Touchmark audit reports against the benchmark ground-truth labels.

    python3 score.py --labels labels reports/invoice-settler-run1.json reports/invoice-settler-run2.json ...
    python3 score.py --labels labels --markdown reports/*.json
    python3 score.py --selftest

Stdlib only (Python 3.11+). See README.md for the matching rules.
"""
from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
import tempfile
from pathlib import Path

TOLERANCE = 5
HIGH = {"critical", "high"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
NON_RISK_KINDS = {"evidence_gap", "warning", "info", "pass"}

# path:line or path:line-line; the path must have an extension. Backticked quotes follow.
LOC_RE = re.compile(r"(?P<path>[A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+):(?P<start>\d+)(?:-(?P<end>\d+))?")
AI_ID_RE = re.compile(r"-ai-(?P<cat>[a-z][a-z-]*?)-\d+$")
AGENT_PREFIX_RE = re.compile(r"(?:^|/)research/benchmark/agents/(?P<agent>[^/]+)/|(?:^|/)agents/(?P<agent2>[^/]+)/")


# ----------------------------------------------------------------------------- loading

def load_labels(directory: Path) -> dict[str, dict]:
    labels = {}
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text())
        if "agent" in data and "defects" in data:
            labels[data["agent"]] = data
    if not labels:
        raise SystemExit(f"no label files found in {directory}")
    return labels


def extract_findings(report) -> list[dict]:
    """Touchmark reports put findings at the top level; saved job results nest them under
    "report" (or a "report_json" string). Accept all three."""
    if isinstance(report, list):
        return report
    if not isinstance(report, dict):
        return []
    if isinstance(report.get("findings"), list):
        return report["findings"]
    inner = report.get("report")
    if isinstance(inner, dict) and isinstance(inner.get("findings"), list):
        return inner["findings"]
    if isinstance(report.get("report_json"), str):
        try:
            return extract_findings(json.loads(report["report_json"]))
        except json.JSONDecodeError:
            pass
    return []


def finding_locations(finding: dict) -> list[tuple[str, int, int]]:
    texts = []
    for key in ("evidence", "location", "locations"):
        value = finding.get(key)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, list):
            texts.extend(str(v) for v in value)
    locs = []
    for text in texts:
        for m in LOC_RE.finditer(text):
            start = int(m["start"])
            locs.append((m["path"].replace("\\", "/"), start, int(m["end"] or start)))
    if finding.get("file") and finding.get("line"):
        try:
            line = int(finding["line"])
            locs.append((str(finding["file"]), line, line))
        except (TypeError, ValueError):
            pass
    return list(dict.fromkeys(locs))


def finding_category(finding: dict, categories: set[str]) -> str | None:
    if finding.get("category"):
        return str(finding["category"])
    m = AI_ID_RE.search(str(finding.get("id", "")))
    if m:
        cat = m["cat"].replace("-", "_")
        if not categories or cat in categories:
            return cat
    return None


def is_risk(finding: dict) -> bool:
    if "is_risk" in finding:
        return bool(finding["is_risk"])
    return str(finding.get("kind", "risk")) not in NON_RISK_KINDS


def infer_agent(report, findings: list[dict], path: Path, labels: dict[str, dict]) -> str | None:
    votes: dict[str, int] = {}
    for f in findings:
        for p, _, _ in finding_locations(f):
            m = AGENT_PREFIX_RE.search(p)
            name = m and (m["agent"] or m["agent2"])
            if name in labels:
                votes[name] = votes.get(name, 0) + 1
    if votes:
        return max(votes, key=votes.get)
    blob = json.dumps(report)[:20000] if isinstance(report, dict) else ""
    for name in sorted(labels, key=len, reverse=True):
        if f"agents/{name}" in blob:
            return name
    for name in sorted(labels, key=len, reverse=True):
        if name in path.name:
            return name
    return None


# ----------------------------------------------------------------------------- matching

def normalise(path: str, agent: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    for prefix in (f"research/benchmark/agents/{agent}/", f"benchmark/agents/{agent}/", f"agents/{agent}/", f"{agent}/"):
        idx = path.find(prefix)
        if idx != -1 and (idx == 0 or path[idx - 1] == "/"):
            return path[idx + len(prefix):]
    return path.lstrip("/")


def same_file(cited: str, labelled: str) -> bool:
    return cited == labelled or labelled.endswith("/" + cited) or cited.endswith("/" + labelled)


def label_ranges(label: dict):
    for d in label["defects"]:
        yield ("defect", d["id"], d["file"], d["line_start"], d["line_end"])
        for alt in d.get("alt_locations", []):
            yield ("defect", d["id"], alt["file"], alt["line_start"], alt["line_end"])
    for k in label.get("decoys", []):
        yield ("decoy", k["id"], k["file"], k["line_start"], k["line_end"])


def best_match(label: dict, file: str, start: int, end: int):
    """Nearest labelled range within tolerance; distance 0 when the cited span overlaps.
    Ties go to defects."""
    best = None
    for kind, id_, lfile, ls, le in label_ranges(label):
        if not same_file(file, lfile):
            continue
        if end < ls - TOLERANCE or start > le + TOLERANCE:
            continue
        distance = 0 if (start <= le and end >= ls) else min(abs(start - le), abs(end - ls))
        key = (distance, 0 if kind == "defect" else 1)
        if best is None or key < best[0]:
            best = (key, kind, id_)
    return None if best is None else (best[1], best[2])


def score_report(label: dict, findings: list[dict], categories: set[str]) -> dict:
    agent = label["agent"]
    defects = {d["id"]: d for d in label["defects"]}
    decoys = {k["id"] for k in label.get("decoys", [])}
    found: dict[str, list[str]] = {}
    decoy_hits: dict[str, list[str]] = {}
    matched_findings, decoy_fp_findings, unlabelled = [], [], []
    category_pairs = []

    for f in findings:
        if not is_risk(f):
            continue
        fid = str(f.get("id", "?"))
        hit_defects, hit_decoys = set(), set()
        for path, s, e in finding_locations(f):
            m = best_match(label, normalise(path, agent), s, e)
            if m is None:
                continue
            (hit_defects if m[0] == "defect" else hit_decoys).add(m[1])
        if hit_defects:
            matched_findings.append(fid)
            cat = finding_category(f, categories)
            for did in sorted(hit_defects):
                found.setdefault(did, []).append(fid)
                d = defects[did]
                ok = cat is not None and (cat == d["category"] or cat in d.get("accept_categories", []))
                category_pairs.append({"finding": fid, "defect": did, "finding_category": cat,
                                       "label_category": d["category"], "agree": ok})
        elif hit_decoys:
            decoy_fp_findings.append(fid)
            for kid in hit_decoys:
                decoy_hits.setdefault(kid, []).append(fid)
        elif SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) >= SEVERITY_RANK["medium"]:
            unlabelled.append({"id": fid, "severity": f.get("severity"), "title": f.get("title", ""),
                               "evidence": str(f.get("evidence", ""))[:200]})

    high = [d for d in defects.values() if d["severity"] in HIGH]
    n_matched, n_fp = len(matched_findings), len(decoy_fp_findings)
    agree = [p for p in category_pairs if p["agree"]]
    return {
        "agent": agent,
        "language": label.get("language"),
        "defects": len(defects),
        "defects_found": sorted(found),
        "defects_missed": sorted(set(defects) - set(found)),
        "recall": _ratio(len(found), len(defects)),
        "recall_high": _ratio(len([d for d in high if d["id"] in found]), len(high)),
        "high_defects": len(high),
        "decoys": len(decoys),
        "decoys_hit": sorted(decoy_hits),
        "decoy_fp_rate": _ratio(len(decoy_hits), len(decoys)),
        "matched_findings": n_matched,
        "decoy_fp_findings": n_fp,
        "precision_lower_bound": _ratio(n_matched, n_matched + n_fp),
        "category_agreement": _ratio(len(agree), len(category_pairs)),
        "category_pairs": category_pairs,
        "unlabelled_count": len(unlabelled),
        "unlabelled": unlabelled,
        "finding_to_defects": found,
        "finding_to_decoys": decoy_hits,
    }


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


def jaccard(a: set, b: set) -> float:
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def consistency(runs: list[dict]) -> dict | None:
    if len(runs) < 2:
        return None
    sets = [set(r["defects_found"]) for r in runs]
    pairs = [jaccard(a, b) for a, b in itertools.combinations(sets, 2)]
    union, inter = set().union(*sets), set.intersection(*sets)
    return {"runs": len(runs), "mean_pairwise_jaccard": round(sum(pairs) / len(pairs), 4),
            "jaccard_all_runs": round(jaccard(inter, union), 4) if union else 1.0,
            "always_found": sorted(inter), "unstable": sorted(union - inter),
            "per_run_found": [sorted(s) for s in sets]}


def aggregate(results: list[dict]) -> dict:
    def total(key):
        return sum(r[key] for r in results)
    found = sum(len(r["defects_found"]) for r in results)
    high_found = 0
    for r in results:
        high_found += round((r["recall_high"] or 0) * r["high_defects"])
    m, fp = total("matched_findings"), total("decoy_fp_findings")
    pairs = [p for r in results for p in r["category_pairs"]]
    return {"reports": len(results), "defects": total("defects"), "defects_found": found,
            "recall": _ratio(found, total("defects")),
            "recall_high": _ratio(high_found, total("high_defects")),
            "decoys": total("decoys"), "decoys_hit": sum(len(r["decoys_hit"]) for r in results),
            "decoy_fp_rate": _ratio(sum(len(r["decoys_hit"]) for r in results), total("decoys")),
            "precision_lower_bound": _ratio(m, m + fp),
            "category_agreement": _ratio(len([p for p in pairs if p["agree"]]), len(pairs)),
            "unlabelled_count": total("unlabelled_count")}


def score(labels: dict[str, dict], report_paths: list[Path], agent_override: str | None = None) -> dict:
    categories = {c for lab in labels.values() for d in lab["defects"]
                  for c in [d["category"], *d.get("accept_categories", [])]}
    runs: dict[str, list[dict]] = {}
    skipped = []
    for path in report_paths:
        report = json.loads(path.read_text())
        findings = extract_findings(report)
        agent = agent_override or infer_agent(report, findings, path, labels)
        if agent not in labels:
            skipped.append({"report": str(path), "reason": "could not determine agent (use --agent)"})
            continue
        result = score_report(labels[agent], findings, categories)
        result["report"] = str(path)
        runs.setdefault(agent, []).append(result)
    per_agent = {}
    for agent, results in runs.items():
        per_agent[agent] = {"language": labels[agent].get("language"), "runs": results,
                            "summary": aggregate(results), "consistency": consistency(results)}
    all_results = [r for rs in runs.values() for r in rs]
    return {"agents": per_agent, "overall": aggregate(all_results) if all_results else None, "skipped": skipped}


# ----------------------------------------------------------------------------- output

def _fmt(v) -> str:
    return "n/a" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))


def markdown(result: dict) -> str:
    out = ["| agent | language | run | recall | recall@high | decoy FP rate | precision LB | category agree | unlabelled | missed |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for agent, data in sorted(result["agents"].items()):
        for i, r in enumerate(data["runs"], 1):
            out.append(f"| {agent} | {data['language']} | {i} | {_fmt(r['recall'])} | {_fmt(r['recall_high'])} | "
                       f"{_fmt(r['decoy_fp_rate'])} | {_fmt(r['precision_lower_bound'])} | {_fmt(r['category_agreement'])} | "
                       f"{r['unlabelled_count']} | {', '.join(r['defects_missed']) or '-'} |")
    o = result["overall"]
    if o:
        out.append(f"| **overall** | | {o['reports']} | {_fmt(o['recall'])} | {_fmt(o['recall_high'])} | "
                   f"{_fmt(o['decoy_fp_rate'])} | {_fmt(o['precision_lower_bound'])} | {_fmt(o['category_agreement'])} | "
                   f"{o['unlabelled_count']} | |")
    cons = [(a, d["consistency"]) for a, d in sorted(result["agents"].items()) if d["consistency"]]
    if cons:
        out += ["", "| agent | runs | mean pairwise Jaccard | Jaccard (all runs) | unstable defects |",
                "| --- | --- | --- | --- | --- |"]
        for agent, c in cons:
            out.append(f"| {agent} | {c['runs']} | {_fmt(c['mean_pairwise_jaccard'])} | {_fmt(c['jaccard_all_runs'])} | "
                       f"{', '.join(c['unstable']) or '-'} |")
    unl = [(a, r) for a, d in sorted(result["agents"].items()) for r in d["runs"] if r["unlabelled"]]
    if unl:
        out += ["", "Unlabelled findings (severity >= medium) for manual triage:", ""]
        for agent, r in unl:
            for u in r["unlabelled"]:
                out.append(f"- {agent} ({Path(r['report']).name}): [{u['severity']}] {u['id']} {u['title']} -- {u['evidence']}")
    for s in result["skipped"]:
        out.append(f"\nSkipped {s['report']}: {s['reason']}")
    return "\n".join(out)


# ----------------------------------------------------------------------------- self-test

def selftest() -> None:
    label = {
        "agent": "demo-agent", "language": "python",
        "defects": [
            {"id": "D1", "category": "unauthorized_payment", "severity": "critical", "file": "app/main.py",
             "line_start": 40, "line_end": 45, "summary": "", "accept_categories": ["control_bypass"],
             "alt_locations": [{"file": "app/ledger.py", "line_start": 10, "line_end": 11}]},
            {"id": "D2", "category": "replay_or_idempotency", "severity": "high", "file": "app/main.py",
             "line_start": 70, "line_end": 72, "summary": "", "accept_categories": []},
            {"id": "D3", "category": "stellar_protocol_misuse", "severity": "medium", "file": "app/ledger.py",
             "line_start": 60, "line_end": 60, "summary": "", "accept_categories": []},
        ],
        "decoys": [
            {"id": "K1", "file": "app/ledger.py", "line_start": 20, "line_end": 22, "why_safe": "",
             "control_file": "app/policy.py", "control_line": 5},
            {"id": "K2", "file": "app/main.py", "line_start": 55, "line_end": 56, "why_safe": "",
             "control_file": "app/auth.py", "control_line": 9},
        ],
    }
    pre = "research/benchmark/agents/demo-agent/"
    run1 = {"findings": [
        # D1 via a prefixed path, category from the deep-review id
        {"id": "security-ai-unauthorized-payment-0", "severity": "critical", "title": "refund pays anyone",
         "evidence": f"{pre}app/main.py:43 `async def refund`", "auditor": "deep-review", "kind": "risk"},
        # D2 within tolerance (line 76 is 4 past line_end 72), wrong category
        {"id": "security-ai-secret-exposure-1", "severity": "high", "title": "double settle",
         "evidence": "app/main.py:76 `invoice.status = 'paid'`", "kind": "risk"},
        # decoy false positive (K1), relative path
        {"id": "security-ai-foreign-transaction-signing-2", "severity": "high", "title": "signs",
         "evidence": "app/ledger.py:21 `tx.sign(kp)`", "kind": "risk"},
        # unlabelled medium
        {"id": "reliability-ai-functional-defect-3", "severity": "medium", "title": "something else",
         "evidence": "app/store.py:5 `x`", "kind": "risk"},
        # evidence gaps are ignored even when they cite a decoy
        {"id": "gap", "severity": "medium", "title": "gap", "evidence": "app/main.py:55", "kind": "evidence_gap"},
        # low unlabelled is not listed
        {"id": "low-1", "severity": "low", "title": "nit", "evidence": "app/store.py:9", "kind": "risk"},
    ]}
    run2 = {"subject": "https://github.com/x/y/tree/main/research/benchmark/agents/demo-agent", "report": {"findings": [
        # D1 through its alternate location, several path:line pairs; second pair hits decoy K1 but the
        # finding still counts as matched because it also cites a defect
        {"id": "security-ai-control-bypass-0", "severity": "critical", "title": "refund",
         "evidence": "app/ledger.py:10 `send_refund` app/ledger.py:22 `sign`", "is_risk": True},
        # D3, category via explicit field
        {"id": "x", "category": "stellar_protocol_misuse", "severity": "medium", "title": "asset code",
         "evidence": "./app/ledger.py:58-61 `asset_code`", "is_risk": True},
        # decoy K2, line 52 is nearer to K2 (55-56) than nothing else
        {"id": "security-ai-unauthorized-payment-2", "severity": "high", "title": "route",
         "evidence": "main.py:52 `@app.post`", "is_risk": True},
    ]}}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "labels").mkdir()
        (tmp / "labels" / "demo-agent.json").write_text(json.dumps(label))
        (tmp / "demo-agent-run1.json").write_text(json.dumps(run1))
        (tmp / "run2.json").write_text(json.dumps(run2))
        labels = load_labels(tmp / "labels")
        res = score(labels, [tmp / "demo-agent-run1.json", tmp / "run2.json"])
    runs = res["agents"]["demo-agent"]["runs"]
    r1, r2 = runs
    assert r1["defects_found"] == ["D1", "D2"], r1["defects_found"]
    assert r1["recall"] == round(2 / 3, 4) and r1["recall_high"] == 1.0
    assert r1["decoys_hit"] == ["K1"] and r1["decoy_fp_rate"] == 0.5
    assert r1["matched_findings"] == 2 and r1["decoy_fp_findings"] == 1
    assert r1["precision_lower_bound"] == round(2 / 3, 4)
    assert r1["unlabelled_count"] == 1 and r1["unlabelled"][0]["id"] == "reliability-ai-functional-defect-3"
    assert r1["category_agreement"] == 0.5, r1["category_pairs"]
    assert r2["defects_found"] == ["D1", "D3"], r2["defects_found"]
    assert r2["recall_high"] == 0.5
    assert r2["decoys_hit"] == ["K2"] and r2["precision_lower_bound"] == round(2 / 3, 4)
    assert r2["category_agreement"] == 1.0
    cons = res["agents"]["demo-agent"]["consistency"]
    assert cons["mean_pairwise_jaccard"] == round(1 / 3, 4), cons
    assert cons["unstable"] == ["D2", "D3"] and cons["always_found"] == ["D1"]
    o = res["overall"]
    assert o["recall"] == round(4 / 6, 4) and o["recall_high"] == 0.75 and o["decoy_fp_rate"] == 0.5
    md = markdown(res)
    assert "| demo-agent | python | 1 |" in md and "unstable" in md
    assert normalise("research/benchmark/agents/demo-agent/app/x.py", "demo-agent") == "app/x.py"
    assert normalise("/tmp/clone/research/benchmark/agents/demo-agent/app/x.py", "demo-agent") == "app/x.py"
    _check_real_labels()
    print("selftest passed")


def _check_real_labels() -> None:
    """When run inside the benchmark, verify every label range points at real lines."""
    root = Path(__file__).resolve().parent
    if not (root / "labels").is_dir() or not (root / "agents").is_dir():
        return
    for name, label in load_labels(root / "labels").items():
        for kind, id_, file, s, e in label_ranges(label):
            path = root / "agents" / name / file
            assert path.is_file(), f"{name} {id_}: missing {file}"
            n = len(path.read_text().splitlines())
            assert 1 <= s <= e <= n, f"{name} {id_}: {file}:{s}-{e} outside 1..{n}"
        for k in label.get("decoys", []):
            cpath = root / "agents" / name / k["control_file"]
            assert cpath.is_file() and 1 <= k["control_line"] <= len(cpath.read_text().splitlines()), \
                f"{name} {k['id']}: bad control location"
        assert not list((root / "agents" / name).rglob("*.json")) or all(
            "defects" not in p.read_text() for p in (root / "agents" / name).rglob("*.json")), \
            f"{name}: label-like file inside the agent folder"


# ----------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="*", type=Path, help="Touchmark report JSON files")
    ap.add_argument("--labels", type=Path, default=Path(__file__).resolve().parent / "labels")
    ap.add_argument("--agent", help="force the agent name for all reports")
    ap.add_argument("--markdown", action="store_true", help="print markdown tables instead of JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    if not args.reports:
        ap.error("give one or more report files (or --selftest)")
    result = score(load_labels(args.labels), args.reports, args.agent)
    print(markdown(result) if args.markdown else json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
