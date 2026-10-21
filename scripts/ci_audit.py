#!/usr/bin/env python3
"""Audit a repository in CI: check its .tmark, run the deterministic analysis, annotate the code.

    python scripts/ci_audit.py [PATH] [--fail-on needs_fixes|never] [--annotate critical|high|medium|low]

In GitHub Actions it writes annotations on the cited lines, a job summary and the outputs
decision, score, tmark and report. Elsewhere it prints the same summary. It exits 1 when
the decision is needs_fixes and --fail-on is needs_fixes. Repository code is parsed, never
imported or executed, and no model or network call is made.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.services import tmark  # noqa: E402
from backend.app.services.repo_audit import audit_repository  # noqa: E402

SEVERITIES = ["info", "low", "medium", "high", "critical"]
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "notice", "info": "notice"}
_LOCATION = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]+):(\d+)")
DOCS = "https://github.com/furkan3152/Touchmark_agent/blob/main/docs/TMARK.md"


def _escape(text: str, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def _annotation(level: str, message: str, title: str, file: str = "", line: str = "") -> str:
    where = f"file={_escape(file, True)},line={line}," if file else ""
    return f"::{level} {where}title={_escape(title, True)}::{_escape(message)}"


def _location(evidence: str, root: Path) -> tuple[str, str]:
    for match in _LOCATION.finditer(evidence or ""):
        if (root / match.group(1)).is_file():
            return match.group(1), match.group(2)
    return "", ""


def _tmark_state(root: Path) -> tuple[str, list[str], tmark.Tmark | None]:
    file = root / tmark.FILE_NAME
    if not file.is_file():
        return "missing", [], None
    parsed, errors = tmark.parse(file.read_text(errors="replace"))
    return ("valid" if parsed else "invalid"), errors, parsed


def _summary(result: dict, state: str, errors: list[str], shown: list[dict], prefix: str) -> str:
    report = result["report"]
    decision, score = result["decision"], report["result"]["overall_score"]
    mark = {"pass": "✅ pass", "needs_fixes": "❌ needs fixes", "needs_evidence": "⚠️ needs evidence"}.get(decision, decision)
    risks = [f for f in report["findings"] if f.get("kind") == "risk"]
    gaps = [f for f in report["findings"] if f.get("kind") == "evidence_gap"]
    lines = [f"## Touchmark: {mark} · score {score}", ""]
    lines.append({"valid": "`.tmark` is valid and was checked against the code.",
                  "missing": f"No `.tmark` at the repository root. Run `python scripts/tmark.py init` ([format]({DOCS})).",
                  "invalid": f"`.tmark` is invalid and was not used ([format]({DOCS})):"}[state])
    lines += [f"- `{e}`" for e in errors[:10]]
    lines += ["", f"{len(risks)} risk(s), {len(gaps)} evidence gap(s). Deterministic analysis only; "
              "the hosted audit adds model review and independent verification.", ""]
    if shown:
        lines += ["| Severity | Finding | Where |", "|---|---|---|"]
        for f in shown[:40]:
            file, line = f["_where"]
            where = f"`{prefix}{file}:{line}`" if file else ""
            lines.append(f"| {f['severity']} | {f['title'].replace('|', '/')} | {where} |")
        if len(shown) > 40:
            lines.append(f"| | {len(shown) - 40} more in the report JSON | |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--fail-on", choices=["needs_fixes", "never"], default="needs_fixes")
    parser.add_argument("--annotate", choices=SEVERITIES[1:], default="medium")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)
    root = Path(args.path).resolve()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE") or root).resolve()
    prefix = f"{root.relative_to(workspace).as_posix()}/" if root != workspace and root.is_relative_to(workspace) else ""

    state, errors, parsed = _tmark_state(root)
    name = parsed.agent.name if parsed else root.name
    purpose = parsed.agent.purpose if parsed else ""
    # The audited repository's own .env is never read: Settings come from this process only.
    result = asyncio.run(audit_repository(root, name=name, purpose=purpose, settings=Settings(_env_file=None), deep=False))
    report = result["report"]

    floor = SEVERITIES.index(args.annotate)
    shown = []
    for f in report["findings"]:
        if f.get("kind") == "risk" and SEVERITIES.index(f["severity"]) >= floor:
            shown.append({**f, "_where": _location(f.get("evidence", ""), root)})
    shown.sort(key=lambda f: -SEVERITIES.index(f["severity"]))

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    out = Path(args.out or os.path.join(os.environ.get("RUNNER_TEMP") or ".", "touchmark-report.json"))
    out.write_text(result["report_json"])
    summary = _summary(result, state, errors, shown, prefix)
    if in_actions:
        for err in errors:
            print(_annotation("error", err, ".tmark is invalid", f"{prefix}{tmark.FILE_NAME}", "1"))
        for f in shown:
            file, line = f["_where"]
            message = f"{f['detail']}\n\nFix: {f.get('remediation', '')}"
            print(_annotation(LEVEL[f["severity"]], message, f"Touchmark: {f['title']}",
                              f"{prefix}{file}" if file else "", line))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
                fh.write(summary)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
                fh.write(f"decision={result['decision']}\nscore={report['result']['overall_score']}\n"
                         f"tmark={state}\nreport={out}\n")
    else:
        print(summary)
        print(json.dumps({"decision": result["decision"], "score": report["result"]["overall_score"],
                          "tmark": state, "report": str(out)}))
    return 1 if args.fail_on == "needs_fixes" and result["decision"] == "needs_fixes" else 0


if __name__ == "__main__":
    sys.exit(main())
