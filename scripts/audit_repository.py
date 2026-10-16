"""Audit a local agent repository checkout with the full Veritas pipeline.

    python scripts/audit_repository.py PATH --name NAME --purpose "..." \
        [--forbid "goal" ...] [--reference https://github.com/o/r] [--revision SHA] \
        [--address G...] [--agent-key G...] [--network testnet|mainnet] [--no-deep] [--out report.json]

Deep review runs when ENABLE_DEEP_REVIEW and an Anthropic key are configured.
Repository code is parsed, never imported or executed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.services.repo_audit import audit_repository  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--name", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--forbid", action="append", default=[])
    parser.add_argument("--reference", default="")
    parser.add_argument("--revision", default="")
    parser.add_argument("--address", default="")
    parser.add_argument("--agent-key", default="")
    parser.add_argument("--network", default="testnet", choices=["testnet", "mainnet"])
    parser.add_argument("--no-deep", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    result = asyncio.run(audit_repository(
        args.path, name=args.name, purpose=args.purpose, forbidden_goals=args.forbid, settings=Settings(),
        network=args.network, stellar_address=args.address, agent_signing_key=args.agent_key,
        deep=not args.no_deep, source_reference=args.reference, revision=args.revision))
    report = result["report"]
    if args.out:
        Path(args.out).write_text(result["report_json"])
    summary = {
        "decision": result["decision"], "score": report["result"]["overall_score"],
        "badge": report["result"]["badge"], "priority": report["priority_finding_ids"],
        "deep_review": {k: report["deep_review"].get(k) for k in ("status", "turns", "coverage", "passes", "usage")},
        "selection": {k: report["repository"][k] for k in ("source_files_selected", "complete")},
        "report_sha256": result["report_sha256"],
    }
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
