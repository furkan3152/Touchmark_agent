"""Audit any agent reference: a registry agent id, a C.../G... address, a GitHub URL, a card or an endpoint.

    python scripts/audit_agent.py REFERENCE [--network testnet|mainnet] [--purpose "..."]
                                            [--resolve-only] [--no-deep] [--out report.json]

The reference is resolved first and every step says what was proven (registry record,
card hash, endpoint hash, WASM hash, build attestation). Source is audited only at a
pinned commit; nothing is executed. Without source, only on-chain evidence is reviewed
and the review cannot pass.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.config import Settings  # noqa: E402
from backend.app.services.agent_resolver import AgentResolver, audit_reference  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reference")
    parser.add_argument("--network", default="testnet", choices=["testnet", "mainnet"])
    parser.add_argument("--purpose", default="")
    parser.add_argument("--resolve-only", action="store_true")
    parser.add_argument("--no-deep", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    settings = Settings()
    if args.resolve_only:
        print(json.dumps(asyncio.run(AgentResolver(settings, args.network).resolve(args.reference)), indent=1))
        return
    result = asyncio.run(audit_reference(args.reference, settings, network=args.network,
                                         deep=not args.no_deep, purpose=args.purpose))
    report = result["report"]
    if args.out:
        Path(args.out).write_text(result["report_json"])
    print(json.dumps({"decision": result["decision"], "score": report["result"]["overall_score"],
                      "resolution": [f"{s['check']}: {s['result']}" for s in report["resolution"]["steps"]],
                      "source": report["resolution"]["source"],
                      "priority": report["priority_finding_ids"], "report_sha256": result["report_sha256"]}, indent=1))


if __name__ == "__main__":
    main()
