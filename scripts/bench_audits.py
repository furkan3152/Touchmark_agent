#!/usr/bin/env python3
"""Agent verification parsing benchmark.

The default run is fully offline. `--address G...` or `--address C...`
can be added for read-only purposes; this tool does not include a signer and does not send transactions.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CORPUS = [
    ("payroll_agent", "production quality"),
    ("research_scribe", "read-only"),
    ("treasury_rebalancer", "partial policy"),
    ("lending_optimizer", "known loopholes"),
    ("mev_sniper", "intentional critical vulnerability"),
    ("airdrop_scam", "intentional scam"),
]


async def run(args: argparse.Namespace) -> int:
    from backend.app.config import Settings
    from backend.app.ingestion import IngestionService, IngestRequest
    from backend.app.models import AuditTier
    from backend.app.services.pipeline import AuditPipeline

    with tempfile.TemporaryDirectory(prefix="agentveritas-stellar-bench-") as temp:
        settings = Settings(
            stellar_network=args.network,
            allow_mainnet=False,
            enable_audit_escrow=False,
            llm_provider="",
            llm_api_key="",
            pinata_jwt="",
            screening_provider="none",
            allow_local_path_ingest=True,
            data_dir=temp,
            event_database=str(Path(temp) / "events.db"),
            _env_file=None,
        )
        pipeline = AuditPipeline(settings)
        ingestion = IngestionService(settings)
        rows: list[dict] = []

        async def audit(req: IngestRequest, label: str, note: str) -> None:
            artifact = await ingestion.ingest(req)
            pipeline.store.put_agent(artifact)
            job = pipeline.create_job(artifact.id, AuditTier.DEEP)
            job = await pipeline.run_job(job.id)
            if not job.report:
                rows.append({"label": label, "error": job.error or "no report"})
                return
            report = job.report
            rows.append(
                {
                    "label": label,
                    "note": note,
                    "score": report.overall_score,
                    "badge": report.badge.value,
                    "findings": len(report.findings),
                    "attestation": report.attestation.mode if report.attestation else "none",
                    "confirmed": bool(report.attestation and report.attestation.confirmed),
                }
            )

        for name, note in CORPUS:
            await audit(
                IngestRequest(kind="repo", local_path=str(ROOT / "examples" / "corpus" / name)),
                name,
                note,
            )
        for name in ("safe_agent", "vulnerable_agent"):
            await audit(
                IngestRequest(kind="repo", local_path=str(ROOT / "examples" / name)),
                name,
                "baseline",
            )
        for index, address in enumerate(args.address, 1):
            await audit(
                IngestRequest(kind="onchain_address", address=address),
                f"address-{index}",
                "read-only network input",
            )

    print(f"{'target':<24}{'score':>8}{'badge':>13}{'findings':>10}{'attest':>13}")
    print("-" * 68)
    for row in rows:
        if "error" in row:
            print(f"{row['label']:<24} ERROR: {row['error']}")
            continue
        print(
            f"{row['label']:<24}{row['score']:>8.1f}{row['badge']:>13}"
            f"{row['findings']:>10}{row['attestation']:>13}"
        )

    by_label = {row["label"]: row for row in rows if "score" in row}
    safe = by_label.get("safe_agent")
    vulnerable = by_label.get("vulnerable_agent")
    spread = (safe["score"] - vulnerable["score"]) if safe and vulnerable else 0.0
    no_false_chain_claim = all(not row.get("confirmed", False) for row in rows)
    ok = not any("error" in row for row in rows) and spread >= 25 and no_false_chain_claim
    print(f"\nsafe-vulnerable spread: {spread:.1f} (expected >= 25)")
    print("onchain success claim: none" if no_false_chain_claim else "ERROR: unverified claim")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", choices=("offline", "testnet"), default="offline")
    parser.add_argument("--address", action="append", default=[], help="read-only G.../C... target")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
