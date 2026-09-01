"""Audits a single target and dumps the findings along with their evidence grade.

Usage:  python scripts/explain_audit.py examples/corpus/airdrop_scam
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
async def main(path: str) -> None:
    from backend.app.config import Settings
    from backend.app.ingestion import IngestionService, IngestRequest
    from backend.app.models import AuditTier
    from backend.app.services.pipeline import AuditPipeline

    temp = tempfile.TemporaryDirectory(prefix="agentveritas-stellar-explain-")
    settings = Settings(
        stellar_network="offline",
        enable_audit_escrow=False,
        llm_provider="",
        llm_api_key="",
        pinata_jwt="",
        screening_provider="none",
        allow_local_path_ingest=True,
        data_dir=temp.name,
        event_database=str(Path(temp.name) / "events.db"),
        _env_file=None,
    )
    pipeline = AuditPipeline(settings)
    ingestion = IngestionService(settings)

    artifact = await ingestion.ingest(IngestRequest(kind="repo", local_path=path))
    pipeline.store.put_agent(artifact)
    job = await pipeline.run_job(pipeline.create_job(artifact.id, AuditTier.DEEP).id)
    r = job.report
    assert r is not None

    print(f"\n{artifact.name} · score {r.overall_score} · {r.badge.value} · σ={r.disagreement_index}")
    for d in r.dimension_scores:
        print(f"  {d.dimension.value:<12}{d.score:>7.1f}  weight {d.weight}")

    print(f"\n{len(r.findings)} findings (severity · evidence · blocks-badge):")
    for f in sorted(r.findings, key=lambda x: x.severity.value):
        blocks = "BLOCKS" if f.evidence_grade.blocks_badge else "soft"
        print(f"  [{f.severity.value:<8}] {f.evidence_grade.value:<9} {blocks:<8} {f.id} · {f.title}")

    print("\nnotes:")
    for n in r.judge_notes:
        print(f"  · {n}")
    temp.cleanup()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "examples/corpus/airdrop_scam"))
