#!/usr/bin/env python3
"""Calibrate the independent finding verifier against hand-labelled findings.

Every finding in the open-source study was labelled by hand (TRUE, PARTIAL, FALSE,
UNVERIFIABLE). This script runs the verifier on a sample of them, with the source at
the same commit, and measures how often it agrees with the hand labels. Only aggregate
numbers are written to the public file; per-row results stay in data/ because they
describe unpublished vulnerabilities.

    python scripts/calibrate_verifier.py --dataset data/oss-study-2026-10-16.json \
        --clones /path/to/clones --sample-true 42
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.models import Dimension, Finding, Severity  # noqa: E402
from backend.app.services.finding_verifier import FindingVerifier, VerificationRun  # noqa: E402
from backend.app.services.repo_audit import select_repository  # noqa: E402

HUMAN_TO_VERIFIER = {"TRUE": "confirmed", "PARTIAL": "partial", "FALSE": "refuted", "UNVERIFIABLE": "unverifiable"}


def real(label: str) -> bool | None:
    """Whether a verdict says the issue is real; None when undecided."""
    return {"confirmed": True, "partial": True, "refuted": False}.get(label)


def kappa(pairs: list[tuple[bool, bool]]) -> float | None:
    n = len(pairs)
    if not n:
        return None
    observed = sum(a == b for a, b in pairs) / n
    pa, pb = sum(a for a, _ in pairs) / n, sum(b for _, b in pairs) / n
    expected = pa * pb + (1 - pa) * (1 - pb)
    return round((observed - expected) / (1 - expected), 3) if expected < 1 else None


def metrics(rows: list[dict]) -> dict:
    confusion = collections.Counter(f"{r['human']}->{r['verifier']}" for r in rows)
    decided = [(real(HUMAN_TO_VERIFIER[r["human"]]), real(r["verifier"])) for r in rows
               if real(HUMAN_TO_VERIFIER[r["human"]]) is not None and real(r["verifier"]) is not None]
    human_false = [r for r in rows if r["human"] == "FALSE"]
    human_true = [r for r in rows if r["human"] == "TRUE"]
    return {
        "rows": len(rows),
        "confusion": dict(sorted(confusion.items())),
        "decided_by_both": len(decided),
        "real_vs_false_agreement": round(sum(a == b for a, b in decided) / len(decided), 3) if decided else None,
        "cohen_kappa_real_vs_false": kappa(decided),
        "exact_label_agreement": round(sum(HUMAN_TO_VERIFIER[r["human"]] == r["verifier"] for r in rows) / len(rows), 3),
        "false_findings_refuted": f"{sum(r['verifier'] == 'refuted' for r in human_false)}/{len(human_false)}",
        "true_findings_wrongly_refuted": f"{sum(r['verifier'] == 'refuted' for r in human_true)}/{len(human_true)}",
        "unverifiable_rate": round(sum(r["verifier"] == "unverifiable" for r in rows) / len(rows), 3),
    }


async def main_async(args) -> None:
    settings = Settings()
    if not settings.anthropic_api_key:
        raise SystemExit("ANTHROPIC_AI_KEY is not set.")
    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=120.0, max_retries=3)
    verifier = FindingVerifier(client, model=settings.verifier_model, effort=settings.verifier_effort,
                               concurrency=args.concurrency)
    dataset = json.loads(Path(args.dataset).read_text())
    for i, row in enumerate(dataset):
        row["index"] = i
    rng = random.Random(args.seed)
    trues = [r for r in dataset if r["verdict"] == "TRUE"]
    sample = [r for r in dataset if r["verdict"] != "TRUE"] + rng.sample(trues, min(args.sample_true, len(trues)))
    files_by_repo: dict[str, dict] = {}
    run = VerificationRun(model=verifier.model)
    tasks = []
    for row in sample:
        repo = row["repo"]
        if repo not in files_by_repo:
            owner, name = repo.removeprefix("https://github.com/").split("/", 1)
            files_by_repo[repo] = select_repository(Path(args.clones) / f"{owner}_{name}")[0]
        severity = row["reported_severity"] if row["reported_severity"] in {s.value for s in Severity} else "medium"
        f = Finding(id=f"row-{row['index']}", dimension=Dimension.SECURITY, severity=Severity(severity),
                    title=row["title"], detail="", evidence=row["evidence"])
        tasks.append(verifier.verify_one(f, files_by_repo[repo], run))
    results = await asyncio.gather(*tasks)
    rows = [{"index": row["index"], "repo": row["repo"], "source": row["source"], "human": row["verdict"],
             "verifier": v.verdict, "quote_verified": v.quote_verified, "reviewed_severity": v.reviewed_severity,
             "human_severity": row["reviewed_severity"], "reason": v.reason, "note": v.note}
            for row, v in zip(sample, results)]
    Path(args.private_out).write_text(json.dumps(rows, indent=1))
    public = {"schema": "agentveritas.verifier-calibration/v1", "model": verifier.model, "effort": verifier.effort,
              "dataset_sha256": json.loads((ROOT / "docs/evidence/oss-study-commitment.json").read_text())["dataset_sha256"],
              "sample": {"all_non_true": len(sample) - min(args.sample_true, len(trues)),
                         "random_true": min(args.sample_true, len(trues)), "seed": args.seed},
              "metrics": metrics(rows),
              "by_source": {src: metrics([r for r in rows if r["source"] == src]) for src in sorted({r["source"] for r in rows})},
              "usage": run.usage,
              "note": "Hand labels come from one AI-assisted annotator; agreement measures consistency between two "
                      "independent passes, not ground truth."}
    Path(args.out).write_text(json.dumps(public, indent=1) + "\n")
    print(json.dumps(public["metrics"], indent=1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--clones", required=True)
    parser.add_argument("--sample-true", type=int, default=42)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--out", default=str(ROOT / "docs/evidence/verifier-calibration.json"))
    parser.add_argument("--private-out", default=str(ROOT / "data/verifier-calibration-rows.json"))
    asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    main()
