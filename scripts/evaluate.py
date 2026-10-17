#!/usr/bin/env python3
"""Reproducible detection evaluation. Never executes submitted source.

Part A, public: every labelled case in backend/tests/fixtures/agent_corpus.json
(Python) and ts_agent_corpus.json (TypeScript) is audited, and the result is scored
as a confusion matrix:
- a flawed case is a true positive only if the expected finding is reported;
- a sound case is a false positive if any actionable risk or a needs_fixes decision
  is reported.
The corpora were written by the maintainers and used during development, so the
numbers are a regression measure, not an independent estimate.

Part B, committed: the open-source study (12 repositories, 199 hand-checked findings)
contains unpublished vulnerability details. Only its SHA-256 commitment is public, in
docs/evidence/oss-study-commitment.json. Whoever holds the dataset can recompute the
statistics and check them against the commitment:

    python scripts/evaluate.py                       # Part A, writes docs/evidence/evaluation.json
    python scripts/evaluate.py --oss-dataset FILE    # also verifies Part B
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from stellar_sdk import Keypair  # noqa: E402

from backend.app.config import Settings  # noqa: E402
from backend.app.services.studio import ReviewRequest, review_source  # noqa: E402

CORPORA = {"python": ROOT / "backend/tests/fixtures/agent_corpus.json",
           "typescript": ROOT / "backend/tests/fixtures/ts_agent_corpus.json"}
COMMITMENT = ROOT / "docs/evidence/oss-study-commitment.json"


def canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


async def run_case(name: str, case: dict, settings: Settings) -> dict:
    # Seed-detection fixtures need a valid seed; it is generated here, never committed.
    bundle = json.loads(json.dumps(copy.deepcopy(case["bundle"])).replace("{{GENERATED_SEED}}", Keypair.random().secret))
    result = await review_source(ReviewRequest(**bundle), settings)
    report = result["report"]
    ids = {f["id"] for f in report["findings"]}
    actionable = [f["id"] for f in report["findings"]
                  if f.get("kind", "risk") == "risk" and f["severity"] in ("critical", "high")]
    if case["flaw"]:
        outcome = "TP" if case["expected_finding"] in ids else "FN"
    else:
        outcome = "FP" if actionable or result["decision"] == "needs_fixes" else "TN"
    return {"case": name, "flaw": case["flaw"], "expected": case.get("expected_finding", ""),
            "decision": result["decision"], "score": report["result"]["overall_score"],
            "outcome": outcome, "actionable": actionable[:5]}


def matrix(rows: list[dict]) -> dict:
    c = collections.Counter(r["outcome"] for r in rows)
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    return {"cases": len(rows), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None}


def part_a() -> dict:
    settings = Settings(_env_file=None)
    out = {"corpora": {}}
    all_rows = []
    for language, path in CORPORA.items():
        corpus = json.loads(path.read_text())
        rows = [asyncio.run(run_case(name, case, settings)) for name, case in corpus.items()]
        all_rows += rows
        out["corpora"][language] = {"source": str(path.relative_to(ROOT)),
                                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                    **matrix(rows), "rows": rows}
    out["total"] = matrix(all_rows)
    return out


def oss_statistics(dataset: list[dict]) -> dict:
    verdicts = collections.Counter(f["verdict"] for f in dataset)
    by_source = collections.Counter(f"{f['source']}:{f['verdict']}" for f in dataset)
    decided = sum(verdicts[v] for v in ("TRUE", "PARTIAL", "FALSE"))
    return {"repositories": len({f["repo"] for f in dataset}), "findings": len(dataset),
            "verdicts": dict(verdicts), "by_source": dict(by_source),
            "precision_strict": round(verdicts["TRUE"] / decided, 3) if decided else None,
            "precision_including_partial": round((verdicts["TRUE"] + verdicts["PARTIAL"]) / decided, 3) if decided else None}


def part_b(path: Path) -> dict:
    dataset = json.loads(path.read_text())
    digest = hashlib.sha256(canonical(dataset)).hexdigest()
    commitment = json.loads(COMMITMENT.read_text())
    return {"sha256": digest, "matches_commitment": digest == commitment["dataset_sha256"],
            **oss_statistics(dataset)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--oss-dataset", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "docs/evidence/evaluation.json")
    args = parser.parse_args()
    result = {"schema": "agentveritas.evaluation/v1", "part_a": part_a()}
    if args.oss_dataset:
        result["part_b"] = part_b(args.oss_dataset)
    args.out.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"part_a": {k: v for k, v in result["part_a"]["total"].items()},
                      **({"part_b": {k: v for k, v in result["part_b"].items() if k != "by_source"}}
                         if args.oss_dataset else {})}, indent=1))


if __name__ == "__main__":
    main()
