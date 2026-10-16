"""Live check of the grounded deep review against the labelled agent corpus.

Runs every corpus bundle through ``review_source`` with ``ai_assistance=True`` and
``Settings(enable_deep_review=True)``; the Anthropic key comes from the environment.
Starts with three pilot cases and only continues to the rest with ``--all`` when the
pilot ran cleanly. Generated seeds are never written anywhere and are redacted from
every printed or saved result.

    python scripts/live_deep_review.py            # pilot only
    python scripts/live_deep_review.py --all      # pilot, then the remaining cases
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from stellar_sdk import Keypair  # noqa: E402

from backend.app.config import Settings  # noqa: E402
from backend.app.services.studio import ReviewRequest, review_source  # noqa: E402

CORPUS = json.loads((ROOT / "backend" / "tests" / "fixtures" / "agent_corpus.json").read_text())
PILOT = ["V1-memo-injection-payment", "C2-guarded-payments", "case-09"]
MODEL = "claude-sonnet-5-5"
# Sonnet 5.5 list prices per million tokens; cache writes at 1.25x and reads at 0.1x input.
PRICE_IN, PRICE_OUT = 2.0, 10.0
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


def env_status() -> dict:
    return {name: "set" if os.environ.get(name) else "missing"
            for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AI_KEY", "ENABLE_DEEP_REVIEW", "ENABLE_ONCHAIN_VERIFICATION")}


def cost(usage: dict) -> float:
    return (usage["input_tokens"] * PRICE_IN + usage["cache_creation_input_tokens"] * PRICE_IN * 1.25
            + usage["cache_read_input_tokens"] * PRICE_IN * 0.1 + usage["output_tokens"] * PRICE_OUT) / 1e6


async def connection_test() -> dict:
    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=Settings().anthropic_api_key or None, timeout=60.0, max_retries=1)
    response = await client.messages.create(model=MODEL, max_tokens=16,
                                            messages=[{"role": "user", "content": "Reply with the word ok."}])
    text = "".join(getattr(b, "text", "") for b in response.content).strip()
    return {"model": response.model, "reply": text[:40],
            "usage": {k: int(getattr(response.usage, k, 0) or 0) for k in USAGE_KEYS}}


def redact(value, secrets: list[str]):
    text = json.dumps(value)
    for secret in secrets:
        text = text.replace(secret, "[REDACTED_SEED]")
    return json.loads(text)


async def run_case(case_id: str, settings: Settings) -> dict:
    case = CORPUS[case_id]
    bundle = copy.deepcopy(case["bundle"])
    seed = Keypair.random().secret
    bundle["files"] = {k: v.replace("{{GENERATED_SEED}}", seed) for k, v in bundle["files"].items()}
    bundle.update(ai_assistance=True, external_processing_consent=True)
    try:
        payload = await review_source(ReviewRequest(**bundle), settings)
    except Exception as exc:
        return {"case": case_id, "error": f"{type(exc).__name__}: {str(exc).replace(seed, '[REDACTED_SEED]')[:300]}"}
    report = payload["report"]
    deep = report.get("deep_review") or {}
    model_ids = set(deep.get("accepted_findings") or [])
    findings = report["findings"]
    rule = [f["id"] for f in findings if f["id"] not in model_ids]
    model = [{"id": f["id"], "severity": f["severity"], "title": f.get("title", ""),
              "evidence": str(f.get("evidence", ""))[:400]} for f in findings if f["id"] in model_ids]
    usage = {k: int((deep.get("usage") or {}).get(k, 0)) for k in USAGE_KEYS}
    expected = case.get("expected_finding")
    result = {
        "case": case_id, "flaw": case["flaw"], "expected_finding": expected,
        "decision": payload["decision"], "priority_finding_ids": payload.get("priority_finding_ids", []),
        "rule_findings": rule, "rules_caught_expected": bool(expected) and expected in rule,
        "model_accepted": model, "model_rejected": deep.get("rejected_claims", []),
        "deep_review_status": deep.get("status", "missing"), "turns": deep.get("turns", 0),
        "usage": usage, "cost_usd": round(cost(usage), 4), "note": deep.get("note", ""),
        "summary": str(deep.get("summary", ""))[:1200],
        # Needs human judgement: model findings on a flawed case beyond what rules found.
        "model_extra_on_flawed": bool(case["flaw"] and model),
        "false_alarm_on_clean": (not case["flaw"]) and (bool(model) or payload["decision"] != "pass"),
    }
    return redact(result, [seed])


def print_case(r: dict) -> None:
    print(f"\n=== {r['case']} ===")
    if "error" in r:
        print("  ERROR:", r["error"])
        return
    print(f"  flaw={r['flaw']} expected={r['expected_finding']} decision={r['decision']}")
    print(f"  priority findings: {r['priority_finding_ids']} (rules caught expected: {r['rules_caught_expected']})")
    print(f"  deep_review.status={r['deep_review_status']} turns={r['turns']} usage={r['usage']} ~${r['cost_usd']}")
    if r["note"]:
        print("  note:", r["note"])
    print("  rule findings:", r["rule_findings"])
    print("  model accepted:", json.dumps(r["model_accepted"], ensure_ascii=False, indent=2))
    print("  model rejected:", json.dumps(r["model_rejected"], ensure_ascii=False, indent=2))
    print("  model extra on flawed case (review by hand):", r["model_extra_on_flawed"])
    print("  false alarm on clean case:", r["false_alarm_on_clean"])


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="continue with the remaining cases after a clean pilot")
    parser.add_argument("--out", default="live_deep_review_results.json")
    args = parser.parse_args()

    # Accept the alternate name some environments use; the value is never printed.
    if not os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("ANTHROPIC_AI_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = os.environ["ANTHROPIC_AI_KEY"]
    status = env_status()
    for name, value in status.items():
        print(f"{name}: {value}")
    if status["ANTHROPIC_API_KEY"] == "missing":
        print("ANTHROPIC_API_KEY is missing; nothing was sent.")
        return 2

    ping = await connection_test()
    print("connection test:", json.dumps(ping))
    settings = Settings(enable_deep_review=True)
    print(f"deep review model={settings.deep_review_model} effort={settings.deep_review_effort} "
          f"onchain={settings.enable_onchain_verification}")

    results = []
    for case_id in PILOT:
        results.append(await run_case(case_id, settings))
        print_case(results[-1])
    pilot_ok = all("error" not in r and r["deep_review_status"] == "completed" for r in results)
    print(f"\npilot clean: {pilot_ok}")
    if args.all and pilot_ok:
        for case_id in sorted(c for c in CORPUS if c not in PILOT):
            results.append(await run_case(case_id, settings))
            print_case(results[-1])

    total = {k: sum(r.get("usage", {}).get(k, 0) for r in results) + ping["usage"][k] for k in USAGE_KEYS}
    print("\n=== totals ===")
    print("cases run:", len(results), "of", len(CORPUS))
    print("statuses:", {r["case"]: r.get("deep_review_status", "error") for r in results})
    print("false alarms on clean cases:", [r["case"] for r in results if r.get("false_alarm_on_clean")])
    print("flawed cases with model-only findings:", [r["case"] for r in results if r.get("model_extra_on_flawed")])
    print("tokens:", total)
    print(f"approx cost: ${cost(total):.4f} (cache-adjusted); "
          f"${(total['input_tokens'] + total['cache_creation_input_tokens'] + total['cache_read_input_tokens']) * PRICE_IN / 1e6 + total['output_tokens'] * PRICE_OUT / 1e6:.4f} "
          "if every input token is billed at $2/MTok")
    Path(args.out).write_text(json.dumps({"connection_test": ping, "results": results, "totals": total}, indent=2))
    return 0 if pilot_ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
