"""AgentVeritas Stellar CLI; does not include backend signer or on-chain write path."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .app.config import get_settings
from .app.ingestion import IngestRequest, IngestionService
from .app.ingestion.templates import list_templates
from .app.models import AuditTier
from .app.services.chain_status import ChainStatusService
from .app.services.pipeline import AuditPipeline

BADGE_ICON = {"SAFE": "✅", "CAUTION": "⚠️ ", "HIGH_RISK": "⛔", "BLOCKLIST": "🚫"}


def build_request(args: argparse.Namespace) -> IngestRequest:
    shared = {"agent_wallet": args.account or ""}
    if args.address:
        field = "address" if args.address.startswith("G") else "agent_contract_id"
        return IngestRequest(kind="onchain_address", **{field: args.address}, **shared)
    if args.repo:
        return IngestRequest(kind="repo", repo_url=args.repo, **shared)
    if args.path:
        return IngestRequest(kind="repo", local_path=args.path, **shared)
    if args.endpoint:
        return IngestRequest(kind="endpoint", endpoint_url=args.endpoint, **shared)
    if args.wizard:
        return IngestRequest(kind="wizard", template=args.wizard, **shared)
    raise SystemExit("Source required: --address | --repo | --path | --endpoint | --wizard")


async def run_audit(args: argparse.Namespace) -> int:
    settings = get_settings()
    if args.path:
        settings = settings.model_copy(update={"allow_local_path_ingest": True})
    pipeline = AuditPipeline(settings)
    artifact = await IngestionService(settings).ingest(build_request(args))
    pipeline.store.put_agent(artifact)
    job = pipeline.create_job(artifact.id, AuditTier(args.tier), requester=args.account or "")
    await pipeline.fund_job(job.id, args.account or "")
    job = await pipeline.run_job(job.id)
    if job.error or not job.report:
        print(f"ERROR: {job.error or 'report not generated'}", file=sys.stderr)
        return 1
    report = job.report
    counts = report.counts()
    print(f"{BADGE_ICON[report.badge.value]} {report.badge.value} · Trust Score {report.overall_score}/100")
    print(
        f"critical={counts['critical']} high={counts['high']} medium={counts['medium']} "
        f"low={counts['low']} · {report.duration_ms} ms"
    )
    for score in report.dimension_scores:
        print(f"  {score.dimension.value:<16} {score.score:>5.1f}")
    if report.attestation:
        att = report.attestation
        print(
            f"attestation={att.mode} confirmed={att.confirmed} "
            f"registry={att.registry_contract_id or 'none'}"
        )
        if att.note:
            print(f"note: {att.note}")
    if args.markdown:
        print(pipeline.markdown_for(job.id))
    if args.json:
        print(json.dumps(pipeline.json_for(job.id), ensure_ascii=False, indent=2))
    return 0


async def show_chain(_: argparse.Namespace) -> int:
    data = await ChainStatusService(get_settings()).status()
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0 if not data["rpc"].get("error") or not get_settings().rpc_enabled else 1


async def show_attestations(args: argparse.Namespace) -> int:
    data = await ChainStatusService(get_settings()).onchain_attestations(args.limit)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


async def sync_events(args: argparse.Namespace) -> int:
    try:
        data = await ChainStatusService(get_settings()).sync_registry_events(args.start_ledger)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


async def show_selftest(args: argparse.Namespace) -> int:
    from .app.services.selftest import SelfTestService

    data = await SelfTestService(get_settings()).run(deep=args.deep)
    for check in data["checks"]:
        print(f"{check['state'].upper():<5} {check['name']}: {check['detail']}")
    return 0 if data["ok"] else 1


async def refresh_sanctions(args: argparse.Namespace) -> int:
    from .app.compliance.ofac import OfacSanctionsList

    settings = get_settings()
    sanctions = OfacSanctionsList(settings.data_path, settings.ofac_max_age_hours)
    try:
        data = await sanctions.refresh(force=args.refresh)
    except Exception as exc:
        print(f"ERROR: Failed to fetch OFAC list: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "publisher": data.get("publisher"),
                "total_addresses": data.get("total_addresses", 0),
                "fetched_at": data.get("fetched_at"),
                "stale": data.get("stale", False),
                "chains": {k: len(v) for k, v in (data.get("chains") or {}).items()},
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def show_integrations() -> int:
    rows = [
        {k: row[k] for k in ("key", "enabled", "value", "unlocks", "fallback")}
        for row in get_settings().integrations()
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def show_templates() -> int:
    print(json.dumps(list_templates(), ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentveritas-stellar")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="run agent audit")
    source = audit.add_mutually_exclusive_group(required=True)
    source.add_argument("--address", help="G... account veya C... contract")
    source.add_argument("--repo")
    source.add_argument("--path")
    source.add_argument("--endpoint")
    source.add_argument("--wizard")
    audit.add_argument("--account", help="agent/requester G... account")
    audit.add_argument("--tier", choices=("basic", "deep"), default="basic")
    audit.add_argument("--markdown", action="store_true")
    audit.add_argument("--json", action="store_true")

    sub.add_parser("chain", help="Stellar RPC and contract boundaries")
    sub.add_parser("templates", help="audit templates")
    sub.add_parser("integrations", help="integration status without showing secrets")
    attest = sub.add_parser("attestations", help="confirmed registry event records")
    attest.add_argument("--limit", type=int, default=20)
    events = sub.add_parser("events-sync", help="process registry event page to persistent store")
    events.add_argument("--start-ledger", type=int, required=True)
    selftest = sub.add_parser("selftest", help="self-test")
    selftest.add_argument("--deep", action="store_true")
    sanctions = sub.add_parser("sanctions", help="OFAC cache status/refresh")
    sanctions.add_argument("--refresh", action="store_true")

    args = parser.parse_args()
    if args.command == "audit":
        return asyncio.run(run_audit(args))
    if args.command == "chain":
        return asyncio.run(show_chain(args))
    if args.command == "templates":
        return show_templates()
    if args.command == "integrations":
        return show_integrations()
    if args.command == "attestations":
        return asyncio.run(show_attestations(args))
    if args.command == "events-sync":
        return asyncio.run(sync_events(args))
    if args.command == "selftest":
        return asyncio.run(show_selftest(args))
    if args.command == "sanctions":
        return asyncio.run(refresh_sanctions(args))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
