"""FastAPI uygulaması: agent ingestion, derin audit ve Soroban validation hazırlığı."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import get_settings
from .stellar.ownership import canonical_message, verify_owner
from .ingestion import IngestionService, IngestRequest
from .ingestion.templates import list_templates
from .models import AuditTier
from .services.chain_status import ChainStatusService
from .services.escrow import EscrowIndeterminateError, ExternalSignatureRequired
from .services.pipeline import AuditPipeline

logger = logging.getLogger("agentveritas.api")

settings = get_settings()
pipeline = AuditPipeline(settings)
ingestion = IngestionService(settings)
chain_status = ChainStatusService(settings)

#: Arka plan patrol turunun sağlığı. Hata sayacı olmadan sürekli patlayan bir
#: döngü hiçbir yerde görünmüyordu; `/api/v1/stats` bunu artık raporluyor.
monitor_health: dict = {"ticks": 0, "errors": 0, "last_error": "", "last_run_at": None}
_operator_requests: dict[str, deque[float]] = defaultdict(deque)


async def require_operator(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Yan etkili API uçlarını fail-closed korur.

    Anahtar yapılandırılmamışsa public yazma yüzeyi açılmaz. Karşılaştırma
    timing-safe'tir; basit process-local limit reverse-proxy limitinin yerini
    tutmaz ama tek anahtarın kazara/otomatik kötüye kullanımını sınırlar.
    """
    expected = settings.admin_api_key
    if not expected:
        raise HTTPException(status_code=503, detail="operatör API kapalı: ADMIN_API_KEY gerekli")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="geçersiz operatör kimliği")

    identity = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _operator_requests[identity]
    while bucket and now - bucket[0] >= 60:
        bucket.popleft()
    limit = max(1, min(settings.admin_rate_limit_per_minute, 600))
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="operatör istek limiti aşıldı")
    bucket.append(now)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Arka plan patrol döngüsünü başlatır ve kapanışta durumu diske yazar.

    `on_event` FastAPI 0.115'te deprecated; `lifespan` tek giriş/çıkış noktası
    verdiği için kapanışta `store.flush()` çağrısının atlanma riski de kalmıyor.
    """
    task = asyncio.create_task(_monitor_loop())
    app.state.monitor_task = task
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 - kapanış yolu
            pass
        pipeline.store.flush()


async def _monitor_loop() -> None:
    """Dakikalık patrol turu.

    Hata **yutulmaz**: sayaç artar ve loglanır. Eskiden `except Exception:
    continue` vardı; abonelik denetimi her turda patlasa bile sistem sağlıklı
    görünüyordu.
    """
    import time

    while True:
        await asyncio.sleep(60)
        try:
            results = await pipeline.monitor_tick(force=False)
            monitor_health["ticks"] += len(results)
            monitor_health["last_run_at"] = time.time()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - döngü ayakta kalmalı
            monitor_health["errors"] += 1
            monitor_health["last_error"] = f"{type(exc).__name__}: {exc}"
            logger.warning("monitor tick başarısız: %s", monitor_health["last_error"])


app = FastAPI(
    title="AgentVeritas",
    version=settings.version,
    description="Stellar agent validation layer — Soroban registry and evidence-first audits.",
    lifespan=lifespan,
)

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


# --------------------------------------------------------------------- schemas
class JobCreate(BaseModel):
    agent_id: str
    tier: AuditTier = AuditTier.BASIC
    requester: str = ""
    validation_request_hash: str = ""
    auto_run: bool = True


class FundRequest(BaseModel):
    funder: str = ""


class OwnershipVerifyRequest(BaseModel):
    """Stellar G-account Ed25519 sahiplik imzası ön kontrolü."""

    agent_ref: str
    owner: str
    signature: str



class ValidationRequestHook(BaseModel):
    """Soroban AgentRegistry validation request olayının güvenilir ingester karşılığı."""

    agent_address: str = ""
    agent_id: str = ""
    request_hash: str = ""
    tier: AuditTier = AuditTier.BASIC
    requester: str = ""


class MonitorSubscribe(BaseModel):
    agent_id: str
    interval_minutes: int = Field(default=30, ge=15, le=1440)
    # Monitoring çekirdek üründe ücretsizdir. Alan eski istemciler için korunur.
    prepaid_usdc: float = Field(default=0.0, ge=0)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """API ve statik UI için tarayıcı güvenlik sınırlarını açıkça uygula."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------- health
@app.get("/api/v1/health")
async def health() -> dict:
    net = settings.network_or_none
    return {
        "status": "ok",
        "version": settings.version,
        "network": {
            "key": settings.stellar_network,
            "name": net.name if net else "",
            "network_passphrase": settings.network_passphrase,
            "is_testnet": settings.is_testnet,
            "explorer": settings.explorer,
        },
        "modes": {
            "operator_api": bool(settings.admin_api_key),
            "llm": settings.llm_enabled,
            "rpc": settings.rpc_enabled,
            "contract_submission": False,
            "ipfs": settings.ipfs_enabled,
            "screening": settings.screening_enabled,
        },
        "integrations": settings.integrations(),
    }


# ------------------------------------------------------------------------ chain
@app.get("/api/v1/chain/status")
async def chain_status_view() -> dict:
    """Ağ, RPC, operatör cüzdanı ve zincire yazma hazırlığı."""
    return await chain_status.status()


@app.get("/api/v1/chain/signing-boundary")
async def signing_boundary() -> dict:
    return {
        "backend_signing": False,
        "secret_storage": False,
        "external_signing_required": True,
        "success_requires": ["successful transaction", "registry state/event readback"],
    }


@app.get("/api/v1/chain/probe/{address}")
async def chain_probe(address: str) -> dict:
    """Bir adresin zincir üzerindeki hızlı özeti (bakiye, nonce, kontrat mı)."""
    return await chain_status.probe_address(address)


@app.get("/api/v1/chain/deployments")
async def chain_deployments() -> dict:
    """Yapılandırılmış Soroban contract ID'leri; configured, deployed demek değildir."""
    return await chain_status.deployed_contracts()


@app.get("/api/v1/chain/attestations")
async def chain_attestations(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    """Kalıcı event deposunda doğrulanmış registry response olayları."""
    return await chain_status.onchain_attestations(limit=limit)


@app.post("/api/v1/chain/events/sync", dependencies=[Depends(require_operator)])
async def chain_events_sync(start_ledger: int = Query(gt=0)) -> dict:
    """Registry olaylarını kalıcı cursor/dedup deposuna bir sayfa işler."""
    try:
        return await chain_status.sync_registry_events(start_ledger)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/api/v1/jobs/{job_id}/attestation/reconcile",
    dependencies=[Depends(require_operator)],
)
async def reconcile_attestation(job_id: str) -> dict:
    """Prepared sonucu registry event + live tx readback ile confirmed yapar."""
    job = pipeline.store.get_job(job_id)
    if not job or not job.report or not job.report.attestation:
        raise HTTPException(status_code=404, detail="attestation bulunamadı")
    proof = await chain_status.confirm_attestation(job.report.attestation)
    if not proof.get("confirmed"):
        raise HTTPException(status_code=409, detail=proof)
    attestation = job.report.attestation
    attestation.mode = "onchain"
    attestation.confirmed = True
    attestation.tx_hash = proof["tx_hash"]
    attestation.ledger = proof.get("ledger")
    attestation.explorer_url = proof.get("explorer_url", "")
    attestation.note = "Registry responded event ve transaction SUCCESS readback doğrulandı."
    artifact = pipeline.store.get_agent(job.agent_id)
    if artifact:
        pipeline.badges.issue(artifact, job.report)
    pipeline.store.put_job(job)
    return {"job_id": job.id, "attestation": attestation.model_dump(mode="json"), "proof": proof}


@app.get("/api/v1/chain/escrow")
async def chain_escrow() -> dict:
    """Çekirdekten bağımsız opsiyonel Soroban escrow + SAC durumu."""
    return await chain_status.escrow_status()


@app.get("/api/v1/compliance/sanctions")
async def compliance_sanctions() -> dict:
    """OFAC SDN yaptırım listesi önbelleğinin durumu.

    Anahtarsız çalışan tek kanıt kaynağı olduğu için UI'ın bunu göstermesi gerekir:
    önbellek yoksa uyum boyutunda yaptırım kontrolü hiç yapılmıyor demektir.
    """
    from .compliance.ofac import OfacSanctionsList

    settings = get_settings()
    sanctions = OfacSanctionsList(settings.data_path, settings.ofac_max_age_hours)
    cache = sanctions.load_cache()

    out: dict = {
        "enabled": settings.ofac_enabled,
        "available": bool(cache),
        "cache_configured": True,
        "max_age_hours": settings.ofac_max_age_hours,
    }
    if cache:
        out.update(
            publisher=cache.get("publisher"),
            source=cache.get("source"),
            total_addresses=cache.get("total_addresses", 0),
            fetched_at=cache.get("fetched_at"),
            fresh=sanctions.is_fresh(cache),
            chains={k: len(v) for k, v in (cache.get("chains") or {}).items()},
        )
    return out


@app.get("/api/v1/selftest")
async def selftest(deep: bool = False) -> dict:
    """Sistem öz-denetimi: her katmanın canlı doğrulaması.

    `deep=true` gerçek bir denetim koşusu da yapar (zafiyetli örnek ajan üzerinde);
    bu yavaştır ama uçtan uca akışın çalıştığını kesin olarak kanıtlar.
    """
    if deep:
        raise HTTPException(
            status_code=405,
            detail="deep selftest yan etkilidir; POST /api/v1/selftest/deep kullanın",
        )
    from .services.selftest import SelfTestService

    return await SelfTestService(get_settings()).run(deep=False)


@app.post("/api/v1/selftest/deep", dependencies=[Depends(require_operator)])
async def selftest_deep() -> dict:
    """Operatör onayıyla yan etkili uçtan uca kontrol."""
    from .services.selftest import SelfTestService

    return await SelfTestService(get_settings()).run(deep=True)


@app.get("/api/v1/config")
async def config() -> dict:
    return {
        "pricing": {
            "basic_usdc": settings.price_basic_usdc,
            "deep_usdc": settings.price_deep_usdc,
            "monitor_tick_usdc": settings.monitor_tick_price_usdc,
            "platform_fee_bps": settings.platform_fee_bps,
        },
        "billing": {
            "enabled": settings.audit_escrow_enabled,
            "asset_code": settings.resolved_escrow_asset_code,
            "backend_signing": False,
            "note": (
                "optional external-signer escrow"
                if settings.audit_escrow_enabled
                else "core validation is free"
            ),
        },
        "contracts": {
            "agent_registry": settings.agent_registry_contract_id,
            "audit_escrow": settings.audit_escrow_contract_id,
            "sac": settings.sac_contract_id,
        },
        "network_passphrase": settings.network_passphrase,
        "network": settings.network_summary(),
        "templates": list_templates(),
    }


# ---------------------------------------------------------------------- agents
@app.post("/api/v1/agents/ingest", dependencies=[Depends(require_operator)])
async def ingest_agent(req: IngestRequest) -> dict:
    try:
        artifact = await ingestion.ingest(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ingestion hatası: {exc}") from exc

    pipeline.store.put_agent(artifact)
    return {
        "agent_id": artifact.id,
        "name": artifact.name,
        "source_kind": artifact.source_kind.value,
        "declared_capabilities": artifact.declared_capabilities,
        "tools": [t.model_dump() for t in artifact.tools],
        "wallet": artifact.agent_wallet,
        "agent_contract_id": artifact.agent_contract_id,
        "domain": artifact.domain,
        "code_files": len(artifact.code_files),
        "dependencies": len(artifact.dependencies),
        "system_prompt_present": bool(artifact.system_prompt),
        "owner": artifact.owner,
        "owner_verified": artifact.owner_verified,
        "owner_verification": artifact.owner_verification_note,
        "onchain": artifact.onchain.model_dump(),
    }


# ------------------------------------------------------------------- ownership
@app.get("/api/v1/ownership/message")
async def ownership_message(agent_ref: str, owner: str) -> dict:
    """G-account tarafından Ed25519 ile imzalanacak ağ-bağlı metni döndürür."""
    if not agent_ref or not owner:
        raise HTTPException(status_code=400, detail="agent_ref ve owner gerekli")
    return {
        "message": canonical_message(agent_ref, owner, settings.network_passphrase),
        "network_passphrase": settings.network_passphrase,
        "scheme": "SEP-53 Ed25519 (G-account); C-account için SEP-45",
    }


@app.post("/api/v1/ownership/verify")
async def ownership_verify(req: OwnershipVerifyRequest) -> dict:
    """İmzayı doğrular. Denetim başlatmadan önce ön kontrol için kullanılır."""
    check = verify_owner(
        req.agent_ref, req.owner, req.signature, settings.network_passphrase
    )
    return {
        "verified": check.verified,
        "reason": check.reason,
        "recovered": check.recovered,
        "evidence": check.evidence,
    }



@app.get("/api/v1/agents")
async def list_agents() -> dict:
    return {
        "agents": [
            {
                "agent_id": a.id,
                "name": a.name,
                "source_kind": a.source_kind.value,
                "wallet": a.agent_wallet,
                "domain": a.domain,
                "jobs": len(pipeline.store.jobs_for_agent(a.id)),
            }
            for a in pipeline.store.agents.values()
        ]
    }


@app.get("/api/v1/agents/{agent_id}")
async def get_agent(agent_id: str) -> dict:
    artifact = pipeline.store.get_agent(agent_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="agent bulunamadı")
    data = artifact.model_dump(mode="json")
    data["code_files"] = {k: f"{len(v)} bytes" for k, v in artifact.code_files.items()}
    return data


# ------------------------------------------------------------------------ jobs
def _job_view(job) -> dict:
    view = job.model_dump(mode="json", exclude={"report"})
    if job.report:
        r = job.report
        view["report"] = {
            "overall_score": r.overall_score,
            "badge": r.badge.value,
            "severity_counts": r.counts(),
            "disagreement_index": r.disagreement_index,
            "duration_ms": r.duration_ms,
            "dimension_scores": [d.model_dump(mode="json") for d in r.dimension_scores],
            "findings": [f.model_dump(mode="json") for f in r.findings],
            "judge_notes": r.judge_notes,
            "auditors": [
                {
                    "auditor": v.auditor,
                    "dimension": v.dimension.value,
                    "score": v.score,
                    "duration_ms": v.duration_ms,
                    "llm_assisted": v.llm_assisted,
                    "notes": v.notes,
                    "scenarios": [s.model_dump() for s in v.scenarios],
                }
                for v in r.verdicts
            ],
            "report_cid": r.report_cid,
            "report_uri": r.report_uri,
            "attestation": r.attestation.model_dump(mode="json") if r.attestation else None,
        }
    return view


@app.post("/api/v1/jobs", dependencies=[Depends(require_operator)])
async def create_job(req: JobCreate) -> dict:
    try:
        job = pipeline.create_job(req.agent_id, req.tier, req.requester, req.validation_request_hash)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if req.auto_run:
        try:
            await pipeline.fund_job(job.id, req.requester)
        except ExternalSignatureRequired as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "job_id": job.id,
                    "state": "awaiting_signature",
                    "reason": str(exc),
                    "invocation": job.escrow.tx_ref if job.escrow else "",
                },
            ) from exc
        except EscrowIndeterminateError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        job = await pipeline.run_job(job.id)
    return _job_view(job)


@app.post("/api/v1/jobs/{job_id}/fund", dependencies=[Depends(require_operator)])
async def fund_job(job_id: str, req: FundRequest) -> dict:
    try:
        job = await pipeline.fund_job(job_id, req.funder)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ExternalSignatureRequired as exc:
        job = pipeline.store.get_job(job_id)
        raise HTTPException(
            status_code=409,
            detail={
                "job_id": job_id,
                "state": "awaiting_signature",
                "reason": str(exc),
                "invocation": job.escrow.tx_ref if job and job.escrow else "",
            },
        ) from exc
    except EscrowIndeterminateError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return _job_view(job)


@app.post("/api/v1/jobs/{job_id}/run", dependencies=[Depends(require_operator)])
async def run_job(job_id: str) -> dict:
    try:
        job = await pipeline.run_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _job_view(job)


@app.get("/api/v1/jobs")
async def list_jobs(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return {"jobs": [_job_view(j) for j in pipeline.store.recent_jobs(limit)]}


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str) -> dict:
    job = pipeline.store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job bulunamadı")
    return _job_view(job)


@app.get("/api/v1/jobs/{job_id}/report.md", response_class=PlainTextResponse)
async def job_report_md(job_id: str) -> str:
    try:
        return pipeline.markdown_for(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/jobs/{job_id}/report.json")
async def job_report_json(job_id: str) -> dict:
    try:
        return pipeline.json_for(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ------------------------------------------------------------------ validation
@app.post("/api/v1/validation/requests", dependencies=[Depends(require_operator)])
async def validation_request(hook: ValidationRequestHook) -> dict:
    """Doğrulanmış Soroban request event'i geldiğinde audit başlatır."""
    agent_id = hook.agent_id
    if not agent_id and hook.agent_address:
        existing = pipeline.store.find_agent_by_wallet(hook.agent_address)
        if existing:
            agent_id = existing.id
        else:
            artifact = await ingestion.ingest(
                IngestRequest(kind="onchain_address", address=hook.agent_address)
            )
            pipeline.store.put_agent(artifact)
            agent_id = artifact.id
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id veya agent_address gerekli")

    job = pipeline.create_job(agent_id, hook.tier, hook.requester, hook.request_hash)
    try:
        await pipeline.fund_job(job.id, hook.requester)
    except ExternalSignatureRequired as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "job_id": job.id,
                "state": "awaiting_signature",
                "reason": str(exc),
                "invocation": job.escrow.tx_ref if job.escrow else "",
            },
        ) from exc
    job = await pipeline.run_job(job.id)

    report = job.report
    return {
        "job_id": job.id,
        "agent_id": agent_id,
        "validation_response": {
            "request_hash": job.validation_request_hash,
            "score": report.overall_score if report else None,
            "tag": report.badge.value if report else None,
            "report_uri": report.report_uri if report else None,
            "invocation": report.attestation.invocation_json if report and report.attestation else None,
            "mode": report.attestation.mode if report and report.attestation else None,
            "tx_hash": report.attestation.tx_hash if report and report.attestation else None,
            "confirmed": report.attestation.confirmed if report and report.attestation else False,
        },
    }


# ---------------------------------------------------------------------- badges
@app.get("/api/v1/badges")
async def all_badges() -> dict:
    return {"badges": pipeline.badges.all_badges()}


@app.get("/api/v1/badges/{identifier}")
async def get_badge(identifier: str) -> dict:
    record = pipeline.badges.get(identifier)
    if not record:
        raise HTTPException(status_code=404, detail="badge bulunamadı")
    return {"badge": record, "history": pipeline.badges.get_history(identifier)}


# ------------------------------------------------------------------ monitoring
@app.post("/api/v1/monitor/subscribe", dependencies=[Depends(require_operator)])
async def monitor_subscribe(req: MonitorSubscribe) -> dict:
    try:
        sub = pipeline.subscribe_monitor(req.agent_id, req.interval_minutes, req.prepaid_usdc)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return sub.model_dump(mode="json")


@app.get("/api/v1/monitor/subscriptions")
async def monitor_list() -> dict:
    return {
        "subscriptions": [s.model_dump(mode="json") for s in pipeline.store.subscriptions.values()]
    }


@app.post("/api/v1/monitor/tick", dependencies=[Depends(require_operator)])
async def monitor_tick(force: bool = True) -> dict:
    results = await pipeline.monitor_tick(force=force)
    return {"ticks": results, "count": len(results)}


# ----------------------------------------------------------------------- swarm
@app.get("/api/v1/swarm/leaderboard")
async def leaderboard() -> dict:
    return {"swarm": pipeline.swarm.leaderboard()}


@app.get("/api/v1/stats")
async def stats() -> dict:
    out = pipeline.stats()
    out["monitor_health"] = dict(monitor_health)
    return out


@app.get("/api/v1/ledger/nanopayments")
async def nanopayments() -> dict:
    ledger = pipeline.escrow.nanopayment_ledger
    return {
        "entries": ledger[-100:],
        "count": len(ledger),
        "total_usdc": round(sum(e["amount_usdc"] for e in ledger), 8),
    }


# ------------------------------------------------------------------- frontend
if FRONTEND_DIR.exists():

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")
