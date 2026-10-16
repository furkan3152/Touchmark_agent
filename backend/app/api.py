"""FastAPI application: agent ingestion, deep audit, and Soroban validation preparation."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
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
from .services.studio import ReviewRequest, review_source
from .studio_guard import StudioGuard
from .services.studio_intake import AddressRequest, GitHubRequest, identify_address, import_github_bundle

logger = logging.getLogger("agentveritas.api")

settings = get_settings()
pipeline = AuditPipeline(settings)
ingestion = IngestionService(settings)
chain_status = ChainStatusService(settings)

#: Health of the background patrol cycle. A continuously crashing loop without an error
#: counter wasn't visible anywhere; `/api/v1/stats` now reports this.
monitor_health: dict = {"ticks": 0, "errors": 0, "last_error": "", "last_run_at": None}
_operator_requests: dict[str, deque[float]] = defaultdict(deque)


async def require_operator(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Protects side-effecting API endpoints in a fail-closed manner.

    If the key is not configured, the public write surface is not opened. The comparison
    is timing-safe; a simple process-local limit does not replace a reverse-proxy limit,
    but it limits accidental/automated abuse of the single key.
    """
    if settings.stateless_studio:
        raise HTTPException(status_code=503, detail="operator API requires persistent deployment")
    expected = settings.admin_api_key
    if not expected:
        raise HTTPException(status_code=503, detail="operator API disabled: ADMIN_API_KEY required")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid operator identity")

    identity = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _operator_requests[identity]
    while bucket and now - bucket[0] >= 60:
        bucket.popleft()
    limit = max(1, min(settings.admin_rate_limit_per_minute, 600))
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="operator request limit exceeded")
    bucket.append(now)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Starts the background patrol loop and writes state to disk on shutdown.

    `on_event` is deprecated in FastAPI 0.115; since `lifespan` provides a single
    entry/exit point, there is no risk of skipping the `store.flush()` call on shutdown.
    """
    if settings.stateless_studio:
        yield
        return
    task = asyncio.create_task(_monitor_loop())
    app.state.monitor_task = task
    order_task = None
    if settings.enable_official_orders:
        from .services.official_fulfillment import OfficialFulfillment
        service = OfficialFulfillment(settings)
        app.state.official_fulfillment = service
        order_task = asyncio.create_task(service.run())
    try:
        yield
    finally:
        if order_task is not None:
            order_task.cancel()
            try:
                await order_task
            except asyncio.CancelledError:
                pass
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 - kapanış yolu
            pass
        pipeline.store.flush()


async def _monitor_loop() -> None:
    """Minute-based patrol cycle.

    Errors are **not swallowed**: the counter increases and is logged. Previously, there was
    `except Exception: continue`; even if the subscription check crashed on every cycle, the
    system appeared healthy.
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
            logger.warning("monitor tick failed: %s", monitor_health["last_error"])

        # Cleanup expired rate limit buckets to prevent memory leak
        now = time.monotonic()
        for ip_key in list(_operator_requests.keys()):
            q = _operator_requests[ip_key]
            while q and now - q[0] >= 60:
                q.popleft()
            if not q:
                del _operator_requests[ip_key]


app = FastAPI(
    title="AgentVeritas",
    version=settings.version,
    description="Stellar agent validation layer — Soroban registry and evidence-first audits.",
    lifespan=lifespan,
)
app.add_middleware(StudioGuard)

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
    """Stellar G-account Ed25519 ownership signature pre-check."""

    agent_ref: str
    owner: str
    signature: str



class ValidationRequestHook(BaseModel):
    """Reliable ingester equivalent of the Soroban AgentRegistry validation request event."""

    agent_address: str = ""
    agent_id: str = ""
    request_hash: str = ""
    tier: AuditTier = AuditTier.BASIC
    requester: str = ""


class MonitorSubscribe(BaseModel):
    agent_id: str
    interval_minutes: int = Field(default=30, ge=15, le=1440)
    # Monitoring is free in the core product. Field is preserved for legacy clients.
    prepaid_usdc: float = Field(default=0.0, ge=0)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Explicitly enforce browser security boundaries for the API and static UI."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self' https://soroban-rpc.testnet.stellar.gateway.fm; "
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
            "operator_api": bool(settings.admin_api_key) and not settings.stateless_studio,
            "stateless_studio": settings.stateless_studio,
            "llm": settings.llm_enabled,
            "rpc": settings.rpc_enabled,
            "contract_submission": bool(getattr(app.state, 'official_fulfillment', None)),
            "contract_submission_scope": 'pinned_testnet_official_provider_and_evaluator_only',
            "ipfs": settings.ipfs_enabled,
            "screening": settings.screening_enabled,
        },
        "integrations": settings.integrations(),
    }


# ------------------------------------------------------------------------ chain
@app.get("/api/v1/chain/status")
async def chain_status_view() -> dict:
    """Network, RPC, operator wallet, and on-chain write readiness."""
    return await chain_status.status()


@app.get("/api/v1/chain/signing-boundary")
async def signing_boundary() -> dict:
    official = bool(getattr(app.state, 'official_fulfillment', None))
    return {
        "backend_signing": official,
        "secret_storage": official,
        "signing_scope": 'pinned_testnet_official_provider_and_evaluator_only' if official else 'disabled',
        "customer_transactions": 'external_wallet_signature_required',
        "external_signing_required": True,
        "success_requires": ["successful transaction", "registry state/event readback"],
    }


@app.get("/api/v1/chain/probe/{address}")
async def chain_probe(address: str) -> dict:
    """Quick on-chain summary of an address (balance, nonce, is contract)."""
    return await chain_status.probe_address(address)


@app.get("/api/v1/chain/deployments")
async def chain_deployments() -> dict:
    """Configured Soroban contract IDs; does not necessarily mean they are deployed."""
    return await chain_status.deployed_contracts()


@app.get("/api/v1/chain/attestations")
async def chain_attestations(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    """Verified registry response events in the persistent event store."""
    return await chain_status.onchain_attestations(limit=limit)


@app.post("/api/v1/chain/events/sync", dependencies=[Depends(require_operator)])
async def chain_events_sync(start_ledger: int = Query(gt=0)) -> dict:
    """Processes a page of registry events into the persistent cursor/dedup store."""
    try:
        return await chain_status.sync_registry_events(start_ledger)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/api/v1/jobs/{job_id}/attestation/reconcile",
    dependencies=[Depends(require_operator)],
)
async def reconcile_attestation(job_id: str) -> dict:
    """Makes the prepared result confirmed with registry event + live tx readback."""
    job = pipeline.store.get_job(job_id)
    if not job or not job.report or not job.report.attestation:
        raise HTTPException(status_code=404, detail="attestation not found")
    proof = await chain_status.confirm_attestation(job.report.attestation)
    if not proof.get("confirmed"):
        raise HTTPException(status_code=409, detail=proof)
    attestation = job.report.attestation
    attestation.mode = "onchain"
    attestation.confirmed = True
    attestation.tx_hash = proof["tx_hash"]
    attestation.ledger = proof.get("ledger")
    attestation.explorer_url = proof.get("explorer_url", "")
    attestation.note = "Registry responded event and transaction SUCCESS readback verified."
    artifact = pipeline.store.get_agent(job.agent_id)
    if artifact:
        pipeline.badges.issue(artifact, job.report)
    pipeline.store.put_job(job)
    return {"job_id": job.id, "attestation": attestation.model_dump(mode="json"), "proof": proof}


@app.get("/api/v1/chain/escrow")
async def chain_escrow() -> dict:
    """Optional Soroban escrow + SAC status, independent of the core."""
    return await chain_status.escrow_status()


@app.get("/api/v1/compliance/sanctions")
async def compliance_sanctions() -> dict:
    """Status of the OFAC SDN sanctions list cache.

    Since it's the only source of truth that runs keyless, the UI must show this:
    if there is no cache, it means the sanction check is not performed at all in the compliance dimension.
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
    """System self-test: live validation of each layer.

    `deep=true` also runs a real audit (on a vulnerable sample agent);
    this is slow but definitively proves the end-to-end flow works.
    """
    if deep:
        raise HTTPException(
            status_code=405,
            detail="deep selftest has side effects; use POST /api/v1/selftest/deep",
        )
    from .services.selftest import SelfTestService

    return await SelfTestService(get_settings()).run(deep=False)


@app.post("/api/v1/selftest/deep", dependencies=[Depends(require_operator)])
async def selftest_deep() -> dict:
    """Side-effecting end-to-end check with operator approval."""
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
from .services.runtime_policy import RuntimePolicy, Action, evaluate


class PolicySimulation(BaseModel):
    policy: RuntimePolicy
    action: Action
    spent: int = Field(default=0, ge=0, le=2**63-1, strict=True)
    paused: bool = False


@app.post("/api/v1/studio/policy")
async def simulate_policy(req: PolicySimulation) -> dict:
    reasons = evaluate(req.policy, req.action, spent=req.spent, paused=req.paused)
    if req.policy.require_approval:
        reasons.append("signed_approval_required")
    return {"allowed": not reasons, "reasons": reasons, "simulation": True,
            "executed": False, "note": "Simulation only. No action is authorized or submitted."}


from .services.runtime_audit import RuntimeRequest, run_runtime
from .services.discovery import discover_project
from .stellar.auth_inspector import AuthorizationInspectionRequest, inspect_authorization_entry

_runtime_lock = asyncio.Lock()


def require_pilot_key(authorization: str, *, ai: bool = False) -> None:
    expected = (settings.ai_review_api_key or settings.runtime_api_key) if ai else settings.runtime_api_key
    if len(expected) < 32 or not authorization.startswith('Bearer ') or not secrets.compare_digest(authorization[7:].encode(), expected.encode()):
        raise HTTPException(status_code=401, detail='A valid private pilot access key is required.')


from .services.audit_product import EngagementRequest, catalogue, build_plan, audit_engagement, normalize
from .services.report_delivery import DeliveryRequest, deliver_report, pilot_evidence
from .services.testnet_checkout import CheckoutRequest, CheckoutStepRequest, prepare_checkout, prepare_checkout_step
from pydantic import ConfigDict


class CapsuleImportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    document: str = Field(min_length=2, max_length=96_000)


@app.get('/api/v1/studio/catalog')
async def studio_catalog() -> dict:
    return catalogue(settings)


@app.post('/api/v1/studio/checkout')
async def studio_checkout(req: CheckoutRequest, authorization: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    try:
        return await prepare_checkout(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post('/api/v1/studio/checkout/prepare')
async def studio_checkout_prepare(req: CheckoutStepRequest, authorization: str = Header(default=''),
                                  x_order_id: str = Header(default=''), x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    try:
        if req.step == 'fund':
            service = _official_service()
            summary = service.store.get(x_order_id, x_order_token)
            if (summary['order_id'] != req.quote.request_id or summary['requester'] != req.quote.requester
                    or summary['plan_sha256'] != req.quote.plan_sha256
                    or summary['source_sha256'] != req.quote.source_sha256
                    or summary['status'] != 'awaiting_payment'):
                raise ValueError('Create a matching private official order before funding.')
        return await prepare_checkout_step(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


from .services.audit_orders import OrderSubmission, create_order, activate_order, recover_order
from .services.order_identity import make_order_challenge
from .services.official_fulfillment import order_capabilities


def _official_service():
    capability = order_capabilities(settings)
    service = getattr(app.state, 'official_fulfillment', None)
    if not capability['available'] or service is None or not service.health['running']:
        raise HTTPException(status_code=503, detail=capability['reason'] or 'The persistent official worker is not running.')
    return service


def _official_store():
    """Read/recovery/refund access survives a paused worker or rotated service key."""
    if settings.stateless_studio:
        raise HTTPException(status_code=503, detail='Private orders require the persistent operator service.')
    service = getattr(app.state, 'official_fulfillment', None)
    if service is not None:
        return service.store
    from .services.audit_orders import AuditOrderStore
    path = Path(settings.official_orders_database)
    if not path.is_file():
        raise HTTPException(status_code=503, detail='The private order database is not available.')
    try:
        return AuditOrderStore(path, deployment='local' if settings.official_orders_local_pilot else 'persistent',
                               durable_storage=settings.official_orders_storage_durable)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail='The private order database is not available on persistent storage.') from exc


@app.get('/api/v1/studio/orders/capabilities')
async def studio_order_capabilities() -> dict:
    value = order_capabilities(settings)
    service = getattr(app.state, 'official_fulfillment', None)
    if value['available'] and (service is None or not service.health['running']):
        value.update(available=False, automatic_settlement=False, reason='The persistent official worker is not running.')
    return value


@app.post('/api/v1/studio/orders/challenge')
async def studio_order_challenge(req: OrderSubmission, authorization: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    _official_store()
    try:
        return make_order_challenge(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post('/api/v1/studio/orders')
async def studio_create_order(req: OrderSubmission, authorization: str = Header(default=''),
                               x_ai_review_key: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    service = _official_service()
    try:
        source, _, _ = normalize(req.engagement)
        if source.ai_assistance:
            require_pilot_key('Bearer ' + x_ai_review_key if x_ai_review_key else authorization, ai=True)
        return await create_order(req, settings, service.store)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get('/api/v1/studio/orders/{order_id}')
async def studio_get_order(order_id: str, authorization: str = Header(default=''),
                            x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    try:
        return _official_store().get(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail='Order not found or private access key is invalid.') from exc


@app.post('/api/v1/studio/orders/recover')
async def studio_recover_order(req: OrderSubmission, authorization: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    store = _official_store()
    try:
        return await recover_order(req, settings, store)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get('/api/v1/studio/orders/{order_id}/result')
async def studio_order_result(order_id: str, authorization: str = Header(default=''),
                               x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    store = _official_store()
    try:
        store.get(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail='Order not found or private access key is invalid.') from exc
    try:
        return store.result(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail='The committed report is not ready.') from exc


@app.post('/api/v1/studio/orders/{order_id}/activate')
@app.post('/api/v1/studio/orders/{order_id}/retry')
async def studio_activate_order(order_id: str, authorization: str = Header(default=''),
                                  x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    service = _official_service()
    try:
        service.store.get(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail='Order not found or private access key is invalid.') from exc
    try:
        return await activate_order(order_id, x_order_token, settings, service.store)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post('/api/v1/studio/orders/{order_id}/refund/prepare')
async def studio_order_refund(order_id: str, authorization: str = Header(default=''),
                              x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    store = _official_store()
    try:
        store.get(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail='Order not found or private access key is invalid.') from exc
    from .services.order_refunds import prepare_order_refund
    try:
        return await prepare_order_refund(store._private(order_id))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post('/api/v1/studio/orders/{order_id}/refund/reconcile')
async def studio_reconcile_refund(order_id: str, authorization: str = Header(default=''),
                                  x_order_token: str = Header(default='')) -> dict:
    require_pilot_key(authorization)
    store = _official_store()
    try:
        store.get(order_id, x_order_token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail='Order not found or private access key is invalid.') from exc
    from .services.order_refunds import reconcile_order_refund
    try:
        return await reconcile_order_refund(order_id, x_order_token, store)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post('/api/v1/studio/ai/check')
async def studio_ai_check(authorization: str = Header(default=''), x_ai_review_key: str = Header(default='')) -> dict:
    require_pilot_key('Bearer ' + x_ai_review_key if x_ai_review_key else authorization, ai=True)
    from .swarm.llm import LlmClient
    return await LlmClient(settings).check_connection()


@app.get('/.well-known/stellar.toml', response_class=PlainTextResponse)
async def stellar_info() -> Response:
    # Publish only integrations that exist. No invented web-auth or anchor URL.
    from .services.report_delivery import pilot_evidence
    import json
    pilot = pilot_evidence()
    lines = ['VERSION="2.7.0"', 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
             '', '[DOCUMENTATION]', 'ORG_DESCRIPTION="AgentVeritas official agent audit Testnet pilot."',
             'ORG_GITHUB="furkan3152"', '', '[AGENTVERITAS]',
             'STATUS="testnet_pilot"', 'INDEPENDENT_OPERATORS=false',
             'CREDENTIAL_STANDARD="custom_nontransferable_audit_record"']
    if pilot.get('available'):
        for name, value in pilot['evidence'].get('contracts', {}).items():
            if name in {'registry', 'escrow', 'credential'} and isinstance(value, dict):
                lines.append(name.upper() + '_CONTRACT=' + json.dumps(value.get('id', '')))
    return PlainTextResponse('\n'.join(lines) + '\n', headers={'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300', 'X-Content-Type-Options': 'nosniff'})


@app.post('/api/v1/studio/plan')
async def studio_plan(req: EngagementRequest) -> dict:
    try:
        return build_plan(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post('/api/v1/studio/audit')
async def studio_audit(req: EngagementRequest, authorization: str = Header(default=''), x_ai_review_key: str = Header(default='')) -> dict:
    try:
        source, _, _ = normalize(req)
        if source.ai_assistance:
            require_pilot_key('Bearer ' + x_ai_review_key if x_ai_review_key else authorization, ai=True)
        if req.tier_id != 'quick':
            require_pilot_key(authorization)
        if _runtime_lock.locked():
            raise HTTPException(status_code=429, detail='An audit is in progress. Retry after it completes.')
        async with _runtime_lock:
            return await audit_engagement(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning('Audit execution incomplete: %s', type(exc).__name__)
        raise HTTPException(status_code=503, detail='The audit did not complete. Check the configured provider; no completed report or credential is claimed.') from exc


@app.post('/api/v1/studio/capsule/import')
async def studio_capsule_import(req: CapsuleImportRequest) -> dict:
    from .services.capsule import parse_capsule, compile_capsule, capsule_review_source
    try:
        capsule = parse_capsule(req.document)
        return {'capsule': capsule.model_dump(mode='json'), 'source': capsule_review_source(capsule).model_dump(mode='json'),
                'compiled': compile_capsule(capsule)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post('/api/v1/studio/capsule/export')
async def studio_capsule_export(req: EngagementRequest) -> dict:
    from .services.capsule import draft_capsule, compile_capsule
    try:
        source, existing, _ = normalize(req)
        capsule = existing or draft_capsule(source, tier=req.tier_id, modules=req.module_ids)
        return {'capsule': capsule.model_dump(mode='json'), 'compiled': compile_capsule(capsule)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post('/api/v1/studio/delivery')
async def studio_delivery(req: DeliveryRequest) -> dict:
    try:
        return await deliver_report(req)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get('/api/v1/studio/delivery/pilot')
async def studio_delivery_pilot() -> dict:
    return pilot_evidence()


@app.post("/api/v1/studio/discover")
async def studio_discover(req: ReviewRequest) -> dict:
    return discover_project(req.files)


@app.post("/api/v1/studio/stellar/inspect-auth")
async def studio_inspect_auth(req: AuthorizationInspectionRequest) -> dict:
    # Pure bounded decoding: no RPC, signatures, model calls or transaction submission.
    from .reporting.generator import canonical_json
    from hashlib import sha256
    report = inspect_authorization_entry(req)
    encoded = canonical_json(report)
    return {"report": report, "report_json": encoded,
            "report_sha256": sha256(encoded.encode()).hexdigest()}


@app.post("/api/v1/studio/runtime")
async def studio_runtime(req: RuntimeRequest, authorization: str = Header(default=""), x_ai_review_key: str = Header(default='')) -> dict:
    # Separate pilot credential; never expose the operator admin key to a public UI.
    expected = settings.runtime_api_key
    if len(expected) < 32 or not authorization.startswith("Bearer ") or not secrets.compare_digest(authorization[7:].encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="A valid runtime pilot access key is required.")
    if req.source.ai_assistance:
        require_pilot_key('Bearer ' + x_ai_review_key if x_ai_review_key else authorization, ai=True)
    if _runtime_lock.locked():
        raise HTTPException(status_code=429, detail="An isolated run is in progress. Retry after it completes.")
    async with _runtime_lock:
        try:
            return await run_runtime(req, settings)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.warning("Runtime provider unavailable: %s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="Isolated execution did not complete. Check Sandbox credentials, quota and provider logs. No runtime assurance is claimed.") from exc


@app.get("/api/v1/studio/capabilities")
async def studio_capabilities() -> dict:
    from .services.assurance import ArchitectureManifest
    return {"runtime_available": settings.enable_sandbox_runtime and len(settings.runtime_api_key) >= 32,
            "soroban_auth_inspection_available": True,
            "runtime_auth_required": True, "runtime_adapter": "python_text",
            "ai_available": settings.enable_public_ai_review and settings.llm_enabled,
            "ai_provider": settings.llm_provider if settings.enable_public_ai_review else "",
            "ai_connection": settings.llm_status(), "ai_auth_required": True,
            "controls": ArchitectureManifest.catalogue(), "checkout_enabled": False,
            "testnet_checkout_available": settings.stellar_network == 'testnet' and len(settings.runtime_api_key) >= 32 and len(settings.checkout_quote_signing_key) >= 32,
            "certificate_minting_enabled": False}


@app.post("/api/v1/studio/review")
async def studio_review(req: ReviewRequest, authorization: str = Header(default=''), x_ai_review_key: str = Header(default='')) -> dict:
    if req.ai_assistance:
        require_pilot_key('Bearer ' + x_ai_review_key if x_ai_review_key else authorization, ai=True)
    try:
        return await review_source(req, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/studio/identify")
async def studio_identify(req: AddressRequest) -> dict:
    return await identify_address(req)


class ResolveRequest(BaseModel):
    reference: str = Field(min_length=10, max_length=300)
    network: Literal["testnet", "mainnet"] = "testnet"


@app.post("/api/v1/studio/resolve")
async def studio_resolve(req: ResolveRequest) -> dict:
    """Read-only: what an agent reference resolves to and what each step proves."""
    from .services.agent_resolver import AgentResolver
    try:
        return await AgentResolver(settings, req.network).resolve(req.reference)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/studio/import")
async def studio_import(req: GitHubRequest) -> dict:
    try:
        return await import_github_bundle(req)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="GitHub could not be reached. Upload your bundle directly.") from exc


@app.post("/api/v1/agents/ingest", dependencies=[Depends(require_operator)])
async def ingest_agent(req: IngestRequest) -> dict:
    try:
        artifact = await ingestion.ingest(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ingestion error: {exc}") from exc

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
    """Returns the network-bound text to be signed by the G-account via Ed25519."""
    if not agent_ref or not owner:
        raise HTTPException(status_code=400, detail="agent_ref and owner are required")
    return {
        "message": canonical_message(agent_ref, owner, settings.network_passphrase),
        "network_passphrase": settings.network_passphrase,
        "scheme": "SEP-53 Ed25519 (G-account); SEP-45 for C-account",
    }


@app.post("/api/v1/ownership/verify")
async def ownership_verify(req: OwnershipVerifyRequest) -> dict:
    """Verifies the signature. Used for pre-check before initiating an audit."""
    check = verify_owner(
        req.agent_ref, req.owner, req.signature, settings.network_passphrase
    )
    return {
        "verified": check.verified,
        "reason": check.reason,
        "recovered": check.recovered,
        "evidence": check.evidence,
    }



@app.get("/api/v1/agents", dependencies=[Depends(require_operator)])
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


@app.get("/api/v1/agents/{agent_id}", dependencies=[Depends(require_operator)])
async def get_agent(agent_id: str) -> dict:
    artifact = pipeline.store.get_agent(agent_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="agent not found")
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
                    "state": exc.state,
                    "reason": str(exc),
                    "invocation": job.escrow.tx_ref if job.escrow and exc.state == "awaiting_signature" else "",
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
                "state": exc.state,
                "reason": str(exc),
                "invocation": job.escrow.tx_ref if job and job.escrow and exc.state == "awaiting_signature" else "",
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
    except ExternalSignatureRequired as exc:
        job = pipeline.store.get_job(job_id)
        raise HTTPException(
            status_code=409,
            detail={
                "job_id": job_id,
                "state": exc.state,
                "reason": str(exc),
                "invocation": job.escrow.tx_ref if job and job.escrow and exc.state == "awaiting_signature" else "",
            },
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _job_view(job)


@app.get("/api/v1/jobs", dependencies=[Depends(require_operator)])
async def list_jobs(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return {"jobs": [_job_view(j) for j in pipeline.store.recent_jobs(limit)]}


@app.get("/api/v1/jobs/{job_id}", dependencies=[Depends(require_operator)])
async def get_job(job_id: str) -> dict:
    job = pipeline.store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return _job_view(job)


@app.get("/api/v1/jobs/{job_id}/report.md", response_class=PlainTextResponse, dependencies=[Depends(require_operator)])
async def job_report_md(job_id: str) -> str:
    try:
        return pipeline.markdown_for(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/jobs/{job_id}/report.json", dependencies=[Depends(require_operator)])
async def job_report_json(job_id: str) -> dict:
    try:
        return pipeline.json_for(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/jobs/{job_id}/report.committed.json", dependencies=[Depends(require_operator)])
async def job_committed_report(job_id: str) -> Response:
    try:
        content = pipeline.committed_json_for(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(content, media_type="application/json", headers={
        "Content-Disposition": 'attachment; filename="agent-review.committed.json"',
    })


# ------------------------------------------------------------------ validation
@app.post("/api/v1/validation/requests", dependencies=[Depends(require_operator)])
async def validation_request(hook: ValidationRequestHook) -> dict:
    """Initiates an audit when a verified Soroban request event arrives."""
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
        raise HTTPException(status_code=400, detail="agent_id or agent_address required")

    job = pipeline.create_job(agent_id, hook.tier, hook.requester, hook.request_hash)
    try:
        await pipeline.fund_job(job.id, hook.requester)
    except ExternalSignatureRequired as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "job_id": job.id,
                "state": exc.state,
                "reason": str(exc),
                "invocation": job.escrow.tx_ref if job.escrow and exc.state == "awaiting_signature" else "",
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
@app.get("/api/v1/badges", dependencies=[Depends(require_operator)])
async def all_badges() -> dict:
    return {"badges": pipeline.badges.all_badges()}


@app.get("/api/v1/badges/{identifier}", dependencies=[Depends(require_operator)])
async def get_badge(identifier: str) -> dict:
    record = pipeline.badges.get(identifier)
    if not record:
        raise HTTPException(status_code=404, detail="badge not found")
    return {"badge": record, "history": pipeline.badges.get_history(identifier)}


# ------------------------------------------------------------------ monitoring
@app.post("/api/v1/monitor/subscribe", dependencies=[Depends(require_operator)])
async def monitor_subscribe(req: MonitorSubscribe) -> dict:
    try:
        sub = pipeline.subscribe_monitor(req.agent_id, req.interval_minutes, req.prepaid_usdc)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return sub.model_dump(mode="json")


@app.get("/api/v1/monitor/subscriptions", dependencies=[Depends(require_operator)])
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


@app.get("/api/v1/ledger/nanopayments", dependencies=[Depends(require_operator)])
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
        return FileResponse(FRONTEND_DIR / "studio.html")

    @app.get("/operator")
    async def operator_console() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")
