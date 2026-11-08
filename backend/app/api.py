"""FastAPI application: agent ingestion, deep audit, and Soroban validation preparation."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .config import get_settings
from .stellar.ownership import canonical_message, verify_owner
from .ingestion import IngestionService, IngestRequest
from .ingestion.templates import list_templates
from .models import AuditTier
from .services.chain_status import ChainStatusService
from .services.escrow import EscrowIndeterminateError, ExternalSignatureRequired
from .services.pipeline import AuditPipeline
from .services.studio import ReviewRequest, review_source
from .services.demo_flow import DemoAuditRequest as DemoAuditRequestModel, DemoCredentialRequest as DemoCredentialRequestModel
from .studio_guard import StudioGuard
from .services.studio_intake import AddressRequest, GitHubRequest, identify_address, import_github_bundle

logger = logging.getLogger("touchmark.api")


class _NoStorePaths(logging.Filter):
    """Drops HTTP client records that name an audit job's store path: a job id is the job's only
    credential (continue, cancel), so it must not reach the runtime logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except Exception:  # noqa: BLE001 - a record that cannot be formatted is dropped
            return False
        return "touchmark-jobs/" not in text and "touchmark-limits/" not in text


def quiet_http_client_logs() -> None:
    """httpx logs every request at INFO with its URL, and Vercel Blob URLs carry the object path
    (touchmark-jobs/<day>/<job token>/...). Those lines are kept out of the logs: the HTTP
    client loggers log warnings and errors only, and never a store path."""
    for name in ("httpx", "httpx2", "httpcore"):
        client_logger = logging.getLogger(name)
        client_logger.setLevel(logging.WARNING)
        if not any(isinstance(f, _NoStorePaths) for f in client_logger.filters):
            client_logger.addFilter(_NoStorePaths())


quiet_http_client_logs()

settings = get_settings()
pipeline = AuditPipeline(settings)
ingestion = IngestionService(settings)
chain_status = ChainStatusService(settings)

#: Health of the background patrol cycle, reported by `/api/v1/stats` so a loop that
#: keeps crashing is visible.
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
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 - shutdown path
            pass
        pipeline.store.flush()


async def _monitor_loop() -> None:
    """Minute-based patrol cycle.

    Errors are counted and logged rather than swallowed, so a subscription check that
    fails on every cycle does not look healthy.
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
        except Exception as exc:  # noqa: BLE001 - the loop must stay alive
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
    title="Touchmark",
    version=settings.version,
    description="Stellar agent validation layer — Soroban registry and evidence-first audits.",
    lifespan=lifespan,
    # /docs is the documentation page (frontend/docs.html); the generated reference moves here.
    docs_url="/api/reference",
    redoc_url=None,
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
            # Two different model integrations: the deep review and its verifier (Anthropic,
            # ANTHROPIC_API_KEY) and the optional public AI second opinion (LLM_PROVIDER).
            "deep_review": _model_review_status(),
            "ai_second_opinion": {"configured": settings.llm_enabled,
                                  "enabled": bool(settings.enable_public_ai_review and settings.llm_enabled),
                                  "provider": settings.llm_provider if settings.llm_enabled else ""},
            # Kept for older clients: the AI second opinion's provider (LLM_PROVIDER), not the deep review.
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
             '', '[DOCUMENTATION]', 'ORG_DESCRIPTION="Touchmark official agent audit Testnet pilot."',
             'ORG_GITHUB="furkan3152"', '', '[TOUCHMARK]',
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


def _studio_ai_mode() -> str:
    """Which model the Studio AI option uses (studio.review_source): the deep review first."""
    if not len(settings.ai_review_api_key or settings.runtime_api_key) >= 32:
        return ""  # no pilot key can be accepted, so the option cannot be used
    if settings.enable_deep_review and settings.anthropic_api_key:
        return "deep_review"
    if settings.enable_public_ai_review and settings.llm_enabled:
        return "second_opinion"
    return ""


@app.get("/api/v1/studio/capabilities")
async def studio_capabilities() -> dict:
    from .services.assurance import ArchitectureManifest
    return {"runtime_available": settings.enable_sandbox_runtime and len(settings.runtime_api_key) >= 32,
            "soroban_auth_inspection_available": True,
            "runtime_auth_required": True, "runtime_adapter": "python_text",
            # The AI option runs the deep review (Anthropic) when it is configured, otherwise the
            # public second opinion (LLM_PROVIDER); either needs the private pilot access key.
            "ai_available": _studio_ai_mode() != "",
            "ai_mode": _studio_ai_mode(),
            "ai_provider": ("anthropic" if _studio_ai_mode() == "deep_review"
                            else settings.llm_provider if _studio_ai_mode() == "second_opinion" else ""),
            "ai_model": (settings.deep_review_model if _studio_ai_mode() == "deep_review"
                         else settings.llm_model if _studio_ai_mode() == "second_opinion" else ""),
            "deep_review": {"configured": bool(settings.enable_deep_review and settings.anthropic_api_key),
                            "verifier": bool(settings.enable_deep_review and settings.anthropic_api_key
                                             and settings.enable_finding_verification)},
            "ai_second_opinion": {"configured": bool(settings.enable_public_ai_review and settings.llm_enabled),
                                  "provider": settings.llm_provider if settings.enable_public_ai_review else ""},
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


_demo_issuance: dict[str, deque] = defaultdict(deque)
_demo_issuance_all: deque = deque()


def _demo_client(request: Request) -> str:
    """The visitor's address as Vercel reports it (x-real-ip, else the last x-forwarded-for
    hop, which Vercel sets); elsewhere the socket peer. Headers are trusted only on Vercel.
    The model-review allowance stores only an HMAC of it (services/rate_limit.py)."""
    if os.environ.get("VERCEL"):
        real = request.headers.get("x-real-ip", "").strip()
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if real or forwarded:
            return (real or forwarded)[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _demo_issuance_allowed(client: str) -> bool:
    """Each issuance writes four Testnet transactions: 3 per client per 10 minutes, 40 per hour overall."""
    now = time.monotonic()
    mine = _demo_issuance[client]
    while mine and now - mine[0] >= 600:
        mine.popleft()
    while _demo_issuance_all and now - _demo_issuance_all[0] >= 3600:
        _demo_issuance_all.popleft()
    if len(mine) >= 3 or len(_demo_issuance_all) >= 40:
        return False
    mine.append(now)
    _demo_issuance_all.append(now)
    return True


@app.get("/api/v1/demo/config")
async def demo_config(request: Request) -> dict:
    from .services.demo_flow import issuance_enabled, manifest
    data = manifest()
    review = _model_review_status()
    return {"issuance_enabled": issuance_enabled(), "network": "testnet",
            "contracts": {k: v.get("id") for k, v in data.get("contracts", {}).items()},
            "operator": data.get("operator", ""),
            # The home page asks for consent before any source goes to a model.
            "model_review": review,
            # How many model reviews this visitor has left (null when it cannot be told).
            "allowance": await _allowance_for(request) if review["available"] else None,
            "streaming": True}


#: {hashed client: (monotonic time, allowance)}: page loads within this many seconds share one look.
_allowance_cache: dict[str, tuple[float, dict]] = {}
ALLOWANCE_CACHE_SECONDS = 20.0


async def _allowance_for(request: Request) -> dict | None:
    """The visitor's model-review allowance, read without claiming (cached briefly, because each
    look lists the store). None when the store cannot answer: the audit still decides."""
    from .services.rate_limit import StoreUnavailable, limiter_from_settings
    limiter = limiter_from_settings(settings)
    key = limiter.client_key(_demo_client(request))
    hit = _allowance_cache.get(key)
    if hit and time.monotonic() - hit[0] < ALLOWANCE_CACHE_SECONDS:
        return hit[1]
    try:
        out = limiter.describe(await limiter.remaining(_demo_client(request)))
        if await _daily_cost_reached(limiter):
            out = _daily_cost_used_up(limiter, out)
        else:
            out["daily_cost_available"] = True
    except StoreUnavailable:
        return None
    if len(_allowance_cache) > 2000:
        _allowance_cache.clear()
    _allowance_cache[key] = (time.monotonic(), out)
    return out


async def _daily_cost_reached(limiter) -> bool:
    """Has today's model-review cost cap been used up? (Raises StoreUnavailable.)"""
    from .services.review_budget import daily_cost_reached
    return limiter.store is not None and await daily_cost_reached(settings, limiter.store)


def _daily_cost_used_up(limiter, allowance: dict | None = None) -> dict:
    """The allowance as a visitor sees it once the daily cost cap is reached: used up until the
    next UTC midnight. Only that it is reached is said, never an amount."""
    from datetime import timedelta
    now = limiter.clock()
    next_day = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).isoformat()
    return {**(allowance or {"left_this_hour": None, "left_today": None}), "used_up": True, "reason": "daily_cost",
            "resets_at": next_day, "daily_cost_available": False}


def _model_review_status() -> dict:
    """What the model review needs and where its allowance lives, without calling anyone."""
    from .services.rate_limit import store_kind
    configured = bool(settings.enable_deep_review and settings.anthropic_api_key)
    store = store_kind(settings)
    return {"configured": configured, "available": configured and store != "none",
            "provider": "anthropic" if configured else "", "model": settings.deep_review_model if configured else "",
            "verifier": bool(configured and settings.enable_finding_verification),
            "verifier_model": settings.verifier_model if configured and settings.enable_finding_verification else "",
            "consent_required": True, "allowance_store": store,
            "limits": {"per_client_per_hour": settings.deep_review_client_hourly_limit,
                       "per_hour": settings.deep_review_hourly_limit, "per_day": settings.deep_review_daily_limit}}


async def _model_review_allowed(request: Request, consent: bool) -> tuple[bool, dict | None, dict | None]:
    """(run the model review?, why not, the allowance left). Fails closed: no consent, no
    allowance or an unreachable allowance store all mean rules only, never a failed audit."""
    if not (settings.enable_deep_review and settings.anthropic_api_key):
        return False, None, None
    if not consent:
        return False, {"reason": "no_consent", "note": "Rules only: the source was not sent to the model review "
                                                       "because consent was not given."}, None
    from .services.rate_limit import limiter_from_settings
    limiter = limiter_from_settings(settings)
    try:
        # Checked before an allowance slot is claimed: once today's cost cap is used up, no model
        # review starts until the next UTC day, and no slot is spent on a review that cannot run.
        if await _daily_cost_reached(limiter):
            allowance = _daily_cost_used_up(limiter)
            return False, {"reason": "rate_limited", "limit": "daily_cost",
                           "note": "The demo reached today's model-review limit, so this audit used the rules only. "
                                   "Model reviews resume at 00:00 UTC."}, allowance
        decision = await limiter.acquire(_demo_client(request))
    except Exception as exc:  # noqa: BLE001 - the allowance must never fail the audit
        logger.warning("model-review allowance failed: %s", type(exc).__name__)
        return False, {"reason": "store_unavailable", "note": "The model-review allowance could not be checked; "
                                                              "this audit used the rules only."}, None
    _allowance_cache.pop(limiter.client_key(_demo_client(request)), None)
    allowance = limiter.describe(decision.left) if decision.left else None
    if allowance is not None:
        allowance["daily_cost_available"] = True
    if decision.allowed:
        return True, None, allowance
    reason = "rate_limited" if decision.reason in {"client_hour", "hour", "day"} else decision.reason
    return False, {"reason": reason, "note": decision.message + " This audit used the rules only.",
                   "limit": decision.reason}, allowance


def _tmark_errors_detail(errors: list[dict]) -> dict:
    return {"message": "The .tmark is not valid, so nothing was audited. Fix each field listed and try again.",
            "tmark_errors": errors}


#: Seconds between heartbeat lines on a streamed audit: below every common proxy idle timeout.
HEARTBEAT_SECONDS = 10.0
#: A request is answered by then whatever happens (vercel.json allows app.py 300 s). A job leg
#: stops starting model calls at demo_leg_seconds, well before.
DEMO_REQUEST_SECONDS = 290


class DemoJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=10, max_length=64)


# ------------------------------------------------------------------ the assay book
_HEX64_PATTERN = "^[0-9a-f]{64}$"


class AssayEntryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entry: str = Field(pattern=_HEX64_PATTERN)


class AssayPrepareRequest(AssayEntryRequest):
    payer: str = Field(min_length=56, max_length=56)


class AssaySubmitRequest(AssayEntryRequest):
    signed_xdr: str = Field(min_length=20, max_length=20_000)


class AssayClaimRequest(AssayEntryRequest):
    tx_hash: str = Field(default="", pattern="^([0-9a-f]{64})?$")


def _book_errors(fn):
    """Assay-book endpoints: a refusal is a 422 with its message; Horizon or the store not
    answering is a 503 that says so, never a bare 500 with internals."""
    import functools

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        from .services.assay_book import BookError
        try:
            return await fn(*args, **kwargs)
        except HTTPException:
            raise
        except BookError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - network or store failure; logged by class only
            logger.warning("assay book unavailable: %s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="Stellar testnet or the book store did not answer. "
                                                        "Try again in a minute.") from exc
    return wrapper


def _book_store():
    from .services.assay_book import store_from_settings
    store = store_from_settings(settings)
    if store is None or not settings.enable_assay_book:
        raise HTTPException(status_code=404, detail="The assay book is not enabled on this deployment.")
    return store


@app.get("/api/v1/assay/book")
@_book_errors
async def assay_book_stats() -> dict:
    """Every entry in the assay book, counted, with the latest entries and their transactions."""
    from .services.assay_book import book
    if not settings.enable_assay_book:
        return {"enabled": False}
    return await book(settings)


@app.get("/api/v1/assay/entry/{entry}")
@_book_errors
async def assay_entry(entry: str) -> dict:
    """The entry as stamped: sha256(canonical JSON of ``entry``) is the stamp transaction's memo."""
    from .services.assay_book import load_entry, paid_record, tx_url
    store = _book_store()
    record = await load_entry(store, entry)
    if record is None:
        raise HTTPException(status_code=404, detail="No such entry in the assay book.")
    paid = await paid_record(store, entry)
    return {**record, "stamp_url": tx_url(record["stamp_tx"]), "paid": bool(paid),
            "how_to_verify": "sha256 of the canonical JSON (sorted keys, no spaces) of `entry` equals the "
                             "memo hash of `stamp_tx`, sent from `account` on Stellar testnet."}


@app.get("/api/v1/assay/report/{entry}.json")
@_book_errors
async def assay_report_json(entry: str) -> Response:
    """The report bytes, once paid. Their SHA-256 is the entry's report_sha256."""
    from .services.assay_book import load_entry, load_report, paid_record
    store = _book_store()
    record = await load_entry(store, entry)
    if record is None:
        raise HTTPException(status_code=404, detail="No such entry in the assay book.")
    if not await paid_record(store, entry):
        raise HTTPException(status_code=402, detail="This report is released for a testnet payment.")
    data = await load_report(store, record["entry"]["report_sha256"])
    if data is None:
        raise HTTPException(status_code=404, detail="The report is not stored.")
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="touchmark-{entry[:12]}.json"'})


@app.post("/api/v1/assay/pay/prepare")
@_book_errors
async def assay_pay_prepare(req: AssayPrepareRequest) -> dict:
    from .services.assay_book import BookError, prepare_payment
    try:
        return await prepare_payment(req.entry, req.payer, settings, store=_book_store())
    except BookError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/assay/pay/submit")
@_book_errors
async def assay_pay_submit(req: AssaySubmitRequest) -> dict:
    """Relay a wallet-signed payment for an entry, then release the report from the ledger."""
    from .services.assay_book import BookError, claim, submit_payment
    store = _book_store()
    try:
        tx_hash = await submit_payment(req.entry, req.signed_xdr, settings, store=store)
        return await claim(req.entry, settings, tx_hash=tx_hash, store=store)
    except BookError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/assay/claim")
@_book_errors
async def assay_claim(req: AssayClaimRequest) -> dict:
    """Look for the entry's payment on Horizon; when it is there, release the report."""
    from .services.assay_book import BookError, claim
    try:
        return await claim(req.entry, settings, tx_hash=req.tx_hash, store=_book_store())
    except BookError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/demo/audit")
async def demo_audit(req: "DemoAuditRequestModel", request: Request):
    """Audit a GitHub repository, folder or agent reference: the deterministic analysers, plus
    the model review and verification when configured, consented to and within the allowance.

    No clock ends the review; only a spend cap can (services/review_budget.py). Where the
    deployment has a job store the audit is a job (services/audit_jobs.py): this request runs
    the first leg, and an audit that needs more than one request ends its stream with a
    ``continue`` event; POST /api/v1/demo/audit/continue runs the next leg.

    With ``Accept: application/x-ndjson`` the response is a stream of JSON lines: a ``job``
    event, ``stage`` events (resolving, fetching, rules, deep_review, verifier, done), a
    ``heartbeat`` every few seconds, then one of ``result`` (the same object as the plain
    response), ``continue``, ``busy``, ``cancelled`` or ``error``."""
    from .services import tmark as tmark_format
    from .services.audit_jobs import StoreError, manager_from_settings
    from .services.demo_flow import run_demo_audit
    if req.tmark is not None:
        parsed, errors = tmark_format.check(req.tmark)
        if parsed is None:
            raise HTTPException(status_code=422, detail=_tmark_errors_detail(errors))

    async def run(started: float, abandoned, announce) -> dict:
        ai, skipped, allowance = await _model_review_allowed(request, req.model_review_consent)
        manager = manager_from_settings(settings)
        handle = None
        if manager is not None:
            try:
                # The job takes the allowance slot claimed above, once: its later legs claim none.
                handle = await manager.create({"reference": req.reference, "tmark": req.tmark, "ai": ai,
                                               "consent": req.model_review_consent, "skipped": skipped,
                                               "allowance": allowance})
            except StoreError as exc:
                logger.warning("audit job could not be created: %s", exc)
                if ai:  # the allowance is spent; without a job a long review could not continue
                    raise HTTPException(status_code=503, detail="The audit store is unavailable. "
                                                                "Run it again in a minute.") from exc
        if handle is None:
            # No job store (serverless without Blob): rules only, which one request always holds.
            try:
                out = await asyncio.wait_for(asyncio.to_thread(_in_own_loop, run_demo_audit, req.reference, settings,
                                                               ai=ai, tmark_text=req.tmark, skipped=skipped),
                                             timeout=DEMO_REQUEST_SECONDS)
            except asyncio.TimeoutError as exc:
                raise HTTPException(status_code=504, detail="The audit did not finish within one request. "
                                                            "Large repositories can be audited with scripts/audit_agent.py.") from exc
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if allowance is not None:
                out["ai"]["allowance"] = allowance
            return {"type": "result", "data": out}
        return await _run_job_leg(handle, started, abandoned, announce)

    return await _respond(run, request)


@app.post("/api/v1/demo/audit/continue")
async def demo_audit_continue(req: DemoJobRequest, request: Request):
    """Run the next leg of an audit job. Idempotent: a finished job returns its result again; a
    job another request is advancing answers ``busy`` with when to try again; two continues of
    one job can never both run (create-only snapshots, services/audit_jobs.py)."""
    from .services.audit_jobs import StoreError, describe, manager_from_settings

    async def run(started: float, abandoned, announce) -> dict:
        manager = manager_from_settings(settings)
        if manager is None:
            raise HTTPException(status_code=404, detail="This deployment keeps no audit jobs.")
        try:
            status, handle, info = await manager.claim(req.job_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Not a job id.") from exc
        except StoreError as exc:
            raise HTTPException(status_code=503, detail="The audit store is unavailable. Try again in a minute.") from exc
        if status == "completed":
            return {"type": "result", "data": info["result"]}
        if status == "busy":
            return {"type": "busy", **describe(info), "retry_after": info.get("retry_after", 5)}
        if status in ("missing", "expired"):
            raise HTTPException(status_code=410, detail="This audit is no longer kept (audits expire after "
                                                        f"{settings.demo_job_ttl_hours:g} hours). Run it again.")
        if status == "cancelled":
            return {"type": "cancelled", **describe(info)}
        if status == "failed":
            raise HTTPException(status_code=422, detail=info.get("error") or "This audit stopped. Run it again.")
        return await _run_job_leg(handle, started, abandoned, announce)

    return await _respond(run, request)


@app.post("/api/v1/demo/audit/cancel")
async def demo_audit_cancel(req: DemoJobRequest) -> dict:
    """Cancel an audit job: a running leg stops before its next model call; nothing continues it."""
    from .services.audit_jobs import StoreError, manager_from_settings
    manager = manager_from_settings(settings)
    if manager is None:
        raise HTTPException(status_code=404, detail="This deployment keeps no audit jobs.")
    try:
        status = await manager.cancel(req.job_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Not a job id.") from exc
    except StoreError as exc:
        raise HTTPException(status_code=503, detail="The audit store is unavailable. Try again.") from exc
    return {"job_id": req.job_id, "status": status}


async def _run_job_leg(handle, started: float, abandoned, announce) -> dict:
    from .services.audit_jobs import describe, run_leg
    announce({"type": "job", **describe(handle.state)})
    try:
        return await asyncio.wait_for(asyncio.to_thread(_in_own_loop, run_leg, handle, settings, started=started,
                                                        abandoned=abandoned), timeout=DEMO_REQUEST_SECONDS)
    except asyncio.TimeoutError:
        abandoned.set()  # the leg saves and stops at its next model call; the page continues it
        return {"type": "continue", **describe(handle.state), "reason": "request_limit", "retry_after": 10}


async def _respond(run, request: Request):
    """Stream the leg as NDJSON when asked; otherwise answer once (202 while a job is unfinished)."""
    import threading
    if "application/x-ndjson" in request.headers.get("accept", ""):
        return StreamingResponse(_stream(run), media_type="application/x-ndjson",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
    event = await run(time.monotonic(), threading.Event(), lambda _event: None)
    if event["type"] == "result":
        return event["data"]
    if event["type"] == "error":
        raise HTTPException(status_code=event.get("status", 500), detail=event.get("detail", ""))
    return JSONResponse(event, status_code=202)


def _in_own_loop(fn, *args, **kwargs):
    """Run a coroutine function to completion on a fresh event loop in the calling (worker)
    thread. Context variables, such as the progress listener, come along with to_thread."""
    return asyncio.run(fn(*args, **kwargs))


async def _stream(run):
    """NDJSON lines for one leg: stage events as they happen, heartbeats while waiting, then
    the event that ends the leg. A client that goes away stops the leg at its next model call."""
    import json
    import threading
    from .services import progress
    queue: asyncio.Queue = asyncio.Queue()
    started = time.monotonic()
    state = {"stage": "queued"}
    abandoned = threading.Event()

    loop = asyncio.get_running_loop()

    def deliver(event: dict) -> None:
        state["stage"] = event.get("stage", state["stage"])
        queue.put_nowait(event)

    def on_event(event: dict) -> None:
        # Called from the audit's worker thread: hand the event to this loop safely.
        try:
            loop.call_soon_threadsafe(deliver, event)
        except RuntimeError:
            pass  # the response already ended

    def line(payload: dict) -> bytes:
        # A job event carries the whole audit's elapsed time (every leg); keep it, so a reloaded page
        # resumes the real clock. Other lines say how long this request has run.
        leg = round(time.monotonic() - started, 1)
        return (json.dumps({"elapsed": leg, **payload, "leg_elapsed": leg}, default=str) + "\n").encode()

    token = progress.listen(on_event)
    try:
        task = asyncio.create_task(run(started, abandoned, on_event))  # copies the context: reports to on_event
    finally:
        progress.stop(token)
    yield line({"type": "stage", "stage": "queued"})
    try:
        # Wake on the next event, the end of the leg, or the heartbeat interval: whichever
        # comes first. Waiting on the queue alone held the result back by up to one interval.
        getter = None
        while True:
            getter = getter or asyncio.ensure_future(queue.get())
            done, _ = await asyncio.wait({getter, task}, timeout=HEARTBEAT_SECONDS,
                                         return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                yield line({"type": "stage", **getter.result()})
                getter = None
            elif task.done():
                getter.cancel()
                while not queue.empty():  # events posted just before the end
                    yield line({"type": "stage", **queue.get_nowait()})
                break
            else:
                yield line({"type": "heartbeat", "stage": state["stage"]})
        try:
            yield line(task.result())
        except HTTPException as exc:
            yield line({"type": "error", "status": exc.status_code, "detail": exc.detail})
        except Exception as exc:  # noqa: BLE001 - reported to the client, not hidden
            logger.warning("streamed demo audit failed: %s", type(exc).__name__)
            yield line({"type": "error", "status": 500, "detail": "The audit stopped on an internal error. Try again."})
    finally:
        if not task.done():
            abandoned.set()  # the client went away: the leg saves its place and stops
            task.cancel()


_self_check_last = [0.0]


@app.post("/api/v1/ops/allowance-check")
async def allowance_self_check(request: Request, authorization: str | None = Header(default=None)) -> dict:
    """Operator self-check of the model-review allowance store: a create-only claim on a
    throwaway path, the same claim again (it must be refused), a listing and a delete, against
    the store this deployment really uses. Answers booleans and exception class names only.

    Open on Vercel preview deployments (behind the team's deployment protection) and to the
    operator key anywhere else; one run per 10 seconds per instance."""
    from .services.rate_limit import BlobStore, limiter_from_settings, self_check, store_kind
    keyed = bool(settings.admin_api_key) and secrets.compare_digest(
        (authorization or "").partition(" ")[2].encode(), settings.admin_api_key.encode())
    if not (os.environ.get("VERCEL_ENV") == "preview" or keyed):
        raise HTTPException(status_code=404, detail="Not Found")
    if time.monotonic() - _self_check_last[0] < 10:
        raise HTTPException(status_code=429, detail="One self-check per 10 seconds.")
    _self_check_last[0] = time.monotonic()
    store = limiter_from_settings(settings).store
    out = {"allowance_store": store_kind(settings), "environment": os.environ.get("VERCEL_ENV", "")}
    if store is None:
        return {**out, "ok": False, "note": "No allowance store is configured; the model review is refused."}
    result = await self_check(store)
    if isinstance(store, BlobStore):
        result["note"] = ("Vercel Blob refused the second create-only write as already existing."
                          if result["ok"] else "The Blob store did not behave as the limiter needs; see the fields.")
    return {**out, **result}


@app.post("/api/v1/ops/job-check")
async def job_self_check(request: Request, authorization: str | None = Header(default=None)) -> dict:
    """Operator self-check of the audit-job machinery on the store this deployment uses: two
    request legs of one job with a model client that costs nothing, a double continue (exactly
    one may run), resume, an idempotent continue of the finished job, cancel and deletion.
    Answers booleans and counts only. Open on preview deployments and to the operator key."""
    from .services.audit_jobs import job_store_from_settings, self_check
    keyed = bool(settings.admin_api_key) and secrets.compare_digest(
        (authorization or "").partition(" ")[2].encode(), settings.admin_api_key.encode())
    if not (os.environ.get("VERCEL_ENV") == "preview" or keyed):
        raise HTTPException(status_code=404, detail="Not Found")
    if time.monotonic() - _self_check_last[0] < 10:
        raise HTTPException(status_code=429, detail="One self-check per 10 seconds.")
    _self_check_last[0] = time.monotonic()
    store = job_store_from_settings(settings)
    from .services.rate_limit import store_kind
    out = {"job_store": store_kind(settings), "environment": os.environ.get("VERCEL_ENV", ""),
           "leg_seconds": settings.demo_leg_seconds}
    if store is None:
        return {**out, "ok": False, "note": "No job store is configured: audits run in one request, rules only."}
    return {**out, **await asyncio.to_thread(_in_own_loop, self_check, store, settings)}


class TmarkCheckRequest(BaseModel):
    text: str = Field(min_length=2, max_length=64_000)


@app.post("/api/v1/tmark/check")
async def tmark_check(req: TmarkCheckRequest) -> dict:
    """Validate a .tmark file: every error with its field and line, the declaration as Touchmark
    reads it and a plain summary. Nothing is stored."""
    from .services import tmark
    parsed, details = tmark.check(req.text)
    out = {"valid": parsed is not None, "errors": [f"{d['field']}: {d['message']}" for d in details],
           "error_details": details, "latest_version": tmark.VERSION, "schema": tmark.SCHEMA_URL}
    if parsed is not None:
        out.update(agent=parsed.agent.name, network=parsed.agent.network, version=parsed.tmark,
                   normalized=tmark.normalized(parsed), summary=tmark.summary(parsed))
    return out


@app.get("/api/v1/tmark/template")
async def tmark_template() -> dict:
    from .services import tmark
    return tmark.template({"payment", "stellar_signing"})


class TmarkDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: A GitHub repository or folder link (as on the home page) ...
    reference: str = Field(default="", max_length=300)
    #: ... or source files (as in Studio): {path: text}.
    files: dict[str, str] = Field(default_factory=dict, max_length=200)
    name: str = Field(default="", max_length=80)


@app.post("/api/v1/tmark/template")
async def tmark_draft(req: TmarkDraftRequest) -> dict:
    """A .tmark draft from a repository's code: the tools it registers and what the code in each
    tool's file can do. Repository code is parsed, never executed; nothing is stored."""
    from .services import tmark
    if bool(req.reference) == bool(req.files):
        raise HTTPException(status_code=422, detail="Give either a repository reference or source files.")
    if req.files:
        if sum(len(v.encode()) for v in req.files.values()) > 2_000_000:
            raise HTTPException(status_code=422, detail="Source limit: 2 MB in total.")
        return tmark.draft_from_source(req.files, name=req.name)
    try:
        return await asyncio.wait_for(asyncio.to_thread(_in_own_loop, _draft_from_reference, req.reference, req.name), timeout=90)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="The repository could not be read in time.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _draft_from_reference(reference: str, name: str) -> dict:
    import re as _re
    import tempfile
    from .services import tmark
    from .services.agent_resolver import AgentResolver
    from .services.repo_audit import select_repository
    resolver = AgentResolver(settings, "testnet")
    resolution = await resolver.resolve(reference.strip())
    source = resolution["source"]
    if not source.get("repository") or not _re.fullmatch(r"[0-9a-f]{40}", source.get("revision") or ""):
        raise ValueError("No source repository could be pinned for this reference.")
    with tempfile.TemporaryDirectory(prefix="touchmark-draft-") as tmp:
        root = await resolver.download(source["repository"], source["revision"], Path(tmp))
        if source.get("path"):
            sub = (root / source["path"]).resolve()
            if not sub.is_dir() or not sub.is_relative_to(root.resolve()):
                raise ValueError(f"The folder {source['path']} does not exist in the repository.")
            root = sub
        files, _ = select_repository(root)
    if not files:
        raise ValueError("No supported source files were found in the repository.")
    out = tmark.draft_from_source(files, name=name or source["repository"].rsplit("/", 1)[-1][:80])
    out["source"] = {k: source.get(k, "") for k in ("repository", "revision", "path")}
    return out


class DemoCompareRequest(BaseModel):
    before: str = Field(min_length=3, max_length=300)
    after: str = Field(min_length=3, max_length=300)


@app.post("/api/v1/demo/compare")
async def demo_compare(req: DemoCompareRequest) -> dict:
    """Re-audit two references (for example a commit and its fix) and show what changed.

    Both sides run the deterministic rules only, so they are compared like with like. That is
    not the audit's full review: its scores can differ from a model-reviewed audit, and a
    model-review finding is never listed as closed here, because neither side looked for it."""
    from .services.agent_resolver import audit_reference
    from .services.report_diff import compare_reports
    try:
        # The analysers are synchronous CPU work: run each side in its own worker thread, as the
        # audit does, so other requests (and their heartbeats) are not held up meanwhile.
        before, after = await asyncio.wait_for(asyncio.gather(
            asyncio.to_thread(_in_own_loop, audit_reference, req.before, settings, network="testnet", deep=False),
            asyncio.to_thread(_in_own_loop, audit_reference, req.after, settings, network="testnet", deep=False)),
            timeout=170)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="The comparison did not finish within the demo time limit.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    comparison = compare_reports(before["report"], after["report"])
    # Belt and braces: a rules-only report holds no model findings, and none may read as fixed.
    comparison["closed"] = [f for f in comparison.get("closed", []) if "-ai-" not in f.get("id", "")]
    return {"mode": "rules_only", "comparison": comparison,
            "note": ("Rules-only comparison: both versions were re-checked by the deterministic rules, not the model "
                     "review. Scores are rules-only scores and can differ from a full audit; findings only the model "
                     "review reports are not re-checked here and are never shown as closed."),
            "before_sha256": before["report_sha256"], "after_sha256": after["report_sha256"]}


class DemoPrepareRequest(BaseModel):
    ticket: str = Field(min_length=20, max_length=4000)


@app.post("/api/v1/demo/credential/prepare")
async def demo_credential_prepare(req: DemoPrepareRequest) -> dict:
    """The registration transaction the repository's named owner signs in their wallet."""
    from .services.demo_flow import DemoError, prepare_owner_registration
    try:
        return await prepare_owner_registration(req.ticket)
    except DemoError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/demo/credential")
async def demo_credential(req: "DemoCredentialRequestModel", request: Request) -> dict:
    """Issue the Testnet AuditCredential for a passing demo audit (server-signed ticket required)."""
    from .services.demo_flow import DemoError, issue_demo_credential
    if not _demo_issuance_allowed(_demo_client(request)):
        raise HTTPException(status_code=429, detail="Too many credential requests; try again in a few minutes.")
    try:
        return await issue_demo_credential(req.ticket, req.signed_xdr)
    except DemoError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - chain failures are reported, not hidden
        logging.getLogger(__name__).warning("demo issuance failed: %s", exc)
        raise HTTPException(status_code=502, detail="The Testnet transaction failed; nothing was issued. Try again.") from exc


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
        return FileResponse(FRONTEND_DIR / "demo.html")

    @app.get("/studio")
    async def studio_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "studio.html")

    @app.get("/guide")
    async def guide_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "guide.html")

    @app.get("/guide/tmark")
    async def guide_tmark_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "guide-tmark.html")

    @app.get("/docs")
    async def docs_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "docs.html")

    @app.get("/book")
    async def book_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "book.html")

    @app.get("/report/{entry}")
    async def report_page(entry: str) -> Response:
        from fastapi.responses import HTMLResponse
        from .services import assay_render
        from .services.assay_book import load_entry, load_report, paid_record, price_xlm, store_from_settings
        store = store_from_settings(settings) if settings.enable_assay_book else None
        try:
            record = await load_entry(store, entry) if store is not None else None
            if record is None:
                return HTMLResponse(assay_render.missing_page(), status_code=404)
            paid = await paid_record(store, entry)
            data = await load_report(store, record["entry"]["report_sha256"]) if paid else None
        except Exception as exc:  # noqa: BLE001 - the store did not answer
            logger.warning("assay report page unavailable: %s", type(exc).__name__)
            return HTMLResponse(assay_render.unavailable_page(), status_code=503)
        if paid and data is not None:
            return HTMLResponse(assay_render.report_page(record, data, paid))
        return HTMLResponse(assay_render.locked_page(record, price_xlm(settings)))

    @app.get("/operator")
    async def operator_console() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")
    # On Vercel, public/ is served by the CDN before the function; this serves it locally.
    MEDIA_DIR = FRONTEND_DIR.parent / "public" / "media"
    if MEDIA_DIR.is_dir():
        app.mount("/media", StaticFiles(directory=str(MEDIA_DIR)), name="media")
    SCHEMA_DIR = FRONTEND_DIR.parent / "public" / "schemas"
    if SCHEMA_DIR.is_dir():
        app.mount("/schemas", StaticFiles(directory=str(SCHEMA_DIR)), name="schemas")
    MASCOT_DIR = FRONTEND_DIR.parent / "public" / "mascot"
    if MASCOT_DIR.is_dir():
        app.mount("/mascot", StaticFiles(directory=str(MASCOT_DIR)), name="mascot")
