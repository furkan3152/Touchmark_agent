"""Pre-parse body and process-local rate bounds for the stateless public review."""

from collections import deque
import os
import time
import weakref

from starlette.responses import JSONResponse

WINDOW_SECONDS = 60
PER_CLIENT_LIMIT = 30
GLOBAL_LIMIT = 300
MAX_TRACKED_CLIENTS = 10_000


def trust_proxy_headers() -> bool:
    """Proxy headers name the client only behind a trusted proxy: on Vercel, or when the operator
    says so (TRUST_PROXY_HEADERS=true)."""
    return bool(os.environ.get("VERCEL")) or os.environ.get("TRUST_PROXY_HEADERS", "").lower() == "true"


def client_address(header, peer: str, *, trust_forwarded: bool) -> str:
    """Who the client is, by one rule for the request throttle and the model-review allowance.

    Behind the trusted proxy (Vercel): ``x-real-ip``, else the last ``x-forwarded-for`` hop,
    which the proxy appends. Elsewhere the socket peer, since headers can be forged.
    ``header(name)`` returns a request header or None."""
    if trust_forwarded:
        real = (header("x-real-ip") or "").strip()
        forwarded = (header("x-forwarded-for") or "").split(",")[-1].strip()
        if real or forwarded:
            return (real or forwarded)[:64]
    return (peer or "unknown")[:64]


#: Every guard in the process, so tests can start each case with an empty window (reset_all).
_GUARDS: "weakref.WeakSet[StudioGuard]" = weakref.WeakSet()


def reset_all() -> None:
    """Forget every request seen so far (tests: one case must not spend another's allowance)."""
    for guard in list(_GUARDS):
        guard.clients.clear()
        guard.requests.clear()


class StudioGuard:
    """Per-client limit so one caller cannot exhaust capacity for everyone, plus a
    process-wide ceiling. Counters live in this process only; serverless instances
    each keep their own, so a shared edge or proxy limit is still required there.
    Forwarded client addresses are trusted only behind a declared proxy (or Vercel,
    whose edge overwrites the header)."""

    def __init__(self, app, *, trust_forwarded=None, clock=time.monotonic):
        _GUARDS.add(self)
        self.app = app
        self.clock = clock
        self.trust_forwarded = trust_proxy_headers() if trust_forwarded is None else trust_forwarded
        self.requests = deque(maxlen=GLOBAL_LIMIT)
        self.clients: dict[str, deque] = {}

    def _client(self, scope):
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        client = scope.get("client")
        return client_address(headers.get, client[0] if client else "", trust_forwarded=self.trust_forwarded)

    def _allow(self, client):
        now = self.clock()
        for bucket in (self.requests, self.clients.get(client)):
            while bucket and now - bucket[0] >= WINDOW_SECONDS:
                bucket.popleft()
        if len(self.requests) >= GLOBAL_LIMIT:
            return False
        bucket = self.clients.get(client)
        if bucket is not None and len(bucket) >= PER_CLIENT_LIMIT:
            return False
        if bucket is None:
            if len(self.clients) >= MAX_TRACKED_CLIENTS:
                self.clients = {k: v for k, v in self.clients.items() if v and now - v[-1] < WINDOW_SECONDS}
                if len(self.clients) >= MAX_TRACKED_CLIENTS:
                    return False
            bucket = self.clients[client] = deque(maxlen=PER_CLIENT_LIMIT)
        bucket.append(now)
        self.requests.append(now)
        return True

    async def __call__(self, scope, receive, send):
        guarded_order = (scope.get('path', '').startswith('/api/v1/studio/orders') and scope.get('method') == 'POST')
        # Public POSTs that fetch a repository or make the book account sign a transaction.
        guarded_order = guarded_order or (scope.get('method') == 'POST' and scope.get('path') in {
            '/api/v1/tmark/template', '/api/v1/assay/claim', '/api/v1/assay/pay/prepare', '/api/v1/assay/pay/submit'})
        if scope["type"] != "http" or (not guarded_order and scope["path"] not in {
            "/api/v1/studio/policy", "/api/v1/studio/review", "/api/v1/studio/identify", "/api/v1/studio/import",
            "/api/v1/studio/discover", "/api/v1/studio/runtime", "/api/v1/studio/stellar/inspect-auth",
            '/api/v1/studio/plan', '/api/v1/studio/audit', '/api/v1/studio/delivery',
            '/api/v1/studio/capsule/import', '/api/v1/studio/capsule/export',
            '/api/v1/studio/ai/check',
            '/api/v1/studio/checkout', '/api/v1/studio/checkout/prepare',
            '/api/v1/demo/audit', '/api/v1/demo/credential', '/api/v1/demo/compare',
            '/api/v1/demo/credential/prepare',
        }):
            return await self.app(scope, receive, send)

        async def reject(status, detail):
            response = JSONResponse({"detail": detail}, status_code=status, headers={
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                **({"Retry-After": "60"} if status == 429 else {}),
            })
            await response(scope, receive, send)

        if not self._allow(self._client(scope)):
            return await reject(429, "Review capacity reached. Retry in one minute.")
        body = bytearray()
        body_limit = 1_048_576 if scope['path'] == '/api/v1/studio/delivery' else 131072
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > body_limit:
                return await reject(413, f"Request exceeds {body_limit // 1024} KiB.")
            if not message.get("more_body", False):
                break

        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def private_send(message):
            if message["type"] == "http.response.start":
                headers = [(key, value) for key, value in message.get("headers", []) if key.lower() != b"cache-control"]
                message = {**message, "headers": [*headers, (b"cache-control", b"no-store")]}
            await send(message)

        await self.app(scope, bounded_receive, private_send)
