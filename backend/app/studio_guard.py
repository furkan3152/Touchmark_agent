"""Pre-parse body and process-wide rate bounds for the stateless public review."""

from collections import deque
import time

from starlette.responses import JSONResponse


class StudioGuard:
    def __init__(self, app):
        self.app = app
        self.requests = deque(maxlen=30)

    async def __call__(self, scope, receive, send):
        guarded_order = (scope.get('path', '').startswith('/api/v1/studio/orders') and scope.get('method') == 'POST')
        if scope["type"] != "http" or (not guarded_order and scope["path"] not in {
            "/api/v1/studio/policy", "/api/v1/studio/review", "/api/v1/studio/identify", "/api/v1/studio/import",
            "/api/v1/studio/discover", "/api/v1/studio/runtime", "/api/v1/studio/stellar/inspect-auth",
            '/api/v1/studio/plan', '/api/v1/studio/audit', '/api/v1/studio/delivery',
            '/api/v1/studio/capsule/import', '/api/v1/studio/capsule/export',
            '/api/v1/studio/ai/check',
            '/api/v1/studio/checkout', '/api/v1/studio/checkout/prepare',
        }):
            return await self.app(scope, receive, send)

        async def reject(status, detail):
            response = JSONResponse({"detail": detail}, status_code=status, headers={
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                **({"Retry-After": "60"} if status == 429 else {}),
            })
            await response(scope, receive, send)

        now = time.monotonic()
        while self.requests and now - self.requests[0] >= 60:
            self.requests.popleft()
        if len(self.requests) >= 30:
            return await reject(429, "Review capacity reached. Retry in one minute.")
        self.requests.append(now)
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
