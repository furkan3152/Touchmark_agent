import asyncio

from backend.app import studio_guard
from backend.app.studio_guard import StudioGuard


async def _ok(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def _call(guard, ip, forwarded=None):
    scope = {"type": "http", "method": "POST", "path": "/api/v1/studio/review", "client": (ip, 1234),
             "headers": [(b"x-forwarded-for", forwarded.encode())] if forwarded else []}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(guard(scope, receive, send))
    return sent[0]["status"]


def test_one_client_cannot_exhaust_capacity_for_others():
    now = [0.0]
    guard = StudioGuard(_ok, trust_forwarded=False, clock=lambda: now[0])
    statuses = [_call(guard, "198.51.100.1") for _ in range(studio_guard.PER_CLIENT_LIMIT + 1)]
    assert statuses[:-1] == [200] * studio_guard.PER_CLIENT_LIMIT and statuses[-1] == 429
    assert _call(guard, "198.51.100.2") == 200
    now[0] += studio_guard.WINDOW_SECONDS
    assert _call(guard, "198.51.100.1") == 200


def test_global_ceiling_still_bounds_total_load():
    guard = StudioGuard(_ok, trust_forwarded=False, clock=lambda: 0.0)
    for i in range(studio_guard.GLOBAL_LIMIT):
        assert _call(guard, f"10.0.{i // 250}.{i % 250}") == 200
    assert _call(guard, "203.0.113.9") == 429


def test_forwarded_address_is_only_trusted_behind_a_declared_proxy():
    direct = StudioGuard(_ok, trust_forwarded=False, clock=lambda: 0.0)
    for i in range(studio_guard.PER_CLIENT_LIMIT):
        assert _call(direct, "192.0.2.1", forwarded=f"198.51.100.{i}") == 200
    # Spoofed headers do not create fresh buckets for a direct client.
    assert _call(direct, "192.0.2.1", forwarded="198.51.100.200") == 429

    proxied = StudioGuard(_ok, trust_forwarded=True, clock=lambda: 0.0)
    for _ in range(studio_guard.PER_CLIENT_LIMIT):
        assert _call(proxied, "10.0.0.1", forwarded="spoof, 198.51.100.7") == 200
    assert _call(proxied, "10.0.0.1", forwarded="other, 198.51.100.7") == 429
    assert _call(proxied, "10.0.0.1", forwarded="198.51.100.8") == 200
