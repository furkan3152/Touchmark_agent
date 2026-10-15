"""Vercel public Studio entrypoint. Persistent operator service uses backend.app.api.

Serverless deployments expose only the stateless Studio. Operator records and
monitoring must run on a durable single-worker service, never ephemeral /tmp.
"""
import os

os.environ["STATELESS_STUDIO"] = "true"
os.environ.setdefault("DATA_DIR", "/tmp/agentveritas-studio")
os.environ.setdefault("EVENT_DATABASE", "/tmp/agentveritas-studio/events.db")
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/agentveritas-studio/unused.db")

from backend.app.api import app  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402


@app.middleware("http")
async def public_surface_only(request, call_next):
    path = request.url.path
    allowed = (path == "/" or path == "/api/v1/health" or path.startswith("/ui/")
               or path in {"/api/v1/studio/review", "/api/v1/studio/identify", "/api/v1/studio/import",
                           "/api/v1/studio/discover", "/api/v1/studio/runtime", "/api/v1/studio/capabilities", "/api/v1/studio/policy",
                           "/api/v1/studio/stellar/inspect-auth"})
    if not allowed:
        return JSONResponse({"detail": "This deployment exposes the public audit Studio only."}, status_code=404)
    return await call_next(request)
