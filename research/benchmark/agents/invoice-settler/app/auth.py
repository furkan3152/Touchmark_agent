import hashlib
import hmac

from fastapi import Depends, Header, HTTPException, Request, status

from .config import Settings, get_settings


def require_api_key(
    x_api_key: str = Header(default=""),
    settings: Settings = Depends(get_settings),
) -> str:
    for key in settings.operator_keys():
        if hmac.compare_digest(x_api_key, key):
            return key
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")


async def verify_signature(request: Request, settings: Settings = Depends(get_settings)) -> bytes:
    body = await request.body()
    provided = request.headers.get("x-accounting-signature", "")
    expected = hmac.new(
        settings.webhook_secret.get_secret_value().encode(), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad signature")
    return body
