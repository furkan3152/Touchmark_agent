"""Content-addressed, private report storage with authenticated byte readback.

Upload: official ``vercel==0.11.6`` Python Blob SDK. Its ``get`` buffers the
entire body and follows redirects, so readback uses the documented authenticated
HTTP interface with streaming limits and redirects disabled instead:
https://vercel.com/docs/vercel-blob/using-blob-sdk
https://vercel.com/docs/vercel-blob/private-storage#accessing-without-the-sdk

The worker supplies canonical report bytes, never a source bundle. This module
does not make data public, issue credentials, or settle payment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import os
import re
from typing import Callable

import httpx

from .report_delivery import DeliveryRequest, decode_report

MAX_REPORT_BYTES = 500_000
_RAW_SOURCE_KEYS = {"files", "code_files", "source_files", "source_code", "raw_source", "source_bundle", "system_prompt"}
_SDK_API = "https://vercel.com/api/blob"


class PublicationError(RuntimeError):
    """A sanitized storage failure; provider messages and credentials are omitted."""


def _reject_raw_source(report: dict) -> None:
    pending: list[object] = [report]
    nodes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > 30_000:
            raise PublicationError("Report structure exceeds the publication limit.")
        if isinstance(current, dict):
            if any(key in _RAW_SOURCE_KEYS and value not in (None, "", {}, []) for key, value in current.items()):
                raise PublicationError("Raw source bundles and system prompts cannot be published as report artifacts.")
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


class PrivateReportPublisher:
    def __init__(self, settings, *, blob_client_factory: Callable | None = None, read_transport=None):
        token = settings.blob_read_write_token
        store = settings.blob_store_id.removeprefix("store_")
        match = re.fullmatch(r"vercel_blob_rw_([A-Za-z0-9]+)_[A-Za-z0-9]+", token)
        if not re.fullmatch(r"[A-Za-z0-9]{8,64}", store) or not match or match.group(1).lower() != store.lower():
            raise PublicationError("Private report storage is not configured for the expected store.")
        # Prevent SDK endpoint overrides from forwarding a store credential.
        for key in ("VERCEL_BLOB_API_URL", "NEXT_PUBLIC_VERCEL_BLOB_API_URL"):
            if os.environ.get(key) not in (None, "", _SDK_API):
                raise PublicationError("Custom Blob API endpoints are disabled for report publication.")
        for key in ("VERCEL_BLOB_PROXY_THROUGH_ALTERNATIVE_API", "NEXT_PUBLIC_VERCEL_BLOB_PROXY_THROUGH_ALTERNATIVE_API"):
            if os.environ.get(key):
                raise PublicationError("Alternative Blob API routing is disabled for report publication.")
        self._token = token
        self.store_id = f"store_{store}"
        self.origin = f"https://{store.lower()}.private.blob.vercel-storage.com"
        self._blob_client_factory = blob_client_factory
        self._read_transport = read_transport

    def __repr__(self) -> str:
        return f"PrivateReportPublisher(origin={self.origin!r})"

    def _uri(self, digest: str) -> str:
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise PublicationError("A canonical report SHA-256 is required.")
        return f"{self.origin}/reports/{digest}.json"

    async def _upload(self, pathname: str, body: bytes):
        factory = self._blob_client_factory
        if factory is None:
            from vercel.blob import AsyncBlobClient
            factory = AsyncBlobClient
        async with factory(token=self._token) as client:
            return await asyncio.wait_for(client.put(
                pathname, body, access="private", content_type="application/json",
                add_random_suffix=False, overwrite=False, multipart=False,
            ), timeout=25)

    async def _readback(self, uri: str, expected: bytes) -> None:
        if len(expected) > MAX_REPORT_BYTES:
            raise PublicationError("Report bytes exceed the publication limit.")
        digest = sha256(expected).hexdigest()
        if uri != self._uri(digest):
            raise PublicationError("Report URI does not match the configured private store and content commitment.")
        async with httpx.AsyncClient(
            timeout=12, follow_redirects=False, transport=self._read_transport,
        ) as client:
            # Origin read avoids a cached stale/missing object after a write.
            async with client.stream("GET", uri, params={"cache": "0"}, headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json", "Accept-Encoding": "identity",
            }) as response:
                if response.status_code != 200:
                    raise PublicationError("Private report readback is unavailable or unauthorized.")
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise PublicationError("Private report readback has an unexpected content type.")
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise PublicationError("Compressed report readback is not accepted.")
                declared = response.headers.get("content-length")
                if declared is not None and (not declared.isascii() or not declared.isdigit() or int(declared) != len(expected)):
                    raise PublicationError("Private report readback length does not match the commitment.")
                chunks = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if len(chunks) + len(chunk) > len(expected):
                        raise PublicationError("Private report readback exceeds the expected bounded length.")
                    chunks.extend(chunk)
                if bytes(chunks) != expected or sha256(chunks).hexdigest() != digest:
                    raise PublicationError("Private report readback bytes do not match the commitment.")

    async def verify(self, publication: dict, expected_bytes: bytes) -> bool:
        """Recheck exact private artifact bytes independently before settlement."""
        if not isinstance(expected_bytes, bytes) or not 2 <= len(expected_bytes) <= MAX_REPORT_BYTES:
            raise PublicationError("Bounded canonical report bytes are required.")
        digest = sha256(expected_bytes).hexdigest()
        if (not isinstance(publication, dict) or publication.get("visibility") != "private"
                or publication.get("report_sha256") != digest
                or publication.get("report_uri") != self._uri(digest)):
            raise PublicationError("Publication metadata does not match the expected private report.")
        try:
            await asyncio.wait_for(self._readback(publication["report_uri"], expected_bytes), timeout=15)
        except PublicationError:
            raise
        except Exception:
            raise PublicationError("Private report readback could not be verified.") from None
        return True

    async def publish(self, order: dict, result: dict) -> dict:
        """Publish exact report bytes; retrying reconciles an existing same-hash blob."""
        consents = order.get("consents", {}) if isinstance(order, dict) else {}
        if not isinstance(consents, dict) or any(consents.get(key) is not True for key in ("storage_consent", "publication_consent")):
            raise PublicationError("Private report storage and publication consent are required.")
        try:
            request = DeliveryRequest(report_json=result["report_json"], report_sha256=result["report_sha256"])
            body = request.report_json.encode("utf-8")
            if len(body) > MAX_REPORT_BYTES:
                raise ValueError("Bounded report required")
            report = decode_report(request)
            if result.get("report") != report:
                raise ValueError("Report envelope mismatch")
            _reject_raw_source(report)
        except Exception:
            raise PublicationError("Publish the original bounded audit report without raw source bundles.") from None
        digest = request.report_sha256
        uri = self._uri(digest)
        pathname = f"reports/{digest}.json"
        publication = {
            "status": "pending_verification", "verified": False,
            "report_sha256": digest, "report_uri": uri,
            "visibility": "private", "storage": "vercel_blob",
            "byte_length": len(body),
        }
        uploaded = False
        try:
            response = await self._upload(pathname, body)
            uploaded = True
        except Exception:
            # This includes a conflict or an uncertain timeout. Never overwrite:
            # only exact authenticated readback can reconcile the previous write.
            response = None
        if uploaded and (getattr(response, "url", None) != uri or getattr(response, "pathname", None) != pathname):
            raise PublicationError("Blob upload returned an unexpected private artifact location.")
        for attempt in range(2):
            try:
                await self.verify(publication, body)
                publication.update(status="verified", verified=True,
                    verified_at=datetime.now(timezone.utc).isoformat(),
                    write_outcome="created" if uploaded else "reconciled_existing")
                return publication
            except PublicationError:
                if attempt == 1:
                    raise PublicationError("Private report publication could not be verified; no delivery is claimed.") from None
                await asyncio.sleep(0.2)
        raise PublicationError("Private report publication could not be verified.")
