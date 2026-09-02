"""Ingestion input guards — local path sandbox and remote URL validation.

Why it is necessary
-----------------
`/api/v1/agents/ingest` was binding two fields controlled by the audited party directly
to the file system and network:

* `local_path` was reading **any directory**. A `local_path=data/keystore` call
  was pulling the operator's `attestor.json` (with `private_key` field) into the
  artifact; the file was entering the server state and `data/state.json`.
* `repo_url` was unconditionally making `client.get(url)` when GitHub/IPFS didn't match.
  This is classic SSRF: a cloud metadata address like `http://169.254.169.254/...` or
  an internal service like `http://127.0.0.1:8000/...` could be fetched.

This module enforces two invariants and both are **the standard of the audit itself**:
input surface is narrowed with an allowlist, out-of-scope requests do not fail silently
— they are rejected with the reason stated.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

#: Uzak kaynak çekmek için izin verilen şemalar. ``file://`` ve ``gopher://``
#: gibi şemalar httpx'te desteklenmese de açıkça dışarıda tutulur.
ALLOWED_SCHEMES = ("http", "https")

#: IPFS CID'inde beklenen karakter kümesi. Gateway'e giden yolda ``../``
#: taşımamak için daraltılır.
CID_RE = re.compile(r"^[A-Za-z0-9]+$")

#: Uzak yanıtın kabul edilen üst boyutu (zip bomb / bellek koruması).
MAX_REMOTE_BYTES = 20 * 1024 * 1024


class IngestGuardError(ValueError):
    """Input guard rejection. Since it's a `ValueError`, API returns 400."""


# --------------------------------------------------------------- yerel yollar
def resolve_ingest_path(raw: str, root: Path) -> Path:
    """Confines the `raw` path under `root`.

    The resolved path including symlinks is compared: a symlink inside the root
    pointing outside is considered an escape.

    Raises:
        IngestGuardError: if the path is outside the root or not a directory.
    """
    if not raw or not raw.strip():
        raise IngestGuardError("local_path is empty")

    root = root.resolve()
    candidate = Path(raw.strip()).expanduser()
    target = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

    if target != root and root not in target.parents:
        raise IngestGuardError(
            f"local_path is outside the allowed root: {target} (root: {root}). "
            "Set INGEST_ROOT to audit another directory."
        )
    if not target.exists():
        raise IngestGuardError(f"directory not found: {target}")
    if not target.is_dir():
        raise IngestGuardError(f"local_path must be a directory: {target}")
    return target


def is_within(path: Path, root: Path) -> bool:
    """Is `path` under `root` when resolved? (file-based symlink check)"""
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved == root or root in resolved.parents


# ------------------------------------------------------------------ uzak URL
def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback / private / link-local / reserved addresses are out of scope."""
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def guard_remote_url(url: str, *, resolver=socket.getaddrinfo) -> str:
    """Validates the remote URL; if accepted, returns its normalized form.

    Checks:
      1. scheme must be `http`/`https`,
      2. host must be present and not carry credentials (`user:pass@`),
      3. **every** address the host resolves to must belong to the public internet.

    `resolver` can be injected to avoid DNS lookups in tests.

    Raises:
        IngestGuardError: if one of the checks fails.
    """
    parts = urlsplit((url or "").strip())

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise IngestGuardError(
            f"unsupported scheme: {parts.scheme or '(none)'} — only http/https"
        )
    if parts.username or parts.password:
        raise IngestGuardError("URL cannot contain credentials")

    host = parts.hostname
    if not host:
        raise IngestGuardError("URL has no host")

    for ip in _addresses_for(host, parts.port, resolver):
        if _is_forbidden_ip(ip):
            raise IngestGuardError(
                f"internal network address out of scope: {host} → {ip}. Only resources "
                "on the public internet can be fetched."
            )
    return parts.geturl()


def _addresses_for(host: str, port: int | None, resolver) -> list:
    """IP addresses of the host. If IP literal, DNS is not queried."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = resolver(host, port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        raise IngestGuardError(f"host could not be resolved: {host} ({exc})") from exc

    out = []
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except (ValueError, IndexError):
            continue
    if not out:
        raise IngestGuardError(f"no address found for host: {host}")
    return out


def guard_cid(cid: str) -> str:
    """Validates the IPFS CID — prevents `../` escaping into the gateway path."""
    cid = (cid or "").strip().strip("/")
    if not cid or not CID_RE.match(cid):
        raise IngestGuardError(f"invalid IPFS CID: {cid or '(empty)'}")
    return cid
