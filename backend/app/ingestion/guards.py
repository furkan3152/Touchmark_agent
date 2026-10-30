"""Ingestion input guards: local path sandbox and remote URL validation.

`/api/v1/agents/ingest` takes two fields controlled by the audited party that reach
the file system and the network:

* `local_path` must stay under the ingest root. Otherwise `local_path=data/keystore`
  would pull the operator's `attestor.json` (with its `private_key`) into the artifact
  and into `data/state.json`.
* `repo_url` outside GitHub/IPFS is fetched only if it resolves to the public internet.
  Otherwise it is an SSRF vector for cloud metadata (`http://169.254.169.254/...`) or
  internal services (`http://127.0.0.1:8000/...`).

Out-of-scope requests are rejected with the reason stated, never ignored silently.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

#: Schemes allowed for fetching remote sources. Schemes such as ``file://`` and
#: ``gopher://`` are excluded explicitly even though httpx does not support them.
ALLOWED_SCHEMES = ("http", "https")

#: Character set expected in an IPFS CID, narrowed so the gateway path cannot
#: carry ``../``.
CID_RE = re.compile(r"^[A-Za-z0-9]+$")

#: Maximum accepted size of a remote response (zip bomb / memory protection).
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
      3. every address the host resolves to must belong to the public internet.

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
    """Validates the IPFS CID; prevents `../` escaping into the gateway path."""
    cid = (cid or "").strip().strip("/")
    if not cid or not CID_RE.match(cid):
        raise IngestGuardError(f"invalid IPFS CID: {cid or '(empty)'}")
    return cid
