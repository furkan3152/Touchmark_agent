"""Ingestion girdi kapıları — yerel yol kumu ve uzak URL denetimi.

Neden gerekli
-------------
`/api/v1/agents/ingest` denetlenen tarafın kontrolündeki iki alanı doğrudan
dosya sistemine ve ağa bağlıyordu:

* ``local_path`` **herhangi bir dizini** okuyordu. ``local_path=data/keystore``
  çağrısı operatörün ``attestor.json`` dosyasını (``private_key`` alanıyla)
  artifact'e alıyordu; dosya sunucu durumuna ve ``data/state.json``'a giriyordu.
* ``repo_url`` GitHub/IPFS eşleşmediğinde koşulsuz ``client.get(url)`` yapıyordu.
  Bu klasik SSRF'tir: ``http://169.254.169.254/...`` gibi bir bulut metadata
  adresi veya ``http://127.0.0.1:8000/...`` gibi bir iç servis çekilebilirdi.

Bu modül iki değişmez uygular ve ikisi de **denetimin kendi standardıdır**:
girdi yüzeyi allowlist ile daraltılır, kapsam dışı istek sessizce başarısız
olmaz — sebebi söylenerek reddedilir.
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
    """Girdi kapısı reddi. `ValueError` olduğu için API 400 döner."""


# --------------------------------------------------------------- yerel yollar
def resolve_ingest_path(raw: str, root: Path) -> Path:
    """`raw` yolunu `root` altına hapseder.

    Sembolik bağlar dahil çözümlenmiş yol karşılaştırılır: kök içindeki bir
    symlink'in dışarıyı göstermesi kaçış sayılır.

    Raises:
        IngestGuardError: yol kökün dışındaysa veya dizin değilse.
    """
    if not raw or not raw.strip():
        raise IngestGuardError("local_path boş")

    root = root.resolve()
    candidate = Path(raw.strip()).expanduser()
    target = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

    if target != root and root not in target.parents:
        raise IngestGuardError(
            f"local_path izin verilen kökün dışında: {target} (kök: {root}). "
            "Başka bir dizini denetlemek için INGEST_ROOT ayarlayın."
        )
    if not target.exists():
        raise IngestGuardError(f"dizin bulunamadı: {target}")
    if not target.is_dir():
        raise IngestGuardError(f"local_path bir dizin olmalı: {target}")
    return target


def is_within(path: Path, root: Path) -> bool:
    """`path` çözümlendiğinde `root` altında mı? (dosya bazlı symlink kontrolü)"""
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved == root or root in resolved.parents


# ------------------------------------------------------------------ uzak URL
def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback / özel / link-local / rezerve adresler kapsam dışıdır."""
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def guard_remote_url(url: str, *, resolver=socket.getaddrinfo) -> str:
    """Uzak URL'yi doğrular; kabul edilirse normalize edilmiş hâlini döndürür.

    Kontroller:
      1. şema `http`/`https` olmalı,
      2. host bulunmalı ve kimlik bilgisi (`user:pass@`) taşımamalı,
      3. host'un çözümlendiği **her** adres genel internete ait olmalı.

    `resolver` testlerde DNS'e çıkmamak için enjekte edilebilir.

    Raises:
        IngestGuardError: kontrollerden biri başarısızsa.
    """
    parts = urlsplit((url or "").strip())

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise IngestGuardError(
            f"desteklenmeyen şema: {parts.scheme or '(yok)'} — yalnızca http/https"
        )
    if parts.username or parts.password:
        raise IngestGuardError("URL'de kimlik bilgisi taşınamaz")

    host = parts.hostname
    if not host:
        raise IngestGuardError("URL'de host yok")

    for ip in _addresses_for(host, parts.port, resolver):
        if _is_forbidden_ip(ip):
            raise IngestGuardError(
                f"iç ağ adresi kapsam dışı: {host} → {ip}. Yalnızca genel "
                "internetteki kaynaklar çekilebilir."
            )
    return parts.geturl()


def _addresses_for(host: str, port: int | None, resolver) -> list:
    """Host'un IP adresleri. IP literal ise DNS'e çıkılmaz."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = resolver(host, port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        raise IngestGuardError(f"host çözümlenemedi: {host} ({exc})") from exc

    out = []
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except (ValueError, IndexError):
            continue
    if not out:
        raise IngestGuardError(f"host için adres bulunamadı: {host}")
    return out


def guard_cid(cid: str) -> str:
    """IPFS CID'ini doğrular — gateway yoluna `../` sızmasını engeller."""
    cid = (cid or "").strip().strip("/")
    if not cid or not CID_RE.match(cid):
        raise IngestGuardError(f"geçersiz IPFS CID: {cid or '(boş)'}")
    return cid
