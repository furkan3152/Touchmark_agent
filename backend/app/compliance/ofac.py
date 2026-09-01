"""OFAC yaptırım listesi tarayıcısı — anahtar gerektirmez.

Neden bu
--------
Chainalysis / TRM / Elliptic ticari anahtar ister ve self-serve kayıt her zaman
mümkün değil. Oysa yaptırım verisinin **birincil kaynağı** zaten kamuya açık:
ABD Hazinesi OFAC, SDN listesini makine-okunur olarak ücretsiz yayımlar ve liste
`Digital Currency Address - ETH 0x…` biçiminde kripto adresleri içerir.

Bu modül o listeyi indirir, kripto adreslerini ayıklar ve yerel bir sete koyar.
Sonuç **CONFIRMED** kanıttır: ticari bir sağlayıcının yorumu değil, birincil
kaynaktan doğrudan eşleşmedir.

Sınırları açıkça söylemek gerekir
---------------------------------
OFAC yalnızca *doğrudan listelenmiş* adresleri verir. "Mixer'a 2 adım uzaklıkta"
gibi dolaylı maruziyet analizi yapmaz — o ticari sağlayıcıların işidir. Bu yüzden
eşleşme yoksa sonuç "temiz" değil, "**yaptırım listesinde değil**"dir; denetçi bunu
`low` risk olarak değil, sınırlı kapsamlı bir kontrol olarak raporlar.

Önbellek
--------
Liste ~5.6 MB ve günde en fazla bir kez değişir. `data/sanctions/ofac-sdn.json`
içine ayıklanmış adreslerle birlikte yazılır; `max_age_hours` içinde tekrar
indirilmez. Ağ yoksa süresi geçmiş önbellek yine kullanılır (uyarıyla).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

#: OFAC'ın makine-okunur SDN dışa aktarımı (302 ile imzalı S3 URL'ine yönlendirir).
SDN_CSV_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"

#: `Digital Currency Address - ETH 0xabc…` kalıbı. Zincir kodu ve adres yakalanır.
ADDRESS_RE = re.compile(
    r"Digital Currency Address\s*-\s*([A-Z0-9]{2,6})\s+([a-zA-Z0-9]{20,120})"
)

#: Hex-address kullanan zincir kodları; OFAC girdilerini normalize etmek içindir.
HEX_CHAINS = frozenset({"ETH", "USDT", "USDC", "ETC", "BNB", "ARB", "BSC"})

CACHE_NAME = "ofac-sdn.json"
DEFAULT_MAX_AGE_HOURS = 24.0


def normalise(address: str) -> str:
    """Arama için adresi normalize eder.

    Hex adresler (`0x…`, checksum karışık yazımlı) küçük harfe indirilir; `0X`
    büyük harfli önek de hex sayılır. Diğer zincirler (BTC/TRX/XMR/XLM) base58 veya
    base32 kullandığı için büyük/küçük harfe duyarlıdır ve dokunulmaz.
    """
    return address.lower() if address[:2].lower() == "0x" else address


def extract_addresses(csv_text: str) -> dict[str, list[str]]:
    """SDN CSV metninden zincir → adres listesi çıkarır.

    Hex adresler küçük harfe indirilir (OFAC karışık checksum yazımı kullanıyor),
    diğer zincirler (BTC, TRX, XMR) büyük/küçük harfe duyarlı olduğu için olduğu
    gibi bırakılır.
    """
    out: dict[str, set[str]] = {}
    for chain, address in ADDRESS_RE.findall(csv_text):
        key = chain.upper()
        value = normalise(address) if key in HEX_CHAINS else address
        out.setdefault(key, set()).add(value)
    return {k: sorted(v) for k, v in sorted(out.items())}


class OfacSanctionsList:
    """SDN listesini indirir, önbelleğe alır ve adres sorgular."""

    def __init__(self, data_dir: Path, max_age_hours: float = DEFAULT_MAX_AGE_HOURS) -> None:
        self.cache_path = Path(data_dir) / "sanctions" / CACHE_NAME
        self.max_age_hours = max_age_hours

    # ------------------------------------------------------------- önbellek
    def load_cache(self) -> dict | None:
        if not self.cache_path.exists():
            return None
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def save_cache(self, payload: dict) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8"
        )

    def is_fresh(self, cache: dict | None) -> bool:
        if not cache:
            return False
        age_h = (time.time() - float(cache.get("fetched_at", 0))) / 3600.0
        return age_h < self.max_age_hours

    # -------------------------------------------------------------- indirme
    async def refresh(self, force: bool = False) -> dict:
        """Gerekliyse listeyi indirir; her durumda kullanılabilir veri döndürür.

        Ağ hatasında süresi geçmiş önbelleğe düşer ve `stale=True` işaretler —
        eski veriyle taramak, hiç taramamaktan iyidir ama bu şeffaf olmalıdır.
        """
        cache = self.load_cache()
        if not force and self.is_fresh(cache):
            return cache

        try:
            async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
                resp = await client.get(SDN_CSV_URL)
                resp.raise_for_status()
                csv_text = resp.text
        except Exception as exc:
            if cache:
                return {**cache, "stale": True, "error": str(exc)}
            raise

        chains = extract_addresses(csv_text)
        payload = {
            "source": SDN_CSV_URL,
            "publisher": "US Treasury OFAC (SDN)",
            "fetched_at": time.time(),
            "total_addresses": sum(len(v) for v in chains.values()),
            "chains": chains,
        }
        self.save_cache(payload)
        return payload

    # -------------------------------------------------------------- sorgulama
    def lookup_cached(self, address: str) -> dict:
        """Adresi **yalnızca önbellekten** arar; ağa çıkmaz.

        Denetim yolunda kullanılan sürüm budur. Bir denetimin ortasında 5.6 MB
        indirmek hem denetimi saniyelerce bloklar hem de sonucu ağ durumuna
        bağımlı kılar. Önbellek yoksa `available=False` döner ve denetçi bunu
        kapsam boşluğu olarak bildirir.
        """
        cache = self.load_cache()
        if not cache:
            return {"available": False, "listed": False, "chains": []}

        chains: dict[str, list[str]] = cache.get("chains", {})
        needle = normalise(address)
        hits = [chain for chain, addresses in chains.items() if needle in addresses]

        return {
            "available": True,
            "listed": bool(hits),
            "chains": sorted(hits),
            "total_addresses": cache.get("total_addresses", 0),
            "fetched_at": cache.get("fetched_at"),
            "stale": not self.is_fresh(cache),
            "publisher": cache.get("publisher", "US Treasury OFAC (SDN)"),
        }

    async def lookup(self, address: str) -> dict:
        """Gerekirse indirip arar. Yalnızca açık komutlarda (CLI/warm-up) kullanılır."""
        await self.refresh()
        return self.lookup_cached(address)
