"""Prompt metni tarama yardımcıları — kelime sınırı ve olumsuzlama duyarlı.

Neden gerekli
-------------
Denetçiler politika sinyallerini prompt metninde arıyor. Naif alt dize aramasının
iki ciddi yanlış negatifi vardı ve ikisi de gerçek bir korpus taramasında ortaya
çıktı:

* ``"trust unlimited issuers"`` içindeki **limit** alt dizesi
  "harcama politikası tanımlı" sayılıyordu → dolandırıcı ajan CRITICAL yerine
  temiz geçiyordu.
* ``"ask for their private key"`` içindeki **private** sözcüğü yürütme
  koruması kanıtı sayılıyordu.

Bu modül üç kural uygular:

1. **Kelime sınırı**: ``limit`` aranırken ``unlimited`` eşleşmez.
2. **Anti-sinyal**: ``no limit``, ``unlimited``, ``there are no spending limits``
   gibi ifadeler sinyali yalnızca geçersiz kılmaz, *tersine* kanıt sayılır.
3. **Çok kelimeli ifadeler** aradaki boşluk sayısından bağımsız eşleşir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Politikanın **yokluğunu** ilan eden ifadeler. Bunlar varsa sinyal aramaya
#: gerek yoktur: ajan açıkça limitsiz çalıştığını söylüyor.
NEGATION_PATTERNS = (
    r"\bunlimited\b",
    r"\bno\s+(?:spend(?:ing)?|budget|daily|transfer)?\s*limits?\b",
    r"\bthere\s+is\s+no\s+\w*\s*limit\b",
    r"\bthere\s+are\s+no\s+\w*\s*limits?\b",
    r"\bwithout\s+(?:any\s+)?limits?\b",
    r"\bno\s+cap\b",
    r"\bignore\s+(?:any\s+)?(?:policy|policies|limits?|rules?)\b",
    r"\bat\s+all\s+costs\b",
    r"\bfull\s+wallet\s+balance\b",
    r"\bmax_?uint\b",
    r"\blimitsiz\b",
    r"\bsınırsız\b",
)

_NEGATION_RE = re.compile("|".join(NEGATION_PATTERNS), re.IGNORECASE)


def _phrase_pattern(phrase: str) -> str:
    """Çok kelimeli ifadeyi esnek boşlukla, kelime sınırlı regex'e çevirir."""
    parts = [re.escape(p) for p in phrase.split()]
    return r"\b" + r"\s+".join(parts) + r"\b"


def has_negation(text: str) -> bool:
    """Metin politikanın yokluğunu açıkça ilan ediyor mu?"""
    return bool(_NEGATION_RE.search(text or ""))


def negations_found(text: str) -> list[str]:
    """Bulunan anti-sinyalleri döndürür (bulguya kanıt olarak yazılır)."""
    return sorted({m.group(0).strip().lower() for m in _NEGATION_RE.finditer(text or "")})


def find_signals(text: str, signals: tuple[str, ...]) -> list[str]:
    """Kelime sınırına saygılı sinyal araması.

    ``limit`` sinyali ``unlimited`` içinde eşleşmez; bu, naif ``in`` aramasının
    en pahalı hatasıydı.
    """
    text = text or ""
    return [s for s in signals if re.search(_phrase_pattern(s), text, re.IGNORECASE)]


@dataclass(frozen=True)
class SignalScan:
    """Bir sinyal ailesinin tarama sonucu."""

    matched: list[str]
    negations: list[str]

    @property
    def present(self) -> bool:
        """Sinyal *geçerli şekilde* var mı?

        Anti-sinyal varsa sinyal sayılmaz: "trust unlimited issuers" cümlesi
        harcama politikası kanıtı değildir.
        """
        return bool(self.matched) and not self.negations

    @property
    def explicitly_absent(self) -> bool:
        """Politikanın yokluğu açıkça ilan edilmiş mi? (daha ağır ceza gerekir)"""
        return bool(self.negations)

    def reason(self, found: str, missing: str) -> str:
        if self.negations:
            return f"politika açıkça reddediliyor: {', '.join(self.negations)}"
        return f"{found}: {', '.join(self.matched)}" if self.matched else missing


def scan(text: str, signals: tuple[str, ...]) -> SignalScan:
    """Sinyal ailesini olumsuzlama duyarlı biçimde tarar."""
    return SignalScan(matched=find_signals(text, signals), negations=negations_found(text))
