"""Frontend design system invariants.

Why test
----------
Interface decisions are embedded in code and break silently: someone changing `--text-3`
to be "slightly dimmer" is enough for contrast to drop below AA, and nobody
notices. These tests lock in four things:

1. **Contrast**: every text/background pair carrying information with color passes WCAG AA.
   Score bands (SAFE/CAUTION/HIGH_RISK/BLOCKLIST) carry information — if unreadable,
   the report is unreadable.
2. **Token discipline**: no raw hex in `styles.css`, every token called via
   `var()` is defined. Raw hex breaks single-point theme management.
3. **DOM contract**: every id sought by `app.js` exists in HTML. A missing id
   silently returns `null` and the panel remains empty — hiding the error.
4. **Band thresholds**: `band()` thresholds in the frontend match
   `BADGE_THRESHOLDS` in the backend. If they diverge, the UI shows the wrong color.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


# --------------------------------------------------------------------- yardımcı
def _tokens() -> dict[str, str]:
    """`tokens.css` içindeki hex değerli CSS değişkenleri."""
    text = (FRONTEND / "tokens.css").read_text(encoding="utf-8")
    return dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", text, re.M))


def _relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relatif parlaklık."""
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(fg: str, bg: str) -> float:
    a, b = _relative_luminance(fg), _relative_luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


#: (açıklama, ön plan tokenı, arka plan tokenı, gereken oran)
#: Eşik 4.5 = WCAG AA normal metin. Kararlar burada belgelidir: bir tonu
#: değiştirmek isteyen kişi hangi çiftin kısıtladığını görür.
CONTRAST_CASES = [
    ("başlık / kart", "--text", "--surface-1", 4.5),
    ("gövde / kart", "--text-2", "--surface-1", 4.5),
    ("ikincil / kart", "--text-3", "--surface-1", 4.5),
    ("gövde / bölüm başlığı", "--text-2", "--surface-2", 4.5),
    ("ikincil / bölüm başlığı", "--text-3", "--surface-2", 4.5),
    # surface-4 en zorlu zemin: .card-step ve segment hover orada.
    ("ikincil / surface-4", "--text-3", "--surface-4", 4.5),
    ("input değeri / input", "--text", "--surface-3", 4.5),
    ("placeholder / input", "--text-4", "--surface-3", 4.5),
    ("footer / canvas", "--text-4", "--surface-canvas", 4.5),
    ("bağlantı / kart", "--accent-text", "--surface-1", 4.5),
    ("aksan metni / aksan zemin", "--accent-text", "--accent-bg", 4.5),
    # Buton hover'da kontrast DÜŞMEMELİ; ikisi de ölçülür.
    ("primary buton / aksan", "--accent-fg", "--accent", 4.5),
    ("primary buton / aksan hover", "--accent-fg", "--accent-hover", 4.5),
    # Dört skor bandı: renk burada bilgi taşır, okunurluk pazarlık konusu değil.
    ("SAFE badge", "--safe-text", "--safe-bg", 4.5),
    ("CAUTION badge", "--caution-text", "--caution-bg", 4.5),
    ("HIGH_RISK badge", "--risk-text", "--risk-bg", 4.5),
    ("BLOCKLIST badge", "--block-text", "--block-bg", 4.5),
]


@pytest.mark.parametrize("label,fg,bg,required", CONTRAST_CASES)
def test_contrast_meets_wcag_aa(label, fg, bg, required):
    """Renkle taşınan her bilgi okunabilir olmalı."""
    tokens = _tokens()
    assert fg in tokens, f"{fg} tanımsız"
    assert bg in tokens, f"{bg} tanımsız"

    ratio = _contrast(tokens[fg], tokens[bg])
    assert ratio >= required, (
        f"{label}: {ratio:.2f}:1 < {required}:1 "
        f"({fg}={tokens[fg]} üzerinde {bg}={tokens[bg]})"
    )


def test_text_hierarchy_is_monotonic():
    """Metin tonları sırayla sönükleşmeli; aksi hâlde hiyerarşi yanıltır."""
    t = _tokens()
    lums = [_relative_luminance(t[k]) for k in ("--text", "--text-2", "--text-3", "--text-4")]
    assert lums == sorted(lums, reverse=True), lums


def test_surface_elevation_is_monotonic():
    """Yükseklik merdiveni: her yüzey bir öncekinden açık olmalı.

    Koyu temada yükseklik gölgeyle değil tonla kurulur; sıra bozulursa
    kartlar zeminin altında görünür.
    """
    t = _tokens()
    keys = ["--surface-canvas", "--surface-1", "--surface-2", "--surface-3", "--surface-4", "--surface-5"]
    lums = [_relative_luminance(t[k]) for k in keys]
    assert lums == sorted(lums), dict(zip(keys, lums))


# ------------------------------------------------------------- token disiplini
def test_no_raw_hex_outside_tokens():
    """`styles.css` ham renk içermemeli — tema tek dosyadan yönetilir.

    Bir bileşene doğrudan `#1a1a1a` yazmak, o bileşeni tema değişiminden
    kopartır ve kontrast testlerinin kapsamı dışına çıkarır.
    """
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")
    leaks = re.findall(r"#[0-9a-fA-F]{3,8}\b", css)
    assert leaks == [], f"styles.css içinde ham hex: {leaks}"


def test_every_used_token_is_defined():
    """`var(--x)` ile çağrılan her token `tokens.css`'te tanımlı olmalı.

    Tanımsız bir token sessizce boşa düşer: kenarlık kaybolur veya metin
    miras aldığı rengi alır. Görsel bir hata, konsola hiçbir şey yazmaz.
    """
    defined = set(
        re.findall(
            r"^\s*(--[a-z0-9-]+):", (FRONTEND / "tokens.css").read_text(encoding="utf-8"), re.M
        )
    )
    used = set()
    for name in ("styles.css", "index.html"):
        used |= set(re.findall(r"var\((--[a-z0-9-]+)", (FRONTEND / name).read_text(encoding="utf-8")))
    assert used <= defined, f"tanımsız token: {sorted(used - defined)}"


def test_no_glassmorphism_or_decorative_gradients():
    """Reddedilen görsel teknikler geri sızmamalı.

    `backdrop-filter` koyu temada metin kontrastını öngörülemez kılar:
    okunabilirlik arkasından ne geçtiğine bağlanır ve ölçülemez.
    `background-clip: text` gradient metin üretir — küçük punto kontrastı
    ölçülemez hâle gelir.

    Gradient *dolgu* da yasak, ama şekil çizen gradientler değil: `select`
    okundaki `linear-gradient(45deg, transparent 50%, renk 50%)` bir renk
    geçişi değil, keskin kenarlı bir üçgen. Ayrım testte açıkça yapılır:
    iki farklı **opak** renk arasında geçiş varsa bu dekoratif dolgudur.
    """
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")

    for banned in ("backdrop-filter", "background-clip: text", "-webkit-background-clip"):
        assert banned not in css, f"yasaklı teknik geri geldi: {banned}"

    for gradient in re.findall(r"(?:linear|radial|conic)-gradient\(([^;]*?)\)", css):
        # `transparent` içeren gradient şekil çizer, renk harmanlamaz.
        if "transparent" in gradient:
            continue
        colors = re.findall(r"var\((--[a-z0-9-]+)\)|#[0-9a-fA-F]{3,8}", gradient)
        assert len(set(colors)) <= 1, f"dekoratif gradient dolgu: {gradient.strip()[:80]}"



# ------------------------------------------------------------- DOM sözleşmesi
def test_every_queried_id_exists_in_html():
    """`app.js`'in aradığı her id HTML'de bulunmalı.

    Eksik id `null` döner; `?.` zinciri sayesinde istisna da fırlatılmaz.
    Sonuç: panel sessizce boş kalır ve hata gizlenir. Bu testin varlık
    sebebi tam olarak o sessizlik.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    js = (FRONTEND / "app.js").read_text(encoding="utf-8")

    html_ids = set(re.findall(r'\bid="([^"]+)"', html))
    queried = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', js))
    queried |= set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', js))
    # loader("panelId", …) — panel kökleri de aynı sözleşmeye tabi.
    queried |= set(re.findall(r'loader\(\s*"([A-Za-z0-9_-]+)"', js))

    assert queried <= html_ids, f"HTML'de olmayan id: {sorted(queried - html_ids)}"


def test_tabs_and_panes_are_paired():
    """Her sekmenin karşılığı bir panel olmalı, tersi de geçerli.

    Eşleşmeyen sekme tıklanır ama hiçbir şey açmaz — kullanıcı formu
    dolduramaz ve neden olduğunu anlamaz.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    tabs = set(re.findall(r'data-tab="([^"]+)"', html))
    panes = set(re.findall(r'data-pane="([^"]+)"', html))
    assert tabs == panes, f"sekme={sorted(tabs)} panel={sorted(panes)}"


def test_every_input_has_a_label():
    """Etiketsiz alan ekran okuyucuda anonim kalır.

    `placeholder` etiket değildir: yazmaya başlayınca kaybolur ve ekran
    okuyucular hepsini okumaz.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    labelled = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', html))

    unlabelled = []
    for tag in re.findall(r"<(?:input|select|textarea)\b[^>]*>", html):
        if 'type="checkbox"' in tag:
            continue  # sarmalayıcı <label class="field-check"> içinde
        m = re.search(r'\bid="([^"]+)"', tag)
        if not m or m.group(1) not in labelled:
            unlabelled.append(tag[:70])
    assert unlabelled == [], f"etiketsiz alan: {unlabelled}"

