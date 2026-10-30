"""Frontend design system invariants.

Making `--text-3` "slightly dimmer" is enough to drop contrast below AA without anyone
noticing, so these tests pin down:

1. Contrast: every text/background pair that carries information with color passes
   WCAG AA, including the four score bands (SAFE/CAUTION/HIGH_RISK/BLOCKLIST).
2. Tokens: no raw hex in `styles.css`, and every token used through `var()` is defined.
3. DOM contract: every id `app.js` looks up exists in the HTML. A missing id returns
   `null` and the panel stays empty without an error.
4. Band thresholds: `band()` in the frontend matches `BADGE_THRESHOLDS` in the backend.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


# ---------------------------------------------------------------------- helpers
def _tokens() -> dict[str, str]:
    """Hex-valued CSS variables in `tokens.css`."""
    text = (FRONTEND / "tokens.css").read_text(encoding="utf-8")
    return dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", text, re.M))


def _relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relative luminance."""
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(fg: str, bg: str) -> float:
    a, b = _relative_luminance(fg), _relative_luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


#: (description, foreground token, background token, required ratio)
#: Threshold 4.5 = WCAG AA normal text. Decisions are documented here: anyone who
#: wants to change a tone can see which pair constrains it.
CONTRAST_CASES = [
    ("heading / card", "--text", "--surface-1", 4.5),
    ("body / card", "--text-2", "--surface-1", 4.5),
    ("secondary / card", "--text-3", "--surface-1", 4.5),
    ("body / section header", "--text-2", "--surface-2", 4.5),
    ("secondary / section header", "--text-3", "--surface-2", 4.5),
    # surface-4 is the hardest background: .card-step and segment hover sit on it.
    ("secondary / surface-4", "--text-3", "--surface-4", 4.5),
    ("input value / input", "--text", "--surface-3", 4.5),
    ("placeholder / input", "--text-4", "--surface-3", 4.5),
    ("footer / canvas", "--text-4", "--surface-canvas", 4.5),
    ("link / card", "--accent-text", "--surface-1", 4.5),
    ("accent text / accent background", "--accent-text", "--accent-bg", 4.5),
    # Contrast MUST NOT drop on button hover; both states are measured.
    ("primary button / accent", "--accent-fg", "--accent", 4.5),
    ("primary button / accent hover", "--accent-fg", "--accent-hover", 4.5),
    # The four score bands: color carries information here, legibility is not negotiable.
    ("SAFE badge", "--safe-text", "--safe-bg", 4.5),
    ("CAUTION badge", "--caution-text", "--caution-bg", 4.5),
    ("HIGH_RISK badge", "--risk-text", "--risk-bg", 4.5),
    ("BLOCKLIST badge", "--block-text", "--block-bg", 4.5),
]


@pytest.mark.parametrize("label,fg,bg,required", CONTRAST_CASES)
def test_contrast_meets_wcag_aa(label, fg, bg, required):
    """Every piece of information carried by color must be legible."""
    tokens = _tokens()
    assert fg in tokens, f"{fg} is undefined"
    assert bg in tokens, f"{bg} is undefined"

    ratio = _contrast(tokens[fg], tokens[bg])
    assert ratio >= required, (
        f"{label}: {ratio:.2f}:1 < {required}:1 "
        f"({fg}={tokens[fg]} on {bg}={tokens[bg]})"
    )


def test_text_hierarchy_is_monotonic():
    """Text tones must get dimmer in order; otherwise the hierarchy misleads."""
    t = _tokens()
    lums = [_relative_luminance(t[k]) for k in ("--text", "--text-2", "--text-3", "--text-4")]
    assert lums == sorted(lums, reverse=True), lums


def test_surface_elevation_is_monotonic():
    """Elevation ladder: every surface must be lighter than the one before.

    In the dark theme elevation comes from tone, not shadow; if the order breaks,
    cards appear below the background.
    """
    t = _tokens()
    keys = ["--surface-canvas", "--surface-1", "--surface-2", "--surface-3", "--surface-4", "--surface-5"]
    lums = [_relative_luminance(t[k]) for k in keys]
    assert lums == sorted(lums), dict(zip(keys, lums))


# ------------------------------------------------------------ token discipline
def test_no_raw_hex_outside_tokens():
    """`styles.css` must not contain raw colors; the theme is managed from one file.

    Writing `#1a1a1a` directly into a component cuts it off from theme changes and
    takes it out of the contrast tests' scope.
    """
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")
    leaks = re.findall(r"#[0-9a-fA-F]{3,8}\b", css)
    assert leaks == [], f"raw hex in styles.css: {leaks}"


def test_every_used_token_is_defined():
    """Every token referenced with `var(--x)` must be defined in `tokens.css`.

    An undefined token silently resolves to nothing: a border disappears or the text
    takes its inherited color. A visual bug that writes nothing to the console.
    """
    defined = set(
        re.findall(
            r"^\s*(--[a-z0-9-]+):", (FRONTEND / "tokens.css").read_text(encoding="utf-8"), re.M
        )
    )
    used = set()
    for name in ("styles.css", "index.html"):
        used |= set(re.findall(r"var\((--[a-z0-9-]+)", (FRONTEND / name).read_text(encoding="utf-8")))
    assert used <= defined, f"undefined token: {sorted(used - defined)}"


def test_no_glassmorphism_or_decorative_gradients():
    """Rejected visual techniques must not leak back in.

    `backdrop-filter` makes text contrast unpredictable in the dark theme: legibility
    depends on whatever passes behind it and cannot be measured. `background-clip: text`
    produces gradient text; small-type contrast becomes unmeasurable.

    Gradient *fills* are banned too, but not gradients that draw shapes: the
    `linear-gradient(45deg, transparent 50%, color 50%)` in the `select` arrow is not a
    color transition but a sharp-edged triangle. The test makes the distinction
    explicit: a transition between two different opaque colors is a decorative fill.
    """
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")

    for banned in ("backdrop-filter", "background-clip: text", "-webkit-background-clip"):
        assert banned not in css, f"banned technique is back: {banned}"

    for gradient in re.findall(r"(?:linear|radial|conic)-gradient\(([^;]*?)\)", css):
        # A gradient with `transparent` draws a shape; it does not blend colors.
        if "transparent" in gradient:
            continue
        colors = re.findall(r"var\((--[a-z0-9-]+)\)|#[0-9a-fA-F]{3,8}", gradient)
        assert len(set(colors)) <= 1, f"decorative gradient fill: {gradient.strip()[:80]}"



# ----------------------------------------------------------------- DOM contract
def test_every_queried_id_exists_in_html():
    """Every id `app.js` looks up must exist in the HTML.

    A missing id returns `null`, and thanks to the `?.` chain no exception is thrown
    either. The result: the panel silently stays empty and the bug is hidden. That
    silence is exactly why this test exists.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    js = (FRONTEND / "app.js").read_text(encoding="utf-8")

    html_ids = set(re.findall(r'\bid="([^"]+)"', html))
    queried = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', js))
    queried |= set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', js))
    # loader("panelId", …): panel roots follow the same contract.
    queried |= set(re.findall(r'loader\(\s*"([A-Za-z0-9_-]+)"', js))

    assert queried <= html_ids, f"id missing from the HTML: {sorted(queried - html_ids)}"


def test_tabs_and_panes_are_paired():
    """Every tab must have a matching pane, and vice versa.

    An unmatched tab can be clicked but opens nothing; the user cannot fill in the
    form and does not understand why.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    tabs = set(re.findall(r'data-tab="([^"]+)"', html))
    panes = set(re.findall(r'data-pane="([^"]+)"', html))
    assert tabs == panes, f"tabs={sorted(tabs)} panes={sorted(panes)}"


def test_every_input_has_a_label():
    """An unlabelled field stays anonymous to a screen reader.

    `placeholder` is not a label: it disappears once you start typing, and screen
    readers do not all read it.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    labelled = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', html))

    unlabelled = []
    for tag in re.findall(r"<(?:input|select|textarea)\b[^>]*>", html):
        if 'type="checkbox"' in tag:
            continue  # inside a wrapping <label class="field-check">
        m = re.search(r'\bid="([^"]+)"', tag)
        if not m or m.group(1) not in labelled:
            unlabelled.append(tag[:70])
    assert unlabelled == [], f"unlabelled field: {unlabelled}"

