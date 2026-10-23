"""The touchmark as an image: the credential card and its token metadata.

A credential lives in the AuditCredential contract; this module only draws it. The card
uses the same print language as the web app (cream stock, navy and red spot inks, a
halftone screen, a rubber score stamp with a second ink off register), so a credential
shown in a wallet or marketplace reads as the stamp the app put on the report. Every
value on the card comes from the credential record, never from the requester.

The metadata follows the common token metadata shape (name, description, image,
external_url, attributes) that wallets and marketplaces read from a token URI.
"""

from __future__ import annotations

import base64
import time
from html import escape

#: Decision -> (stamp word, ink). The inks are the web app's --green, --amber and --red.
_STATES = {
    "pass": ("Passed", "#1f7a5a"),
    "needs_evidence": ("Needs evidence", "#b97c0b"),
    "needs_fixes": ("Needs fixes", "#e2432a"),
}
_PAPER, _CARD, _INK, _SOFT, _RED, _LINE = "#f4eee1", "#fbf7ee", "#1d2b4f", "#4e5878", "#e2432a", "#c9c3b4"
_SERIF = "Fraunces, 'Iowan Old Style', Georgia, serif"
_SANS = "Archivo, 'Helvetica Neue', Arial, sans-serif"
_MONO = "'IBM Plex Mono', ui-monospace, 'SFMono-Regular', Menlo, monospace"


def _e(value) -> str:
    return escape(str(value), quote=True)


def _short(value: str, head: int = 6, tail: int = 4) -> str:
    value = str(value or "")
    return value if len(value) <= head + tail + 1 else f"{value[:head]}…{value[-tail:]}"


def _status(c: dict, now: float) -> str:
    if c.get("revoked"):
        return "revoked"
    if c.get("expires_at") and float(c["expires_at"]) < now:
        return "expired"
    return "current" if c.get("issued", True) else "preview"


def card_svg(c: dict, *, now: float | None = None) -> str:
    """The credential card, 1000 x 1000.

    ``c`` keys: agent_name, decision, score, owner, token_id, report_sha256, expires_at
    (unix seconds), network, contract, version, issued (False for a report not yet
    stamped), revoked."""
    now = time.time() if now is None else now
    word, ink = _STATES.get(c.get("decision", ""), ("Reviewed", _INK))
    status = _status(c, now)
    score = max(0, min(100, int(round(float(c.get("score") or 0)))))
    name = str(c.get("agent_name") or "Unnamed agent")
    # The name stays left of the stamp: about 460 px wide.
    name = name if len(name) <= 20 else name[:19] + "…"
    network = str(c.get("network") or "testnet").upper()
    digest = str(c.get("report_sha256") or "")
    expires = time.strftime("%Y-%m-%d", time.gmtime(float(c["expires_at"]))) if c.get("expires_at") else "—"
    # Score ring: circumference of r=150 is 942.48.
    dash = f"{942.48 * score / 100:.1f} 942.48"
    head = {"preview": "REPORT COPY · ORIGIN UNVERIFIED", "current": f"AUDIT CREDENTIAL · STELLAR {network}",
            "expired": "AUDIT CREDENTIAL · EXPIRED", "revoked": "AUDIT CREDENTIAL · REVOKED"}[status]
    rows = [("OWNER", _short(c.get("owner"), 8, 6) or "—"),
            ("TOKEN", _short(c.get("token_id"), 10, 6) or "—"),
            ("VALID UNTIL", expires),
            ("CONTRACT", _short(c.get("contract"), 8, 6) or "—")]
    fields = "".join(
        f'<text x="{90 + (i % 2) * 420}" y="{690 + (i // 2) * 74}" font-family="{_MONO}" font-size="15" '
        f'letter-spacing="2" fill="{_SOFT}">{label}</text>'
        f'<text x="{90 + (i % 2) * 420}" y="{718 + (i // 2) * 74}" font-family="{_MONO}" font-size="22" '
        f'fill="{_INK}">{_e(value)}</text>' for i, (label, value) in enumerate(rows))
    void = ""
    if status in {"revoked", "expired"}:
        void = (f'<g transform="rotate(-18 520 440)" opacity=".9"><rect x="190" y="370" width="660" height="140" '
                f'fill="none" stroke="{_RED}" stroke-width="10"/><text x="520" y="480" text-anchor="middle" '
                f'font-family="{_SERIF}" font-weight="800" font-size="118" letter-spacing="14" fill="{_RED}">'
                f'{"VOID" if status == "revoked" else "EXPIRED"}</text></g>')
    stamp_word = "Not stamped" if status == "preview" else word
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000" viewBox="0 0 1000 1000" role="img" aria-label="Touchmark credential for {_e(name)}: {_e(word)}, {score} of 100">
<defs>
  <pattern id="dots" width="12" height="12" patternUnits="userSpaceOnUse"><circle cx="3" cy="3" r="1.5" fill="{_INK}" opacity=".13"/></pattern>
  <pattern id="ink-dots" width="9" height="9" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.6" fill="{ink}" opacity=".35"/></pattern>
  <filter id="grain"><feTurbulence type="fractalNoise" baseFrequency=".8" numOctaves="3" stitchTiles="stitch"/><feColorMatrix values="0 0 0 0 .3 0 0 0 0 .25 0 0 0 0 .15 0 0 0 .22 0"/></filter>
  <filter id="rough"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="7"/><feDisplacementMap in="SourceGraphic" scale="3.5"/></filter>
</defs>
<rect width="1000" height="1000" fill="{_PAPER}"/>
<rect width="1000" height="1000" fill="url(#dots)"/>
<path d="M78 40h844a38 38 0 0 0 38 38v844a38 38 0 0 0-38 38H78a38 38 0 0 0-38-38V78a38 38 0 0 0 38-38Z" fill="{_RED}" transform="translate(9 9)"/>
<path d="M78 40h844a38 38 0 0 0 38 38v844a38 38 0 0 0-38 38H78a38 38 0 0 0-38-38V78a38 38 0 0 0 38-38Z" fill="{_CARD}" stroke="{_INK}" stroke-width="4"/>
<g transform="translate(90 92) scale(1.05)">
  <path d="M14 4h36a10 10 0 0 0 10 10v36a10 10 0 0 0-10 10H14A10 10 0 0 0 4 50V14A10 10 0 0 0 14 4Z" fill="{_INK}"/>
  <path d="M33.6 11.5c1.5 11.4 7.9 17.8 19.3 19.3-11.4 1.5-17.8 7.9-19.3 19.3-1.5-11.4-7.9-17.8-19.3-19.3 11.4-1.5 17.8-7.9 19.3-19.3Z" fill="#ef4a2f"/>
  <path d="M32 13c1.5 11.4 7.9 17.8 19.3 19.3C39.9 33.8 33.5 40.2 32 51.6 30.5 40.2 24.1 33.8 12.7 32.3 24.1 30.8 30.5 24.4 32 13Z" fill="none" stroke="#f6f0e3" stroke-width="2.4" stroke-linejoin="round"/>
</g>
<text x="174" y="134" font-family="{_SERIF}" font-weight="650" font-size="44" letter-spacing="-1" fill="{_INK}">Touchmark</text>
<text x="176" y="164" font-family="{_MONO}" font-size="15" letter-spacing="2.5" fill="{_SOFT}">{_e(head)}</text>
<text x="90" y="262" font-family="{_MONO}" font-size="16" letter-spacing="3" fill="{_SOFT}">AGENT</text>
<text x="88" y="318" font-family="{_SERIF}" font-weight="700" font-size="{56 if len(name) <= 15 else 44}" letter-spacing="-1.5" fill="{_INK}">{_e(name)}</text>
<text x="90" y="366" font-family="{_SANS}" font-size="21" fill="{_SOFT}">Code tested before it</text>
<text x="90" y="394" font-family="{_SANS}" font-size="21" fill="{_SOFT}">was given the keys. Its</text>
<text x="90" y="422" font-family="{_SANS}" font-size="21" fill="{_SOFT}">report hash and score</text>
<text x="90" y="450" font-family="{_SANS}" font-size="21" fill="{_SOFT}">are written on Stellar.</text>
<g transform="translate(722 420) rotate(-8)" filter="url(#rough)">
  <circle r="168" fill="url(#ink-dots)" transform="translate(7 6)"/>
  <circle r="168" fill="none" stroke="{ink}" stroke-width="7"/>
  <circle r="150" fill="none" stroke="{ink}" stroke-width="16" opacity=".18"/>
  <circle r="150" fill="none" stroke="{ink}" stroke-width="16" stroke-dasharray="{dash}" transform="rotate(-90)"/>
  <text y="22" text-anchor="middle" font-family="{_SERIF}" font-weight="800" font-size="104" letter-spacing="-3" fill="{ink}">{score}</text>
  <text y="66" text-anchor="middle" font-family="{_MONO}" font-weight="600" font-size="18" letter-spacing="3" fill="{ink}">/ 100</text>
  <rect x="-132" y="128" width="264" height="50" fill="{_CARD}" stroke="{ink}" stroke-width="5"/>
  <text y="162" text-anchor="middle" font-family="{_MONO}" font-weight="700" font-size="22" letter-spacing="3" fill="{ink}">{_e(stamp_word.upper())}</text>
</g>
<path d="M90 630H910" stroke="{_LINE}" stroke-width="2.5" stroke-dasharray="10 9"/>
<circle cx="40" cy="630" r="18" fill="{_PAPER}" stroke="{_INK}" stroke-width="4"/>
<circle cx="960" cy="630" r="18" fill="{_PAPER}" stroke="{_INK}" stroke-width="4"/>
{fields}
<text x="90" y="876" font-family="{_MONO}" font-size="15" letter-spacing="2" fill="{_SOFT}">REPORT SHA-256</text>
<text x="90" y="904" font-family="{_MONO}" font-size="19" fill="{_INK}">{_e(digest[:32])}</text>
<text x="90" y="930" font-family="{_MONO}" font-size="19" fill="{_INK}">{_e(digest[32:64])}</text>
<text x="910" y="930" text-anchor="end" font-family="{_MONO}" font-size="14" letter-spacing="2" fill="{_SOFT}">NON-TRANSFERABLE</text>
{void}
<rect width="1000" height="1000" filter="url(#grain)" opacity=".55" style="mix-blend-mode:multiply"/>
</svg>'''


def token_metadata(c: dict, *, image_url: str = "", external_url: str = "", now: float | None = None) -> dict:
    """Token metadata for the credential. Without an image URL the card is embedded."""
    now = time.time() if now is None else now
    word, _ = _STATES.get(c.get("decision", ""), ("Reviewed", ""))
    status = _status(c, now)
    image = image_url or "data:image/svg+xml;base64," + base64.b64encode(card_svg(c, now=now).encode()).decode()
    attributes = [
        {"trait_type": "Decision", "value": word},
        {"trait_type": "Score", "value": int(round(float(c.get("score") or 0))), "max_value": 100, "display_type": "number"},
        {"trait_type": "Status", "value": status},
        {"trait_type": "Network", "value": f"Stellar {c.get('network') or 'testnet'}"},
        {"trait_type": "Transferable", "value": "No"},
    ]
    if c.get("expires_at"):
        attributes.append({"trait_type": "Valid until", "value": int(c["expires_at"]), "display_type": "date"})
    return {
        "name": f"Touchmark · {c.get('agent_name') or 'agent'} · {int(round(float(c.get('score') or 0)))}/100",
        "description": ("A Touchmark audit credential. The report's SHA-256 and score are held by the "
                        "AuditCredential contract on Stellar; verify them there before relying on this image. "
                        "It is bound to the audited version and cannot be transferred."),
        "image": image,
        **({"external_url": external_url} if external_url else {}),
        "attributes": attributes,
        "properties": {"token_id": c.get("token_id", ""), "report_sha256": c.get("report_sha256", ""),
                       "contract": c.get("contract", ""), "owner": c.get("owner", ""), "version": c.get("version", "")},
    }
