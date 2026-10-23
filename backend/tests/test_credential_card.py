"""The credential card draws only the credential record, in every state, and its token
metadata says the contract is the source of truth."""

from __future__ import annotations

import base64
import time
import xml.etree.ElementTree as ET

from backend.app.reporting.credential_card import card_svg, token_metadata

NOW = 1_800_000_000.0
RECORD = {"agent_name": "safe-treasury-agent", "decision": "pass", "score": 97, "owner": "G" + "A" * 55,
          "token_id": "ab" * 32, "report_sha256": "cd" * 32, "expires_at": NOW + 86_400, "network": "testnet",
          "contract": "C" + "B" * 55}


def _text(svg: str) -> str:
    return " ".join(t.text or "" for t in ET.fromstring(svg).iter("{http://www.w3.org/2000/svg}text"))


def test_each_state_is_a_valid_svg_that_says_what_the_credential_is():
    passed = _text(card_svg(RECORD, now=NOW))
    assert "97" in passed and "PASSED" in passed and "STELLAR TESTNET" in passed and "cdcd" in passed
    assert "NOT STAMPED" in _text(card_svg({**RECORD, "issued": False, "decision": "needs_evidence"}, now=NOW))
    assert "VOID" in _text(card_svg({**RECORD, "revoked": True}, now=NOW))
    assert "EXPIRED" in _text(card_svg({**RECORD, "expires_at": NOW - 1}, now=NOW))


def test_requester_text_is_escaped_and_long_names_are_cut():
    svg = card_svg({**RECORD, "agent_name": '<script>alert(1)</script>"&' * 3}, now=NOW)
    assert "<script>" not in svg
    ET.fromstring(svg)  # still well-formed
    assert "…" in _text(svg)


def test_metadata_embeds_the_card_and_names_the_contract():
    meta = token_metadata(RECORD, now=NOW)
    assert meta["name"].endswith("97/100")
    assert base64.b64decode(meta["image"].split(",", 1)[1]).decode().startswith("<svg")
    traits = {a["trait_type"]: a["value"] for a in meta["attributes"]}
    assert traits["Transferable"] == "No" and traits["Status"] == "current" and traits["Decision"] == "Passed"
    assert meta["properties"]["report_sha256"] == "cd" * 32 and "contract on Stellar" in meta["description"]
    assert token_metadata(RECORD, image_url="https://x/card.svg", now=NOW)["image"] == "https://x/card.svg"


def test_cards_are_deterministic_for_one_record():
    assert card_svg(RECORD, now=NOW) == card_svg(dict(RECORD), now=NOW)
    assert time.time() > 0
