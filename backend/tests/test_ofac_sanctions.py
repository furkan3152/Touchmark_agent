"""OFAC SDN sanctions list: free, keyless, primary source.

Checks that CSV extraction works and that the audit path makes no network calls
(downloading 5.6 MB mid-audit would block it). The tests are offline; the real OFAC
line format comes from embedded examples."""

from __future__ import annotations

import json
import time

import pytest

from backend.app.compliance.ofac import (
    HEX_CHAINS,
    OfacSanctionsList,
    extract_addresses,
)
from backend.app.config import Settings
from backend.app.models import AgentArtifact, OnchainActivity, Severity, SourceKind
from backend.app.swarm.compliance import ComplianceAuditor

# Format taken from the real SDN CSV (the addresses really are listed).
SDN_SAMPLE = (
    '36,"SOME ENTITY",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0-\n'
    '999,"BAD ACTOR",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,'
    '"Digital Currency Address - ETH 0x098B716B8Aaf21512996dC57EB0615e2383E2f96; '
    "Digital Currency Address - XBT 1Ai52Uw6usjhpcDrwSmkUvjuqLpcznUuyF; "
    'Digital Currency Address - TRX TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX."\n'
)

SANCTIONED_ETH = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
CLEAN_ETH = "0x1c574fAdF9e7581bB3ea4863621186c5911Aab9D"


def _settings(tmp_path, **kw) -> Settings:
    base = dict(
        stellar_network="offline",
        llm_provider="",
        pinata_jwt="",
        screening_provider="none",
        screening_api_key="",
        data_dir=str(tmp_path / "data"),
        _env_file=None,
    )
    base.update(kw)
    return Settings(**base)


def _artifact(wallet: str) -> AgentArtifact:
    return AgentArtifact(
        name="agent",
        source_kind=SourceKind.ONCHAIN_ADDRESS,
        source_ref=wallet,
        agent_wallet=wallet,
        onchain=OnchainActivity(data_source="indexer", tx_count=10, is_contract=False),
    )


def _seed_cache(tmp_path, *, fetched_at: float | None = None) -> OfacSanctionsList:
    """Write a cache extracted from the real CSV to disk."""
    s = _settings(tmp_path)
    sanctions = OfacSanctionsList(s.data_path)
    sanctions.save_cache(
        {
            "publisher": "US Treasury OFAC (SDN)",
            "fetched_at": time.time() if fetched_at is None else fetched_at,
            "chains": extract_addresses(SDN_SAMPLE),
            "total_addresses": 3,
        }
    )
    return sanctions


# ------------------------------------------------------------------- extraction
def test_extract_finds_all_chains():
    chains = extract_addresses(SDN_SAMPLE)

    assert set(chains) == {"ETH", "XBT", "TRX"}
    assert len(chains["ETH"]) == 1


def test_hex_addresses_are_lowercased():
    """OFAC uses mixed-case checksums; hex matching must be case-insensitive."""
    chains = extract_addresses(SDN_SAMPLE)

    assert chains["ETH"][0] == SANCTIONED_ETH.lower()
    assert "ETH" in HEX_CHAINS


def test_non_hex_addresses_keep_case():
    """BTC and TRX addresses are case-sensitive; lower-casing them breaks matching."""
    chains = extract_addresses(SDN_SAMPLE)

    assert chains["XBT"][0] == "1Ai52Uw6usjhpcDrwSmkUvjuqLpcznUuyF"
    assert chains["TRX"][0] == "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"


def test_extract_ignores_non_address_rows():
    """Rows without a crypto address must not appear in the result."""
    plain = '36,"SOME ENTITY",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0-\n'
    assert extract_addresses(plain) == {}


# -------------------------------------------------------------------- sorgulama
def test_lookup_matches_sanctioned_address_case_insensitively(tmp_path):
    sanctions = _seed_cache(tmp_path)

    for variant in (SANCTIONED_ETH, SANCTIONED_ETH.lower(), SANCTIONED_ETH.upper()):
        result = sanctions.lookup_cached(variant)
        assert result["listed"] is True, variant
        assert result["chains"] == ["ETH"]


def test_lookup_reports_clean_address_as_not_listed(tmp_path):
    sanctions = _seed_cache(tmp_path)
    result = sanctions.lookup_cached(CLEAN_ETH)

    assert result["available"] is True
    assert result["listed"] is False
    assert result["chains"] == []


def test_lookup_without_cache_is_unavailable(tmp_path):
    """Without a cache the answer is unknown, not 'not listed'."""
    s = _settings(tmp_path)
    result = OfacSanctionsList(s.data_path).lookup_cached(CLEAN_ETH)

    assert result["available"] is False


def test_stale_cache_is_flagged(tmp_path):
    """A 48-hour-old list can be used but must be marked as not current."""
    sanctions = _seed_cache(tmp_path, fetched_at=time.time() - 48 * 3600)
    result = sanctions.lookup_cached(SANCTIONED_ETH)

    assert result["listed"] is True
    assert result["stale"] is True


def test_corrupt_cache_is_treated_as_missing(tmp_path):
    s = _settings(tmp_path)
    sanctions = OfacSanctionsList(s.data_path)
    sanctions.cache_path.parent.mkdir(parents=True, exist_ok=True)
    sanctions.cache_path.write_text("{bozuk json", encoding="utf-8")

    assert sanctions.load_cache() is None
    assert sanctions.lookup_cached(CLEAN_ETH)["available"] is False


# ------------------------------------------------------ auditor integration
def test_auditor_flags_sanctioned_wallet_as_critical(tmp_path, run):
    """A sanctioned address must be CRITICAL + CONFIRMED; it is a primary-source fact."""
    _seed_cache(tmp_path)
    verdict = run(ComplianceAuditor(_settings(tmp_path)).run(_artifact(SANCTIONED_ETH)))

    hits = [f for f in verdict.findings if f.id.endswith("wallet-screening-hit")]
    assert len(hits) == 1
    assert hits[0].severity == Severity.CRITICAL
    assert "ofac_sdn" in hits[0].detail or "ofac" in hits[0].detail.lower()


def test_auditor_does_not_flag_unlisted_wallet(tmp_path, run):
    """An unlisted address must not be accused; only partial coverage is reported."""
    _seed_cache(tmp_path)
    verdict = run(ComplianceAuditor(_settings(tmp_path)).run(_artifact(CLEAN_ETH)))

    assert not any(f.id.endswith("wallet-screening-hit") for f in verdict.findings)
    assert not any(f.severity == Severity.CRITICAL for f in verdict.findings)

    gaps = [f for f in verdict.findings if f.id.endswith("wallet-screening-unavailable")]
    assert len(gaps) == 1
    assert gaps[0].severity == Severity.LOW
    # OFAC was screened, so the text must say "partial", not "not performed"
    assert "partial" in gaps[0].title.lower()


def test_missing_cache_reports_no_scan_not_partial(tmp_path, run):
    """With no source at all the message must say 'not performed', not partial coverage."""
    verdict = run(ComplianceAuditor(_settings(tmp_path)).run(_artifact(CLEAN_ETH)))

    gaps = [f for f in verdict.findings if f.id.endswith("wallet-screening-unavailable")]
    assert len(gaps) == 1
    assert "not performed" in gaps[0].title.lower()


def test_ofac_can_be_disabled(tmp_path, run):
    """Can be turned off with ENABLE_OFAC_SCREENING=false."""
    _seed_cache(tmp_path)
    s = _settings(tmp_path, enable_ofac_screening=False)
    screen = run(ComplianceAuditor(s)._screen_wallet(SANCTIONED_ETH))

    assert screen["provider"] == "unavailable"
    assert screen["risk"] == "unknown"


def test_ofac_enabled_by_default_without_any_key(tmp_path):
    """Must be on without a key: the source is public."""
    s = _settings(tmp_path)
    assert s.ofac_enabled is True
    assert s.screening_enabled is False


def test_audit_path_never_hits_network(tmp_path, run, monkeypatch):
    """No HTTP request may be made during an audit; only the cache is read."""
    _seed_cache(tmp_path)

    from backend.app.compliance import ofac as ofac_mod

    def explode(*args, **kwargs):
        raise AssertionError("a network request was made on the audit path")

    monkeypatch.setattr(ofac_mod.httpx, "AsyncClient", explode)
    verdict = run(ComplianceAuditor(_settings(tmp_path)).run(_artifact(SANCTIONED_ETH)))

    assert any(f.id.endswith("wallet-screening-hit") for f in verdict.findings)
