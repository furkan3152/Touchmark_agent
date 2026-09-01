"""Opsiyonel entegrasyon anahtarlarının kapısı (LLM / AML tarama / IPFS).

Buradaki tek kural: **anahtar yoksa iddia üretilmez.** Sağlayıcı yapılandırılmadığında
sistem tam işlevini korur ama eksik kontrolü kapsam boşluğu olarak bildirir; asla
uydurma bir sonuç üretmez. `SCREENING_PROVIDER` set edilip anahtar verilmemesi de
"kapalı" sayılır — yarım yapılandırma sessizce sahte veri üretmemeli.
"""

from __future__ import annotations

import pytest

from backend.app.config import Settings


def _settings(tmp_path, **kwargs) -> Settings:
    base = dict(
        stellar_network="offline",
        llm_provider="",
        llm_api_key="",
        pinata_jwt="",
        screening_provider="none",
        screening_api_key="",
        data_dir=str(tmp_path / "data"),
        _env_file=None,
    )
    base.update(kwargs)
    return Settings(**base)


# --------------------------------------------------------------- screening kapısı
def test_provider_without_key_is_disabled(tmp_path):
    """Yarım yapılandırma açık sayılmamalı; aksi halde sahte tarama sonucu üretilir."""
    s = _settings(tmp_path, screening_provider="trm", screening_api_key="")
    assert s.screening_enabled is False


def test_key_without_provider_is_disabled(tmp_path):
    s = _settings(tmp_path, screening_provider="none", screening_api_key="secret")
    assert s.screening_enabled is False


def test_unknown_provider_is_disabled(tmp_path):
    """Desteklenmeyen sağlayıcı adı sessizce kabul edilmemeli."""
    s = _settings(tmp_path, screening_provider="somethingelse", screening_api_key="secret")
    assert s.screening_enabled is False


@pytest.mark.parametrize("provider", ["trm", "elliptic", "TRM", "Elliptic"])
def test_provider_and_key_enable_screening(tmp_path, provider):
    s = _settings(tmp_path, screening_provider=provider, screening_api_key="secret")
    assert s.screening_enabled is True


def test_chainalysis_provider_is_supported(tmp_path):
    """Ücretsiz Chainalysis yaptırım API'si de geçerli bir sağlayıcıdır."""
    s = _settings(tmp_path, screening_provider="chainalysis", screening_api_key="secret")
    assert s.screening_enabled is True


def test_disabled_screening_returns_unknown_not_risk(tmp_path, run):
    """Kapalıyken `_screen_wallet` risk uydurmaz, 'unknown' döner."""
    from backend.app.swarm.compliance import ComplianceAuditor

    s = _settings(tmp_path, screening_provider="trm", screening_api_key="")
    screen = run(ComplianceAuditor(s)._screen_wallet("0x" + "11" * 20))

    assert screen["risk"] == "unknown"
    assert screen["provider"] == "unavailable"
    assert screen["categories"] == []


# --------------------------------------------------------------------- LLM kapısı
def test_llm_requires_both_provider_and_key(tmp_path):
    assert _settings(tmp_path, llm_provider="anthropic").llm_enabled is False
    assert _settings(tmp_path, llm_api_key="secret").llm_enabled is False
    assert (
        _settings(tmp_path, llm_provider="anthropic", llm_api_key="secret").llm_enabled is True
    )


def test_llm_provider_none_is_disabled(tmp_path):
    s = _settings(tmp_path, llm_provider="none", llm_api_key="secret")
    assert s.llm_enabled is False


def test_openrouter_base_url_is_derived(tmp_path):
    """OpenRouter için kullanıcının ayrıca LLM_BASE_URL yazması gerekmemeli."""
    s = _settings(tmp_path, llm_provider="openrouter", llm_api_key="k")
    assert s.llm_api_base == "https://openrouter.ai/api/v1"
    assert s.llm_enabled is True


def test_explicit_base_url_overrides_provider_default(tmp_path):
    """Yerel vLLM/LM Studio gibi durumlar için override çalışmalı (sonda / temizlenir)."""
    s = _settings(
        tmp_path,
        llm_provider="openrouter",
        llm_api_key="k",
        llm_base_url="http://localhost:1234/v1/",
    )
    assert s.llm_api_base == "http://localhost:1234/v1"


def test_unknown_provider_falls_back_to_openai_base(tmp_path):
    s = _settings(tmp_path, llm_provider="mystery", llm_api_key="k")
    assert s.llm_api_base == "https://api.openai.com/v1"


# ------------------------------------------------------------- entegrasyon raporu
def test_integrations_list_capabilities_and_fail_closed_fallbacks(tmp_path):
    """Her entegrasyon ne açtığını ve kapalıyken ne olduğunu söylemeli."""
    items = _settings(tmp_path).integrations()

    keys = [i["key"] for i in items]
    assert keys == [
        "AGENT_REGISTRY_CONTRACT_ID",
        "AUDIT_ESCROW_CONTRACT_ID",
        "LLM_API_KEY",
        "(anahtarsız)",
        "SCREENING_API_KEY",
        "PINATA_JWT",
        "SEP10/SEP45 endpoints",
    ]
    for item in items:
        assert item["unlocks"]
        assert item["fallback"]
    # OFAC anahtarsız çalıştığı için varsayılan olarak açık; diğerleri kapalı
    by_key = {i["key"]: i for i in items}
    assert by_key["(anahtarsız)"]["enabled"] is True
    assert by_key["LLM_API_KEY"]["enabled"] is False
    assert by_key["SCREENING_API_KEY"]["enabled"] is False
    assert by_key["PINATA_JWT"]["enabled"] is False


def test_integrations_never_leaks_secret_values(tmp_path):
    """Rapor anahtar değerini değil, yalnızca sağlayıcı adını taşımalı."""
    secret = "sk-super-secret-value"
    s = _settings(
        tmp_path,
        llm_provider="anthropic",
        llm_api_key=secret,
        screening_provider="trm",
        screening_api_key=secret,
        pinata_jwt=secret,
    )
    blob = repr(s.integrations())

    assert secret not in blob
    by_key = {i["key"]: i for i in s.integrations()}
    assert by_key["LLM_API_KEY"]["enabled"] is True
    assert by_key["SCREENING_API_KEY"]["enabled"] is True
    assert by_key["PINATA_JWT"]["enabled"] is True


def test_screening_mode_is_boolean_not_provider_name(tmp_path):
    """`modes.screening` sağlayıcı adı değil, gerçekten açık mı olduğudur.

    Eskiden `SCREENING_PROVIDER` adı dönüyordu; "none" bile dolu bir string olduğu
    için UI kapalı entegrasyonu açık gösteriyordu.
    """
    s = _settings(tmp_path, screening_provider="trm", screening_api_key="")

# ------------------------------------------------------- Chainalysis eşlemesi
class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """httpx.AsyncClient yerine geçen, isteği kaydeden sahte istemci."""

    calls: list[dict] = []

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None, **kwargs):
        type(self).calls.append({"url": url, "headers": headers or {}})
        return _FakeResponse(self._payload)


def _screen_with(monkeypatch, tmp_path, run, payload: dict) -> dict:
    from backend.app.swarm import compliance as mod

    fake = _FakeClient(payload)
    _FakeClient.calls = []
    monkeypatch.setattr(mod.httpx, "AsyncClient", fake)

    s = _settings(tmp_path, screening_provider="chainalysis", screening_api_key="test-key")
    return run(mod.ComplianceAuditor(s)._screen_wallet("0x" + "ab" * 20))


def test_chainalysis_sanctioned_address_is_severe(monkeypatch, tmp_path, run):
    """`identifications` doluysa yaptırımlıdır — gri bölge yok."""
    payload = {"identifications": [{"category": "sanctions", "name": "OFAC SDN"}]}
    screen = _screen_with(monkeypatch, tmp_path, run, payload)

    assert screen["provider"] == "chainalysis"
    assert screen["risk"] == "severe"
    assert screen["categories"] == ["sanctions"]


def test_chainalysis_clean_address_is_low(monkeypatch, tmp_path, run):
    screen = _screen_with(monkeypatch, tmp_path, run, {"identifications": []})

    assert screen["risk"] == "low"
    assert screen["categories"] == []


def test_chainalysis_uses_x_api_key_header(monkeypatch, tmp_path, run):
    """Chainalysis Bearer değil `X-API-Key` bekler; yanlış header 401 verir."""
    _screen_with(monkeypatch, tmp_path, run, {"identifications": []})

    call = _FakeClient.calls[0]
    assert call["headers"]["X-API-Key"] == "test-key"
    assert "Authorization" not in call["headers"]
    assert call["url"].startswith("https://public.chainalysis.com/api/v1/address/")


def test_chainalysis_network_error_falls_back_to_unknown(monkeypatch, tmp_path, run):
    """Sağlayıcıya ulaşılamazsa risk uydurulmaz, 'unknown' döner."""
    from backend.app.swarm import compliance as mod

    class Boom(_FakeClient):
        async def get(self, url, headers=None, **kwargs):
            raise OSError("bağlantı yok")

    monkeypatch.setattr(mod.httpx, "AsyncClient", Boom({}))
    s = _settings(tmp_path, screening_provider="chainalysis", screening_api_key="test-key")
    screen = run(mod.ComplianceAuditor(s)._screen_wallet("0x" + "cd" * 20))

    assert screen["risk"] == "unknown"
    assert screen["provider"] == "unavailable"


def test_screening_mode_is_boolean_not_provider_name(tmp_path):
    """`modes.screening` sağlayıcı adı değil, gerçekten açık mı olduğudur.

    Eskiden `SCREENING_PROVIDER` adı dönüyordu; "none" bile dolu bir string olduğu
    için UI kapalı entegrasyonu açık gösteriyordu.
    """
    s = _settings(tmp_path, screening_provider="trm", screening_api_key="")
    assert s.screening_enabled is False
    assert isinstance(s.screening_enabled, bool)
