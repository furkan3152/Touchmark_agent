"""Stellar öz-denetimin evidence-boundary sınıflandırması."""

from __future__ import annotations

from backend.app.config import Settings
from backend.app.services.selftest import FAIL, OK, WARN, SelfTestService


def _settings(tmp_path, **updates) -> Settings:
    values = {
        "stellar_network": "offline",
        "llm_provider": "",
        "llm_api_key": "",
        "pinata_jwt": "",
        "screening_provider": "none",
        "data_dir": str(tmp_path / "data"),
        "event_database": str(tmp_path / "events.db"),
        "_env_file": None,
    }
    values.update(updates)
    return Settings(**values)


def _by_name(result: dict) -> dict[str, dict]:
    return {check["name"]: check for check in result["checks"]}


def test_fresh_offline_install_has_no_failures(tmp_path, run):
    result = run(SelfTestService(_settings(tmp_path)).run())
    assert result["ok"] is True
    assert result["summary"][FAIL] == 0
    assert result["summary"][WARN] > 0


def test_signing_boundary_is_positive_evidence(tmp_path, run):
    checks = _by_name(run(SelfTestService(_settings(tmp_path)).run()))
    assert checks["İmzalama sınırı"]["state"] == OK
    assert "prepared invocation" in checks["İmzalama sınırı"]["detail"]


def test_configured_contract_is_not_reported_as_deployed(tmp_path, run):
    settings = _settings(tmp_path, agent_registry_contract_id="C" + "A" * 55)
    checks = _by_name(run(SelfTestService(settings).run()))
    assert checks["Agent registry"]["state"] == WARN
    assert "doğrulanmadı" in checks["Agent registry"]["detail"]


def test_disabled_escrow_is_healthy_core_boundary(tmp_path, run):
    checks = _by_name(run(SelfTestService(_settings(tmp_path)).run()))
    assert checks["Audit escrow"]["state"] == OK
    assert "bağımsız" in checks["Audit escrow"]["detail"]


def test_partial_sep_auth_is_warn(tmp_path, run):
    settings = _settings(tmp_path, sep10_web_auth_endpoint="https://anchor.example/auth")
    checks = _by_name(run(SelfTestService(settings).run()))
    assert checks["Account auth"]["state"] == WARN
    assert "SEP-45" in checks["Account auth"]["detail"]


def test_invalid_network_is_failure(tmp_path, run):
    result = run(SelfTestService(_settings(tmp_path, stellar_network="unknown")).run())
    checks = _by_name(result)
    assert checks["Ağ profili"]["state"] == FAIL
    assert result["ok"] is False


def test_summary_counts_match_checks(tmp_path, run):
    result = run(SelfTestService(_settings(tmp_path)).run())
    summary = result["summary"]
    assert summary[OK] + summary[WARN] + summary[FAIL] == len(result["checks"])
