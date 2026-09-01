"""Yan etkili API uçlarının fail-closed operatör kapısı."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from backend.app import api
from backend.app.config import Settings


def _request(host: str = "127.0.0.1") -> Request:
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [], "client": (host, 1)})


def test_operator_api_is_closed_without_key(monkeypatch, tmp_path, run):
    monkeypatch.setattr(
        api,
        "settings",
        Settings(
            stellar_network="offline",
            admin_api_key="",
            data_dir=str(tmp_path / "data"),
            event_database=str(tmp_path / "events.db"),
            _env_file=None,
        ),
    )
    with pytest.raises(HTTPException) as caught:
        run(api.require_operator(_request(), None))
    assert caught.value.status_code == 503


def test_operator_api_rejects_wrong_bearer(monkeypatch, tmp_path, run):
    monkeypatch.setattr(
        api,
        "settings",
        Settings(
            stellar_network="offline",
            admin_api_key="correct-secret",
            data_dir=str(tmp_path / "data"),
            event_database=str(tmp_path / "events.db"),
            _env_file=None,
        ),
    )
    with pytest.raises(HTTPException) as caught:
        run(api.require_operator(_request(), "Bearer wrong-secret"))
    assert caught.value.status_code == 401


def test_operator_api_rate_limit_is_enforced(monkeypatch, tmp_path, run):
    monkeypatch.setattr(
        api,
        "settings",
        Settings(
            stellar_network="offline",
            admin_api_key="correct-secret",
            admin_rate_limit_per_minute=1,
            data_dir=str(tmp_path / "data"),
            event_database=str(tmp_path / "events.db"),
            _env_file=None,
        ),
    )
    api._operator_requests.clear()
    run(api.require_operator(_request("192.0.2.10"), "Bearer correct-secret"))
    with pytest.raises(HTTPException) as caught:
        run(api.require_operator(_request("192.0.2.10"), "Bearer correct-secret"))
    assert caught.value.status_code == 429


def test_deep_selftest_cannot_be_triggered_with_get(run):
    with pytest.raises(HTTPException) as caught:
        run(api.selftest(deep=True))
    assert caught.value.status_code == 405
