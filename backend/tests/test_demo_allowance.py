"""What a visitor is told about the model-review allowance, and the operator self-check that
exercises the real allowance store (Vercel Blob) the way the limiter uses it."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import Settings
from backend.app.services import rate_limit
from backend.app.services.rate_limit import BlobStore, DeepReviewLimiter, MemoryStore, self_check

from .test_demo_api import CLOCK, PEER, FakeBlob, demo  # noqa: F401 - the fixture is used by name


def test_a_claim_reports_what_is_left_and_when_it_resets():
    shared = DeepReviewLimiter(MemoryStore(), client_hour=3, hour=60, day=200, salt=b"s", clock=CLOCK)
    first = asyncio.run(shared.acquire("c"))
    assert first.left == {"client_hour": 2, "hour": 59, "day": 199}
    assert shared.describe(first.left) == {"left_this_hour": 2, "left_today": 199, "used_up": False,
                                           "reason": "", "resets_at": ""}
    for _ in range(2):
        asyncio.run(shared.acquire("c"))
    refused = asyncio.run(shared.acquire("c"))
    assert not refused.allowed and refused.left == {"client_hour": 0}
    told = shared.describe(refused.left)
    assert told["used_up"] and told["reason"] == "client_hour" and told["resets_at"] == "2026-10-31T15:00:00+00:00"
    # Looking does not claim: the counts are read, nothing is written.
    store = shared.store
    before = set(store.paths)
    assert asyncio.run(shared.remaining("c")) == {"client_hour": 0, "hour": 57, "day": 197}
    assert store.paths == before


def test_the_daily_ceiling_resets_at_midnight_utc():
    shared = DeepReviewLimiter(MemoryStore(), salt=b"s", clock=CLOCK)
    told = shared.describe({"client_hour": 4, "hour": 10, "day": 0})
    assert told["reason"] == "day" and told["resets_at"] == "2026-11-01T00:00:00+00:00"


def test_the_home_page_config_tells_the_visitor_their_allowance(demo):  # noqa: F811
    client, _, _ = demo
    api._allowance_cache.clear()
    fresh = client.get("/api/v1/demo/config").json()
    assert fresh["allowance"]["left_this_hour"] == 5 and not fresh["allowance"]["used_up"]
    body = {"reference": "https://github.com/o/r", "model_review_consent": True}
    runs = [client.post("/api/v1/demo/audit", json=body).json() for _ in range(6)]
    assert runs[0]["ai"]["allowance"]["left_this_hour"] == 4
    assert runs[-1]["ai"]["review"] == "rate_limited" and runs[-1]["ai"]["allowance"]["used_up"]
    spent = client.get("/api/v1/demo/config").json()["allowance"]
    assert spent["used_up"] and spent["reason"] == "client_hour" and spent["left_this_hour"] == 0
    # Without consent nothing is claimed and no allowance is reported on the result.
    plain = client.post("/api/v1/demo/audit", json={"reference": "https://github.com/o/r"}).json()
    assert "allowance" not in plain["ai"]


def test_no_allowance_is_reported_where_the_model_review_is_off(monkeypatch):
    monkeypatch.setattr(api, "settings", Settings(_env_file=None))
    with TestClient(api.app, client=PEER) as client:
        config = client.get("/api/v1/demo/config").json()
    assert config["model_review"]["available"] is False and config["allowance"] is None


def test_an_unreachable_store_hides_the_allowance_instead_of_failing(monkeypatch):
    broken = DeepReviewLimiter(BlobStore("t", client_factory=FakeBlob(fail=True).client), salt=b"s", clock=CLOCK)
    monkeypatch.setattr(api, "settings", Settings(_env_file=None, enable_deep_review=True, anthropic_ai_key="k",
                                                  blob_read_write_token="vercel_blob_rw_x"))
    monkeypatch.setattr(rate_limit, "limiter_from_settings", lambda _settings: broken)
    api._allowance_cache.clear()
    with TestClient(api.app, client=PEER) as client:
        response = client.get("/api/v1/demo/config")
    assert response.status_code == 200 and response.json()["allowance"] is None


@pytest.mark.parametrize("store", [MemoryStore(), BlobStore("t", client_factory=FakeBlob().client)])
def test_the_self_check_claims_once_and_refuses_the_duplicate(store):
    out = asyncio.run(self_check(store))
    assert out["ok"] is True and out["first_claim"] is True and out["second_claim"] is False
    assert out["listed"] == 1 and out["listed_after_delete"] == 0 and "errors" not in out


def test_the_self_check_reports_a_store_that_cannot_answer_by_class_only():
    out = asyncio.run(self_check(BlobStore("t", client_factory=FakeBlob(fail=True).client)))
    assert out["ok"] is False and out["errors"]["first_claim"] == "BlobServiceNotAvailable"
    assert out["errors"]["listed"] == "ConnectionError"
    assert "down" not in str(out)  # messages are not echoed


def test_the_self_check_endpoint_is_for_previews_and_the_operator_only(monkeypatch):
    blob = FakeBlob()
    monkeypatch.setattr(api, "settings", Settings(_env_file=None, blob_read_write_token="vercel_blob_rw_x",
                                                  admin_api_key="k" * 32))
    monkeypatch.setattr(rate_limit, "limiter_from_settings",
                        lambda _s: DeepReviewLimiter(BlobStore("t", client_factory=blob.client), salt=b"s"))
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    api._self_check_last[0] = 0.0
    with TestClient(api.app, client=PEER) as client:
        hidden = client.post("/api/v1/ops/allowance-check")
        wrong = client.post("/api/v1/ops/allowance-check", headers={"Authorization": "Bearer nope"})
        keyed = client.post("/api/v1/ops/allowance-check", headers={"Authorization": "Bearer " + "k" * 32})
        again = client.post("/api/v1/ops/allowance-check", headers={"Authorization": "Bearer " + "k" * 32})
        monkeypatch.setenv("VERCEL_ENV", "preview")
        api._self_check_last[0] = 0.0
        preview = client.post("/api/v1/ops/allowance-check")
    assert hidden.status_code == 404 and wrong.status_code == 404
    assert keyed.status_code == 200 and keyed.json()["ok"] is True and keyed.json()["allowance_store"] == "vercel_blob"
    assert again.status_code == 429
    assert preview.status_code == 200 and preview.json()["environment"] == "preview"
    assert not blob.paths  # the throwaway slot was deleted
