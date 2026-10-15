"""Provider outcomes, spend bounds and evidence grounding; no paid network calls."""
import asyncio
import json

import httpx
import pytest

from backend.app.config import Settings
from backend.app.services.ai_review import _evidence, redact, second_opinion
from backend.app.services.studio import ReviewRequest
from backend.app.swarm.llm import LlmClient


def configured(**kwargs):
    return Settings(llm_provider="vercel", llm_model="openai/gpt-4.1-mini",
                    ai_gateway_api_key="test-gateway-secret", _env_file=None, **kwargs)


def request():
    return ReviewRequest(name="Review fixture", purpose="Inspect the supplied source fixture.",
                         files={"agent.py": "def respond(prompt):\n    return eval(prompt)\n"})


def mock_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        return original(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(httpx, "AsyncClient", factory)


def response(content='{"observations":[]}', **extra):
    return {"model": "openai/gpt-4.1-mini", "usage": {"prompt_tokens": 110, "completion_tokens": 9,
            "total_tokens": 119, "cost": 0.0000584},
            "choices": [{"finish_reason": "stop", "message": {"content": content}}], **extra}


def test_gateway_api_key_and_oidc_are_scoped_and_not_serialized():
    s = configured(vercel_oidc_token="test-oidc-token")
    assert s.llm_credential == "test-gateway-secret"
    assert s.llm_auth_mode == "api_key"
    assert "test-gateway-secret" not in repr(s) + s.model_dump_json()
    oidc = s.model_copy(update={"ai_gateway_api_key": "", "llm_api_key": ""})
    assert oidc.llm_enabled and oidc.llm_auth_mode == "vercel_oidc"
    assert oidc.llm_status()["connection_verified"] is False
    direct = oidc.model_copy(update={"llm_provider": "openai"})
    assert not direct.llm_enabled  # Vercel credentials never go to OpenAI directly.


@pytest.mark.parametrize("url", ["http://127.0.0.1/v1", "https://api.openai.com@evil.invalid/v1",
                                  "https://ai-gateway.vercel.sh/v1?x=1", "https://ai-gateway.vercel.sh.evil.invalid/v1"])
def test_invalid_provider_endpoint_never_sends_request(monkeypatch, url):
    mock_transport(monkeypatch, lambda _: pytest.fail("must not call network"))
    client = LlmClient(configured(llm_base_url=url))
    assert asyncio.run(client.judge("system", "evidence")) is None
    assert client.last_call["request_sent"] is False


def test_success_reports_provider_usage_and_request_bounds(monkeypatch):
    def handler(req):
        assert req.url == "https://ai-gateway.vercel.sh/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer test-gateway-secret"
        payload = json.loads(req.content)
        assert payload["max_tokens"] == 100
        assert payload["response_format"] == {"type": "json_object"}
        assert "tools" not in payload
        return httpx.Response(200, json=response())
    mock_transport(monkeypatch, handler)
    client = LlmClient(configured(llm_max_output_tokens=100))
    assert asyncio.run(client.judge("JSON only", "untrusted input", 900)) == {"observations": []}
    assert client.last_call["status"] == "completed"
    assert client.last_call["usage"]["total_tokens"] == 119
    assert client.last_call["cost_usd"] == 0.0000584
    assert client.last_call["requests"] == 1
    assert "test-gateway-secret" not in json.dumps(client.last_call)


@pytest.mark.parametrize("code,status", [(401, "authentication_failed"), (403, "permission_denied"),
                                          (402, "credit_required"), (429, "rate_or_budget_limited"),
                                          (503, "provider_unavailable"), (302, "provider_rejected")])
def test_http_failure_is_honest_redacted_and_never_retried(monkeypatch, code, status):
    calls = []
    def handler(req):
        calls.append(req)
        return httpx.Response(code, headers={"Location": "http://127.0.0.1/private"},
                              json={"error": "secret diagnostic must not escape"})
    mock_transport(monkeypatch, handler)
    client = LlmClient(configured())
    assert asyncio.run(client.judge("JSON", "evidence")) is None
    assert len(calls) == 1
    assert client.last_call["status"] == status
    assert "secret diagnostic" not in json.dumps(client.last_call)


def test_response_and_input_budgets(monkeypatch):
    calls = []
    def handler(req):
        calls.append(req)
        return httpx.Response(200, content=b"x" * 5000)
    mock_transport(monkeypatch, handler)
    client = LlmClient(configured(llm_max_input_bytes=1000, llm_max_response_bytes=4096))
    assert asyncio.run(client.judge("JSON", "x" * 1001)) is None
    assert client.last_call["status"] == "input_budget_exceeded"
    assert calls == []
    assert asyncio.run(client.judge("JSON", "source")) is None
    assert client.last_call["status"] == "response_budget_exceeded"


def test_truncated_and_invalid_json_are_not_completed(monkeypatch):
    mock_transport(monkeypatch, lambda _: httpx.Response(200, json=response(
        choices=[{"finish_reason": "length", "message": {"content": '{"observations":[]}'}}])))
    client = LlmClient(configured())
    assert asyncio.run(client.judge("JSON", "source")) is None
    assert client.last_call["status"] == "incomplete_response"
    for raw in ['{"x": 1, "x": 2}', '{"x": NaN}', 'text {"x":1}', '{"x":1}{"y":2}', '[]']:
        assert client._extract_json(raw) is None


def test_anthropic_protocol_and_unreported_cost(monkeypatch):
    def handler(req):
        assert req.url == "https://api.anthropic.com/v1/messages"
        assert req.headers["x-api-key"] == "test-direct"
        assert "Authorization" not in req.headers
        return httpx.Response(200, json={"model": "configured-model", "stop_reason": "end_turn",
              "content": [{"type": "text", "text": '{"observations":[]}'}],
              "usage": {"input_tokens": 10, "output_tokens": 4}})
    mock_transport(monkeypatch, handler)
    client = LlmClient(Settings(llm_provider="anthropic", llm_api_key="test-direct", _env_file=None))
    assert asyncio.run(client.judge("JSON", "source")) == {"observations": []}
    assert client.last_call["cost_usd"] is None
    assert client.last_call["usage"]["total_tokens"] == 14


def test_source_quote_grounding_rejects_invented_quotes_and_unseen_lines(monkeypatch):
    def handler(req):
        payload = json.loads(req.content)
        assert "untrusted" in payload["messages"][0]["content"].lower()
        observation = {"file": "agent.py", "line": 2, "evidence_quote": "eval(prompt)",
                       "title": "Untrusted evaluation", "risk": "Prompt controls code", "remediation": "Remove eval"}
        invented = {**observation, "evidence_quote": "exec(prompt)"}
        bad_line = {**observation, "line": 999}
        return httpx.Response(200, json=response(json.dumps({"observations": [observation, invented, bad_line]})))
    mock_transport(monkeypatch, handler)
    result = asyncio.run(second_opinion(request(), configured()))
    assert result["status"] == "completed" and len(result["observations"]) == 1
    assert result["rejected_observations"] == 2
    assert result["observations"][0]["source_quote_verified"] is True
    assert result["observations"][0]["vulnerability_verified"] is False
    assert result["scores_changed"] is False


@pytest.mark.parametrize("observations,status", [([], "no_observations"), ([{"file": "fake.py"}], "invalid_response")])
def test_empty_or_fabricated_model_result_is_not_a_completed_security_review(monkeypatch, observations, status):
    mock_transport(monkeypatch, lambda _: httpx.Response(200, json=response(json.dumps({"observations": observations}))))
    result = asyncio.run(second_opinion(request(), configured()))
    assert result["status"] == status
    assert result["observations"] == []


def test_line_preserving_redaction_and_bounded_complete_json():
    secret = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\ncode()"
    cleaned = redact(secret)
    assert cleaned.splitlines()[3] == "code()"
    r = request().model_copy(update={"files": {"agent.py": "x" * 1000 + "\nsmall()\n", "b.py": "return 1"}})
    body, sent, scope = _evidence(r, 300)
    assert len(body.encode()) <= 300
    assert isinstance(json.loads(body), dict)
    assert scope["source_complete"] is False
    assert "agent.py" not in sent


def test_connection_canary_never_sends_customer_source_and_requires_response(monkeypatch):
    def handler(req):
        payload = json.loads(req.content)
        assert payload["max_tokens"] == 64
        assert "no customer source" in payload["messages"][1]["content"].lower()
        return httpx.Response(200, json=response('{"connection":"ok"}'))
    mock_transport(monkeypatch, handler)
    result = asyncio.run(LlmClient(configured()).check_connection())
    assert result["connection_verified"] is True
    assert result["provider_call"]["status"] == "completed"
    missing = configured().model_copy(update={"ai_gateway_api_key": "", "vercel_oidc_token": "", "llm_api_key": ""})
    result = asyncio.run(LlmClient(missing).check_connection())
    assert result["connection_verified"] is False
    assert result["provider_call"]["request_sent"] is False
