import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app import api
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.services.ai_review import second_opinion, redact
from backend.app.services.runtime_policy import RuntimePolicy, Action, PolicyGateway, approval_token
from backend.app.swarm.llm import LlmClient


def source(**kwargs):
    return ReviewRequest(name="Treasury", purpose="Prepare approved treasury payments.",
                         files={"agent.py": "def pay(request):\n    return request\n"}, **kwargs)


def test_coverage_never_turns_keywords_into_verified_controls(settings):
    result = asyncio.run(review_source(source(), settings))
    assurance = result["report"]["assurance"]
    assert assurance["total"] == 24
    assert assurance["runtime_verified"] == 0
    assert all(not row["runtime_verified"] for row in assurance["controls"])
    assert assurance["release_gate"] != "approved"
    assert sha256(result["report_json"].encode()).hexdigest() == result["report_sha256"]


def test_architecture_changes_commitment_and_reports_explicit_insecurity(settings):
    clean = asyncio.run(review_source(source(), settings))
    risky = asyncio.run(review_source(source(architecture={"mcp_servers":["demo"], "controls":{"mcp_authentication":False}}), settings))
    assert clean["report"]["input_hash"] != risky["report"]["input_hash"]
    assert "security-architecture-mcp-auth" in risky["priority_finding_ids"]
    assert risky["decision"] == "needs_fixes"


def test_ai_requires_consent_and_operator_enablement(settings):
    with pytest.raises(ValueError, match="consent"):
        asyncio.run(review_source(source(ai_assistance=True), settings))
    with pytest.raises(ValueError, match="unavailable"):
        asyncio.run(review_source(source(ai_assistance=True, external_processing_consent=True), settings))


def test_ai_rejects_fabricated_source_locations_and_cannot_change_verdict(settings, monkeypatch):
    async def fake(self, system, user, **kwargs):
        assert "untrusted" in system.lower()
        return {"observations":[
            {"file":"agent.py","line":1,"title":"Check input","risk":"Potential injection","remediation":"Validate input"},
            {"file":"imaginary.py","line":1,"title":"Fake","risk":"Fake","remediation":"Fake"},
            {"file":"agent.py","line":999,"title":"Fake","risk":"Fake","remediation":"Fake"}], "score":100}
    monkeypatch.setattr(LlmClient,"judge",fake)
    enabled = settings.model_copy(update={"enable_public_ai_review":True,"llm_provider":"openai","llm_api_key":"test-only","llm_model":"test"})
    plain = asyncio.run(review_source(source(), enabled))
    ai = asyncio.run(review_source(source(ai_assistance=True,external_processing_consent=True), enabled))
    assert len(ai["report"]["ai_review"]["observations"]) == 1
    assert ai["report"]["result"]["overall_score"] == plain["report"]["result"]["overall_score"]
    assert ai["decision"] == plain["decision"]
    assert ai["scope"]["external_processors"] == ["openai:test"]
    assert not ai["report"]["result"]["deterministic"]


def test_redaction_covers_known_key_formats():
    assert "S" + "A" * 55 not in redact("secret=" + "S" + "A" * 55)
    assert "super-secret" not in redact('api_key="super-secret"')


def policy_and_action():
    policy = RuntimePolicy(agent_id="treasury",version="a"*64,asset="XLM",allowed_tools=["payment"],
        allowed_destinations=["treasury"],max_per_action=70,max_total=100,expires_at=2000)
    action = Action(nonce="unique-nonce-0001",agent_id="treasury",version="a"*64,network="testnet",
        tool="payment",asset="XLM",destination="treasury",amount=60,expires_at=1500)
    return policy, action


def test_exact_action_approval_replay_and_persistent_kill_switch(tmp_path):
    policy, action = policy_and_action()
    key = b"x"*32
    gateway = PolicyGateway(tmp_path/"policy.db", key)
    proof = approval_token(policy,action,key)
    altered = action.model_copy(update={"destination":"attacker"})
    assert "approval_missing_or_invalid" in gateway.authorize(policy,altered,proof,now=1000)["reasons"]
    assert gateway.authorize(policy,action,proof,now=1000)["allowed"]
    assert "replay" in gateway.authorize(policy,action,proof,now=1000)["reasons"]
    gateway.pause(policy.agent_id)
    restarted = PolicyGateway(tmp_path/"policy.db",key)
    next_action=action.model_copy(update={"nonce":"unique-nonce-0002","amount":1})
    assert "emergency_stop" in restarted.authorize(policy,next_action,approval_token(policy,next_action,key),now=1000)["reasons"]


def test_concurrent_reservations_cannot_overspend(tmp_path):
    policy, action = policy_and_action(); key=b"x"*32
    gateway=PolicyGateway(tmp_path/"policy.db",key)
    def call(i):
        candidate=action.model_copy(update={"nonce":f"unique-nonce-{i:04d}"})
        return gateway.authorize(policy,candidate,approval_token(policy,candidate,key),now=1000)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(call,range(4)))
    assert sum(r["allowed"] for r in results) == 1
    assert all("cumulative_limit" in r["reasons"] for r in results if not r["allowed"])


def test_changed_version_does_not_reset_budget(tmp_path):
    policy, action=policy_and_action(); key=b"x"*32
    gateway=PolicyGateway(tmp_path/"policy.db",key)
    assert gateway.authorize(policy,action,approval_token(policy,action,key),now=1000)["allowed"]
    updated=policy.model_copy(update={"version":"b"*64})
    next_action=action.model_copy(update={"version":"b"*64,"nonce":"unique-nonce-0002"})
    assert "cumulative_limit" in gateway.authorize(updated,next_action,approval_token(updated,next_action,key),now=1000)["reasons"]


@pytest.mark.parametrize("field,value,reason",[("network","mainnet","network_mismatch"),("version","b"*64,"version_mismatch"),("expires_at",999,"expired"),("depth",9,"delegation_depth"),("asset","OTHER","asset_mismatch")])
def test_policy_denies_boundary_crossings(tmp_path,field,value,reason):
    policy,action=policy_and_action();key=b"x"*32
    action=action.model_copy(update={field:value})
    result=PolicyGateway(tmp_path/"policy.db",key).authorize(policy,action,approval_token(policy,action,key),now=1000)
    assert reason in result["reasons"]


def test_simulation_does_not_treat_unsigned_approval_as_authority():
    policy,action=policy_and_action()
    with TestClient(api.app) as client:
        response=client.post("/api/v1/studio/policy",json={"policy":policy.model_dump(),"action":action.model_dump()})
    assert response.status_code==200
    assert not response.json()["allowed"]
    assert not response.json()["executed"]
    assert "signed_approval_required" in response.json()["reasons"]


@pytest.mark.parametrize("amount", [-1,1.1,True,"1",2**63])
def test_financial_amounts_are_strict_bounded_integers(amount):
    _,action=policy_and_action()
    with pytest.raises(ValidationError):
        Action.model_validate({**action.model_dump(),"amount":amount})
