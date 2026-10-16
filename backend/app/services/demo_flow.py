"""The public demo: one reference in, a committed report out, and, for a passing report,
an AuditCredential issued on Stellar TESTNET.

The audit runs the deterministic analysers only (no paid model call). Issuance is
stateless: the audit returns a ticket the server signs over the report hash, score and
source binding, so a browser cannot raise a score or swap a report before minting. The
contracts enforce the rest: only the approved validator can complete a validation, and
the credential contract refuses scores below its pass threshold.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..config import Settings
from .agent_resolver import audit_reference

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "deployments/demo-testnet.json"
LOCAL_KEY = ROOT / "data/demo-operator.json"
TICKET_TTL = 30 * 60
CREDENTIAL_DAYS = 90
EXPLORER = "https://stellar.expert/explorer/testnet"
NO_ENDPOINT = hashlib.sha256(b"agentveritas.demo.no-endpoint").digest()


class DemoAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=3, max_length=300)


class DemoCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(min_length=20, max_length=4000)


class DemoError(ValueError):
    """A request the demo refuses, with a message safe to show."""


def manifest() -> dict:
    return json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}


def _operator_secret() -> str:
    secret = os.environ.get("DEMO_OPERATOR_SECRET", "").strip()
    if not secret and LOCAL_KEY.exists():
        secret = json.loads(LOCAL_KEY.read_text()).get("secret", "")
    return secret


def issuance_enabled() -> bool:
    return bool(_operator_secret() and manifest().get("contracts", {}).get("credential"))


def _ticket_key() -> bytes:
    # Derived, never the signing key itself: a leaked ticket cannot sign transactions.
    return hmac.new(_operator_secret().encode(), b"agentveritas.demo.ticket.v1", hashlib.sha256).digest()


def _sign(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode()
    mac = hmac.new(_ticket_key(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _verify(ticket: str) -> dict:
    body, _, mac = ticket.rpartition(".")
    expected = hmac.new(_ticket_key(), body.encode(), hashlib.sha256).hexdigest()
    if not body or not hmac.compare_digest(mac, expected):
        raise DemoError("The issuance ticket is not valid. Run the audit again.")
    payload = json.loads(base64.urlsafe_b64decode(body.encode()))
    if payload.get("expires_at", 0) < time.time():
        raise DemoError("The issuance ticket expired. Run the audit again.")
    return payload


def _summary(finding: dict) -> dict:
    return {"id": finding["id"], "severity": finding["severity"], "kind": finding.get("kind", "risk"),
            "title": finding.get("title", ""), "evidence": (finding.get("evidence") or "")[:400],
            "remediation": (finding.get("remediation") or "")[:400]}


async def run_demo_audit(reference: str, settings: Settings) -> dict:
    result = await audit_reference(reference.strip(), settings, network="testnet", deep=False)
    report = result["report"]
    findings = report.get("findings", [])
    risks = [f for f in findings if f.get("kind", "risk") == "risk"]
    gaps = [f for f in findings if f.get("kind") == "evidence_gap"]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    risks.sort(key=lambda f: rank.get(f["severity"], 5))
    gaps.sort(key=lambda f: rank.get(f["severity"], 5))
    resolution = report.get("resolution", {})
    source = resolution.get("source", {})
    score = int(report["result"]["overall_score"])
    out = {
        "reference": reference, "decision": result["decision"], "score": score,
        "report_sha256": result["report_sha256"], "report_json": result["report_json"],
        "source": source, "kind": resolution.get("kind", ""),
        "steps": [{"check": s["check"], "result": s["result"], "evidence": (s.get("evidence") or "")[:300]}
                  for s in resolution.get("steps", [])],
        "risks": [_summary(f) for f in risks[:12]], "gaps": [_summary(f) for f in gaps[:12]],
        "counts": {"risks": len(risks), "gaps": len(gaps),
                   **{sev: sum(1 for f in risks if f["severity"] == sev) for sev in rank}},
        "files": (report.get("repository") or {}).get("source_files_selected", 0),
        "issuance": {"enabled": issuance_enabled(), "eligible": result["decision"] == "pass"},
    }
    repository = source.get("repository") or ""
    if repository and source.get("path"):
        repository = f"{repository}/tree/{source.get('revision', '')}/{source['path']}"
    if out["issuance"]["enabled"] and out["issuance"]["eligible"] and repository:
        out["issuance"]["ticket"] = _sign({
            "report_sha256": result["report_sha256"], "score": score, "repository": repository,
            "revision": source.get("revision", ""), "expires_at": int(time.time()) + TICKET_TTL})
    elif out["issuance"]["eligible"] and not repository:
        out["issuance"]["reason"] = "Only audits of a bound source repository can be credentialed."
    elif not out["issuance"]["eligible"]:
        out["issuance"]["reason"] = "Only a passing audit can be credentialed; the contract enforces score >= 65."
    return out


class _Chain:
    """Soroban calls signed by the demo operator (registry admin and sole validator)."""

    def __init__(self) -> None:
        from stellar_sdk import Keypair
        data = manifest()
        self.rpc, self.passphrase = data["rpc"], data["network_passphrase"]
        self.registry, self.credential = data["contracts"]["registry"]["id"], data["contracts"]["credential"]["id"]
        self.keypair = Keypair.from_secret(_operator_secret())
        self.transactions: list[dict] = []

    def call(self, contract: str, fn: str, args: list, *, write: bool = True):
        from stellar_sdk.contract import ContractClient
        client = ContractClient(contract, self.rpc, self.passphrase)
        tx = client.invoke(fn, args, source=self.keypair.public_key, signer=self.keypair, submit_timeout=60)
        if not write:
            return tx.result()
        value = tx.sign_and_submit()
        digest = tx.send_transaction_response.hash
        self.transactions.append({"function": fn, "hash": digest, "url": f"{EXPLORER}/tx/{digest}"})
        return value

    def read(self, contract: str, fn: str, args: list):
        try:
            return self.call(contract, fn, args, write=False)
        except Exception:  # noqa: BLE001 - a missing record simulates as a contract error
            return None


def _issue(ticket: dict) -> dict:
    from stellar_sdk import scval
    chain = _Chain()
    address = scval.to_address(chain.keypair.public_key)
    agent_id = hashlib.sha256(f"agentveritas.demo.agent:{ticket['repository'].lower()}".encode()).digest()
    meta_hash = hashlib.sha256(f"{ticket['repository']}@{ticket['revision']}".encode()).digest()
    report_hash = bytes.fromhex(ticket["report_sha256"])

    record = chain.read(chain.registry, "get_agent", [scval.to_bytes(agent_id)])
    agent = scval.to_native(record) if record is not None else None
    if agent is None:
        version = 1
        chain.call(chain.registry, "reg_agent", [address, scval.to_bytes(agent_id), scval.to_string(ticket["repository"]),
                                                  scval.to_bytes(meta_hash), scval.to_bytes(NO_ENDPOINT), scval.to_uint32(1)])
    elif bytes(agent["meta_hash"]) != meta_hash:
        version = int(agent["version"]) + 1
        chain.call(chain.registry, "upd_agent", [address, scval.to_bytes(agent_id), scval.to_string(ticket["repository"]),
                                                  scval.to_bytes(meta_hash), scval.to_bytes(NO_ENDPOINT), scval.to_uint32(version)])
    else:
        version = int(agent["version"])

    # One request per report and source version: issuing the same report twice returns
    # the credential that already exists.
    req_id = hashlib.sha256(f"agentveritas.demo.request:{ticket['report_sha256']}:{version}".encode()).digest()
    existing = chain.read(chain.credential, "get", [scval.to_bytes(req_id)])
    if existing is None:
        if chain.read(chain.registry, "get_valid", [scval.to_bytes(req_id)]) is None:
            chain.call(chain.registry, "req_valid", [address, scval.to_bytes(req_id), scval.to_bytes(agent_id), address])
        chain.call(chain.registry, "respond", [address, scval.to_bytes(req_id), scval.to_uint32(ticket["score"]),
                                               scval.to_string(f"urn:sha256:{ticket['report_sha256']}"),
                                               scval.to_bytes(report_hash)])
        expires = int(time.time()) + CREDENTIAL_DAYS * 86_400 - 3600
        chain.call(chain.credential, "issue", [scval.to_bytes(req_id), scval.to_uint64(expires)])
    credential = scval.to_native(chain.call(chain.credential, "get", [scval.to_bytes(req_id)], write=False))
    current = scval.to_native(chain.call(chain.credential, "is_current", [scval.to_bytes(req_id)], write=False))
    on_chain_hash = bytes(credential["report_hash"]).hex()
    return {
        "token_id": req_id.hex(), "agent_id": agent_id.hex(), "version": version,
        "contract": chain.credential, "contract_url": f"{EXPLORER}/contract/{chain.credential}",
        "registry": chain.registry, "issuer": chain.keypair.public_key,
        "score": int(credential["score"]), "report_sha256": on_chain_hash,
        "report_matches": on_chain_hash == ticket["report_sha256"], "is_current": bool(current),
        "expires_at": int(credential["expires_at"]), "transactions": chain.transactions,
        "already_issued": existing is not None,
    }


async def issue_demo_credential(ticket: str) -> dict:
    if not issuance_enabled():
        raise DemoError("Credential issuance is not configured on this deployment.")
    payload = _verify(ticket)
    return await asyncio.to_thread(_issue, payload)
