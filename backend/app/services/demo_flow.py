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
#: The model review and verification stop by then, inside the 300 s function limit (vercel.json).
DEMO_DEADLINE_SECONDS = 250.0
CREDENTIAL_DAYS = 90
EXPLORER = "https://stellar.expert/explorer/testnet"
NO_ENDPOINT = hashlib.sha256(b"agentveritas.demo.no-endpoint").digest()


class DemoAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=3, max_length=300)


class DemoCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(min_length=20, max_length=4000)
    #: The owner's signed registration (from /credential/prepare) when the repository names an owner.
    signed_xdr: str = Field(default="", max_length=20_000)


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
    out = {"id": finding["id"], "severity": finding["severity"], "kind": finding.get("kind", "risk"),
           "title": finding.get("title", ""), "evidence": (finding.get("evidence") or "")[:400],
           "remediation": (finding.get("remediation") or "")[:400]}
    if finding.get("auditor") == "deep-review":
        out["source"] = "ai_review"
    if (finding.get("verification") or {}).get("verdict"):
        v = finding["verification"]
        out["verification"] = {"verdict": v["verdict"], "reason": (v.get("reason") or "")[:300]}
    return out


def _ai_summary(report: dict, ai: bool, settings: Settings) -> dict:
    """What the model review and the verifier did, so a reader knows which checks ran."""
    review = report.get("deep_review") or {}
    if not review:
        if not report.get("repository"):
            return {"review": "no_source"}
        configured = bool(settings.enable_deep_review and settings.anthropic_api_key)
        return {"review": "rate_limited" if configured and not ai else "off"}
    verification = report.get("verification") or {}
    coverage = review.get("coverage") or {}
    return {"review": review.get("status", "not_run"), "note": review.get("note", ""),
            "findings_added": len(review.get("accepted_findings") or []),
            "files_read": len(coverage.get("files_read") or []), "files_total": coverage.get("files_total", 0),
            "verification": {k: verification[k] for k in ("checked", "confirmed", "partial", "refuted",
                                                         "unverifiable", "agreement") if k in verification}}


async def run_demo_audit(reference: str, settings: Settings, *, ai: bool = True) -> dict:
    """``ai`` allows the model review and verification when they are configured; the
    deterministic analysis always runs. Both stop by DEMO_DEADLINE_SECONDS."""
    deadline = time.monotonic() + DEMO_DEADLINE_SECONDS
    result = await audit_reference(reference.strip(), settings, network="testnet", deep=ai, deadline=deadline)
    report = result["report"]
    findings = report.get("findings", [])
    risks = [f for f in findings if f.get("kind", "risk") == "risk"]
    gaps = [f for f in findings if f.get("kind") == "evidence_gap"]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    risks.sort(key=lambda f: rank.get(f["severity"], 5))
    gaps.sort(key=lambda f: rank.get(f["severity"], 5))
    resolution = report.get("resolution", {})
    source = resolution.get("source", {})
    score = round(float(report["result"]["overall_score"]), 1)
    chain_score = int(score)  # the registry stores whole points (u32); never rounded up
    out = {
        "reference": reference, "decision": result["decision"], "score": score,
        "report_sha256": result["report_sha256"], "report_json": result["report_json"],
        "source": source, "kind": resolution.get("kind", ""),
        "steps": [{"check": s["check"], "result": s["result"], "evidence": (s.get("evidence") or "")[:300]}
                  for s in resolution.get("steps", [])],
        "risks": [_summary(f) for f in risks[:40]], "gaps": [_summary(f) for f in gaps[:20]],
        "breakdown": {k: v for k, v in (report["result"].get("score_breakdown") or {}).items() if k != "deductions"}
                     | {"deductions": [{key: d.get(key) for key in ("id", "title", "severity", "evidence_grade",
                                                                     "confidence", "places", "deduction", "restates")}
                                       for d in (report["result"].get("score_breakdown") or {}).get("deductions", [])[:15]]},
        "counts": {"risks": len(risks), "gaps": len(gaps),
                   **{sev: sum(1 for f in risks if f["severity"] == sev) for sev in rank}},
        "files": (report.get("repository") or {}).get("source_files_selected", 0),
        "ownership": (report.get("repository") or {}).get("ownership_claim") or {},
        "tmark": ((report.get("repository") or {}).get("declarations") or {}).get("tmark") or {"status": "missing"},
        "issuance": {"enabled": issuance_enabled(), "eligible": result["decision"] == "pass"},
        "ai": _ai_summary(report, ai, settings),
    }
    repository = source.get("repository") or ""
    if repository and source.get("path"):
        repository = f"{repository}/tree/{source.get('revision', '')}/{source['path']}"
    if out["issuance"]["enabled"] and out["issuance"]["eligible"] and repository:
        owner = out["ownership"].get("stellar_owner", "")
        out["issuance"]["owner"] = owner
        out["issuance"]["ticket"] = _sign({
            "report_sha256": result["report_sha256"], "score": chain_score, "repository": repository,
            "revision": source.get("revision", ""), "owner": owner, "expires_at": int(time.time()) + TICKET_TTL})
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


def _agent_keys(ticket: dict, operator: str) -> tuple[bytes, bytes, str]:
    """Agent id, metadata hash and owner. With an owner claim the agent id includes the
    owner, so an owned registration never collides with an operator-held one."""
    owner = ticket.get("owner") or operator
    seed = f"agentveritas.demo.agent:{ticket['repository'].lower()}" + (f":{owner}" if ticket.get("owner") else "")
    return (hashlib.sha256(seed.encode()).digest(),
            hashlib.sha256(f"{ticket['repository']}@{ticket['revision']}".encode()).digest(), owner)


def _registration(chain: "_Chain", ticket: dict) -> tuple[str, int, list]:
    """What the registry needs before validation: ("none" | "reg_agent" | "upd_agent"), version, args."""
    from stellar_sdk import scval
    agent_id, meta_hash, owner = _agent_keys(ticket, chain.keypair.public_key)
    record = chain.read(chain.registry, "get_agent", [scval.to_bytes(agent_id)])
    agent = scval.to_native(record) if record is not None else None
    if agent is not None and bytes(agent["meta_hash"]) == meta_hash:
        return "none", int(agent["version"]), []
    fn, version = ("reg_agent", 1) if agent is None else ("upd_agent", int(agent["version"]) + 1)
    return fn, version, [scval.to_address(owner), scval.to_bytes(agent_id), scval.to_string(ticket["repository"]),
                         scval.to_bytes(meta_hash), scval.to_bytes(NO_ENDPOINT), scval.to_uint32(version)]


def _prepare(ticket: dict) -> dict:
    """The registration the owner signs in their wallet (owner.require_auth in the registry)."""
    from stellar_sdk import SorobanServer, TransactionBuilder
    chain = _Chain()
    fn, version, args = _registration(chain, ticket)
    if fn == "none":
        return {"signature_needed": False, "owner": ticket["owner"], "version": version}
    server = SorobanServer(chain.rpc)
    try:
        account = server.load_account(ticket["owner"])
    except Exception as exc:  # noqa: BLE001 - an unfunded testnet account
        raise DemoError("Fund the owner account on testnet first (Freighter can use Friendbot).") from exc
    tx = (TransactionBuilder(account, chain.passphrase, base_fee=1000)
          .append_invoke_contract_function_op(contract_id=chain.registry, function_name=fn, parameters=args)
          .set_timeout(300).build())
    tx = server.prepare_transaction(tx)
    return {"signature_needed": True, "owner": ticket["owner"], "function": fn, "version": version,
            "unsigned_xdr": tx.to_xdr(), "network_passphrase": chain.passphrase}


def _check_owner_signature(chain: "_Chain", ticket: dict, signed_xdr: str) -> str:
    """Accept only the owner's own registration of this agent, signed by the owner. Returns the hash."""
    from stellar_sdk import Address, Keypair, TransactionEnvelope
    fn, _, args = _registration(chain, ticket)
    try:
        envelope = TransactionEnvelope.from_xdr(signed_xdr, chain.passphrase)
    except Exception as exc:  # noqa: BLE001
        raise DemoError("The signed transaction could not be read.") from exc
    tx = envelope.transaction
    ops = tx.operations
    if tx.source.account_id != ticket["owner"] or len(ops) != 1:
        raise DemoError("The transaction must come from the owner account and contain one operation.")
    host = getattr(ops[0], "host_function", None)
    invoke = getattr(host, "invoke_contract", None)
    if invoke is None or Address.from_xdr_sc_address(invoke.contract_address).address != chain.registry:
        raise DemoError("The transaction must call the AgentVeritas registry.")
    name = invoke.function_name.sc_symbol.decode()
    if name != fn or [a.to_xdr() for a in invoke.args] != [a.to_xdr() for a in args]:
        raise DemoError("The transaction does not register this agent with the audited source.")
    owner = Keypair.from_public_key(ticket["owner"])
    digest = envelope.hash()
    for sig in envelope.signatures:
        try:
            owner.verify(digest, sig.signature)
            return envelope.hash_hex()
        except Exception:  # noqa: BLE001 - try the next signature
            continue
    raise DemoError("The owner account did not sign this transaction.")


def _submit_owner_registration(chain: "_Chain", ticket: dict, signed_xdr: str) -> None:
    from stellar_sdk import SorobanServer
    from stellar_sdk.soroban_rpc import GetTransactionStatus, SendTransactionStatus
    digest = _check_owner_signature(chain, ticket, signed_xdr)
    server = SorobanServer(chain.rpc)
    sent = server.send_transaction(signed_xdr)
    if sent.status not in (SendTransactionStatus.PENDING, SendTransactionStatus.DUPLICATE):
        raise DemoError(f"The network rejected the owner's registration ({sent.status.value}).")
    for _ in range(30):
        result = server.get_transaction(digest)
        if result.status == GetTransactionStatus.SUCCESS:
            chain.transactions.append({"function": "owner registration", "hash": digest, "url": f"{EXPLORER}/tx/{digest}"})
            return
        if result.status == GetTransactionStatus.FAILED:
            raise DemoError("The owner's registration failed on chain.")
        time.sleep(2)
    raise DemoError("The owner's registration was not confirmed in time.")


def _issue(ticket: dict, signed_xdr: str = "") -> dict:
    from stellar_sdk import scval
    chain = _Chain()
    address = scval.to_address(chain.keypair.public_key)
    agent_id, _, owner = _agent_keys(ticket, chain.keypair.public_key)
    report_hash = bytes.fromhex(ticket["report_sha256"])
    fn, version, args = _registration(chain, ticket)
    if fn != "none" and ticket.get("owner"):
        if not signed_xdr:
            raise DemoError("The repository names an owner: sign the registration in your wallet first.")
        _submit_owner_registration(chain, ticket, signed_xdr)
    elif fn != "none":
        chain.call(chain.registry, fn, args)

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
    chain_owner = getattr(credential["owner"], "address", None) or str(credential["owner"])
    return {
        "token_id": req_id.hex(), "agent_id": agent_id.hex(), "version": version,
        "contract": chain.credential, "contract_url": f"{EXPLORER}/contract/{chain.credential}",
        "registry": chain.registry, "issuer": chain.keypair.public_key,
        "owner": chain_owner, "owner_verified": bool(ticket.get("owner")) and chain_owner == owner,
        "score": int(credential["score"]), "report_sha256": on_chain_hash,
        "report_matches": on_chain_hash == ticket["report_sha256"], "is_current": bool(current),
        "expires_at": int(credential["expires_at"]), "transactions": chain.transactions,
        "already_issued": existing is not None,
    }


async def issue_demo_credential(ticket: str, signed_xdr: str = "") -> dict:
    if not issuance_enabled():
        raise DemoError("Credential issuance is not configured on this deployment.")
    payload = _verify(ticket)
    return await asyncio.to_thread(_issue, payload, signed_xdr)


async def prepare_owner_registration(ticket: str) -> dict:
    if not issuance_enabled():
        raise DemoError("Credential issuance is not configured on this deployment.")
    payload = _verify(ticket)
    if not payload.get("owner"):
        raise DemoError("The repository names no owner; the credential is issued to the demo operator.")
    return await asyncio.to_thread(_prepare, payload)
