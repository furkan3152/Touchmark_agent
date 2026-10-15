"""Portable report artifacts and read-only verification of official credentials."""
from __future__ import annotations

import asyncio
from hashlib import sha256
from html import escape
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..reporting.generator import canonical_json
from ..stellar.identity import is_valid_stellar_address

ROOT = Path(__file__).resolve().parents[3]
PILOT_PATH = ROOT / 'deployments/testnet-audit-delivery-2026-10-15.json'


class CredentialReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    contract_id: str = Field(pattern=r'^C[A-Z2-7]{55}$')
    token_id: str = Field(pattern=r'^[a-f0-9]{64}$')
    owner: str = Field(min_length=56, max_length=56)

    @field_validator('contract_id', 'owner')
    @classmethod
    def valid_address(cls, value):
        if not is_valid_stellar_address(value):
            raise ValueError('Provide a valid public Stellar address.')
        return value


class DeliveryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    report_json: str = Field(min_length=2, max_length=500_000)
    report_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    credential: CredentialReference | None = None


def pilot_evidence() -> dict:
    if not PILOT_PATH.exists():
        return {'available': False, 'note': 'A current end-to-end Testnet receipt has not been published.'}
    evidence = json.loads(PILOT_PATH.read_text())
    return {'available': True, 'evidence': evidence,
            'report_url': evidence.get('report', {}).get('uri', ''),
            'note': 'Protocol proof using the published fixture. This is not a credential for your uploaded agent.'}


def _official_contracts() -> dict[str, str]:
    allowed = {}
    for path in [PILOT_PATH, ROOT / 'deployments/testnet-pilot-2026-10-15.json']:
        if not path.exists():
            continue
        evidence = json.loads(path.read_text())
        contract = evidence.get('contracts', {}).get('credential', {}).get('id')
        source = evidence.get('roles', {}).get('requester') or evidence.get('admin')
        if contract and source:
            allowed[contract] = source
    return allowed


def _read_credential(ref: CredentialReference, source: str) -> tuple[dict, bool, int]:
    from stellar_sdk import Network, scval
    from stellar_sdk.contract import ContractClient
    from stellar_sdk.client.requests_client import RequestsClient
    client = RequestsClient(num_retries=0, request_timeout=10, post_timeout=10)
    try:
        contract = ContractClient(ref.contract_id, 'https://soroban-rpc.testnet.stellar.gateway.fm',
                                  Network.TESTNET_NETWORK_PASSPHRASE, request_client=client)
        token = scval.to_bytes(bytes.fromhex(ref.token_id))
        record = scval.to_native(contract.invoke('get', [token], source=source).result())
        current_tx = contract.invoke('is_current', [token], source=source)
        current = scval.from_bool(current_tx.result())
        ledger = current_tx.simulation.latest_ledger
        return record, current, ledger
    finally:
        client.close()


async def verify_credential(ref: CredentialReference, report_hash: str, *, reader=None) -> dict:
    source = _official_contracts().get(ref.contract_id)
    if not source:
        return {'status': 'invalid', 'reason': 'This contract is not an official Testnet credential deployment.'}
    try:
        record, current, ledger = await asyncio.wait_for(asyncio.to_thread(reader or _read_credential, ref, source), 45)
        owner = record['owner'].address if hasattr(record['owner'], 'address') else str(record['owner'])
        committed_hash = record['report_hash'].hex()
        match = owner == ref.owner and committed_hash == report_hash
        return {'status': 'current' if match and current else 'invalid', 'network': 'testnet',
                'contract_id': ref.contract_id, 'token_id': ref.token_id, 'owner': owner,
                'report_hash_matches': committed_hash == report_hash, 'owner_matches': owner == ref.owner,
                'is_current': bool(current), 'checked_at_ledger': ledger, 'read_method': 'rpc_simulate_readonly',
                'note': 'Current issuer assertion for this report; not a guarantee that the agent is secure.'}
    except Exception:
        return {'status': 'unavailable', 'reason': 'The official credential could not be read from Testnet. No issuance is claimed.'}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate report keys are not accepted.')
        result[key] = value
    return result


def decode_report(request: DeliveryRequest) -> dict:
    if sha256(request.report_json.encode()).hexdigest() != request.report_sha256:
        raise ValueError('Report bytes do not match the supplied commitment.')
    try:
        report = json.loads(request.report_json, object_pairs_hook=_unique_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite report number.')))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Provide the downloaded canonical report JSON.') from exc
    if not isinstance(report, dict) or canonical_json(report) != request.report_json:
        raise ValueError('Provide the original canonical report; reformatted JSON has a different commitment.')
    if not isinstance(report.get('agent'), dict) or not isinstance(report.get('findings'), list):
        raise ValueError('An AgentVeritas source audit report is required.')
    if len(report['findings']) > 500 or any(not isinstance(f, dict) for f in report['findings']):
        raise ValueError('Invalid report finding inventory.')
    if not isinstance(report.get('engagement', {}), dict) or not isinstance(report.get('review_scope', {}), dict):
        raise ValueError('Invalid report scope.')
    decision = report.get('review_decision', 'needs_evidence')
    if not isinstance(decision, str) or decision not in {'needs_evidence', 'needs_fixes'}:
        raise ValueError('Unknown review decision; this report cannot assert safety approval.')
    ai = report.get('ai_review', {})
    if (not isinstance(ai, dict) or not isinstance(ai.get('observations', []), list)
            or not isinstance(ai.get('status', 'not_requested'), str)):
        raise ValueError('Invalid AI observation inventory.')
    runtime = report.get('engagement', {}).get('runtime')
    if runtime is not None and (not isinstance(runtime, dict) or not isinstance(runtime.get('report'), dict)
            or not isinstance(runtime['report'].get('observations', []), list)):
        raise ValueError('Invalid runtime observation inventory.')
    return report


def render_artifacts(report: dict, digest: str, proof: dict) -> dict:
    e = lambda value: escape(str(value), quote=True)
    name = str(report['agent'].get('name', 'Agent'))[:100]
    current = proof['status'] == 'current'
    label = f"TESTNET RECORD • VERIFIED AT LEDGER {proof.get('checked_at_ledger', 'unknown')}" if current else 'REPORT COPY • ORIGIN UNVERIFIED'
    engagement = report.get('engagement', {})
    plan = engagement.get('plan', {}) if isinstance(engagement.get('plan', {}), dict) else {}
    tier = plan.get('tier', {}).get('name', 'Source review') if isinstance(plan.get('tier', {}), dict) else 'Source review'
    findings = report['findings']
    rows = ''.join(f'<article class="finding"><div class="severity">{e(f.get("severity", "info"))} · {e(f.get("evidence_grade", "unclassified"))}</div><h3>{e(f.get("title", f.get("id", "Finding")))}</h3><p>{e(f.get("detail", f.get("description", "")))}</p><pre>{e(f.get("evidence", ""))}</pre><p class="fix">{e(f.get("remediation", ""))}</p></article>' for f in findings)
    scope = report.get('review_scope', {})
    limits = scope.get('limits', []) if isinstance(scope.get('limits', []), list) else []
    runtime = engagement.get('runtime')
    runtime_report = runtime.get('report', {}) if isinstance(runtime, dict) else {}
    observations = runtime_report.get('observations', []) if isinstance(runtime_report, dict) else []
    cases = ''.join(f'<tr><td>{e(o.get("id", ""))}</td><td>{e(o.get("status", ""))}</td><td>{e(o.get("response", ""))}</td></tr>' for o in observations if isinstance(o, dict))
    limits_html = ''.join(f'<li>{e(item)}</li>' for item in limits[:30])
    ai = report.get('ai_review', {})
    ai = ai if isinstance(ai, dict) else {}
    ai_rows = ''.join(f'<article class="finding"><div class="severity">AI hypothesis · {e(o.get("file", ""))}:{e(o.get("line", ""))}</div><h3>{e(o.get("title", ""))}</h3><p>{e(o.get("risk", ""))}</p><p class="fix">{e(o.get("remediation", ""))}</p></article>' for o in ai.get('observations', []) if isinstance(o, dict))
    issuer_label = 'Veritas Official' if current else 'Unverified report copy'
    symbol = 'm985 180 30 30 60-70' if current else 'M995 155H1065M995 180H1065M995 205H1040'
    proof_text = canonical_json(proof)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="760" viewBox="0 0 1200 760"><defs><linearGradient id="g" x2="1" y2="1"><stop stop-color="#fafbf8"/><stop offset="1" stop-color="#e0e9e2"/></linearGradient></defs><rect width="1200" height="760" rx="40" fill="url(#g)"/><circle cx="1030" cy="180" r="95" fill="none" stroke="#1b4030" stroke-width="2"/><circle cx="1030" cy="180" r="65" fill="none" stroke="#1b4030"/><path d="{symbol}" fill="none" stroke="#1b4030" stroke-width="8"/><g font-family="Arial,sans-serif" fill="#1b2922"><text x="65" y="95" font-size="26" letter-spacing="5">VERITAS / EVIDENCE</text><text x="65" y="215" font-size="15" letter-spacing="2">{label}</text><text x="65" y="300" font-size="44">{e(name[:38])}</text><text x="65" y="360" font-size="23">{e(tier)} · {len(findings)} findings · {len(observations)} runtime observations</text><text x="65" y="445" font-size="19">A record of scope, findings and evidence.</text><text x="65" y="478" font-size="19">Security is evaluated within the published test boundaries.</text><path d="M65 545H1135" stroke="#b5c4b9"/><text x="65" y="590" font-size="14" letter-spacing="2">REPORT SHA-256</text><text x="65" y="625" font-size="17" font-family="monospace">{digest}</text><text x="65" y="705" font-size="15">{e(issuer_label)} • {e(proof['status'])} • Non-transferable audit record</text></g></svg>'''
    html = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><title>{e(name)} — Veritas audit report</title><style>*{{box-sizing:border-box}}body{{margin:0;background:#f5f6f3;color:#1c2720;font:16px/1.65 -apple-system,BlinkMacSystemFont,Arial,sans-serif}}main{{max-width:1000px;margin:auto;padding:64px 40px}}header{{border-bottom:1px solid #cbd3cb;padding-bottom:44px}}.brand,.severity{{text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:700}}h1{{font-size:54px;line-height:1.1;letter-spacing:-.045em;margin:35px 0 20px}}h2{{font-size:28px;margin-top:48px}}h3{{line-height:1.35}}.muted{{color:#667167}}.metrics{{display:flex;gap:40px;margin:30px 0}}.metrics strong{{display:block;font-size:32px}}.finding{{padding:26px 0;border-top:1px solid #d5ddd5;break-inside:avoid}}pre{{font:12px/1.6 monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#e9ede7;padding:16px}}.fix{{border-left:3px solid #53735b;padding-left:15px}}.hash{{font:12px/1.6 monospace;overflow-wrap:anywhere}}table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #d5ddd5;vertical-align:top;overflow-wrap:anywhere}}td:last-child{{white-space:pre-wrap}}footer{{margin-top:50px;border-top:1px solid #cbd3cb;padding-top:24px}}@media print{{body{{background:white}}main{{padding:0}}h1{{font-size:40px}}h2{{break-after:avoid}}}}@page{{margin:18mm}}</style><main><header><div class="brand">Veritas / Report viewer</div><h1>{e(name)}</h1><p>{e(tier)} · {e(report.get('review_decision','needs_evidence').replace('_',' '))}</p><p class="muted">{label}</p><div class="metrics"><div><strong>{len(findings)}</strong>source findings</div><div><strong>{len(observations)}</strong>runtime observations</div><div><strong>{e(ai.get('status','not_requested').replace('_',' '))}</strong>AI review</div></div><div class="hash">SHA-256 {digest}</div></header><h2>Scope and evidence</h2><p>{e(scope.get('analysis','Source review'))}. Origin: {e(issuer_label)}.</p><ul>{limits_html}</ul><h2>Findings and remediation</h2>{rows or '<p>No source finding was recorded. This does not establish safety.</p>'}<h2>Runtime observations</h2>{('<table><thead><tr><th>Case</th><th>Outcome</th><th>Observed response</th></tr></thead><tbody>'+cases+'</tbody></table>') if cases else '<p>No runtime execution is included in this report.</p>'}<h2>AI second opinion</h2>{ai_rows or '<p>No AI observation is included.</p>'}<h2>Credential verification</h2><pre>{e(proof_text)}</pre><footer><p>The canonical JSON carries the report commitment. This HTML and the visual card are renderings; a downloaded image does not issue an NFT.</p><p class="muted">A content hash checks integrity. Official origin requires a verified issuer credential.</p></footer></main></html>'''
    metadata = {'name': f'Veritas audit — {name}', 'description': 'Non-transferable record of an audit scope and report, not a safety guarantee.',
                'schema': 'veritas.credential-metadata/v1', 'origin_verified': current, 'report_sha256': digest, 'issuance_status': proof['status'],
                'network': 'testnet' if current else None, 'credential': proof if current else None,
                'attributes': [{'trait_type': 'Audit tier', 'value': tier},
                               {'trait_type': 'Source findings', 'value': len(findings)},
                               {'trait_type': 'Runtime observations', 'value': len(observations)}],
                'artifacts': {'html_sha256': sha256(html.encode()).hexdigest(), 'svg_sha256': sha256(svg.encode()).hexdigest()}}
    return {'html': html, 'svg': svg, 'metadata': metadata}


async def deliver_report(request: DeliveryRequest, *, verifier=None) -> dict:
    report = decode_report(request)
    proof = {'status': 'not_issued', 'note': 'No onchain credential was supplied. Downloading this report does not mint a token.'}
    if request.credential:
        proof = await (verifier or verify_credential)(request.credential, request.report_sha256)
    return {'status': proof['status'], 'report_sha256': request.report_sha256, 'proof': proof,
            'artifacts': render_artifacts(report, request.report_sha256, proof)}
