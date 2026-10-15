"""Official audit engagements: explicit scope, bounded depth and committed plans.

Prices describe the proposed product. A plan is not an invoice or payment proof.
All baseline source rules run so selecting a specialist cannot hide a known issue.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..reporting.generator import canonical_json
from .discovery import discover_project, source_digest
from .studio import ReviewRequest, review_source
from .runtime_audit import RuntimeRequest, run_runtime

ModuleID = Literal['intent', 'injection', 'tools', 'privacy', 'financial', 'resilience', 'stellar', 'provenance']
TierID = Literal['quick', 'standard', 'deep']
OPERATOR = {'id': 'veritas-official', 'name': 'Veritas Official', 'status': 'first_party',
            'description': 'One accountable platform team. Independent operators are a future phase.'}

_MODULES = [
    ('intent', 'Intent Analyst', 'Purpose, instruction conflicts and forbidden goals.', 'intent', ['source_rules', 'behavior_samples']),
    ('injection', 'Adversarial Examiner', 'Instruction override, retrieved-content injection and role confusion.', 'security', ['source_paths', 'behavior_samples']),
    ('tools', 'Authority Inspector', 'Dangerous sinks, tool permissions and delegation boundaries.', 'security', ['source_paths', 'behavior_samples']),
    ('privacy', 'Privacy Examiner', 'Embedded secrets, disclosure requests and data boundaries.', 'security', ['source_rules', 'behavior_samples']),
    ('financial', 'Treasury Inspector', 'Spending authority, recipient restrictions and economic risk signals.', 'economic', ['source_rules', 'behavior_samples']),
    ('resilience', 'Reliability Examiner', 'Failure handling, malformed input and bounded execution.', 'reliability', ['source_rules', 'behavior_samples']),
    ('stellar', 'Soroban Inspector', 'Contract authorization, storage lifetime and transaction boundaries.', 'stellar_native', ['source_rules']),
    ('provenance', 'Provenance Examiner', 'Source commitments, dependencies and release traceability.', 'provenance', ['source_rules', 'content_hashes']),
]
MODULES = [dict(id=id, name=name, description=description, dimension=dimension,
                methods=methods, default_selected=True, operator_id=OPERATOR['id'])
           for id, name, description, dimension, methods in _MODULES]
TIERS = [
    dict(id='quick', name='Preview', description='Source triage and an actionable evidence plan.',
         price=dict(amount='3', asset='USD', network='proposed', live=False, testnet_amount='0.1', testnet_asset='XLM'),
         budgets=dict(runtime_cases=0, ai_reviews=1), includes=['Baseline source rules', 'Selected specialist scope', 'Portable report']),
    dict(id='standard', name='Assurance', description='Source review with isolated behavior sampling.',
         price=dict(amount='19', asset='USD', network='proposed', live=False, testnet_amount='1', testnet_asset='XLM'),
         budgets=dict(runtime_cases=12, ai_reviews=1), includes=['Preview scope', 'Up to 12 isolated cases', 'Source-bound runtime evidence']),
    dict(id='deep', name='Deep', description='A broader adversarial case budget and capsule-specific scenarios.',
         price=dict(amount='49', asset='USD', network='proposed', live=False, testnet_amount='3', testnet_asset='XLM'),
         budgets=dict(runtime_cases=24, ai_reviews=1), includes=['Assurance scope', 'Up to 24 isolated cases', 'Capsule policy and scenario commitments']),
]


def catalogue(settings) -> dict:
    return {'schema': 'veritas.catalog/v1', 'operator': OPERATOR, 'modules': MODULES, 'tiers': TIERS,
            'checkout_enabled': False, 'network': 'testnet',
            'testnet_checkout_available': settings.stellar_network == 'testnet' and len(settings.runtime_api_key) >= 32 and len(settings.checkout_quote_signing_key) >= 32,
            'runtime_available': settings.enable_sandbox_runtime and len(settings.runtime_api_key) >= 32,
            'ai_available': settings.enable_public_ai_review and settings.llm_enabled,
            'price_note': 'Proposed USD prices; no live checkout. Testnet XLM has no monetary value.',
            'delivery': 'Download a report immediately. An onchain credential requires a completed official validation.',
            'independent_operators': 'planned'}


class EngagementRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source: ReviewRequest | None = None
    capsule: dict | None = None
    tier_id: TierID = 'quick'
    module_ids: list[ModuleID] = Field(default_factory=lambda: [m['id'] for m in MODULES], min_length=1, max_length=8)
    entrypoint: str = Field(default='', max_length=200)
    execution_consent: bool = False
    ai_assistance: bool = False
    external_processing_consent: bool = False
    plan_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def validate_selection(self):
        if (self.source is None) == (self.capsule is None):
            raise ValueError('Provide either source or a Veritas capsule.')
        if len(set(self.module_ids)) != len(self.module_ids):
            raise ValueError('Choose each official specialist once.')
        return self


def normalize(request: EngagementRequest):
    capsule, compiled = None, None
    source = request.source
    if request.capsule is not None:
        from .capsule import Capsule, compile_capsule, capsule_review_source
        capsule = Capsule.model_validate(request.capsule)
        compiled = compile_capsule(capsule)
        if capsule.audit.tier != request.tier_id or set(capsule.audit.modules) != set(request.module_ids):
            raise ValueError('Tier and specialists must match the capsule; export a revised capsule to change its committed scope.')
        source = capsule_review_source(capsule)
    assert source is not None
    if request.ai_assistance:
        source = source.model_copy(update={'ai_assistance': True,
            'external_processing_consent': request.external_processing_consent})
    return source, capsule, compiled


def build_plan(request: EngagementRequest, settings) -> dict:
    source, capsule, compiled = normalize(request)
    from .execution_contract import load_contract, workflow_cases, preflight, profile_digest
    execution = load_contract(source.files)
    discovery = discover_project(source.files)
    tier = next(t for t in TIERS if t['id'] == request.tier_id)
    modules = [m for m in MODULES if m['id'] in request.module_ids]
    entries = [e for e in discovery['entrypoints'] if e['adapter'] == 'python_text']
    entry = next((e for e in entries if e['id'] == request.entrypoint), None)
    if not request.entrypoint and len(entries) == 1:
        entry = entries[0]
    blockers = []
    if request.tier_id != 'quick':
        if not settings.enable_sandbox_runtime:
            blockers.append('Isolated execution is not enabled on this deployment.')
        if not entry:
            blockers.append('Select a supported Python text callable after source discovery.')
        if discovery['blueprint']['status'] == 'blocked':
            blockers.append('Resolve the blocked Blueprint before execution.')
        if compiled and compiled.get('status') == 'blocked':
            blockers.extend(compiled.get('blockers', []))
        from .capsule import module_cases
        planned_cases = compiled['cases'] if compiled else module_cases(source, tier=request.tier_id, modules=sorted(request.module_ids))
        if execution:
            planned_cases = workflow_cases(execution)
            blockers.extend(preflight(execution, capsule, settings))
            if any(w.model_reply is None for w in execution.workflows) and not source.external_processing_consent:
                blockers.append('Live model tools require explicit external processing consent.')
        elif capsule:
            environment = capsule.environment
            if environment.python_version not in {'3', '3.14'}:
                blockers.append('The native sandbox provides Python 3.14; declare a reviewed execution profile for another version.')
            if environment.dependencies or environment.required_environment_names:
                blockers.append('Dependencies or environment configuration require an explicit reviewed execution profile before payment.')
        if not planned_cases:
            blockers.append('These specialists have no Python behavior pack; choose Preview or include a behavior specialist.')
    else:
        planned_cases = []
    if source.ai_assistance and not (source.external_processing_consent and settings.enable_public_ai_review and settings.llm_enabled):
        blockers.append('AI review requires consent and a configured provider.')
    plan = {'schema': 'veritas.engagement-plan/v1', 'operator': OPERATOR, 'tier': tier,
            'modules': modules, 'price': tier['price'], 'budgets': tier['budgets'],
            'source_sha256': source_digest(source.files),
            'request_sha256': sha256(canonical_json(source.model_dump(mode='json')).encode()).hexdigest(),
            'capsule_plan_sha256': compiled.get('plan_sha256') if compiled else None,
            'blueprint_plan_sha256': discovery['blueprint'].get('plan_sha256'),
            'entrypoint': entry, 'blockers': blockers,
            'planned_runtime_cases': len(planned_cases),
            'runtime_cases_sha256': sha256(canonical_json(planned_cases).encode()).hexdigest(),
            'ai_generated_cases_max': max(0, tier['budgets']['runtime_cases'] - len(planned_cases)) if source.ai_assistance else 0,
            'case_commitment_note': 'This digest commits planned operator and declared cases. Any opt-in AI additions are separately committed with all issued cases in the runtime report.',
            'runtime_image': settings.sandbox_image if request.tier_id != 'quick' else None,
            'ai_processor': {'provider': settings.llm_provider, 'model': settings.llm_model,
                'max_output_tokens': settings.llm_max_output_tokens} if source.ai_assistance else None,
            'optional_evidence': ['Soroban authorization XDR policy inspection is a separate explicit Studio tool.'],
            'coverage': {'baseline_source_dimensions': 7, 'selected_specialists': len(modules),
                'execution': 'none' if request.tier_id == 'quick' else 'python_text_microvm',
                'production_integrations': False, 'independent_reviewers': False,
                'note': 'Every baseline source rule runs. Selection sets the specialist focus and runtime case families.'},
            'required_evidence': ['Exact source revision', 'Actual production tool traces', 'Deployment/source binding',
                                  'Human review of consequential findings'],
            'payment': {'state': 'not_requested', 'checkout_enabled': False},
            'limits': ['A larger case budget increases sampled coverage; it does not establish complete security.',
                       'Tool, memory and live model integrations require separate instrumented adapters.']}
    if execution and request.tier_id != 'quick':
        plan['execution_profile'] = {'id': execution.profile, 'sha256': profile_digest(),
            'mode': 'brokered_workflows', 'network': 'Testnet tools through external broker',
            'native_clients_tested': False, 'bindings': [b.model_dump() for b in execution.bindings]}
        plan['ai_generated_cases_max'] = 0
        plan['coverage']['execution'] = 'brokered_python_microvm'
        plan['limits'].append('Declared client classes are substituted; native transport implementations need separate validation.')
    return {'plan': plan, 'plan_sha256': sha256(canonical_json(plan).encode()).hexdigest()}


async def audit_engagement(request: EngagementRequest, settings, *, runtime_runner=None) -> dict:
    planned = build_plan(request, settings)
    plan = planned['plan']
    if plan['blockers']:
        raise ValueError(' '.join(str(b) for b in plan['blockers']))
    if request.plan_sha256 != planned['plan_sha256']:
        raise ValueError('Review and acknowledge the current audit plan before starting.')
    source, capsule, compiled = normalize(request)
    if request.tier_id != 'quick' and not request.execution_consent:
        raise ValueError('Explicit isolated execution consent is required for this tier.')
    result = await review_source(source, settings)
    payload = deepcopy(result['report'])
    runtime = None
    if request.tier_id != 'quick':
        options = {'audit_tier': request.tier_id, 'modules': sorted(request.module_ids)}
        if capsule:
            from .capsule import capsule_runtime_options
            options.update(capsule_runtime_options(capsule))
        runtime_request = RuntimeRequest(source=source, entrypoint=plan['entrypoint']['id'],
            execution_consent=True, plan_sha256=plan['blueprint_plan_sha256'], **options)
        runtime = await (runtime_runner or run_runtime)(runtime_request, settings)
    observations = runtime['report']['observations'] if runtime else []
    observed_statuses = {'observed', 'needs_investigation'}
    sampled = [o for o in observations if o.get('status') in observed_statuses]
    module_results = []
    for module in plan['modules']:
        findings = [f['id'] for f in payload['findings'] if f['dimension'] == module['dimension']]
        related = [o['id'] for o in observations if o.get('module') == module['id']]
        module_sampled = any(o.get('module') == module['id'] for o in sampled)
        module_results.append({'id': module['id'], 'operator_id': OPERATOR['id'],
            'source_review': 'completed', 'finding_ids': findings, 'runtime_observation_ids': related,
            'runtime': 'sampled' if module_sampled else ('inconclusive' if related else 'not_exercised'), 'security_verified': False})
    payload['engagement'] = {'plan': plan, 'plan_sha256': planned['plan_sha256'],
        'module_results': module_results, 'runtime': {'report': runtime['report'],
            'report_sha256': runtime.get('report_sha256')} if runtime else None,
        'capsule': {'sha256': compiled.get('capsule_sha256'), 'policy_sha256': compiled.get('policy_sha256')}
                   if compiled else None,
        'delivery': {'status': 'not_issued', 'type': 'nontransferable_audit_credential',
            'note': 'The report is available now. A downloaded card is not an issued token.'}}
    payload['review_scope']['runtime_attempted'] = bool(runtime)
    payload['review_scope']['runtime_executed'] = bool(sampled)
    payload['review_scope']['analysis'] = ('source rules and isolated behavior sampling' if sampled
        else 'source rules; isolated behavior attempt inconclusive' if runtime else 'source rules')
    payload['review_scope']['limits'] = [l for l in payload['review_scope']['limits']
        if not (runtime and l == 'Source review does not execute the agent or establish production safety.')]
    if runtime:
        payload['review_scope']['limits'].extend(runtime['report']['limits'])
        payload['judge_notes'][0] = 'Source assessment with separately committed isolated runtime observations.'
        if not sampled:
            payload['review_scope']['limits'].append('No successful agent response was observed; inspect blocked, timeout and error outcomes.')
    encoded = canonical_json(payload)
    return {**result, 'mode': 'official_audit', 'report': payload, 'report_json': encoded,
            'scope': payload['review_scope'], 'report_sha256': sha256(encoded.encode()).hexdigest()}
