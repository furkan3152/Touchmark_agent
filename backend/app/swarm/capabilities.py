"""Reconcile what an agent declares with what its source can actually do.

Every auditor reads `artifact.tools`. Before this module, those were only the
submitter's declarations, so declaring a signing agent "read only" removed every
financial rule. The orchestrator now audits an *effective* artifact:

* capabilities found in source but not granted by any declared tool are added as
  tools with origin="observed";
* a declared spend limit is kept only when the source bounds payment amounts.

The submitted artifact (and its input commitment) is never modified.
"""

from __future__ import annotations

from ..models import AgentArtifact, ToolSpec
from .codeflow import CodeProfile, analyse_code

_IMPLEMENTATION = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")
_SIGNING_SCOPE_WORDS = ("sign", "wallet", "transfer", "spend", "payment", "account")
_EXEC_WORDS = ("shell", "exec", "bash", "eval", "python", "run_code", "subprocess")
#: Capabilities that exercise authority. Building an unsigned operation (payment or
#: account_control alone) drafts a transaction for someone else to sign; it is not authority.
FINANCIAL_CAPABILITIES = ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation")
OVERSIGHT_WORDS = ("human", "confirm", "approval", "escalate", "operator", "onay")


def _signing(tool: ToolSpec) -> bool:
    return tool.requires_signature or any(w in scope.lower() for scope in tool.scopes for w in _SIGNING_SCOPE_WORDS)


def _executes(tool: ToolSpec) -> bool:
    text = (tool.name + " " + " ".join(tool.scopes)).lower()
    return any(w in text for w in _EXEC_WORDS)


def has_source(artifact: AgentArtifact) -> bool:
    return any(name.lower().endswith(_IMPLEMENTATION) for name in artifact.code_files)


def declared_entrypoints(artifact: AgentArtifact) -> dict[str, set[str]]:
    """Entry functions the repository names, in .tmark or a legacy veritas.json Blueprint."""
    entrypoints: dict[str, set[str]] = {}
    for item in (artifact.raw_metadata.get("tmark") or {}).get("entrypoints", []):
        entrypoints.setdefault(item["path"], set()).add(item["symbol"])
    if "veritas.json" in artifact.code_files:
        from ..services.blueprint import parse_blueprint
        try:
            blueprint = parse_blueprint(artifact.code_files["veritas.json"])
            component = next(c for c in blueprint.components if c.id == blueprint.entrypoint.component)
            entrypoints.setdefault(component.path, set()).add(blueprint.entrypoint.symbol)
        except (ValueError, StopIteration):
            pass  # an invalid declaration is reported by discovery; source is never imported
    return entrypoints


def profile_for(artifact: AgentArtifact) -> CodeProfile:
    return analyse_code(artifact.code_files, declared_entrypoints(artifact))


def _where(profile: CodeProfile, *capabilities: str) -> str:
    locations = [loc.render() for cap in capabilities for loc in profile.capabilities.get(cap, [])[:2]]
    return "; ".join(locations[:4])


def effective_artifact(artifact: AgentArtifact) -> AgentArtifact:
    """Return the artifact auditors should judge: declarations reconciled with source."""
    if not has_source(artifact):
        return artifact
    profile = profile_for(artifact)
    tools = [tool.model_copy() for tool in artifact.tools]
    declared = [tool for tool in tools if tool.origin == "declared"]
    added: list[ToolSpec] = []

    financial = [cap for cap in FINANCIAL_CAPABILITIES if profile.has(cap)]
    if financial and not any(_signing(t) for t in declared):
        scopes = ["sign:tx"]
        if profile.has("payment") or profile.has("contract_invocation"):
            scopes.append("transfer")
        if profile.has("account_control"):
            scopes.append("account:admin")
        added.append(ToolSpec(name="observed:stellar_signing", origin="observed", requires_signature=True,
                              scopes=scopes, description="Observed in source: " + _where(profile, *financial)))
    if profile.has("code_execution") and not any(_executes(t) for t in declared):
        added.append(ToolSpec(name="observed:code_execution", origin="observed", scopes=["exec:process"],
                              description="Observed in source: " + _where(profile, "code_execution")))
    if profile.has("network_fetch") and not any(t.network_access for t in declared):
        added.append(ToolSpec(name="observed:network_fetch", origin="observed", network_access=True,
                              scopes=["network:http"], description="Observed in source: " + _where(profile, "network_fetch")))
    if profile.has("file_access") and not any("file" in s or "fs" in s for t in declared for s in t.scopes):
        added.append(ToolSpec(name="observed:file_access", origin="observed", scopes=["read:files"],
                              description="Observed in source: " + _where(profile, "file_access")))

    # A declared limit is only credited when the source bounds every payment amount.
    if profile.unbounded_amounts and financial:
        for tool in tools:
            if _signing(tool) and tool.spend_limit_usdc is not None:
                tool.spend_limit_usdc = None
                tool.description = (tool.description + " [declared spend limit is not enforced in source]").strip()

    return artifact.model_copy(update={"tools": tools + added, "code_profile": profile.summary()})


def unverifiable_control_files(artifact: AgentArtifact) -> list[str]:
    """Files holding signing/payment authority whose controls the data flow cannot see.

    Fail-closed controls are verified by data flow for Python and JavaScript/TypeScript.
    Authority found in files the analysis could not parse, or in other languages, can
    only be judged by reading that code.
    """
    capabilities = artifact.code_profile.get("capabilities", {})
    analysed = set(artifact.code_profile.get("analysed_files", []))
    files = {loc.split(":", 1)[0] for cap in FINANCIAL_CAPABILITIES + ("payment", "account_control", "code_execution")
             for loc in capabilities.get(cap, [])}
    return sorted(f for f in files if f not in analysed and not f.lower().endswith(".py"))


def authority_only_declared(artifact: AgentArtifact) -> bool:
    """Signing or payment authority is declared, but the submitted source never signs, submits
    or pays. The missing control is real but latent until that code exists."""
    if not has_source(artifact):
        return False
    caps = artifact.code_profile.get("capabilities", {})
    return not any(caps.get(cap) for cap in FINANCIAL_CAPABILITIES + ("payment", "account_control"))


def code_enforced_spend_limit(artifact: AgentArtifact) -> bool:
    """The source caps or gates every untrusted payment: an amount bound or approval
    gate is enforced, no untrusted amount reaches signing unbounded, and no untrusted
    value reaches a financial sink. Such a limit counts even if no manifest declares it."""
    if not has_source(artifact):
        return False
    profile = artifact.code_profile
    controls = profile.get("controls", {})
    # The cap or gate must sit in code that can pay; a comparison elsewhere limits nothing.
    paying = {loc.split(":", 1)[0] for cap in FINANCIAL_CAPABILITIES + ("payment",)
              for loc in profile.get("capabilities", {}).get(cap, [])}
    gated = any(loc.split(":", 1)[0] in paying
                for loc in controls.get("amount_cap", []) + controls.get("approval", []))
    unsafe = {"financial", "account_control", "foreign_signing"}
    return gated and not profile.get("unbounded_amounts") and not any(
        f["category"] in unsafe for f in profile.get("flows", []))


def human_approval_enforced(artifact: AgentArtifact, prompt_lower: str) -> bool:
    """A person (or a second key) must approve: attested flag, ledger co-signer or code gate.

    Prompt wording counts only when no source was supplied at all; with source,
    a sentence asking the model to confirm is not an enforced control.
    """
    if artifact.human_oversight:
        return True
    # A co-signer required by the ledger is an enforced control, stronger than any code check.
    account = artifact.chain_authority.get("account", {})
    agent = account.get("agent_key", {})
    if account.get("status") == "found" and (
            (agent.get("is_signer") and not agent.get("can_pay_alone"))
            or (not agent and account.get("multisig_required_for_payments"))):
        return True
    if has_source(artifact):
        return bool(artifact.code_profile.get("controls", {}).get("approval"))
    return any(word in prompt_lower for word in OVERSIGHT_WORDS)


def bounded_autonomy(artifact: AgentArtifact) -> bool:
    """Recipients and amounts are constrained in code and no untrusted value reaches signing."""
    if not has_source(artifact):
        return False
    profile = artifact.code_profile
    controls = profile.get("controls", {})
    unsafe = {"financial", "account_control", "foreign_signing"}
    bounded = (controls.get("allowlist") or controls.get("value_binding")) and controls.get("amount_cap")
    return bool(bounded) and not any(f["category"] in unsafe for f in profile.get("flows", []))


def oversight_enforced(artifact: AgentArtifact, prompt_lower: str) -> bool:
    """Human approval, or autonomy that the code keeps within fixed bounds."""
    return human_approval_enforced(artifact, prompt_lower) or bounded_autonomy(artifact)


def unenforced_limit_tools(artifact: AgentArtifact) -> list[ToolSpec]:
    return [t for t in artifact.tools if "[declared spend limit is not enforced in source]" in t.description]
