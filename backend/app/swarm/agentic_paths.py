"""Stellar deep-tier static source-to-sink analysis for autonomous agents.

Python uses bounded AST propagation; other languages produce inferred signals.
CONFIRMED describes visible static evidence, never a successfully executed exploit.
This implementation uses Stellar/Soroban transaction sinks.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity


_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_ASSIGN_RE = re.compile(rf"\b(?P<var>{_IDENT})\s*(?::[^=]+)?=\s*(?P<rhs>.+)")
_FUNCTION_RE = re.compile(
    rf"(?:async\s+)?def\s+{_IDENT}\s*\((?P<py>[^)]*)\)|"
    rf"(?:async\s+)?function\s+{_IDENT}\s*\((?P<js>[^)]*)\)",
    re.I,
)
_SOURCE_RE = re.compile(
    r"request\.(?:json|body|form|args)|req\.(?:body|query|params)|"
    r"event\.(?:body|data)|webhook|input\s*\(|stdin|argv|"
    r"messages?\s*\[|user[_-]?(?:input|message)|response\.(?:text|json)|resp\.text",
    re.I,
)
_SOURCE_NAMES = {
    "input", "user_input", "prompt", "payload", "query", "message", "messages",
    "command", "cmd", "code", "request", "webhook",
}
_COMMAND_SINK_RE = re.compile(
    # `exec(` as a function, not a method: RegExp.exec / db.exec are not code execution.
    r"(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(|os\.system\s*\(|subprocess\.(?:run|call|popen)\s*\(|"
    r"child_process\.(?:exec|execSync|spawn)\s*\(|\b(?:execSync|spawnSync|execFile)\s*\(|\bCommand::new\s*\(",
    re.I,
)
# Stellar Classic transaction submission and Soroban invocation/authorization
# are explicit sinks here; EVM writeContract/sendRawTransaction are not.
_FINANCIAL_SINK_RE = re.compile(
    r"\.(?:transfer|send_transaction|sign_transaction|submit_transaction|"
    r"invoke_contract|invoke_host_function|authorize_entry|sign_auth_entry)\s*\(|"
    r"\b(?:submit_transaction|invoke_contract|token\.transfer)\s*\(",
    re.I,
)
_CONTROL_RE = re.compile(
    r"authori[sz]|authenticat|verify_signature|require_auth|allowlist|whitelist|validate|"
    r"schema|sanitize|spend_limit|max_(?:amount|spend)|daily_(?:cap|limit)|"
    r"human_(?:approval|oversight)|idempoten|sequence|nonce|replay|policyerror|require\s*\(",
    re.I,
)
_SECRET_NAME_RE = re.compile(
    r"(?:private[_-]?key|secret|seed(?:_phrase)?|mnemonic|api[_-]?key|access[_-]?token)",
    re.I,
)
_SECRET_SOURCE_RE = re.compile(
    r"os\.(?:environ|getenv)|process\.env|std::env|private[_-]?key|mnemonic|seed[_-]?phrase|"
    r"(?:sk|pk|xprv)-[A-Za-z0-9_-]{8,}|S[A-Z2-7]{55}",
    re.I,
)
_EXFIL_SINK_RE = re.compile(
    r"\bprint\s*\(|console\.log\s*\(|log(?:ger|ging)?\.(?:debug|info|warning|error)\s*\(|"
    r"requests?\.(?:post|put|get)\s*\(|fetch\s*\(|httpx?\.",
    re.I,
)
_IMPLEMENTATION_SUFFIXES = (
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".sol",
)
_SIGNING_SCOPES = {"sign:tx", "write:wallet", "wallet", "transfer", "spend"}


@dataclass(frozen=True)
class _Hit:
    file: str
    line: int
    variable: str
    text: str
    grade: EvidenceGrade = EvidenceGrade.INFERRED

    def evidence(self) -> str:
        return f"{self.file}:{self.line} `{' '.join(self.text.strip().split())[:180]}`"


def _names(text: str) -> set[str]:
    return set(re.findall(_IDENT, text))


def _function_params(line: str) -> set[str]:
    match = _FUNCTION_RE.search(line)
    if not match:
        return set()
    raw = match.group("py") or match.group("js") or ""
    params = set()
    for item in raw.split(","):
        name_match = re.search(_IDENT, item.strip())
        if name_match and name_match.group(0).lower() in _SOURCE_NAMES:
            params.add(name_match.group(0))
    return params


def _scan_file(filename: str, content: str, external_entrypoints: set[str] | None = None) -> tuple[list[_Hit], list[_Hit], list[_Hit]]:
    tainted: set[str] = set()
    secrets: set[str] = set()
    commands: list[_Hit] = []
    financial: list[_Hit] = []
    exfil: list[_Hit] = []

    for number, line in enumerate(content.splitlines(), 1):
        params = _function_params(line)
        if _FUNCTION_RE.search(line):
            tainted = params
        assignment = _ASSIGN_RE.search(line)
        if assignment:
            variable = assignment.group("var")
            rhs = assignment.group("rhs")
            if _SOURCE_RE.search(rhs) or _names(rhs) & tainted:
                tainted.add(variable)
            if _SECRET_NAME_RE.search(variable) and _SECRET_SOURCE_RE.search(rhs):
                secrets.add(variable)

        referenced_taint = sorted(_names(line) & tainted)
        if referenced_taint and _COMMAND_SINK_RE.search(line):
            commands.append(_Hit(filename, number, referenced_taint[0], line))
        if referenced_taint and _FINANCIAL_SINK_RE.search(line):
            financial.append(_Hit(filename, number, referenced_taint[0], line))

        referenced_secrets = sorted(_names(line) & secrets)
        if referenced_secrets and _EXFIL_SINK_RE.search(line):
            if not assignment or assignment.group("var") not in referenced_secrets:
                exfil.append(_Hit(filename, number, referenced_secrets[0], line))
    return commands[:5], financial[:5], exfil[:5]


_PATH_RULES = {
    # category: (finding id, severity for direct input, title, detail, remediation, references)
    "command": ("security-path-untrusted-to-command", Severity.CRITICAL,
        "External input reaches a process or code-execution boundary",
        "Input-derived data appears in an eval, exec or process call. Inspect whether an attacker controls executable content or arguments. A static path alone does not prove arbitrary code execution.",
        "Remove dynamic execution. Otherwise use an isolated worker without network access or Stellar signing keys, with allowlisted commands and arguments.",
        ["OWASP LLM05 Improper Output Handling", "CWE-78"]),
    "financial": ("security-path-untrusted-to-financial-sink", Severity.CRITICAL,
        "External input reaches a Stellar transaction boundary",
        "A static input-to-transaction path is visible: the recipient or an unbounded amount of a signed Stellar operation comes from untrusted input. Authorization names and comments do not prove enforcement. This is not proof of a successful exploit.",
        "Enforce typed inputs, recipient allowlists, fail-closed spending limits, replay protection and explicit approval before signing. Test each boundary with rejected requests.",
        ["Soroban authorization", "OWASP LLM06 Excessive Agency"]),
    "foreign_signing": ("security-path-external-transaction-signed", Severity.CRITICAL,
        "An externally supplied transaction is signed with the agent key",
        "A transaction envelope parsed from request or model input is signed or submitted without inspecting its operations. Whoever supplies the envelope chooses what the agent key authorizes.",
        "Never sign arbitrary envelopes. Build transactions server-side, or decode and allowlist every operation, source, destination and amount before signing.",
        ["Stellar transaction signing", "OWASP LLM06 Excessive Agency"]),
    "account_control": ("security-path-untrusted-account-control", Severity.CRITICAL,
        "Untrusted input changes account authority",
        "Signer, threshold, trustline or merge operations are built from untrusted input and signed. A prompt injection or forged request can add a signer or merge the account.",
        "Remove account-administration tools from the agent, or require an out-of-band human approval and fixed parameters for each change.",
        ["Stellar set_options", "OWASP LLM06 Excessive Agency"]),
    "ssrf": ("security-path-untrusted-to-network", Severity.HIGH,
        "Untrusted input chooses a server-side request URL",
        "A URL derived from model or request input is fetched without a fixed host. The agent can be steered to internal services, cloud metadata endpoints or attacker hosts.",
        "Allowlist hosts and schemes, resolve and pin addresses, block private ranges and do not return raw responses to the model.",
        ["CWE-918", "OWASP LLM06 Excessive Agency"]),
    "path_traversal": ("security-path-untrusted-to-file", Severity.HIGH,
        "Untrusted input chooses a file path",
        "A file path derived from model or request input is opened without a containment check. Relative segments such as ../ can reach configuration and key files.",
        "Resolve the path and require it to stay inside a fixed directory (Path.resolve().is_relative_to(base)); allowlist extensions.",
        ["CWE-22"]),
    "secret_to_model": ("security-path-secret-to-model", Severity.CRITICAL,
        "Secret material is sent to the language model",
        "A secret value is placed into a model request. It leaves the trust boundary to the model provider and can be extracted from the conversation by prompt injection.",
        "Keep keys out of prompts and tool results. Sign in a separate component the model cannot read, and rotate any key that was sent.",
        ["OWASP LLM02 Sensitive Information Disclosure"]),
    "secret_exfiltration": ("security-path-secret-to-exfiltration", Severity.CRITICAL,
        "A signing secret reaches a logging or network boundary",
        "A variable derived from secret material appears in a logging or network call. Confirm the sink semantics and remove secret material from the output path.",
        "Keep Stellar keys in an external signer. Remove secret logging, redact diagnostics, and rotate credentials if they were exposed.",
        ["OWASP LLM02 Sensitive Information Disclosure", "CWE-532"]),
}


def _evidence(flows) -> str:
    return "; ".join(f"{flow.location.render()} [{', '.join(sorted(flow.labels - {'secret'})) or 'secret'} -> {flow.function}]"
                     for flow in flows[:5])


def analyse_agentic_paths(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    from .codeflow import analyse_code

    entrypoints: dict[str, set[str]] = {}
    if 'veritas.json' in artifact.code_files:
        from ..services.blueprint import parse_blueprint
        try:
            blueprint = parse_blueprint(artifact.code_files['veritas.json'])
            component = next(c for c in blueprint.components if c.id == blueprint.entrypoint.component)
            entrypoints[component.path] = {blueprint.entrypoint.symbol}
        except ValueError:
            pass  # Invalid declaration is reported by discovery; never import source.
    profile = analyse_code(artifact.code_files, entrypoints)
    findings: list[Finding] = []

    by_category: dict[str, list] = {}
    for flow in profile.flows:
        by_category.setdefault(flow.category, []).append(flow)
    for category, (fid, severity, title, detail, remediation, refs) in _PATH_RULES.items():
        flows = by_category.get(category, [])
        if category == "secret_exfiltration" and not flows and by_category.get("secret_possible"):
            possible = by_category["secret_possible"]
            findings.append(Finding(
                id=fid, dimension=Dimension.SECURITY, severity=Severity.LOW,
                title="Review an unresolved return value from a secret-bearing object",
                detail="A method on an object initialized with a secret returns a value that is logged or sent. The return may be a public receipt; no secret disclosure is established.",
                evidence=_evidence(possible), evidence_grade=EvidenceGrade.INFERRED,
                remediation=remediation, references=refs, auditor=auditor, confidence=0.35))
            continue
        if not flows:
            continue
        direct = [f for f in flows if f.direct or category.startswith("secret")]
        chosen = direct or flows
        confirmed = bool(direct)
        findings.append(Finding(
            id=fid, dimension=Dimension.SECURITY,
            severity=severity if confirmed else severity.downgrade(1),
            title=title,
            detail=detail if confirmed else detail + " The value enters through a public function whose callers are not in the submitted source, so the input origin is unresolved.",
            evidence=_evidence(chosen),
            evidence_grade=EvidenceGrade.CONFIRMED if confirmed else EvidenceGrade.INFERRED,
            remediation=remediation, references=refs, auditor=auditor,
            confidence=0.97 if confirmed else 0.75,
        ))

    if profile.nonblocking_controls:
        findings.append(Finding(
            id="security-path-control-not-blocking", dimension=Dimension.SECURITY,
            severity=Severity.HIGH,
            title="A spending limit check does not stop the action",
            detail="A comparison against a cap or limit only logs a warning; execution continues to the signed operation. The control exists in name but is not enforced.",
            evidence="; ".join(loc.render() for loc in profile.nonblocking_controls[:5]),
            evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Raise or return when the limit is exceeded, before any transaction is built or signed, and cover the rejection with a test.",
            references=["CWE-693 Protection Mechanism Failure"], auditor=auditor, confidence=0.95,
        ))

    # Non-Python sources keep lexical candidates; they are never reported as confirmed data flow.
    lexical_command: list[_Hit] = []
    lexical_financial: list[_Hit] = []
    lexical_exfil: list[_Hit] = []
    for filename, content in artifact.code_files.items():
        if filename.lower().endswith(".py") or not filename.lower().endswith(_IMPLEMENTATION_SUFFIXES):
            continue
        commands, financial, exfil = _scan_file(filename, content)
        lexical_command += commands
        lexical_financial += financial
        lexical_exfil += exfil
    known = {f.id for f in findings}
    for hits, fid in ((lexical_command, "security-path-untrusted-to-command"),
                      (lexical_financial, "security-path-untrusted-to-financial-sink"),
                      (lexical_exfil, "security-path-secret-to-exfiltration")):
        if hits and fid not in known:
            rule = next(r for r in _PATH_RULES.values() if r[0] == fid)
            findings.append(Finding(
                id=fid, dimension=Dimension.SECURITY, severity=rule[1].downgrade(1), title=rule[2],
                detail=rule[3] + " Detected lexically in non-Python source; data flow is not resolved.",
                evidence="; ".join(hit.evidence() for hit in hits), evidence_grade=EvidenceGrade.INFERRED,
                remediation=rule[4], references=rule[5], auditor=auditor, confidence=0.6))

    executable = {name for name in artifact.code_files if name.lower().endswith(_IMPLEMENTATION_SUFFIXES)}
    signing = any(tool.requires_signature or set(tool.scopes) & _SIGNING_SCOPES for tool in artifact.tools) or any(
        profile.has(cap) for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation"))
    enforced = any(profile.controls.get(kind) for kind in ("allowlist", "amount_cap", "approval", "transaction_inspection"))
    if signing and executable and not enforced:
        findings.append(Finding(
            id="security-path-controls-not-enforced", dimension=Dimension.SECURITY,
            severity=Severity.HIGH,
            title="No enforced Stellar spending control in source",
            detail="The agent can sign or move funds, but no fail-closed recipient allowlist, amount cap, approval gate or transaction inspection was found in the source. Prompt statements are not enforceable controls.",
            evidence="files with signing or payment authority=" + (", ".join(sorted({
                loc.file for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation", "payment")
                for loc in profile.capabilities.get(cap, [])})) or ", ".join(sorted(executable)[:10])),
            evidence_grade=EvidenceGrade.INFERRED,
            remediation="Enforce recipient allowlists, amount caps and approval in code that raises before signing; add negative tests.",
            references=["Soroban authorization", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.82,
        ))
    return findings
