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
    r"\beval\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.(?:run|call|popen)\s*\(|"
    r"child_process\.(?:exec|spawn)\s*\(|\bCommand::new\s*\(",
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


def _scan_file(filename: str, content: str) -> tuple[list[_Hit], list[_Hit], list[_Hit]]:
    if filename.lower().endswith(".py"):
        return _scan_python(filename, content)
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


def _scan_python(filename: str, content: str) -> tuple[list[_Hit], list[_Hit], list[_Hit]]:
    """Bounded intraprocedural analysis; parses source, never imports or executes it.

    Branches are conservatively joined. A path is a static observation, not an
    exploit or proof that an external authorization implementation can be bypassed.
    Dynamic dispatch, cross-file calls and arbitrary sanitizers are not resolved.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], []
    commands: list[_Hit] = []
    financial: list[_Hit] = []
    exfil: list[_Hit] = []
    lines = content.splitlines()

    def qualified(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + "." + node.attr
        return ""

    def tags(node: ast.AST | None, state: dict[str, set[str]]) -> set[str]:
        if node is None or isinstance(node, (ast.Constant, ast.Lambda)):
            return set()
        if isinstance(node, ast.Name):
            return state.get(node.id, set()).copy()
        found: set[str] = set()
        child_tags = [(child, tags(child, state)) for child in ast.iter_child_nodes(node)]
        for _, value in child_tags:
            found |= value
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)):
            label = qualified(node.func if isinstance(node, ast.Call) else node)
            if _SOURCE_RE.search(label + "("):
                found.add("external")
            # Environment access is sensitive only when the referenced key is a secret.
            if label in {"os.getenv", "os.environ.get"} and isinstance(node, ast.Call):
                if node.args and isinstance(node.args[0], ast.Constant) and _SECRET_NAME_RE.search(str(node.args[0].value)):
                    found.add("secret")
            if isinstance(node, ast.Subscript) and qualified(node.value) == "os.environ":
                if isinstance(node.slice, ast.Constant) and _SECRET_NAME_RE.search(str(node.slice.value)):
                    found.add("secret")
        if isinstance(node, ast.Call):
            arguments: set[str] = set()
            for child, value in child_tags:
                if child is not node.func:
                    arguments |= value
            callee = qualified(node.func) + "("
            hit = _Hit(filename, node.lineno, ",".join(sorted(arguments)), lines[node.lineno - 1], EvidenceGrade.CONFIRMED)
            if "external" in arguments:
                if _COMMAND_SINK_RE.search(callee):
                    commands.append(hit)
                if _FINANCIAL_SINK_RE.search(callee):
                    financial.append(hit)
            if "secret" in arguments and _EXFIL_SINK_RE.search(callee):
                exfil.append(hit)
        return found

    def bind(target: ast.AST, value: set[str], state: dict[str, set[str]]) -> None:
        if isinstance(target, ast.Name):
            state[target.id] = value.copy()
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind(element, value, state)

    def block(statements: list[ast.stmt], state: dict[str, set[str]]) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = {key: value.copy() for key, value in state.items()}
                args = [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]
                for arg in args:
                    local[arg.arg] = {"external"} if arg.arg.lower() in _SOURCE_NAMES else set()
                block(stmt.body, local)
            elif isinstance(stmt, ast.ClassDef):
                block(stmt.body, state.copy())
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = tags(stmt.value, state)
                for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                    bind(target, value, state)
            elif isinstance(stmt, ast.If):
                tags(stmt.test, state)
                branches = []
                for body in (stmt.body, stmt.orelse):
                    branch = {key: value.copy() for key, value in state.items()}
                    block(body, branch)
                    branches.append(branch)
                for key in set(branches[0]) | set(branches[1]):
                    state[key] = branches[0].get(key, set()) | branches[1].get(key, set())
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try)):
                # A loop/exception path may execute zero times: retain incoming taint.
                branch = {key: value.copy() for key, value in state.items()}
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    bind(stmt.target, tags(stmt.iter, state), branch)
                elif isinstance(stmt, ast.While):
                    tags(stmt.test, state)
                block(stmt.body, branch)
                for key, value in branch.items():
                    state[key] = state.get(key, set()) | value
                for handler in getattr(stmt, "handlers", []):
                    block(handler.body, state)
                block(stmt.orelse, state)
                block(getattr(stmt, "finalbody", []), state)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    value = tags(item.context_expr, state)
                    if item.optional_vars:
                        bind(item.optional_vars, value, state)
                block(stmt.body, state)
            else:
                tags(stmt, state)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    break

    block(tree.body, {})
    return commands[:5], financial[:5], exfil[:5]


def analyse_agentic_paths(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    command_hits: list[_Hit] = []
    financial_hits: list[_Hit] = []
    exfil_hits: list[_Hit] = []
    for filename, content in artifact.code_files.items():
        if not filename.lower().endswith(_IMPLEMENTATION_SUFFIXES):
            continue
        commands, financial, exfil = _scan_file(filename, content)
        command_hits.extend(commands)
        financial_hits.extend(financial)
        exfil_hits.extend(exfil)

    # Do not let adding a heuristic-only file dilute directly observed evidence.
    command_hits = [hit for hit in command_hits if hit.grade is EvidenceGrade.CONFIRMED] or command_hits
    financial_hits = [hit for hit in financial_hits if hit.grade is EvidenceGrade.CONFIRMED] or financial_hits
    exfil_hits = [hit for hit in exfil_hits if hit.grade is EvidenceGrade.CONFIRMED] or exfil_hits

    findings: list[Finding] = []
    if command_hits:
        findings.append(Finding(
            id="security-path-untrusted-to-command", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="External input reaches a process or code-execution boundary",
            detail="Input-derived data appears in an eval, exec or process call. Inspect whether an attacker controls executable content or arguments. A static path alone does not prove arbitrary code execution.",
            evidence="; ".join(hit.evidence() for hit in command_hits),
            evidence_grade=command_hits[0].grade,
            remediation="Remove dynamic execution. Otherwise use an isolated worker without network access or Stellar signing keys, with allowlisted commands and arguments.",
            references=["OWASP LLM05 Improper Output Handling", "CWE-78"],
            auditor=auditor, confidence=0.98,
        ))
    if financial_hits:
        findings.append(Finding(
            id="security-path-untrusted-to-financial-sink", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="External input reaches a Stellar transaction boundary",
            detail="A static input-to-transaction path is visible. Authorization names and comments do not prove enforcement; validate the recipient, amount and signing policy with negative tests. This is not proof of a successful exploit.",
            evidence="; ".join(hit.evidence() for hit in financial_hits),
            evidence_grade=financial_hits[0].grade,
            remediation="Enforce typed inputs, Soroban require_auth, recipient allowlists, spending limits, replay protection and explicit approval. Test each boundary with rejected requests.",
            references=["Soroban authorization", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.96,
        ))
    if exfil_hits:
        findings.append(Finding(
            id="security-path-secret-to-exfiltration", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="A signing secret reaches a logging or network boundary",
            detail="A variable derived from a secret environment value appears in a logging or network call. Confirm the sink semantics and remove secret material from the output path.",
            evidence="; ".join(hit.evidence() for hit in exfil_hits),
            evidence_grade=exfil_hits[0].grade,
            remediation="Keep Stellar keys in an external signer. Remove secret logging, redact diagnostics, and rotate credentials if they were exposed.",
            references=["OWASP LLM02 Sensitive Information Disclosure", "CWE-532"],
            auditor=auditor, confidence=0.98,
        ))
    executable = {
        name: content
        for name, content in artifact.code_files.items()
        if name.lower().endswith(_IMPLEMENTATION_SUFFIXES)
    }
    signing_tools = [
        tool
        for tool in artifact.tools
        if tool.requires_signature or bool(set(tool.scopes) & _SIGNING_SCOPES)
    ]
    if signing_tools and executable and not _CONTROL_RE.search("\n".join(executable.values())):
        findings.append(Finding(
            id="security-path-controls-not-enforced", dimension=Dimension.SECURITY,
            severity=Severity.HIGH,
            title="Stellar finansal kontrollerinin uygulama düzeyi kanıtı yok",
            detail="Agent imza/harcama araçları ilan ediyor fakat kaynakta require_auth, allowlist, limit veya sequence/idempotency zorlaması görülmedi. Prompt beyanı enforce edilebilir kontrol değildir.",
            evidence="imza araçları=" + ", ".join(t.name for t in signing_tools)
            + "; incelenen kaynaklar=" + ", ".join(sorted(executable)),
            evidence_grade=EvidenceGrade.INFERRED,
            remediation="Kontrolleri Soroban require_auth/policy ve uygulama kodunda fail-closed zorlayın; negatif ve bypass testlerini CI'a ekleyin.",
            references=["Soroban authorization", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.82,
        ))
    return findings
