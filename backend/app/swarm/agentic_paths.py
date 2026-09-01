"""Stellar deep-tier static source-to-sink analysis for autonomous agents.

Only a visible source, propagated variable and sink in the same file is called
CONFIRMED.  This is deliberately independent from the Arc implementation and
uses Stellar/Soroban transaction sinks.
"""

from __future__ import annotations

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
    tainted: set[str] = set()
    secrets: set[str] = set()
    commands: list[_Hit] = []
    financial: list[_Hit] = []
    exfil: list[_Hit] = []
    control_present = bool(_CONTROL_RE.search(content))

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
        if referenced_taint and _FINANCIAL_SINK_RE.search(line) and not control_present:
            financial.append(_Hit(filename, number, referenced_taint[0], line))

        referenced_secrets = sorted(_names(line) & secrets)
        if referenced_secrets and _EXFIL_SINK_RE.search(line):
            if not assignment or assignment.group("var") not in referenced_secrets:
                exfil.append(_Hit(filename, number, referenced_secrets[0], line))
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

    findings: list[Finding] = []
    if command_hits:
        findings.append(Finding(
            id="security-path-untrusted-to-command", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="Güvenilmeyen girdiden komut/kod yürütmeye doğrulanmış yol",
            detail="Dış girdiyi taşıyan değişken eval/exec/shell sink'ine ulaşıyor; bu yol agent girdisini uzaktan kod çalıştırmaya dönüştürebilir.",
            evidence="; ".join(hit.evidence() for hit in command_hits),
            evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Dinamik yürütmeyi kaldırın; zorunluysa ağsız ve Stellar imza anahtarı olmayan allowlist'li sandbox kullanın.",
            references=["OWASP LLM05 Improper Output Handling", "CWE-78"],
            auditor=auditor, confidence=0.98,
        ))
    if financial_hits:
        findings.append(Finding(
            id="security-path-untrusted-to-financial-sink", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="Güvenilmeyen girdiden Stellar finansal işleme kontrolsüz yol",
            detail="Dış girdi, require_auth/allowlist/limit/sequence-idempotency kontrolü görülmeden Soroban veya Stellar işlem sink'ine ulaşıyor.",
            evidence="; ".join(hit.evidence() for hit in financial_hits),
            evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Kaynak ile sink arasına tipli doğrulama, require_auth, alıcı allowlist'i, harcama politikası, sequence/idempotency ve insan onayı koyun.",
            references=["Soroban authorization", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.96,
        ))
    if exfil_hits:
        findings.append(Finding(
            id="security-path-secret-to-exfiltration", dimension=Dimension.SECURITY,
            severity=Severity.CRITICAL,
            title="Stellar sırrından log/ağ sızıntısına doğrulanmış veri yolu",
            detail="Secret seed, özel anahtar veya erişim sırrı değişkeni loglama ya da ağ çağrısında kullanılıyor.",
            evidence="; ".join(hit.evidence() for hit in exfil_hits),
            evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Stellar secret seed'i sink'e taşımayın; donanım/passkey/harici imzalayıcıda tutun, redaction uygulayın ve anahtarı döndürün.",
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
