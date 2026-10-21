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
#: A secret passed through a masking, hashing or public-key step on the same line is not leaked.
_SANITISED_RE = re.compile(r"mask|redact|hash|digest|fingerprint|public_?key|publicKey|\.length\b|\blen\(", re.I)
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
        if referenced_secrets and _EXFIL_SINK_RE.search(line) and not _SANITISED_RE.search(line):
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
    "endpoint": ("security-path-untrusted-ledger-endpoint", Severity.CRITICAL,
        "Input chooses the Stellar RPC or Horizon server the agent trusts",
        "The URL of the RPC or Horizon server comes from a tool argument, flag or request field. That server returns the simulation, authorization entries, sequence numbers and quotes the agent then signs, so a malicious server chooses what the agent's key authorizes. Checks on the user's request do not cover what the server returns.",
        "Take RPC, Horizon and network passphrase from operator configuration only; if overrides are needed, allowlist them. Inspect the authorization tree before signing.",
        ["Stellar RPC simulation", "OWASP LLM06 Excessive Agency"]),
    "signing_oracle": ("security-path-key-signs-arbitrary-bytes", Severity.CRITICAL,
        "The agent key signs whatever bytes the requester supplies",
        "Raw data from a tool argument or request is signed with the agent's keypair. A Stellar transaction is authorized by a signature over its hash, and a Soroban authorization entry by a signature over its payload hash, so a requester who chooses the bytes can get any transaction or contract call signed as this account.",
        "Never expose raw signing. Sign only transactions the server builds and inspects; for login or proof of control use SEP-10/SEP-45 or SEP-53 message signing, which prefixes the message so it cannot be a transaction.",
        ["Stellar transaction signatures", "SEP-53", "OWASP LLM06 Excessive Agency"]),
    "asset_route": ("security-path-untrusted-conversion-route", Severity.HIGH,
        "Input chooses the assets or route of a path payment",
        "A signed path payment takes its send asset, destination asset or path from a tool argument or request. The conversion then runs through whatever assets and liquidity pools the requester names, including a look-alike token or a thin pool they control, and the value lost in the trade goes to them.",
        "Fix the assets (code and issuer) and allowed paths in configuration, and require a minimum received amount computed from an independent price.",
        ["Stellar path payments", "OWASP LLM06 Excessive Agency"]),
    "sql": ("security-path-untrusted-to-sql", Severity.HIGH,
        "Input is written into a SQL statement",
        "A SQL statement is built by string formatting with a value from a tool argument, request or model output. The requester can rewrite the query: read other users' records, or change balances, approvals and spending totals that controls depend on.",
        "Pass values as bound parameters (cursor.execute(sql, params), $1 placeholders, tagged sql templates); never format them into the statement.",
        ["CWE-89", "OWASP LLM05 Improper Output Handling"]),
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
    "secret_via_model": ("security-path-secret-handled-by-model", Severity.HIGH,
        "The model is asked to handle secret keys",
        "A model-callable tool takes secret key material as an argument. Keys pass through the model's context, client transcripts and provider logs, and any key the model has seen can be replayed into other calls.",
        "Keep keys out of tool arguments: sign with a key held by the server or an external signer, and pass only public keys or unsigned XDR through the model.",
        ["OWASP LLM02 Sensitive Information Disclosure", "CWE-522"]),
    "x402_unbounded": ("security-path-x402-payment-unbounded", Severity.HIGH,
        "Paid requests pay whatever the server asks",
        "An x402/MPP client wrapper signs the payment a 402 response requests, with no maximum amount or requirement selector. A malicious or compromised paid endpoint chooses the recipient, asset and amount.",
        "Configure a maximum per payment and an allowlist of payees and assets in the wrapper (or a requirements selector that enforces them), and track spend across calls.",
        ["OWASP LLM06 Excessive Agency", "x402 client payment policy"]),
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

    from .capabilities import declared_entrypoints
    entrypoints = declared_entrypoints(artifact)
    profile = analyse_code(artifact.code_files, entrypoints)
    findings: list[Finding] = []

    by_category: dict[str, list] = {}
    for flow in profile.flows:
        by_category.setdefault(flow.category, []).append(flow)
    for category, (fid, severity, title, detail, remediation, refs) in _PATH_RULES.items():
        flows = by_category.get(category, [])
        # A value merely derived from an object that holds a secret (a receipt, a form's other
        # fields) is not reported: on unseen agents every such report was a false alarm.
        if not flows:
            continue
        direct = [f for f in flows if f.direct or category.startswith("secret")]
        if category == "endpoint":
            # A skill's commands are run by the model, so their flags are the model's choice.
            # Only a skill's own SKILL.md makes the model the one running its commands (AGENTS.md
            # guides coding assistants), and only for the scripts in that skill's folder: an SDK
            # elsewhere in the repository is called by its integrators, not by the model.
            skill_dirs = [m.group(1) for m in re.finditer(r"^\[((?:[^\]\n]*/)?)skill\.md\]$",
                                                          artifact.system_prompt or "", re.I | re.M)]
            direct = [f for f in flows if f.direct or ("caller" in f.labels
                      and any(f.location.file.startswith(d) for d in skill_dirs))]
            if not any(profile.has(cap) for cap in ("stellar_signing", "tx_submission", "foreign_tx_signing", "contract_invocation")):
                severity = Severity.MEDIUM  # nothing is signed against what that server returns
        if category == "path_traversal" and not direct:
            # A file path from a public function with no caller in the source: on unseen agents
            # these were all dead code or operator-chosen paths (env, argv, own templates).
            continue
        if category in {"secret_via_model", "secret_to_model"} and all("fresh" in f.labels for f in flows):
            # A key generated in this call and handed back (create_account): not yet funded or
            # used by anyone, so exposing it is a handling flaw, not a theft path.
            severity = severity.downgrade(2)
        chosen = direct or flows
        confirmed = bool(direct)
        findings.append(Finding(
            id=fid, dimension=Dimension.SECURITY,
            # A file path its caller chooses is the caller's own business unless input from
            # outside reaches it; that case is confirmed above.
            # A library that exposes raw signing to its integrators is an API choice until
            # outside input is shown to reach it.
            # Unresolved origins were false in 23 of 31 hand-checked cases on real agents: kept
            # visible as an API to review, at low.
            severity=severity if confirmed else Severity.LOW,
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

    forgeable = profile.forgeable_approvals or profile.unresolved_approvals
    if forgeable:
        moves_funds = any(profile.has(cap) for cap in ("stellar_signing", "tx_submission", "payment", "contract_invocation",
                                                       "foreign_tx_signing", "account_control"))
        severity = Severity.CRITICAL if moves_funds else Severity.HIGH
        # A flag only an unseen caller sets is the integrator's API until outside input reaches it.
        resolved = bool(profile.forgeable_approvals)
        findings.append(Finding(
            id="security-path-forgeable-approval", dimension=Dimension.SECURITY,
            severity=severity if resolved else Severity.LOW,
            title="The approval gate checks a value the requester supplies",
            detail="The code refuses to act unless an approval flag is set, but that flag is a tool argument, request "
                   "field or fetched value. Whoever can talk to the agent can set it: a request the model refuses "
                   "when asked plainly passes when reworded so the model fills in the flag. The gate is not an approval.",
            evidence="; ".join(loc.render() for loc in forgeable[:5]),
            evidence_grade=EvidenceGrade.CONFIRMED if resolved else EvidenceGrade.INFERRED,
            remediation="Take approval from outside the model's reach: a signed approval record, a wallet prompt the "
                        "human answers, or an operator decision stored server-side and bound to the exact recipient and amount.",
            references=["CWE-807 Reliance on Untrusted Inputs in a Security Decision", "OWASP LLM06 Excessive Agency"],
            auditor=auditor, confidence=0.93,
        ))

    # Non-Python sources keep lexical candidates; they are never reported as confirmed data flow.
    lexical_command: list[_Hit] = []
    lexical_financial: list[_Hit] = []
    lexical_exfil: list[_Hit] = []
    analysed = set(profile.analysed_files)
    for filename, content in artifact.code_files.items():
        if filename in analysed or filename.lower().endswith(".py") or not filename.lower().endswith(_IMPLEMENTATION_SUFFIXES):
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

    # A payment rule the instructions state but the code does not enforce: the model is the
    # only control, and a reworded, role-played or indirect request gets past a model.
    moving = {f.id for f in findings} & {"security-path-untrusted-to-financial-sink", "security-path-forgeable-approval",
                                         "security-path-external-transaction-signed", "security-path-x402-payment-unbounded"}
    rules = _prompt_payment_rules(artifact)
    if moving and rules:
        findings.append(Finding(
            id="security-policy-only-in-prompt", dimension=Dimension.SECURITY, severity=Severity.HIGH,
            title="A payment rule is stated to the model but not enforced in code",
            detail="The instructions tell the model what it may pay, but the payment path does not check it. The model "
                   "is then the only control: a plain request may be refused while the same request reworded, "
                   "role-played, translated, split up or planted in content the agent reads is carried out.",
            evidence="; ".join(rules[:3]), evidence_grade=EvidenceGrade.CONFIRMED,
            remediation="Enforce each stated rule in the code that builds or signs the transaction (allowlist, caps, "
                        "approval bound to recipient and amount), and test it with reworded and indirect requests.",
            references=["OWASP LLM01 Prompt Injection", "OWASP LLM06 Excessive Agency"], auditor=auditor, confidence=0.9,
        ))

    # A per-payment cap with no running total: many small requests each pass it.
    pay_files = {loc.file for cap in ("stellar_signing", "tx_submission", "payment", "contract_invocation")
                 for loc in profile.capabilities.get(cap, [])}
    if profile.controls.get("amount_cap") and pay_files and not any(
            _CUMULATIVE.search(artifact.code_files.get(f, "")) for f in pay_files):
        findings.append(Finding(
            id="security-per-call-cap-only", dimension=Dimension.SECURITY, severity=Severity.MEDIUM,
            title="Payments are capped per call, with no total or rate limit",
            detail="Each payment is checked against a maximum, but nothing tracks how much has been sent. Splitting a "
                   "large request into many calls that each stay under the cap moves any amount.",
            evidence="caps at " + "; ".join(loc.render() for loc in profile.controls["amount_cap"][:3])
                     + " · no running total in " + ", ".join(sorted(pay_files)[:5]),
            evidence_grade=EvidenceGrade.INFERRED,
            remediation="Keep a persistent spent-amount per period (and per user for shared funds), reject when it "
                        "would exceed the budget, and rate-limit payment calls.",
            references=["CWE-770 Allocation of Resources Without Limits or Throttling"], auditor=auditor, confidence=0.7,
        ))
    return findings


_PAY_WORDS = re.compile(r"\b(?:pay\w*|send\w*|transfer\w*|withdraw\w*|spend\w*|xlm|usdc|funds?|payments?|recipients?)\b", re.I)
_RULE_WORDS = re.compile(r"\b(?:never|do not|don't|must not|must only|only (?:send|pay|transfer)|at most|no more than|"
                         r"maximum|max(?:imum)? of|limit(?:ed)? to|cap(?:ped)?|without (?:approval|confirmation)|"
                         r"(?:ask|require)s? (?:for )?(?:approval|confirmation)|refuse)\b", re.I)
_CUMULATIVE = re.compile(r"spent|total_?(?:spent|paid|sent|amount)|daily|per_?(?:day|hour|period)|cumulative|budget|"
                         r"quota|remaining|allowance|rate_?limit|window_?(?:start|total)|spend_?tracker|ledger", re.I)


_DEVELOPER_GUIDES = {"agents.md", "claude.md", "contributing.md", ".cursorrules", "copilot-instructions.md"}


def _prompt_payment_rules(artifact: AgentArtifact) -> list[str]:
    """Sentences in the agent's instructions that state a payment rule, with their file."""
    found: list[str] = []
    for block in re.split(r"\n(?=\[[^\]\n]+\]\n)", artifact.system_prompt or ""):
        head = re.match(r"\[([^\]\n]+)\]\n", block)
        where = head.group(1) if head else "instructions"
        if where.lower().startswith("readme") or where.lower().rsplit("/", 1)[-1] in _DEVELOPER_GUIDES:
            # A README describes the project to people, and AGENTS.md / CLAUDE.md guide the coding
            # assistants that work on the repository; neither instructs the agent at run time.
            continue
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", block[head.end():] if head else block):
            sentence = sentence.strip(" -*#>")
            if 12 <= len(sentence) <= 300 and _PAY_WORDS.search(sentence) and _RULE_WORDS.search(sentence):
                found.append(f"{where}: \"{sentence}\"")
    # Approval and limit rules first: they are what a reworded request gets past.
    found.sort(key=lambda rule: not _GATE_WORDS.search(rule))
    return found[:5]


_GATE_WORDS = re.compile(r"approv|confirm|prompt|limit|cap\b|max|at most|no more than|only (?:pay|send|transfer)", re.I)
