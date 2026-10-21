"""File-level checks for weaknesses that are not an input-to-sink flow.

Each check looks for one concrete defect with a known exploit: instructions hidden in
text the model reads, credentials committed to the repository, signed transactions that
never expire, ledger traffic without TLS, retries that pay twice, payments accepted by
asset code alone and Soroban arithmetic that wraps. They report locations, never the
secret or the hidden text itself.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity

_CODE = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".rs", ".go", ".sol")
_TESTLIKE = re.compile(r"(^|/)(tests?|spec|fixtures?|examples?|mocks?|__tests__)/|(test|spec|mock|fixture|example)", re.I)

# --------------------------------------------------------------------------- hidden text
#: Characters that render as nothing or reorder text: Unicode tags (ASCII smuggling),
#: bidirectional overrides (Trojan Source) and zero-width characters.
_TAGS = re.compile("[\U000e0000-\U000e007f]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_ZERO_WIDTH = re.compile("[​‌⁠⁡⁢⁣⁤᠎]|(?<!^)﻿")

# --------------------------------------------------------------------------- tool poisoning
#: Text a tool description should never contain: hidden instruction blocks, orders to keep
#: something from the user, overrides, and requests to read or send secrets.
_POISON = (
    ("hidden instruction block", re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden)\s*>", re.I)),
    ("tells the model to hide something from the user",
     re.compile(r"\b(?:do not|don't|never)\s+(?:tell|mention|inform|notify|alert|show)\s+(?:this\s+to\s+)?(?:the\s+)?user", re.I)),
    ("overrides earlier instructions", re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier|other)\s+(?:instructions|rules)", re.I)),
    ("asks for secrets or local files",
     re.compile(r"\b(?:read|cat|open|send|upload|pass|attach|forward|include|copy)\b[^.\n]{0,80}"
                r"(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\bmcp\.json\b|\.aws/credentials|\bcredentials\.json\b|"
                r"claude_desktop_config|\.cursor/mcp|/etc/passwd|\.npmrc\b|\.git-credentials|\.ssh/)", re.I)),
    ("orders a step before the tool runs",
     re.compile(r"\bbefore\s+(?:using|calling|running)\s+(?:this|any(?:\s+other)?)\s+tool\b[^.\n]{0,100}\b(?:read|call|send|pass|fetch)\b", re.I)),
)
#: The agent's own instructions are allowed to talk about secrecy; only exfiltration counts there.
_PROMPT_POISON = {"asks for secrets or local files"}
_DESC_PROP = re.compile(r"""\bdescription\s*[:=]\s*(?P<q>["'`])(?P<text>(?:\\.|(?!(?P=q)).){12,2000}?)(?P=q)""", re.S)
_TOOL_CALL_DESC = re.compile(r"""\.(?:tool|registerTool|addTool)\(\s*["'`][\w.-]+["'`]\s*,\s*(?P<q>["'`])(?P<text>(?:\\.|(?!(?P=q)).){12,2000}?)(?P=q)""", re.S)
_TOOL_DECORATOR = re.compile(r"(?:^|\.)(?:tool|function_tool|mcp_tool)$")

# --------------------------------------------------------------------------- credentials
_CREDENTIALS = (
    ("Anthropic API key", re.compile(rb"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}")),
    ("OpenAI API key", re.compile(rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{80,}")),
    ("AWS access key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Slack token", re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{20,}")),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(rb"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}")),
    ("private key block", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("EVM private key", re.compile(rb"(?i)(?:private[_-]?key|priv[_-]?key|PK)\s*[:=]\s*[\"']?(?:0x)?[0-9a-f]{64}\b")),
)
_PLACEHOLDER = re.compile(rb"(?i)x{6,}|your[_-]|example|dummy|placeholder|redacted|changeme|<|0{16,}|1234567890")


def _entropy(token: bytes) -> float:
    counts = Counter(token)
    return -sum(c / len(token) * math.log2(c / len(token)) for c in counts.values()) if token else 0.0


def find_credentials(name: str, data: bytes) -> list[str]:
    """Redacted locations of live-looking credentials in one file."""
    found = []
    for kind, pattern in _CREDENTIALS:
        for match in pattern.finditer(data):
            token = match.group(0)
            if kind != "private key block" and (_PLACEHOLDER.search(token) or _entropy(token) < 3.3):
                continue
            line = data[:match.start()].count(b"\n") + 1
            found.append(f"{name}:{line} ({kind}, redacted)")
    return found


# --------------------------------------------------------------------------- Stellar specifics
_INFINITE_TIMEOUT = re.compile(r"\.setTimeout\(\s*(?:0|(?:[\w$]+\.)*TimeoutInfinite)\s*\)|setTimebounds\(\s*0\s*,\s*0\s*\)|"
                               r"\bset_timeout\(\s*0\s*\)|\bTimeBounds\(\s*(?:min_time\s*=\s*)?0\s*,\s*(?:max_time\s*=\s*)?0\s*\)|"
                               r"\badd_time_bounds\(\s*0\s*,\s*0\s*\)")
_SIGNS = re.compile(r"\.sign\(|sign_transaction|signTransaction|submit_transaction|submitTransaction|sendTransaction")
_PLAIN_URL = re.compile(r"""["'`](http://([^/"'`\s:]+)[^"'`\s]*)["'`]""")
_RESERVED_HOST = re.compile(r"(?:^|\.)example(?:\.(?:com|net|org))?$|\.(?:invalid|test|example)$", re.I)
_LEDGER_WORDS = re.compile(r"horizon|soroban|stellar|rpc", re.I)
_LOCAL_HOST = re.compile(r"^(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)|\.(?:local|internal|localhost)$", re.I)
_RETRY_DECORATOR = re.compile(r"retry|backoff|tenacity", re.I)
_REBUILD = re.compile(r"\bload_account\(|\bloadAccount\(|TransactionBuilder\(|getAccount\(")
_SUBMIT = re.compile(r"\bsubmit_transaction\(|\bsubmitTransaction\(|\bsendTransaction\(|\bsend_transaction\(")
_JS_RETRY_WRAPPER = re.compile(r"\b(?:pRetry|asyncRetry|retry|backoff|withRetry|retryAsync)\s*\(")
_ATTEMPT_LOOP = re.compile(r"\b(?:for|while)\s*\([^)\n]*\b(?:attempt|retr|tries|tryCount)\w*", re.I)
_ASSET_CODE_CMP = re.compile(
    r"""\b(?:asset_code|assetCode|asset(?:\.|\[["'])code(?:["']\])?)\s*(?:===?|!==?)\s*["'](?!native\b|XLM\b)[A-Za-z0-9]{3,12}["']|"""
    r"""["'](?!native\b|XLM\b)[A-Za-z0-9]{3,12}["']\s*(?:===?|!==?)\s*\b(?:asset_code|assetCode|asset(?:\.|\[["'])code(?:["']\])?)""")
_SECRET_VAR = r"\w*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)\w*"
_DEFAULT_SECRET = re.compile(
    r"\$\{(?P<a>" + _SECRET_VAR + r"):-(?P<av>[^}\s]+)\}"
    r"|process\.env\.(?P<b>" + _SECRET_VAR + r")\s*(?:\|\||\?\?)\s*[\"'`](?P<bv>[^\"'`]+)[\"'`]"
    r"|os\.(?:getenv|environ\.get)\(\s*[\"'](?P<c>" + _SECRET_VAR + r")[\"']\s*,\s*[\"'](?P<cv>[^\"']+)[\"']")
_RECEIPT_CONTEXT = re.compile(r"payment|paid|deposit|incoming|receiv|operations|x402|verify|settle", re.I)


def _block(text: str, start: int, limit: int = 6000) -> str:
    """The brace-delimited block that begins at the first `{` after start."""
    open_at = text.find("{", start, start + 400)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, min(len(text), open_at + limit)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[open_at:i + 1]
    return text[open_at:open_at + limit]


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _commented(text: str, pos: int) -> bool:
    """The match sits in a line comment or a doc-comment line."""
    start = text.rfind("\n", 0, pos) + 1
    return text[start:pos].lstrip().startswith(("//", "#", "*", "/*", "--"))


def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: list[str], remediation: str,
             refs: list[str], auditor: str, *, grade: EvidenceGrade = EvidenceGrade.CONFIRMED, confidence: float = 0.85) -> Finding:
    return Finding(id=fid, dimension=Dimension.SECURITY, severity=severity, title=title, detail=detail,
                   evidence="; ".join(evidence[:6]), evidence_grade=grade, remediation=remediation,
                   references=refs, auditor=auditor, confidence=confidence)


def _tool_descriptions(name: str, text: str) -> list[tuple[int, str]]:
    """Text the model reads as tool documentation: descriptions and @tool docstrings."""
    out = [(_line(text, m.start("text")), m.group("text")) for m in _DESC_PROP.finditer(text)]
    out += [(_line(text, m.start("text")), m.group("text")) for m in _TOOL_CALL_DESC.finditer(text)]
    if name.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return out
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    _TOOL_DECORATOR.search(ast.unparse(d.func if isinstance(d, ast.Call) else d)) for d in node.decorator_list):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    out.append((node.body[0].lineno, doc))
    return out


def analyse_hardening(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    findings: list[Finding] = []
    files = artifact.code_files
    # Rust unit tests live in the same file after #[cfg(test)]; they are not the agent.
    code = {n: (t.split("#[cfg(test)]", 1)[0] if n.endswith(".rs") else t)
            for n, t in files.items() if n.lower().endswith(_CODE)}
    texts = dict(files)
    if artifact.system_prompt:
        texts["<instructions>"] = artifact.system_prompt

    # Hidden characters: instructions a reviewer cannot see but the model reads, or code
    # whose displayed order differs from what runs.
    hidden_tags, hidden_bidi, hidden_zw = [], [], []
    for name, text in texts.items():
        for pattern, bucket in ((_TAGS, hidden_tags), (_BIDI, hidden_bidi), (_ZERO_WIDTH, hidden_zw)):
            match = pattern.search(text)
            if match:
                count = len(pattern.findall(text))
                bucket.append(f"{name}:{_line(text, match.start())} ({count} character{'s' if count > 1 else ''}, "
                              f"first U+{ord(match.group(0)[-1]):04X})")
    if hidden_tags or hidden_bidi:
        findings.append(_finding(
            "security-hidden-unicode", Severity.HIGH,
            "Invisible characters hide text or reorder code",
            "Unicode tag characters carry text that renders as nothing but is read by language models (ASCII "
            "smuggling); bidirectional controls make code display in a different order than it runs (Trojan "
            "Source). Either can hide an instruction or a branch from a human reviewer.",
            hidden_tags + hidden_bidi,
            "Remove the characters (or escape them visibly), and reject them in CI for source, prompts and tool descriptions.",
            ["CVE-2021-42574 Trojan Source", "OWASP LLM01 Prompt Injection"], auditor, confidence=0.95))
    elif hidden_zw:
        findings.append(_finding(
            "security-hidden-unicode", Severity.MEDIUM,
            "Zero-width characters in source or instructions",
            "Zero-width characters make two different strings look identical (an allowlisted name, a recipient label) "
            "and can carry hidden text into a prompt.",
            hidden_zw, "Remove them, or normalize and reject them where names and instructions are compared.",
            ["Unicode TR36 security considerations"], auditor, confidence=0.75))

    # Tool descriptions are instructions to the model; a poisoned one runs with the user's trust.
    poisoned = []
    for name, text in code.items():
        if _TESTLIKE.search(name):
            continue
        for line, desc in _tool_descriptions(name, text):
            for what, pattern in _POISON:
                if pattern.search(desc):
                    poisoned.append(f"{name}:{line} ({what})")
                    break
    for line_no, line in enumerate((artifact.system_prompt or "").splitlines(), 1):
        for what, pattern in _POISON:
            if what in _PROMPT_POISON and pattern.search(line):
                poisoned.append(f"<instructions>:{line_no} ({what})")
    if poisoned:
        findings.append(_finding(
            "security-tool-description-injection", Severity.HIGH,
            "Tool descriptions or instructions carry orders for the model",
            "Text the model reads as tool documentation tells it to hide something from the user, override its rules, "
            "take a step before the tool runs, or read or send secrets. A model follows tool descriptions with the "
            "user's authority (tool poisoning), and the user never sees them.",
            poisoned,
            "Keep tool descriptions to what the tool does and its parameters. Remove instructions, and pin and review "
            "descriptions of third-party tools before they reach the model.",
            ["MCP tool poisoning", "OWASP LLM01 Prompt Injection"], auditor, confidence=0.88))

    # Credentials committed with the source.
    leaked = list(artifact.raw_metadata.get("committed_credentials") or [])
    for name, text in files.items():
        leaked += find_credentials(name, text.encode("utf-8", "ignore"))
    leaked = list(dict.fromkeys(leaked))
    if leaked:
        test_only = all(_TESTLIKE.search(item.split(":", 1)[0]) for item in leaked)
        findings.append(_finding(
            "security-committed-credential", Severity.MEDIUM if test_only else Severity.HIGH,
            "A live-looking credential is committed to the repository",
            "An API key, token or private key is in the repository. Anyone with read access, and every fork and "
            "clone, has it; an AI provider key lets others run up the bill or read the agent's traffic."
            + (" Only in test or example files." if test_only else ""),
            leaked, "Revoke and rotate the credential now, remove it from history, and load it from the environment or a secret manager.",
            ["CWE-798 Use of Hard-coded Credentials"], auditor, confidence=0.9))

    signing_files = {n for n, t in code.items() if _SIGNS.search(t)}

    # Signed transactions with no expiry: a held or leaked envelope stays valid forever.
    forever = [f"{n}:{_line(t, m.start())}" for n, t in code.items() if n in signing_files
               for m in _INFINITE_TIMEOUT.finditer(t) if not _commented(t, m.start())]
    if forever:
        findings.append(_finding(
            "security-transaction-never-expires", Severity.MEDIUM,
            "Signed transactions are built without an expiry",
            "The transaction's time bounds are infinite (timeout 0). An envelope that is signed but not submitted at "
            "once — after a timeout, in a queue, in a log or with a relayer — can be submitted at any later time, "
            "long after the user or the agent decided otherwise.",
            forever, "Set a short timeout (for example 30 to 180 seconds) on every transaction the agent signs.",
            ["Stellar transaction time bounds"], auditor, confidence=0.9))

    # Ledger traffic without TLS: whoever is on the path chooses the simulation the agent signs.
    # A host without a dot is a container or LAN name (http://stellar:8000), not the internet.
    plain = [f"{n}:{_line(t, m.start())} ({m.group(1)[:60]})" for n, t in code.items() for m in _PLAIN_URL.finditer(t)
             if not _commented(t, m.start()) and "." in m.group(2) and not _LOCAL_HOST.search(m.group(2)) and not _RESERVED_HOST.search(m.group(2))
             and _LEDGER_WORDS.search(m.group(1))]
    if plain:
        findings.append(_finding(
            "security-ledger-endpoint-plain-http", Severity.MEDIUM if signing_files else Severity.LOW,
            "A Horizon or RPC server is reached over plain HTTP",
            "Responses from Horizon or Soroban RPC (balances, sequence numbers, simulations and authorization entries) "
            "travel unencrypted. Anyone on the network path can change them, and the agent signs what the simulation returns.",
            plain, "Use https:// endpoints for any server not on the same machine.",
            ["CWE-319 Cleartext Transmission"], auditor, confidence=0.85))

    # A retry that rebuilds the transaction: if the first one landed despite the error, it pays twice.
    double = []
    for name, text in code.items():
        if name.endswith(".py"):
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                body = None
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                        _RETRY_DECORATOR.search(ast.unparse(d)) for d in node.decorator_list):
                    body = node
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and re.search(
                        r"attempt|retr|tries", ast.unparse(node.target if isinstance(node, (ast.For, ast.AsyncFor)) else node.test), re.I):
                    body = node
                if body is not None:
                    src = ast.unparse(body)
                    if _REBUILD.search(src) and _SUBMIT.search(src):
                        double.append(f"{name}:{node.lineno}")
        else:
            for pattern in (_JS_RETRY_WRAPPER, _ATTEMPT_LOOP):
                for m in pattern.finditer(text):
                    # Only the retried block itself: rebuilding and submitting must both repeat.
                    window = _block(text, m.end())
                    if _REBUILD.search(window) and _SUBMIT.search(window):
                        double.append(f"{name}:{_line(text, m.start())}")
                        break
    if double:
        findings.append(_finding(
            "security-retry-may-pay-twice", Severity.MEDIUM,
            "A failed submission is retried with a newly built transaction",
            "The retry reloads the account and builds a new transaction. A submission that timed out may still have "
            "been applied; the rebuilt transaction gets the next sequence number and is applied too, so the payment "
            "is made twice.",
            double, "On a timeout, resubmit the same signed envelope or look it up by hash; build a new one only after "
            "the first is known to have failed (expired time bounds or a bad sequence number).",
            ["Stellar transaction submission and timeouts"], auditor, grade=EvidenceGrade.INFERRED, confidence=0.7))

    # Incoming payments checked by asset code only: anyone can issue a token with that code.
    by_code = []
    for name, text in code.items():
        if not _RECEIPT_CONTEXT.search(text):
            continue
        lines = text.splitlines()
        for m in _ASSET_CODE_CMP.finditer(text):
            if _commented(text, m.start()):
                continue
            line = _line(text, m.start())
            near = "\n".join(lines[max(0, line - 13):line + 12])
            # The agent's own balances only hold trustlines it opened; an incoming payment
            # record carries whatever asset the sender chose.
            close = "\n".join(lines[max(0, line - 4):line + 1])
            if not re.search(r"issuer", near, re.I) and not re.search(r"balance", close, re.I) \
                    and re.search(r"\b(?:payment|operation|record|transfer|from|deposit|received?)\b", near, re.I):
                by_code.append(f"{name}:{line}")
    if by_code:
        findings.append(_finding(
            "security-asset-checked-by-code-only", Severity.HIGH,
            "A payment is accepted by asset code without checking the issuer",
            "The code compares an asset's code (for example \"USDC\") but not its issuer. Anyone can issue an asset "
            "with any code, so a payment in a worthless look-alike passes the check.",
            by_code, "Compare code and issuer together against a configured asset (Asset.equals, or both fields).",
            ["Stellar assets and issuers"], auditor, confidence=0.8))

    # Soroban contracts whose release build wraps on overflow.
    manifests = {n: t for n, t in files.items() if n.endswith("Cargo.toml")}
    soroban = [n for n, t in manifests.items() if re.search(r"^\s*soroban-sdk\s*=", t, re.M)]
    if soroban and not any(re.search(r"^\s*overflow-checks\s*=\s*true", t, re.M) for t in manifests.values()):
        findings.append(_finding(
            "security-soroban-overflow-unchecked", Severity.MEDIUM,
            "Soroban contract arithmetic can wrap around in release builds",
            "The contract crate does not enable overflow-checks for its release profile. Without it, an addition or "
            "multiplication that overflows wraps silently instead of trapping, so balances, limits and counters can "
            "come out as small or negative numbers.",
            soroban, "Add overflow-checks = true under [profile.release] in the workspace Cargo.toml, or use checked arithmetic.",
            ["Soroban contract build profile", "CWE-190"], auditor, grade=EvidenceGrade.INFERRED, confidence=0.75))
    # A secret that falls back to a fixed value: unset in production, the shipped default is the key.
    defaults = []
    for name, text in files.items():
        if _TESTLIKE.search(name) and not re.search(r"(^|/)docker-compose[^/]*\.ya?ml$", name):
            continue
        for m in _DEFAULT_SECRET.finditer(text):
            var = m.group("a") or m.group("b") or m.group("c")
            value = m.group("av") or m.group("bv") or m.group("cv")
            # A public key, an asset contract or a YOUR_... template placeholder is not a usable secret.
            if (re.search(r"PUBLIC|ADDRESS|CONTRACT|ASSET|USDC|EURC|XLM|_ID$", var, re.I) or re.fullmatch(r"[GC][A-Z2-7]{55}", value)
                    or re.match(r"(?i)your[_-]|<|x{4,}", value) or _commented(text, m.start())):
                continue
            defaults.append(f"{name}:{_line(text, m.start())} {var}")
    if defaults:
        findings.append(_finding(
            "security-default-secret", Severity.MEDIUM,
            "A secret falls back to a fixed value when it is not configured",
            "When the variable is missing, the code or deployment file uses the value written in the repository. "
            "Anyone who reads the repository then holds the admin key, token or password of every deployment "
            "that forgot to set it.",
            defaults, "Fail at startup when the secret is unset instead of falling back to a default.",
            ["CWE-1188 Insecure Default Initialization of Resource", "CWE-798"], auditor, confidence=0.85))
    return findings
