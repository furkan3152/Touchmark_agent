"""File-level checks for weaknesses that are not an input-to-sink flow.

Each check looks for one concrete defect with a known exploit: instructions hidden in
text the model reads, credentials committed to the repository, signed transactions that
never expire, ledger traffic without TLS, retries that pay twice, payments accepted by
asset code alone, payment addresses, assets and amounts that are wrong by construction
(asset_rules.py) and Soroban arithmetic that wraps. They report locations, never the
secret or the hidden text itself.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity
from .asset_rules import AssetRules, asset_findings
from .consolidate import stable_id
from .codeflow import unparse
from .sdk_rules import hardening_evidence
from .source_index import EXAMPLE_PATH

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
#: Where the Stellar CLI keeps identities: `<config>/identity/<name>.toml`, with the config
#: directory `.stellar` in a project or `~/.config/stellar` (stellar-cli config/locator.rs).
#: A `secret_key` there is an S... seed, which the committed-seed check already reports.
_CLI_IDENTITY = re.compile(r"(?:^|/)(?:\.stellar|\.config/stellar)/identity/[^/]+\.toml$")
_SEED_PHRASE = re.compile(rb"""^\s*seed_phrase\s*=\s*["']([a-z ]{20,})["']""", re.M)
#: A credential kind whose account and network are not known from the file alone.
CLI_SEED_PHRASE = "Stellar CLI identity seed phrase"


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
    if _CLI_IDENTITY.search(name):
        from stellar_sdk.sep.mnemonic import Language, StellarMnemonic
        for match in _SEED_PHRASE.finditer(data):
            words = match.group(1).decode().split()
            # Placeholders fail the checksum, or repeat one word (which passes it 1 time in 16).
            if len(set(words)) > len(words) // 2 and StellarMnemonic(Language.ENGLISH).check(" ".join(words)):
                line = data[:match.start()].count(b"\n") + 1
                found.append(f"{name}:{line} ({CLI_SEED_PHRASE}, redacted)")
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
_SECRET_VAR = r"\w*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)\w*"
_DEFAULT_SECRET = re.compile(
    r"\$\{(?P<a>" + _SECRET_VAR + r"):-(?P<av>[^}\s]+)\}"
    r"|process\.env\.(?P<b>" + _SECRET_VAR + r")\s*(?:\|\||\?\?)\s*[\"'`](?P<bv>[^\"'`]+)[\"'`]"
    r"|os\.(?:getenv|environ\.get)\(\s*[\"'](?P<c>" + _SECRET_VAR + r")[\"']\s*,\s*[\"'](?P<cv>[^\"']+)[\"']")
#: mppx binds its payment challenges with an HMAC under `secretKey`; whoever knows the key
#: can mint challenges the server accepts (mppx server/Mppx.js).
_MPPX_SERVER_IMPORT = re.compile(r"""["'](?:mppx/(?:server|express|hono|nextjs|elysia)|@stellar/mpp/(?:charge|channel)/server)["']""")
_MPPX_CREATE = re.compile(r"\bMppx\.create\s*\(")
_SECRET_KEY_OPTION = re.compile(r"\bsecretKey\s*:\s*(?P<expr>[^,\n}]+)")
#: A non-empty literal the key falls back to. An empty one fails closed: mppx refuses a
#: falsy secretKey at start-up ("Missing secret key", mppx server/Mppx.js).
_FALLBACK_LITERAL = re.compile(r"""(?:^|\?\?|\|\|)\s*(?P<q>["'`])(?P<value>[^"'`$]+)(?P=q)\s*$""")
_HTML_SINK = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?P<rhs>[^;\n]+)|\.insertAdjacentHTML\([^,]+,\s*(?P<arg>[^)\n]+)"
                        r"|dangerouslySetInnerHTML=\{\{\s*__html:\s*(?P<react>[^}\n]+)")
_DYNAMIC = re.compile(r"\$\{|[\"'`]\s*\+\s*[A-Za-z_$]|\+\s*[A-Za-z_$]")
_FUNCTION_HEAD = re.compile(r"(?:function\s+(?P<a>[\w$]+)\s*\((?P<ap>[^)]*)\)|(?:const|let|var)\s+(?P<b>[\w$]+)\s*=\s*"
                            r"(?:async\s*)?\((?P<bp>[^)]*)\)\s*=>)")
_ESCAPED = re.compile(r"escape|sanitiz|DOMPurify|purify|encode|marked\.parse|textContent", re.I)


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


def _wrapped_sink(text: str, pos: int, value: str) -> bool:
    """`function add(html) { el.innerHTML = html }` called as add(`...${input}`): the sink
    takes its parameter, and a caller in the same file builds it from a dynamic value."""
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", value):
        return False
    heads = [h for h in _FUNCTION_HEAD.finditer(text, max(0, pos - 3000), pos)]
    if not heads:
        return False
    head = heads[-1]
    fn, params = head.group("a") or head.group("b"), head.group("ap") or head.group("bp") or ""
    if value not in re.findall(r"[A-Za-z_$][\w$]*", params):
        return False
    return any(_DYNAMIC.search(call.group(1)) and not _ESCAPED.search(call.group(1))
               for call in re.finditer(r"\b" + re.escape(fn) + r"\(([^\n]*)", text))


def _mppx_secrets(name: str, text: str) -> tuple[list[str], list[tuple[int, str]]]:
    """In an MPP server, the `secretKey` options that fall back to a value written in the
    repository (as default-secret evidence), and those that are also the Stellar seed
    passed to Keypair.fromSecret (line, code)."""
    defaults: list[str] = []
    reuse: list[tuple[int, str]] = []
    if not _MPPX_SERVER_IMPORT.search(text):
        return defaults, reuse
    lines = text.splitlines()
    for call in _MPPX_CREATE.finditer(text):
        open_at = call.end() + len(text[call.end():]) - len(text[call.end():].lstrip())
        if text[open_at:open_at + 1] != "{":
            continue  # options passed by name: not read here
        block = _block(text, open_at)
        for option in _SECRET_KEY_OPTION.finditer(block):
            expr = option.group("expr").strip()
            at = open_at + option.start("expr")
            if _commented(text, at):
                continue
            target, target_at = expr, at
            named = re.fullmatch(r"[A-Za-z_$][\w$]*", expr)
            if named:
                declared = re.search(r"\b(?:const|let|var)\s+" + re.escape(expr) + r"\s*(?::[^=\n]+)?=\s*([^;\n]+)", text)
                if declared:
                    target, target_at = declared.group(1).strip(), declared.start(1)
            if _FALLBACK_LITERAL.search(target):
                defaults.append(f"{name}:{_line(text, target_at)} secretKey")
            key = expr if named or re.fullmatch(r"process\.env\.\w+", expr) else ""
            if key and re.search(r"\bfromSecret\(\s*" + re.escape(key) + r"\s*[,)]", text):
                line = _line(text, at)
                reuse.append((line, lines[line - 1] if line <= len(lines) else expr))
    return defaults, reuse


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
                    _TOOL_DECORATOR.search(unparse(d.func if isinstance(d, ast.Call) else d)) for d in node.decorator_list):
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
        # A CLI identity's account and network are unknown here (ledger triage raises it);
        # on its own it is reported at medium.
        cli_only = all(CLI_SEED_PHRASE in item for item in leaked)
        findings.append(_finding(
            "security-committed-credential", Severity.MEDIUM if test_only or cli_only else Severity.HIGH,
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
    # The Python SDK builds an envelope with no time bounds when none are set (it only warns).
    sdk_evidence = hardening_evidence(artifact)
    unbounded = sdk_evidence["no_expiry"]
    if forever or unbounded:
        findings.append(_finding(
            "security-transaction-never-expires", Severity.MEDIUM if forever else Severity.LOW,
            "Signed transactions are built without an expiry",
            ("The transaction's time bounds are infinite (timeout 0). " if forever else
             "The transaction is built with no time bounds (stellar_sdk TransactionBuilder.build() only warns). ")
            + "An envelope that is signed but not submitted at "
            "once — after a timeout, in a queue, in a log or with a relayer — can be submitted at any later time, "
            "long after the user or the agent decided otherwise.",
            forever + unbounded, "Set a short timeout (for example 30 to 180 seconds) on every transaction the agent signs.",
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
                        _RETRY_DECORATOR.search(unparse(d)) for d in node.decorator_list):
                    body = node
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and re.search(
                        r"attempt|retr|tries", unparse(node.target if isinstance(node, (ast.For, ast.AsyncFor)) else node.test), re.I):
                    body = node
                if body is not None:
                    src = unparse(body)
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
    # The same defect without a loop: the failure handler of a send frees the reservation or budget
    # it held, or a paid x402 request is repeated, although the payment may have gone through.
    released = sdk_evidence["released"]
    if double or released:
        findings.append(_finding(
            "security-retry-may-pay-twice", Severity.MEDIUM,
            "A failed submission is retried with a newly built transaction" if double else
            "A payment that may have gone through is treated as not made",
            ("The retry reloads the account and builds a new transaction. A submission that timed out may still have "
             "been applied; the rebuilt transaction gets the next sequence number and is applied too, so the payment "
             "is made twice. " if double else "")
            + ("An error raised after the transaction or paid request was sent (a timeout, a failed poll, an error "
               "response after settlement) releases the reservation, claim or budget held for it, or repeats the paid "
               "request, without checking whether the first one landed. The next attempt pays again." if released else ""),
            double + released, "On a timeout, resubmit the same signed envelope or look it up by hash; build a new one "
            "(or release what was reserved) only after the first is known to have failed (expired time bounds or a "
            "bad sequence number). Keep a flag set just before sending and release only while it is unset.",
            ["Stellar transaction submission and timeouts"], auditor, grade=EvidenceGrade.INFERRED, confidence=0.7))

    # Incoming payments checked by asset code only: anyone can issue a token with that code. Only
    # receipt and verification code that reads ledger records counts; the agent's own balances
    # only hold trustlines it opened. An `||` with a full-asset comparison is the same bypass.
    assets = AssetRules(artifact)
    by_code = assets.code_only_checks()
    if by_code:
        literal = any(item[3] for item in by_code)
        severity = Severity.HIGH if literal else Severity.MEDIUM
        if all(EXAMPLE_PATH.search(item[0]) for item in by_code):  # templates and examples drop one level
            severity = Severity.MEDIUM if literal else Severity.LOW
        findings.append(_finding(
            "security-asset-checked-by-code-only", severity,
            "A payment is accepted by asset code without checking the issuer",
            "The code compares an asset's code (for example \"USDC\") but not its issuer. Anyone can issue an asset "
            "with any code, so a payment in a worthless look-alike passes the check."
            + ("" if literal else " Here the code is compared with a configured value, so the bypass works whenever "
               "that value is a bare code."),
            [f"{path}:{line} `{snippet[:120]}`" for path, line, snippet, _ in by_code],
            "Compare code and issuer together against a configured asset (Asset.equals, or both fields).",
            ["Stellar assets and issuers"], auditor, confidence=0.8))
    findings += asset_findings(assets, lambda fid, severity, title, detail, evidence, remediation, refs: _finding(
        fid, severity, title, detail, evidence, remediation, refs, auditor, confidence=0.85))

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
    # Text written into the page as HTML: model output, a fetched reply or user input becomes
    # markup, so a crafted reply runs script in the page (and in a wallet page, reaches keys).
    sinks = []
    for name, text in files.items():
        if not name.lower().endswith((".js", ".mjs", ".ts", ".tsx", ".jsx", ".html", ".vue", ".svelte")) or _TESTLIKE.search(name):
            continue
        for m in _HTML_SINK.finditer(text):
            value = (m.group("rhs") or m.group("arg") or m.group("react") or "").strip()
            if _ESCAPED.search(value) or _commented(text, m.start()):
                continue
            if _DYNAMIC.search(value) or _wrapped_sink(text, m.start(), value):
                sinks.append(f"{name}:{_line(text, m.start())}")
    if sinks:
        findings.append(_finding(
            "security-html-injection", Severity.LOW,
            "Dynamic text is written into the page as HTML",
            "A value built at run time is assigned to innerHTML (or an equivalent) without escaping. If it carries "
            "model output, a fetched reply or user input, markup in it runs as script in the page.",
            sinks, "Use textContent, or escape or sanitize (DOMPurify) the value before inserting it as HTML.",
            ["CWE-79", "OWASP LLM05 Improper Output Handling"], auditor, grade=EvidenceGrade.INFERRED, confidence=0.7))

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
    # An MPP server's challenge key with a fallback value: the same defect, one finding.
    reused = []
    for name, text in code.items():
        if _TESTLIKE.search(name):
            continue
        mpp_defaults, mpp_reuse = _mppx_secrets(name, text)
        defaults += [d for d in mpp_defaults if not any(e.split(" ", 1)[0] == d.split(" ", 1)[0] for e in defaults)]
        reused += [(name, line, snippet) for line, snippet in mpp_reuse]
    if defaults:
        findings.append(_finding(
            "security-default-secret", Severity.MEDIUM,
            "A secret falls back to a fixed value when it is not configured",
            "When the variable is missing, the code or deployment file uses the value written in the repository. "
            "Anyone who reads the repository then holds the admin key, token or password of every deployment "
            "that forgot to set it.",
            defaults, "Fail at startup when the secret is unset instead of falling back to a default.",
            ["CWE-1188 Insecure Default Initialization of Resource", "CWE-798"], auditor, confidence=0.85))
    # Rust clients that sign Soroban authorization entries: how long each signature stays valid.
    from .auth_rules import rust_expiration_hits
    for name, line, snippet, expiry in rust_expiration_hits(code):
        findings.append(_finding(
            stable_id("security-auth-expiration-wide", name, snippet),
            expiry.severity.downgrade(1) if _TESTLIKE.search(name) else expiry.severity,
            "Signed authorizations stay valid longer than needed",
            "A signed Soroban authorization entry can be submitted by whoever holds it until its "
            f"signature_expiration_ledger; {expiry.note}.",
            [f"{name}:{line} `{' '.join(snippet.split())[:160]}`"],
            "Expire entries a few minutes ahead, and cap any timeout the counterparty names against a constant.",
            ["Soroban authorization", "x402 Stellar exact scheme"], auditor, grade=EvidenceGrade.INFERRED, confidence=0.8))
    by_file: dict[str, list[tuple[int, str]]] = {}
    for name, line, snippet in reused:
        by_file.setdefault(name, []).append((line, snippet))
    for name, places in by_file.items():  # one finding per file: the same lines would share an id
        findings.append(_finding(
            stable_id("security-mpp-secret-reuses-stellar-seed", name, places[0][1]), Severity.LOW,
            "The MPP challenge key is the agent's Stellar seed",
            "The value that signs MPP payment challenges is also the secret seed of a Stellar account. The seed then "
            "sits in a second subsystem (HMAC keys are logged, rotated and shared differently from signing keys), and "
            "rotating one forces rotating the other.",
            [f"{name}:{line} `{' '.join(snippet.split())[:160]}`" for line, snippet in places[:5]],
            "Give the MPP server its own random secret of at least 32 bytes.",
            ["CWE-323 Reusing a Nonce, Key Pair in Encryption", "MPP challenge binding"], auditor, confidence=0.85))
    return findings
