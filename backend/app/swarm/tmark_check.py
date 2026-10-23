"""Compare what a repository's .tmark declares with what its code does.

A declaration never closes a risk. It turns a vague question ("is this safe?") into
specific claims (testnet only, recipients from an allowlist, a human approves each
payment) that the code either keeps or breaks; a broken claim is reported as such.
"""

from __future__ import annotations

import io
import re
import tokenize
from bisect import bisect_left, bisect_right

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity
from ..stellar.canonical import NETWORK_MARKERS
from .network_rules import MAINNET_REACHABLE, mask, network_hits as binding_hits

#: Signing against the public network: its passphrase, the SDK constants for it, its CAIP-2 id,
#: the mainnet USDC issuer and contracts, and the mainnet x402 facilitator.
_MAINNET = re.compile(r"Networks\.PUBLIC\b|Network\.PUBLIC_NETWORK_PASSPHRASE|PUBLIC_NETWORK_PASSPHRASE|"
                      r"mainnet\.sorobanrpc|channels\.openzeppelin\.com/x402(?!/testnet)|"
                      + "|".join(re.escape(m) for m in NETWORK_MARKERS["mainnet"]))
#: The same markers for testnet.
_TESTNET = re.compile(r"Networks\.TESTNET\b|TESTNET_NETWORK_PASSPHRASE|channels\.openzeppelin\.com/x402/testnet|"
                      + "|".join(re.escape(m) for m in NETWORK_MARKERS["testnet"]))
#: Code that can still pick mainnet without a constant: a network-name string, or the network
#: or passphrase read from the environment.
_CHOOSES_NETWORK = re.compile(r"""["'`](?:mainnet|pubnet|public)["'`]|"""
                              r"(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|env::var)\W{0,3}[\w.]{0,40}"
                              r"(?:NETWORK|PASSPHRASE|HORIZON|RPC)", re.I)
#: A value or key in an object, map or match keyed by network name. The key starts where a
#: name starts: an unanchored [\w.]* would retry at every character of a long run (minified
#: code, a hex blob) before each marker.
_NET_KEY = r"""(?:(?<![\w.])[\w.]*(?:main_?net|pub_?net|public|production)\w*|stellar:pubnet)"""
_VALUE_START = r"""\s*(?:\w+\(\s*)?["'`]?(?:[a-z]+://)?[\w.-]*$"""
# The colon follows the key directly: `cond ? A : B` is a ternary, not a key and a value.
_AS_VALUE = re.compile(_NET_KEY + r"""["'`\]]?(?::|\s*=>)""" + _VALUE_START, re.I)
_AS_MAP_VALUE = re.compile(r"""\[\s*["'`]?""" + _NET_KEY + r"""["'`]?\s*,""" + _VALUE_START, re.I)
_AS_KEY = re.compile(r"""^["'`]?\]?(?::|\s*=>)""")
_AS_MAP_KEY = (re.compile(r"""\[\s*["'`]?$"""), re.compile(r"""^["'`]?\s*,"""))
#: A block opened under a network key: `mainnet: {`, `"stellar:pubnet": {`, `Network::Mainnet => {`.
_AS_BLOCK = re.compile(_NET_KEY + r"""["'`\]]?\s*(?::|=>|=)\s*(?:\w+\s*\(\s*)?$""", re.I)
_TESTNET_SIBLING = re.compile(r"""(?:testnet|futurenet)\w*["'`\]]?\s*(?::|=>|,)""", re.I)
#: How far before a match its key is looked for, and around a network block its testnet sibling.
_KEY_REACH, _BLOCK_REACH = 200, 1500
_CODE = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".mts", ".cts", ".rs")
#: A guard that refuses a network is not a use of it: the marker is one side of an equality
#: in an `if` whose branch starts by failing (logging first is allowed). `&&`/`and` or a negation
#: make the refusal conditional, so such a condition is still a use; so is `!=`, which refuses
#: every other network. The guard is looked for this many characters around the marker.
_REFUSAL_REACH = 300
_IF = re.compile(r"\bif\b")
#: The marker (or the URL string it is in) right after or right before `==` / `===`.
_EQUALS_BEFORE = re.compile(r"""(?<![!<>=])={2,3}\s*["'`]?[^"'`\s()!=]*$""")
_EQUALS_AFTER = re.compile(r"""^[^"'`\s()!=]*["'`]?\s*={2,3}(?!=)""")
#: One statement of the branch, a condition that makes the refusal conditional, logging, and
#: the statements that fail. A statement is read from its first visible character, so a run of
#: blanks with no statement in it costs one look per blank.
_STATEMENT = re.compile(r"[^;\n\s][^;\n]*")
_CONDITIONAL = re.compile(r"&&|!(?!=)|\band\b|\bnot\b")
_LOGS = re.compile(r"^\s*(?:(?:console|logger|log|logging)\s*\.\s*\w+|print|e?println!|(?:log::)?(?:warn|error)!)\s*\(")
_FAILS = re.compile(r"^\s*(?:throw\b|raise\b|panic!|panic_with_error!|bail!|return\s+(?:Err\s*\(|Promise\s*\.\s*reject\b|"
                    r"""new\s+\w*Error\b|\w*Error\s*\()|(?:process|sys)\s*\.\s*exit\s*\(\s*(?:[1-9]|["']))""")
#: How each network-binding rule lets mainnet in (network_rules.MAINNET_REACHABLE).
_CHOOSES_MAINNET = {"security-network-chosen-per-call": "a tool argument picks the network",
                    "security-network-chosen-by-counterparty": "the paid server's challenge picks the network",
                    "security-network-fallback-mainnet": "unrecognised values fall back to mainnet"}
#: What the code can do, against what .tmark says the agent signs.
_SIGNS_FOR = {"payment": "payments", "contract_invocation": "contract_calls", "account_control": "account_changes",
              "foreign_tx_signing": "foreign_transactions"}


def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: str, remediation: str,
             auditor: str, grade: EvidenceGrade = EvidenceGrade.CONFIRMED, confidence: float = 0.85) -> Finding:
    return Finding(id=fid, dimension=Dimension.INTENT, severity=severity, title=title, detail=detail,
                   evidence=evidence, evidence_grade=grade, remediation=remediation,
                   references=[".tmark v1 (docs/TMARK.md)"], auditor=auditor, confidence=confidence)


class _Blocks:
    """The innermost '{' open at any offset of a file, from one pass over its braces, and
    whether that block is opened under a network key with a testnet sibling nearby. Siblings
    are found in one pass too, so nested keyed blocks do not each rescan what they enclose."""

    def __init__(self, text: str):
        self.text, self.positions, self.openers, self.closes, self.keyed = text, [], [], {}, {}
        self.siblings: list[tuple[int, int]] | None = None
        stack: list[int] = []
        for m in re.finditer(r"[{}]", text):
            if m.group() == "{":
                stack.append(m.start())
            elif stack:
                self.closes[stack.pop()] = m.start()
            self.positions.append(m.start())
            self.openers.append(stack[-1] if stack else -1)

    def network_block(self, offset: int) -> bool:
        k = bisect_right(self.positions, offset - 1) - 1
        brace = self.openers[k] if k >= 0 else -1
        if brace < 0:
            return False
        if brace not in self.keyed:
            close = self.closes.get(brace, len(self.text))
            self.keyed[brace] = (bool(_AS_BLOCK.search(self.text[max(0, brace - _KEY_REACH):brace]))
                                 and self._sibling(max(0, brace - _BLOCK_REACH), close + _BLOCK_REACH))
        return self.keyed[brace]

    def _sibling(self, start: int, end: int) -> bool:
        """A testnet sibling key lies within [start, end)."""
        if self.siblings is None:
            self.siblings = [(m.start(), m.end()) for m in _TESTNET_SIBLING.finditer(self.text)]
        k = bisect_left(self.siblings, (start, -1))
        return k < len(self.siblings) and self.siblings[k][1] <= end


def _network_keyed(text: str, start: int, end: int, line_start: int, blocks: _Blocks) -> bool:
    """The match is a key or value of a map that lists networks side by side
    ({'stellar:pubnet': ..., 'stellar:testnet': ...}), or sits in a block opened under a network
    key (mainnet: { horizonUrl: ... }, testnet: { ... }): the code serves each network it names,
    and the one it uses is chosen elsewhere. Only a bounded stretch of the line is read, so a
    long minified line costs no more than a short one."""
    newline = text.find("\n", end, end + _KEY_REACH)
    before = text[max(line_start, start - _KEY_REACH):start]
    after = text[end:newline if newline >= 0 else end + _KEY_REACH]
    keyed = (bool(_AS_KEY.match(after)) or bool(_AS_VALUE.search(before)) or bool(_AS_MAP_VALUE.search(before))
             or (bool(_AS_MAP_KEY[0].search(before)) and bool(_AS_MAP_KEY[1].match(after))))
    if keyed and _TESTNET_SIBLING.search(text, max(0, start - 400), end + 400):
        return True
    return blocks.network_block(start)


def _without_docstrings(code: str) -> str:
    """Blank Python string statements (docstrings and other bare string literals), keeping
    offsets: they are text, not code. Source that does not tokenize is returned unchanged."""
    starts = [0]
    for line in code.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    spans, statement, previous = [], [], tokenize.NEWLINE
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type in (tokenize.NL, tokenize.COMMENT):
                continue
            if tok.type == tokenize.STRING and (statement or previous in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)):
                statement.append(tok)
            elif tok.type in (tokenize.NEWLINE, tokenize.ENDMARKER) and statement:
                spans += [(starts[t.start[0] - 1] + t.start[1], starts[t.end[0] - 1] + t.end[1]) for t in statement]
                statement = []
            else:
                statement = []
            previous = tok.type
    except (tokenize.TokenError, SyntaxError):
        return code
    out = list(code)
    for start, end in spans:
        for k in range(start, min(end, len(out))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _masked(name: str, text: str) -> tuple[str, str]:
    """(code, skeleton): comments blanked in both, Python docstrings too, and string contents
    also blanked in the skeleton; offsets are kept, so line numbers stay true."""
    python = name.endswith(".py")
    code, skel = mask(text, python=python)
    return (_without_docstrings(code) if python else code), skel


def _closing(skel: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for i in range(start, min(len(skel), start + 4 * _REFUSAL_REACH)):
        depth += (skel[i] == opening) - (skel[i] == closing)
        if depth == 0:
            return i
    return -1


def _fails_first(skel: str) -> bool:
    """The branch's first statement that is not logging makes it fail."""
    for statement in _STATEMENT.finditer(skel):
        if not _LOGS.match(statement.group()):
            return bool(_FAILS.match(statement.group()))
    return False


def _python_if(skel: str, line_start: int) -> tuple[int, int, bool] | None:
    """The `if` or `elif` that opens the line at ``line_start``: where its condition lies, and
    whether the condition is unconditional and the branch starts by failing. None when the line
    opens no `if`. Read once per line, so many markers on one long line cost one read of it."""
    line_end = skel.find("\n", line_start)
    line_end = len(skel) if line_end < 0 else line_end
    m = re.match(r"(\s*)(?:el)?if\b(.*?):(.*)$", skel[line_start:line_end])
    if not m:
        return None
    condition, branch, indent = m.group(2), m.group(3)[:4 * _REFUSAL_REACH], len(m.group(1))
    if not branch.strip():  # the branch is the indented block below
        rest = []
        for line in skel[line_end + 1:line_end + 1 + 4 * _REFUSAL_REACH].split("\n"):
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            rest.append(line)
        branch = "\n".join(rest)
    refuses = not _CONDITIONAL.search(re.sub(r"!==?", "", condition)) and _fails_first(branch)
    return line_start + m.start(2), line_start + m.end(2), refuses


def _refused(code: str, skel: str, start: int, end: int, python: bool, rust: bool,
             line_start: int = -1, lines: dict | None = None) -> bool:
    """The match at [start, end) is a guard that refuses its network (see _REFUSAL_REACH).
    ``line_start`` is where the match's line starts, and ``lines`` caches _python_if per line."""
    if python:
        line_start = code.rfind("\n", 0, start) + 1 if line_start < 0 else line_start
        lines = {} if lines is None else lines
        if line_start not in lines:
            lines[line_start] = _python_if(skel, line_start)
        guard = lines[line_start]
        if not guard or not (guard[0] <= start and end <= guard[1]) or not guard[2]:
            return False
        before, after_text = code[max(0, start - 80):start], code[end:end + 80]  # operator and URL prefix
        return bool(_EQUALS_BEFORE.search(before)) or bool(_EQUALS_AFTER.match(after_text))
    else:
        ifs = [m for m in _IF.finditer(skel, max(0, start - _REFUSAL_REACH), start)]
        if not ifs:
            return False
        head = ifs[-1].end()
        if rust:
            brace = skel.find("{", end, end + _REFUSAL_REACH)
            if brace < 0 or re.search(r"[;{}]", skel[head:brace]):
                return False
            condition, after = skel[head:brace], brace
        else:
            opening = skel.find("(", head, head + 40)
            if opening < 0 or skel[head:opening].strip():
                return False
            close = _closing(skel, opening, "(", ")")
            if close < end:
                return False
            condition, after = skel[opening + 1:close], close + 1
            while after < len(skel) and skel[after] in " \t\r\n":
                after += 1
        window = skel[after:after + 4 * _REFUSAL_REACH]
        if window.startswith("{"):
            close = _closing(skel, after, "{", "}")
            branch = window[1:close - after if close > 0 else len(window)]
        else:
            stop = re.search(r"[;\n]", window)
            branch = window[:stop.end() if stop else len(window)]
    if _CONDITIONAL.search(re.sub(r"!==?", "", condition)):
        return False
    before, after_text = code[max(0, start - 80):start], code[end:end + 80]  # operator and URL prefix
    operand = bool(_EQUALS_BEFORE.search(before)) or bool(_EQUALS_AFTER.match(after_text))
    return operand and _fails_first(branch)


def network_hits(files: dict[str, str], pattern: re.Pattern, skip_keyed: bool = True) -> list[str]:
    """First file:line per code file where ``pattern`` names a network in code: not in a
    comment or a Python docstring, not in a guard that refuses it, and (with ``skip_keyed``)
    not in a network-keyed map. Only a file the pattern matches at all is masked."""
    hits = []
    for name, text in files.items():
        if not name.endswith(_CODE) or not pattern.search(text):
            continue
        code, skel = _masked(name, text)
        line_start, scanned, blocks, lines = 0, 0, None, {}
        for m in pattern.finditer(code):
            newline = code.rfind("\n", scanned, m.start())
            line_start, scanned = (newline + 1 if newline >= 0 else line_start), m.start()
            if skip_keyed:
                blocks = blocks or _Blocks(code)
                if _network_keyed(code, m.start(), m.end(), line_start, blocks):
                    continue
            if _refused(code, skel, m.start(), m.end(), name.endswith(".py"), name.endswith(".rs"), line_start, lines):
                continue
            hits.append(f"{name}:{code.count(chr(10), 0, m.start()) + 1}")
            break
    return hits


def tmark_findings(artifact: AgentArtifact, auditor: str) -> list[Finding]:
    info = artifact.raw_metadata.get("tmark") or {}
    status = info.get("status")
    if status == "invalid":
        return [_finding(
            "intent-tmark-invalid", Severity.MEDIUM, "The .tmark file is not valid, so nothing in it was used",
            "A .tmark is read only when every field is valid; a half-read declaration could hide a limit or an "
            "authority the agent has. Fix the errors listed and audit again.",
            "; ".join(info.get("errors", [])[:8]),
            "Validate the file against https://touchmark-stellar.vercel.app/schemas/tmark-v1.json (or "
            "python scripts/tmark.py check) and fix each listed field.", auditor)]
    if status == "legacy":
        return [_finding(
            "intent-tmark-legacy", Severity.LOW, "The repository uses an older declaration file",
            "touchmark.json, agentveritas.json and veritas.json are still read, but they are free-form; .tmark "
            "has one checked structure, and only it can declare limits and approvals that the audit verifies.",
            "files: " + ", ".join(info.get("files", [])),
            "Replace the old file with a .tmark (python scripts/tmark.py init) and delete the old one.",
            auditor, grade=EvidenceGrade.INFERRED, confidence=0.9)]
    declared = info.get("declared")
    if status != "valid" or not declared:
        return []

    out: list[Finding] = []
    profile = artifact.code_profile or {}
    caps = profile.get("capabilities", {})
    controls = profile.get("controls", {})
    authority, limits = declared["authority"], declared.get("limits") or {}

    # Network: a testnet-only agent must not carry the public network's passphrase, nor let a
    # tool argument, a paid server's challenge or a fallback pick mainnet (network_rules).
    if declared["agent"]["network"] == "testnet":
        hits = network_hits(artifact.code_files, _MAINNET)
        chosen = [f"{h.file}:{h.line} ({_CHOOSES_MAINNET[h.rule]})" for h in binding_hits(artifact.code_files)[0]
                  if h.rule in MAINNET_REACHABLE]
        if hits or chosen:
            out.append(_finding(
                "intent-tmark-network-mismatch", Severity.HIGH, "Declared testnet only, but the code can use the public network",
                "The .tmark says the agent runs on testnet, and the code "
                + ("contains the public network passphrase or mainnet endpoints" if hits else "")
                + (" and " if hits and chosen else "")
                + ("lets something other than the operator select mainnet" if chosen else "")
                + ". A configuration switch, or input that picks the network, moves real funds.",
                "; ".join((hits[:5] + chosen[:3]) if hits else chosen[:5]),
                "Remove mainnet constants and pin the network to configuration, or declare network mainnet/both and "
                "the limits that apply there.", auditor))
    # The reverse: declared mainnet, but every network the code names is testnet.
    if declared["agent"]["network"] == "mainnet":
        code = {n: t for n, t in artifact.code_files.items() if n.endswith(_CODE)}
        hits = network_hits(code, _TESTNET)
        if hits and not any(_MAINNET.search(t) or _CHOOSES_NETWORK.search(t) for t in code.values()):
            out.append(_finding(
                "intent-tmark-network-mismatch", Severity.LOW, "Declared mainnet, but the code only targets testnet",
                "The .tmark says the agent runs on mainnet, but every network the code names is testnet (passphrase, "
                "hosts, CAIP-2 id or USDC contract), and nothing selects another network. The declaration does not "
                "describe what this code does.",
                "; ".join(hits[:5]),
                "Declare network testnet, or add the mainnet configuration the agent actually runs with.", auditor))

    # Authority: what the code can sign, against what is declared.
    holds = any(c in caps for c in ("key_custody", "stellar_signing", "tx_submission"))
    missing = sorted({sign for cap, sign in _SIGNS_FOR.items() if cap in caps} - set(authority["signs"]))
    if (holds and not authority["holds_keys"]) or missing:
        where = "; ".join(loc for cap in ("key_custody", "stellar_signing", *_SIGNS_FOR) for loc in caps.get(cap, [])[:1])
        out.append(_finding(
            "intent-tmark-authority-mismatch", Severity.HIGH, "The code has more Stellar authority than the .tmark declares",
            ("The .tmark says the agent holds no key, but the code loads one or signs. " if holds and not authority["holds_keys"] else "")
            + (f"The code can also sign: {', '.join(missing)}, which authority.signs does not list." if missing else ""),
            where, "Declare every authority the code has, or remove the code paths that use it.", auditor))

    # Limits: each declared control must exist in the code that pays.
    moves = any(c in caps for c in ("payment", "tx_submission", "contract_invocation"))
    broken = []
    if moves and limits.get("recipients") == "allowlist" and not controls.get("allowlist"):
        broken.append("recipients: allowlist (no recipient allowlist is enforced in code)")
    if moves and limits.get("per_payment") and not controls.get("amount_cap"):
        broken.append(f"per_payment {limits['per_payment']['amount']} {limits['per_payment']['asset']} (no amount cap in code)")
    if moves and limits.get("human_approval") in {"always", "above_limit"} and not controls.get("approval"):
        broken.append(f"human_approval: {limits['human_approval']} (no approval gate in code)")
    if moves and limits.get("per_day"):
        cumulative = re.compile(r"spent|daily|per_?day|budget|remaining|allowance|window", re.I)
        pay_files = {loc.split(":")[0] for cap in ("payment", "tx_submission") for loc in caps.get(cap, [])}
        if not any(cumulative.search(artifact.code_files.get(f, "")) for f in pay_files):
            broken.append(f"per_day {limits['per_day']['amount']} {limits['per_day']['asset']} (no running total near the payment code)")
    if broken:
        out.append(_finding(
            "intent-tmark-limit-not-enforced", Severity.HIGH, "A limit the .tmark declares is not enforced by the code",
            "Users read the .tmark to decide how far to trust the agent. Each limit listed here is promised there but "
            "missing where the agent pays, so it does not hold.",
            "; ".join(broken), "Enforce each declared limit in the code that builds or signs the payment, and test it.",
            auditor, grade=EvidenceGrade.INFERRED, confidence=0.8))
    return out
