"""Compare what a repository's .tmark declares with what its code does.

A declaration never closes a risk. It turns a vague question ("is this safe?") into
specific claims (testnet only, recipients from an allowlist, a human approves each
payment) that the code either keeps or breaks; a broken claim is reported as such.
"""

from __future__ import annotations

import re
from bisect import bisect_right

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, Severity
from ..stellar.canonical import NETWORK_MARKERS
from .network_rules import MAINNET_REACHABLE, network_hits as binding_hits

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
#: A comment line, or a line inside a block comment. '#' starts one in Python only: in JS it is
#: a private field, in Rust an attribute.
_COMMENT = re.compile(r"\s*(?://|\*|/\*)")
_PY_COMMENT = re.compile(r"\s*#")
_CODE = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".mts", ".cts", ".rs")
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
    whether that block is opened under a network key with a testnet sibling nearby."""

    def __init__(self, text: str):
        self.text, self.positions, self.openers, self.closes, self.keyed = text, [], [], {}, {}
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
                                 and bool(_TESTNET_SIBLING.search(self.text, max(0, brace - _BLOCK_REACH),
                                                                  close + _BLOCK_REACH)))
        return self.keyed[brace]


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


def network_hits(files: dict[str, str], pattern: re.Pattern, skip_keyed: bool = True) -> list[str]:
    """First file:line per code file where ``pattern`` names a network in code, outside
    comments and (with ``skip_keyed``) network-keyed maps."""
    hits = []
    for name, text in files.items():
        if not name.endswith(_CODE):
            continue
        comment = _PY_COMMENT if name.endswith(".py") else _COMMENT
        line_start, scanned, blocks = 0, 0, None
        for m in pattern.finditer(text):
            newline = text.rfind("\n", scanned, m.start())
            line_start, scanned = (newline + 1 if newline >= 0 else line_start), m.start()
            if comment.match(text, line_start, m.start()):
                continue
            if skip_keyed:
                blocks = blocks or _Blocks(text)
                if _network_keyed(text, m.start(), m.end(), line_start, blocks):
                    continue
            hits.append(f"{name}:{text.count(chr(10), 0, m.start()) + 1}")
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
