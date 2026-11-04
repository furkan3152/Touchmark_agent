""".tmark v1 (1.1): the one file a repository commits to describe its agent to Touchmark.

The format is strict on purpose. Every field has one meaning and one shape, unknown
fields are rejected, and a file with any error is not used at all: a declaration that is
half read is worse than none. What it states is checked against the code; it never closes
a risk by itself.

    {
      "$schema": "https://usetouchmark.app/schemas/tmark-v1.json",
      "tmark": "1",
      "agent": {"name": "...", "purpose": "...", "kind": "mcp_server", "network": "testnet"},
      "owner": {"stellar_account": "G..."},
      "authority": {"holds_keys": true, "key_source": "env", "signs": ["payments"]},
      "limits": {"per_payment": {"amount": "25", "asset": "USDC:G..."}, "per_day": {...},
                 "recipients": "allowlist", "human_approval": "above_limit"},
      "tools": [{"name": "pay_invoice", "description": "...", "moves_funds": true, "signs": true,
                 "network": true, "max_amount": {"amount": "25", "asset": "USDC:G..."}}],
      "forbidden": ["pay an address that is not in the saved payee list"],
      "contact": {"security": "security@example.com"}
    }

Version 1.1 adds, backward compatibly (a "1" file keeps validating unchanged):

- ``authority.key_source`` ``caller_supplied`` (the caller passes a secret with each call)
  and ``agent_generated`` (the agent creates a key and stores it itself);
- ``tools[].executes_code`` (the tool runs a shell command or code): declared execution is
  disclosed, and the code's execution paths are still assessed;
- ``tools[].generated`` (a family of tools the code generates at run time, named by a glob
  ``pattern``, e.g. one tool per function of a registered contract).

A file that uses a 1.1 field must say ``"tmark": "1.1"``.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

FILE_NAME = ".tmark"
VERSION = "1.1"
#: Every version this parser reads. Minor versions only add optional fields and values.
VERSIONS = ("1", "1.1")
SCHEMA_URL = "https://usetouchmark.app/schemas/tmark-v1.json"
MAX_BYTES = 64_000

_AMOUNT = re.compile(r"^(?:0|[1-9]\d{0,11})(?:\.\d{1,7})?$")
_ASSET = re.compile(r"^(?:XLM|native|[A-Za-z0-9]{1,12}:G[A-Z2-7]{55}|C[A-Z2-7]{55})$")
SIGNS = ("payments", "contract_calls", "account_changes", "trustlines", "foreign_transactions", "messages")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _account(value: str, prefix: str = "G") -> str:
    from stellar_sdk import StrKey
    valid = (StrKey.is_valid_ed25519_public_key(value) if prefix == "G"
             else StrKey.is_valid_contract(value) if prefix == "C" else False)
    if not valid:
        raise ValueError(f"must be a valid Stellar {prefix}... address (checksum included)")
    return value


class Money(_Strict):
    amount: str = Field(description="Decimal string, at most 7 decimal places, e.g. \"25\" or \"0.5\".")
    asset: str = Field(description="XLM, CODE:G...ISSUER, or a C... token contract.")

    @field_validator("amount")
    @classmethod
    def _amount(cls, value: str) -> str:
        if not _AMOUNT.match(value) or Decimal(value) <= 0:
            raise ValueError("must be a positive decimal string with at most 7 decimal places, e.g. \"25\"")
        return value

    @field_validator("asset")
    @classmethod
    def _asset(cls, value: str) -> str:
        if not _ASSET.match(value):
            raise ValueError("must be XLM, CODE:ISSUER (G... issuer) or a C... token contract")
        if ":" in value:
            _account(value.split(":", 1)[1])
        elif value.startswith("C"):
            _account(value, "C")
        return value


class Agent(_Strict):
    name: str = Field(min_length=2, max_length=80)
    purpose: str = Field(min_length=20, max_length=1000,
                         description="What the agent does and for whom, in one or two sentences.")
    kind: Literal["mcp_server", "autonomous_agent", "x402_client", "x402_server", "sdk", "skill", "contract", "other"]
    network: Literal["testnet", "mainnet", "both"]
    discloses_ai: bool = Field(default=True, description="Users are told they talk to an AI.")


class Owner(_Strict):
    stellar_account: str = Field(description="The G... account that receives the Touchmark credential.")

    _check = field_validator("stellar_account")(lambda cls, v: _account(v))


KEY_SOURCES_V1_1 = ("caller_supplied", "agent_generated")


class Authority(_Strict):
    holds_keys: bool = Field(description="The agent itself holds a Stellar secret key.")
    key_source: Literal["env", "kms", "external_signer", "wallet_prompt", "none", "caller_supplied", "agent_generated"] = Field(
        description="Where the signing key comes from. 1.1: caller_supplied (the caller passes a secret with each "
                    "call, the agent keeps none) and agent_generated (the agent creates and stores the key itself).")
    signs: list[Literal["payments", "contract_calls", "account_changes", "trustlines",
                        "foreign_transactions", "messages"]] = Field(default_factory=list, max_length=6)
    agent_account: str = Field(default="", description="G... account or C... contract the agent acts from, if fixed.")

    @field_validator("agent_account")
    @classmethod
    def _agent_account(cls, value: str) -> str:
        return _account(value, value[:1]) if value else value

    @model_validator(mode="after")
    def _consistent(self):
        if self.holds_keys and self.key_source in {"none", "wallet_prompt"}:
            raise ValueError("holds_keys is true, so key_source cannot be none or wallet_prompt")
        if not self.holds_keys and self.key_source in {"env", "kms"}:
            raise ValueError("key_source env or kms means the agent holds a key; set holds_keys to true")
        if not self.holds_keys and self.key_source == "agent_generated":
            raise ValueError("key_source agent_generated means the agent stores a key; set holds_keys to true")
        if len(set(self.signs)) != len(self.signs):
            raise ValueError("signs lists a value twice")
        return self


class Limits(_Strict):
    per_payment: Money | None = None
    per_day: Money | None = None
    recipients: Literal["allowlist", "any", "none"] = Field(
        description="allowlist: only saved payees; any: whatever the request names; none: never pays.")
    human_approval: Literal["always", "above_limit", "never"]


class Generated(_Strict):
    """A family of tools the code creates at run time (one per contract function, per route)."""
    pattern: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:*?\[\]{}-]+$",
                         description="Glob that every generated tool name matches, e.g. \"*_*\" or \"contract_*\".")
    source: str = Field(min_length=8, max_length=300,
                        description="What the tools are generated from, e.g. \"each function of a contract the caller registers\".")


class Tool(_Strict):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = Field(min_length=8, max_length=400)
    moves_funds: bool
    signs: bool
    network: bool
    #: Reads or writes local files (a spend ledger, a keystore, a cache).
    files: bool = False
    #: 1.1: runs a shell command or code (a build, a CLI, an interpreter).
    executes_code: bool = Field(default=False, description="1.1: the tool runs a shell command or code.")
    #: 1.1: the entry stands for a family of generated tools rather than one fixed name.
    generated: Generated | None = Field(default=None, description="1.1: a family of tools generated at run time.")
    max_amount: Money | None = None

    @model_validator(mode="after")
    def _limit(self):
        if self.max_amount is not None and not self.moves_funds:
            raise ValueError("max_amount is set but moves_funds is false")
        return self

    def covers(self, name: str) -> bool:
        """Whether a tool name the code registers is this declared tool or one of its family."""
        from fnmatch import fnmatchcase
        return name == self.name or (self.generated is not None and fnmatchcase(name, self.generated.pattern))


class Contact(_Strict):
    security: str = Field(min_length=5, max_length=200, description="Email or URL for security reports.")


class Entrypoint(_Strict):
    path: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
    symbol: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")

    @field_validator("path")
    @classmethod
    def _relative(cls, value: str) -> str:
        if ".." in value.split("/") or "//" in value:
            raise ValueError("must be a relative path inside the repository")
        return value


class Tmark(_Strict):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)
    schema_url: str = Field(default=SCHEMA_URL, alias="$schema")
    tmark: Literal["1", "1.1"]
    agent: Agent
    owner: Owner | None = None
    authority: Authority
    limits: Limits | None = None
    tools: list[Tool] = Field(default_factory=list, max_length=60)
    forbidden: list[str] = Field(default_factory=list, max_length=30)
    entrypoints: list[Entrypoint] = Field(default_factory=list, max_length=10)
    contact: Contact | None = None

    @field_validator("forbidden")
    @classmethod
    def _forbidden(cls, value: list[str]) -> list[str]:
        if any(not (8 <= len(v.strip()) <= 300) for v in value):
            raise ValueError("each forbidden item must be 8 to 300 characters")
        return [v.strip() for v in value]

    @model_validator(mode="after")
    def _consistent(self):
        pays = "payments" in self.authority.signs or any(t.moves_funds for t in self.tools)
        if pays and self.limits is None:
            raise ValueError("the agent moves funds, so limits is required")
        if pays and self.limits and self.limits.recipients == "none":
            raise ValueError("limits.recipients is none but the agent moves funds")
        if any(t.signs for t in self.tools) and not self.authority.signs:
            raise ValueError("a tool signs, so authority.signs must list what it signs")
        names = [t.name for t in self.tools]
        if len(set(names)) != len(names):
            raise ValueError("two tools have the same name")
        if self.tmark == "1" and self.minor_features():
            raise ValueError(f"uses .tmark 1.1 fields ({', '.join(self.minor_features())}); set \"tmark\": \"1.1\"")
        return self

    def minor_features(self) -> list[str]:
        """The 1.1 fields and values this declaration uses."""
        used = []
        if self.authority.key_source in KEY_SOURCES_V1_1:
            used.append(f"authority.key_source {self.authority.key_source}")
        used += [f"tools.{i}.executes_code" for i, t in enumerate(self.tools) if t.executes_code]
        used += [f"tools.{i}.generated" for i, t in enumerate(self.tools) if t.generated is not None]
        return used


def _where(loc: tuple) -> str:
    return ".".join(str(p) for p in loc if p not in ("function-after[_consistent()]",)) or "(file)"


def parse(text: str) -> tuple[Tmark | None, list[str]]:
    """Parse and validate a .tmark file. Returns (tmark, []) or (None, readable errors)."""
    parsed, details = check(text)
    return parsed, [f"{d['field']}: {d['message']}" for d in details]


def check(text: str) -> tuple[Tmark | None, list[dict]]:
    """Parse and validate, with each error located: ``{"field", "line", "message"}``. The line
    is where the field (or, for a missing field, its parent object) starts; 0 when unknown."""
    if len(text.encode()) > MAX_BYTES:
        return None, [{"field": "(file)", "line": 0, "message": f"the file is larger than {MAX_BYTES} bytes"}]
    try:
        raw = json.loads(text)
    except ValueError as exc:
        return None, [{"field": "(file)", "line": getattr(exc, "lineno", 0), "message": f"not valid JSON: {exc}"}]
    if not isinstance(raw, dict):
        return None, [{"field": "(file)", "line": 1, "message": "the file must be one JSON object"}]
    try:
        return Tmark.model_validate(raw), []
    except ValidationError as exc:
        lines = _lines(text)
        errors = []
        for err in exc.errors()[:20]:
            msg = err["msg"].removeprefix("Value error, ")
            if err["type"] == "extra_forbidden":
                msg = "unknown field; see the .tmark schema for allowed fields"
            elif err["type"] == "missing":
                msg = "required"
            path = tuple(p for p in err["loc"] if not (isinstance(p, str) and p.startswith("function-")))
            if not path and '"tmark"' in msg:
                path = ("tmark",)  # the version line is what to change
            line = next((lines[path[:k]] for k in range(len(path), -1, -1) if path[:k] in lines), 0)
            errors.append({"field": _where(err["loc"]), "line": line, "message": msg})
        return None, errors


def _lines(text: str) -> dict[tuple, int]:
    """{key path: line} for every value in a JSON document (the line its key or item starts on).
    Only called on text json.loads already accepted, so the scan cannot go out of step."""
    from json.decoder import scanstring
    out: dict[tuple, int] = {(): 1}
    decoder, pos = json.JSONDecoder(), 0

    def line_at(i: int) -> int:
        return text.count("\n", 0, i) + 1

    def skip(i: int) -> int:
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        return i

    def value(i: int, path: tuple) -> int:
        i = skip(i)
        out.setdefault(path, line_at(i))
        if text[i] == "{":
            i = skip(i + 1)
            if text[i] == "}":
                return i + 1
            while True:
                key_line = line_at(i)
                key, i = scanstring(text, i + 1)
                out[path + (key,)] = key_line
                i = skip(i)
                i = value(i + 1, path + (key,))  # past the colon
                i = skip(i)
                if text[i] == ",":
                    i = skip(i + 1)
                    continue
                return i + 1
        if text[i] == "[":
            i, n = skip(i + 1), 0
            if text[i] == "]":
                return i + 1
            while True:
                out[path + (n,)] = line_at(skip(i))
                i = skip(value(i, path + (n,)))
                n += 1
                if text[i] == ",":
                    i += 1
                    continue
                return i + 1
        _, end = decoder.raw_decode(text, i)
        return end

    try:
        value(pos, ())
    except (ValueError, IndexError, RecursionError):
        pass
    return out


def summary(tm: Tmark) -> list[str]:
    """What the declaration says, in plain sentences, for a person checking it before it is used."""
    a, auth = tm.agent, tm.authority
    keys = {"env": "from the environment", "kms": "from a key management service",
            "external_signer": "through an external signer", "wallet_prompt": "by asking the user's wallet",
            "none": "nowhere (it signs nothing)", "caller_supplied": "from the caller, with each call",
            "agent_generated": "it generates and stores itself"}[auth.key_source]
    kind = a.kind.replace("_", " ")
    out = [f"{a.name}: {'an' if kind[0] in 'aeiou' or kind.startswith('mcp') else 'a'} {kind} on {'testnet and mainnet' if a.network == 'both' else a.network}.",
           ("Holds a Stellar key" if auth.holds_keys else "Holds no Stellar key") + f"; the signing key comes {keys}.",
           ("Signs: " + ", ".join(s.replace("_", " ") for s in auth.signs) + ".") if auth.signs else "Signs nothing."]
    if tm.limits:
        lim = tm.limits
        caps = [f"{label} {m.amount} {m.asset}" for label, m in (("per payment", lim.per_payment), ("per day", lim.per_day)) if m]
        out.append("Limits: " + (", ".join(caps) if caps else "no amount cap") + f"; recipients: {lim.recipients}; "
                   f"human approval: {lim.human_approval.replace('_', ' ')}.")
    if tm.tools:
        moving = [t.name for t in tm.tools if t.moves_funds]
        executing = [t.name for t in tm.tools if t.executes_code]
        generated = [f"{t.name} ({t.generated.pattern})" for t in tm.tools if t.generated]
        out.append(f"{len(tm.tools)} tool(s)" + (f"; move funds: {', '.join(moving)}" if moving else "; none moves funds") + ".")
        if executing:
            out.append("Runs shell commands or code: " + ", ".join(executing) + ".")
        if generated:
            out.append("Generated tool families: " + ", ".join(generated) + ".")
    if tm.owner:
        out.append(f"Owner: {tm.owner.stellar_account[:6]}…{tm.owner.stellar_account[-4:]}.")
    if tm.forbidden:
        out.append(f"{len(tm.forbidden)} forbidden goal(s).")
    return out


def normalized(tm: Tmark) -> dict:
    """The declaration as Touchmark reads it: every default filled in, $schema dropped."""
    return tm.model_dump(mode="json", by_alias=False, exclude={"schema_url"})


#: Fields compared when a supplied declaration and a committed one both exist.
def differences(supplied: Tmark, committed: Tmark) -> list[str]:
    """Where a declaration supplied with the request disagrees with the repository's own .tmark."""
    a, b = normalized(supplied), normalized(committed)
    out = []
    for section, keys in (("agent", ("network", "kind")), ("authority", ("holds_keys", "key_source", "signs", "agent_account"))):
        for key in keys:
            left, right = a[section].get(key), b[section].get(key)
            if isinstance(left, list):
                left, right = sorted(left), sorted(right or [])
            if left != right:
                out.append(f"{section}.{key}: supplied {left!r}, committed {right!r}")
    if (a.get("limits") or {}) != (b.get("limits") or {}):
        out.append("limits differ")
    tools_a = {t["name"]: t for t in a["tools"]}
    tools_b = {t["name"]: t for t in b["tools"]}
    for name in sorted(set(tools_a) ^ set(tools_b)):
        out.append(f"tool {name}: only in the {'supplied' if name in tools_a else 'committed'} declaration")
    for name in sorted(set(tools_a) & set(tools_b)):
        for key in ("moves_funds", "signs", "network", "files", "executes_code", "max_amount"):
            if tools_a[name].get(key) != tools_b[name].get(key):
                out.append(f"tool {name}.{key}: supplied {tools_a[name].get(key)!r}, committed {tools_b[name].get(key)!r}")
    if (a.get("owner") or {}) != (b.get("owner") or {}):
        out.append("owner differs (only the committed owner can receive a credential)")
    return out[:30]


def stroops(amount: str) -> int:
    """A .tmark amount in the asset's smallest unit (seven decimal places), exactly: amounts
    are compared as integers, never as floats."""
    return int(Decimal(amount).scaleb(7))


def cap(money: Money | None) -> dict | None:
    """A declared cap in its own asset: {"amount": "500.0000000", "asset": "XLM"}."""
    if money is None:
        return None
    return {"amount": f"{Decimal(stroops(money.amount)).scaleb(-7):.7f}",
            "asset": "XLM" if money.asset == "native" else money.asset}


def _is_usdc(asset: str) -> bool:
    from ..stellar.canonical import canonical_asset
    return asset.upper().startswith("USDC:") or (canonical_asset(asset) or ("",))[0] == "USDC"


def to_declaration(tm: Tmark) -> dict:
    """The fields the audit uses, in the shape of the legacy touchmark.json declaration.

    Every tool cap is kept in its own asset (``spend_limit``); ``spend_limit_usdc`` is also
    set for a USDC cap, for readers of the older field."""
    usdc = lambda m: float(m.amount) if m and _is_usdc(m.asset) else None  # noqa: E731
    tools = [{"name": t.name, "description": t.description,
              "scopes": (["payments"] if t.moves_funds else []) + (["sign"] if t.signs else [])
                        + (["files"] if t.files else []) + (["exec:process"] if t.executes_code else []),
              "requires_signature": t.signs, "network_access": t.network,
              "moves_funds": t.moves_funds, "executes_code": t.executes_code,
              **({"pattern": t.generated.pattern} if t.generated else {}),
              "spend_limit_usdc": usdc(t.max_amount), "spend_limit": cap(t.max_amount)} for t in tm.tools]
    capabilities = (list(tm.authority.signs) + (["moves_funds"] if any(t.moves_funds for t in tm.tools) else [])
                    + (["network"] if any(t.network for t in tm.tools) else []))
    account = tm.authority.agent_account
    return {
        "name": tm.agent.name, "purpose": tm.agent.purpose, "description": tm.agent.purpose,
        "capabilities": capabilities, "tools": tools, "forbidden_goals": tm.forbidden,
        "human_oversight": bool(tm.limits and tm.limits.human_approval != "never"),
        "discloses_ai": tm.agent.discloses_ai,
        # Kept so a reader of the declaration sees the limits beside the tools they bound.
        "limits": tm.limits.model_dump(mode="json") if tm.limits else None,
        "key_source": tm.authority.key_source,
        "agent_wallet": account if account.startswith("G") else "",
        # A smart account or contract agent: read on chain like a C... reference (agent_resolver).
        "agent_contract_id": account if account.startswith("C") else "",
    }


def schema() -> dict:
    out = Tmark.model_json_schema(by_alias=True)
    out["$id"] = SCHEMA_URL
    out["title"] = ".tmark v1 (1.1)"
    out["description"] = "What a repository declares about its Stellar agent. Checked against the code by Touchmark."
    return out


def template(capabilities: set[str] | None = None, tools: list[dict] | None = None, *,
             name: str = "", network: str = "testnet") -> dict:
    """A starting .tmark, pre-filled from what the code can do.

    ``tools`` are the tools the code registers, each ``{"name", "where", "moves_funds", "signs",
    "network", "files", "executes_code"}`` as far as the analysis could attribute them; the draft
    passes the check as drafted, but its purpose and tool descriptions are placeholders a person
    replaces, and its limits are the pessimistic ones ("any" recipient, no approval): the draft
    never claims a control the author has not confirmed."""
    caps = capabilities or set()
    signs = [s for s, cap in (("payments", "payment"), ("contract_calls", "contract_invocation"),
                              ("account_changes", "account_control"), ("trustlines", "trustline"),
                              ("foreign_transactions", "foreign_tx_signing"))
             if cap in caps]
    holds = bool(caps & {"key_custody", "stellar_signing", "tx_submission"})
    drafted = []
    for tool in (tools or [])[:60]:
        where = tool.get("where") or "the source"
        entry = {"name": tool["name"], "description": f"Registered at {where}. Describe what it does."[:400],
                 "moves_funds": bool(tool.get("moves_funds")), "signs": bool(tool.get("signs")),
                 "network": bool(tool.get("network"))}
        if tool.get("files"):
            entry["files"] = True
        if tool.get("executes_code"):
            entry["executes_code"] = True
        drafted.append(entry)
    if any(t["signs"] for t in drafted) and not signs:
        signs = ["contract_calls"]
    out: dict = {
        "$schema": SCHEMA_URL, "tmark": VERSION,
        "agent": {"name": (name or "my-agent")[:80].ljust(2, "-"),
                  "purpose": "Drafted by Touchmark from the code. Replace this with what the agent is for and who uses it.",
                  "kind": "mcp_server", "network": network, "discloses_ai": True},
        "authority": {"holds_keys": holds, "key_source": "env" if holds else "none", "signs": signs},
        "tools": drafted, "forbidden": [],
    }
    if "payments" in signs or any(t["moves_funds"] for t in drafted):
        # The pessimistic statement until the author confirms a limit, an allowlist or an approval
        # step the code enforces; add per_payment / per_day amounts then.
        out["limits"] = {"recipients": "any", "human_approval": "never"}
    return out


def draft_from_source(files: dict[str, str], *, name: str = "") -> dict:
    """A .tmark draft from source: the capabilities the analysis finds and the tools the code
    registers, each tool marked with what the code in its file can do. Nothing is executed."""
    from ..swarm.codeflow import analyse_code
    from ..swarm.capabilities import shipped
    from .repo_audit import registered_tools
    profile = analyse_code(files) if files else None
    caps = {cap for cap, locs in (profile.capabilities.items() if profile else [])
            if any(shipped(loc.render()) for loc in locs)}
    by_file: dict[str, set[str]] = {}
    for cap, locs in (profile.capabilities.items() if profile else []):
        for loc in locs:
            by_file.setdefault(loc.file, set()).add(cap)
    tools = []
    for tool in registered_tools(files):
        where = tool.description.removeprefix("Registered in source at ")
        here = by_file.get(where.rsplit(":", 1)[0], set())
        tools.append({"name": tool.name, "where": where,
                      "moves_funds": bool(here & {"payment", "tx_submission"}),
                      "signs": bool(here & {"stellar_signing", "key_custody"}),
                      "network": bool(here & {"network_fetch", "tx_submission"}),
                      "files": "file_access" in here, "executes_code": "code_execution" in here})
    mainnet = any(m in text for text in files.values() for m in ("Public Global Stellar Network", "Networks.PUBLIC"))
    testnet = any(m in text for text in files.values() for m in ("Test SDF Network", "Networks.TESTNET"))
    draft = template(caps, tools, name=name, network="both" if mainnet and testnet else "mainnet" if mainnet else "testnet")
    return {"draft": draft, "capabilities": sorted(caps),
            "tools": [{"name": t["name"], "where": t["where"]} for t in tools],
            "note": ("A draft from what the code shows. It passes the check as it stands, but replace the purpose "
                     "and each tool description, check every flag, and tighten the limits only to what the code "
                     "enforces. Add owner and contact to be eligible for a credential.")}
