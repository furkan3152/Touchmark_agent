""".tmark v1: the one file a repository commits to describe its agent to Touchmark.

The format is strict on purpose. Every field has one meaning and one shape, unknown
fields are rejected, and a file with any error is not used at all: a declaration that is
half read is worse than none. What it states is checked against the code; it never closes
a risk by itself.

    {
      "$schema": "https://touchmark-stellar.vercel.app/schemas/tmark-v1.json",
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
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

FILE_NAME = ".tmark"
VERSION = "1"
SCHEMA_URL = "https://touchmark-stellar.vercel.app/schemas/tmark-v1.json"
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


class Authority(_Strict):
    holds_keys: bool = Field(description="The agent itself holds a Stellar secret key.")
    key_source: Literal["env", "kms", "external_signer", "wallet_prompt", "none"]
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
        if len(set(self.signs)) != len(self.signs):
            raise ValueError("signs lists a value twice")
        return self


class Limits(_Strict):
    per_payment: Money | None = None
    per_day: Money | None = None
    recipients: Literal["allowlist", "any", "none"] = Field(
        description="allowlist: only saved payees; any: whatever the request names; none: never pays.")
    human_approval: Literal["always", "above_limit", "never"]


class Tool(_Strict):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = Field(min_length=8, max_length=400)
    moves_funds: bool
    signs: bool
    network: bool
    max_amount: Money | None = None

    @model_validator(mode="after")
    def _limit(self):
        if self.max_amount is not None and not self.moves_funds:
            raise ValueError("max_amount is set but moves_funds is false")
        return self


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
    tmark: Literal["1"]
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
        return self


def _where(loc: tuple) -> str:
    return ".".join(str(p) for p in loc if p not in ("function-after[_consistent()]",)) or "(file)"


def parse(text: str) -> tuple[Tmark | None, list[str]]:
    """Parse and validate a .tmark file. Returns (tmark, []) or (None, readable errors)."""
    if len(text.encode()) > MAX_BYTES:
        return None, [f"the file is larger than {MAX_BYTES} bytes"]
    try:
        raw = json.loads(text)
    except ValueError as exc:
        return None, [f"not valid JSON: {exc}"]
    if not isinstance(raw, dict):
        return None, ["the file must be one JSON object"]
    try:
        return Tmark.model_validate(raw), []
    except ValidationError as exc:
        errors = []
        for err in exc.errors()[:20]:
            msg = err["msg"].removeprefix("Value error, ")
            if err["type"] == "extra_forbidden":
                msg = "unknown field; see the .tmark schema for allowed fields"
            elif err["type"] == "missing":
                msg = "required"
            errors.append(f"{_where(err['loc'])}: {msg}")
        return None, errors


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
              "scopes": (["payments"] if t.moves_funds else []) + (["sign"] if t.signs else []),
              "requires_signature": t.signs, "network_access": t.network,
              "spend_limit_usdc": usdc(t.max_amount), "spend_limit": cap(t.max_amount)} for t in tm.tools]
    capabilities = list(tm.authority.signs) + (["network"] if any(t.network for t in tm.tools) else [])
    account = tm.authority.agent_account
    return {
        "name": tm.agent.name, "purpose": tm.agent.purpose, "description": tm.agent.purpose,
        "capabilities": capabilities, "tools": tools, "forbidden_goals": tm.forbidden,
        "human_oversight": bool(tm.limits and tm.limits.human_approval != "never"),
        "discloses_ai": tm.agent.discloses_ai,
        "agent_wallet": account if account.startswith("G") else "",
        # A smart account or contract agent: read on chain like a C... reference (agent_resolver).
        "agent_contract_id": account if account.startswith("C") else "",
    }


def schema() -> dict:
    out = Tmark.model_json_schema(by_alias=True)
    out["$id"] = SCHEMA_URL
    out["title"] = ".tmark v1"
    out["description"] = "What a repository declares about its Stellar agent. Checked against the code by Touchmark."
    return out


def template(capabilities: set[str] | None = None) -> dict:
    """A starting .tmark, pre-filled from what the code can do."""
    caps = capabilities or set()
    signs = [s for s, cap in (("payments", "payment"), ("contract_calls", "contract_invocation"),
                              ("account_changes", "account_control"), ("foreign_transactions", "foreign_tx_signing"))
             if cap in caps]
    holds = bool(caps & {"key_custody", "stellar_signing", "tx_submission"})
    out: dict = {
        "$schema": SCHEMA_URL, "tmark": VERSION,
        "agent": {"name": "", "purpose": "", "kind": "mcp_server", "network": "testnet", "discloses_ai": True},
        "owner": {"stellar_account": ""},
        "authority": {"holds_keys": holds, "key_source": "env" if holds else "none", "signs": signs},
        "tools": [], "forbidden": [], "contact": {"security": ""},
    }
    if "payments" in signs:
        out["limits"] = {"per_payment": {"amount": "", "asset": "XLM"}, "per_day": {"amount": "", "asset": "XLM"},
                         "recipients": "allowlist", "human_approval": "above_limit"}
    return out
