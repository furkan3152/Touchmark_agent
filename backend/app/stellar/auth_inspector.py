"""Read-only, bounded inspection of a *single* Soroban authorization entry.

This deliberately narrow policy accepts only ordinary SEP-41 ``transfer``
invocations. It never signs, submits, simulates, verifies signatures, or claims
that the supplied policy/current ledger is trustworthy. Authorization trees are
not complete execution traces: calls that do not require this address's
authorization can be absent.

Protocol references (checked 2026-10-15):
https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization
https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction
https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator
from stellar_sdk import Address, scval, xdr
from xdrlib3 import Unpacker

MAX_XDR_BYTES = 65_536
MAX_BASE64_CHARS = ((MAX_XDR_BYTES + 2) // 3) * 4
MAX_INVOCATIONS = 64
MAX_INVOCATION_DEPTH = 8
MAX_XDR_DEPTH = 32
MAX_ARGS = 16
I128_MAX = 2**127 - 1
U32_MAX = 2**32 - 1

AtomicAmount = Annotated[str, Field(min_length=1, max_length=39, pattern=r"^[1-9][0-9]*$")]


def _address(value: xdr.SCAddress) -> str | None:
    if value.type not in (
        xdr.SCAddressType.SC_ADDRESS_TYPE_ACCOUNT,
        xdr.SCAddressType.SC_ADDRESS_TYPE_CONTRACT,
    ):
        return None
    return Address.from_xdr_sc_address(value).address


class TransferPolicy(BaseModel):
    """Caller-declared expectations; atomic amounts are strings to preserve i128."""

    model_config = ConfigDict(extra="forbid", strict=True)

    token_contract: str = Field(min_length=56, max_length=56)
    from_address: str = Field(min_length=56, max_length=56)
    to_address: str = Field(min_length=56, max_length=56)
    max_transfer_atomic: AtomicAmount
    max_total_atomic: AtomicAmount
    current_ledger: int = Field(ge=1, le=U32_MAX)
    max_expiration_ledgers: int = Field(ge=1, le=U32_MAX)

    @field_validator("token_contract", "from_address", "to_address")
    @classmethod
    def valid_address(cls, value: str, info) -> str:
        try:
            parsed = Address(value).to_xdr_sc_address()
            if _address(parsed) != value:
                raise ValueError("Unsupported address")
            if info.field_name == "token_contract" and not value.startswith("C"):
                raise ValueError("Token must be a contract address")
        except Exception as exc:
            raise ValueError("Use a canonical Stellar G/C address; token must be C") from exc
        return value

    @field_validator("max_transfer_atomic", "max_total_atomic")
    @classmethod
    def bounded_amount(cls, value: str) -> str:
        if int(value) > I128_MAX:
            raise ValueError("Atomic budget exceeds signed i128")
        return value


class AuthorizationInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    entry_xdr: str = Field(min_length=4, max_length=MAX_BASE64_CHARS)
    policy: TransferPolicy


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _typed_arg(value: xdr.SCVal) -> dict:
    summary = {"type": value.type.name, "xdr_sha256": _sha(value.to_xdr_bytes())}
    if value.type == xdr.SCValType.SCV_ADDRESS and value.address is not None:
        summary["address"] = _address(value.address)
    elif value.type == xdr.SCValType.SCV_I128:
        summary["atomic_value"] = str(scval.from_int128(value))
    # Strings, bytes, maps and vectors may carry secrets. Keep only type/hash.
    return summary


def inspect_authorization_entry(request: AuthorizationInspectionRequest) -> dict:
    """Compare decoded requests to declared limits, never grant authorization."""
    policy = request.policy
    violations: list[dict] = []

    def reject(code: str, path: str, detail: str) -> None:
        violations.append({"code": code, "path": path, "detail": detail})

    result = {
        "schema": "agentveritas.soroban-auth-inspection.v1",
        "input_sha256": _sha(request.entry_xdr.encode("utf-8")),
        "payload_sha256": None,
        "policy_sha256": _sha(json.dumps(policy.model_dump(), sort_keys=True, separators=(",", ":")).encode()),
        "declared_policy": policy.model_dump(),
        "matches_declared_policy": False,
        "inspection_complete": False,
        "signature_status": "not_inspected",
        "signature_verified": False,
        "network_verified": False,
        "ledger_verified": False,
        "ledger_state_verified": False,
        "transaction_executed": False,
        "policy_origin": "caller_declared",
        "current_ledger_origin": "caller_declared",
        "tree": None,
        "violations": violations,
        "transfer_count": 0,
        "total_requested_atomic": "0",
        "limits": {
            "xdr_bytes": MAX_XDR_BYTES,
            "invocations": MAX_INVOCATIONS,
            "invocation_depth": MAX_INVOCATION_DEPTH,
        },
        "scope": [
            "One authorization entry; other entries and transaction operations are not inspected.",
            "Only transfer(Address, Address, i128) with ordinary G/C addresses is supported.",
            "An authorization tree is not a complete execution trace or token-code verification.",
            "The policy, ledger freshness, network, signatures and replay state are not verified.",
            "This result does not authorize a transaction, guarantee safety or reserve a budget.",
            "Amounts are summed across this entry, not across transactions or an agent session.",
        ],
    }
    try:
        raw = base64.b64decode(request.entry_xdr, validate=True)
        if len(raw) > MAX_XDR_BYTES or base64.b64encode(raw).decode("ascii") != request.entry_xdr:
            raise ValueError("Noncanonical or oversized base64")
        result["payload_sha256"] = _sha(raw)
        unpacker = Unpacker(raw)
        entry = xdr.SorobanAuthorizationEntry.unpack(unpacker, depth_limit=MAX_XDR_DEPTH)
        unpacker.done()
        if entry.to_xdr_bytes() != raw:
            raise ValueError("Noncanonical XDR")
    except Exception:
        reject("invalid_xdr", "entry", "Expected canonical, bounded SorobanAuthorizationEntry base64 XDR.")
        return result

    # Bound the entire invocation tree before producing any policy match.
    pending = [(entry.root_invocation, 1)]
    node_count = 0
    while pending:
        invocation, depth = pending.pop()
        node_count += 1
        if node_count > MAX_INVOCATIONS or depth > MAX_INVOCATION_DEPTH:
            reject("invocation_limit", "root", "Invocation tree exceeds the supported depth or node count.")
            return result
        pending.extend((child, depth + 1) for child in invocation.sub_invocations)
    result["invocation_count"] = node_count

    credentials = entry.credentials
    result["credential_type"] = credentials.type.name
    if credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS or credentials.address is None:
        reject("unsupported_credentials", "credentials", "Explicit v1 address credentials are required; source-account, v2 and delegate credentials are unsupported.")
    else:
        address_credentials = credentials.address
        authorizer = _address(address_credentials.address)
        result["authorizer"] = authorizer
        result["nonce_sha256"] = _sha(address_credentials.nonce.to_xdr_bytes())
        if authorizer != policy.from_address:
            reject("authorizer_mismatch", "credentials.address", "Authorizer does not match the declared token sender.")
        expiration = address_credentials.signature_expiration_ledger.uint32
        result["signature_expiration_ledger"] = expiration
        if expiration == 0 or expiration < policy.current_ledger:
            reject("expired_authorization", "credentials.expiration", "Expiration is zero or precedes the caller-supplied current ledger.")
        elif expiration - policy.current_ledger > policy.max_expiration_ledgers:
            reject("expiration_too_distant", "credentials.expiration", "Expiration exceeds the declared ledger window.")
        signature = address_credentials.signature
        empty = signature.type == xdr.SCValType.SCV_VOID or (
            signature.type == xdr.SCValType.SCV_VEC and (signature.vec is None or not signature.vec.sc_vec)
        )
        result["signature_status"] = "unsigned" if empty else "present_unverified"
        result["signature_xdr_sha256"] = _sha(signature.to_xdr_bytes())

    total = 0
    transfer_count = 0

    def inspect_node(invocation: xdr.SorobanAuthorizedInvocation, path: str) -> dict:
        nonlocal total, transfer_count
        function = invocation.function
        node = {"path": path, "kind": function.type.name, "children": []}
        if function.type != xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN or function.contract_fn is None:
            node["function_xdr_sha256"] = _sha(function.to_xdr_bytes())
            reject("unsupported_function_kind", path, "Contract creation and other host functions are outside this transfer policy.")
        else:
            contract_fn = function.contract_fn
            contract = _address(contract_fn.contract_address)
            name_bytes = contract_fn.function_name.sc_symbol
            name = name_bytes.decode("ascii") if re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]{0,31}", name_bytes) else None
            node.update({"contract": contract, "function": name, "function_name_sha256": _sha(name_bytes)})
            if contract != policy.token_contract:
                reject("token_mismatch", path, "Contract does not match the declared token contract.")
            if name != "transfer":
                reject("function_not_allowed", path, "Only the exact function name transfer is allowed by this policy.")
            args = contract_fn.args
            node["argument_count"] = len(args)
            node["arguments"] = [_typed_arg(arg) for arg in args[:MAX_ARGS]]
            if len(args) > MAX_ARGS:
                reject("argument_limit", path, "Arguments exceed the bounded inspection limit.")
            if name == "transfer":
                expected = [xdr.SCValType.SCV_ADDRESS, xdr.SCValType.SCV_ADDRESS, xdr.SCValType.SCV_I128]
                if len(args) != 3 or [arg.type for arg in args] != expected:
                    reject("transfer_signature_mismatch", path, "Expected exactly Address sender, Address recipient and signed i128 amount.")
                else:
                    sender = _address(args[0].address)
                    recipient = _address(args[1].address)
                    amount = scval.from_int128(args[2])
                    transfer_count += 1
                    if sender != policy.from_address:
                        reject("sender_mismatch", path, "Transfer sender does not match the declared sender.")
                    if recipient != policy.to_address:
                        reject("recipient_mismatch", path, "Transfer recipient does not match the declared recipient.")
                    if amount <= 0:
                        reject("nonpositive_amount", path, "Transfer amounts must be positive; negatives never offset the budget.")
                    else:
                        total += amount
                        if amount > int(policy.max_transfer_atomic):
                            reject("transfer_budget_exceeded", path, "Transfer exceeds the declared per-transfer atomic budget.")
        node["children"] = [inspect_node(child, f"{path}.children[{index}]") for index, child in enumerate(invocation.sub_invocations)]
        return node

    result["tree"] = inspect_node(entry.root_invocation, "root")
    result["transfer_count"] = transfer_count
    result["total_requested_atomic"] = str(total)
    if total > I128_MAX:
        reject("aggregate_i128_overflow", "root", "Sum of requested positive transfers exceeds signed i128.")
    if total > int(policy.max_total_atomic):
        reject("total_budget_exceeded", "root", "Sum of all positive transfers exceeds the declared total atomic budget.")
    incomplete = {"argument_limit", "unsupported_credentials", "unsupported_function_kind", "transfer_signature_mismatch"}
    result["inspection_complete"] = not any(v["code"] in incomplete for v in violations)
    result["matches_declared_policy"] = not violations
    return result
