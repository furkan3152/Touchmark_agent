"""What the Stellar SDKs actually return, per release, for the rules that read RPC results.

A Soroban RPC call that the code reads the wrong way fails silently: the Python SDK's
status fields are plain ``Enum`` members, so ``resp.status == "SUCCESS"`` is always False;
its responses are pydantic models, so a field the release does not have raises
AttributeError (often after the transaction was sent); and ``get_contract_data`` treats any
durability that is not ``Durability.PERSISTENT`` as TEMPORARY. In JavaScript, a symbol a
major release removed is ``undefined`` at run time. Each table names the releases it was
read from; a rule reports a field as missing only when every verified release the project
can install lacks it.

Sources: the stellar-sdk wheels 9.0.0, 10.0.0, 11.0.0, 12.0.0, 13.1.0, 14.0.0, 15.0.0 and
16.0.0 from PyPI (stellar_sdk/soroban_rpc.py, base_soroban_server.py, soroban_server.py),
the @stellar/stellar-sdk 12.3.0, 13.0.0, 14.0.0 and 16.0.1 tarballs from npm (lib/index.d.ts,
CHANGELOG.md, lib/rpc/server.js) and @stellar/stellar-base 14.0.0 (lib/operation.js).
"""

from __future__ import annotations

from ..services.lockfiles import spec_admits, version_key

# ------------------------------------------------------------------ Python stellar_sdk

#: Fields of the pydantic response models, per verified release. Reading any other name
#: raises AttributeError.
_SEND = ("error_result_xdr", "status", "hash", "latest_ledger", "latest_ledger_close_time")
_GET_9 = ("status", "latest_ledger", "latest_ledger_close_time", "oldest_ledger", "oldest_ledger_close_time",
          "application_order", "fee_bump", "envelope_xdr", "result_xdr", "result_meta_xdr", "ledger")
_SIM_9 = ("error", "transaction_data", "min_resource_fee", "events", "results", "restore_preamble", "latest_ledger")
PY_RESPONSE_FIELDS: dict[str, dict[str, frozenset[str]]] = {
    "send": {"9.0.0": frozenset(_SEND),
             **{v: frozenset(_SEND + ("diagnostic_events_xdr",))
                for v in ("10.0.0", "11.0.0", "12.0.0", "13.1.0", "14.0.0", "15.0.0", "16.0.0")}},
    "get": {"9.0.0": frozenset(_GET_9 + ("ledger_close_time",)),
            "10.0.0": frozenset(_GET_9 + ("create_at",)),
            "11.0.0": frozenset(_GET_9 + ("create_at",)),
            "12.0.0": frozenset(_GET_9 + ("create_at", "transaction_hash")),
            "13.1.0": frozenset(_GET_9 + ("create_at", "transaction_hash", "events")),
            **{v: frozenset(_GET_9 + ("create_at", "transaction_hash", "events", "diagnostic_events_xdr"))
               for v in ("14.0.0", "15.0.0", "16.0.0")}},
    # simulate_transaction's `cost` was removed in 12.0.0.
    "simulate": {"9.0.0": frozenset(_SIM_9 + ("cost",)),
                 "10.0.0": frozenset(_SIM_9 + ("cost", "state_changes")),
                 "11.0.0": frozenset(_SIM_9 + ("cost", "state_changes")),
                 **{v: frozenset(_SIM_9 + ("state_changes",))
                    for v in ("12.0.0", "13.1.0", "14.0.0", "15.0.0", "16.0.0")}},
}
PY_VERIFIED = ("9.0.0", "10.0.0", "11.0.0", "12.0.0", "13.1.0", "14.0.0", "15.0.0", "16.0.0")
#: Names every pydantic model answers to (methods and v1 compatibility shims).
PY_MODEL_ATTRS = frozenset({"dict", "json", "copy", "schema", "schema_json", "parse_obj", "parse_raw",
                            "construct", "validate", "fields", "__fields__", "__dict__", "__class__"})
#: The Soroban RPC methods whose result is one of the models above.
PY_RPC_RESULT = {"send_transaction": "send", "get_transaction": "get", "poll_transaction": "get",
                 "simulate_transaction": "simulate"}
#: Result fields typed as plain Enum (never equal to a str) in every verified release.
PY_ENUM_FIELDS = {"send": {"status": "SendTransactionStatus"}, "get": {"status": "GetTransactionStatus"}}
#: The server classes that make a receiver a Soroban RPC client (Horizon's Server has none
#: of the methods above).
PY_RPC_CLASSES = frozenset({"SorobanServer", "SorobanServerAsync"})


def py_tables(kind: str, spec: str | None, version: str | None) -> list[frozenset[str]]:
    """The verified field tables a project may run with: the locked release's own (or those
    of its major), the releases its range admits, or every one when nothing is known."""
    tables = PY_RESPONSE_FIELDS[kind]
    if version and version_key(version):
        if version in tables:
            return [tables[version]]
        major = version_key(version)[0]
        same = [t for v, t in tables.items() if version_key(v)[0] == major]
        if same:
            return same
    if spec:
        admitted = [t for v, t in tables.items() if spec_admits(spec, v, _next_patch(v), ecosystem="pypi")]
        if admitted:
            return admitted
    return list(tables.values())


def _next_patch(version: str) -> str:
    major, minor, patch = version_key(version)
    return f"{major}.{minor}.{patch + 1}"


def py_field_missing(kind: str, field: str, spec: str | None, version: str | None) -> bool:
    if field.startswith("_") or field.startswith("model_") or field in PY_MODEL_ATTRS:
        return False
    return all(field not in table for table in py_tables(kind, spec, version))


#: ``get_contract_data(..., durability=...)`` compares the argument with
#: ``Durability.PERSISTENT`` and uses TEMPORARY for anything else (every verified release).
PY_DURABILITY_METHODS = frozenset({"get_contract_data"})

# ------------------------------------------------------------------ JavaScript @stellar/stellar-sdk

#: Top-level exports a major release removed: (package, symbol) -> first release without it.
#: ``SorobanRpc`` was a deprecated alias of ``rpc`` in 12.x (lib/index.d.ts) and is gone
#: from 13.0.0 ("The SorobanRpc import, previously deprecated, has been removed").
JS_REMOVED_EXPORTS = {("@stellar/stellar-sdk", "SorobanRpc"): "13.0.0"}
#: RPC methods that read a submitted transaction's outcome. pollTransaction returns the
#: last NOT_FOUND response when it runs out of attempts (lib/rpc/server.js).
POLL_METHODS = frozenset({"getTransaction", "pollTransaction", "get_transaction", "poll_transaction"})
#: Calls that submit and then wait for the outcome themselves.
SELF_POLLING = frozenset({"signAndSend", "signAndSendTransaction"})

# ------------------------------------------------------------------ amounts

#: The largest amount (or trustline limit) an operation accepts: int64 stroops / 10^7. A
#: larger value throws in stellar-base isValidAmount and in the Python SDK.
MAX_AMOUNT = "922337203685.4775807"
MAX_STROOPS = 9223372036854775807
