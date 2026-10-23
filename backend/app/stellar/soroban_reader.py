"""Read-only Soroban ledger reads used to identify on-chain agents.

Everything here is read with `getLedgerEntries` (no simulation, no transaction, no
key): a contract's instance and executable, the WASM code itself, its contract spec
(functions) and metadata (SEP-46 `contractmetav0`, including a declared source
repository), and records in the AgentVeritas `AgentRegistry` contract.

The WASM hash is recomputed from the downloaded bytes and compared with the hash the
ledger references, so the functions and metadata reported belong to the code that
actually runs. A contract whose executable is a CAP-85 external reference runs the WASM
named by its owner's executable-tag entry; that entry and the owner are read too (one
level), because whoever can rewrite the entry controls the agent's code.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from dataclasses import dataclass

import httpx
import xdrlib3
from stellar_sdk import Address, StrKey, xdr
from stellar_sdk.xdr.base import Unpacker

from . import wasm_profile
from .networks import NETWORKS

MAX_WASM_BYTES = 2_000_000
#: What decoding ledger XDR or WASM can raise; the resolver records these as unreadable.
READ_ERRORS = (ValueError, TypeError, AttributeError, KeyError, IndexError, EOFError, struct.error, xdrlib3.Error)
#: Upgrade entry points by name, used only when the WASM imports cannot be read.
_UPGRADE_NAMES = frozenset({"upgrade", "update_code", "set_wasm"})
#: Spec functions kept in the facts (the exports the profile describes first), parameters kept
#: per function (the host passes an invoked function at most 32 arguments: rs-soroban-env
#: 0c99950e vm.rs MAX_VM_ARGS) and over all of them, and characters kept of a type name. A spec
#: is as large as the module lets it be (XDR bounds names, not counts); the rules read the
#: parameters of the described exports, and treat a function whose parameters were cut as untyped.
_MAX_FUNCTIONS, _MAX_INPUTS, _MAX_ALL_INPUTS, _MAX_TYPE = wasm_profile._MAX_EXPORTS, wasm_profile._MAX_ARGS, 512, 64
#: contractmetav0 entries kept, and characters kept of a key and of a value.
_MAX_META, _MAX_META_KEY, _MAX_META_VALUE = 32, 64, 256
#: What the deep review gets of a profile's name lists and of each function's signature and doc.
_REVIEW_NAMES, _REVIEW_SIGNATURE, _REVIEW_DOC = 64, 200, 120


class LedgerUnavailable(Exception):
    """The RPC could not be reached or returned an error; nothing is concluded."""


@dataclass
class LedgerEntry:
    data: xdr.LedgerEntryData
    last_modified: int | None
    #: None for entries without a TTL. RPC reports archived entries with 0.
    live_until: int | None
    archived: bool


@dataclass
class SpecFunction:
    name: str
    inputs: list[tuple[str, str]]
    outputs: list[str]
    doc: str = ""

    def as_dict(self, max_inputs: int = _MAX_INPUTS) -> dict:
        """The function as facts; parameters past ``max_inputs`` are counted, not listed."""
        out = {"name": self.name, "inputs": [{"name": n, "type": t[:_MAX_TYPE]} for n, t in self.inputs[:max_inputs]],
               "outputs": [t[:_MAX_TYPE] for t in self.outputs[:1]], "doc": self.doc[:300]}  # XDR: outputs<1>
        if len(self.inputs) > max_inputs:
            out["inputs_omitted"] = len(self.inputs) - max_inputs
        return out


def _leb128(data: bytes, offset: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated LEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return result, offset
        if shift > 35:
            raise ValueError("LEB128 too long")


def wasm_custom_sections(wasm: bytes) -> dict[str, bytes]:
    """Custom sections of a WASM module by name (concatenated when repeated)."""
    if wasm[:4] != b"\0asm":
        raise ValueError("not a WASM module")
    sections: dict[str, bytes] = {}
    offset = 8
    while offset < len(wasm):
        section_id = wasm[offset]
        size, offset = _leb128(wasm, offset + 1)
        end = offset + size
        if end > len(wasm):
            raise ValueError("truncated WASM section")
        if section_id == 0:
            name_len, start = _leb128(wasm, offset)
            name = wasm[start:start + name_len].decode("utf-8", "replace")
            sections[name] = sections.get(name, b"") + wasm[start + name_len:end]
        offset = end
    return sections


def _ledger(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _entries(data: bytes, cls) -> list:
    out = []
    unpacker = Unpacker(data)
    while unpacker.get_position() < len(data):
        out.append(cls.unpack(unpacker))
    return out


def _type_name(spec_type) -> str:
    t = spec_type.type
    name = t.name.replace("SC_SPEC_TYPE_", "").lower()
    if t == xdr.SCSpecType.SC_SPEC_TYPE_UDT and spec_type.udt is not None:
        return spec_type.udt.name.decode() if isinstance(spec_type.udt.name, bytes) else str(spec_type.udt.name)
    if t == xdr.SCSpecType.SC_SPEC_TYPE_VEC and spec_type.vec is not None:
        return f"vec<{_type_name(spec_type.vec.element_type)}>"
    if t == xdr.SCSpecType.SC_SPEC_TYPE_OPTION and spec_type.option is not None:
        return f"option<{_type_name(spec_type.option.value_type)}>"
    if t == xdr.SCSpecType.SC_SPEC_TYPE_BYTES_N and spec_type.bytes_n is not None:
        return f"bytes{spec_type.bytes_n.n.uint32}"
    return name


def _text(value) -> str:
    raw = getattr(value, "sc_symbol", None) or value
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def parse_spec(data: bytes) -> list[SpecFunction]:
    functions = []
    for entry in _entries(data, xdr.SCSpecEntry):
        if entry.kind != xdr.SCSpecEntryKind.SC_SPEC_ENTRY_FUNCTION_V0:
            continue
        fn = entry.function_v0
        functions.append(SpecFunction(
            name=_text(fn.name),
            inputs=[(_text(i.name), _type_name(i.type)) for i in fn.inputs],
            outputs=[_type_name(o) for o in fn.outputs],
            doc=_text(fn.doc)))
    return functions


def parse_meta(data: bytes) -> dict[str, str]:
    """contractmetav0 entries (a repeated key joins its values), at most _MAX_META keys, cut at
    _MAX_META_KEY and _MAX_META_VALUE characters."""
    meta: dict[str, str] = {}
    for entry in _entries(data, xdr.SCMetaEntry):
        key, val = _text(entry.v0.key)[:_MAX_META_KEY], _text(entry.v0.val)
        if key in meta:
            meta[key] = (meta[key] + "," + val)[:_MAX_META_VALUE]
        elif len(meta) < _MAX_META:
            meta[key] = val[:_MAX_META_VALUE]
    return meta


def _kept_functions(functions: list[SpecFunction], described: set[str]) -> dict:
    """The spec functions as facts: at most _MAX_FUNCTIONS, those of the described exports first
    (the rules read their parameters), then in spec order; at most _MAX_ALL_INPUTS parameters
    over all of them. ``functions_omitted`` counts the functions left out."""
    order = [f for f in functions if f.name in described] + [f for f in functions if f.name not in described]
    kept, room = [], _MAX_ALL_INPUTS
    for f in order[:_MAX_FUNCTIONS]:
        kept.append(f.as_dict(min(_MAX_INPUTS, room)))
        room -= len(kept[-1]["inputs"])
    out: dict = {"functions": kept}
    if len(functions) > _MAX_FUNCTIONS:
        out["functions_omitted"] = len(functions) - _MAX_FUNCTIONS
    return out


def _sc_to_py(value: xdr.SCVal):
    t = value.type
    T = xdr.SCValType
    if t == T.SCV_BOOL:
        return value.b
    if t == T.SCV_VOID:
        return None
    if t == T.SCV_U32:
        return value.u32.uint32
    if t == T.SCV_I32:
        return value.i32.int32
    if t == T.SCV_U64:
        return value.u64.uint64
    if t == T.SCV_I64:
        return value.i64.int64
    if t == T.SCV_BYTES:
        return value.bytes.sc_bytes.hex()
    if t == T.SCV_STRING:
        return _text(value.str.sc_string)
    if t == T.SCV_SYMBOL:
        return _text(value.sym.sc_symbol)
    if t == T.SCV_ADDRESS:
        return Address.from_xdr_sc_address(value.address).address
    if t == T.SCV_VEC:
        return [_sc_to_py(v) for v in (value.vec.sc_vec if value.vec else [])]
    if t == T.SCV_MAP:
        return {str(_sc_to_py(e.key)): _sc_to_py(e.val) for e in (value.map.sc_map if value.map else [])}
    return t.name


def _inspect(code: bytes) -> dict:
    """Spec, metadata and bytecode profile of a WASM (CPU only; the reader runs it in a thread)."""
    facts: dict = {}
    functions: list[SpecFunction] | None = None
    try:
        sections = wasm_custom_sections(code)
        spec = parse_spec(sections.get("contractspecv0", b""))
        meta = parse_meta(sections.get("contractmetav0", b"")) if sections.get("contractmetav0") else {}
    except READ_ERRORS as exc:
        facts["spec_error"] = str(exc)[:200]
    else:
        functions = spec
        facts.update(meta=meta, custom_account=any(f.name == "__check_auth" for f in functions))
    try:
        profile = wasm_profile.profile(code, [f.name for f in functions or []])
    except wasm_profile.WasmError as exc:
        facts["profile_error"] = str(exc)[:200]
        facts["upgradeable"] = any(f.name in _UPGRADE_NAMES for f in functions or [])
        profile = {}
    else:
        facts["profile"] = profile
        facts["upgradeable"] = profile["can_upgrade"]
    if functions is not None:
        facts.update(_kept_functions(functions, set(profile.get("exports") or {})))
    return facts


def _signature(function: dict) -> dict:
    """A spec function as one line, "name(arg: type, ...) -> type", and the start of its doc."""
    args = [f"{i['name']}: {i['type']}" for i in function.get("inputs", [])]
    if function.get("inputs_omitted"):
        args.append(f"... {function['inputs_omitted']} more")
    line = f"{function['name']}({', '.join(args)})" + "".join(f" -> {t}" for t in function.get("outputs", []))
    out = {"function": line[:_REVIEW_SIGNATURE]}
    if function.get("doc"):
        out["doc"] = function["doc"][:_REVIEW_DOC]
    return out


def without_export_detail(chain: dict) -> dict:
    """Chain facts with each WASM profile cut to its module-level facts (imports, upgrade
    exports and their paths, hidden exports, delegated signers, coverage), its other name lists
    cut to _REVIEW_NAMES, and the spec functions cut to their signatures. The per-export reach
    and flows feed the rules and stay in the report; a reviewer reading the facts gets the
    summary, which stays small whatever the module holds."""
    def cut(contract: dict) -> dict:
        out = dict(contract)
        if isinstance(out.get("profile"), dict):
            profile = {k: v for k, v in out["profile"].items() if k != "exports"}
            profile["exports_described"] = len(out["profile"].get("exports") or {})
            for key, names in out["profile"].items():  # imports are bounded by the host table
                if key != "imports" and isinstance(names, list) and len(names) > _REVIEW_NAMES:
                    profile[key] = names[:_REVIEW_NAMES]
                    profile[f"{key}_omitted"] = profile.get(f"{key}_omitted", 0) + len(names) - _REVIEW_NAMES
            out["profile"] = profile
        if isinstance(out.get("functions"), list):
            out["functions"] = [_signature(f) for f in out["functions"]]
        ref = out.get("external_ref")
        if isinstance(ref, dict) and isinstance(ref.get("owner_contract"), dict):
            out["external_ref"] = {**ref, "owner_contract": cut(ref["owner_contract"])}
        return out
    if not isinstance((chain or {}).get("contract"), dict):
        return chain
    return {**chain, "contract": cut(chain["contract"])}


class SorobanReader:
    def __init__(self, network: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 15.0):
        profile = NETWORKS[network]
        self.network, self.rpc_url = network, profile.rpc_url
        self._transport, self._timeout = transport, timeout

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, follow_redirects=False, transport=self._transport)

    async def read(self, keys: list[xdr.LedgerKey]) -> tuple[dict[str, LedgerEntry], int | None]:
        """Entries by their key XDR, and the ledger the RPC read them at; missing keys are absent."""
        if not self.rpc_url:
            raise LedgerUnavailable("no RPC for this network")
        try:
            async with await self._client() as client:
                response = await client.post(self.rpc_url, json={
                    "jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries",
                    "params": {"keys": [k.to_xdr() for k in keys]}})
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LedgerUnavailable(str(exc)) from exc
        if payload.get("error") or not isinstance(payload.get("result", {}).get("entries"), list):
            raise LedgerUnavailable(str(payload.get("error", "malformed RPC response"))[:200])
        latest = _ledger(payload["result"].get("latestLedger"))
        wanted = {k.to_xdr() for k in keys}
        out = {}
        for item in payload["result"]["entries"]:
            if item.get("key") in wanted:
                live = _ledger(item.get("liveUntilLedgerSeq"))
                out[item["key"]] = LedgerEntry(
                    xdr.LedgerEntryData.from_xdr(item["xdr"]), _ledger(item.get("lastModifiedLedgerSeq")), live,
                    archived=live is not None and (live == 0 or (latest is not None and live < latest)))
        return out, latest

    async def entries(self, keys: list[xdr.LedgerKey]) -> dict[str, xdr.LedgerEntryData]:
        """Entries by their key XDR; missing keys are simply absent."""
        found, _ = await self.read(keys)
        return {k: e.data for k, e in found.items()}

    @staticmethod
    def _data_key(contract_id: str, key: xdr.SCVal, durability=xdr.ContractDataDurability.PERSISTENT) -> xdr.LedgerKey:
        return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
            contract=Address(contract_id).to_xdr_sc_address(), key=key, durability=durability))

    async def contract(self, contract_id: str, *, wasm: bool = True, follow_ref: bool = True) -> dict:
        """Instance and executable, and for the WASM that runs (named directly or through a
        CAP-85 executable reference) its verified spec, metadata and import profile.

        ``follow_ref=False`` records an executable reference without reading its entry; the
        owner of a reference is read that way, so the chain is followed one level only."""
        if not StrKey.is_valid_contract(contract_id):
            raise ValueError("not a contract address")
        key = self._data_key(contract_id, xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE))
        found, latest = await self.read([key])
        entry = found.get(key.to_xdr())
        if entry is None:
            return {"status": "not_found", "contract_id": contract_id, "network": self.network}
        instance = entry.data.contract_data.val.instance
        executable = instance.executable
        facts: dict = {"status": "found", "contract_id": contract_id, "network": self.network,
                       "read_at_ledger": latest, "instance_last_modified_ledger": entry.last_modified,
                       "instance_storage_entries": len(instance.storage.sc_map) if instance.storage else 0}
        if entry.archived:
            facts["instance_archived"] = True
        kinds = xdr.ContractExecutableType
        if executable.type == kinds.CONTRACT_EXECUTABLE_STELLAR_ASSET:
            facts["executable"] = "stellar_asset"
            return facts
        if executable.type == kinds.CONTRACT_EXECUTABLE_WASM:
            wasm_hash = executable.wasm_hash.hash
            facts.update(executable="wasm", wasm_hash=wasm_hash.hex())
        elif executable.type == kinds.CONTRACT_EXECUTABLE_EXTERNAL_REF:
            facts["executable"] = "external_ref"
            ref = facts["external_ref"] = await self._external_ref(contract_id, executable.external_ref, follow_ref)
            if ref["status"] != "resolved":
                return facts
            wasm_hash = bytes.fromhex(ref["resolved_wasm_hash"])
            facts["wasm_hash"] = ref["resolved_wasm_hash"]  # the code that runs until the entry changes
        else:
            facts["executable"] = "unknown"
            return facts
        if wasm:
            facts.update(await self._code(wasm_hash))
        return facts

    async def _external_ref(self, contract_id: str, ref: xdr.ContractExecutableExternalRef, follow: bool) -> dict:
        """The owner's executable-tag entry: ContractData{owner, SCV_EXECUTABLE_TAG(tag),
        PERSISTENT} holding a 32-byte WASM hash (rs-soroban-env executable_ref_ledger_key)."""
        tag = _text(ref.tag.sc_string)
        try:
            owner = Address.from_xdr_sc_address(ref.executable_owner).address
        except READ_ERRORS:
            return {"status": "malformed", "tag": tag, "error": "the owner is not an address"}
        out: dict = {"owner": owner, "tag": tag}
        if not follow:
            out["status"] = "not_followed"
            return out
        key = xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
            contract=ref.executable_owner, key=xdr.SCVal(xdr.SCValType.SCV_EXECUTABLE_TAG, executable_tag=ref.tag),
            durability=xdr.ContractDataDurability.PERSISTENT))
        entry = None
        try:
            entry = (await self.read([key]))[0].get(key.to_xdr())
        except LedgerUnavailable as exc:
            out.update(status="unavailable", error=str(exc)[:200])
        except READ_ERRORS as exc:
            out.update(status="malformed", error=f"{type(exc).__name__}: {exc}"[:200])
        if entry is not None:
            out.update(tag_last_modified_ledger=entry.last_modified, tag_live_until_ledger=entry.live_until)
            if entry.archived:
                out["tag_archived"] = True  # restorable by anyone, with the same value
            value = getattr(entry.data.contract_data, "val", None)
            if value is not None and value.type == xdr.SCValType.SCV_BYTES and len(value.bytes.sc_bytes) == 32:
                out.update(status="resolved", resolved_wasm_hash=value.bytes.sc_bytes.hex())
            else:
                out["status"] = "malformed"
        elif "status" not in out:
            out["status"] = "missing"
        if owner == contract_id:
            out["owner_contract"] = {"status": "self"}
        elif StrKey.is_valid_contract(owner):
            try:
                out["owner_contract"] = await self.contract(owner, follow_ref=False)
            except LedgerUnavailable as exc:
                out["owner_contract"] = {"status": "unavailable", "error": str(exc)[:200]}
            except READ_ERRORS as exc:
                out["owner_contract"] = {"status": "unreadable", "error": f"{type(exc).__name__}: {exc}"[:200]}
        else:
            out["owner_contract"] = {"status": "not_a_contract"}
        return out

    async def _code(self, wasm_hash: bytes) -> dict:
        """The WASM a hash names, checked against the hash, with its spec, metadata and profile."""
        code_key = xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_CODE,
                                 contract_code=xdr.LedgerKeyContractCode(hash=xdr.Hash(wasm_hash)))
        code_entry = (await self.read([code_key]))[0].get(code_key.to_xdr())
        if code_entry is None:
            return {"code": "archived_or_missing"}
        code = bytes(code_entry.data.contract_code.code)
        if len(code) > MAX_WASM_BYTES:
            return {"code": "too_large"}
        facts: dict = {"code_size": len(code), "wasm_hash_verified": hashlib.sha256(code).hexdigest() == wasm_hash.hex()}
        if code_entry.archived:
            facts["code_archived"] = True
        # Bounded CPU work (wasm_profile budgets it), off the event loop so other requests go on.
        facts.update(await asyncio.to_thread(_inspect, code))
        return facts

    async def registry_agent(self, registry_id: str, agent_id_hex: str) -> dict:
        """An AgentVeritas AgentRegistry record (DataKey::Agent(id))."""
        agent_id = bytes.fromhex(agent_id_hex)
        if len(agent_id) != 32:
            raise ValueError("agent id must be 32 bytes (64 hex characters)")
        key = self._data_key(registry_id, xdr.SCVal(xdr.SCValType.SCV_VEC, vec=xdr.SCVec([
            xdr.SCVal(xdr.SCValType.SCV_SYMBOL, sym=xdr.SCSymbol(b"Agent")),
            xdr.SCVal(xdr.SCValType.SCV_BYTES, bytes=xdr.SCBytes(agent_id))])))
        entry = (await self.entries([key])).get(key.to_xdr())
        if entry is None:
            return {"status": "not_found", "agent_id": agent_id_hex, "registry": registry_id}
        record = _sc_to_py(entry.contract_data.val)
        if not isinstance(record, dict):
            return {"status": "malformed", "agent_id": agent_id_hex, "registry": registry_id}
        return {"status": "found", "agent_id": agent_id_hex, "registry": registry_id, "network": self.network,
                "owner": record.get("owner", ""), "meta_uri": record.get("meta_uri", ""),
                "meta_hash": record.get("meta_hash", ""), "end_hash": record.get("end_hash", ""),
                "active": bool(record.get("active")), "version": record.get("version", 0)}
