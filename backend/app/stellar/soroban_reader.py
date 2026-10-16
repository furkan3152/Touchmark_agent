"""Read-only Soroban ledger reads used to identify on-chain agents.

Everything here is read with `getLedgerEntries` (no simulation, no transaction, no
key): a contract's instance and executable, the WASM code itself, its contract spec
(functions) and metadata (SEP-46 `contractmetav0`, including a declared source
repository), and records in the AgentVeritas `AgentRegistry` contract.

The WASM hash is recomputed from the downloaded bytes and compared with the hash the
ledger references, so the functions and metadata reported belong to the code that
actually runs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx
from stellar_sdk import Address, StrKey, xdr
from stellar_sdk.xdr.base import Unpacker

from .networks import NETWORKS

MAX_WASM_BYTES = 2_000_000


class LedgerUnavailable(Exception):
    """The RPC could not be reached or returned an error; nothing is concluded."""


@dataclass
class SpecFunction:
    name: str
    inputs: list[tuple[str, str]]
    outputs: list[str]
    doc: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "inputs": [{"name": n, "type": t} for n, t in self.inputs],
                "outputs": self.outputs, "doc": self.doc[:300]}


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
    meta: dict[str, str] = {}
    for entry in _entries(data, xdr.SCMetaEntry):
        key, val = _text(entry.v0.key), _text(entry.v0.val)
        meta[key] = val if key not in meta else meta[key] + "," + val
    return meta


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


class SorobanReader:
    def __init__(self, network: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 15.0):
        profile = NETWORKS[network]
        self.network, self.rpc_url = network, profile.rpc_url
        self._transport, self._timeout = transport, timeout

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, follow_redirects=False, transport=self._transport)

    async def entries(self, keys: list[xdr.LedgerKey]) -> dict[str, xdr.LedgerEntryData]:
        """Entries by their key XDR; missing keys are simply absent."""
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
        wanted = {k.to_xdr() for k in keys}
        out = {}
        for item in payload["result"]["entries"]:
            if item.get("key") in wanted:
                out[item["key"]] = xdr.LedgerEntryData.from_xdr(item["xdr"])
        return out

    @staticmethod
    def _data_key(contract_id: str, key: xdr.SCVal, durability=xdr.ContractDataDurability.PERSISTENT) -> xdr.LedgerKey:
        return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
            contract=Address(contract_id).to_xdr_sc_address(), key=key, durability=durability))

    async def contract(self, contract_id: str, *, wasm: bool = True) -> dict:
        """Instance, executable, and (for WASM contracts) verified spec and metadata."""
        if not StrKey.is_valid_contract(contract_id):
            raise ValueError("not a contract address")
        key = self._data_key(contract_id, xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE))
        found = await self.entries([key])
        entry = found.get(key.to_xdr())
        if entry is None:
            return {"status": "not_found", "contract_id": contract_id, "network": self.network}
        instance = entry.contract_data.val.instance
        executable = instance.executable
        facts: dict = {"status": "found", "contract_id": contract_id, "network": self.network,
                       "instance_storage_entries": len(instance.storage.sc_map) if instance.storage else 0}
        if executable.type == xdr.ContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET:
            facts["executable"] = "stellar_asset"
            return facts
        wasm_hash = executable.wasm_hash.hash
        facts.update(executable="wasm", wasm_hash=wasm_hash.hex())
        if not wasm:
            return facts
        code_key = xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_CODE,
                                 contract_code=xdr.LedgerKeyContractCode(hash=xdr.Hash(wasm_hash)))
        code_entry = (await self.entries([code_key])).get(code_key.to_xdr())
        if code_entry is None:
            facts["code"] = "archived_or_missing"
            return facts
        code = bytes(code_entry.contract_code.code)
        if len(code) > MAX_WASM_BYTES:
            facts["code"] = "too_large"
            return facts
        facts["code_size"] = len(code)
        facts["wasm_hash_verified"] = hashlib.sha256(code).hexdigest() == wasm_hash.hex()
        try:
            sections = wasm_custom_sections(code)
            functions = parse_spec(sections.get("contractspecv0", b""))
            meta = parse_meta(sections.get("contractmetav0", b"")) if sections.get("contractmetav0") else {}
        except (ValueError, IndexError, KeyError, AttributeError) as exc:
            facts["spec_error"] = str(exc)[:200]
            return facts
        facts["functions"] = [f.as_dict() for f in functions]
        facts["meta"] = meta
        facts["custom_account"] = any(f.name == "__check_auth" for f in functions)
        facts["upgradeable"] = any(f.name in {"upgrade", "update_code", "set_wasm"} for f in functions)
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
