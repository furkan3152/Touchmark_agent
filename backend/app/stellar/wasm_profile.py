"""What a deployed Soroban WASM can do, read from its bytecode.

A contract reaches the ledger only through host functions, which it imports by short
codes ("l.6" is update_current_contract_wasm). The imports say what the module can do at
all; a call graph over the code section says which exported function can reach which host
function. That is evidence about the deployed code whatever source is shown, and it finds
an upgrade entry point whatever it is named.

The codes are named from soroban_env_host_fns.json, a subset of rs-soroban-env's env.json
pinned to one commit. The decoder knows the instructions a Soroban build contains (MVP,
sign extension, saturating truncation, bulk memory and table operations, reference types).
Anything else stops the call graph: that is an evidence gap, never a finding.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

_TABLE = json.loads((Path(__file__).parent / "soroban_env_host_fns.json").read_text())
#: Host function export code -> (name, minimum protocol or None).
HOST_FUNCTIONS: dict[str, tuple[str, int | None]] = {k: (v[0], v[1]) for k, v in _TABLE["functions"].items()}
#: The rs-soroban-env commit the table was taken from.
HOST_TABLE_COMMIT: str = _TABLE["source"]["commit"]
#: Bumped whenever the decoder or the facts it derives change.
DECODER_VERSION = "1"

#: update_current_contract_wasm, update_current_contract_executable_ref: replace own code.
UPGRADE = frozenset({"l.6", "l.j"})
#: create_executable_tag, create_external_ref_contract (CAP-85, protocol 28).
EXTERNAL_REF = frozenset({"l.h", "l.i"})
#: put_contract_data: with create_executable_tag, writes an executable reference entry.
PUT_DATA = "l._"
#: require_auth, require_auth_for_args, delegate_account_auth.
AUTH_CALLS = frozenset({"a.0", "a._", "a.a"})
#: Signature and pairing checks: ed25519, secp256k1 recovery, secp256r1, BLS12-381 and
#: BN254 pairings, ML-DSA.
SIG_VERIFY = frozenset({"c.0", "c.2", "c.3", "c.g", "c.o", "c.A", "c.B", "c.C"})
#: Anything that authenticates a caller or checks a signature.
AUTH = AUTH_CALLS | SIG_VERIFY
#: call, try_call: another contract may decide.
CALL = frozenset({"d._", "d.0"})
#: get_delegated_signers_for_current_auth_check: user-supplied signers (protocol 27).
DELEGATED_SIGNERS = "a.9"
#: obj_cmp and has_contract_data: ways a supplied value can be checked against state.
VALUE_CHECKS = frozenset({"x.0", "l.0"})
#: Exports the SDK adds that are never in the contract spec.
SDK_EXPORTS = frozenset({"_"})
#: Entry points the host calls itself; not reachable by an ordinary invocation.
HOST_ENTRY_POINTS = frozenset({"__check_auth", "__constructor"})
#: Host functions whose call paths are recorded for findings.
_TRACED = UPGRADE | EXTERNAL_REF | CALL | {PUT_DATA, DELEGATED_SIGNERS}

_BLOCK_TYPES = frozenset({0x40, 0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F})
_NO_IMMEDIATE = frozenset({0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1, *range(0x45, 0xC5)})
_ONE_INDEX = frozenset({0x0C, 0x0D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x3F, 0x40, 0xD2})
#: 0xFC sub-opcode -> number of index immediates (0-7 are the saturating truncations).
_FC_INDEXES = {**{n: 0 for n in range(8)}, 8: 2, 9: 1, 10: 2, 11: 1, 12: 2, 13: 1, 14: 2, 15: 1, 16: 1, 17: 1}


class WasmError(ValueError):
    """The module is malformed or uses an instruction the decoder does not know."""


def _u32(data: bytes, offset: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if offset >= len(data):
            raise WasmError("truncated LEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            raise WasmError("LEB128 too long")


def _name(data: bytes, offset: int) -> tuple[str, int]:
    size, offset = _u32(data, offset)
    if offset + size > len(data):
        raise WasmError("truncated name")
    return data[offset:offset + size].decode("utf-8", "replace"), offset + size


def _limits(data: bytes, offset: int) -> int:
    flags = data[offset]
    _, offset = _u32(data, offset + 1)
    return _u32(data, offset)[1] if flags & 1 else offset


@dataclass
class Module:
    #: Host code ("l.6") of each imported function, in function index order.
    func_imports: list[str] = field(default_factory=list)
    #: Function exports: name -> function index.
    exports: dict[str, int] = field(default_factory=dict)
    #: Code section bodies of the defined functions, in order.
    bodies: list[bytes] = field(default_factory=list)
    defined: int = 0


def parse_module(wasm: bytes) -> Module:
    """Imports, function exports and function bodies of a WASM module."""
    try:
        return _parse_module(wasm)
    except IndexError as exc:
        raise WasmError("truncated WASM module") from exc


def _parse_module(wasm: bytes) -> Module:
    if wasm[:4] != b"\0asm":
        raise WasmError("not a WASM module")
    module = Module()
    offset = 8
    while offset < len(wasm):
        section_id = wasm[offset]
        size, start = _u32(wasm, offset + 1)
        end = start + size
        if end > len(wasm):
            raise WasmError("truncated WASM section")
        body = wasm[start:end]
        if section_id == 2:
            count, pos = _u32(body, 0)
            for _ in range(count):
                mod, pos = _name(body, pos)
                fld, pos = _name(body, pos)
                kind = body[pos]
                pos += 1
                if kind == 0:
                    _, pos = _u32(body, pos)
                    module.func_imports.append(f"{mod}.{fld}")
                elif kind == 1:
                    pos = _limits(body, pos + 1)
                elif kind == 2:
                    pos = _limits(body, pos)
                elif kind == 3:
                    pos += 2
                else:
                    raise WasmError(f"unknown import kind {kind}")
        elif section_id == 3:
            module.defined = _u32(body, 0)[0]
        elif section_id == 7:
            count, pos = _u32(body, 0)
            for _ in range(count):
                name, pos = _name(body, pos)
                kind = body[pos]
                index, pos = _u32(body, pos + 1)
                if kind == 0:
                    module.exports[name] = index
        elif section_id == 10:
            count, pos = _u32(body, 0)
            for _ in range(count):
                length, pos = _u32(body, pos)
                module.bodies.append(body[pos:pos + length])
                pos += length
        offset = end
    if module.bodies and len(module.bodies) != module.defined:
        raise WasmError("function and code sections disagree")
    return module


def _calls(body: bytes, where: str) -> tuple[set[int], bool]:
    """Direct call targets of one function body, and whether it calls indirectly."""
    targets: set[int] = set()
    indirect = False
    count, pos = _u32(body, 0)
    for _ in range(count):  # local declarations: (count, valtype)
        _, pos = _u32(body, pos)
        pos += 1
    end = len(body)
    while pos < end:
        op = body[pos]
        pos += 1
        if op in _NO_IMMEDIATE:
            continue
        if op in _ONE_INDEX:
            _, pos = _u32(body, pos)
        elif op == 0x10:
            target, pos = _u32(body, pos)
            targets.add(target)
        elif op == 0x11:
            indirect = True
            _, pos = _u32(body, pos)
            _, pos = _u32(body, pos)
        elif op in (0x02, 0x03, 0x04):
            if pos < end and body[pos] in _BLOCK_TYPES:
                pos += 1
            else:
                _, pos = _u32(body, pos)  # s33 type index
        elif op == 0x0E:
            labels, pos = _u32(body, pos)
            for _ in range(labels + 1):
                _, pos = _u32(body, pos)
        elif 0x28 <= op <= 0x3E:
            _, pos = _u32(body, pos)
            _, pos = _u32(body, pos)
        elif op in (0x41, 0x42):
            _, pos = _u32(body, pos)  # signed LEB: only its length matters
        elif op == 0x43:
            pos += 4
        elif op == 0x44:
            pos += 8
        elif op == 0x1C:
            types, pos = _u32(body, pos)
            pos += types
        elif op == 0xD0:
            pos += 1
        elif op == 0xFC:
            sub, pos = _u32(body, pos)
            if sub not in _FC_INDEXES:
                raise WasmError(f"unsupported instruction 0xfc {sub} in {where}")
            for _ in range(_FC_INDEXES[sub]):
                _, pos = _u32(body, pos)
        else:
            raise WasmError(f"unsupported instruction 0x{op:02x} in {where}")
    if pos != end:
        raise WasmError(f"truncated body of {where}")
    return targets, indirect


def describe(code: str) -> str:
    name = HOST_FUNCTIONS.get(code, ("unknown",))[0]
    return f"{code} ({name})"


def profile(wasm: bytes, spec_names: list[str] | None = None) -> dict:
    """Import facts for the module and, per function export, the host functions it can reach.

    Reachability follows direct calls through every branch, so a host function missing from
    an export's set is never called by it, except through call_indirect, which is recorded.
    Raises WasmError when the module itself cannot be read; a body the decoder does not know
    only leaves the call graph out (``callgraph.status`` says why).
    """
    module = parse_module(wasm)
    imports = set(module.func_imports)
    out: dict = {
        "decoder": DECODER_VERSION, "host_table_commit": HOST_TABLE_COMMIT,
        "imports": sorted(imports), "unknown_imports": sorted(i for i in imports if i not in HOST_FUNCTIONS),
        "can_upgrade": bool(imports & UPGRADE), "has_auth": bool(imports & AUTH_CALLS),
        "calls_out": bool(imports & CALL), "verifies_sig": bool(imports & SIG_VERIFY),
        "manages_external_refs": bool(imports & EXTERNAL_REF), "writes_data": PUT_DATA in imports,
        "function_exports": sorted(module.exports),
    }
    if spec_names:
        named = set(spec_names)
        out["hidden_exports"] = sorted(n for n in module.exports if n not in named and n not in SDK_EXPORTS
                                       and (not n.startswith("__") or n in HOST_ENTRY_POINTS))
        out["spec_only"] = sorted(named - set(module.exports))
    imported = len(module.func_imports)
    graph: list[tuple[set[int], bool]] = []
    try:
        for i, body in enumerate(module.bodies):
            graph.append(_calls(body, f"f{imported + i}"))
    except WasmError as exc:
        out["callgraph"] = {"status": "undecoded", "error": str(exc)[:200]}
        return out
    out["callgraph"] = {"status": "decoded", "functions": len(graph)}
    out["exports"] = {name: _reach(name, index, module, graph) for name, index in sorted(module.exports.items())}
    return out


def _reach(name: str, start: int, module: Module, graph: list[tuple[set[int], bool]]) -> dict:
    imported = len(module.func_imports)
    parent: dict[int, int | None] = {start: None}
    queue = deque([start])
    reached: set[str] = set()
    paths: dict[str, str] = {}
    indirect = False
    while queue:
        node = queue.popleft()
        if node < imported:
            code = module.func_imports[node]
            reached.add(code)
            if code in _TRACED and code not in paths:
                hops, step = [], parent[node]
                while step is not None:
                    hops.append(f"f{step}")
                    step = parent[step]
                paths[code] = " -> ".join([f"export {name}", *hops[::-1], f"import {describe(code)}"])
            continue
        if node - imported >= len(graph):
            continue
        targets, calls_indirect = graph[node - imported]
        indirect |= calls_indirect
        for target in sorted(targets):
            if target not in parent:
                parent[target] = node
                queue.append(target)
    return {"reaches": sorted(reached), "indirect": indirect, "paths": paths}
