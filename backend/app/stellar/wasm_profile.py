"""What a deployed Soroban WASM can do, read from its bytecode.

A contract reaches the ledger only through host functions, which it imports by short
codes ("l.6" is update_current_contract_wasm). The imports say what the module can do at
all; a call graph over the code section says which exported function can reach which host
function. That is evidence about the deployed code whatever source is shown, and it finds
an upgrade entry point whatever it is named.

Reaching a host function is not enough to tell who chooses what it does: an upgrade that
installs the hash its caller passes is open to anyone, one that installs a hash an
authenticated step stored is a timelock. A small data flow over the same instructions
follows each export's arguments through the operand stack, locals, direct calls and the
stack-frame slots the SDK passes values through (a BytesN argument is converted through an
out-pointer) into the arguments of update_current_contract_wasm,
update_current_contract_executable_ref and put_contract_data, and into any host function
that could check them. A memory write it cannot place forgets every slot, so the flow can
miss a path but does not invent one; what an argument lost that way is recorded, because
"nothing checks the hash" is only shown when nothing about the hash was forgotten (an open
upgrade whose hash was is left undecided: an evidence gap).

The codes are named from soroban_env_host_fns.json, a subset of rs-soroban-env's env.json
pinned to one commit. The decoder knows the instructions a Soroban build contains (MVP,
sign extension, saturating truncation, bulk memory and table operations, reference types).
Anything else stops the call graph: that is an evidence gap, never a finding.

Anyone can deploy a module and have it read, so every step is bounded: reachability is
computed once per strongly connected component of the call graph, the data flow counts its
work and gives up at a budget (an evidence gap), and the facts describe at most
_MAX_EXPORTS exports, those findings can come from first.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_TABLE = json.loads((Path(__file__).parent / "soroban_env_host_fns.json").read_text())
#: Host function export code -> (name, minimum protocol or None).
HOST_FUNCTIONS: dict[str, tuple[str, int | None]] = {k: (v[0], v[1]) for k, v in _TABLE["functions"].items()}
#: The rs-soroban-env commit the table was taken from.
HOST_TABLE_COMMIT: str = _TABLE["source"]["commit"]
#: Bumped whenever the decoder or the facts it derives change.
DECODER_VERSION = "4"

#: update_current_contract_wasm, update_current_contract_executable_ref: replace own code.
UPGRADE = frozenset({"l.6", "l.j"})
#: create_executable_tag, create_external_ref_contract (CAP-85, protocol 28).
EXTERNAL_REF = frozenset({"l.h", "l.i"})
#: put_contract_data: with create_executable_tag, writes an executable reference entry.
PUT_DATA = "l._"
#: get_contract_data: its result is a value read from storage.
GET_DATA = "l.1"
#: create_executable_tag: its result is the key of an executable reference entry.
EXECUTABLE_TAG = "l.h"
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
#: Exports the SDK adds that are never in the contract spec.
SDK_EXPORTS = frozenset({"_"})
#: Entry points the host calls itself; not reachable by an ordinary invocation.
HOST_ENTRY_POINTS = frozenset({"__check_auth", "__constructor"})
#: Function names are SCSymbols: at most 32 bytes of [A-Za-z0-9_] (Stellar-contract.x
#: SCSYMBOL_LIMIT, rs-soroban-env symbol.rs encode_byte). The host looks an invoked function
#: up by that name, so an export named otherwise cannot be invoked.
_SYMBOL = re.compile(r"[A-Za-z0-9_]{0,32}")
#: Names the host refuses to invoke unless it makes the call itself, which it does only for
#: HOST_ENTRY_POINTS (rs-soroban-env 0c99950e host/frame.rs RESERVED_CONTRACT_FN_PREFIX,
#: checked in call_n_internal for transactions and contract calls alike).
_RESERVED_PREFIX = "__"
#: The host passes an invoked function at most this many arguments (vm.rs MAX_VM_ARGS), and
#: the VM calls a function only with as many as it takes.
_MAX_VM_ARGS = 32
#: Host functions whose call paths are recorded for findings.
_TRACED = UPGRADE | EXTERNAL_REF | CALL | {PUT_DATA, DELEGATED_SIGNERS}
#: Storage and executable-tag writes; what an unlisted export must not reach unauthenticated.
_WRITES, _RISKY = frozenset({PUT_DATA, EXECUTABLE_TAG}), UPGRADE | CALL | {PUT_DATA}
#: Host functions whose arguments the data flow records, with their arity (env.json).
_SINKS = {"l.6": 1, "l.j": 2, PUT_DATA: 3}
#: Host functions that use a value without being able to check it: the SDK's BytesN length
#: check, events and logs, storage writes, deletes and TTL extensions, the upgrades, tag
#: creation. Any other host function a supplied hash reaches (obj_cmp, a storage lookup, a
#: byte copy, a hash) may compare it with an approval. Reaching has_contract_data alone says
#: nothing: every SDK storage read (Storage::get) calls it before get_contract_data.
_NOT_CHECKS = frozenset({"b.8", "x.1", "x._", PUT_DATA, "l.2", "l.6", "l.j", "l.h", "l.7", "l.8", "l.9", "l.c", "l.d",
                         "l.f", "l.g"})

_BLOCK_TYPES = frozenset({0x40, 0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F})
_NO_IMMEDIATE = frozenset({0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1, *range(0x45, 0xC5)})
_ONE_INDEX = frozenset({0x0C, 0x0D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x3F, 0x40, 0xD2})
#: 0xFC sub-opcode -> number of index immediates (0-7 are the saturating truncations).
_FC_INDEXES = {**{n: 0 for n in range(8)}, 8: 2, 9: 1, 10: 2, 11: 1, 12: 2, 13: 1, 14: 2, 15: 1, 16: 1, 17: 1}
#: Numeric instructions that take two operands (comparisons and binary arithmetic); every
#: other opcode in 0x45-0xC4 takes one.
_BINARY = frozenset({*range(0x46, 0x50), *range(0x51, 0x67), *range(0x6A, 0x79), *range(0x7C, 0x8B),
                     *range(0x92, 0x99), *range(0xA0, 0xA7)})
#: 0xFC sub-opcode -> operands popped, values pushed (beyond the saturating truncations).
_FC_STACK = {8: (3, 0), 9: (0, 0), 10: (3, 0), 11: (3, 0), 12: (3, 0), 13: (0, 0), 14: (3, 0), 15: (2, 1),
             16: (0, 1), 17: (3, 0)}
#: Data flow bounds: more locals in a function, more rounds without a fixpoint, or more work
#: over the whole module than this leave the flow out. Work counts instructions walked and
#: values, memory slots and the sources they hold copied, joined or compared; a unit costs at
#: most 0.75 us, so the budget stops any module within about 3 s. Real builds have at most 72
#: locals and parameters in a function and use at most 14% of the budget (94 SDK and test
#: WASMs; the largest, 66 KB, takes 0.14 s).
_MAX_LOCALS, _MAX_ROUNDS, _MAX_WORK = 1_000, 64, 4_000_000
#: Work charged per walk over a body and per instruction walked, beyond the values touched.
_PASS_COST, _STEP_COST = 16, 2
#: More offsets into one base, slots, caller-visible writes or a larger offset than this are
#: forgotten.
_MAX_OFFSETS, _MAX_SLOTS, _MAX_WRITES, _MAX_OFFSET = 4, 512, 64, 1 << 20
#: Facts kept per module: exports described in detail, names per list, functions shown per
#: call path (the first and last few), argument indexes per flow.
_MAX_EXPORTS, _MAX_NAMES, _MAX_HOPS, _MAX_ARGS = 64, 256, 12, 32
#: Characters kept of a listed name (an invokable one has at most 32; imports and uninvokable
#: exports can be as long as the module).
_MAX_NAME = 64
_HEAD, _TAIL = 6, 4
_EMPTY: frozenset = frozenset()
#: The source "anything the caller had stored" (see the data flow notes below).
_CALLER_MEMORY = ("m*",)


class WasmError(ValueError):
    """The module is malformed or uses an instruction the decoder does not know."""


class _FlowError(Exception):
    """The data flow could not follow a body (an invalid stack, or no fixpoint)."""


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


def _s32(data: bytes, offset: int) -> tuple[int, int]:
    start = offset
    value, offset = _u32(data, offset)
    bits = 7 * (offset - start)
    return (value - (1 << bits) if value & (1 << (bits - 1)) else value), offset


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
    #: Type section: (parameter count, result count) per function type.
    types: list[tuple[int, int]] = field(default_factory=list)
    #: Type index of every function, imports first.
    func_types: list[int] = field(default_factory=list)
    #: Global 0 is a mutable i32 (the stack pointer of a Rust build), and no global is imported.
    stack_pointer: bool = False
    imported_globals: int = 0


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
        if section_id == 1:
            count, pos = _u32(body, 0)
            for _ in range(count):
                if body[pos] != 0x60:
                    raise WasmError("unknown type form")
                params, pos = _u32(body, pos + 1)
                pos += params
                results, pos = _u32(body, pos)
                pos += results
                module.types.append((params, results))
        elif section_id == 2:
            count, pos = _u32(body, 0)
            for _ in range(count):
                mod, pos = _name(body, pos)
                fld, pos = _name(body, pos)
                kind = body[pos]
                pos += 1
                if kind == 0:
                    type_index, pos = _u32(body, pos)
                    module.func_imports.append(f"{mod}.{fld}")
                    module.func_types.append(type_index)
                elif kind == 1:
                    pos = _limits(body, pos + 1)
                elif kind == 2:
                    pos = _limits(body, pos)
                elif kind == 3:
                    pos += 2
                    module.imported_globals += 1
                else:
                    raise WasmError(f"unknown import kind {kind}")
        elif section_id == 3:
            module.defined, pos = _u32(body, 0)
            for _ in range(module.defined):
                type_index, pos = _u32(body, pos)
                module.func_types.append(type_index)
        elif section_id == 6:
            count, pos = _u32(body, 0)
            module.stack_pointer = count > 0 and not module.imported_globals and body[pos:pos + 2] == b"\x7f\x01"
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


def _decode(body: bytes, where: str) -> tuple[int, list[tuple[int, object]]]:
    """Declared local count and the instructions of one function body as (opcode, immediate).

    The immediate is the index for calls, branches and locals, the labels of br_table, the
    offset of loads and stores, the value of i32.const, and the block type of block, loop and
    if (-1 empty, -2 one value, else a type index); 0xFC instructions carry their sub-opcode
    in the opcode (0xFC0A is memory.copy)."""
    count, pos = _u32(body, 0)
    declared = 0
    for _ in range(count):  # local declarations: (count, valtype)
        n, pos = _u32(body, pos)
        declared += n
        pos += 1
    code: list[tuple[int, object]] = []
    end = len(body)
    while pos < end:
        op = body[pos]
        pos += 1
        imm: object = None
        if op in _NO_IMMEDIATE:
            pass
        elif op in _ONE_INDEX or op == 0x10:
            imm, pos = _u32(body, pos)
        elif op == 0x11:
            imm, pos = _u32(body, pos)  # type index; the table index follows
            _, pos = _u32(body, pos)
        elif op in (0x02, 0x03, 0x04):
            if pos < end and body[pos] in _BLOCK_TYPES:
                imm = -1 if body[pos] == 0x40 else -2
                pos += 1
            else:
                imm, pos = _u32(body, pos)  # s33 type index
        elif op == 0x0E:
            labels, pos = _u32(body, pos)
            targets = []
            for _ in range(labels + 1):
                label, pos = _u32(body, pos)
                targets.append(label)
            imm = tuple(targets)
        elif 0x28 <= op <= 0x3E:
            _, pos = _u32(body, pos)  # alignment
            imm, pos = _u32(body, pos)  # offset
        elif op == 0x41:
            imm, pos = _s32(body, pos)
        elif op == 0x42:
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
            op = 0xFC00 | sub
        else:
            raise WasmError(f"unsupported instruction 0x{op:02x} in {where}")
        code.append((op, imm))
    if pos != end:
        raise WasmError(f"truncated body of {where}")
    return declared, code


def describe(code: str) -> str:
    name = HOST_FUNCTIONS.get(code, ("unknown",))[0]
    return f"{code} ({name})"


def profile(wasm: bytes, spec_names: list[str] | None = None) -> dict:
    """Import facts for the module and, per function export, the host functions it can reach
    and which of its arguments flow into an upgrade or a storage write.

    Reachability follows direct calls through every branch, so a host function missing from
    an export's set is never called by it, except through call_indirect, which is recorded.
    Only exports a transaction can invoke (named by a valid symbol outside the host's reserved
    prefix, taking at most _MAX_VM_ARGS arguments) and the host entry points are analysed, and
    at most _MAX_EXPORTS of them are described, those findings can come from first
    (``exports_omitted`` counts the rest, ``exports_omitted_unauthenticated`` those of them a
    finding could come from). Raises WasmError when the module itself cannot be read; a body
    the decoder does not know only leaves the call graph out (``callgraph.status`` says why),
    and a body the data flow cannot follow only leaves the flows out (``dataflow.status``).
    """
    module = parse_module(wasm)
    imports = set(module.func_imports)
    known = sorted(i for i in imports if i in HOST_FUNCTIONS)
    exports = {n: i for n, i in module.exports.items() if _invokable(module, n, i)}
    out: dict = {
        "decoder": DECODER_VERSION, "host_table_commit": HOST_TABLE_COMMIT,
        "imports": known, **_listed("unknown_imports", sorted(imports - set(known))),
        "can_upgrade": bool(imports & UPGRADE), "has_auth": bool(imports & AUTH_CALLS),
        "calls_out": bool(imports & CALL), "verifies_sig": bool(imports & SIG_VERIFY),
        "manages_external_refs": bool(imports & EXTERNAL_REF), "writes_data": PUT_DATA in imports,
        **_listed("function_exports", sorted(exports)),
    }
    if len(exports) < len(module.exports):
        out.update(_listed("uninvokable_exports", sorted(set(module.exports) - set(exports))))
    hidden: list[str] = []
    if spec_names:
        named = set(spec_names)
        hidden = sorted(n for n in exports if n not in named and n not in SDK_EXPORTS)
        out.update(_listed("hidden_exports", hidden))
        out.update(_listed("spec_only", sorted(named - set(module.exports))))
    imported = len(module.func_imports)
    decoded: list[tuple[int, list[tuple[int, object]]]] = []
    try:
        for i, body in enumerate(module.bodies):
            decoded.append(_decode(body, f"f{imported + i}"))
    except WasmError as exc:
        out["callgraph"] = {"status": "undecoded", "error": str(exc)[:200]}
        return out
    graph = [({imm for op, imm in code if op == 0x10}, any(op == 0x11 for op, _ in code)) for _, code in decoded]
    out["callgraph"] = {"status": "decoded", "functions": len(graph)}
    reach = _Reach(module, graph)
    flow = _DataFlow(module, decoded, graph)
    try:
        flow.run()
    except _FlowError as exc:
        out["dataflow"] = {"status": "incomplete", "error": str(exc)[:200]}
    else:
        out["dataflow"] = {"status": "decoded"}
    traced = out["dataflow"]["status"] == "decoded"
    reaches = {name: reach.of(index) for name, index in exports.items()}
    hidden_set = set(hidden)
    ranked = sorted(exports, key=lambda n: reach.rank(n, *reaches[n], n in hidden_set))
    candidates = {n for n in exports if reach.candidate(n, *reaches[n], n in hidden_set)}
    details: dict = {}
    for name in sorted(ranked[:_MAX_EXPORTS]):
        index, (bits, indirect) = exports[name], reaches[name]
        details[name] = {"reaches": list(reach.names(bits)), "indirect": indirect,
                         "paths": reach.paths(name, index, bits)}
        if index < imported or traced:  # a re-exported host function needs no body
            try:
                details[name]["flows"] = flow.flows(index)
            except _FlowError:
                pass
    out["exports"] = details
    if len(ranked) > _MAX_EXPORTS:
        out["exports_omitted"] = len(ranked) - _MAX_EXPORTS
        out["exports_omitted_unauthenticated"] = sum(n in candidates for n in ranked[_MAX_EXPORTS:])
    if len(hidden) > _MAX_NAMES:  # list the unlisted exports findings can come from first
        risky = [n for n in hidden if n in candidates]
        out.update(_listed("hidden_exports", risky + sorted(hidden_set - set(risky))))
    upgraders = {n: r for n, r in details.items() if set(r["reaches"]) & UPGRADE}
    out["upgrade_exports"] = {n: next(p for c, p in sorted(r["paths"].items()) if c in UPGRADE)
                              for n, r in upgraders.items()}
    # Another contract or an indirect call may hold the check: authentication is unproven.
    out["upgrade_auth_unproven"] = sorted(n for n, r in upgraders.items() if not set(r["reaches"]) & AUTH
                                          and (set(r["reaches"]) & CALL or r["indirect"]))
    out["delegates_read"] = DELEGATED_SIGNERS in (details.get("__check_auth") or {}).get("reaches", [])
    return out


def _invokable(module: Module, name: str, index: int) -> bool:
    """A transaction or another contract can invoke the export by its name and pass it its
    arguments, or the host calls it itself."""
    if not _SYMBOL.fullmatch(name) or (name.startswith(_RESERVED_PREFIX) and name not in HOST_ENTRY_POINTS):
        return False
    try:
        return module.types[module.func_types[index]][0] <= _MAX_VM_ARGS
    except IndexError:  # an invalid module: keep it in view
        return True


def _listed(key: str, names: list[str]) -> dict:
    """A list of names cut at _MAX_NAMES, each cut at _MAX_NAME characters, with the count of
    the rest."""
    out: dict = {key: [n[:_MAX_NAME] for n in names[:_MAX_NAMES]]}
    if len(names) > _MAX_NAMES:
        out[f"{key}_omitted"] = len(names) - _MAX_NAMES
    return out


class _Reach:
    """The host functions each function can reach through direct calls, and the call path to
    each traced one. Reach is a bitset of host functions per strongly connected component of
    the call graph, and the paths come from one backward search per traced host function, so
    the cost is linear in the module whatever the number of exports. Only host functions in
    the pinned table are named; ``unknown_imports`` lists the rest.

    A path is the one a breadth-first search from the export, taking callees in index order,
    finds first: a shortest path, at each hop the lowest-numbered callee that stays on one."""

    def __init__(self, module: Module, graph: list[tuple[set[int], bool]]):
        self.imported, self.imports = len(module.func_imports), module.func_imports
        base, size = self.imported, len(graph)
        self.codes = sorted({c for c in module.func_imports if c in HOST_FUNCTIONS})
        self.bit = {c: 1 << i for i, c in enumerate(self.codes)}
        #: Defined callees (as body numbers) and the host functions each body calls itself.
        self.calls = [sorted({t - base for t in targets if base <= t < base + size}) for targets, _ in graph]
        self.direct = [0] * size
        for v, (targets, _) in enumerate(graph):
            for t in targets:
                if t < base:
                    self.direct[v] |= self.bit.get(self.imports[t], 0)
        self.comp, self.bits, self.indirect = self._components([ind for _, ind in graph])
        self._names: dict[int, tuple[str, ...]] = {}
        self._masks: dict[frozenset, int] = {}
        self._toward_cache: dict[str, tuple[list[int], list[int], list[tuple[int, ...]]]] = {}
        self._callers: list[list[int]] | None = None

    def _components(self, indirect: list[bool]) -> tuple[list[int], list[int], list[bool]]:
        """Tarjan's algorithm, iteratively; a component is finished after every component it
        calls, so its reach is its own calls joined with theirs."""
        size = len(self.calls)
        order, low, comp = [-1] * size, [0] * size, [-1] * size
        on_stack = [False] * size
        stack: list[int] = []
        bits: list[int] = []
        ind: list[bool] = []
        counter = 0
        for root in range(size):
            if order[root] >= 0:
                continue
            work = [(root, 0)]
            while work:
                v, i = work[-1]
                if i == 0:
                    order[v] = low[v] = counter
                    counter += 1
                    stack.append(v)
                    on_stack[v] = True
                if i < len(self.calls[v]):
                    work[-1] = (v, i + 1)
                    w = self.calls[v][i]
                    if order[w] < 0:
                        work.append((w, 0))
                    elif on_stack[w]:
                        low[v] = min(low[v], order[w])
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
                if low[v] != order[v]:
                    continue
                members, c = [], len(bits)
                while True:
                    w = stack.pop()
                    on_stack[w], comp[w] = False, c
                    members.append(w)
                    if w == v:
                        break
                b, flag = 0, False
                for w in members:
                    b, flag = b | self.direct[w], flag or indirect[w]
                    for x in self.calls[w]:
                        if comp[x] != c:
                            b, flag = b | bits[comp[x]], flag or ind[comp[x]]
                bits.append(b)
                ind.append(flag)
        return comp, bits, ind

    def of(self, index: int) -> tuple[int, bool]:
        """(host function bitset, reaches call_indirect) of a function index."""
        if index < self.imported:
            return self.bit.get(self.imports[index], 0), False
        if index - self.imported >= len(self.comp):
            return 0, False
        c = self.comp[index - self.imported]
        return self.bits[c], self.indirect[c]

    def mask(self, codes: frozenset) -> int:
        if codes not in self._masks:
            self._masks[codes] = sum(self.bit[c] for c in codes & self.bit.keys())
        return self._masks[codes]

    def names(self, bits: int) -> tuple[str, ...]:
        if bits not in self._names:
            self._names[bits] = tuple(c for i, c in enumerate(self.codes) if bits >> i & 1)
        return self._names[bits]

    def candidate(self, name: str, bits: int, indirect: bool, hidden: bool) -> bool:
        """Whether an on-chain finding can come from the export, as the rules decide them: a
        host entry point (delegated signers), or one that reaches no authentication or signature
        check and reaches an upgrade (open or gated by another contract), writes storage or tags
        with no contract or indirect call (a writer of what an upgrade installs), or is unlisted
        and reaches an upgrade, a contract call or a storage write (hidden-export)."""
        if name in HOST_ENTRY_POINTS:
            return True
        if bits & self.mask(AUTH):
            return False
        return bool(bits & self.mask(UPGRADE) or (hidden and bits & self.mask(_RISKY))
                    or (bits & self.mask(_WRITES) and not bits & self.mask(CALL) and not indirect))

    def rank(self, name: str, bits: int, indirect: bool, hidden: bool) -> tuple:
        """Exports findings can come from first (host entry points first), then the rest; in
        each group upgrades, then storage and tag writers, other traced calls and the rest, those
        with no authentication or contract call first, unlisted before listed."""
        kind = (0 if bits & self.mask(UPGRADE) or name in HOST_ENTRY_POINTS else
                1 if bits & self.mask(_WRITES) else 2 if bits & self.mask(_TRACED) else 3)
        guarded = bool(bits & self.mask(AUTH | CALL)) or indirect
        return (not self.candidate(name, bits, indirect, hidden), name not in HOST_ENTRY_POINTS, kind, guarded,
                not hidden, name)

    def paths(self, name: str, index: int, bits: int) -> dict[str, str]:
        out = {}
        for code in self.names(bits & self.mask(_TRACED)):
            hops = [] if index < self.imported else self._hops(code, index - self.imported)
            out[code] = " -> ".join([f"export {name}", *hops, f"import {describe(code)}"])
        return out

    def _hops(self, code: str, node: int) -> list[str]:
        dist, nxt, tail = self._toward(code)
        steps = [node]
        while dist[steps[-1]] > 0 and len(steps) < (_MAX_HOPS if dist[node] < _MAX_HOPS else _HEAD):
            steps.append(nxt[steps[-1]])
        hops = [f"f{self.imported + v}" for v in steps]
        if dist[node] >= _MAX_HOPS:
            hops += [f"({dist[node] + 1 - _HEAD - _TAIL} more)"] + [f"f{self.imported + v}" for v in tail[node]]
        return hops

    def _toward(self, code: str) -> tuple[list[int], list[int], list[tuple[int, ...]]]:
        """Per body: calls to the nearest body that calls ``code`` itself, the next hop on the
        path, and the last _TAIL bodies of the path."""
        if code not in self._toward_cache:
            if self._callers is None:
                self._callers = [[] for _ in self.calls]
                for v, callees in enumerate(self.calls):
                    for w in callees:
                        self._callers[w].append(v)
            bit, size = self.bit[code], len(self.calls)
            dist, nxt, tail = [-1] * size, [-1] * size, [()] * size
            order = [v for v in range(size) if self.direct[v] & bit]
            for v in order:
                dist[v] = 0
            for v in order:  # grows while it is walked: breadth first
                for u in self._callers[v]:
                    if dist[u] < 0:
                        dist[u] = dist[v] + 1
                        order.append(u)
            for v in order:
                if dist[v] == 0:
                    tail[v] = (v,)
                    continue
                w = nxt[v] = min(x for x in self.calls[v] if dist[x] == dist[v] - 1)
                tail[v] = tail[w] if len(tail[w]) >= _TAIL else (v, *tail[w])
            self._toward_cache[code] = dist, nxt, tail
        return self._toward_cache[code]


# ---------------------------------------------------------------------------------- data flow
# An abstract value is the set of sources it may hold. Data sources: an int is a parameter of
# the function being summarised, "S" a get_contract_data result, "T" a create_executable_tag
# result, ("m", i, off) what the caller had stored at parameter i + off, ("m*",) anything the
# caller had stored. ("~", source) marks a source that may have reached an object a host
# function built from linear memory (a storage key, a struct): good enough to say a value
# may have been checked, never to say it was written. Addresses: ("#", k) is the i32
# constant k and ("@", base, off) a pointer off bytes from this function's stack frame
# ("sp") or from pointer parameter i (off None: unknown). Other constants, loads from memory
# the flow does not follow, globals and other host results hold nothing.

def _const(value: frozenset) -> int | None:
    if len(value) == 1:
        (label,) = value
        if isinstance(label, tuple) and label[0] == "#":
            return label[1]
    return None


def _data(value: frozenset) -> frozenset:
    """The data sources of a value, without constants and addresses."""
    return frozenset(lb for lb in value if not (isinstance(lb, tuple) and lb[0] in ("#", "@")))


def _maybe(value: frozenset) -> frozenset:
    """Sources that only may have reached a value (through memory a host function read)."""
    return frozenset(lb if isinstance(lb, tuple) and lb[0] == "~" else ("~", lb) for lb in _data(value))


def _shift(value: frozenset, delta: int | None) -> frozenset:
    """A pointer moved by delta bytes; data sources carry over, constants are not folded."""
    out: set = set()
    for label in value:
        if isinstance(label, int):
            out.add(("@", label, delta))
        elif isinstance(label, tuple) and label[0] == "@":
            off = None if label[2] is None or delta is None else label[2] + delta
            out.add(("@", label[1], off if off is None or abs(off) <= _MAX_OFFSET else None))
        elif not (isinstance(label, tuple) and label[0] == "#"):
            out.add(label)
    return frozenset(out)


def _address(value: frozenset, offset: int) -> tuple | None:
    """The one memory slot an address can name, or None when it may name another."""
    keys = set()
    for label in value:
        if isinstance(label, int):
            keys.add((label, offset))
        elif isinstance(label, tuple) and label[0] == "@" and label[2] is not None:
            keys.add((label[1], label[2] + offset))
        else:
            return None
    return keys.pop() if len(keys) == 1 else None


def _widen(value: frozenset) -> frozenset:
    """Pointers into one base at many offsets (a loop walking memory) lose their offset; an
    unknown offset absorbs the known ones."""
    bases: dict = {}
    for label in value:
        if isinstance(label, tuple) and label[0] == "@":
            bases.setdefault(label[1], []).append(label)
    crowded = {b for b, labels in bases.items() if len(labels) > _MAX_OFFSETS or ("@", b, None) in labels}
    crowded = {b for b in crowded if len(bases[b]) > 1}
    if not crowded:
        return value
    return frozenset(lb for lb in value if not (isinstance(lb, tuple) and lb[0] == "@" and lb[1] in crowded)) \
        | {("@", b, None) for b in crowded}


def _from_caller(label) -> bool:
    """A source the caller supplied: a parameter, or something the caller had stored."""
    while isinstance(label, tuple) and label[0] == "~":
        label = label[1]
    return isinstance(label, int) or (isinstance(label, tuple) and label[0] in ("m", "m*"))


def _size(values) -> int:
    """Work to copy, join or compare values: one per value and one per source it holds."""
    return len(values) + sum(map(len, values))


class _Memory:
    """Linear memory as far as the flow follows it: values stored at a known offset from this
    function's frame or from a pointer parameter. Any write it cannot place (an unknown
    address, memory.copy, a host function that fills memory, an indirect call) forgets every
    slot, so a slot never keeps a value that may have been overwritten. ``entry`` holds until
    then: an unwritten slot behind a pointer parameter still has what the caller stored."""

    __slots__ = ("slots", "entry")

    def __init__(self, slots: dict | None = None, entry: bool = True):
        self.slots: dict[tuple, frozenset] = dict(slots or {})
        self.entry = entry

    def copy(self) -> "_Memory":
        return _Memory(self.slots, self.entry)

    def load(self, key: tuple | None) -> frozenset:
        if key is None:
            return _EMPTY
        if key in self.slots:
            return self.slots[key]
        if self.entry and isinstance(key[0], int):
            return frozenset((("m", key[0], key[1]),))
        return _EMPTY

    def forget(self) -> None:
        self.slots, self.entry = {}, False

    def join(self, other: "_Memory") -> "_Memory":
        out = _Memory(entry=self.entry and other.entry)
        for key in self.slots.keys() | other.slots.keys():
            out.slots[key] = self.load(key) | other.load(key)
        return out

    def contents(self) -> frozenset:
        """Every source the followed slots hold, and the caller's memory while it is intact."""
        out = frozenset((_CALLER_MEMORY,)) if self.entry else _EMPTY
        return out.union(*map(_data, self.slots.values()))

    def size(self) -> int:
        return _size(self.slots.values())

    def widen(self) -> "_Memory":
        return _Memory({k: _widen(v) for k, v in self.slots.items()}, self.entry)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Memory) and self.entry == other.entry and self.slots == other.slots


#: State at a program point: locals, the values a branch carries, memory.
_State = tuple[list[frozenset], list[frozenset], _Memory]


def _join_values(a: list[frozenset], b: list[frozenset]) -> list[frozenset]:
    if len(a) != len(b):
        raise _FlowError("branches disagree on the stack")
    return [x if x is y else x | y for x, y in zip(a, b)]


@dataclass
class _Frame:
    kind: str  # func, block, loop or if
    height: int  # stack height below the frame's parameters
    params: int
    results: int
    pc: int = 0
    #: For an if: the state its else branch starts from (None when unreachable).
    else_state: _State | None = None
    has_else: bool = False
    #: States that reach the end of a block or if, by falling through or branching to it.
    ends: list[_State] = field(default_factory=list)


#: A function summary: sources of its results; (host, argument sources) of every upgrade and
#: storage write it can make; the caller-visible slots it leaves, as ((param, off), sources);
#: whether it may overwrite memory it does not describe; the caller-supplied sources it may
#: have dropped on the way (forgotten memory, a global, an indirect call), whose later checks
#: the flow would not see.
_Summary = tuple[tuple[frozenset, ...], frozenset, frozenset, bool, frozenset]


class _DataFlow:
    """Function summaries in terms of each function's own parameters, recomputed until no
    summary changes (callees first). ``work`` counts the steps taken; past _MAX_WORK the flow
    stops (_FlowError), so no module costs more than the budget."""

    def __init__(self, module: Module, decoded: list[tuple[int, list[tuple[int, object]]]],
                 graph: list[tuple[set[int], bool]]):
        self.module, self.decoded, self.imported = module, decoded, len(module.func_imports)
        self.summary: dict[int, _Summary] = {}
        self.order = self._postorder(graph)
        self.callers: dict[int, set[int]] = {}
        for i, (targets, _) in enumerate(graph):
            for target in targets:
                if target >= self.imported:
                    self.callers.setdefault(target, set()).add(self.imported + i)
        self.work = 0
        self._flows: dict[int, dict] = {}
        names = {c: HOST_FUNCTIONS[c][0] if c in HOST_FUNCTIONS else "" for c in module.func_imports}
        #: Host functions that may write linear memory (and any the table does not know).
        self.memory_writers = {c for c, n in names.items() if not n or n.endswith("_to_linear_memory")}
        #: Host functions that read linear memory: what they build may hold any followed slot.
        self.memory_readers = {c for c, n in names.items() if "linear_memory" in n and c not in self.memory_writers}

    def spend(self, units: int) -> None:
        self.work += units
        if self.work > _MAX_WORK:
            raise _FlowError("the data flow needs more work than its budget")

    def _postorder(self, graph: list[tuple[set[int], bool]]) -> list[int]:
        seen: set[int] = set()
        order: list[int] = []
        for root in range(len(graph)):
            if root in seen:
                continue
            seen.add(root)
            stack = [(root, iter(sorted(graph[root][0])))]
            while stack:
                node, children = stack[-1]
                for child in children:
                    child -= self.imported
                    if 0 <= child < len(graph) and child not in seen:
                        seen.add(child)
                        stack.append((child, iter(sorted(graph[child][0]))))
                        break
                else:
                    stack.pop()
                    order.append(node + self.imported)
        return order

    def signature(self, index: int) -> tuple[int, int]:
        try:
            return self.module.types[self.module.func_types[index]]
        except IndexError:
            raise _FlowError(f"no type for f{index}") from None

    def block_type(self, imm: int) -> tuple[int, int]:
        if imm < 0:
            return 0, 0 if imm == -1 else 1
        if imm >= len(self.module.types):
            raise _FlowError("unknown block type")
        return self.module.types[imm]

    def run(self) -> None:
        """Rounds over the functions, callees first; a function is analysed again only when a
        callee's summary changed since (its own summary depends on nothing else)."""
        stale = set(self.order)
        for _ in range(_MAX_ROUNDS):
            for index in self.order:
                if index not in stale:
                    continue
                stale.discard(index)
                summary = self._analyse(index)
                self.spend(2 * (len(summary[1]) + len(summary[2]) + len(summary[4]) + _size(summary[0])))
                if summary != self.summary.get(index):
                    self.summary[index] = summary
                    stale |= self.callers.get(index, set())
            if not stale:
                return
        raise _FlowError("the data flow did not converge")

    def flows(self, index: int) -> dict:
        """Which parameters of a function reach the code an upgrade installs, a storage write,
        or a host function that can check them (``checked``: precise or through memory), and
        which installed ones the flow may have lost track of on the way (``upgrade_code_lost``:
        memory, a global or an indirect call it could not follow, where a check could go unseen).
        An exported host function (a re-export of an import) passes its arguments straight to
        the host."""
        if index not in self._flows:
            if index < self.imported:
                sinks, lost = self._host_sinks(index), _EMPTY
            else:
                sinks, lost = (self.summary[index][1], self.summary[index][4]) if index in self.summary else ((), _EMPTY)
            self._flows[index] = self._flows_from(sinks, lost)
        return self._flows[index]

    def _host_sinks(self, index: int) -> set:
        """The sinks of a host function called with its own parameters, as _call records them."""
        host, (params, _) = self.module.func_imports[index], self.signature(index)
        args = tuple(frozenset((i,)) for i in range(params))
        if host in _SINKS:
            return {(host, (args + (_EMPTY,) * _SINKS[host])[:_SINKS[host]])}
        if params and host not in _NOT_CHECKS and host not in self.memory_readers:
            return {("use", (frozenset(range(params)),))}
        return set()

    @staticmethod
    def _flows_from(sinks, lost: frozenset) -> dict:
        code_args: set[int] = set()
        tag_args: set[int] = set()
        stores: set[int] = set()
        tag_writes: set[int] = set()
        checked: set[int] = set()
        from_storage = False
        params = lambda value: {lb for lb in value if isinstance(lb, int)}  # noqa: E731
        maybe = lambda value: params(value) | {lb[1] for lb in value  # noqa: E731
                                               if isinstance(lb, tuple) and lb[0] == "~" and isinstance(lb[1], int)}
        for host, args in sinks:
            if host == "use":
                checked |= maybe(args[0])
            elif host == "l.6":
                code_args |= params(args[0])
                from_storage |= "S" in args[0]
            elif host == "l.j":
                code_args |= params(args[0])
                tag_args |= params(args[1])
                from_storage |= "S" in args[0] | args[1]
            elif host == PUT_DATA:
                stores |= params(args[1])
                if "T" in args[0]:
                    tag_writes |= params(args[1])
        listed = lambda indexes: sorted(indexes)[:_MAX_ARGS]  # noqa: E731
        return {"upgrade_code": listed(code_args), "upgrade_code_checked": listed(code_args & checked),
                "upgrade_code_lost": listed(code_args & maybe(lost)), "upgrade_tag": listed(tag_args),
                "upgrade_from_storage": from_storage, "stores": listed(stores), "tag_writes": listed(tag_writes)}

    def _analyse(self, index: int) -> _Summary:
        params, results = self.signature(index)
        declared, code = self.decoded[index - self.imported]
        if params + declared > _MAX_LOCALS:
            raise _FlowError(f"too many locals in f{index}")
        heads: dict[int, _State] = {}
        for _ in range(_MAX_ROUNDS):
            sinks: set = set()
            exits: list = []
            lost: set = set()
            if not self._pass(index, code, params, declared, results, heads, sinks, exits, lost):
                break
        else:
            raise _FlowError(f"no fixpoint in f{index}")
        if not exits:
            return (_EMPTY,) * results, frozenset(sinks), frozenset(), False, self._caller_part(lost)
        values, memory = exits[0]
        for more, more_memory in exits[1:]:
            self.spend(_size(values) + _size(more) + memory.size() + more_memory.size())
            values, memory = _join_values(values, more), memory.join(more_memory)
        writes = frozenset((k, v) for k, v in memory.slots.items() if isinstance(k[0], int))
        clobbers = not memory.entry
        if len(writes) > _MAX_WRITES:
            lost.update(*(_data(v) for _, v in writes))
            writes, clobbers = frozenset(), True
        self.spend(memory.size() + len(sinks) + len(lost))
        return tuple(_widen(v) for v in values), frozenset(sinks), writes, clobbers, self._caller_part(lost)

    @staticmethod
    def _caller_part(lost: set) -> frozenset:
        return frozenset(lb for lb in lost if _from_caller(lb))

    def _forget(self, mem: _Memory, lost: set) -> None:
        """Forget every followed slot; what they held (and the caller's memory) is lost."""
        self.spend(mem.size())
        lost.update(mem.contents())
        mem.forget()

    def _store(self, mem: _Memory, key: tuple | None, value: frozenset, lost: set) -> None:
        if key is None or (key not in mem.slots and len(mem.slots) >= _MAX_SLOTS):
            self._forget(mem, lost)
            lost.update(_data(value))
        else:
            mem.slots[key] = value

    def _pass(self, index: int, code: list[tuple[int, object]], params: int, declared: int, results: int,
              heads: dict[int, _State], sinks: set, exits: list, lost: set) -> bool:
        """One walk over a body; True when a loop head took a new state (walk again)."""
        local = [frozenset((i,)) for i in range(params)] + [_EMPTY] * declared
        self.spend(_PASS_COST + _STEP_COST * len(code) + len(local))
        stack: list[frozenset] = []
        mem = _Memory()
        ctrl = [_Frame("func", 0, 0, results)]
        live, grew = True, False

        def top(n: int) -> list[frozenset]:
            if len(stack) - n < ctrl[-1].height:
                raise _FlowError(f"stack underflow in f{index}")
            if not n:
                return []
            values = stack[len(stack) - n:]
            self.spend(_size(values))
            return values

        def pop(n: int = 1) -> list[frozenset]:
            values = top(n)
            if n:
                del stack[-n:]
            return values

        def snapshot(values: list[frozenset]) -> _State:
            self.spend(len(local) + len(mem.slots))
            return list(local), values, mem.copy()

        def join(a: _State, b: _State) -> _State:
            self.spend(_size(a[0]) + _size(a[1]) + a[2].size() + _size(b[0]) + _size(b[1]) + b[2].size())
            return _join_values(a[0], b[0]), _join_values(a[1], b[1]), a[2].join(b[2])

        def branch(depth: int) -> None:
            nonlocal grew
            if depth >= len(ctrl):
                raise _FlowError(f"branch out of f{index}")
            target = ctrl[-1 - depth]
            if target.kind == "loop":
                state: _State = snapshot(top(target.params))
                old = heads.get(target.pc)
                if old is not None:
                    state = join(old, state)
                state = ([_widen(v) for v in state[0]], [_widen(v) for v in state[1]], state[2].widen())
                self.spend(2 * (_size(state[0]) + _size(state[1]) + state[2].size()))  # widen, compare
                if old is None or state[0] != old[0] or state[1] != old[1] or state[2] != old[2]:
                    heads[target.pc], grew = state, True
            elif target.kind == "func":
                self.spend(len(mem.slots))
                exits.append((top(results), mem.copy()))
            else:
                target.ends.append(snapshot(top(target.results)))

        for pc, (op, imm) in enumerate(code):
            if not ctrl:
                raise _FlowError(f"code after the end of f{index}")
            if op in (0x02, 0x03, 0x04):
                ins, outs = self.block_type(imm)
                kind = {0x02: "block", 0x03: "loop", 0x04: "if"}[op]
                if not live:
                    ctrl.append(_Frame(kind, len(stack), ins, outs, pc))
                    continue
                if op == 0x04:
                    pop()
                entry = top(ins)
                frame = _Frame(kind, len(stack) - ins, ins, outs, pc)
                if op == 0x04:
                    frame.else_state = snapshot(entry)
                elif op == 0x03 and pc in heads:
                    local, values, mem = join((local, entry, mem), heads[pc])
                    stack[frame.height:] = values
                ctrl.append(frame)
                continue
            if op == 0x05:
                frame = ctrl[-1]
                if live:
                    frame.ends.append(snapshot(top(frame.results)))
                del stack[frame.height:]
                frame.has_else = True
                live = frame.else_state is not None
                if live:
                    local, values, mem = list(frame.else_state[0]), frame.else_state[1], frame.else_state[2].copy()
                    self.spend(len(local) + len(mem.slots))
                    stack.extend(values)
                continue
            if op == 0x0B:
                frame = ctrl[-1]
                values = top(frame.results) if live else []
                if frame.kind == "func":
                    if live:
                        self.spend(len(mem.slots))
                        exits.append((values, mem.copy()))
                    ctrl.pop()
                    continue
                if live and frame.kind != "loop":
                    frame.ends.append(snapshot(values))
                if frame.kind == "if" and not frame.has_else and frame.else_state is not None:
                    frame.ends.append(frame.else_state)  # the false branch passes the parameters through
                ctrl.pop()
                del stack[frame.height:]
                if frame.kind == "loop":
                    stack.extend(values)
                elif frame.ends:
                    merged = frame.ends[0]
                    for more in frame.ends[1:]:
                        merged = join(merged, more)
                    local, values, mem = list(merged[0]), merged[1], merged[2].copy()
                    self.spend(len(local) + len(mem.slots))
                    stack.extend(values)
                    live = True
                else:
                    live = False
                continue
            if not live:
                continue
            if op in (0x00, 0x0C, 0x0E, 0x0F):  # unreachable, br, br_table, return
                if op == 0x0C:
                    branch(imm)
                elif op == 0x0E:
                    pop()
                    for depth in imm:
                        branch(depth)
                elif op == 0x0F:
                    self.spend(len(mem.slots))
                    exits.append((top(results), mem.copy()))
                live = False
                del stack[ctrl[-1].height:]
            elif op == 0x0D:
                pop()
                branch(imm)
            elif op == 0x10:
                stack.extend(self._call(imm, pop, mem, sinks, lost))
            elif op == 0x11:
                pop()  # table index
                ins, outs = self.block_type(imm)
                lost.update(*map(_data, pop(ins)))  # whatever the callee does with them is unseen
                self._forget(mem, lost)
                stack.extend([_EMPTY] * outs)
            elif op == 0x20:
                if imm >= len(local):
                    raise _FlowError(f"unknown local in f{index}")
                stack.append(local[imm])
            elif op in (0x21, 0x22):
                if imm >= len(local):
                    raise _FlowError(f"unknown local in f{index}")
                local[imm] = pop()[0] if op == 0x21 else top(1)[0]
            elif op == 0x1A:
                pop()
            elif op in (0x1B, 0x1C):
                pop()  # the condition chooses between the two values
                b, a = pop()[0], pop()[0]
                stack.append(a | b)
            elif op == 0x41:
                stack.append(frozenset((("#", imm),)))
            elif op == 0x23:
                stack.append(frozenset((("@", "sp", 0),)) if imm == 0 and self.module.stack_pointer else _EMPTY)
            elif op in (0x3F, 0xD0, 0xD2) or 0x42 <= op <= 0x44:
                stack.append(_EMPTY)  # memory.size, ref.null, ref.func, other constants
            elif op == 0x24:
                lost.update(_data(pop()[0]))  # global.get gives nothing back
            elif op in (0x25, 0x40):
                pop()
                stack.append(_EMPTY)  # table.get, memory.grow
            elif 0x28 <= op <= 0x35:
                stack.append(mem.load(_address(pop()[0], imm)))
            elif 0x36 <= op <= 0x3E:
                value, address = pop()[0], pop()[0]
                self._store(mem, _address(address, imm), value, lost)
            elif op == 0x26:
                pop(2)
            elif op in (0x6A, 0x6B):  # i32.add, i32.sub: pointer arithmetic when one side is a constant
                b, a = pop()[0], pop()[0]
                cb, ca = _const(b), _const(a)
                if cb is not None:
                    stack.append(_shift(a, cb if op == 0x6A else -cb))
                elif ca is not None and op == 0x6A:
                    stack.append(_shift(b, ca))
                else:
                    stack.append(_data(a) | _data(b))
            elif op in _BINARY:
                b, a = pop()[0], pop()[0]
                stack.append(_data(a) | _data(b))
            elif 0x45 <= op <= 0xC4 or op == 0xD1 or 0xFC00 <= op <= 0xFC07:
                stack.append(_data(pop()[0]))
            elif op == 0x01:
                pass
            elif op >= 0xFC00 and (op & 0xFF) in _FC_STACK:
                taken, pushed = _FC_STACK[op & 0xFF]
                pop(taken)
                if op in (0xFC08, 0xFC0A, 0xFC0B):  # memory.init, memory.copy, memory.fill
                    self._forget(mem, lost)
                stack.extend([_EMPTY] * pushed)
            else:
                raise _FlowError(f"no stack effect for 0x{op:x}")
        if ctrl:
            raise _FlowError(f"unterminated body of f{index}")
        return grew

    def _call(self, callee: int, pop, mem: _Memory, sinks: set, lost: set) -> list[frozenset]:
        params, results = self.signature(callee)
        args = pop(params)
        if callee < self.imported:
            host = self.module.func_imports[callee]
            used = _EMPTY.union(*map(_data, args))
            if host in _SINKS:
                arity = _SINKS[host]
                sinks.add((host, tuple(_data(a) for a in (args + [_EMPTY] * arity)[:arity])))
            elif host in self.memory_readers:  # builds an object from memory: it carries what it read
                self.spend(mem.size())
                used = _maybe(used | mem.contents())
            if used and host not in _NOT_CHECKS and host not in self.memory_readers:
                sinks.add(("use", (used,)))
            if host in self.memory_writers:
                self._forget(mem, lost)
            if host == GET_DATA:
                value = frozenset(("S",))
            elif host == EXECUTABLE_TAG:
                value = frozenset(("T",)) | used
            elif host in self.memory_readers:
                value = used
            else:
                value = _EMPTY
            return [value] * results
        summary = self.summary.get(callee)
        if summary is None:  # not summarised yet (a cycle): the next round sees it
            return [_EMPTY] * results
        returned, callee_sinks, writes, clobbers, callee_lost = summary
        self.spend(len(callee_sinks) + len(writes))
        out = [self._subst(r, args, mem) for r in returned]
        for host, host_args in callee_sinks:
            sinks.add((host, tuple(_data(self._subst(a, args, mem)) for a in host_args)))
        lost.update(self._subst(callee_lost, args, mem))
        placed = [(_address(args[i], off) if i < len(args) else None, self._subst(v, args, mem))
                  for (i, off), v in sorted(writes, key=lambda w: w[0])]
        if clobbers:
            self._forget(mem, lost)
        for key, value in placed:
            self._store(mem, key, value, lost)
        return out

    def _subst(self, labels: frozenset, args: list[frozenset], mem: _Memory) -> frozenset:
        """A callee's value in its caller's terms (memory as it was when the call started)."""
        self.spend(len(labels))
        out: set = set()
        for label in labels:
            if isinstance(label, int):
                if label < len(args):
                    self.spend(len(args[label]))
                    out |= args[label]
            elif isinstance(label, tuple) and label[0] == "@":
                if isinstance(label[1], int) and label[1] < len(args):
                    self.spend(2 * len(args[label[1]]))
                    out |= _shift(args[label[1]], label[2]) - _data(args[label[1]])
                # a pointer into the callee's own frame does not outlive the call
            elif isinstance(label, tuple) and label[0] == "m":
                if label[1] < len(args):
                    self.spend(len(args[label[1]]))
                    out |= mem.load(_address(args[label[1]], label[2]))
            elif label == _CALLER_MEMORY:
                self.spend(mem.size())
                out |= mem.contents()
            elif isinstance(label, tuple) and label[0] == "~":
                out |= _maybe(self._subst(frozenset((label[1],)), args, mem))
            else:
                out.add(label)
        self.spend(len(out))
        return frozenset(out)
