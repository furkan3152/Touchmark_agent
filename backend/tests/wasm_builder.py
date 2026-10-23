"""Synthetic Soroban WASM modules for tests: host imports, exports, a call graph and the
contractspecv0 / contractmetav0 custom sections, and nothing else.

A body is a sequence of calls, whose arguments can be the function's parameters or other
calls' results, wrapped in a few ordinary instructions (block, i64.const, load, drop) so the
decoder walks real immediates and the data flow follows real operands.
"""

from __future__ import annotations

from stellar_sdk import xdr

_TYPES = {"address": xdr.SCSpecType.SC_SPEC_TYPE_ADDRESS, "string": xdr.SCSpecType.SC_SPEC_TYPE_STRING,
          "u32": xdr.SCSpecType.SC_SPEC_TYPE_U32, "i128": xdr.SCSpecType.SC_SPEC_TYPE_I128,
          "bytes": xdr.SCSpecType.SC_SPEC_TYPE_BYTES}


def leb(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _vec(items: list[bytes]) -> bytes:
    return leb(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    return leb(len(text.encode())) + text.encode()


def section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + leb(len(payload)) + payload


def custom_section(name: str, payload: bytes) -> bytes:
    return section(0, _name(name) + payload)


def _type_def(name: str) -> xdr.SCSpecTypeDef:
    if name.startswith("bytes") and name[5:].isdigit():
        return xdr.SCSpecTypeDef(xdr.SCSpecType.SC_SPEC_TYPE_BYTES_N, bytes_n=xdr.SCSpecTypeBytesN(xdr.Uint32(int(name[5:]))))
    return xdr.SCSpecTypeDef(_TYPES[name])


def spec_section(functions: dict[str, list[tuple[str, str]]]) -> bytes:
    """contractspecv0 with one FUNCTION_V0 entry per name: inputs are (name, type) pairs."""
    entries = b"".join(xdr.SCSpecEntry(kind=xdr.SCSpecEntryKind.SC_SPEC_ENTRY_FUNCTION_V0, function_v0=xdr.SCSpecFunctionV0(
        doc=b"", name=xdr.SCSymbol(name.encode()),
        inputs=[xdr.SCSpecFunctionInputV0(doc=b"", name=arg.encode(), type=_type_def(kind)) for arg, kind in inputs],
        outputs=[])).to_xdr_bytes() for name, inputs in functions.items())
    return custom_section("contractspecv0", entries)


def meta_section(meta: dict[str, str]) -> bytes:
    entries = b"".join(xdr.SCMetaEntry(kind=xdr.SCMetaKind.SC_META_V0, v0=xdr.SCMetaV0(key=k.encode(), val=v.encode()))
                       .to_xdr_bytes() for k, v in meta.items())
    return custom_section("contractmetav0", entries)


def _parse(text: str) -> tuple:
    """'l._(c,p1,l.1(p0,c))' -> ('call', 'l._', [('const',), ('param', 1), ('call', 'l.1', [...])])."""
    def expr(pos: int) -> tuple[tuple, int]:
        end = pos
        while end < len(text) and text[end] not in "(),":
            end += 1
        token, args = text[pos:end], []
        if token in ("c", "m"):
            return (("const",) if token == "c" else ("load",)), end
        if token[:1] == "p" and token[1:].isdigit():
            return ("param", int(token[1:])), end
        if end < len(text) and text[end] == "(":
            end += 1
            while text[end] != ")":
                arg, end = expr(end)
                args.append(arg)
                if text[end] == ",":
                    end += 1
            end += 1
        return ("call", token, args), end

    tree, end = expr(0)
    if end != len(text):
        raise ValueError(f"cannot parse {text!r}")
    return tree


def _walk(tree: tuple):
    yield tree
    for arg in tree[2] if tree[0] == "call" else ():
        yield from _walk(arg)


def contract_wasm(exports: dict[str, list[str]], *, helpers: dict[str, list[str]] | None = None,
                  spec: dict[str, list[tuple[str, str]]] | None = None, meta: dict[str, str] | None = None,
                  indirect: frozenset[str] | set[str] = frozenset(), raw_body: dict[str, bytes] | None = None) -> bytes:
    """A module whose exported functions call host functions ("l.6") and helpers ("h:name").

    Each body entry is a call whose result is dropped. Arguments are optional and nest:
    "l.6(p0)" passes the function's parameter 0, "l._(l.h(p0),p1,c)" a call's result, "c" a
    constant and "m" a load from linear memory; missing arguments are constants. An entry
    "=expr" is the function's result (default a constant). Every function takes and returns
    i64 values (an export takes one per spec input); a host function takes as many as its
    widest call passes.

    ``spec`` defaults to every export with no inputs; pass {} for a module without a spec.
    Functions named in ``indirect`` also contain a call_indirect. ``raw_body`` replaces a
    function's instructions (for decoder tests)."""
    helpers = helpers or {}
    order = list(helpers) + [name for name in exports if name not in helpers]
    bodies = {**helpers, **exports}
    statements = {name: [(item.startswith("="), _parse(item.lstrip("="))) for item in items]
                  for name, items in bodies.items()}
    arity: dict[str, int] = {}
    hosts: list[str] = []
    for name, items in statements.items():
        for _, tree in items:
            for node in _walk(tree):
                if node[0] == "call":
                    if not node[1].startswith("h:") and node[1] not in hosts:
                        hosts.append(node[1])
                    arity[node[1]] = max(arity.get(node[1], 0), len(node[2]))
                elif node[0] == "param":
                    arity[f"h:{name}"] = max(arity.get(f"h:{name}", 0), node[1] + 1)
    for name in exports:
        arity[f"h:{name}"] = max(arity.get(f"h:{name}", 0), len((spec or {}).get(name, [])))
    index = {code: i for i, code in enumerate(hosts)}
    index.update({f"h:{name}": len(hosts) + i for i, name in enumerate(order)})
    types = [(0, 0)]  # type 0: () -> (), used by call_indirect and raw bodies

    def type_of(params: int) -> int:
        if (params, 1) not in types:
            types.append((params, 1))
        return types.index((params, 1))

    def emit(tree: tuple) -> bytes:
        if tree[0] == "const":
            return b"\x42\x00"
        if tree[0] == "load":
            return b"\x41\x00\x29\x03\x00"  # i32.const 0; i64.load
        if tree[0] == "param":
            return b"\x20" + leb(tree[1])
        args = tree[2] + [("const",)] * (arity[tree[1]] - len(tree[2]))
        return b"".join(emit(a) for a in args) + b"\x10" + leb(index[tree[1]])

    def code(name: str) -> bytes:
        if raw_body and name in raw_body:
            instructions = raw_body[name]
        else:
            result = b"\x42\x00"
            instructions = b"\x02\x40" + b"\x42\x05\x1a" + b"\x41\x00\x29\x03\x08\x1a"  # block; i64.const 5; drop; i64.load
            for is_result, tree in statements[name]:
                if is_result:
                    result = emit(tree)
                else:
                    instructions += emit(tree) + b"\x1a"
            if name in indirect:
                instructions += b"\x41\x00\x11\x00\x00"  # i32.const 0; call_indirect type 0 table 0
            instructions += b"\x0b" + result
        body = b"\x00" + instructions + b"\x0b"  # no locals
        return leb(len(body)) + body

    host_types = [type_of(arity[c]) for c in hosts]
    func_types = [type_of(arity.get(f"h:{name}", 0)) for name in order]
    module = b"\0asm\x01\0\0\0"
    module += section(1, _vec([b"\x60" + _vec([b"\x7e"] * p) + _vec([b"\x7e"] * r) for p, r in types]))
    module += section(2, _vec([_name(c.split(".")[0]) + _name(c.split(".", 1)[1]) + b"\x00" + leb(t)
                               for c, t in zip(hosts, host_types)]))
    module += section(3, _vec([leb(t) for t in func_types]))
    module += section(4, _vec([b"\x70\x00\x01"]))  # funcref table, min 1
    module += section(5, _vec([b"\x00\x01"]))  # one memory page
    module += section(6, _vec([b"\x7f\x01\x41" + leb(4096) + b"\x0b"]))  # the stack pointer
    module += section(7, _vec([_name(name) + b"\x00" + leb(index[f"h:{name}"]) for name in exports]
                              + [_name("memory") + b"\x02\x00"]))
    module += section(10, _vec([code(name) for name in order]))
    module += spec_section({n: [] for n in exports} if spec is None else spec) if spec != {} else b""
    if meta:
        module += meta_section(meta)
    return module
