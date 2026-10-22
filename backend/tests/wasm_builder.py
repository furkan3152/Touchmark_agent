"""Synthetic Soroban WASM modules for tests: host imports, exports, a call graph and the
contractspecv0 / contractmetav0 custom sections, and nothing else.

Every function has type () -> (); a body is a sequence of calls wrapped in a few ordinary
instructions (block, i64.const, load, drop) so the decoder walks real immediates.
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


def contract_wasm(exports: dict[str, list[str]], *, helpers: dict[str, list[str]] | None = None,
                  spec: dict[str, list[tuple[str, str]]] | None = None, meta: dict[str, str] | None = None,
                  indirect: frozenset[str] | set[str] = frozenset(), raw_body: dict[str, bytes] | None = None) -> bytes:
    """A module whose exported functions call host functions ("l.6") and helpers ("h:name").

    ``spec`` defaults to every export with no inputs; pass {} for a module without a spec.
    Functions named in ``indirect`` also contain a call_indirect. ``raw_body`` replaces a
    function's instructions (for decoder tests)."""
    helpers = helpers or {}
    order = list(helpers) + [name for name in exports if name not in helpers]
    bodies = {**helpers, **exports}
    hosts: list[str] = []
    for calls in bodies.values():
        for callee in calls:
            if not callee.startswith("h:") and callee not in hosts:
                hosts.append(callee)
    index = {code: i for i, code in enumerate(hosts)}
    index.update({f"h:{name}": len(hosts) + i for i, name in enumerate(order)})

    def code(name: str) -> bytes:
        if raw_body and name in raw_body:
            instructions = raw_body[name]
        else:
            instructions = b"\x02\x40" + b"\x42\x05\x1a" + b"\x41\x00\x29\x03\x08\x1a"  # block; i64.const 5; drop; i64.load
            instructions += b"".join(b"\x10" + leb(index[c]) for c in bodies[name])
            if name in indirect:
                instructions += b"\x41\x00\x11\x00\x00"  # i32.const 0; call_indirect type 0 table 0
            instructions += b"\x0b"
        body = b"\x00" + instructions + b"\x0b"  # no locals
        return leb(len(body)) + body

    module = b"\0asm\x01\0\0\0"
    module += section(1, _vec([b"\x60\x00\x00"]))
    module += section(2, _vec([_name(c.split(".")[0]) + _name(c.split(".", 1)[1]) + b"\x00\x00" for c in hosts]))
    module += section(3, _vec([b"\x00" for _ in order]))
    module += section(4, _vec([b"\x70\x00\x01"]))  # funcref table, min 1
    module += section(5, _vec([b"\x00\x01"]))  # one memory page
    module += section(7, _vec([_name(name) + b"\x00" + leb(index[f"h:{name}"]) for name in exports]
                              + [_name("memory") + b"\x02\x00"]))
    module += section(10, _vec([code(name) for name in order]))
    module += spec_section({n: [] for n in exports} if spec is None else spec) if spec != {} else b""
    if meta:
        module += meta_section(meta)
    return module
