"""Import, export, call-graph and data-flow facts read from Soroban WASM bytecode.

Synthetic modules test each mechanism. The contracts in fixtures/wasm_sdk25 are real builds:
the sources in fixtures/wasm_sdk25/src, compiled with soroban-sdk 25.3.0 and rustc 1.91.0
(`cargo build --release --target wasm32v1-none`, opt-level "z", lto, codegen-units 1, panic
abort, symbols stripped). They carry the shapes the SDK emits: every storage read calls
has_contract_data first, BytesN arguments are converted through an out-pointer in linear
memory, struct values are unpacked by the host into memory.
"""

from __future__ import annotations

import json
import random
import time
from collections import deque
from pathlib import Path

import pytest

from backend.app.stellar import wasm_profile
from backend.app.stellar.wasm_profile import WasmError, parse_module, profile
from backend.tests.wasm_builder import contract_wasm, leb, raw_module, section

SDK25 = Path(__file__).parent / "fixtures" / "wasm_sdk25"


def test_host_table_is_pinned_and_names_the_protocol_28_functions():
    assert wasm_profile.HOST_TABLE_COMMIT == "0c99950e96128beba3319aa96b116646ce974e69"
    table = wasm_profile.HOST_FUNCTIONS
    assert table["l.6"] == ("update_current_contract_wasm", None)
    assert table["l.h"] == ("create_executable_tag", 28) and table["l.i"] == ("create_external_ref_contract", 28)
    assert table["l.j"] == ("update_current_contract_executable_ref", 28)
    assert table["a.9"] == ("get_delegated_signers_for_current_auth_check", 27)
    assert table["a.a"] == ("delegate_account_auth", 27)
    assert table["c.A"] == ("verify_sig_ml_dsa_44", 30) and table["x.0"] == ("obj_cmp", None)
    assert table["l._"][0] == "put_contract_data" and table["a.0"][0] == "require_auth"


def test_imports_give_module_facts_and_paths_follow_helpers():
    wasm = contract_wasm({"upgrade": ["h:admin", "h:swap"], "version": []},
                         helpers={"admin": ["l.1", "a.0"], "swap": ["l.6"]})
    facts = profile(wasm, ["upgrade", "version"])
    assert facts["callgraph"]["status"] == "decoded"
    assert facts["can_upgrade"] and facts["has_auth"] and not facts["calls_out"] and not facts["manages_external_refs"]
    upgrade = facts["exports"]["upgrade"]
    assert upgrade["reaches"] == ["a.0", "l.1", "l.6"] and upgrade["indirect"] is False
    assert upgrade["paths"]["l.6"] == "export upgrade -> f5 -> f4 -> import l.6 (update_current_contract_wasm)"
    assert facts["exports"]["version"]["reaches"] == []
    assert facts["hidden_exports"] == [] and facts["spec_only"] == []


def test_call_indirect_is_recorded_on_every_export_that_reaches_it():
    wasm = contract_wasm({"run": ["h:dispatch"], "other": []}, helpers={"dispatch": ["l.6"]}, indirect={"dispatch"})
    facts = profile(wasm, ["run", "other"])
    assert facts["exports"]["run"]["indirect"] is True and facts["exports"]["other"]["indirect"] is False


def test_exports_missing_from_the_spec_are_hidden_except_sdk_entries():
    wasm = contract_wasm({"transfer": ["a.0", "l._"], "balance": ["l.1"], "sweep_all": ["d._"], "_": [],
                          "__check_auth": ["a._"], "__data_end": []},
                         spec={"transfer": [], "balance": [], "mint": []})
    facts = profile(wasm, ["transfer", "balance", "mint"])
    assert facts["hidden_exports"] == ["__check_auth", "sweep_all"]  # '_' and other '__' names are the SDK's
    assert facts["spec_only"] == ["mint"]
    assert profile(wasm, [])["function_exports"] and "hidden_exports" not in profile(wasm, [])


def test_decoder_reads_the_immediates_soroban_builds_use():
    body = (b"\x02\x7e" + b"\x42" + leb(300) + b"\x0b\x1a"           # block (result i64) i64.const; drop
            + b"\x03\x40\x0b" + b"\x04\x00\x0b"                       # loop; if with a type index
            + b"\x41\x00\x0e\x02\x00\x00\x00"                        # br_table with two labels and a default
            + b"\x43\x00\x00\x00\x00\x1a\x44" + b"\x00" * 8 + b"\x1a"  # f32.const, f64.const
            + b"\x41\x00\x28\x02\x10\x1a\xc0\x1a"                    # i32.load align 2 offset 16; i32.extend8_s
            + b"\x41\x00\x41\x00\x41\x00\xfc\x0a\x00\x00"            # memory.copy
            + b"\xfc\x00\xd0\x70\xd1\x1a"                            # trunc_sat; ref.null; ref.is_null
            + b"\x41\x00\x41\x00\x41\x00\x1c\x01\x7f\x1a"            # select (i32)
            + b"\x3f\x00\x1a" + b"\x10\x00")                         # memory.size; call import 0
    facts = profile(contract_wasm({"run": ["l.6"]}, raw_body={"run": body}), ["run"])
    assert facts["callgraph"]["status"] == "decoded"
    assert facts["exports"]["run"]["reaches"] == ["l.6"]


def test_an_unknown_instruction_leaves_the_call_graph_out_not_the_imports():
    simd = b"\xfd\x0c" + b"\x00" * 16 + b"\x1a"  # v128.const
    facts = profile(contract_wasm({"upgrade": ["a.0", "l.6"]}, raw_body={"upgrade": simd}), ["upgrade"])
    assert facts["callgraph"]["status"] == "undecoded" and "0xfd" in facts["callgraph"]["error"]
    assert "exports" not in facts and facts["can_upgrade"] is True


@pytest.mark.parametrize("wasm", [
    b"not wasm",
    b"\0asm\x01\0\0\0" + b"\x02\x05\x01\x01l",                               # import section cut short
    b"\0asm\x01\0\0\0" + section(2, b"\x01\x01l\x016\x09"),                    # unknown import kind
    b"\0asm\x01\0\0\0" + section(3, b"\x02\x00\x00") + section(10, b"\x01\x02\x00\x0b"),  # 2 functions, 1 body
])
def test_malformed_modules_raise_wasm_error(wasm):
    with pytest.raises(WasmError):
        parse_module(wasm)


def test_profile_records_upgrade_exports_unproven_authentication_and_delegated_signers():
    wasm = contract_wasm({"upgrade": ["a.0", "l.6"], "migrate": ["d._", "l.6"], "__check_auth": ["a.9", "c.0"]},
                         spec={"upgrade": [], "migrate": [], "__check_auth": []})
    facts = profile(wasm, ["upgrade", "migrate", "__check_auth"])
    assert set(facts["upgrade_exports"]) == {"migrate", "upgrade"}
    assert facts["upgrade_exports"]["migrate"].endswith("import l.6 (update_current_contract_wasm)")
    assert facts["upgrade_auth_unproven"] == ["migrate"]  # another contract may hold the check
    assert facts["delegates_read"] is True and facts["decoder"] == "4"


# --------------------------------------------------------------------------- data flow
def _flows(exports: dict, helpers: dict | None = None, spec: dict | None = None) -> dict:
    facts = profile(contract_wasm(exports, helpers=helpers, spec=spec), list(exports))
    assert facts["dataflow"] == {"status": "decoded"}
    return {name: r["flows"] for name, r in facts["exports"].items()}


def test_an_argument_reaches_the_upgrade_directly_through_helpers_and_their_results():
    flows = _flows({"direct": ["l.6(p0)"], "helper": ["h:install(c,p1)"], "returned": ["l.6(h:same(p0))"],
                    "stored": ["l.6(l.1(p0,c))"], "loaded": ["l.6(m)"]},
                   helpers={"install": ["l.6(p1)"], "same": ["=p0"]},
                   spec={"direct": [("h", "bytes32")], "helper": [("x", "u32"), ("h", "bytes32")],
                         "returned": [("h", "bytes32")], "stored": [("id", "bytes32")], "loaded": [("h", "bytes32")]})
    assert flows["direct"]["upgrade_code"] == [0] and flows["helper"]["upgrade_code"] == [1]
    assert flows["returned"]["upgrade_code"] == [0]
    # read from storage by a caller-chosen key is not the caller's code; memory not followed is nothing
    assert flows["stored"]["upgrade_code"] == [] and flows["stored"]["upgrade_from_storage"] is True
    assert flows["loaded"]["upgrade_code"] == [] and flows["loaded"]["upgrade_from_storage"] is False


def test_storage_writes_executable_tags_and_checks_are_followed_per_argument():
    flows = _flows({"publish": ["l._(l.h(p0),p1,c)"], "note": ["l._(p0,c,c)", "l._(c,p1,c)"],
                    "upgrade": ["x.0(p0,l.1(c,c))", "l.6(p0)"], "repoint": ["l.j(p0,l.h(p1))"]})
    assert flows["publish"]["tag_writes"] == [1] and flows["publish"]["stores"] == [1]
    assert flows["note"]["stores"] == [1] and flows["note"]["tag_writes"] == []  # p0 is only a key
    assert flows["upgrade"]["upgrade_code"] == [0] and flows["upgrade"]["upgrade_code_checked"] == [0]
    assert flows["repoint"]["upgrade_code"] == [0] and flows["repoint"]["upgrade_tag"] == [1]


def _raw(exports: dict, raw: dict, spec: dict) -> dict:
    facts = profile(contract_wasm(exports, spec=spec, raw_body=raw), list(spec))
    assert facts["dataflow"] == {"status": "decoded"}, facts["dataflow"]
    return {name: r["flows"] for name, r in facts["exports"].items()}


#: global.get 0; i32.const 16; i32.sub: a slot in the function's stack frame.
_FRAME = b"\x23\x00\x41\x10\x6b"


def test_memory_follows_stack_slots_through_an_out_pointer_and_forgets_after_unknown_writes():
    # imports: l.6 = 0, b.1 = 1; helper conv = 2 stores its p1 at [p0 + 8]; exports follow.
    conv = b"\x20\x00\x20\x01\x37\x03\x08" + b"\x42\x00"
    through = _FRAME + b"\x20\x00\x10\x02\x1a" + _FRAME + b"\x29\x03\x08\x10\x00\x1a\x42\x00"
    copied = (_FRAME + b"\x20\x00\x37\x03\x08" + b"\x41\x00\x41\x00\x41\x00\xfc\x0a\x00\x00"  # memory.copy
              + _FRAME + b"\x29\x03\x08\x10\x00\x1a\x42\x00")
    filled = (_FRAME + b"\x20\x00\x37\x03\x08" + b"\x42\x00\x42\x00\x42\x00\x42\x00\x10\x01\x1a"  # b.1 writes
              + _FRAME + b"\x29\x03\x08\x10\x00\x1a\x42\x00")
    other = _FRAME + b"\x20\x00\x37\x03\x08" + _FRAME + b"\x29\x03\x10\x10\x00\x1a\x42\x00"  # slot 16, not 8
    exports = {name: ["h:conv(c,c)", "l.6(c)", "b.1(c,c,c,c)"] for name in ("through", "copied", "filled", "other")}
    spec = {name: [("h", "bytes32")] for name in exports}
    module = contract_wasm(exports, helpers={"conv": []}, spec=spec,
                           raw_body={"conv": conv, "through": through, "copied": copied, "filled": filled,
                                     "other": other})
    facts = profile(module, list(spec))
    assert facts["dataflow"] == {"status": "decoded"}
    flows = {name: r["flows"]["upgrade_code"] for name, r in facts["exports"].items()}
    assert flows == {"through": [0], "copied": [], "filled": [], "other": []}


def test_branches_and_loops_merge_what_each_path_can_hold():
    # l.6(if p1 { p0 } else { l.1(..) })
    either = (b"\x20\x01\xa7\x04\x7e\x20\x00\x05\x42\x00\x42\x00\x10\x01\x0b"
              + b"\x10\x00\x1a\x42\x00")
    # loop { l.6(slot); slot = p0; br_if p1 }: the second iteration installs p0
    looped = (b"\x03\x40" + _FRAME + b"\x29\x03\x08\x10\x00\x1a" + _FRAME + b"\x20\x00\x37\x03\x08"
              + b"\x20\x01\xa7\x0d\x00\x0b\x42\x00")
    exports = {"either": ["l.6(c)", "l.1(c,c)"], "looped": ["l.6(c)", "l.1(c,c)"]}
    spec = {name: [("h", "bytes32"), ("flag", "u32")] for name in exports}
    flows = _raw(exports, {"either": either, "looped": looped}, spec)
    assert flows["either"]["upgrade_code"] == [0] and flows["either"]["upgrade_from_storage"] is True
    assert flows["looped"]["upgrade_code"] == [0]


def test_a_body_the_flow_cannot_follow_leaves_the_flows_out_and_the_call_graph_in():
    broken = b"\x1a\x10\x00"  # drop on an empty stack
    facts = profile(contract_wasm({"upgrade": ["l.6(p0)"]}, raw_body={"upgrade": broken}), ["upgrade"])
    assert facts["callgraph"]["status"] == "decoded" and facts["dataflow"]["status"] == "incomplete"
    assert "flows" not in facts["exports"]["upgrade"] and facts["upgrade_exports"]


#: Real builds: (fixture, export, upgrade_code, upgrade_code_checked, upgrade_from_storage, stores).
SDK25_FLOWS = [
    ("up_auth", "upgrade", [0], [], False, []),           # admin.require_auth() then install the argument
    ("up_noauth", "upgrade", [0], [], False, []),         # the same with the check removed
    ("up_multi", "upgrade", [0], [], False, []),          # BytesN conversion outlined: through memory
    ("up_ref", "upgrade", [0], [], False, [0]),           # passed by reference to an install helper
    ("up_event", "upgrade", [0], [], False, []),          # the hash is also published in an event
    ("up_approved", "upgrade", [0], [0], False, []),      # has(Approved(hash)) before installing it
    ("up_cmp", "upgrade", [0], [0], False, []),           # compared with the stored approval
    ("timelock_slot", "execute", [], [], True, []),       # installs the stored hash
    ("timelock_done", "execute", [], [], True, []),       # ... and marks the operation done
    ("timelock_opid", "execute", [], [], False, []),      # the argument is only the operation id
    ("timelock_open", "schedule", [], [], False, [0]),    # anyone stores the hash
    ("timelock_init", "initialize", [], [], False, [0]),  # one-time initialiser stores the admin
]


@pytest.mark.parametrize("fixture, export, code, checked, from_storage, stores", SDK25_FLOWS)
def test_sdk_builds_give_the_flows_their_source_has(fixture, export, code, checked, from_storage, stores):
    facts = profile((SDK25 / f"{fixture}.wasm").read_bytes(), None)
    assert facts["callgraph"]["status"] == "decoded" and facts["dataflow"] == {"status": "decoded"}
    flows = facts["exports"][export]["flows"]
    assert (flows["upgrade_code"], flows["upgrade_code_checked"], flows["upgrade_from_storage"], flows["stores"]) \
        == (code, checked, from_storage, stores)


def test_every_sdk_storage_read_reaches_has_contract_data():
    # Storage::get calls has_contract_data and then get_contract_data, so l.0 says nothing
    # about whether a supplied hash is compared with anything.
    for name in ("up_noauth", "timelock_slot", "timelock_opid"):
        reach = profile((SDK25 / f"{name}.wasm").read_bytes(), None)["exports"]
        assert all({"l.0", "l.1"} <= set(r["reaches"]) for n, r in reach.items() if "l.1" in r["reaches"])


# --------------------------------------------------------------------------- invokable names
def test_exports_no_transaction_can_invoke_are_left_out():
    # Function names are SCSymbols: at most 32 bytes of [A-Za-z0-9_]; the host looks them up by name,
    # refuses its reserved prefix "__" unless it makes the call itself (__check_auth, __constructor:
    # frame.rs RESERVED_CONTRACT_FN_PREFIX) and passes at most 32 arguments (vm.rs MAX_VM_ARGS).
    names = ["not-a-symbol", "a.b", "x" * 33, "x" * 32, "_start", "__upgrade", "__check_auth", "_up", "y" * 100,
             "transfer"]
    wasm = raw_module([(3, 1), (0, 1), (33, 1), (32, 1)], ["l._"], [1, 1, 2, 3],
                      [(n, 1 + (n == "transfer")) for n in names] + [("wide", 3), ("widest", 4)],
                      [(0, b"\x42\x00\x42\x00\x42\x00\x10\x00"), (0, b"\x42\x00"), (0, b"\x42\x00"), (0, b"\x42\x00")])
    facts = profile(wasm, ["transfer"])
    assert facts["hidden_exports"] == ["__check_auth", "_start", "_up", "widest", "x" * 32]
    assert facts["uninvokable_exports"] == sorted(["not-a-symbol", "a.b", "x" * 33, "__upgrade", "y" * 64, "wide"])
    assert set(facts["exports"]) == {"__check_auth", "_start", "_up", "transfer", "widest", "x" * 32}


# --------------------------------------------------------------------------- re-exported host functions
@pytest.mark.parametrize("host, params, flows", [
    ("l.6", 1, {"upgrade_code": [0], "upgrade_tag": [], "stores": []}),
    ("l.j", 2, {"upgrade_code": [0], "upgrade_tag": [1], "stores": []}),
    ("l._", 3, {"upgrade_code": [], "upgrade_tag": [], "stores": [1]}),
    ("l.1", 2, {"upgrade_code": [], "upgrade_tag": [], "stores": []}),
])
def test_an_exported_import_passes_its_arguments_straight_to_the_host(host, params, flows):
    # (export "upgrade" (func 0)) where func 0 is the import: the caller's arguments are the host's.
    wasm = raw_module([(params, 1), (0, 1)], [host], [1], [("upgrade", 0), ("hello", 1)], [(0, b"\x42\x00")])
    for facts in (profile(wasm, ["upgrade", "hello"]), profile(wasm, None)):
        found = facts["exports"]["upgrade"]
        assert found["reaches"] == [host]
        assert {k: found["flows"][k] for k in flows} == flows
        assert found["flows"]["upgrade_code_checked"] == [] and found["flows"]["upgrade_code_lost"] == []


def test_an_exported_import_under_the_reserved_prefix_is_left_out():
    wasm = raw_module([(1, 1), (0, 1)], ["l.6"], [1], [("__upgrade", 0), ("_up", 0), ("hello", 1)],
                      [(0, b"\x42\x00")])
    facts = profile(wasm, ["hello"])
    assert facts["uninvokable_exports"] == ["__upgrade"] and set(facts["upgrade_exports"]) == {"_up"}
    assert facts["exports"]["_up"]["flows"]["upgrade_code"] == [0]


# --------------------------------------------------------------------------- which exports are described
def test_exports_findings_can_come_from_are_described_before_padding():
    # 70 unauthenticated getters sort ahead of the exports the rules read: an unlisted export that
    # calls another contract, a custom account that reads delegated signers and checks a signature,
    # and an admin-gated upgrade (whose path the upgradeable disclosure shows).
    getters = {f"get_{i}": ["l.1"] for i in range(70)}
    wasm = contract_wasm(dict(getters, sweep_all=["d._"], __check_auth=["a.9", "c.0"], upgrade=["a.0", "l.6(p0)"]),
                         spec=dict({n: [] for n in getters}, __check_auth=[], upgrade=[("h", "bytes32")]))
    facts = profile(wasm, [*getters, "__check_auth", "upgrade"])
    assert {"sweep_all", "__check_auth", "upgrade"} <= set(facts["exports"])
    assert facts["exports_omitted"] == 73 - 64 and facts["exports_omitted_unauthenticated"] == 0
    assert facts["delegates_read"] and facts["upgrade_exports"]["upgrade"].startswith("export upgrade -> ")
    # What does not fit and could raise a finding is counted: open upgrades, unauthenticated writers.
    many = {f"up_{i}": ["l.6(p0)"] for i in range(40)} | {f"put_{i}": ["l._(c,p0,c)"] for i in range(40)}
    facts = profile(contract_wasm(dict(getters, **many)), [*getters, *many])
    assert facts["exports_omitted"] == 150 - 64 and facts["exports_omitted_unauthenticated"] == 80 - 64
    assert set(facts["exports"]) == set(many) - set(sorted(many, key=lambda n: (n.startswith("put"), n))[64:])


def test_unlisted_exports_beyond_the_name_list_keep_the_risky_ones_first():
    padding = {f"a{i:03d}": ["l.1"] for i in range(300)}
    facts = profile(contract_wasm(dict(padding, zz_sweep=["d._"], listed=["l.1"])), ["listed"])
    assert facts["hidden_exports"][0] == "zz_sweep" and facts["hidden_exports_omitted"] == 301 - 256


# --------------------------------------------------------------------------- memory the flow forgets
#: imports: f0 bytes_copy_to_linear_memory (4 -> 1), f1 get_contract_data (2 -> 1), f2 obj_cmp
#: (2 -> 1), f3 update_current_contract_wasm (1 -> 1); the export is f4 (1 -> 1).
_FORGET_IMPORTS = [("b.1", 0), ("l.1", 1), ("x.0", 1), ("l.6", 2)]
_COPY = b"\x42\x00" * 4 + b"\x10\x00\x1a"                       # an unrelated copy into memory
_SPILL, _RELOAD = b"\x23\x00\x20\x00\x37\x03\x08", b"\x23\x00\x29\x03\x08"  # [sp+8] = p0; [sp+8]
_COMPARE = b"\x42\x00\x42\x00\x10\x01\x10\x02\x50\x45\x04\x40\x00\x0b"  # if obj_cmp(.., stored) != 0 trap
_INSTALL = b"\x20\x00\x10\x03"


def _forget_flows(code: bytes) -> dict:
    wasm = raw_module([(4, 1), (2, 1), (1, 1)], _FORGET_IMPORTS, [2], [("upgrade", 4)], [(0, code)],
                      memory=True, stack_pointer=True)
    return profile(wasm, ["upgrade"])["exports"]["upgrade"]["flows"]


def test_a_check_on_a_copy_the_flow_forgot_leaves_the_argument_lost_not_unchecked():
    spilled = _forget_flows(_SPILL + _COPY + _RELOAD + _COMPARE + _INSTALL)
    assert spilled["upgrade_code"] == [0] and spilled["upgrade_code_checked"] == []
    assert spilled["upgrade_code_lost"] == [0]
    direct = _forget_flows(_COPY + b"\x20\x00" + _COMPARE + _INSTALL)  # compared from the local
    assert direct["upgrade_code_checked"] == [0] and direct["upgrade_code_lost"] == []
    # Memory forgotten while the hash is only in a local loses nothing: unchecked stays unchecked.
    local_only = _forget_flows(_COPY + _INSTALL)
    assert local_only["upgrade_code_checked"] == [] and local_only["upgrade_code_lost"] == []


def test_a_value_dropped_through_a_global_is_lost():
    through_global = b"\x20\x00\x24\x01" + _INSTALL  # global.set 1 (p0); the check would read it back
    wasm = raw_module([(4, 1), (2, 1), (1, 1)], _FORGET_IMPORTS, [2], [("upgrade", 4)], [(0, through_global)],
                      memory=True, stack_pointer=True, globals_=1)
    assert profile(wasm, ["upgrade"])["exports"]["upgrade"]["flows"]["upgrade_code_lost"] == [0]
    kept = raw_module([(4, 1), (2, 1), (1, 1)], _FORGET_IMPORTS, [2], [("upgrade", 4)], [(0, _INSTALL)],
                      memory=True, stack_pointer=True, globals_=1)
    assert profile(kept, ["upgrade"])["exports"]["upgrade"]["flows"]["upgrade_code_lost"] == []


# --------------------------------------------------------------------------- hostile modules
#: The testnet's maximum contract size (CONFIG_SETTING_CONTRACT_MAX_SIZE_BYTES).
MAX_CODE = 131072


def _fill(unit: bytes, room: int = MAX_CODE - 300) -> bytes:
    return unit * (room // len(unit))


def _timed(wasm: bytes, names: list[str] | None = None) -> tuple[dict, float]:
    assert len(wasm) <= MAX_CODE
    start = time.perf_counter()
    facts = profile(wasm, names)
    return facts, time.perf_counter() - start


_BLOCK_BRANCH = b"\x02\x40\x41\x00\x0d\x00\x0b"  # block; br_if 0 (0); end: a copy and a join of every local
_GROW = b"".join(b"\x20" + leb(i + 1) + b"\x21" + leb(i) for i in range(1, 60)) + b"\x20\x00\x21" + leb(60)
_SLOTS = b"".join(b"\x23\x00\x20\x00\x37\x03" + leb(8 * i) for i in range(500))  # p0 in 500 frame slots
HOSTILE = {
    # 990 locals copied at every branch and joined at every end (a 49,000-local version took 74 s).
    "joins": raw_module([(0, 0)], [], [0], [("a", 0)], [(990, _fill(_BLOCK_BRANCH))]),
    # A loop whose head takes one more source per walk, with joins inside (old code: 80 s).
    "loop": raw_module([(1, 0)], [], [0], [("a", 0)],
                       [(990, b"\x03\x40" + _GROW + _fill(_BLOCK_BRANCH, 60000) + b"\x41\x00\x0d\x00\x0b")]),
    # A memory-reading host call after another while 500 slots hold the argument (old code: 6 s).
    "readers": raw_module([(2, 1), (1, 0)], ["b.3"], [1], [("a", 1)],
                          [(0, _SLOTS + _fill(b"\x42\x00\x42\x00\x10\x00\x1a", MAX_CODE - 4300))],
                          memory=True, stack_pointer=True),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_data_flow_stops_at_its_work_budget_within_seconds(name):
    facts, seconds = _timed(HOSTILE[name])
    assert facts["callgraph"]["status"] == "decoded"
    assert facts["dataflow"] == {"status": "incomplete", "error": "the data flow needs more work than its budget"}
    assert "flows" not in facts["exports"]["a"] and seconds < 5


def test_more_locals_than_any_build_leave_the_flow_out_at_once():
    facts, seconds = _timed(raw_module([(0, 0)], [], [0], [("a", 0)], [(49_000, _fill(_BLOCK_BRANCH))]))
    assert facts["dataflow"]["error"] == "too many locals in f0" and seconds < 1


def test_sdk_builds_stay_well_inside_the_work_budget():
    used = []
    run = wasm_profile._DataFlow.run

    def record(self):
        run(self)
        used.append(self.work)
    wasm_profile._DataFlow.run = record
    try:
        for path in sorted(SDK25.glob("*.wasm")):
            profile(path.read_bytes(), None)
    finally:
        wasm_profile._DataFlow.run = run
    assert used and max(used) < wasm_profile._MAX_WORK // 20


def test_reach_and_paths_cost_the_same_for_one_export_or_thousands():
    # 8,000 exports at the head of an 8,000-function chain that ends in an upgrade (old code: 19 s).
    n = 8000
    bodies = [(0, b"\x10" + leb(i + 2)) for i in range(n - 1)] + [(0, b"\x10\x00")]
    wasm = raw_module([(0, 0)], ["l.6"], [0] * n, [(f"e{j}", 1) for j in range(n)], bodies)
    facts, seconds = _timed(wasm)
    assert seconds < 5 and facts["exports_omitted"] == n - wasm_profile._MAX_EXPORTS
    path = facts["exports"]["e0"]["paths"]["l.6"]
    assert path == ("export e0 -> f1 -> f2 -> f3 -> f4 -> f5 -> f6 -> (7990 more) -> f7997 -> f7998 -> f7999 -> f8000 "
                    "-> import l.6 (update_current_contract_wasm)")
    assert len(json.dumps(facts)) < 100_000


def _bfs(name: str, start: int, imports: list[str], graph: list[tuple[set[int], bool]]) -> dict:
    """The search reach and paths are defined by: breadth first from the export, callees in index order."""
    parent, queue, reached, paths, indirect = {start: None}, deque([start]), set(), {}, False
    while queue:
        node = queue.popleft()
        if node < len(imports):
            reached.add(imports[node])
            if imports[node] in wasm_profile._TRACED and imports[node] not in paths:
                hops, step = [], parent[node]
                while step is not None:
                    hops.append(f"f{step}")
                    step = parent[step]
                paths[imports[node]] = " -> ".join([f"export {name}", *hops[::-1],
                                                    f"import {wasm_profile.describe(imports[node])}"])
            continue
        targets, calls_indirect = graph[node - len(imports)]
        indirect |= calls_indirect
        for target in sorted(targets):
            if target not in parent:
                parent[target] = node
                queue.append(target)
    return {"reaches": sorted(reached), "indirect": indirect, "paths": paths}


@pytest.mark.parametrize("seed", range(30))
def test_component_reach_and_backward_paths_match_a_search_from_every_export(seed):
    rng = random.Random(seed)
    imports = rng.sample(["l.6", "l.j", "l._", "d._", "a.0", "l.1", "x.0", "a.9"], 5) + ["l.6"]
    n = rng.randint(1, 14)
    calls = [{rng.randrange(len(imports) + n) for _ in range(rng.randint(0, 4))} for _ in range(n)]
    indirect = [rng.random() < 0.1 for _ in range(n)]
    bodies = [(0, b"".join(b"\x10" + leb(t) for t in sorted(c)) + (b"\x41\x00\x11\x00\x00" if ind else b""))
              for c, ind in zip(calls, indirect)]
    exports = [(f"e{i}", i) for i in range(len(imports) + n)]
    wasm = raw_module([(0, 0)], imports, [0] * n, exports, bodies)
    facts = profile(wasm, None)
    graph = [(c, ind) for c, ind in zip(calls, indirect)]
    for name, index in exports:
        found = facts["exports"][name]
        assert {k: found[k] for k in ("reaches", "indirect", "paths")} == _bfs(name, index, imports, graph)
