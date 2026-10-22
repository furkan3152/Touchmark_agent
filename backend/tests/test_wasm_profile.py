"""Import, export and call-graph facts read from Soroban WASM bytecode (synthetic modules)."""

from __future__ import annotations

import pytest

from backend.app.stellar import wasm_profile
from backend.app.stellar.wasm_profile import WasmError, parse_module, profile
from backend.tests.wasm_builder import contract_wasm, leb, section


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
