"""Every ContractExecutable arm, CAP-85 executable references, and the bytecode findings
(Soroban RPC is mocked; WASM modules are synthetic)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json

import httpx
import pytest
from stellar_sdk import Address, StrKey, xdr

from backend.app.config import Settings
from backend.app.models import AgentArtifact, AuditorVerdict, Dimension, EvidenceGrade, FindingKind, Severity, SourceKind
from backend.app.services.agent_resolver import AgentResolver, audit_reference
from backend.app.services.report_diff import compare_reports
from backend.app.stellar.soroban_reader import SorobanReader
from backend.app.swarm.orchestrator import _KEEPS_SEVERITY, AuditSwarm
from backend.app.swarm.policy import BLOCKING_GAPS, artifact_commitment
from backend.app.swarm.stellar_native import StellarNativeAuditor
from backend.tests.wasm_builder import contract_wasm


def _contract(seed: str) -> str:
    return StrKey.encode_contract(hashlib.sha256(seed.encode()).digest())


AGENT, OWNER, OTHER = _contract("agent"), _contract("owner"), _contract("other")
TAG = "wallet-v1"
LATEST = 5000
#: The agent's code: a payment entry point and a renamed, authenticated upgrader.
AGENT_WASM = contract_wasm({"pay": ["a.0", "d._"], "migrate": ["l.1", "a.0", "l.6"]},
                           spec={"pay": [("to", "address")], "migrate": [("new_wasm_hash", "bytes32")]})
#: A contract that owns executable entries: every write needs its admin.
REGISTRY_SPEC = {"__constructor": [("admin", "address")], "publish": [("tag", "string"), ("wasm_hash", "bytes32")],
                 "lookup": [("tag", "string")], "deploy_from_tag": [("tag", "string"), ("salt", "bytes32")]}
REGISTRY = contract_wasm({"__constructor": ["l._"], "publish": ["h:admin", "l.h", "l._"], "lookup": ["l.h", "l.1"],
                          "deploy_from_tag": ["h:admin", "l.h", "l.i"]}, helpers={"admin": ["l.1", "a.0"]},
                         spec=REGISTRY_SPEC)
#: The same owner with the admin check removed from publish: no a.* import left.
REGISTRY_OPEN = contract_wasm({"__constructor": ["l._"], "publish": ["l.h", "l._"], "lookup": ["l.h", "l.1"]},
                              spec={k: v for k, v in REGISTRY_SPEC.items() if k != "deploy_from_tag"})


def sc_address(contract: str) -> xdr.SCAddress:
    return Address(contract).to_xdr_sc_address()


def wasm_exec(wasm: bytes) -> xdr.ContractExecutable:
    return xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,
                                  wasm_hash=xdr.Hash(hashlib.sha256(wasm).digest()))


def ref_exec(owner: str, tag: str = TAG) -> xdr.ContractExecutable:
    return xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_EXTERNAL_REF,
                                  external_ref=xdr.ContractExecutableExternalRef(sc_address(owner), xdr.SCString(tag.encode())))


def instance(contract: str, executable: xdr.ContractExecutable) -> xdr.LedgerEntryData:
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.ContractDataEntry(
        ext=xdr.ExtensionPoint(0), contract=sc_address(contract),
        key=xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE), durability=xdr.ContractDataDurability.PERSISTENT,
        val=xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE, instance=xdr.SCContractInstance(executable=executable, storage=None))))


def tag_entry(owner: str, value: xdr.SCVal, tag: str = TAG) -> xdr.LedgerEntryData:
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.ContractDataEntry(
        ext=xdr.ExtensionPoint(0), contract=sc_address(owner),
        key=xdr.SCVal(xdr.SCValType.SCV_EXECUTABLE_TAG, executable_tag=xdr.SCString(tag.encode())),
        durability=xdr.ContractDataDurability.PERSISTENT, val=value))


def hash_value(wasm: bytes) -> xdr.SCVal:
    return xdr.SCVal(xdr.SCValType.SCV_BYTES, bytes=xdr.SCBytes(hashlib.sha256(wasm).digest()))


def code(wasm: bytes) -> xdr.LedgerEntryData:
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_CODE, contract_code=xdr.ContractCodeEntry(
        ext=xdr.ContractCodeEntryExt(0), hash=xdr.Hash(hashlib.sha256(wasm).digest()), code=wasm))


def key_of(data: xdr.LedgerEntryData) -> str:
    if data.type == xdr.LedgerEntryType.CONTRACT_CODE:
        return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_CODE,
                             contract_code=xdr.LedgerKeyContractCode(hash=data.contract_code.hash)).to_xdr()
    cd = data.contract_data
    return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        contract=cd.contract, key=cd.key, durability=cd.durability)).to_xdr()


def rpc(*entries, live_until: int = LATEST + 1000, raw: dict[str, str] | None = None):
    """getLedgerEntries over ``entries`` (LedgerEntryData, or (data, liveUntilLedgerSeq))."""
    table = {}
    for item in entries:
        data, live = item if isinstance(item, tuple) else (item, live_until)
        table[key_of(data)] = {"xdr": data.to_xdr(), "lastModifiedLedgerSeq": 4000, "liveUntilLedgerSeq": live}
    for key, value in (raw or {}).items():
        table[key] = {"xdr": value, "lastModifiedLedgerSeq": 4000, "liveUntilLedgerSeq": live_until}

    def handler(request: httpx.Request) -> httpx.Response:
        keys = json.loads(request.content)["params"]["keys"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
            "entries": [{"key": k, **table[k]} for k in keys if k in table], "latestLedger": LATEST}})
    return httpx.MockTransport(handler)


def read(transport, contract: str = AGENT) -> dict:
    return asyncio.run(SorobanReader("testnet", transport=transport).contract(contract))


def findings(contract: dict, *, declared: dict | None = None) -> dict:
    artifact = AgentArtifact(name="Contract agent", source_kind=SourceKind.ONCHAIN_ADDRESS, source_ref=AGENT,
                             chain_authority={"network": "testnet", "contract": contract},
                             raw_metadata={"tmark": {"status": "valid", "declared": declared}} if declared else {})
    return {f.id.removeprefix("stellar_native-"): f
            for f in StellarNativeAuditor(Settings(_env_file=None))._authority_findings(artifact)}


def external_ref_agent(owner_wasm: bytes, *, owner: str = OWNER, agent_wasm: bytes = AGENT_WASM):
    return rpc(instance(AGENT, ref_exec(owner)), tag_entry(owner, hash_value(agent_wasm)), code(agent_wasm),
               instance(owner, wasm_exec(owner_wasm)), code(owner_wasm))


# --------------------------------------------------------------------------- the executable arms
def test_external_ref_crashed_the_old_reader_and_now_resolves_through_the_owner_entry():
    with pytest.raises(AttributeError):
        ref_exec(OWNER).wasm_hash.hash  # what soroban_reader read for every non-SAC executable
    facts = read(external_ref_agent(REGISTRY))
    ref = facts["external_ref"]
    assert facts["executable"] == "external_ref" and facts["read_at_ledger"] == LATEST
    assert ref["owner"] == OWNER and ref["tag"] == TAG and ref["status"] == "resolved"
    assert ref["resolved_wasm_hash"] == hashlib.sha256(AGENT_WASM).hexdigest() == facts["wasm_hash"]
    assert ref["tag_last_modified_ledger"] == 4000 and ref["tag_live_until_ledger"] == LATEST + 1000
    assert facts["wasm_hash_verified"] is True and [f["name"] for f in facts["functions"]] == ["pay", "migrate"]
    assert ref["owner_contract"]["executable"] == "wasm" and ref["owner_contract"]["profile"]["manages_external_refs"]


def test_the_tag_key_is_contract_data_keyed_by_scv_executable_tag():
    # rs-soroban-env executable_ref_ledger_key: ContractData{owner, ScVal::ExecutableTag(tag), Persistent}.
    key = xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        contract=sc_address(OWNER), key=xdr.SCVal(xdr.SCValType.SCV_EXECUTABLE_TAG, executable_tag=xdr.SCString(b"payroll1")),
        durability=xdr.ContractDataDurability.PERSISTENT))
    raw = key.to_xdr_bytes()
    assert raw[:8] == (6).to_bytes(4, "big") + (1).to_bytes(4, "big")         # CONTRACT_DATA, SC_ADDRESS_TYPE_CONTRACT
    assert raw[8:40] == StrKey.decode_contract(OWNER)
    assert raw[40:44] == (22).to_bytes(4, "big")                              # SCV_EXECUTABLE_TAG
    assert raw[44:48] == (8).to_bytes(4, "big") and raw[48:56] == b"payroll1"  # SCString
    assert raw[56:] == (1).to_bytes(4, "big")                                 # PERSISTENT


@pytest.mark.parametrize("value, status", [
    (xdr.SCVal(xdr.SCValType.SCV_U32, u32=xdr.Uint32(7)), "malformed"),
    (xdr.SCVal(xdr.SCValType.SCV_BYTES, bytes=xdr.SCBytes(b"\x01" * 31)), "malformed"),
    (None, "missing"),
])
def test_an_unusable_tag_entry_leaves_the_code_unresolved_and_blocks_a_pass(value, status):
    ledger = [instance(AGENT, ref_exec(OWNER)), instance(OWNER, wasm_exec(REGISTRY)), code(REGISTRY)]
    if value is not None:
        ledger.append(tag_entry(OWNER, value))
    facts = read(rpc(*ledger))
    assert facts["external_ref"]["status"] == status and "wasm_hash" not in facts
    found = findings(facts)
    gap = found["onchain-contract-code-unresolved"]
    assert gap.kind is FindingKind.EVIDENCE_GAP and gap.severity is Severity.MEDIUM
    assert "stellar_native-onchain-contract-code-unresolved" in BLOCKING_GAPS
    assert found["onchain-contract-code-externally-controlled"].severity is Severity.MEDIUM


def test_an_undecodable_tag_entry_is_malformed_and_keeps_the_instance_facts():
    transport = rpc(instance(AGENT, ref_exec(OWNER)), instance(OWNER, wasm_exec(REGISTRY)), code(REGISTRY),
                    raw={key_of(tag_entry(OWNER, hash_value(AGENT_WASM))): "AAAA"})
    facts = read(transport)
    assert facts["status"] == "found" and facts["external_ref"]["status"] == "malformed"
    assert findings(facts)["onchain-contract-code-unresolved"].kind is FindingKind.EVIDENCE_GAP


def test_an_archived_tag_still_names_the_code_it_restores_to():
    facts = read(rpc(instance(AGENT, ref_exec(OWNER)), (tag_entry(OWNER, hash_value(AGENT_WASM)), 0), code(AGENT_WASM),
                     instance(OWNER, wasm_exec(REGISTRY)), code(REGISTRY)))
    assert facts["external_ref"]["status"] == "resolved" and facts["external_ref"]["tag_archived"] is True
    assert "onchain-contract-code-unresolved" not in findings(facts)


def test_an_owner_that_is_itself_a_reference_is_recorded_and_not_followed():
    facts = read(rpc(instance(AGENT, ref_exec(OWNER)), tag_entry(OWNER, hash_value(AGENT_WASM)), code(AGENT_WASM),
                     instance(OWNER, ref_exec(OTHER, "shared-v2")), instance(OTHER, wasm_exec(REGISTRY)), code(REGISTRY)))
    owner = facts["external_ref"]["owner_contract"]
    assert owner["executable"] == "external_ref"
    assert owner["external_ref"] == {"owner": OTHER, "tag": "shared-v2", "status": "not_followed"}
    finding = findings(facts)["onchain-contract-code-externally-controlled"]
    assert finding.severity is Severity.MEDIUM and "not followed" in finding.detail


def test_an_executable_the_sdk_cannot_decode_is_unreadable_never_a_server_error():
    good = instance(AGENT, wasm_exec(AGENT_WASM))
    raw = bytearray(good.to_xdr_bytes())
    marker = (0).to_bytes(4, "big") + hashlib.sha256(AGENT_WASM).digest()  # CONTRACT_EXECUTABLE_WASM + hash
    at = bytes(raw).index(marker)
    raw[at:at + 4] = (3).to_bytes(4, "big")  # an executable type this SDK does not know
    transport = rpc(raw={key_of(good): base64.b64encode(bytes(raw)).decode()})
    res = asyncio.run(AgentResolver(Settings(_env_file=None), transport=transport).resolve(AGENT))
    assert {s["check"]: s["result"] for s in res["steps"]}["contract"] == "unreadable"
    assert res["contract"]["status"] == "unreadable"
    result = asyncio.run(audit_reference(AGENT, Settings(_env_file=None), transport=transport, deep=False))
    ids = {f["id"]: f for f in result["report"]["findings"]}
    assert ids["stellar_native-onchain-contract-code-unresolved"]["kind"] == "evidence_gap"
    assert result["decision"] == "needs_evidence"


def test_plain_wasm_and_asset_contracts_have_no_reference_findings():
    sac = xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET)
    assert read(rpc(instance(AGENT, sac)))["executable"] == "stellar_asset"
    facts = read(rpc(instance(AGENT, wasm_exec(AGENT_WASM)), code(AGENT_WASM)))
    found = findings(facts)
    assert "external_ref" not in facts and not any("external" in k or "unresolved" in k for k in found)


# --------------------------------------------------------------------------- who controls the code
def test_owner_that_can_repoint_without_authentication_is_high_inferred():
    found = findings(read(external_ref_agent(REGISTRY_OPEN)))
    finding = found["onchain-contract-code-externally-controlled"]
    assert finding.severity is Severity.HIGH and finding.evidence_grade is EvidenceGrade.INFERRED
    assert "export publish -> " in finding.detail and "import l.h (create_executable_tag)" in finding.detail


def test_owner_whose_writes_need_the_admin_is_a_medium_disclosure():
    found = findings(read(external_ref_agent(REGISTRY)))
    finding = found["onchain-contract-code-externally-controlled"]
    assert finding.severity is Severity.MEDIUM and finding.evidence_grade is EvidenceGrade.CONFIRMED
    assert OWNER in finding.detail and TAG in finding.evidence
    assert found["onchain-contract-upgradeable"].severity is Severity.LOW  # migrate reaches l.6 with require_auth


def test_owner_without_a_call_graph_falls_back_to_its_imports():
    simd = b"\xfd\x0c" + b"\x00" * 16 + b"\x1a"
    undecodable = contract_wasm({"publish": ["l.h", "l._"]}, raw_body={"publish": simd + b"\x10\x00\x10\x01"},
                                spec={"publish": [("tag", "string")]})
    finding = findings(read(external_ref_agent(undecodable)))["onchain-contract-code-externally-controlled"]
    assert finding.severity is Severity.HIGH and "imports create_executable_tag" in finding.detail


@pytest.mark.parametrize("declared", [
    None,  # the agent's own entry
    {"authority": {"agent_account": OWNER}, "owner": {"stellar_account": "G" + "A" * 55}},
])
def test_an_owner_the_agent_declares_is_low(declared):
    owner = AGENT if declared is None else OWNER
    transport = rpc(instance(AGENT, ref_exec(owner)), tag_entry(owner, hash_value(AGENT_WASM)), code(AGENT_WASM),
                    instance(OWNER, wasm_exec(REGISTRY)), code(REGISTRY))
    finding = findings(read(transport), declared=declared)["onchain-contract-code-externally-controlled"]
    assert finding.severity is Severity.LOW


def test_the_contract_that_publishes_references_is_disclosed_as_info():
    found = findings(read(rpc(instance(AGENT, wasm_exec(REGISTRY)), code(REGISTRY))))
    assert found["onchain-contract-manages-external-refs"].severity is Severity.INFO
    assert not [f for f in found.values() if f.is_risk and f.severity.rank >= Severity.MEDIUM.rank]


# --------------------------------------------------------------------------- upgrades from bytecode
UPGRADEABLE = {"__constructor": ["l._"], "version": [], "upgrade": ["h:admin", "l.6"]}
UPGRADE_SPEC = {"__constructor": [("admin", "address")], "version": [], "upgrade": [("new_wasm_hash", "bytes32")]}


def contract_findings(wasm: bytes) -> dict:
    return findings(read(rpc(instance(AGENT, wasm_exec(wasm)), code(wasm))))


def test_upgradeable_contract_with_require_auth_is_a_low_disclosure():
    found = contract_findings(contract_wasm(UPGRADEABLE, helpers={"admin": ["l.1", "a.0"]}, spec=UPGRADE_SPEC))
    assert found["onchain-contract-upgradeable"].severity is Severity.LOW
    assert "export upgrade -> " in found["onchain-contract-upgradeable"].evidence
    assert not [k for k in found if k != "onchain-contract-upgradeable"]


def test_upgrade_without_require_auth_that_takes_the_hash_is_critical():
    found = contract_findings(contract_wasm(UPGRADEABLE, helpers={"admin": ["l.1"]}, spec=UPGRADE_SPEC))
    finding = found["onchain-contract-upgrade-unauthenticated"]
    assert finding.severity is Severity.CRITICAL and finding.evidence_grade is EvidenceGrade.CONFIRMED
    assert "export upgrade -> " in finding.evidence and "import l.6 (update_current_contract_wasm)" in finding.evidence
    assert "onchain-contract-upgradeable" not in found  # one finding for the one upgrade path


def test_upgrade_that_can_compare_the_supplied_hash_is_high_inferred():
    found = contract_findings(contract_wasm({"upgrade": ["l.0", "x.0", "l.6"]}, spec={"upgrade": [("hash", "bytes32")]}))
    finding = found["onchain-contract-upgrade-unauthenticated"]
    assert finding.severity is Severity.HIGH and finding.evidence_grade is EvidenceGrade.INFERRED


def test_timelock_execute_whose_schedule_is_authenticated_is_not_a_risk():
    timelock = {"schedule_upgrade": ["a.0", "l._"], "execute_upgrade": ["l.1", "l.6"]}
    spec = {"schedule_upgrade": [("hash", "bytes32")], "execute_upgrade": []}
    found = contract_findings(contract_wasm(timelock, spec=spec))
    assert "onchain-contract-upgrade-unauthenticated" not in found
    assert found["onchain-contract-upgradeable"].severity is Severity.LOW
    exposed = contract_findings(contract_wasm({**timelock, "poke": ["l._"]}, spec={**spec, "poke": []}))
    finding = exposed["onchain-contract-upgrade-unauthenticated"]
    assert finding.severity is Severity.HIGH and finding.evidence_grade is EvidenceGrade.INFERRED
    assert "poke write storage without authentication" in finding.evidence


@pytest.mark.parametrize("module", [
    contract_wasm({"upgrade": ["d._", "l.6"]}, spec={"upgrade": [("hash", "bytes32")]}),          # another contract decides
    contract_wasm({"upgrade": ["h:go"]}, helpers={"go": ["l.6"]}, indirect={"go"}, spec={"upgrade": [("hash", "bytes32")]}),
])
def test_an_upgrade_that_another_contract_or_an_indirect_call_may_gate_is_unproven(module):
    found = contract_findings(module)
    assert "onchain-contract-upgrade-unauthenticated" not in found
    assert found["onchain-contract-upgradeable"].severity is Severity.LOW


def test_a_renamed_upgrader_is_found_and_a_name_alone_is_not():
    assert contract_findings(AGENT_WASM)["onchain-contract-upgradeable"].severity is Severity.LOW  # "migrate"
    named = contract_wasm({"upgrade": ["a.0", "l._"], "_": []}, spec={"upgrade": [("hash", "bytes32")]})
    assert "onchain-contract-upgradeable" not in contract_findings(named)


def test_name_fallback_only_when_the_imports_cannot_be_read():
    broken = contract_wasm({"upgrade": ["a.0"]}, spec={"upgrade": []}).replace(b"\x01a\x010\x00\x00", b"\x01a\x010\x09\x00")
    facts = read(rpc(instance(AGENT, wasm_exec(broken)), code(broken)))
    assert "profile_error" in facts and facts["upgradeable"] is True


# --------------------------------------------------------------------------- interface and accounts
def test_an_export_missing_from_the_spec_that_moves_funds_is_high():
    module = contract_wasm({"transfer": ["a.0", "l._"], "balance": ["l.1"], "sweep_all": ["d._"]},
                           spec={"transfer": [], "balance": []})
    finding = contract_findings(module)["onchain-contract-hidden-export"]
    assert finding.severity is Severity.HIGH and "sweep_all" in finding.evidence and "import d._ (call)" in finding.evidence
    reader = contract_wasm({"transfer": ["a.0", "l._"], "peek": ["l.1"], "_": []}, spec={"transfer": []})
    assert contract_findings(reader)["onchain-contract-hidden-export"].severity is Severity.MEDIUM
    sdk = contract_findings(contract_wasm({"transfer": ["a.0", "l._"], "_": []}, spec={"transfer": [], "allowance": []}))
    assert "onchain-contract-hidden-export" not in sdk and sdk["onchain-contract-spec-only"].severity is Severity.INFO


def test_an_unlisted_upgrader_without_authentication_is_high_on_both_counts():
    found = contract_findings(contract_wasm({"transfer": ["a.0", "l._"], "reset_code": ["l.6"]}, spec={"transfer": []}))
    assert found["onchain-contract-hidden-export"].severity is Severity.HIGH
    upgrade = found["onchain-contract-upgrade-unauthenticated"]
    assert upgrade.severity is Severity.HIGH and "not in the spec" in upgrade.evidence


def test_a_module_without_a_spec_is_a_low_gap():
    found = contract_findings(contract_wasm({"transfer": ["a.0", "l._"]}, spec={}))
    assert found["onchain-contract-spec-missing"].kind is FindingKind.EVIDENCE_GAP
    assert "onchain-contract-hidden-export" not in found


def test_check_auth_that_reads_delegated_signers_must_authenticate_them():
    spec = {"__check_auth": [], "execute": []}
    open_ = contract_findings(contract_wasm({"__check_auth": ["a.9", "c.0"], "execute": ["a.0", "d._"]}, spec=spec))
    finding = open_["onchain-contract-delegates-unauthenticated"]
    assert finding.severity is Severity.HIGH and finding.evidence_grade is EvidenceGrade.INFERRED
    checked = contract_findings(contract_wasm({"__check_auth": ["a.9", "a.a"], "execute": ["a.0", "d._"]}, spec=spec))
    assert "onchain-contract-delegates-unauthenticated" not in checked


def test_an_undecodable_body_is_a_resolution_step_not_a_finding():
    simd = b"\xfd\x0c" + b"\x00" * 16 + b"\x1a"
    module = contract_wasm({"upgrade": ["l.6"]}, raw_body={"upgrade": simd + b"\x10\x00"}, spec={"upgrade": [("h", "bytes32")]})
    transport = rpc(instance(AGENT, wasm_exec(module)), code(module))
    res = asyncio.run(AgentResolver(Settings(_env_file=None), transport=transport).resolve(AGENT))
    assert {s["check"]: s["result"] for s in res["steps"]}["contract_callgraph"] == "undecoded"
    found = findings(res["contract"])
    assert "onchain-contract-upgrade-unauthenticated" not in found
    assert found["onchain-contract-upgradeable"].severity is Severity.LOW


def test_ledger_and_bytecode_findings_keep_their_severity_under_verification():
    for rule in ("upgradeable", "upgrade-unauthenticated", "code-externally-controlled", "hidden-export",
                 "delegates-unauthenticated", "code-unresolved", "manages-external-refs"):
        assert _KEEPS_SEVERITY.search(f"stellar_native-onchain-contract-{rule}")
    assert not _KEEPS_SEVERITY.search("stellar_native-onchain-identity-unbound")
    critical = contract_findings(contract_wasm(UPGRADEABLE, helpers={"admin": ["l.1"]}, spec=UPGRADE_SPEC))
    high = findings(read(external_ref_agent(REGISTRY_OPEN)))
    for finding in (critical["onchain-contract-upgrade-unauthenticated"], high["onchain-contract-code-externally-controlled"]):
        verdict = AuditorVerdict(auditor="stellar_native", dimension=Dimension.STELLAR_NATIVE, score=50.0, findings=[finding])
        for outcome in ({"verdict": "refuted"}, {"verdict": "partial", "reviewed_severity": "low"}):
            result = {"results": [{"finding_id": finding.id, "quote_verified": True, "quote": "admin.require_auth();",
                                   "reason": "the source checks the admin", **outcome}]}
            assert AuditSwarm._apply_disputes([verdict], result)[0].findings[0].severity is finding.severity


# --------------------------------------------------------------------------- the end-to-end audit
def test_external_ref_agent_audit_reports_the_owner_and_the_resolved_code():
    result = asyncio.run(audit_reference(AGENT, Settings(_env_file=None), transport=external_ref_agent(REGISTRY_OPEN),
                                         deep=False))
    steps = {s["check"]: s for s in result["report"]["resolution"]["steps"]}
    assert steps["executable_ref"]["result"] == "resolved" and OWNER in steps["executable_ref"]["evidence"]
    finding = next(f for f in result["report"]["findings"]
                   if f["id"] == "stellar_native-onchain-contract-code-externally-controlled")
    assert finding["severity"] == "high" and result["decision"] == "needs_fixes"


# --------------------------------------------------------------------------- the commitment
def _commitment(contract: dict | None = None, account: dict | None = None) -> str:
    chain = {"network": "testnet", **({"contract": contract} if contract else {}), **({"account": account} if account else {})}
    return artifact_commitment(AgentArtifact(name="agent", source_kind=SourceKind.ONCHAIN_ADDRESS, source_ref=AGENT,
                                             chain_authority=chain))


ACCOUNT = {"status": "found", "address": "G" + "B" * 55, "thresholds": {"low": 1, "medium": 2, "high": 3},
           "signers": [{"key": "G" + "B" * 55, "weight": 2, "type": "ed25519_public_key"}],
           "flags": {"auth_required": False}, "last_modified_ledger": 900, "native_balance": "100.0",
           "trustlines": [{"asset": "USDC:G", "limit": "10", "unlimited": False}]}


def test_commitment_binds_the_resolved_code_and_signers_but_not_balances_or_ttls():
    facts = read(external_ref_agent(REGISTRY))
    base = _commitment(facts, ACCOUNT)
    repointed = json.loads(json.dumps(facts))
    repointed["external_ref"]["resolved_wasm_hash"] = "ab" * 32
    reweighted = json.loads(json.dumps(ACCOUNT))
    reweighted["signers"][0]["weight"] = 3
    assert _commitment(repointed, ACCOUNT) != base and _commitment(facts, reweighted) != base
    richer = {**ACCOUNT, "native_balance": "5000.0"}
    longer = json.loads(json.dumps(facts))
    longer["external_ref"]["tag_live_until_ledger"] += 50_000
    assert _commitment(facts, richer) == base and _commitment(longer, ACCOUNT) == base
    plain = AgentArtifact(name="agent", source_kind=SourceKind.ONCHAIN_ADDRESS, source_ref=AGENT)
    assert artifact_commitment(plain) == artifact_commitment(plain.model_copy(update={"chain_authority": {"network": "testnet"}}))


def test_report_diff_flags_a_repointed_executable_or_new_signer():
    facts = read(external_ref_agent(REGISTRY))
    repointed = json.loads(json.dumps(facts))
    repointed["external_ref"]["resolved_wasm_hash"] = "cd" * 32
    report = lambda contract, account: {"result": {"overall_score": 50}, "findings": [],  # noqa: E731
                                        "onchain_authority": {"network": "testnet", "contract": contract, "account": account}}
    more = {**ACCOUNT, "signers": ACCOUNT["signers"] + [{"key": "G" + "C" * 55, "weight": 1, "type": "ed25519_public_key"}]}
    diff = compare_reports(report(facts, ACCOUNT), report(repointed, more))
    assert {c["field"] for c in diff["identity_changes"]} == {"contract.external_ref.resolved_wasm_hash", "account.signers"}
    assert compare_reports(report(facts, ACCOUNT), report(facts, {**ACCOUNT, "native_balance": "1"}))["identity_changes"] == []
