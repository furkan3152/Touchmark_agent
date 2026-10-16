"""Any agent reference resolves to proven evidence (Soroban RPC, GitHub and card hosts are mocked)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import zipfile

import httpx
import pytest
from stellar_sdk import Address, Keypair, xdr

from backend.app.config import Settings
from backend.app.services import agent_resolver
from backend.app.services.agent_resolver import AgentResolver, audit_reference, classify
from backend.app.stellar.soroban_reader import parse_meta, parse_spec, wasm_custom_sections

REGISTRY = "CBBBUECSLXGXVXYMRYK3BCTL3YYBRWDZGW3RNCH5CWKY6KU6UGE576KT"
CONTRACT = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
OWNER = "GA5G3W7O4TLNONP5EWRPZY3ZU7JXE3KHAZD422RTFA3NV4BPSYNCSI44"
AGENT_ID = "c5ac7797509246b6d74d429b7c6ce6fcce73da46047808592a7c75095fc4f6e0"
COMMIT = "a" * 40
ENDPOINT = "https://agent.example.com/mcp"


def _leb(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def custom_section(name: str, payload: bytes) -> bytes:
    body = _leb(len(name)) + name.encode() + payload
    return b"\x00" + _leb(len(body)) + body


def build_wasm(meta: dict[str, str], functions: list[str]) -> bytes:
    spec = b"".join(xdr.SCSpecEntry(kind=xdr.SCSpecEntryKind.SC_SPEC_ENTRY_FUNCTION_V0, function_v0=xdr.SCSpecFunctionV0(
        doc=b"", name=xdr.SCSymbol(name.encode()),
        inputs=[xdr.SCSpecFunctionInputV0(doc=b"", name=b"to", type=xdr.SCSpecTypeDef(xdr.SCSpecType.SC_SPEC_TYPE_ADDRESS))],
        outputs=[])).to_xdr_bytes() for name in functions)
    metas = b"".join(xdr.SCMetaEntry(kind=xdr.SCMetaKind.SC_META_V0, v0=xdr.SCMetaV0(key=k.encode(), val=v.encode())).to_xdr_bytes()
                     for k, v in meta.items())
    return b"\0asm\x01\0\0\0" + custom_section("contractspecv0", spec) + custom_section("contractmetav0", metas)


def entry_xdr(data: xdr.LedgerEntryData) -> str:
    return data.to_xdr()


def instance_entry(contract: str, wasm: bytes) -> xdr.LedgerEntryData:
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.ContractDataEntry(
        ext=xdr.ExtensionPoint(0), contract=Address(contract).to_xdr_sc_address(),
        key=xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE), durability=xdr.ContractDataDurability.PERSISTENT,
        val=xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE, instance=xdr.SCContractInstance(
            executable=xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,
                                              wasm_hash=xdr.Hash(hashlib.sha256(wasm).digest())),
            storage=None))))


def code_entry(wasm: bytes) -> xdr.LedgerEntryData:
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_CODE, contract_code=xdr.ContractCodeEntry(
        ext=xdr.ContractCodeEntryExt(0), hash=xdr.Hash(hashlib.sha256(wasm).digest()), code=wasm))


def agent_entry(card: bytes, endpoint: str, active: bool = True) -> xdr.LedgerEntryData:
    def sym(s):
        return xdr.SCVal(xdr.SCValType.SCV_SYMBOL, sym=xdr.SCSymbol(s.encode()))

    def b32(h):
        return xdr.SCVal(xdr.SCValType.SCV_BYTES, bytes=xdr.SCBytes(h))
    fields = [("active", xdr.SCVal(xdr.SCValType.SCV_BOOL, b=active)),
              ("end_hash", b32(hashlib.sha256(endpoint.encode()).digest())),
              ("meta_hash", b32(hashlib.sha256(card).digest())),
              ("meta_uri", xdr.SCVal(xdr.SCValType.SCV_STRING, str=xdr.SCString(b"https://cards.example.com/agent.json"))),
              ("owner", xdr.SCVal(xdr.SCValType.SCV_ADDRESS, address=Address(OWNER).to_xdr_sc_address())),
              ("version", xdr.SCVal(xdr.SCValType.SCV_U32, u32=xdr.Uint32(1)))]
    key = xdr.SCVal(xdr.SCValType.SCV_VEC, vec=xdr.SCVec([sym("Agent"), b32(bytes.fromhex(AGENT_ID))]))
    return xdr.LedgerEntryData(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.ContractDataEntry(
        ext=xdr.ExtensionPoint(0), contract=Address(REGISTRY).to_xdr_sc_address(), key=key,
        durability=xdr.ContractDataDurability.PERSISTENT,
        val=xdr.SCVal(xdr.SCValType.SCV_MAP, map=xdr.SCMap([xdr.SCMapEntry(sym(k), v) for k, v in fields]))))


def key_of(data: xdr.LedgerEntryData) -> str:
    if data.type == xdr.LedgerEntryType.CONTRACT_CODE:
        return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_CODE,
                             contract_code=xdr.LedgerKeyContractCode(hash=data.contract_code.hash)).to_xdr()
    cd = data.contract_data
    return xdr.LedgerKey(type=xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        contract=cd.contract, key=cd.key, durability=cd.durability)).to_xdr()


def repo_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(f"repo-{COMMIT}/{name}", text)
    return buf.getvalue()


def network(ledger: list[xdr.LedgerEntryData], http: dict[str, bytes]):
    table = {key_of(e): entry_xdr(e) for e in ledger}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            keys = json.loads(request.content)["params"]["keys"]
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
                "entries": [{"key": k, "xdr": table[k]} for k in keys if k in table], "latestLedger": 1}})
        url = str(request.url)
        for prefix, body in http.items():
            if url.startswith(prefix):
                return httpx.Response(200, content=body)
        return httpx.Response(404, json={})
    return httpx.MockTransport(handler)


def settings():
    return Settings(_env_file=None, agent_registry_contract_id=REGISTRY)


@pytest.fixture(autouse=True)
def offline_hosts(monkeypatch):
    # The SSRF guard resolves DNS; the hosts here only exist in the mock transport.
    monkeypatch.setattr(agent_resolver, "guard_remote_url", lambda url: url)


def test_references_are_classified():
    assert classify(AGENT_ID) == "registry_agent"
    assert classify(CONTRACT) == "contract"
    assert classify(OWNER) == "account"
    assert classify("https://github.com/o/r/tree/main") == "repository"
    assert classify("https://x.example.com/.well-known/agent.json") == "card"
    assert classify("https://x.example.com/mcp") == "endpoint"
    with pytest.raises(ValueError):
        classify(Keypair.random().secret)


def test_wasm_spec_and_metadata_are_parsed():
    wasm = build_wasm({"source_repo": "github:acme/agent", "rsver": "1.91.0"}, ["pay", "upgrade"])
    sections = wasm_custom_sections(wasm)
    assert [f.name for f in parse_spec(sections["contractspecv0"])] == ["pay", "upgrade"]
    assert parse_meta(sections["contractmetav0"]) == {"source_repo": "github:acme/agent", "rsver": "1.91.0"}


def test_registry_agent_with_hash_bound_card_resolves_source_and_endpoint():
    card = json.dumps({"name": "Payroll agent", "description": "Pays approved payroll.",
                       "source": {"repository": "https://github.com/acme/payroll", "commit": COMMIT},
                       "endpoints": [{"name": "MCP", "endpoint": ENDPOINT}], "wallet": OWNER}).encode()
    transport = network([agent_entry(card, ENDPOINT)], {"https://cards.example.com/agent.json": card})
    res = asyncio.run(AgentResolver(settings(), transport=transport).resolve(AGENT_ID))
    steps = {s["check"]: s["result"] for s in res["steps"]}
    assert steps["registry"] == "found" and steps["card_hash"] == "verified" and steps["endpoint_hash"] == "verified"
    assert res["source"] == {"repository": "https://github.com/acme/payroll", "revision": COMMIT,
                             "binding": "registry_card", "verified": True}
    assert res["wallet"] == OWNER and res["endpoint_bound"] is True


def test_card_that_does_not_match_the_registry_hash_is_ignored():
    card = json.dumps({"name": "x", "source": {"repository": "https://github.com/acme/payroll", "commit": COMMIT}}).encode()
    transport = network([agent_entry(b"what the owner registered", ENDPOINT)], {"https://cards.example.com/agent.json": card})
    res = asyncio.run(AgentResolver(settings(), transport=transport).resolve(AGENT_ID))
    assert {s["check"]: s["result"] for s in res["steps"]}["card_hash"] == "mismatch"
    assert res["card"] is None and res["source"]["repository"] == ""


def _attestation(wasm_hash: str, commit: str) -> bytes:
    statement = {"subject": [{"digest": {"sha256": wasm_hash}}],
                 "predicate": {"buildDefinition": {"externalParameters": {"workflow": {"path": ".github/workflows/release.yml"}},
                                                   "resolvedDependencies": [{"digest": {"gitCommit": commit}}]}}}
    return json.dumps({"attestations": [{"bundle": {"dsseEnvelope": {
        "payload": base64.b64encode(json.dumps(statement).encode()).decode()}}}]}).encode()


def test_contract_source_is_verified_only_by_a_build_attestation_for_the_same_wasm():
    wasm = build_wasm({"source_repo": "github:acme/agent"}, ["pay"])
    wasm_hash = hashlib.sha256(wasm).hexdigest()
    ledger = [instance_entry(CONTRACT, wasm), code_entry(wasm)]
    attested = network(ledger, {f"https://api.github.com/repos/acme/agent/attestations/sha256:{wasm_hash}": _attestation(wasm_hash, COMMIT)})
    res = asyncio.run(AgentResolver(settings(), transport=attested).resolve(CONTRACT))
    assert res["contract"]["wasm_hash_verified"] is True and [f["name"] for f in res["contract"]["functions"]] == ["pay"]
    assert res["source"] == {"repository": "https://github.com/acme/agent", "revision": COMMIT,
                             "binding": "attested_build", "verified": True}
    other = network(ledger, {f"https://api.github.com/repos/acme/agent/attestations/sha256:{wasm_hash}": _attestation("ff" * 32, COMMIT)})
    res = asyncio.run(AgentResolver(settings(), transport=other).resolve(CONTRACT))
    assert res["source"]["binding"] == "wasm_metadata" and res["source"]["verified"] is False


def test_onchain_only_agent_cannot_pass_and_says_why():
    wasm = build_wasm({}, ["pay", "upgrade"])
    transport = network([instance_entry(CONTRACT, wasm), code_entry(wasm)], {})
    result = asyncio.run(audit_reference(CONTRACT, settings(), transport=transport, deep=False))
    findings = {f["id"]: f for f in result["report"]["findings"]}
    assert result["decision"] == "needs_evidence"
    assert findings["stellar_native-onchain-source-unbound"]["kind"] == "evidence_gap"
    assert findings["stellar_native-onchain-contract-upgradeable"]["severity"] == "low"
    assert result["report"]["resolution"]["contract"]["wasm_hash_verified"] is True
    encoded = json.loads(result["report_json"])
    assert encoded["resolution"]["kind"] == "contract"
    assert hashlib.sha256(result["report_json"].encode()).hexdigest() == result["report_sha256"]


def test_registry_agent_with_bound_source_is_audited_at_the_pinned_commit(monkeypatch):
    agent = ('from stellar_sdk import Keypair, Server, TransactionBuilder, Network, Asset\nimport os\n'
             'from decimal import Decimal\n'
             'ALLOW = {"GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"}\nMAX = Decimal("50")\n'
             'def pay(to, amount, approval):\n'
             '    if not approved(approval):\n        raise PermissionError("approval")\n'
             '    if to not in ALLOW:\n        raise PermissionError("recipient")\n'
             '    if Decimal(amount) > MAX:\n        raise ValueError("cap")\n'
             '    kp = Keypair.from_secret(os.environ["SECRET"])\n'
             '    tx = TransactionBuilder(Server("https://horizon-testnet.stellar.org").load_account(kp.public_key),'
             ' Network.TESTNET_NETWORK_PASSPHRASE).append_payment_op(to, Asset.native(), amount).build()\n'
             '    tx.sign(kp)\n    return tx\n'
             'def approved(token):\n    return token == os.environ["APPROVAL"]\n')
    card = json.dumps({"name": "Payroll agent", "description": "Pays approved payroll vendors.",
                       "source": {"repository": "https://github.com/acme/payroll", "commit": COMMIT}}).encode()
    transport = network([agent_entry(card, ENDPOINT)], {
        "https://cards.example.com/agent.json": card,
        f"https://codeload.github.com/acme/payroll/zip/{COMMIT}": repo_zip({"agent/pay.py": agent, "README.md": "Payroll."})})
    result = asyncio.run(audit_reference(AGENT_ID, settings(), transport=transport, deep=False))
    assert result["report"]["repository"]["revision"] == COMMIT
    assert result["report"]["resolution"]["source"]["binding"] == "registry_card"
    assert "stellar_native-onchain-source-unbound" not in {f["id"] for f in result["report"]["findings"]}


def test_archive_paths_cannot_escape_the_extraction_directory(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("repo/../../escape.txt", "x")
        z.writestr("repo/ok.py", "print(1)\n")
    transport = network([], {f"https://codeload.github.com/acme/r/zip/{COMMIT}": buf.getvalue()})
    resolver = AgentResolver(settings(), transport=transport)
    asyncio.run(resolver.download("https://github.com/acme/r", COMMIT, tmp_path))
    assert (tmp_path / "ok.py").exists() and not (tmp_path.parent / "escape.txt").exists()


def _pkt(line: str) -> bytes:
    data = line.encode()
    return f"{len(data) + 4:04x}".encode() + data


def test_repository_reference_is_pinned_from_git_refs_and_audited_at_that_commit():
    refs = (_pkt("# service=git-upload-pack\n") + b"0000" + _pkt(f"{COMMIT} HEAD\x00multi_ack symref=HEAD:refs/heads/main\n")
            + _pkt(f"{COMMIT} refs/heads/main\n") + b"0000")
    agent = "def pay(to, amount):\n    return None\n"
    transport = network([], {"https://github.com/acme/agent.git/info/refs": refs,
                             f"https://codeload.github.com/acme/agent/zip/{COMMIT}": repo_zip({"agent.py": agent})})
    result = asyncio.run(audit_reference("https://github.com/acme/agent", settings(), transport=transport, deep=False))
    steps = {s["check"]: s["result"] for s in result["report"]["resolution"]["steps"]}
    assert steps == {"source_pin": "pinned", "source_fetch": "fetched"}
    assert result["report"]["repository"]["revision"] == COMMIT


def test_an_unreachable_repository_is_an_error_not_a_silent_onchain_audit():
    with pytest.raises(ValueError, match="commit could not be resolved"):
        asyncio.run(audit_reference("https://github.com/acme/missing", settings(), transport=network([], {}), deep=False))
