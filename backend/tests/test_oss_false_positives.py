"""False positives found by comparing system reports on open-source agents with manual review."""

from __future__ import annotations

import asyncio
import json

import httpx

from backend.app.config import Settings
from backend.app.models import AgentArtifact, SourceKind
from backend.app.services.repo_audit import _dependencies, select_repository
from backend.app.stellar.authority import AuthorityReader, code_networks
from backend.app.swarm.provenance import ProvenanceAuditor
from backend.app.swarm.security import SecurityAuditor
from backend.app.swarm.stellar_native import StellarNativeAuditor

DEST = "GDSTL33DJ5NU5IWBW2Z67IEAXRJIFLQBI3FDWYV73XEDG4JBVQBQZXSP"
SETTINGS = Settings(_env_file=None)


def collect(code):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(404, json={})
    reader = AuthorityReader("testnet", transport=httpx.MockTransport(handler))
    return asyncio.run(reader.collect(code_files=code)), seen


def test_blocklist_and_test_addresses_are_not_payment_destinations():
    facts, seen = collect({
        "src/pay-link/blacklist.ts": f'export const SCAM = ["{DEST}"];\n',
        "scripts/smoke-test-send.ts": f'const to = "{DEST}";\n',
        "src/policy.ts": f'const blocked = new Set(["{DEST}"]); // denylist\n',
        "src/net.ts": 'const NET = "Test SDF Network ; September 2015";\n'})
    assert facts["destinations"] == [] and seen == []


def test_destinations_are_not_checked_on_a_network_the_code_does_not_target():
    code = {"pay.ts": f'const NET = Networks.PUBLIC;\nconst TREASURY = "{DEST}";\n'}
    assert code_networks(code) == {"mainnet"}
    facts, seen = collect(code)
    assert facts["destinations"] == [] and "mainnet" in facts["destinations_skipped"] and seen == []


def run(auditor_cls, artifact):
    findings, _, _ = asyncio.run(auditor_cls(SETTINGS).analyse(artifact, True))
    return {f.id for f in findings}


def test_contract_id_alone_does_not_raise_sep45():
    sac = "C" + "A" * 55
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="budget",
                             code_files={"budget.ts": f'const USDC_SAC = "{sac}";\n'})
    assert "stellar_native-sep45-boundary" not in run(StellarNativeAuditor, artifact)
    passkeys = AgentArtifact(source_kind=SourceKind.REPO, name="kit", code_files={
        "kit.ts": f'// smart account kit\nconst ADDR = {{ webauthnVerifier: "{sac}" }};\n'})
    assert "stellar_native-sep45-boundary" not in run(StellarNativeAuditor, passkeys)
    login = AgentArtifact(source_kind=SourceKind.REPO, name="login", code_files={
        "auth.ts": "// smart wallet login\nconst challenge = await buildChallenge(); // SEP-10 web auth\n"})
    assert "stellar_native-sep45-boundary" in run(StellarNativeAuditor, login)
    # An EVM product with ERC-4337 smart wallets and a login route has no SEP-45 boundary.
    evm = AgentArtifact(source_kind=SourceKind.REPO, name="evm", code_files={
        "wallet.ts": "// smart wallet (ERC-4337) via viem\napp.post('/auth', siweLogin);\n"})
    assert "stellar_native-sep45-boundary" not in run(StellarNativeAuditor, evm)


def test_comments_and_comparisons_in_code_are_not_floating_dependencies():
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="x", code_files={
        "src/a.ts": "/**\n * doc\n */\nif (amount >= limit) throw new Error();\n",
        "package-lock.json": "{}"})
    assert "provenance-floating-dependencies" not in run(ProvenanceAuditor, artifact)
    package = artifact.model_copy(update={"code_files": {**artifact.code_files, "package.json": json.dumps({
        "engines": {"node": ">=20"}, "scripts": {"lint": "eslint src/**/*.ts"},
        "dependencies": {"zod": "4.1.0"}})}})
    assert "provenance-floating-dependencies" not in run(ProvenanceAuditor, package)
    docker = artifact.model_copy(update={"code_files": {**artifact.code_files, "Dockerfile": "FROM node:latest\n"}})
    assert "provenance-floating-dependencies" in run(ProvenanceAuditor, docker)


def test_lockfile_pins_manifest_ranges(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"@stellar/stellar-sdk": "^12.3.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {}, "node_modules/@stellar/stellar-sdk": {"version": "12.3.0"}}}))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text("export const a = 1;\n")
    assert _dependencies(tmp_path) == ["@stellar/stellar-sdk@12.3.0"]
    ranged = AgentArtifact(source_kind=SourceKind.REPO, name="x", code_files={"a.ts": "x"},
                           dependencies=["@stellar/stellar-sdk@^12.3.0"])
    assert "security-unpinned-deps" in run(SecurityAuditor, ranged)
    locked = ranged.model_copy(update={"lockfiles": {"package-lock.json": "ab"}})
    assert "security-unpinned-deps" not in run(SecurityAuditor, locked)


def test_generator_templates_are_selected_as_source(tmp_path):
    (tmp_path / "templates" / "python").mkdir(parents=True)
    (tmp_path / "templates" / "python" / "server.py.hbs").write_text("import os\nSECRET = os.environ['SIGNER_SECRET']\n")
    (tmp_path / "templates" / "README.md.hbs").write_text("# docs\n")
    files, _ = select_repository(tmp_path)
    assert list(files) == ["templates/python/server.py.hbs"]


def test_loaded_key_without_transactions_is_custody_not_signing():
    from backend.app.swarm.codeflow import analyse_code
    wallet = ("from stellar_sdk import Keypair, Server\n"
              "class Wallet:\n"
              "    def __init__(self, secret):\n"
              "        self.kp = Keypair.from_secret(secret)\n"
              "    def balance(self):\n"
              "        return Server('https://horizon-testnet.stellar.org').accounts().account_id(self.kp.public_key).call()\n")
    profile = analyse_code({"wallet.py": wallet})
    assert profile.has("key_custody") and not profile.has("stellar_signing")
    paying = wallet + ("    def pay(self, to, amount):\n"
                       "        return Server('x').submit_transaction(build(self.kp, to, amount))\n")
    assert analyse_code({"wallet.py": paying}).has("stellar_signing")


def test_registered_mcp_tools_and_readme_are_review_surfaces(tmp_path):
    from backend.app.services.repo_audit import registered_tools
    files = {"src/server.ts": 'server.tool("get_budget", "Report budget", {}, async () => x);\n'
                              'server.registerTool("check_spend", { description: "advise" }, h);\n',
             "app.py": "@mcp.tool()\nasync def get_balance(address: str):\n    return 1\n"}
    assert [t.name for t in registered_tools(files)] == ["get_balance", "get_budget", "check_spend"]
    assert all(t.origin == "registered" for t in registered_tools(files))
    (tmp_path / "README.md").write_text("Advises on a budget. Never pays.\n")
    (tmp_path / "server.ts").write_text(files["src/server.ts"])
    _, selection = select_repository(tmp_path)
    assert selection["instructions"] == {"README.md": "Advises on a budget. Never pays.\n"}


def test_asset_issuers_and_examples_are_not_destinations():
    facts, seen = collect({"run.ts": f'throw new Error(`use CODE:ISSUER (e.g. EURC:{DEST})`);\n'
                                     f'const asset = new Asset("USDC", "{DEST}");\n'})
    assert facts["destinations"] == [] and seen == []


def test_lockfile_pins_ranges_but_not_build_inputs():
    base = AgentArtifact(source_kind=SourceKind.REPO, name="x", lockfiles={"uv.lock": "ab"}, code_files={
        "pyproject.toml": '[project]\ndependencies = ["httpx>=0.28.1"]\n', "a.py": "x = 1\n"})
    assert "provenance-floating-dependencies" not in run(ProvenanceAuditor, base)
    docker = base.model_copy(update={"code_files": {**base.code_files, "Dockerfile": "RUN corepack prepare pnpm@latest\n"}})
    assert "provenance-floating-dependencies" in run(ProvenanceAuditor, docker)


def test_masked_secret_in_a_log_is_not_exfiltration():
    from backend.app.swarm.agentic_paths import _scan_file
    code = ("const secretKey = process.env.STELLAR_SECRET;\n"
            "console.log(`Secret: ${maskSecret(secretKey)}`);\n")
    assert _scan_file("cli.js", code)[2] == []
    assert _scan_file("cli.js", code.replace("maskSecret(secretKey)", "secretKey"))[2]


def test_configured_base_url_with_variable_path_is_not_ssrf():
    from backend.app.swarm.codeflow import analyse_code
    sdk = ("import httpx\n"
           "class Client:\n"
           "    def __init__(self, base_url):\n"
           "        self.base_url = base_url\n"
           "    def account(self, account_id):\n"
           "        return httpx.get(f\"{self.base_url}/accounts/{account_id}\")\n")
    assert not [f for f in analyse_code({"client.py": sdk}).flows if f.category == "ssrf"]
    tool = ("import httpx\n"
            "from mcp import tool\n"
            "@tool\n"
            "def fetch(url: str):\n"
            "    return httpx.get(url).text\n")
    assert [f for f in analyse_code({"tool.py": tool}).flows if f.category == "ssrf"]


def test_repository_selection_keeps_records_and_security_files(tmp_path):
    from backend.app.services.repo_audit import select_repository
    (tmp_path / "LICENSE").write_text("MIT License\n")
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/ci.yml").write_text("on: push\n")
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"util{i}.ts").write_text("export const fetchIt = () => fetch(url); // payment secret\n" * 3)
    (src / "auth.ts").write_text("export function check(k: string) { return k.length > 0; }\n")
    files, selection = select_repository(tmp_path, max_files=2)
    assert {"LICENSE", ".github/workflows/ci.yml", "src/auth.ts"} <= set(files)
    manifest = selection["manifest"]
    assert manifest["complete"] is False and len(manifest["source_files_not_selected"]) == 4


def test_source_outside_the_budget_keeps_analysis_incomplete():
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="big", code_files={"a.ts": "export const x = 1;\n"},
                             raw_metadata={"source_not_selected": ["src/auth.ts"]})
    assert "security-source-analysis-incomplete" in run(SecurityAuditor, artifact)


def test_ci_floats_only_through_unpinned_actions_and_latest_images():
    pinned = ("jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
              "      - uses: docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302\n"
              "        with:\n          flavor: latest=auto\n          tags: [\"v*\"]\n")
    def found(text):
        artifact = AgentArtifact(source_kind=SourceKind.REPO, name="ci", lockfiles={"package-lock.json": "x"},
                                 code_files={"a.ts": "export const a = 1;\n", ".github/workflows/ci.yml": text})
        return "provenance-floating-dependencies" in run(ProvenanceAuditor, artifact)
    assert not found(pinned)
    assert found(pinned.replace("checkout@11d5960a326750d5838078e36cf38b85af677262", "checkout@v4"))
