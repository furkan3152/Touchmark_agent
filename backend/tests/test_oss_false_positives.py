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
    login = AgentArtifact(source_kind=SourceKind.REPO, name="login", code_files={
        "auth.ts": "// smart wallet login\nconst challenge = await buildChallenge(); // SEP-10 web auth\n"})
    assert "stellar_native-sep45-boundary" in run(StellarNativeAuditor, login)


def test_comments_and_comparisons_in_code_are_not_floating_dependencies():
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="x", code_files={
        "src/a.ts": "/**\n * doc\n */\nif (amount >= limit) throw new Error();\n",
        "package-lock.json": "{}"})
    assert "provenance-floating-dependencies" not in run(ProvenanceAuditor, artifact)
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
