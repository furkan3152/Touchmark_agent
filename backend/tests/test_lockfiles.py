"""The installed version decides version-dependent rules, so the resolver must read every
lockfile format the study corpus uses and pick the one the package manager would."""

from __future__ import annotations

import asyncio
import json
import time

from backend.app.services import lockfiles
from backend.app.services.lockfiles import Lockset, exact_pin, read_repository, spec_admits, spec_intervals, version_key


def test_ranges_admit_exactly_the_versions_their_package_manager_would_install():
    assert spec_admits("^2.17.0", None, "2.23.0") and spec_admits("^2.17.0", "2.23.0")
    assert spec_admits("^2.23.1", None, "2.23.0") is False
    assert spec_admits("~0.4.0", "0.4.0", "0.5.0") and spec_admits("~0.4.0", "0.5.0") is False
    assert spec_admits("^0.3.0", "0.4.0") is False                      # caret below 1.0 stays in the minor
    assert spec_admits("22.0.7", "23.0.0", None, "cargo") is False      # Cargo's bare version is a caret
    assert spec_admits(">=22.0.0, <23", "22.0.9", "22.0.10", "cargo")
    assert spec_admits("~=1.4", "1.9.0", "2.0.0", "pypi") and spec_admits("~=1.4", "2.0.0", None, "pypi") is False
    assert spec_admits("1.2.3 - 1.4", "1.4.5", "1.4.6") and spec_admits("1.2.3 - 1.4", "1.5.0") is False
    assert spec_admits("workspace:*") is None and spec_admits("latest") is None
    assert exact_pin("2.8.0") == "2.8.0" and exact_pin("=2.8.0") == "2.8.0" and exact_pin("^2.8.0") is None


def test_npm_workspace_resolves_each_package_through_its_nearest_node_modules(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}))
    sdk = tmp_path / "packages" / "sdk"
    sdk.mkdir(parents=True)
    (sdk / "package.json").write_text(json.dumps({"dependencies": {"@x402/fetch": "^2.17.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/@x402/fetch": {"version": "2.17.0"},
        "node_modules/@x402/core": {"version": "2.17.0"},
        "packages/sdk/node_modules/@x402/fetch": {"version": "2.28.0"},
        "packages/sdk/node_modules/@x402/core": {"version": "2.28.0"}}}))
    locks = Lockset.read(tmp_path)
    assert locks.resolve("@x402/fetch", "packages/sdk/src/index.ts").versions == ("2.28.0",)
    # Not a direct dependency of packages/sdk: every installed copy, for the rule to judge.
    assert locks.resolve("@x402/core", "packages/sdk/src/index.ts").versions == ("2.17.0", "2.28.0")
    assert locks.resolve("left-pad", "packages/sdk/src/index.ts") is None


def test_pnpm_importers_yarn_and_unlocked_ranges(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    app = tmp_path / "apps" / "agent"
    app.mkdir(parents=True)
    (app / "package.json").write_text(json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0", "mppx": "*"}}))
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  apps/agent:\n    dependencies:\n"
        "      '@stellar/mpp':\n        specifier: ^0.4.0\n        version: 0.4.0(typescript@5.9.3)\n"
        "      mppx:\n        specifier: '*'\n        version: 0.6.15(hono@4.12.18)\n\npackages:\n\n"
        "  '@stellar/mpp@0.4.0':\n    resolution: {integrity: sha512-x}\n")
    locks = Lockset.read(tmp_path)
    mpp = locks.resolve("@stellar/mpp", "apps/agent/src/server.ts")
    assert mpp.versions == ("0.4.0",) and mpp.spec == "^0.4.0" and mpp.source == "pnpm-lock.yaml"
    assert locks.resolve("mppx", "apps/agent/src/server.ts").versions == ("0.6.15",)

    other = tmp_path / "yarnrepo"
    other.mkdir()
    (other / "package.json").write_text(json.dumps({"dependencies": {"@x402/core": "^2.8.0"}}))
    (other / "yarn.lock").write_text('"@x402/core@^2.8.0":\n  version "2.9.1"\n  resolved "x"\n')
    assert Lockset.read(other).resolve("@x402/core", "src/a.ts").versions == ("2.9.1",)

    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "package.json").write_text(json.dumps({"dependencies": {"@x402/core": "^2.17.0"}}))
    unlocked = Lockset.read(bare).resolve("@x402/core", "src/a.ts")
    assert not unlocked.locked and unlocked.spec == "^2.17.0"


def test_cargo_lock_gives_transitive_crates_and_survives_the_intake_record(tmp_path):
    crate = tmp_path / "contracts" / "beacon"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "beacon"\n\n[dependencies]\nsoroban-sdk = "=28.0.0"\n')
    (crate / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "soroban-sdk"\nversion = "28.0.0"\n\n'
        '[[package]]\nname = "soroban-sdk-macros"\nversion = "28.0.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n')
    record = json.loads(json.dumps(Lockset.read(tmp_path).to_json()))
    locks = Lockset(record)
    assert locks.resolve("soroban-sdk", "contracts/beacon/src/lib.rs").versions == ("28.0.0",)
    assert locks.resolve("soroban-sdk-macros", "contracts/beacon/src/lib.rs").versions == ("28.0.0",)
    assert "serde" not in record["locked"]["contracts/beacon/Cargo.lock"]   # only watched crates are kept


def test_intake_records_where_the_server_is_deployed_as_several_instances(tmp_path):
    from backend.app.services.repo_audit import select_repository

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.ts").write_text("export const app = 1;\n")
    (tmp_path / "vercel.json").write_text("{}")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "wrangler.toml").write_text("")
    assert select_repository(tmp_path)[1]["deployment_markers"] == ["vercel.json"]


def test_pep440_and_prerelease_versions_resolve_instead_of_failing_the_read(tmp_path):
    assert version_key("2.9.0.post0") == (2, 9, 0) and version_key("2.31.0.20240406") == (2, 31, 0)
    assert version_key("2.0.0rc1") == (2, 0, 0) and version_key("1.0.0-rc.1+b") == (1, 0, 0)
    assert version_key("2023.3.post1") == (2023, 3, 0) and version_key("1" * 200) is None
    assert spec_admits(">=2.8", "not-a-version") is None
    cases = {"poetry.lock": ('[tool.poetry.dependencies]\nstellar-sdk = "^12"\npytz = "*"\n',
                             '[[package]]\nname = "pytz"\nversion = "2023.3.post1"\n\n'
                             '[[package]]\nname = "stellar-sdk"\nversion = "12.0.0"\n'),
             "uv.lock": ('[project]\nname = "x"\ndependencies = ["stellar-sdk>=12", "python-dateutil>=2.8"]\n',
                         '[[package]]\nname = "python-dateutil"\nversion = "2.9.0.post0"\n\n'
                         '[[package]]\nname = "stellar-sdk"\nversion = "12.1.0"\n')}
    for lock, (manifest, text) in cases.items():
        repo = tmp_path / lock
        repo.mkdir()
        (repo / "pyproject.toml").write_text(manifest)
        (repo / lock).write_text(text)
        assert Lockset.read(repo).resolve("stellar-sdk", "agent.py").versions in {("12.0.0",), ("12.1.0",)}


#: Files that parse but have the wrong shape, or nest deeper than a parser recurses.
HOSTILE = {
    "package.json": "[]", "a/package.json": '{"dependencies": ["x"]}', "b/package.json": "{}",
    "b/package-lock.json": "[1]", "c/Cargo.toml": 'dependencies = "x"\nworkspace = "x"\n',
    "d/pyproject.toml": '[project]\ndependencies = [1, 2]\n[tool.poetry]\ndependencies = ["a"]\n',
    "e/package.json": "{}", "e/bun.lock": "[]", "f/requirements.txt": "x\n", "f/Pipfile.lock": "[]",
    "g/requirements.txt": "x\n", "g/Pipfile.lock": '{"default": {"stellar-sdk": "13.0.0"}, "develop": [1]}',
    "h/Cargo.toml": '[dependencies]\nsoroban-sdk = { version = 22, package = 7 }\n', "h/Cargo.lock": "package = 3\n",
    "i/package.json": "{}",
    "i/package-lock.json": '{"dependencies":' + '{"a":{"version":"1.0.0","dependencies":' * 3000 + "{}" + "}}" * 3000 + "}",
    "j/package.json": "[" * 100_000 + "]" * 100_000,
}


def test_wrong_shaped_or_deeply_nested_files_cost_only_their_own_versions(tmp_path):
    for name, text in HOSTILE.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    good = tmp_path / "ok"
    good.mkdir()
    (good / "package.json").write_text(json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0"}}))
    (good / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/@stellar/mpp": {"version": "0.4.0"}}}))
    started = time.monotonic()
    locks = Lockset.read(tmp_path)
    assert time.monotonic() - started < 5
    assert locks.resolve("@stellar/mpp", "ok/src/server.ts").versions == ("0.4.0",)
    assert locks.resolve("soroban-sdk", "h/src/lib.rs").versions == ()


def test_a_repository_with_broken_lockfiles_is_still_audited(tmp_path):
    from backend.app.config import Settings
    from backend.app.services.repo_audit import audit_repository

    for name, text in HOSTILE.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "agent.ts").write_text('import { Horizon } from "@stellar/stellar-sdk";\nexport const h = 1;\n')
    out = asyncio.run(audit_repository(tmp_path, name="x", purpose="", settings=Settings(_env_file=None), deep=False))
    assert out["decision"] and out["report"]["findings"] is not None


def test_each_lockfile_is_parsed_once_however_many_workspaces_use_it(tmp_path, monkeypatch):
    packages = {"": {}}
    for i in range(150):
        ws = tmp_path / "packages" / f"p{i}"
        ws.mkdir(parents=True)
        (ws / "package.json").write_text(json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0", f"dep{i}": "^1.0.0"}}))
        packages[f"packages/p{i}/node_modules/@stellar/mpp"] = {"version": f"0.4.{i}"}
        for j in range(60):
            packages[f"node_modules/lib{i}-{j}"] = {"version": "1.0.0"}
    packages["node_modules/@stellar/mpp"] = {"version": "0.3.0"}
    (tmp_path / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    parsed = []
    real = lockfiles._package_lock
    monkeypatch.setattr(lockfiles, "_package_lock", lambda text: parsed.append(1) or real(text))
    started = time.monotonic()
    locks = Lockset(read_repository(tmp_path))
    assert len(parsed) == 1 and time.monotonic() - started < 3
    assert locks.resolve("@stellar/mpp", "packages/p7/src/a.ts").versions == ("0.4.7",)


def test_pnpm_single_project_lockfiles_list_the_root_dependencies_at_the_top_level(tmp_path):
    v5 = ("lockfileVersion: 5.4\n\nspecifiers:\n  '@stellar/mpp': ^0.4.0\n\ndependencies:\n  '@stellar/mpp': 0.4.0\n\n"
          "packages:\n\n  /@stellar/mpp/0.4.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n")
    v6 = ("lockfileVersion: '6.0'\n\ndependencies:\n  '@stellar/mpp':\n    specifier: ^0.4.0\n    version: 0.4.0\n\n"
          "devDependencies:\n  typescript:\n    specifier: ^5.0.0\n    version: 5.4.0\n\n"
          "packages:\n\n  /@stellar/mpp@0.4.0:\n    resolution: {integrity: sha512-x}\n")
    for label, text in (("v5", v5), ("v6", v6)):
        repo = tmp_path / label
        repo.mkdir()
        (repo / "package.json").write_text(json.dumps({"dependencies": {"@stellar/mpp": "^0.4.0"}}))
        (repo / "pnpm-lock.yaml").write_text(text)
        found = Lockset.read(repo).resolve("@stellar/mpp", "src/server.ts")
        assert found.versions == ("0.4.0",) and found.source == "pnpm-lock.yaml", label


def test_a_declared_dependency_without_its_own_entry_takes_only_locked_versions_its_range_admits():
    record = {"importers": {"": {"lockfiles": ["yarn.lock"], "deps": {
                  "@stellar/mpp": {"spec": "^0.4.0", "version": None, "source": "package.json"},
                  "@x402/core": {"spec": "^2.30.0", "version": None, "source": "package.json"},
                  "@x402/fetch": {"spec": "workspace:*", "version": None, "source": "package.json"}}}},
              "locked": {"yarn.lock": {"@stellar/mpp": ["0.3.0", "0.4.2"], "@x402/core": ["2.17.0"],
                                       "@x402/fetch": ["2.17.0"]}}}
    locks = Lockset(record)
    mpp = locks.resolve("@stellar/mpp", "src/a.ts")
    assert mpp.versions == ("0.4.2",) and mpp.source == "yarn.lock"
    assert locks.resolve("@x402/core", "src/a.ts").versions == ()      # the locked copy is not this range's
    assert locks.resolve("@x402/fetch", "src/a.ts").versions == ()     # an unreadable range admits nothing


def test_a_lockfile_above_a_directory_it_does_not_list_says_nothing_about_it(tmp_path):
    # A scaffold template below a pnpm workspace that does not list it: the root lockfile has no
    # importer for it, so its declared range takes no version from there.
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"@stellar/stellar-sdk": "^14.0.0"}}))
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n")
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      other:\n        specifier: 1.0.0\n"
        "        version: 1.0.0\n\npackages:\n\n  '@stellar/stellar-sdk@14.6.1':\n    resolution: {integrity: x}\n")
    template = tmp_path / "packages/cli/templates/bot"
    template.mkdir(parents=True)
    (template / "package.json").write_text(json.dumps({"dependencies": {"@stellar/stellar-sdk": "^14.0.0"}}))
    locks = Lockset.read(tmp_path)
    assert locks.resolve("@stellar/stellar-sdk", "packages/cli/templates/bot/src/a.ts").versions == ()
    # The lockfile in the root's own directory still stands for the root.
    assert locks.resolve("@stellar/stellar-sdk", "src/a.ts").versions == ("14.6.1",)


def test_long_ranges_are_unreadable_at_once():
    for spec in (">=0.1" + " " * 120_000 + "<1", " " * 20_000 + "x", "1" + " || 1" * 10_000):
        started = time.monotonic()
        assert spec_intervals(spec) is None and exact_pin(spec) is None and spec_admits(spec, "0.4.0") is None
        assert time.monotonic() - started < 0.1
    assert spec_intervals(">=1.2.3 <2.0.0 || ^3.0.0") == [((1, 2, 3), (2, 0, 0)), ((3, 0, 0), (4, 0, 0))]
    assert exact_pin(" ==2.8.0 ") == "2.8.0"
