"""The installed version decides version-dependent rules, so the resolver must read every
lockfile format the study corpus uses and pick the one the package manager would."""

from __future__ import annotations

import json

from backend.app.services.lockfiles import Lockset, exact_pin, spec_admits


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


def test_paths_deeper_than_any_real_repository_are_not_selected(tmp_path):
    import time

    from backend.app.services.repo_audit import MAX_PATH_DEPTH, select_repository

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "agent.ts").write_text("export const a = 1;\n")
    deep = tmp_path.joinpath(*["d"] * (MAX_PATH_DEPTH + 5))
    deep.mkdir(parents=True)
    (deep / "x.ts").write_text("export const b = 2;\n")
    started = time.monotonic()
    files, _ = select_repository(tmp_path)
    assert "src/agent.ts" in files and not any(name.endswith("/x.ts") for name in files)
    assert time.monotonic() - started < 5
