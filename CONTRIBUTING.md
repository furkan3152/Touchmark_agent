# Contributing to Touchmark Stellar

Thanks for taking a look. Bug reports, fixes and new checks are all welcome.

## Setup

You need:

- Python 3.12 for the backend and API.
- Rust for the Soroban contracts. The toolchain and the `wasm32v1-none` target are pinned in `rust-toolchain.toml`.
- Soroban CLI if you want to deploy or call contracts on testnet.
- Docker if you want to run the service in a container (`compose.yaml`).

```bash
git clone https://github.com/furkan3152/Touchmark_agent.git
cd Touchmark_agent
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements-dev.txt
```

## Code style

- Python follows PEP 8. Use `black`, `isort` and `flake8`.
- Rust uses the standard formatting. Run `cargo fmt` before committing; `cargo clippy` should pass without warnings.

## Tests

Run the full suite before opening a pull request:

```bash
./scripts/test.sh
```

It runs the Python tests offline, two end-to-end audits of the example agents, a syntax check of the frontend JavaScript, `cargo fmt`, `cargo clippy`, the contract tests and the WASM build. It needs Node.js and the Rust target above.

## Pull requests

1. Fork the repo and branch from `main`.
2. Add tests for new behaviour and for bug fixes.
3. Update the docs if you change a user-facing API, a CLI command or a contract interface.
4. Make sure `./scripts/test.sh` passes.
5. Open the pull request with the template, describe the change and link the issue it addresses.

A maintainer will review it.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/), which keeps the history readable and lets release notes be generated from it:

- `feat: add evidence verification endpoint`
- `fix: resolve overflow in Soroban contract`
- `docs: update setup instructions in README`
- `chore: update rust dependencies`

## Issues

Search the existing issues first. For a new one, use the `Bug report` or `Feature request` template, and for bugs include your environment and the steps to reproduce.
