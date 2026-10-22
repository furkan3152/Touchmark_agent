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

### Code Style

We enforce strict coding standards to keep our codebase clean and maintainable.

## Tests

Run the full suite before opening a pull request:

```bash
./scripts/test.sh
```

Ensure you have a local Stellar quickstart node running if you are running integration tests.

## Pull Request Process

A maintainer will review it.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/), which keeps the history readable and lets release notes be generated from it:

Examples:
- `feat: add evidence verification endpoint`
- `fix: resolve overflow in Soroban contract`
- `docs: update setup instructions in README`
- `chore: update rust dependencies`

## Issues

Search the existing issues first. For a new one, use the `Bug report` or `Feature request` template, and for bugs include your environment and the steps to reproduce.
