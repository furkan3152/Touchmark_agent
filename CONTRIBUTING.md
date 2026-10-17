# Contributing to Touchmark Stellar

Thanks for taking a look. Bug reports, fixes and new checks are all welcome.

## Setup

You need:

To contribute to Touchmark Stellar, you will need the following tools installed:

- **Python 3.10+**: Used for the backend and API services.
- **Rust (latest stable)**: Required for writing and compiling Soroban smart contracts.
- **Soroban CLI**: Essential for deploying and interacting with contracts on the Stellar network.
- **Docker**: For running local test environments and databases.

Clone the repository and set up your virtual environment:

```bash
git clone https://github.com/your-org/agentveritas-stellar.git
cd agentveritas-stellar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
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
