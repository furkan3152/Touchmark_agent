# Contributing to AgentVeritas Stellar

First off, thank you for considering contributing to AgentVeritas Stellar! It's people like you that make this an excellent evidence-first verification and audit system for AI agents on the Stellar network.

## Getting Started

### Development Environment Setup

To contribute to AgentVeritas Stellar, you will need the following tools installed:

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

- **Python**: We adhere to PEP 8 guidelines. Please use `black` for formatting, `isort` for import sorting, and `flake8` for linting.
- **Rust**: Use standard Rust formatting. Run `cargo fmt` before committing, and ensure `cargo clippy` passes without warnings.

### Running Tests

Before submitting a pull request, ensure all tests pass. We provide a convenient script to run the full test suite across both Python and Rust environments:

```bash
./scripts/test.sh
```

Ensure you have a local Stellar quickstart node running if you are running integration tests.

## Pull Request Process

1. **Fork the repo** and create your branch from `main`.
2. **Write clear code** and add tests for any new functionality or bug fixes.
3. **Update documentation** if you are changing user-facing APIs, CLI commands, or smart contract interfaces.
4. **Run the test suite** (`./scripts/test.sh`) and ensure it passes.
5. **Open a Pull Request** using the provided PR template. Describe your changes in detail and link to any relevant issues.
6. A maintainer will review your PR. Please be responsive to feedback.

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/). This helps us automate release notes and maintain a clean history.

Examples:
- `feat: add evidence verification endpoint`
- `fix: resolve overflow in Soroban contract`
- `docs: update setup instructions in README`
- `chore: update rust dependencies`

## Reporting Issues

If you find a bug or have a feature request, please search the existing issues first. If your issue is new, open one using the appropriate issue template (`Bug report` or `Feature request`). Provide as much context as possible, including environment details and steps to reproduce for bugs.
