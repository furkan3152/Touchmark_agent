#!/usr/bin/env bash
# AgentVeritas Stellar — verification run with no external writes
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

TEST_DATA_DIR="$(mktemp -d /tmp/agentveritas-stellar-test.XXXXXX)"
cleanup() {
  if [[ -d "${TEST_DATA_DIR}" && "${TEST_DATA_DIR}" == /tmp/agentveritas-stellar-test.* ]]; then
    rm -rf -- "${TEST_DATA_DIR}"
  fi
}
trap cleanup EXIT

PY="${ROOT}/.venv/bin/python"
if [[ ! -x "${PY}" ]]; then
  echo "→ .venv not found, creating..."
  python3 -m venv .venv
  PY="${ROOT}/.venv/bin/python"
  "${PY}" -m pip install --quiet --upgrade pip
  "${PY}" -m pip install --quiet -r backend/requirements-dev.txt
fi

if ! "${PY}" -c "import pytest" 2>/dev/null; then
  echo "→ installing pytest..."
  "${PY}" -m pip install --quiet -r backend/requirements-dev.txt
fi

export STELLAR_NETWORK=offline
export ALLOW_MAINNET=false
export STELLAR_RPC_URL=
export STELLAR_HORIZON_URL=
export AGENT_REGISTRY_CONTRACT_ID=
export AUDIT_ESCROW_CONTRACT_ID=
export SAC_CONTRACT_ID=
export ENABLE_AUDIT_ESCROW=false
export LLM_PROVIDER=
export LLM_API_KEY=
export PINATA_JWT=
export SCREENING_PROVIDER=none
export SCREENING_API_KEY=
export ENABLE_OFAC_SCREENING=false
export ALLOW_LOCAL_PATH_INGEST=true
export DATA_DIR="${TEST_DATA_DIR}"
export EVENT_DATABASE="${TEST_DATA_DIR}/events.db"

echo "=== Python tests (offline) ==="
# Unit tests independently verify ENABLE_OFAC_SCREENING's default and on/off
# states. We remove the variable only from this subprocess;
# since the audit path only reads local cache, it does not initiate network access.
env -u ENABLE_OFAC_SCREENING "${PY}" -m pytest backend/tests -q

echo
echo "=== end-to-end: safe agent ==="
"${PY}" -m backend.cli audit --path ./examples/safe_agent --tier basic

echo
echo "=== end-to-end: vulnerable agent ==="
"${PY}" -m backend.cli audit --path ./examples/vulnerable_agent --tier deep

echo
echo "=== frontend JavaScript ==="
node --check frontend/app.js

echo
echo "=== Soroban format / lint / test / WASM ==="
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --target wasm32v1-none --release

echo
echo "=== network independence ==="
./scripts/verify_independence.sh
