#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"
OTHER="${AGENTVERITAS_ARC_PATH:-../agentveritas-arc}"

if find backend frontend contracts scripts -type l -print -quit | grep -q .; then
  echo "ERROR: symlink found in the source tree"
  exit 1
fi

if grep -RIlE \
  'ARC_NETWORK|backend\.app\.chain|eth_account|from web3|import web3|/agentveritas-arc|/Masaüstü/arc' \
  backend frontend contracts scripts README.md .env.example deployments Cargo.toml \
  --exclude='verify_independence.sh' --exclude='*.pyc' --exclude-dir='__pycache__' \
  --exclude-dir='.pytest_cache' >/dev/null; then
  echo "ERROR: Arc/EVM runtime dependency found in Stellar sources"
  exit 1
fi

if [[ -d "${OTHER}" ]]; then
  STELLAR_INODES="$(mktemp /tmp/agentveritas-stellar-inodes.XXXXXX)"
  OTHER_INODES="$(mktemp /tmp/agentveritas-other-inodes.XXXXXX)"
  trap 'rm -f -- "${STELLAR_INODES}" "${OTHER_INODES}"' EXIT
  find "${ROOT}" \( -path '*/.venv' -o -path '*/target' -o -path '*/.pytest_cache' -o -path '*/__pycache__' -o -path '*/data' \) -prune -o -type f -printf '%D:%i\n' | sort -u >"${STELLAR_INODES}"
  find "${OTHER}" \( -path '*/.venv' -o -path '*/target' -o -path '*/.pytest_cache' -o -path '*/__pycache__' -o -path '*/data' \) -prune -o -type f -printf '%D:%i\n' | sort -u >"${OTHER_INODES}"
  if comm -12 "${STELLAR_INODES}" "${OTHER_INODES}" | grep -q .; then
    echo "ERROR: shared inode/hardlink found between the two projects"
    exit 1
  fi
fi

echo "OK: Stellar source line is independent; no cross import/env, source symlinks, or hardlinks"
