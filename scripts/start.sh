#!/usr/bin/env bash
# AgentVeritas — install, verify, start with a single command.
#
# After installation, this is the only answer to the "is it working?" question:
#   1) virtual environment + dependencies
#   2) OFAC sanctions list (free, keyless) is downloaded on user run
#   3) each layer is verified (selftest; does not write to chain)
#   4) UI is opened
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="${ROOT}/.venv/bin/python"

if [[ ! -x "${PY}" ]]; then
  echo "→ creating .venv..."
  python3 -m venv .venv
  "${PY}" -m pip install --quiet --upgrade pip
  "${PY}" -m pip install --quiet -r backend/requirements.txt
elif ! "${PY}" -c "import fastapi, uvicorn" 2>/dev/null; then
  echo "→ installing dependencies..."
  "${PY}" -m pip install --quiet -r backend/requirements.txt
fi

if [[ ! -f .env ]]; then
  echo "→ creating .env (copying .env.example)"
  cp .env.example .env
fi

# The OFAC list does not require a key; if there is no cache, sanction screening is skipped entirely.
if [[ ! -f data/sanctions/ofac-sdn.json ]]; then
  echo "→ downloading OFAC sanctions list (free, keyless)..."
  "${PY}" -m backend.cli sanctions --refresh || echo "  (skipped — no network)"
fi

echo
echo "=== system status ==="
"${PY}" -m backend.cli selftest || true

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo
echo "→ UI:   http://${HOST}:${PORT}/"
echo "→ API:  http://${HOST}:${PORT}/api/v1"
echo "→ Docs: http://${HOST}:${PORT}/docs"
echo
exec "${PY}" -m uvicorn backend.app.api:app --host "${HOST}" --port "${PORT}"
