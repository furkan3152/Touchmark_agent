#!/usr/bin/env bash
# AgentVeritas development server — UI + API + /docs
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

PY="${ROOT}/.venv/bin/python"
if [[ ! -x "${PY}" ]]; then
  echo "→ .venv not found, creating..."
  python3 -m venv .venv
  PY="${ROOT}/.venv/bin/python"
  "${PY}" -m pip install --quiet --upgrade pip
  "${PY}" -m pip install --quiet -r backend/requirements.txt
fi

if ! "${PY}" -c "import fastapi, uvicorn" 2>/dev/null; then
  echo "→ installing dependencies..."
  "${PY}" -m pip install --quiet -r backend/requirements.txt
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

echo "→ AgentVeritas http://${HOST}:${PORT}  (UI: /  · API: /api/v1  · Docs: /docs)"
exec "${PY}" -m uvicorn backend.app.api:app --host "${HOST}" --port "${PORT}" --reload
