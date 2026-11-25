#!/usr/bin/env bash
# For working on the code: backend and GUI with live reload.
#
#   scripts/dev.sh     # open http://localhost:5173
#
# Python changes restart the backend; GUI changes appear in the browser as
# you save. Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -x .venv/bin/python ] || { echo "dev: not set up yet. Run scripts/setup.sh first." >&2; exit 1; }

.venv/bin/python -m uvicorn backend.app:app --reload --port 8000 --log-level warning &
BACKEND=$!
trap 'kill "$BACKEND" 2>/dev/null || true' EXIT

echo "==> Backend on http://localhost:8000, GUI on http://localhost:5173  (Ctrl+C to stop)"
cd frontend
npm run dev
