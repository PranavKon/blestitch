#!/usr/bin/env bash
# Start blestitch and open it in the browser.
#
#   scripts/run.sh            # http://localhost:8000
#   PORT=9000 scripts/run.sh  # another port
#   NO_BROWSER=1 scripts/run.sh
#
# One process serves both the GUI and the API. Stop it with Ctrl+C.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8000}"
URL="http://localhost:$PORT"

[ -x .venv/bin/python ] || { echo "run: not set up yet. Run scripts/setup.sh first." >&2; exit 1; }

# Rebuild the GUI if it has never been built or its source has changed since.
if [ ! -f frontend/dist/index.html ] ||
   [ -n "$(find frontend/src frontend/index.html frontend/package.json -newer frontend/dist/index.html -print -quit)" ]; then
  echo "==> Building the GUI"
  (cd frontend && npm run build --silent)
fi

# Open the browser once the server answers.
if [ -z "${NO_BROWSER:-}" ]; then
  (
    for _ in $(seq 1 50); do
      if curl -fsS -o /dev/null "$URL/api/health" 2>/dev/null; then
        if command -v open >/dev/null; then open "$URL"
        elif command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1
        fi
        break
      fi
      sleep 0.2
    done
  ) &
fi

echo "==> blestitch is at $URL  (Ctrl+C to stop)"
exec .venv/bin/python -m uvicorn backend.app:app --port "$PORT" --log-level warning
