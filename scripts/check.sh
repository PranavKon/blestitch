#!/usr/bin/env bash
# Everything that should pass before a change is shared: tests, lint, GUI build.
#
#   scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -x .venv/bin/python ] || { echo "check: not set up yet. Run scripts/setup.sh first." >&2; exit 1; }

echo "==> Tests"
.venv/bin/python -m pytest -q
echo "==> Lint"
.venv/bin/python -m ruff check .
echo "==> GUI build"
(cd frontend && npm run build --silent)
echo
echo "All checks passed."
