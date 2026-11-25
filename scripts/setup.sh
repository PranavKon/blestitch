#!/usr/bin/env bash
# One-time setup: Python environment, dependencies, and a built GUI.
#
#   scripts/setup.sh
#
# Safe to run again; it only does what is missing or out of date.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "setup: $*" >&2; exit 1; }

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null || fail "$PYTHON not found. Install Python 3.11 or newer."
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || fail "Python 3.11 or newer is needed; $PYTHON is $("$PYTHON" -c 'import platform; print(platform.python_version())')."

command -v node >/dev/null || fail "node not found. Install Node.js 18 or newer."
[ "$(node -p 'Number(process.versions.node.split(".")[0])')" -ge 18 ] \
  || fail "Node.js 18 or newer is needed; found $(node --version)."

if [ ! -d .venv ]; then
  echo "==> Creating Python environment in .venv"
  "$PYTHON" -m venv .venv
fi
echo "==> Installing Python packages"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -e ".[backend,dev]"

echo "==> Installing GUI packages"
(cd frontend && npm ci --no-audit --no-fund --silent)
echo "==> Building the GUI"
(cd frontend && npm run build --silent)

echo
echo "Ready. Start the app with:  scripts/run.sh"
