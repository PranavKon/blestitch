#!/usr/bin/env bash
# Record a capture from an nRF Sniffer dongle straight to a file in data/.
#
#   scripts/capture.sh                  # data/capture-<date>-<time>.pcap
#   scripts/capture.sh kitchen-test     # data/kitchen-test.pcap
#   PORT=/dev/tty.usbmodem1203 scripts/capture.sh
#
# Runs until you press Ctrl+C. On macOS the computer is kept awake for the
# duration: a Mac that goes to sleep cuts power to the dongle and ends the
# capture, typically after about five idle minutes.
#
# Needs Nordic's nrfutil with the ble-sniffer command, and a dongle already
# flashed with the sniffer firmware (see "Recording a capture" in README.md).
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "capture: $*" >&2; exit 1; }

command -v nrfutil >/dev/null \
  || fail "nrfutil not found. Install it, then run: nrfutil install ble-sniffer device"

if [ -z "${PORT:-}" ]; then
  shopt -s nullglob
  ports=(/dev/tty.usbmodem* /dev/ttyACM*)
  shopt -u nullglob
  case "${#ports[@]}" in
    0) fail "no sniffer found. Plug in the dongle, or set PORT=/dev/... yourself." ;;
    1) PORT="${ports[0]}" ;;
    *) fail "several serial devices found (${ports[*]}). Pick one: PORT=/dev/... scripts/capture.sh" ;;
  esac
fi

mkdir -p data
OUT="data/${1:-capture-$(date +%Y%m%d-%H%M%S)}.pcap"
[ ! -e "$OUT" ] || fail "$OUT already exists. Choose another name."

KEEP_AWAKE=()
if command -v caffeinate >/dev/null; then
  KEEP_AWAKE=(caffeinate -dims)
fi

echo "==> Recording from $PORT to $OUT"
echo "    Leave this running. Press Ctrl+C to stop."
START=$(date +%s)
# Ctrl+C goes to nrfutil, which ends the capture; this script then reports.
trap ':' INT
${KEEP_AWAKE[@]+"${KEEP_AWAKE[@]}"} nrfutil ble-sniffer sniff --port "$PORT" --output-pcap-file "$OUT" || true
trap - INT

[ -s "$OUT" ] || fail "nothing was recorded. Check the dongle and the port ($PORT)."
ELAPSED=$(( $(date +%s) - START ))
echo
echo "==> Saved $OUT ($(( ELAPSED / 60 )) min $(( ELAPSED % 60 )) s)"
echo "    Summary:  .venv/bin/blestitch $OUT"
echo "    Or drop the file onto the app:  scripts/run.sh"
