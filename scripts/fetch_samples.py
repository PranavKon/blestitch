#!/usr/bin/env python3
"""Download public BLE sniffer captures into data/ for development.

These are real captures published with the Wireshark project. They are not
committed (data/ is git-ignored); tests that use them skip when absent.

    python scripts/fetch_samples.py
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

SAMPLES = {
    # Real nRF Sniffer capture (pcapng, Nordic DLT 272, protocol version 2):
    # one peripheral advertising, being scanned and then connected to.
    # Attached to Wireshark issue 17808.
    "nrf_sniffer_sterzo.pcapng": (
        "https://gitlab.com/-/project/7898047/uploads/"
        "ac7df8335b967e5f1d5eb735574002ee/sample.pcapng"
    ),
    # Wireshark dissector coverage captures: small, but they exercise every
    # PDU type across link types 251, 256 and 272 (protocol version 3).
    "btle_coverage.pcapng.gz": (
        "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/"
        "btle_coverage.pcapng.gz"
    ),
    "btle_rf_coverage.pcap.gz": (
        "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/"
        "btle_rf_coverage.pcap.gz"
    ),
}


def main() -> int:
    out_dir = Path(__file__).resolve().parent.parent / "data"
    out_dir.mkdir(exist_ok=True)
    failed = 0
    for name, url in SAMPLES.items():
        dest = out_dir / name
        if dest.exists():
            print(f"have     {name}")
            continue
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                dest.write_bytes(resp.read())
            print(f"fetched  {name} ({dest.stat().st_size} bytes)")
        except OSError as exc:
            failed += 1
            print(f"FAILED   {name}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
