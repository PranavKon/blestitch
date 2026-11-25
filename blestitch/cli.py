"""Command-line use: stitch a capture and print the device trails.

    blestitch capture.pcapng
    blestitch capture.pcapng --json result.json

The same analysis the GUI shows, as a table in the terminal, with the full
result optionally written out as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from blestitch.dissect.epoch import DEFAULT_MAX_GAP_US
from blestitch.io.pcap_reader import PcapFormatError
from blestitch.pipeline import analyze_bytes
from blestitch.results.artifact import AnalysisResult

_TYPE_NAMES = {
    "resolvable": "RPA",
    "nrpa": "NRPA",
    "static": "static",
    "public": "public",
    "unknown": "reserved",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blestitch",
        description="Stitch a BLE sniffer capture into per-device trails.",
    )
    parser.add_argument("capture", type=Path, help="a .pcap or .pcapng capture (may be gzipped)")
    parser.add_argument("--json", type=Path, metavar="FILE", help="also write the full result as JSON")
    parser.add_argument(
        "--max-gap",
        type=float,
        default=DEFAULT_MAX_GAP_US / 1e6,
        metavar="SECONDS",
        help="silence that splits one address into two epochs (default: %(default)g)",
    )
    args = parser.parse_args(argv)

    try:
        data = args.capture.read_bytes()
    except OSError as exc:
        print(f"blestitch: cannot read {args.capture}: {exc.strerror}", file=sys.stderr)
        return 1
    try:
        result = analyze_bytes(
            data, source=f"pcap:{args.capture.name}", max_gap_us=int(args.max_gap * 1e6)
        ).result
    except PcapFormatError as exc:
        print(f"blestitch: {args.capture} is not a capture this can read: {exc}", file=sys.stderr)
        return 1

    print(format_report(result, args.capture.name))
    if args.json:
        args.json.write_text(json.dumps(result.to_dict(), indent=2))
        print(f"\nFull result written to {args.json}")
    return 0


def format_report(result: AnalysisResult, name: str) -> str:
    c = result.capture
    lines = [
        (
            f"{name}: {_duration(result.t_max_us - result.t_min_us)}, "
            f"{c.n_records:,} records, {', '.join(c.link_types) or 'no BLE link type'}"
        ),
    ]
    unused = [
        (c.n_bad_crc, "failed CRC"),
        (c.n_data_channel, "connection-data"),
        (c.n_unattributed, "extended adverts without an address"),
        (c.n_malformed, "malformed"),
        (c.n_unsupported_link, "on other link types"),
    ]
    if any(n for n, _ in unused):
        lines.append("Not used: " + ", ".join(f"{n:,} {what}" for n, what in unused if n))

    rotations = [link for link in result.links if link.kind == "rotation"]
    ambiguous = sum(link.ambiguous for link in rotations)
    lines.append(
        f"{_count(result.n_devices, 'device')} (estimated) · "
        f"{_count(len(result.tracks), 'trail')} · "
        f"{_count(result.n_epochs, 'address epoch')} · "
        f"{_count(len(rotations), 'rotation')} linked"
        + (f" ({ambiguous} ambiguous)" if ambiguous else "")
    )
    if not result.tracks:
        return "\n".join(lines)

    rows = [("TRAIL", "TYPE", "ADDRS", "FIRST SEEN", "SPAN", "PACKETS", "WEAKEST LINK", "IDENTITY")]
    for t in result.tracks:
        if t.min_score is None:
            weakest = "-"
        else:
            weakest = f"{t.min_score:.2f}" + (" ambiguous" if t.ambiguous else "")
        rows.append((
            t.name,
            _TYPE_NAMES.get(t.addr_type, t.addr_type),
            str(t.n_addresses),
            _offset(t.t_start_us - result.t_min_us),
            _duration(t.t_end_us - t.t_start_us),
            f"{t.n_packets:,}",
            weakest,
            t.label or "-",
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]) - 1)]
    right = {2, 5}  # numeric columns
    lines.append("")
    for r in rows:
        cells = [
            r[i].rjust(w) if i in right else r[i].ljust(w) for i, w in enumerate(widths)
        ]
        lines.append("  ".join(cells + [r[-1]]).rstrip())
    lines.append("")
    lines.append(
        "Weakest link is the matcher's score for a trail's least certain rotation "
        "(0.5 = accept line). It ranks links; it is not a probability."
    )
    return "\n".join(lines)


def _count(n: int, noun: str) -> str:
    return f"{n:,} {noun}" + ("" if n == 1 else "s")


def _duration(us: int) -> str:
    s = us / 1e6
    if s < 60:
        return f"{s:.1f} s"
    whole = round(s)
    if whole < 3600:
        return f"{whole // 60} min {whole % 60} s"
    return f"{whole // 3600} h {whole % 3600 // 60} min"


def _offset(us: int) -> str:
    s = round(us / 1e6)
    return f"+{s // 60}:{s % 60:02d}"
