"""Reader for BLE link-layer PCAP captures.

Supports the two link types a BLE sniffer produces:

* DLT 256 — ``LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR``: a 10-byte pseudo-header
  (RF channel, signal power, flags, reference access address) followed by the
  BLE LL packet (access address + PDU + CRC). This is the format the plan
  targets and what this reader is tested against.
* DLT 272 — ``LINKTYPE_NORDIC_BLE``: Nordic's own encapsulation, which also
  carries a microsecond event timestamp. Parsed best-effort; it will be
  validated against real nRF Sniffer captures once the hardware arrives.

The reader is pure stdlib (no scapy) so the hot path is small and predictable.
It yields normalized :class:`~blestitch.records.Packet` objects and never
raises on a malformed record — truncated tails are skipped, because real
captures contain partial packets at the snaplen boundary.
"""

from __future__ import annotations

import struct
from pathlib import Path

from blestitch.dissect.pdu import extract_tx_power, parse_ad_structures, parse_pdu_header
from blestitch.io.labeled_trace import LabeledTrace
from blestitch.records import Packet, classify_address

DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_NORDIC_BLE = 272

_PCAP_MAGIC_LE = 0xA1B2C3D4  # microsecond, little-endian host order
_PCAP_MAGIC_BE = 0xD4C3B2A1
_PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond-resolution variant


class PcapFormatError(ValueError):
    """Raised when the file is not a classic PCAP we understand."""


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


def read_pcap(path: str | Path) -> LabeledTrace:
    """Read a BLE PCAP file into a blind :class:`LabeledTrace`."""
    data = Path(path).read_bytes()
    packets = list(iter_packets(data, source=f"pcap:{Path(path).name}"))
    return LabeledTrace(packets=packets, source=f"pcap:{Path(path).name}")


def iter_packets(data: bytes, *, source: str = "pcap"):
    """Parse raw PCAP bytes, yielding :class:`Packet` for each BLE adv PDU."""
    if len(data) < 24:
        raise PcapFormatError("file shorter than a PCAP global header")

    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE):
        endian = "<"
        ts_is_ns = magic == _PCAP_MAGIC_NS_LE
    elif magic == _PCAP_MAGIC_BE:
        endian = ">"
        ts_is_ns = False
    else:
        raise PcapFormatError(f"unrecognized PCAP magic 0x{magic:08x}")

    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype not in (DLT_BLUETOOTH_LE_LL_WITH_PHDR, DLT_NORDIC_BLE):
        raise PcapFormatError(
            f"unsupported link type {linktype}; expected 256 or 272"
        )

    rec_hdr = struct.Struct(endian + "IIII")
    off = 24
    n = len(data)
    while off + rec_hdr.size <= n:
        ts_a, ts_b, incl_len, _orig_len = rec_hdr.unpack_from(data, off)
        off += rec_hdr.size
        if off + incl_len > n:
            break  # truncated final record
        body = data[off : off + incl_len]
        off += incl_len

        t_hw_us = ts_a * 1_000_000 + (ts_b // 1000 if ts_is_ns else ts_b)

        if linktype == DLT_BLUETOOTH_LE_LL_WITH_PHDR:
            pkt = _parse_le_ll_phdr(body, t_hw_us, endian, source)
        else:
            pkt = _parse_nordic(body, t_hw_us, source)
        if pkt is not None:
            yield pkt


def _parse_le_ll_phdr(
    body: bytes, t_hw_us: int, endian: str, source: str
) -> Packet | None:
    if len(body) < 10 + 4 + 2:
        return None
    channel = body[0]
    rssi = _s8(body[1])
    ble = body[10:]
    return _parse_ble_ll(ble, t_hw_us, channel, rssi, source)


def _parse_nordic(body: bytes, t_hw_us: int, source: str) -> Packet | None:
    # Nordic BLE pseudo-header (nRF Sniffer): header_len at byte 1, then a
    # payload whose fixed fields include flags, channel, RSSI and a 32-bit
    # microsecond event timestamp. Layout has varied across sniffer versions,
    # so we parse defensively and fall back to the record timestamp.
    if len(body) < 2:
        return None
    header_len = body[1]
    if header_len < 6 or len(body) < header_len + 6:
        return None
    # Common v3 layout: [id, hlen, plen(2), protover, pktcount(2), id2,
    #   flags, channel, rssi, event_counter(2), timestamp_us(4)] then BLE LL.
    try:
        channel = body[7]
        rssi = -_s8(body[8]) if body[8] else 0
        ts_us = struct.unpack_from("<I", body, header_len - 4)[0]
        if ts_us:
            t_hw_us = ts_us
    except (IndexError, struct.error):
        channel, rssi = 0, 0
    ble = body[header_len:]
    return _parse_ble_ll(ble, t_hw_us, channel, rssi, source)


def _parse_ble_ll(
    ble: bytes, t_hw_us: int, channel: int, rssi: int, source: str
) -> Packet | None:
    if len(ble) < 4 + 2:
        return None
    b0, b1 = ble[4], ble[5]
    hdr = parse_pdu_header(b0, b1)
    payload = ble[6 : 6 + hdr.length]
    if not hdr.has_adva or len(payload) < 6:
        return None
    address = int.from_bytes(payload[0:6], "little")
    advdata = payload[6:]
    addr_random = hdr.tx_add
    return Packet(
        t_hw_us=t_hw_us,
        channel=channel,
        rssi=rssi,
        address=address,
        addr_random=addr_random,
        addr_type=classify_address(address, random=addr_random),
        pdu_type=hdr.pdu_type,
        chsel=hdr.chsel,
        tx_power=extract_tx_power(advdata),
        ad_structure=parse_ad_structures(advdata),
        payload=advdata,
        source=source,
    )
