"""Reader for BLE link-layer captures — classic PCAP and PCAPNG.

Containers:
* **classic PCAP** (magic 0xa1b2c3d4): a 24-byte global header, then per-packet
  records.
* **PCAPNG** (magic 0x0a0d0d0a): the format Wireshark / nrfutil write by default.
  Parsed via its block structure (Section Header, Interface Description, Enhanced
  Packet blocks).

Link types (DLT), dispatched per interface:
* **272 — NORDIC_BLE**: the nRF Sniffer format. A variable-length Nordic
  pseudo-header (channel at byte 9, RSSI magnitude at byte 10, BLE-header length
  at byte 7) precedes the air packet. This layout was verified against real nRF
  Sniffer captures.
* **256 — BLUETOOTH_LE_LL_WITH_PHDR**: a 10-byte pseudo-header then the LL packet.
* **251 — BLUETOOTH_LE_LL**: the LL packet with no pseudo-header.

Pure stdlib, no scapy. Never raises on a malformed record — truncated or
non-advertising packets are skipped.
"""

from __future__ import annotations

import struct
from pathlib import Path

from blestitch.dissect.pdu import extract_tx_power, parse_ad_structures, parse_pdu_header
from blestitch.io.labeled_trace import LabeledTrace
from blestitch.records import Packet, classify_address

DLT_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_NORDIC_BLE = 272
_SUPPORTED_DLT = (DLT_BLUETOOTH_LE_LL, DLT_BLUETOOTH_LE_LL_WITH_PHDR, DLT_NORDIC_BLE)

_PCAP_MAGIC_LE = 0xA1B2C3D4
_PCAP_MAGIC_BE = 0xD4C3B2A1
_PCAP_MAGIC_NS_LE = 0xA1B23C4D
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapFormatError(ValueError):
    """Raised when the file is not a capture container we understand."""


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


def read_pcap(path: str | Path) -> LabeledTrace:
    """Read a BLE PCAP/PCAPNG file into a blind :class:`LabeledTrace`."""
    data = Path(path).read_bytes()
    src = f"pcap:{Path(path).name}"
    return LabeledTrace(packets=list(iter_packets(data, source=src)), source=src)


def iter_packets(data: bytes, *, source: str = "pcap"):
    """Parse raw capture bytes, yielding :class:`Packet` for each adv PDU.

    Dispatches on the container magic: PCAPNG, or classic PCAP.
    """
    if len(data) < 4:
        raise PcapFormatError("file too short")
    if data[:4] == _PCAPNG_MAGIC:
        yield from _iter_pcapng(data, source)
        return

    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE):
        endian, ts_is_ns = "<", magic == _PCAP_MAGIC_NS_LE
    elif magic == _PCAP_MAGIC_BE:
        endian, ts_is_ns = ">", False
    else:
        raise PcapFormatError(f"unrecognized capture magic 0x{magic:08x}")
    yield from _iter_classic(data, source, endian, ts_is_ns)


# --------------------------------------------------------------------------- #
# classic PCAP
# --------------------------------------------------------------------------- #
def _iter_classic(data: bytes, source: str, endian: str, ts_is_ns: bool):
    if len(data) < 24:
        raise PcapFormatError("file shorter than a PCAP global header")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype not in _SUPPORTED_DLT:
        raise PcapFormatError(f"unsupported link type {linktype}; expected 251/256/272")

    rec_hdr = struct.Struct(endian + "IIII")
    off, n = 24, len(data)
    while off + rec_hdr.size <= n:
        ts_a, ts_b, incl_len, _orig = rec_hdr.unpack_from(data, off)
        off += rec_hdr.size
        if off + incl_len > n:
            break
        body = data[off : off + incl_len]
        off += incl_len
        t_hw_us = ts_a * 1_000_000 + (ts_b // 1000 if ts_is_ns else ts_b)
        pkt = _parse_by_linktype(linktype, body, t_hw_us, source)
        if pkt is not None:
            yield pkt


# --------------------------------------------------------------------------- #
# PCAPNG
# --------------------------------------------------------------------------- #
def _iter_pcapng(data: bytes, source: str):
    # Section Header Block carries the byte-order magic at offset 8.
    if len(data) < 12:
        raise PcapFormatError("truncated PCAPNG")
    bom = struct.unpack_from("<I", data, 8)[0]
    endian = "<" if bom == 0x1A2B3C4D else ">"

    # interface id -> (linktype, microseconds-per-timestamp-tick)
    interfaces: dict[int, tuple[int, float]] = {}
    iface_count = 0
    off, n = 0, len(data)
    while off + 12 <= n:
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8 : off + blen - 4]

        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces[iface_count] = (linktype, _tsresol_us(body[8:], endian))
            iface_count += 1
        elif btype in (0x00000006, 0x00000003):  # Enhanced / Simple Packet Block
            pkt = _pcapng_packet(btype, body, endian, interfaces, source)
            if pkt is not None:
                yield pkt
        off += blen


def _tsresol_us(opts: bytes, endian: str) -> float:
    """Return microseconds per timestamp tick from an IDB's if_tsresol option.

    Default resolution is 1e-6 s (microseconds) when the option is absent.
    """
    i, n = 0, len(opts)
    while i + 4 <= n:
        code, ln = struct.unpack_from(endian + "HH", opts, i)
        if code == 0:  # opt_endofopt
            break
        if code == 9 and ln >= 1:  # if_tsresol
            val = opts[i + 4]
            if val & 0x80:  # 2^-(val & 0x7f) seconds per tick
                return (2.0 ** -(val & 0x7F)) * 1e6
            return (10.0 ** -val) * 1e6  # 10^-val seconds per tick
        i += 4 + ((ln + 3) & ~3)  # options are padded to 4 bytes
    return 1.0  # 1e-6 s -> 1 microsecond per tick


def _pcapng_packet(btype, body, endian, interfaces, source):
    if btype == 0x00000006:  # Enhanced Packet Block
        ifid, ts_hi, ts_lo, caplen = struct.unpack_from(endian + "IIII", body, 0)
        pdata = body[20 : 20 + caplen]
        ts = (ts_hi << 32) | ts_lo
    else:  # Simple Packet Block: origlen(4) then data; no timestamp
        ifid, ts = 0, 0
        (origlen,) = struct.unpack_from(endian + "I", body, 0)
        pdata = body[4 : 4 + origlen]

    linktype, us_per_tick = interfaces.get(ifid, (DLT_NORDIC_BLE, 1.0))
    t_hw_us = int(ts * us_per_tick)
    return _parse_by_linktype(linktype, pdata, t_hw_us, source)


# --------------------------------------------------------------------------- #
# per-link-type packet parsing
# --------------------------------------------------------------------------- #
def _parse_by_linktype(linktype, body, t_hw_us, source):
    if linktype == DLT_NORDIC_BLE:
        return _parse_nordic(body, t_hw_us, source)
    if linktype == DLT_BLUETOOTH_LE_LL_WITH_PHDR:
        return _parse_le_ll_phdr(body, t_hw_us, source)
    if linktype == DLT_BLUETOOTH_LE_LL:
        return _parse_ble_ll(body, t_hw_us, 0, 0, source)
    return None


def _parse_le_ll_phdr(body, t_hw_us, source):
    if len(body) < 10 + 4 + 2:
        return None
    return _parse_ble_ll(body[10:], t_hw_us, body[0], _s8(body[1]), source)


def _parse_nordic(body, t_hw_us, source):
    """Parse an nRF Sniffer (NORDIC_BLE) packet.

    Layout (verified against real captures): a 7-byte transport header, then a
    BLE metadata header of ``body[7]`` bytes, then the air packet. Channel is at
    byte 9, RSSI magnitude at byte 10 (actual dBm = -value).
    """
    if len(body) < 11:
        return None
    ble_hdr_len = body[7]
    air_off = 7 + ble_hdr_len
    if air_off + 6 > len(body):
        return None
    channel = body[9]
    rssi = -body[10]
    return _parse_ble_ll(body[air_off:], t_hw_us, channel, rssi, source)


def _parse_ble_ll(ble, t_hw_us, channel, rssi, source):
    if len(ble) < 4 + 2:
        return None
    hdr = parse_pdu_header(ble[4], ble[5])
    payload = ble[6 : 6 + hdr.length]
    if not hdr.has_adva or len(payload) < 6:
        return None
    address = int.from_bytes(payload[0:6], "little")
    advdata = payload[6:]
    return Packet(
        t_hw_us=t_hw_us,
        channel=channel,
        rssi=rssi,
        address=address,
        addr_random=hdr.tx_add,
        addr_type=classify_address(address, random=hdr.tx_add),
        pdu_type=hdr.pdu_type,
        chsel=hdr.chsel,
        tx_power=extract_tx_power(advdata),
        ad_structure=parse_ad_structures(advdata),
        payload=advdata,
        source=source,
    )
