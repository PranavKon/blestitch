"""Reader for BLE link-layer captures.

Containers: classic ``.pcap`` and ``.pcapng`` (what Wireshark saves by
default), either optionally gzip-compressed.

Link types a BLE sniffer produces:

* DLT 272 — ``LINKTYPE_NORDIC_BLE``: the nRF Sniffer's own encapsulation. It
  carries the channel, RSSI, a CRC verdict and the sniffer's microsecond
  hardware clock. This is what the project's nRF52840 hardware emits.
* DLT 256 — ``LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR``: a 10-byte pseudo-header
  (RF channel, signal power, flags) followed by the BLE LL packet.

The reader is pure stdlib (no scapy) so the hot path is small and predictable.
It yields normalized :class:`~blestitch.records.Packet` objects and never
raises on a malformed record: truncated tails are skipped and everything that
is skipped is counted in :class:`~blestitch.io.labeled_trace.CaptureStats`.
"""

from __future__ import annotations

import gzip
import struct
from collections.abc import Iterator
from pathlib import Path

from blestitch.dissect.ad import ad_structure, extract_tx_power
from blestitch.dissect.pdu import ADV_ACCESS_ADDRESS, parse_adv_pdu
from blestitch.io.labeled_trace import CaptureStats, LabeledTrace
from blestitch.records import Packet, classify_address

DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_NORDIC_BLE = 272

_LINK_NAMES = {
    DLT_BLUETOOTH_LE_LL_WITH_PHDR: "BLUETOOTH_LE_LL_WITH_PHDR (256)",
    DLT_NORDIC_BLE: "NORDIC_BLE (272)",
}

_PCAP_MAGIC = 0xA1B2C3D4      # microsecond timestamps
_PCAP_MAGIC_NS = 0xA1B23C4D   # nanosecond timestamps
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BOM = 0x1A2B3C4D
_GZIP_MAGIC = b"\x1f\x8b"

# DLT 256 pseudo-header flag bits.
_PHDR_SIGNAL_VALID = 0x0002
_PHDR_CRC_CHECKED = 0x0400
_PHDR_CRC_VALID = 0x0800
_PHDR_PHY_SHIFT = 14

_PHY_CODED = 2  # in both the DLT 256 flags and the Nordic flags

_U32 = 1 << 32


class PcapFormatError(ValueError):
    """Raised when the file is not a capture format we understand."""


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def read_pcap(path: str | Path) -> LabeledTrace:
    """Read a BLE capture file into a blind :class:`LabeledTrace`."""
    source = f"pcap:{Path(path).name}"
    packets, stats = read_capture(Path(path).read_bytes(), source=source)
    return LabeledTrace(packets=packets, source=source, stats=stats)


def read_capture(
    data: bytes, *, source: str = "pcap"
) -> tuple[list[Packet], CaptureStats]:
    """Parse raw capture bytes into packets plus an account of what was skipped."""
    stats = CaptureStats()
    packets = list(_iter_packets(data, source, stats))
    stats.n_packets = len(packets)
    return packets, stats


def iter_packets(data: bytes, *, source: str = "pcap") -> Iterator[Packet]:
    """Parse raw capture bytes, yielding a :class:`Packet` per advertising PDU."""
    return _iter_packets(data, source, CaptureStats())


# --------------------------------------------------------------------------
# Containers: yield (interface, linktype, host_timestamp_us, record_bytes)
# --------------------------------------------------------------------------

_Record = tuple[int, int, int, bytes]


def _iter_records(data: bytes) -> Iterator[_Record]:
    if data[:2] == _GZIP_MAGIC:
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise PcapFormatError(f"corrupt gzip stream: {exc}") from exc
    if len(data) < 24:
        raise PcapFormatError("file shorter than a capture file header")
    magic_le = struct.unpack_from("<I", data, 0)[0]
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_le == _PCAPNG_SHB:
        return _iter_pcapng(data)
    if magic_le in (_PCAP_MAGIC, _PCAP_MAGIC_NS):
        return _iter_pcap(data, "<", magic_le == _PCAP_MAGIC_NS)
    if magic_be in (_PCAP_MAGIC, _PCAP_MAGIC_NS):
        return _iter_pcap(data, ">", magic_be == _PCAP_MAGIC_NS)
    raise PcapFormatError(f"unrecognized capture magic 0x{magic_le:08x}")


def _iter_pcap(data: bytes, endian: str, ts_is_ns: bool) -> Iterator[_Record]:
    linktype = struct.unpack_from(endian + "I", data, 20)[0] & 0x0FFFFFFF
    rec_hdr = struct.Struct(endian + "IIII")
    off, n = 24, len(data)
    while off + rec_hdr.size <= n:
        ts_a, ts_b, incl_len, _orig_len = rec_hdr.unpack_from(data, off)
        off += rec_hdr.size
        if off + incl_len > n:
            break  # truncated final record
        ts_us = ts_a * 1_000_000 + (ts_b // 1000 if ts_is_ns else ts_b)
        yield 0, linktype, ts_us, data[off : off + incl_len]
        off += incl_len


def _iter_pcapng(data: bytes) -> Iterator[_Record]:
    endian = "<"
    # Per interface: (linktype, timestamp units per second, offset in seconds).
    ifaces: list[tuple[int, int, int]] = []
    section = -1
    off, n = 0, len(data)
    while off + 12 <= n:
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == _PCAPNG_SHB:
            bom = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bom == _PCAPNG_BOM else ">"
            ifaces = []
            section += 1
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or blen % 4 or off + blen > n:
            break  # truncated or corrupt block
        body = data[off + 8 : off + blen - 4]
        off += blen

        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            ifaces.append((linktype, *_idb_time_options(body[8:], endian)))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap_len = struct.unpack_from(endian + "IIII", body, 0)
            if iface < len(ifaces) and 20 + cap_len <= len(body):
                linktype, units, offset_s = ifaces[iface]
                ts = (ts_hi << 32) | ts_lo
                ts_us = ts * 1_000_000 // units + offset_s * 1_000_000
                yield (section << 16) | iface, linktype, ts_us, body[20 : 20 + cap_len]
        # Simple Packet Blocks carry no timestamp and are of no use here.


def _idb_time_options(opts: bytes, endian: str) -> tuple[int, int]:
    """Return (timestamp units per second, offset seconds) from IDB options."""
    units, offset_s = 1_000_000, 0
    i = 0
    while i + 4 <= len(opts):
        code, length = struct.unpack_from(endian + "HH", opts, i)
        value = opts[i + 4 : i + 4 + length]
        i += 4 + ((length + 3) & ~3)
        if code == 0:
            break
        if code == 9 and len(value) >= 1:  # if_tsresol
            exp = value[0] & 0x7F
            units = (1 << exp) if value[0] & 0x80 else 10**exp
        elif code == 14 and len(value) >= 8:  # if_tsoffset
            offset_s = struct.unpack_from(endian + "q", value, 0)[0]
    return units, offset_s


# --------------------------------------------------------------------------
# Link layers
# --------------------------------------------------------------------------


def _iter_packets(data: bytes, source: str, stats: CaptureStats) -> Iterator[Packet]:
    clocks: dict[int, _NordicClock] = {}
    seen_links: set[int] = set()
    used_firmware_clock = False

    for iface, linktype, ts_us, body in _iter_records(data):
        stats.n_records += 1
        if linktype == DLT_NORDIC_BLE:
            clock = clocks.setdefault(iface, _NordicClock())
            pkt = _parse_nordic(body, ts_us, clock, source, stats)
            used_firmware_clock = True
        elif linktype == DLT_BLUETOOTH_LE_LL_WITH_PHDR:
            pkt = _parse_le_ll_phdr(body, ts_us, source, stats)
        else:
            stats.n_unsupported_link += 1
            continue
        if linktype not in seen_links:
            seen_links.add(linktype)
            stats.link_types.append(_LINK_NAMES[linktype])
            stats.time_source = "firmware" if used_firmware_clock else "capture"
        if pkt is not None:
            yield pkt

    if not seen_links and stats.n_unsupported_link:
        raise PcapFormatError(
            "no BLE link-layer records; expected link type 256 or 272"
        )


# RF channel number (frequency order) -> BLE channel index.
def _rf_to_index(rf: int) -> int:
    if rf == 0:
        return 37
    if rf == 12:
        return 38
    if rf == 39:
        return 39
    return rf - 1 if rf < 12 else rf - 2


def _parse_le_ll_phdr(
    body: bytes, ts_us: int, source: str, stats: CaptureStats
) -> Packet | None:
    if len(body) < 10 + 4 + 2:
        stats.n_malformed += 1
        return None
    flags = body[8] | (body[9] << 8)
    if flags & _PHDR_CRC_CHECKED and not flags & _PHDR_CRC_VALID:
        stats.n_bad_crc += 1
        return None
    rssi = _s8(body[1]) if flags & _PHDR_SIGNAL_VALID else None
    coded = (flags >> _PHDR_PHY_SHIFT) == _PHY_CODED
    return _parse_ble_ll(
        body[10:], ts_us, _rf_to_index(body[0]), rssi, source, stats, coded=coded
    )


class _NordicClock:
    """Rebuilds a continuous microsecond timeline from nRF Sniffer records.

    The sniffer's own clock is far more precise than the host timestamps in
    the capture file (which carry USB/OS jitter of milliseconds), so packet
    times are taken from it and only *anchored* to host time:

    * protocol version 3 reports an absolute 32-bit firmware timestamp, which
      wraps every ~71.6 minutes and is unwrapped against host time;
    * versions 1-2 report the gap from the end of the previous packet to the
      start of this one, which is accumulated. The 16-bit packet counter
      reveals a lost record, in which case that one step falls back to the
      host-time gap.
    """

    __slots__ = ("fw0", "host0", "prev_counter", "prev_end", "prev_host", "prev_start")

    def __init__(self) -> None:
        self.host0: int | None = None
        self.fw0 = 0
        self.prev_start = 0
        self.prev_end = 0
        self.prev_host = 0
        self.prev_counter = -1

    def stamp(
        self, protover: int, counter: int, time_field: int, host_us: int, airtime_us: int
    ) -> int:
        if self.host0 is None:
            self.host0, self.fw0 = host_us, time_field
            t = host_us
        elif protover >= 3:
            raw = (time_field - self.fw0) % _U32
            wraps = max(0, round((host_us - self.host0 - raw) / _U32))
            t = self.host0 + raw + wraps * _U32
        elif counter == (self.prev_counter + 1) & 0xFFFF:
            t = self.prev_end + time_field
        else:  # a record is missing: this delta is relative to a packet we lack
            t = max(self.prev_end, self.prev_start + host_us - self.prev_host)
        self.prev_start, self.prev_end = t, t + airtime_us
        self.prev_host, self.prev_counter = host_us, counter
        return t


def _airtime_us(ll_len: int, phy: int) -> int:
    """On-air duration of an LL packet of `ll_len` bytes (AA..CRC)."""
    if phy == 1:  # 2M: 2-byte preamble, 4 us per byte
        return 4 * (2 + ll_len)
    if phy == _PHY_CODED:  # assuming S=8: FEC block 1 + payload + TERM2
        return 376 + 64 * max(0, ll_len - 5) + 24
    return 8 * (1 + ll_len)  # 1M: 1-byte preamble, 8 us per byte


def _parse_nordic(
    body: bytes, host_us: int, clock: _NordicClock, source: str, stats: CaptureStats
) -> Packet | None:
    """nRF Sniffer record: board id, 6-byte UART header, 10-byte event header,
    then the LL packet. Layout per the nRF Sniffer packet format (header
    versions 1-3); the legacy 0xBEEF-marked format is not supported.

        [0] board id   [1:3] payload length   [3] protocol version
        [4:6] packet counter   [6] packet id
        [7] event header length   [8] flags   [9] channel   [10] RSSI (negated)
        [11:13] event counter   [13:17] firmware timestamp / delta (us)
        [17:] access address, PDU header, payload, CRC
    """
    if len(body) < 17 + 6 or body[0:2] == b"\xbe\xef":
        stats.n_malformed += 1
        return None
    protover = body[3]
    counter = body[4] | (body[5] << 8)
    flags, channel = body[8], body[9]
    time_field = struct.unpack_from("<I", body, 13)[0]
    ble = body[17:]

    phy = (flags >> 4) & 0x7

    # Every record advances the clock, including ones we go on to discard.
    t_us = clock.stamp(protover, counter, time_field, host_us, _airtime_us(len(ble), phy))
    if not flags & 0x01:
        stats.n_bad_crc += 1
        return None
    return _parse_ble_ll(
        ble, t_us, channel, -body[10], source, stats, coded=phy == _PHY_CODED
    )


def _parse_ble_ll(
    ble: bytes,
    t_us: int,
    channel: int,
    rssi: int | None,
    source: str,
    stats: CaptureStats,
    *,
    coded: bool = False,
) -> Packet | None:
    """`ble` is access address (4) + PDU header (2) + payload [+ CRC]. On the
    Coded PHY a 1-byte coding indicator sits between the access address and
    the PDU header."""
    pdu_at = 5 if coded else 4
    if len(ble) < pdu_at + 2:
        stats.n_malformed += 1
        return None
    if int.from_bytes(ble[0:4], "little") != ADV_ACCESS_ADDRESS:
        stats.n_data_channel += 1
        return None
    pdu = parse_adv_pdu(ble[pdu_at:])
    if pdu is None:
        stats.n_malformed += 1
        return None
    if pdu.adv_a is None:
        if pdu.header.pdu_type in (0x7, 0x8):
            stats.n_unattributed += 1
        else:
            stats.n_malformed += 1
        return None
    tx_power = pdu.tx_power if pdu.tx_power is not None else extract_tx_power(pdu.data)
    return Packet(
        t_hw_us=t_us,
        channel=channel,
        rssi=rssi,
        address=pdu.adv_a,
        addr_random=pdu.adv_random,
        addr_type=classify_address(pdu.adv_a, random=pdu.adv_random),
        pdu_type=pdu.header.pdu_type,
        chsel=pdu.header.chsel,
        tx_power=tx_power,
        ad_structure=ad_structure(pdu.data),
        payload=pdu.data,
        source=source,
        peer_address=pdu.peer_a,
        peer_random=pdu.peer_random,
        ext_sid=pdu.sid,
        ext_did=pdu.did,
    )
