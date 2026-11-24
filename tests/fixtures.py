"""Build tiny in-memory BLE captures for testing.

These are *test fixtures*, not a traffic simulator: hand-crafted records in
the exact byte layouts the reader accepts (classic pcap and pcapng containers,
DLT 256 and Nordic DLT 272 link layers), so the engine can be exercised
without hardware. The Nordic layout here was checked against a real nRF
Sniffer capture.
"""

from __future__ import annotations

import random
import struct

ADV_ACCESS_ADDRESS = 0x8E89BED6

# Advertising address examples. Random (TxAdd=1) addresses with top two bits 01
# are Resolvable Private Addresses.
ADDR_A1 = 0x7A1122334455  # device A, epoch 1 (resolvable)
ADDR_A2 = 0x6BAABBCCDDEE  # device A, epoch 2 (resolvable)
ADDR_B1 = 0x551020304050  # device B (resolvable)
ADDR_PUB = 0x00AABBCCDDEE  # a public-address device
ADDR_SCANNER = 0x4C0102030405  # some phone doing an active scan

# AD payloads: flags + TX power (-12 dBm) + Apple manufacturer data.
ADV_DATA_A = bytes([0x02, 0x01, 0x06, 0x02, 0x0A, 0xF4, 0x05, 0xFF, 0x4C, 0x00, 0x01, 0x02])
ADV_DATA_B = bytes([0x02, 0x01, 0x06, 0x03, 0x09, 0x42, 0x42])  # name "BB"
ADV_DATA_PUB = bytes([0x02, 0x01, 0x04])

ADV_IND = 0x0
ADV_DIRECT_IND = 0x1
ADV_NONCONN_IND = 0x2
SCAN_REQ = 0x3
SCAN_RSP = 0x4
CONNECT_IND = 0x5
ADV_EXT = 0x7

# DLT 256 pseudo-header flags.
PHDR_SIGNAL_VALID = 0x0002
PHDR_CRC_CHECKED = 0x0400
PHDR_CRC_VALID = 0x0800


# ---- link-layer packets -------------------------------------------------


def ll_packet(
    pdu_type: int,
    payload: bytes,
    *,
    tx_add: int = 0,
    rx_add: int = 0,
    chsel: int = 0,
    access_address: int = ADV_ACCESS_ADDRESS,
) -> bytes:
    """Access address + PDU header + payload + a dummy 3-byte CRC."""
    hdr0 = (pdu_type & 0x0F) | ((chsel & 1) << 5) | ((tx_add & 1) << 6) | ((rx_add & 1) << 7)
    return (
        struct.pack("<I", access_address)
        + bytes([hdr0, len(payload) & 0xFF])
        + payload
        + b"\x00\x00\x00"
    )


def addr_bytes(address: int) -> bytes:
    return address.to_bytes(6, "little")


def adv_ll(address: int, tx_add: int, pdu_type: int, advdata: bytes, chsel: int = 0) -> bytes:
    """A legacy `AdvA | AdvData` PDU (ADV_IND, ADV_NONCONN_IND, SCAN_RSP, …)."""
    return ll_packet(pdu_type, addr_bytes(address) + advdata, tx_add=tx_add, chsel=chsel)


def scan_req_ll(scanner: int, advertiser: int, *, adv_random: int = 1) -> bytes:
    return ll_packet(
        SCAN_REQ, addr_bytes(scanner) + addr_bytes(advertiser), tx_add=1, rx_add=adv_random
    )


def connect_ind_ll(initiator: int, advertiser: int, *, adv_random: int = 1) -> bytes:
    return ll_packet(
        CONNECT_IND,
        addr_bytes(initiator) + addr_bytes(advertiser) + bytes(22),
        tx_add=1,
        rx_add=adv_random,
    )


# ---- DLT 256 records ----------------------------------------------------


def rf_channel(index: int) -> int:
    """BLE channel index -> RF channel number, as DLT 256 stores it."""
    if index == 37:
        return 0
    if index == 38:
        return 12
    if index == 39:
        return 39
    return index + 1 if index < 11 else index + 2


def phdr(channel: int, rssi: int, *, crc_ok: bool = True, phy: int = 0) -> bytes:
    flags = PHDR_SIGNAL_VALID | PHDR_CRC_CHECKED | (PHDR_CRC_VALID if crc_ok else 0)
    flags |= phy << 14
    return (
        bytes([rf_channel(channel), rssi & 0xFF, 0, 0])
        + struct.pack("<I", ADV_ACCESS_ADDRESS)
        + struct.pack("<H", flags)
    )


# ---- Nordic (DLT 272) records ------------------------------------------


def nordic_record(
    ll: bytes,
    *,
    channel: int = 37,
    rssi: int = -50,
    counter: int = 0,
    time_field: int = 0,
    protover: int = 3,
    crc_ok: bool = True,
    phy: int = 0,
) -> bytes:
    """One nRF Sniffer record: board id, UART header, event header, LL packet.
    `time_field` is the firmware timestamp (protover 3) or the end-to-start
    delta from the previous packet (protover 1-2)."""
    flags = (1 if crc_ok else 0) | (phy << 4)
    event = (
        bytes([10, flags, channel, -rssi])
        + struct.pack("<H", 0)
        + struct.pack("<I", time_field)
    )
    payload = event + ll
    packet_id = 0x02 if protover >= 3 else 0x06
    return (
        bytes([0])
        + struct.pack("<H", len(payload))
        + bytes([protover])
        + struct.pack("<H", counter & 0xFFFF)
        + bytes([packet_id])
        + payload
    )


# ---- containers ---------------------------------------------------------


def build_pcap_raw(bodies: list[tuple[int, bytes]], linktype: int = 256) -> bytes:
    """Classic pcap from (t_us, record body) pairs."""
    parts = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for t_us, body in bodies:
        parts.append(struct.pack("<IIII", t_us // 1_000_000, t_us % 1_000_000, len(body), len(body)))
        parts.append(body)
    return b"".join(parts)


def build_pcap(records: list[tuple], linktype: int = 256) -> bytes:
    """records: (t_us, channel, rssi, address, tx_add, pdu_type, advdata)."""
    return build_pcap_raw(
        [
            (t_us, phdr(channel, rssi) + adv_ll(address, tx_add, pdu_type, advdata))
            for t_us, channel, rssi, address, tx_add, pdu_type, advdata in records
        ],
        linktype,
    )


def _block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def build_pcapng(
    linktypes: list[int],
    packets: list[tuple[int, int, bytes]],
    *,
    tsresol: int | None = None,
) -> bytes:
    """pcapng with one interface per entry of `linktypes`.

    packets: (interface index, timestamp in interface units, record body).
    `tsresol` sets if_tsresol (e.g. 9 for nanoseconds); default microseconds.
    """
    parts = [_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))]
    for linktype in linktypes:
        opts = b""
        if tsresol is not None:
            opts = struct.pack("<HH", 9, 1) + bytes([tsresol, 0, 0, 0]) + struct.pack("<HH", 0, 0)
        parts.append(_block(1, struct.pack("<HHI", linktype, 0, 0) + opts))
    for iface, ts, body in packets:
        head = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(body), len(body))
        parts.append(_block(6, head + body))
    return b"".join(parts)


# ---- scenarios ----------------------------------------------------------


def make_capture() -> bytes:
    """A small 8-packet scenario: 4 distinct addresses => 4 epochs."""
    records = [
        # device A, epoch 1 — burst across the three adv channels
        (1_000_000, 37, -50, ADDR_A1, 1, ADV_IND, ADV_DATA_A),
        (1_100_000, 38, -52, ADDR_A1, 1, ADV_IND, ADV_DATA_A),
        (1_200_000, 39, -55, ADDR_A1, 1, ADV_IND, ADV_DATA_A),
        # device B
        (1_050_000, 37, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
        (1_150_000, 38, -61, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
        # a public-address device
        (1_300_000, 37, -40, ADDR_PUB, 0, ADV_NONCONN_IND, ADV_DATA_PUB),
        # device A, epoch 2 (new address after rotation)
        (2_000_000, 37, -50, ADDR_A2, 1, ADV_IND, ADV_DATA_A),
        (2_100_000, 38, -53, ADDR_A2, 1, ADV_IND, ADV_DATA_A),
    ]
    return build_pcap(records)


def apple_adv(nearby_tag: bytes, handoff_seq: int | None = None) -> bytes:
    """Flags + Apple manufacturer data: Nearby Info, optionally Handoff."""
    msgs = bytes([0x10, 0x05, 0x07, 0x1C]) + nearby_tag[:3]
    if handoff_seq is not None:
        msgs = (
            bytes([0x0C, 0x0E, 0x00]) + handoff_seq.to_bytes(2, "big") + bytes([0x48])
            + bytes(range(10)) + msgs
        )
    mfr = bytes([0x4C, 0x00]) + msgs
    return bytes([0x02, 0x01, 0x1A, len(mfr) + 1, 0xFF]) + mfr


def find_my_adv(key: bytes) -> bytes:
    mfr = bytes([0x4C, 0x00, 0x12, 0x19, 0x10]) + key[:22] + bytes([0x03, 0x00])
    return bytes([len(mfr) + 1, 0xFF]) + mfr


def make_rotation_capture(
    *, minutes: float = 12, seed: int = 7, loss: float = 0.3
) -> tuple[bytes, dict[int, str]]:
    """A deterministic multi-device scenario with address rotations, as a
    Nordic (protover 3) pcapng. Returns (capture, {address: device name}).

    Devices: two phones that rotate their address every few minutes while
    carrying a Handoff counter across the rotation; one Find My tracker that
    rotates once; one named wearable on a static address that answers scan
    requests; one public-address beacon.
    """
    rng = random.Random(seed)
    end_us = int(minutes * 60e6)
    events: list[tuple[int, int, int, bytes]] = []  # (t_us, channel, rssi, ll)
    truth: dict[int, str] = {}

    def rpa() -> int:
        return (0b01 << 46) | rng.getrandbits(46)

    def advertise(name, address, start, stop, interval_us, rssi, payload, *, tx_add=1,
                  pdu=ADV_IND, scan_rsp=None):
        truth[address] = name
        t = start
        while t < stop:
            for i, ch in enumerate((37, 38, 39)):
                if rng.random() >= loss:
                    data = payload(t) if callable(payload) else payload
                    events.append((t + i * 400, ch, rssi + rng.randint(-3, 3),
                                   adv_ll(address, tx_add, pdu, data)))
                    if scan_rsp and rng.random() < 0.15:
                        events.append((t + i * 400 + 250, ch, rssi - 20,
                                       scan_req_ll(ADDR_SCANNER, address, adv_random=tx_add)))
                        events.append((t + i * 400 + 500, ch, rssi,
                                       adv_ll(address, tx_add, SCAN_RSP, scan_rsp)))
            t += interval_us + rng.randint(0, 10_000)

    for name, interval, rssi, rotate_s, seq0 in (
        ("phone-1", 180_000, -55, 240, 0x1200),
        ("phone-2", 211_000, -68, 310, 0x7F00),
    ):
        t, seq = rng.randint(0, 2_000_000), seq0
        while t < end_us:
            stop = min(end_us, t + int(rotate_s * 1e6) + rng.randint(-20, 20) * 1_000_000)
            tag = rng.randbytes(3)
            base, start = seq, t
            advertise(name, rpa(), t, stop, interval, rssi,
                      lambda now, base=base, start=start, tag=tag:
                          apple_adv(tag, base + (now - start) // 45_000_000))
            seq = base + (stop - t) // 45_000_000 + 1
            t = stop + rng.randint(100_000, 900_000)

    half = end_us // 2 + rng.randint(-30, 30) * 1_000_000
    advertise("tracker", (0b11 << 46) | rng.getrandbits(46), 0, half, 2_000_000, -75,
              find_my_adv(rng.randbytes(22)), pdu=ADV_NONCONN_IND)
    advertise("tracker", (0b11 << 46) | rng.getrandbits(46), half + 400_000, end_us,
              2_000_000, -75, find_my_adv(rng.randbytes(22)), pdu=ADV_NONCONN_IND)

    advertise("wearable", (0b11 << 46) | rng.getrandbits(46), 5_000_000, end_us - 40_000_000,
              100_000, -62, bytes([0x02, 0x01, 0x06, 0x03, 0x03, 0x0D, 0x18]),
              scan_rsp=bytes([0x08, 0x09]) + b"Band-42")
    advertise("beacon", ADDR_PUB, 0, end_us, 1_000_000, -80,
              bytes([0x02, 0x01, 0x04, 0x03, 0x03, 0xAA, 0xFE, 0x0D, 0x16, 0xAA, 0xFE, 0x30, 0xEE])
              + bytes(range(8)), tx_add=0, pdu=ADV_NONCONN_IND)

    events.sort(key=lambda e: e[0])
    host0 = 1_700_000_000_000_000
    packets = [
        (0, host0 + t + rng.randint(0, 3000),
         nordic_record(ll, channel=ch, rssi=min(-1, rssi), counter=n,
                       time_field=(123_456 + t) & 0xFFFFFFFF))
        for n, (t, ch, rssi, ll) in enumerate(events)
    ]
    return build_pcapng([272], packets), truth


def build_scenario(segments: list[dict], *, seed: int = 1, loss: float = 0.0) -> bytes:
    """A capture from a list of advertising segments, one per address epoch.

    Each segment: ``address, start_s, stop_s`` plus optional ``interval_ms``
    (default 200), ``rssi`` (default -60), ``payload`` (bytes, or a function of
    time in µs), ``tx_add`` (default 1) and ``pdu`` (default ADV_IND).
    """
    rng = random.Random(seed)
    records = []
    for seg in segments:
        payload = seg.get("payload", ADV_DATA_B)
        t = int(seg["start_s"] * 1e6)
        while t <= seg["stop_s"] * 1e6:
            for i, ch in enumerate((37, 38, 39)):
                if rng.random() >= loss:
                    records.append((
                        t + i * 400, ch, seg.get("rssi", -60) + rng.randint(-1, 1),
                        seg["address"], seg.get("tx_add", 1), seg.get("pdu", ADV_IND),
                        payload(t) if callable(payload) else payload,
                    ))
            t += int(seg.get("interval_ms", 200) * 1000) + rng.randint(0, 10_000)
    records.sort(key=lambda r: r[0])
    return build_pcap(records)


def rpa(n: int) -> int:
    """A distinct resolvable private address for test device/epoch `n`."""
    return (0b01 << 46) | (0x1000_0000_0000 + n * 0x0101_0101)


def static_addr(n: int) -> int:
    return (0b11 << 46) | (0x1000_0000_0000 + n * 0x0101_0101)
