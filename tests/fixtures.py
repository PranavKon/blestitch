"""Build tiny in-memory BLE PCAP captures for testing the reader.

This is a *test fixture*, not a traffic simulator: it emits a handful of
hand-crafted DLT 256 (LE_LL_WITH_PHDR) records so the parser can be exercised
without real hardware. The byte layout mirrors exactly what the reader expects.
"""

from __future__ import annotations

import struct

ADV_ACCESS_ADDRESS = 0x8E89BED6

# Advertising address examples. Random (TxAdd=1) addresses with top two bits 01
# are Resolvable Private Addresses.
ADDR_A1 = 0x7A1122334455  # device A, epoch 1 (resolvable)
ADDR_A2 = 0x6BAABBCCDDEE  # device A, epoch 2 (resolvable)
ADDR_B1 = 0x551020304050  # device B (resolvable)
ADDR_PUB = 0x00AABBCCDDEE  # a public-address device

# AD payloads: flags + TX power (-12 dBm) + Apple manufacturer data.
ADV_DATA_A = bytes([0x02, 0x01, 0x06, 0x02, 0x0A, 0xF4, 0x05, 0xFF, 0x4C, 0x00, 0x01, 0x02])
ADV_DATA_B = bytes([0x02, 0x01, 0x06, 0x03, 0x09, 0x42, 0x42])  # name "BB"
ADV_DATA_PUB = bytes([0x02, 0x01, 0x04])

ADV_IND = 0x0
ADV_NONCONN_IND = 0x2


def _ble_ll(address: int, tx_add: int, pdu_type: int, advdata: bytes, chsel: int = 0) -> bytes:
    hdr0 = (pdu_type & 0x0F) | ((chsel & 1) << 5) | ((tx_add & 1) << 6)
    payload = address.to_bytes(6, "little") + advdata
    hdr1 = len(payload) & 0xFF
    return struct.pack("<I", ADV_ACCESS_ADDRESS) + bytes([hdr0, hdr1]) + payload + b"\x00\x00\x00"


def _phdr(channel: int, rssi: int) -> bytes:
    return bytes([channel & 0xFF, rssi & 0xFF, 0, 0]) + struct.pack("<I", ADV_ACCESS_ADDRESS) + struct.pack("<H", 0)


def build_pcap(records: list[tuple], linktype: int = 256) -> bytes:
    """records: (t_us, channel, rssi, address, tx_add, pdu_type, advdata)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for t_us, channel, rssi, address, tx_add, pdu_type, advdata in records:
        body = _phdr(channel, rssi) + _ble_ll(address, tx_add, pdu_type, advdata)
        out += struct.pack("<IIII", t_us // 1_000_000, t_us % 1_000_000, len(body), len(body)) + body
    return out


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
