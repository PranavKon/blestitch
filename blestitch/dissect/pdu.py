"""Link-layer advertising PDU parsing.

Turns the bytes of one advertising-channel PDU (header + payload, without the
access address or CRC) into an :class:`AdvPdu`: who advertised, who it was
aimed at, and the advertising data it carried. Kept separate from the capture
reader so the same logic works whichever container the bytes arrived in.

Reference: Bluetooth Core Spec, Vol 6, Part B §2.3 (advertising physical
channel PDUs) and §2.3.4 (Common Extended Advertising Payload Format).
"""

from __future__ import annotations

from dataclasses import dataclass

from blestitch.records import (
    PDU_ADV_DIRECT_IND,
    PDU_ADV_EXT,
    PDU_ADV_IND,
    PDU_ADV_NONCONN_IND,
    PDU_ADV_SCAN_IND,
    PDU_AUX_CONNECT_RSP,
    PDU_CONNECT_IND,
    PDU_SCAN_REQ,
    PDU_SCAN_RSP,
)

ADV_ACCESS_ADDRESS = 0x8E89BED6

_PRIMARY_NAMES = {
    PDU_ADV_IND: "ADV_IND",
    PDU_ADV_DIRECT_IND: "ADV_DIRECT_IND",
    PDU_ADV_NONCONN_IND: "ADV_NONCONN_IND",
    PDU_SCAN_REQ: "SCAN_REQ",
    PDU_SCAN_RSP: "SCAN_RSP",
    PDU_CONNECT_IND: "CONNECT_IND",
    PDU_ADV_SCAN_IND: "ADV_SCAN_IND",
    PDU_ADV_EXT: "ADV_EXT_IND",
    PDU_AUX_CONNECT_RSP: "AUX_CONNECT_RSP",
}
# The same type codes mean different PDUs on the secondary (data) channels.
_SECONDARY_NAMES = {
    PDU_SCAN_REQ: "AUX_SCAN_REQ",
    PDU_CONNECT_IND: "AUX_CONNECT_REQ",
    PDU_ADV_EXT: "AUX_ADV_IND",
    PDU_AUX_CONNECT_RSP: "AUX_CONNECT_RSP",
}

# Legacy PDUs laid out as `AdvA | AdvData`.
_ADVA_THEN_DATA = {PDU_ADV_IND, PDU_ADV_NONCONN_IND, PDU_SCAN_RSP, PDU_ADV_SCAN_IND}
# PDUs laid out as `sender | AdvA | ...` (the advertiser is the *second* address).
_SENDER_THEN_ADVA = {PDU_SCAN_REQ, PDU_CONNECT_IND}
_EXTENDED = {PDU_ADV_EXT, PDU_AUX_CONNECT_RSP}

# Extended header flag bits, in the order their fields appear.
_EXT_ADVA = 0x01
_EXT_TARGETA = 0x02
_EXT_CTE_INFO = 0x04
_EXT_ADI = 0x08
_EXT_AUX_PTR = 0x10
_EXT_SYNC_INFO = 0x20
_EXT_TX_POWER = 0x40


def pdu_type_name(pdu_type: int, channel: int | None = 37) -> str:
    """Human-readable PDU name; `channel` disambiguates primary vs secondary.
    An unknown channel is taken to be a primary one."""
    if channel is not None and channel < 37 and pdu_type in _SECONDARY_NAMES:
        return _SECONDARY_NAMES[pdu_type]
    return _PRIMARY_NAMES.get(pdu_type, f"RFU_{pdu_type:#x}")


@dataclass(slots=True)
class PduHeader:
    pdu_type: int
    chsel: bool
    tx_add: bool
    rx_add: bool
    length: int


def parse_pdu_header(b0: int, b1: int) -> PduHeader:
    """Decode the 2-byte advertising PDU header.

    b0: PDU Type [3:0], ChSel [5], TxAdd [6], RxAdd [7]. b1: payload length.
    """
    return PduHeader(
        pdu_type=b0 & 0x0F,
        chsel=bool((b0 >> 5) & 0x1),
        tx_add=bool((b0 >> 6) & 0x1),
        rx_add=bool((b0 >> 7) & 0x1),
        length=b1 & 0xFF,
    )


@dataclass(slots=True)
class AdvPdu:
    """A parsed advertising PDU. `adv_a` is None when the PDU carries no
    advertiser address (an ADV_EXT_IND that only points at an AUX packet)."""

    header: PduHeader
    adv_a: int | None = None
    adv_random: bool = False
    peer_a: int | None = None      # TargetA, or the ScanA/InitA that sent it
    peer_random: bool = False
    data: bytes = b""              # AdvData / ScanRspData
    tx_power: int | None = None    # from the extended header, if present
    sid: int | None = None         # extended: Advertising Set ID
    did: int | None = None         # extended: Advertising Data ID
    adv_mode: int | None = None    # extended: 0 non-conn, 1 connectable, 2 scannable


def _addr(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


def parse_adv_pdu(pdu: bytes) -> AdvPdu | None:
    """Parse `header(2) | payload`. Returns None if too short to be a PDU.

    A payload shorter than its header claims (snaplen truncation) is parsed as
    far as it goes; address fields that do not fit leave `adv_a` as None.
    """
    if len(pdu) < 2:
        return None
    hdr = parse_pdu_header(pdu[0], pdu[1])
    payload = pdu[2 : 2 + hdr.length]
    out = AdvPdu(header=hdr)
    t = hdr.pdu_type

    if t in _ADVA_THEN_DATA:
        if len(payload) >= 6:
            out.adv_a, out.adv_random = _addr(payload[0:6]), hdr.tx_add
            out.data = payload[6:]
    elif t == PDU_ADV_DIRECT_IND:
        if len(payload) >= 6:
            out.adv_a, out.adv_random = _addr(payload[0:6]), hdr.tx_add
        if len(payload) >= 12:
            out.peer_a, out.peer_random = _addr(payload[6:12]), hdr.rx_add
    elif t in _SENDER_THEN_ADVA:
        if len(payload) >= 12:
            out.peer_a, out.peer_random = _addr(payload[0:6]), hdr.tx_add
            out.adv_a, out.adv_random = _addr(payload[6:12]), hdr.rx_add
    elif t in _EXTENDED:
        _parse_extended(payload, hdr, out)
    return out


def _parse_extended(payload: bytes, hdr: PduHeader, out: AdvPdu) -> None:
    if not payload:
        return
    ext_len = payload[0] & 0x3F
    out.adv_mode = payload[0] >> 6
    ext = payload[1 : 1 + ext_len]
    out.data = payload[1 + ext_len :]
    if not ext:
        return
    flags = ext[0]
    i = 1

    def take(n: int) -> bytes | None:
        nonlocal i
        if i + n > len(ext):
            i = len(ext)
            return None
        chunk = ext[i : i + n]
        i += n
        return chunk

    if flags & _EXT_ADVA and (b := take(6)) is not None:
        out.adv_a, out.adv_random = _addr(b), hdr.tx_add
    if flags & _EXT_TARGETA and (b := take(6)) is not None:
        out.peer_a, out.peer_random = _addr(b), hdr.rx_add
    if flags & _EXT_CTE_INFO:
        take(1)
    if flags & _EXT_ADI and (b := take(2)) is not None:
        adi = b[0] | (b[1] << 8)
        out.did, out.sid = adi & 0x0FFF, adi >> 12
    if flags & _EXT_AUX_PTR:
        take(3)
    if flags & _EXT_SYNC_INFO:
        take(18)
    if flags & _EXT_TX_POWER and (b := take(1)) is not None:
        out.tx_power = _s8(b[0])
