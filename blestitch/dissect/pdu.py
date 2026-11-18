"""Link-layer advertising PDU helpers.

Parses the BLE LL advertising PDU header flags and the Advertising Data (AD)
structures carried in the payload. Kept separate from the PCAP reader so the
same logic works regardless of which capture format the bytes arrived in.

References: Bluetooth Core Spec, Vol 6, Part B §2.3 (advertising PDUs) and
Vol 3, Part C §11 (AD structure format: each is `len | type | data[len-1]`).
"""

from __future__ import annotations

from dataclasses import dataclass

# Legacy advertising PDU types that carry a 6-byte AdvA at the start of payload.
_ADV_PDU_WITH_ADVA = {
    0x0,  # ADV_IND
    0x1,  # ADV_DIRECT_IND
    0x2,  # ADV_NONCONN_IND
    0x4,  # SCAN_RSP
    0x6,  # ADV_SCAN_IND
}

# Common AD types we surface explicitly.
AD_TYPE_TX_POWER = 0x0A
AD_TYPE_MANUFACTURER = 0xFF


@dataclass(slots=True)
class PduHeader:
    pdu_type: int
    chsel: bool
    tx_add: bool
    rx_add: bool
    length: int

    @property
    def has_adva(self) -> bool:
        return self.pdu_type in _ADV_PDU_WITH_ADVA


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


def parse_ad_structures(advdata: bytes) -> tuple[tuple[int, int], ...]:
    """Return the ordered (AD type, data_length) list.

    Malformed/truncated tails are ignored rather than raising — real captures
    contain partial AD fields at the snaplen boundary.
    """
    out: list[tuple[int, int]] = []
    i = 0
    n = len(advdata)
    while i < n:
        length = advdata[i]
        if length == 0 or i + 1 + length > n:
            break
        ad_type = advdata[i + 1]
        out.append((ad_type, length - 1))  # minus the type byte
        i += 1 + length
    return tuple(out)


def iter_ad_fields(advdata: bytes):
    """Yield (ad_type, data_bytes) for each well-formed AD structure."""
    i = 0
    n = len(advdata)
    while i < n:
        length = advdata[i]
        if length == 0 or i + 1 + length > n:
            break
        ad_type = advdata[i + 1]
        yield ad_type, advdata[i + 2 : i + 1 + length]
        i += 1 + length


def extract_tx_power(advdata: bytes) -> int | None:
    """Return the advertised TX Power Level (signed dBm) if present."""
    for ad_type, data in iter_ad_fields(advdata):
        if ad_type == AD_TYPE_TX_POWER and len(data) >= 1:
            v = data[0]
            return v - 256 if v >= 128 else v
    return None


def extract_company_id(advdata: bytes) -> int | None:
    """Return the 16-bit company identifier from manufacturer-specific data."""
    for ad_type, data in iter_ad_fields(advdata):
        if ad_type == AD_TYPE_MANUFACTURER and len(data) >= 2:
            return data[0] | (data[1] << 8)
    return None
