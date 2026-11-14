"""Advertising Data (AD) structure parsing and decoding.

AdvData is a sequence of `length | type | data[length-1]` structures (Core
Spec, Vol 3, Part C §11; types in the Core Specification Supplement). This
module does three things with it:

* :func:`ad_structure` / :func:`ad_signature` — the ordered *shape* of the
  payload, a per-firmware fingerprint the structural clue matches on.
* :func:`decode_ad` — every field decoded for display in the GUI.
* :func:`summarize_ad` — the identifying facts (vendor, name, services,
  protocols) rolled up for an epoch profile.

Malformed or truncated tails are ignored rather than raising — real captures
contain partial AD fields at the snaplen boundary.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from blestitch.dissect import vendors

AD_FLAGS = 0x01
AD_UUID16_INCOMPLETE = 0x02
AD_UUID16_COMPLETE = 0x03
AD_UUID32_INCOMPLETE = 0x04
AD_UUID32_COMPLETE = 0x05
AD_UUID128_INCOMPLETE = 0x06
AD_UUID128_COMPLETE = 0x07
AD_NAME_SHORT = 0x08
AD_NAME_COMPLETE = 0x09
AD_TX_POWER = 0x0A
AD_CONN_INTERVAL_RANGE = 0x12
AD_SOLICIT_UUID16 = 0x14
AD_SOLICIT_UUID128 = 0x15
AD_SERVICE_DATA_16 = 0x16
AD_APPEARANCE = 0x19
AD_ADV_INTERVAL = 0x1A
AD_SERVICE_DATA_32 = 0x20
AD_SERVICE_DATA_128 = 0x21
AD_MANUFACTURER = 0xFF

AD_TYPE_NAMES = {
    AD_FLAGS: "Flags",
    AD_UUID16_INCOMPLETE: "16-bit Service UUIDs (incomplete)",
    AD_UUID16_COMPLETE: "16-bit Service UUIDs",
    AD_UUID32_INCOMPLETE: "32-bit Service UUIDs (incomplete)",
    AD_UUID32_COMPLETE: "32-bit Service UUIDs",
    AD_UUID128_INCOMPLETE: "128-bit Service UUIDs (incomplete)",
    AD_UUID128_COMPLETE: "128-bit Service UUIDs",
    AD_NAME_SHORT: "Shortened Local Name",
    AD_NAME_COMPLETE: "Complete Local Name",
    AD_TX_POWER: "TX Power Level",
    0x0D: "Class of Device",
    0x10: "Device ID",
    0x11: "Security Manager OOB Flags",
    AD_CONN_INTERVAL_RANGE: "Peripheral Connection Interval Range",
    AD_SOLICIT_UUID16: "16-bit Service Solicitation UUIDs",
    AD_SOLICIT_UUID128: "128-bit Service Solicitation UUIDs",
    AD_SERVICE_DATA_16: "Service Data (16-bit UUID)",
    0x17: "Public Target Address",
    0x18: "Random Target Address",
    AD_APPEARANCE: "Appearance",
    AD_ADV_INTERVAL: "Advertising Interval",
    0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role",
    0x1F: "32-bit Service Solicitation UUIDs",
    AD_SERVICE_DATA_32: "Service Data (32-bit UUID)",
    AD_SERVICE_DATA_128: "Service Data (128-bit UUID)",
    0x24: "URI",
    0x29: "Mesh Provisioning (PB-ADV)",
    0x2A: "Mesh Message",
    0x2B: "Mesh Beacon",
    0x2C: "BIGInfo",
    0x2D: "Broadcast Code",
    0x30: "Broadcast Name",
    AD_MANUFACTURER: "Manufacturer Specific Data",
}

_FLAG_BITS = (
    (0x01, "LE Limited Discoverable"),
    (0x02, "LE General Discoverable"),
    (0x04, "BR/EDR Not Supported"),
    (0x08, "LE + BR/EDR (Controller)"),
    (0x10, "LE + BR/EDR (Host)"),
)

# Appearance category = value >> 6 (Assigned Numbers §2.6).
_APPEARANCE_CATEGORIES = {
    0: "Unknown", 1: "Phone", 2: "Computer", 3: "Watch", 4: "Clock",
    5: "Display", 6: "Remote Control", 7: "Eye-glasses", 8: "Tag",
    9: "Keyring", 10: "Media Player", 11: "Barcode Scanner",
    12: "Thermometer", 13: "Heart Rate Sensor", 14: "Blood Pressure",
    15: "Human Interface Device", 16: "Glucose Meter",
    17: "Running Walking Sensor", 18: "Cycling", 49: "Pulse Oximeter",
    50: "Weight Scale",
}

Structure = tuple[tuple[int, int], ...]


def iter_ad_fields(advdata: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (ad_type, data_bytes) for each well-formed AD structure."""
    i = 0
    n = len(advdata)
    while i < n:
        length = advdata[i]
        if length == 0 or i + 1 + length > n:
            break
        yield advdata[i + 1], advdata[i + 2 : i + 1 + length]
        i += 1 + length


def ad_structure(advdata: bytes) -> Structure:
    """Return the ordered (AD type, data_length) list."""
    return tuple((t, len(d)) for t, d in iter_ad_fields(advdata))


def ad_signature(structure: Structure) -> str:
    """A stable text key for a payload's shape, e.g. ``01:1|0a:1|ff:4``."""
    return "|".join(f"{t:02x}:{n}" for t, n in structure)


def extract_tx_power(advdata: bytes) -> int | None:
    """Return the advertised TX Power Level (signed dBm) if present."""
    for ad_type, data in iter_ad_fields(advdata):
        if ad_type == AD_TX_POWER and len(data) >= 1:
            return _s8(data[0])
    return None


def extract_company_id(advdata: bytes) -> int | None:
    """Return the 16-bit company identifier from manufacturer-specific data."""
    for ad_type, data in iter_ad_fields(advdata):
        if ad_type == AD_MANUFACTURER and len(data) >= 2:
            return data[0] | (data[1] << 8)
    return None


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


def _uuid16(b: bytes) -> str:
    return f"{b[1]:02x}{b[0]:02x}"


def _uuid32(b: bytes) -> str:
    return b[::-1].hex()


def _uuid128(b: bytes) -> str:
    h = b[::-1].hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _uuid_list(data: bytes, size: int) -> list[str]:
    fmt = {2: _uuid16, 4: _uuid32, 16: _uuid128}[size]
    return [fmt(data[i : i + size]) for i in range(0, len(data) - size + 1, size)]


def _uuid16_label(u: str) -> str:
    name = vendors.service_name(u)
    return f"0x{u} ({name})" if name else f"0x{u}"


@dataclass(slots=True)
class DecodedField:
    """One AD structure, decoded for display."""

    type: int
    name: str
    data: bytes
    summary: str
    fields: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name,
            "hex": self.data.hex(),
            "summary": self.summary,
            "fields": [list(f) for f in self.fields],
        }


@dataclass(slots=True)
class AdSummary:
    """Identifying facts pulled out of one AdvData payload."""

    company_id: int | None = None
    local_name: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)   # protocol labels, in order
    appearance: str | None = None
    tx_power: int | None = None

    def add_tag(self, tag: str | None) -> None:
        if tag and tag not in self.tags:
            self.tags.append(tag)


def decode_ad(advdata: bytes) -> list[DecodedField]:
    """Decode every AD structure in `advdata`, in order."""
    return [_decode_field(t, d, None) for t, d in iter_ad_fields(advdata)]


def summarize_ad(advdata: bytes) -> AdSummary:
    """Roll one AdvData payload up into an :class:`AdSummary`."""
    summary = AdSummary()
    for t, d in iter_ad_fields(advdata):
        _decode_field(t, d, summary)
    return summary


def _decode_field(t: int, d: bytes, s: AdSummary | None) -> DecodedField:
    name = AD_TYPE_NAMES.get(t, f"AD type 0x{t:02x}")
    summary = d.hex()
    fields: list[tuple[str, str]] = []

    if t == AD_FLAGS and d:
        set_bits = [label for bit, label in _FLAG_BITS if d[0] & bit]
        summary = f"0x{d[0]:02x}" + (f" — {', '.join(set_bits)}" if set_bits else "")

    elif t in (AD_UUID16_INCOMPLETE, AD_UUID16_COMPLETE, AD_SOLICIT_UUID16):
        uuids = _uuid_list(d, 2)
        summary = ", ".join(_uuid16_label(u) for u in uuids)
        if s is not None and t != AD_SOLICIT_UUID16:
            _extend_unique(s.service_uuids, uuids)

    elif t in (AD_UUID32_INCOMPLETE, AD_UUID32_COMPLETE):
        uuids = _uuid_list(d, 4)
        summary = ", ".join(uuids)
        if s is not None:
            _extend_unique(s.service_uuids, uuids)

    elif t in (AD_UUID128_INCOMPLETE, AD_UUID128_COMPLETE, AD_SOLICIT_UUID128):
        uuids = _uuid_list(d, 16)
        summary = ", ".join(uuids)
        if s is not None and t != AD_SOLICIT_UUID128:
            _extend_unique(s.service_uuids, uuids)

    elif t in (AD_NAME_SHORT, AD_NAME_COMPLETE):
        summary = d.decode("utf-8", errors="replace")
        if s is not None and (s.local_name is None or t == AD_NAME_COMPLETE):
            s.local_name = summary

    elif t == AD_TX_POWER and d:
        summary = f"{_s8(d[0])} dBm"
        if s is not None:
            s.tx_power = _s8(d[0])

    elif t == AD_CONN_INTERVAL_RANGE and len(d) >= 4:
        lo, hi = d[0] | (d[1] << 8), d[2] | (d[3] << 8)
        summary = f"{lo * 1.25:g}–{hi * 1.25:g} ms"

    elif t == AD_APPEARANCE and len(d) >= 2:
        value = d[0] | (d[1] << 8)
        category = _APPEARANCE_CATEGORIES.get(value >> 6)
        summary = f"0x{value:04x}" + (f" ({category})" if category else "")
        if s is not None:
            s.appearance = category or f"0x{value:04x}"

    elif t == AD_ADV_INTERVAL and len(d) >= 2:
        summary = f"{(d[0] | (d[1] << 8)) * 0.625:g} ms"

    elif t == AD_SERVICE_DATA_16 and len(d) >= 2:
        uuid = _uuid16(d[0:2])
        tag, fields = vendors.decode_service_data(uuid, d[2:])
        summary = f"{_uuid16_label(uuid)} · {len(d) - 2} bytes"
        if tag and tag != vendors.service_name(uuid):
            summary = f"{tag} · {len(d) - 2} bytes"
        if s is not None:
            _extend_unique(s.service_uuids, [uuid])
            s.add_tag(tag)

    elif t == AD_SERVICE_DATA_32 and len(d) >= 4:
        summary = f"{_uuid32(d[0:4])} · {len(d) - 4} bytes"
        fields = [("data", d[4:].hex())]

    elif t == AD_SERVICE_DATA_128 and len(d) >= 16:
        summary = f"{_uuid128(d[0:16])} · {len(d) - 16} bytes"
        fields = [("data", d[16:].hex())]

    elif t == AD_MANUFACTURER and len(d) >= 2:
        cid = d[0] | (d[1] << 8)
        tags, fields = vendors.decode_manufacturer(cid, d[2:])
        company = vendors.company_name(cid) or "unregistered company"
        summary = f"{company} (0x{cid:04x})"
        if tags:
            summary += " · " + ", ".join(tags)
        if s is not None:
            if s.company_id is None:
                s.company_id = cid
            for tag in tags:
                s.add_tag(tag)

    return DecodedField(type=t, name=name, data=d, summary=summary, fields=fields)


def _extend_unique(target: list[str], items: list[str]) -> None:
    for item in items:
        if item not in target:
            target.append(item)
