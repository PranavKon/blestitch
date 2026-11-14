"""Vendor and protocol lookups for advertising data.

* Bluetooth SIG company identifiers and 16-bit service UUID names (vendored
  from the Bluetooth Numbers Database; see ``blestitch/data/NOTICE``).
* Decoders for the manufacturer-data and service-data formats that trackers,
  beacons and wearables put on air.

Every decoder returns ``(tag, fields)``: `tag` is a short protocol label used
to describe an epoch ("Find My", "Eddystone"), and `fields` is an ordered list
of ``(label, value)`` strings for display. Decoders never raise.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from blestitch.dissect import continuity

MICROSOFT_COMPANY_ID = 0x0006

# Member-assigned 16-bit UUIDs that are missing from the vendored GATT list.
_EXTRA_SERVICE_NAMES = {
    "fd5a": "Samsung SmartTag",
    "fd84": "Tile",
    "fe03": "Amazon",
    "fe59": "Nordic Secure DFU",
    "fe95": "Xiaomi MiBeacon",
    "fe9f": "Google",
    "febe": "Bose",
    "fee0": "Huami (Mi Band)",
    "feec": "Tile",
    "feed": "Tile",
}

Fields = list[tuple[str, str]]


@lru_cache(maxsize=1)
def _company_table() -> dict[str, str]:
    text = resources.files("blestitch.data").joinpath("company_ids.json").read_text()
    return json.loads(text)


@lru_cache(maxsize=1)
def _service_table() -> dict[str, str]:
    text = resources.files("blestitch.data").joinpath("service_uuids.json").read_text()
    return {**json.loads(text), **_EXTRA_SERVICE_NAMES}


def company_name(company_id: int) -> str | None:
    """Registered name for a 16-bit company identifier, or None."""
    return _company_table().get(f"{company_id:04x}")


def short_company_name(company_id: int) -> str:
    """A compact display name: "Apple" rather than "Apple, Inc."."""
    name = company_name(company_id)
    if name is None:
        return f"0x{company_id:04x}"
    for suffix in (", Inc.", " Inc.", ", Ltd.", " Ltd.", " Co.", " ASA", " LLC",
                   " Corporation", " Corp.", " GmbH", " AB", " OY", " Oy"):
        cut = name.find(suffix)
        if cut > 0:
            name = name[:cut]
    return name.rstrip(" ,")


def service_name(uuid16: str) -> str | None:
    """Name for a 16-bit service UUID given as 4 lowercase hex digits."""
    return _service_table().get(uuid16.lower())


def decode_manufacturer(company_id: int, data: bytes) -> tuple[list[str], Fields]:
    """Decode manufacturer-specific data (the bytes after the company ID).

    Returns ``(tags, fields)``; Apple data can carry several messages, hence a
    list of tags.
    """
    if company_id == continuity.APPLE_COMPANY_ID:
        tags: list[str] = []
        fields: Fields = []
        for msg in continuity.parse_continuity(data):
            tags.append(msg.name)
            if msg.fields:
                fields += [(f"{msg.name}: {k}", v) for k, v in msg.fields]
            else:
                fields.append((msg.name, msg.data.hex()))
        return tags, fields
    if company_id == MICROSOFT_COMPANY_ID and data[:1] == b"\x01":
        return ["Microsoft CDP beacon"], [("data", data.hex())]
    return [], [("data", data.hex())]


def decode_service_data(uuid16: str, data: bytes) -> tuple[str | None, Fields]:
    """Decode 16-bit-UUID service data. Returns ``(tag, fields)``."""
    decoder = _SERVICE_DECODERS.get(uuid16.lower())
    if decoder is not None:
        try:
            return decoder(data)
        except IndexError:  # shorter than the documented layout
            pass
    return service_name(uuid16), [("data", data.hex())]


def _eddystone(d: bytes) -> tuple[str, Fields]:
    frame = d[0]
    if frame == 0x00:
        return "Eddystone-UID", [
            ("namespace", d[2:12].hex()),
            ("instance", d[12:18].hex()),
        ]
    if frame == 0x10:
        return "Eddystone-URL", [("encoded url", d[2:].hex())]
    if frame == 0x20:
        return "Eddystone-TLM", [
            ("advertisement count", str(int.from_bytes(d[6:10], "big"))),
            ("uptime", f"{int.from_bytes(d[10:14], 'big') / 10:.1f} s"),
            ("battery", f"{int.from_bytes(d[2:4], 'big')} mV"),
        ]
    if frame == 0x30:
        return "Eddystone-EID", [("ephemeral id", d[2:10].hex())]
    return "Eddystone", [("data", d.hex())]


def _exposure_notification(d: bytes) -> tuple[str, Fields]:
    return "Exposure Notification", [
        ("rolling proximity id", d[0:16].hex()),
        ("encrypted metadata", d[16:20].hex()),
    ]


def _fast_pair(d: bytes) -> tuple[str, Fields]:
    if len(d) == 3:
        return "Fast Pair", [("model id", d.hex())]
    return "Fast Pair", [("account data", d.hex())]


def _tile(d: bytes) -> tuple[str, Fields]:
    return "Tile", [("data", d.hex())]


def _smarttag(d: bytes) -> tuple[str, Fields]:
    return "Samsung SmartTag", [("data", d.hex())]


def _mibeacon(d: bytes) -> tuple[str, Fields]:
    return "Xiaomi MiBeacon", [
        ("frame counter", str(d[4])),
        ("product id", f"0x{d[2] | (d[3] << 8):04x}"),
        ("frame control", f"0x{d[0] | (d[1] << 8):04x}"),
        ("rest", d[5:].hex()),
    ]


_SERVICE_DECODERS = {
    "feaa": _eddystone,
    "fd6f": _exposure_notification,
    "fe2c": _fast_pair,
    "feed": _tile,
    "feec": _tile,
    "fd84": _tile,
    "fd5a": _smarttag,
    "fe95": _mibeacon,
}
