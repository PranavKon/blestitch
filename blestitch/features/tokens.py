"""Identifying tokens: payload content that could survive an address rotation.

A token is one field of an advertisement taken as a whole — a local name, a
service-data blob, an Apple Continuity message body, an AirPlay IP address.
Privacy-conscious devices randomize most of these along with the address, but
many leave something constant, and a constant that nobody else nearby is
sending ties two addresses together.

How much a shared token proves depends on how unusual it is; that is judged
later, against everything else on air (see :mod:`blestitch.features.pairwise`).
This module only extracts them.
"""

from __future__ import annotations

from blestitch.dissect import continuity
from blestitch.dissect.ad import (
    AD_MANUFACTURER,
    AD_NAME_COMPLETE,
    AD_NAME_SHORT,
    AD_SERVICE_DATA_16,
    iter_ad_fields,
)

# (kind, value). `kind` says which field it came from, so equal bytes in
# unrelated fields never count as a match.
Token = tuple[str, bytes]

NAME = "name"


def extract_tokens(advdata: bytes) -> set[Token]:
    """Every token in one AdvData / ScanRspData payload."""
    tokens: set[Token] = set()
    for ad_type, data in iter_ad_fields(advdata):
        if not data:
            continue
        if ad_type in (AD_NAME_SHORT, AD_NAME_COMPLETE):
            tokens.add((NAME, data))
        elif ad_type == AD_MANUFACTURER and len(data) >= 2:
            company = data[0] | (data[1] << 8)
            if company == continuity.APPLE_COMPANY_ID:
                tokens |= _apple_tokens(data[2:])
            else:
                tokens.add((f"mfr:{company:04x}", data[2:]))
        elif ad_type == AD_SERVICE_DATA_16 and len(data) >= 2:
            tokens.add((f"svc:{data[1]:02x}{data[0]:02x}", data[2:]))
        else:
            tokens.add((f"ad:{ad_type:02x}", data))
    return {t for t in tokens if t[1]}


def _apple_tokens(data: bytes) -> set[Token]:
    tokens: set[Token] = set()
    for msg in continuity.parse_continuity(data):
        tokens.add((f"apple:{msg.type:02x}", msg.data))
        if msg.type == continuity.AIRPLAY_TARGET and len(msg.data) >= 6:
            # The IP outlives the neighbouring config-seed byte.
            tokens.add(("apple:airplay-ip", msg.data[2:6]))
    return tokens


def describe_token(token: Token) -> str:
    """A short label for a token, for clue details."""
    kind, value = token
    if kind == NAME:
        return f"name “{value.decode('utf-8', errors='replace')}”"
    if kind == "apple:airplay-ip":
        return "AirPlay address " + ".".join(str(b) for b in value)
    if kind.startswith("apple:"):
        mtype = int(kind[6:], 16)
        name = continuity.MESSAGE_NAMES.get(mtype, f"Apple message 0x{mtype:02x}")
        return f"{name} body {_short(value)}"
    if kind.startswith("svc:"):
        return f"service data 0x{kind[4:]} {_short(value)}"
    if kind.startswith("mfr:"):
        return f"manufacturer data (0x{kind[4:]}) {_short(value)}"
    return f"AD field 0x{kind[3:]} {_short(value)}"


def _short(value: bytes) -> str:
    h = value.hex()
    return h if len(h) <= 16 else f"{h[:12]}…({len(value)} bytes)"
