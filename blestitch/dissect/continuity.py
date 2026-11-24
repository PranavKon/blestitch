"""Apple Continuity message decoding.

Apple devices pack one or more `type | length | data` messages into
manufacturer-specific data under company ID 0x004C. These messages are the
richest source of linking clues for Apple devices: Handoff carries a rolling
sequence number, Nearby Info carries an auth tag, and Proximity Pairing
(AirPods) carries a lid-open counter.

Apple does not publish this format. Field layouts follow public reverse
engineering — Martin et al., "Handoff All Your Privacy" (PETS 2019); Celosia &
Cunche, "Discontinued Privacy" (PETS 2020); Heinrich et al., "Who Can Find My
Devices?" (PETS 2021) — as catalogued by the furiousMAC/continuity project.
Treat decoded names as best-effort; the raw bytes are always kept.
"""

from __future__ import annotations

from dataclasses import dataclass, field

APPLE_COMPANY_ID = 0x004C

OVERFLOW_AREA = 0x01
IBEACON = 0x02
PROXIMITY_PAIRING = 0x07
AIRPLAY_TARGET = 0x09
MAGIC_SWITCH = 0x0B
HANDOFF = 0x0C
TETHERING_SOURCE = 0x0E
NEARBY_ACTION = 0x0F
NEARBY_INFO = 0x10
FIND_MY = 0x12

MESSAGE_NAMES = {
    OVERFLOW_AREA: "Overflow Area",
    IBEACON: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    PROXIMITY_PAIRING: "Proximity Pairing",
    0x08: "Hey Siri",
    AIRPLAY_TARGET: "AirPlay Target",
    0x0A: "AirPlay Source",
    MAGIC_SWITCH: "Magic Switch",
    HANDOFF: "Handoff",
    0x0D: "Tethering Target",
    TETHERING_SOURCE: "Tethering Source",
    NEARBY_ACTION: "Nearby Action",
    NEARBY_INFO: "Nearby Info",
    FIND_MY: "Find My",
}

_NEARBY_INFO_ACTIONS = {
    0x00: "activity level unknown",
    0x01: "activity reporting disabled",
    0x03: "idle user",
    0x05: "audio playing, screen locked",
    0x07: "active user (screen on)",
    0x09: "screen on with video playing",
    0x0A: "watch on wrist and unlocked",
    0x0B: "recent user interaction",
    0x0D: "user driving a vehicle",
    0x0E: "phone or FaceTime call",
}

_NEARBY_ACTION_TYPES = {
    0x01: "Apple TV Setup",
    0x04: "Mobile Backup",
    0x05: "Watch Setup",
    0x06: "Apple TV Pair",
    0x07: "Internet Relay",
    0x08: "Wi-Fi Password",
    0x09: "iOS Setup",
    0x0A: "Repair",
    0x0B: "Speaker Setup",
    0x0C: "Apple Pay",
    0x0D: "Whole Home Audio Setup",
    0x0E: "Developer Tools Pairing Request",
    0x0F: "Answered Call",
    0x10: "Ended Call",
    0x11: "DD Ping",
    0x12: "DD Pong",
    0x13: "Remote Auto Fill",
    0x14: "Companion Link Proximity",
    0x15: "Remote Management",
    0x16: "Remote Auto Fill Pong",
    0x17: "Remote Display",
}

# Proximity Pairing device models, read as the two bytes in transmit order.
_PP_MODELS = {
    0x0220: "AirPods (1st gen)",
    0x0F20: "AirPods (2nd gen)",
    0x1320: "AirPods (3rd gen)",
    0x0E20: "AirPods Pro",
    0x1420: "AirPods Pro (2nd gen)",
    0x0A20: "AirPods Max",
}


@dataclass(slots=True)
class ContinuityMessage:
    type: int
    name: str
    data: bytes
    fields: list[tuple[str, str]] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.fields:
            return self.name
        label, value = self.fields[0]
        return f"{self.name} ({label} {value})"


def parse_continuity(data: bytes) -> list[ContinuityMessage]:
    """Split Apple manufacturer data (after the company ID) into messages.

    A truncated final message is kept with whatever bytes are present, so a
    snaplen-clipped capture still reports which message types were on air.
    """
    out: list[ContinuityMessage] = []
    i, n = 0, len(data)
    while i + 2 <= n:
        if data[i] == OVERFLOW_AREA:
            # No length byte: the rest is a 128-bit bitmap of the services
            # that backgrounded apps are advertising.
            body = data[i + 1 :]
            out.append(
                ContinuityMessage(
                    type=OVERFLOW_AREA,
                    name=MESSAGE_NAMES[OVERFLOW_AREA],
                    data=body,
                    fields=[("service bitmap", body.hex())],
                )
            )
            break
        mtype, length = data[i], data[i + 1]
        body = data[i + 2 : i + 2 + length]
        out.append(
            ContinuityMessage(
                type=mtype,
                name=MESSAGE_NAMES.get(mtype, f"Unknown 0x{mtype:02x}"),
                data=body,
                fields=_decode(mtype, body),
            )
        )
        i += 2 + length
    return out


def _decode(mtype: int, d: bytes) -> list[tuple[str, str]]:
    decoder = _DECODERS.get(mtype)
    if decoder is None:
        return []
    try:
        return decoder(d)
    except IndexError:  # shorter than the documented layout
        return [("raw", d.hex())]


def _ibeacon(d: bytes) -> list[tuple[str, str]]:
    if len(d) < 21:
        return [("raw", d.hex())]
    u = d[0:16].hex()
    uuid = f"{u[0:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}"
    power = d[20] - 256 if d[20] >= 128 else d[20]
    return [
        ("uuid", uuid),
        ("major", str(int.from_bytes(d[16:18], "big"))),
        ("minor", str(int.from_bytes(d[18:20], "big"))),
        ("measured power", f"{power} dBm"),
    ]


def _proximity_pairing(d: bytes) -> list[tuple[str, str]]:
    if d[0] != 0x01:
        # Only the 0x01 form carries plaintext status; other forms (seen from
        # paired AirPods near their owner) are opaque.
        return [("form", f"0x{d[0]:02x}"), ("encrypted", d[1:].hex())]
    model = (d[1] << 8) | d[2]
    out = [
        ("model", _PP_MODELS.get(model, f"0x{model:04x}")),
        ("status", f"0x{d[3]:02x}"),
        ("pod battery nibbles", f"{d[4] >> 4}/{d[4] & 0x0F} (x10%, 15 = unknown)"),
        ("case battery nibble", f"{d[5] & 0x0F} (x10%, 15 = unknown)"),
        ("charging flags", f"0x{d[5] >> 4:x}"),
        ("lid open counter", str(d[6])),
        ("color", f"0x{d[7]:02x}"),
    ]
    if len(d) > 9:
        out.append(("encrypted", d[9:].hex()))
    return out


def _airplay_target(d: bytes) -> list[tuple[str, str]]:
    return [
        ("ipv4", ".".join(str(b) for b in d[2:6])),
        ("flags", f"0x{d[0]:02x}"),
        ("config seed", f"0x{d[1]:02x}"),
    ] + ([("rest", d[6:].hex())] if len(d) > 6 else [])


def _magic_switch(d: bytes) -> list[tuple[str, str]]:
    return [("data", d[0:2].hex()), ("wrist confidence", f"0x{d[2]:02x}")]


def _handoff(d: bytes) -> list[tuple[str, str]]:
    return [
        # Byte order of the counter is not documented; kept as transmitted.
        ("sequence (IV)", d[1:3].hex()),
        ("clipboard", "copy/cut pending" if d[0] else "none"),
        ("auth tag", d[3:4].hex()),
        ("encrypted", d[4:].hex()),
    ]


def _tethering_source(d: bytes) -> list[tuple[str, str]]:
    return [
        ("battery", f"{d[2]}%"),
        ("version", f"0x{d[0]:02x}"),
        ("flags", f"0x{d[1]:02x}"),
        ("cell type", d[3:5].hex()),
        ("cell bars", str(d[5])),
    ]


def _nearby_action(d: bytes) -> list[tuple[str, str]]:
    out = [
        ("action", _NEARBY_ACTION_TYPES.get(d[1], f"0x{d[1]:02x}")),
        ("flags", f"0x{d[0]:02x}"),
    ]
    if len(d) >= 5:
        out.append(("auth tag", d[2:5].hex()))
    if len(d) > 5:
        out.append(("parameters", d[5:].hex()))
    return out


def _nearby_info(d: bytes) -> list[tuple[str, str]]:
    action = d[0] & 0x0F
    status = d[0] >> 4
    flags = d[1]
    out = [
        ("activity", _NEARBY_INFO_ACTIONS.get(action, f"0x{action:x}")),
        ("status flags", f"0x{status:x}"),
        ("data flags", f"0x{flags:02x}"),
    ]
    tag_len = 4 if flags & 0x02 else 3
    if len(d) >= 2 + tag_len:
        out.append(("auth tag", d[2 : 2 + tag_len].hex()))
        if len(d) > 2 + tag_len:
            out.append(("post-tag data", d[2 + tag_len :].hex()))
    elif len(d) > 2:
        out.append(("auth tag", d[2:].hex()))
    return out


def _find_my(d: bytes) -> list[tuple[str, str]]:
    status = d[0]
    out = [("status", f"0x{status:02x}")]
    if len(d) >= 25:
        out += [
            ("public key bytes 6-27", d[1:23].hex()),
            ("public key bits", f"0x{d[23]:02x}"),
            ("hint", f"0x{d[24]:02x}"),
        ]
    elif len(d) > 1:
        out.append(("data", d[1:].hex()))
    return out


_DECODERS = {
    IBEACON: _ibeacon,
    PROXIMITY_PAIRING: _proximity_pairing,
    AIRPLAY_TARGET: _airplay_target,
    MAGIC_SWITCH: _magic_switch,
    HANDOFF: _handoff,
    TETHERING_SOURCE: _tethering_source,
    NEARBY_ACTION: _nearby_action,
    NEARBY_INFO: _nearby_info,
    FIND_MY: _find_my,
}
