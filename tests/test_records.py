from blestitch.records import AddrType, classify_address


def test_public_when_not_random():
    assert classify_address(0x00AABBCCDDEE, random=False) is AddrType.PUBLIC


def test_resolvable_top_bits_01():
    # 0x7A.. -> top byte 0b0111_1010 -> top two bits 01
    assert classify_address(0x7A1122334455, random=True) is AddrType.RESOLVABLE


def test_non_resolvable_top_bits_00():
    # 0x3A.. -> top byte 0b0011_1010 -> top two bits 00
    assert classify_address(0x3A1122334455, random=True) is AddrType.NON_RESOLVABLE


def test_static_top_bits_11():
    # 0xFA.. -> top byte 0b1111_1010 -> top two bits 11
    assert classify_address(0xFA1122334455, random=True) is AddrType.STATIC


def test_reserved_top_bits_10_is_unknown():
    # 0xBA.. -> top byte 0b1011_1010 -> top two bits 10 (reserved)
    assert classify_address(0xBA1122334455, random=True) is AddrType.UNKNOWN
