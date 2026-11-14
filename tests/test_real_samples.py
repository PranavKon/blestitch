"""Checks against real public sniffer captures.

Skipped unless the files are present; fetch them with
``python scripts/fetch_samples.py``.
"""

from pathlib import Path

import pytest

from blestitch.pipeline import analyze_bytes

DATA = Path(__file__).resolve().parent.parent / "data"


def _analyze(name: str):
    path = DATA / name
    if not path.exists():
        pytest.skip(f"{name} not downloaded (run scripts/fetch_samples.py)")
    return analyze_bytes(path.read_bytes(), source=name)


def test_real_nrf_sniffer_capture():
    a = _analyze("nrf_sniffer_sterzo.pcapng")
    stats = a.result.capture
    assert stats.link_types == ["NORDIC_BLE (272)"]
    assert stats.time_source == "firmware"
    assert stats.n_records == 1305
    assert stats.n_malformed == 0
    # every record is accounted for
    assert stats.n_packets + stats.n_bad_crc + stats.n_data_channel == stats.n_records

    (epoch,) = a.result.epochs
    assert epoch.address == "c9:b3:05:0b:2b:55"
    assert epoch.addr_type == "static"
    assert epoch.local_name == "STERZO"
    assert epoch.pdu_counts == {"ADV_IND": 511, "SCAN_RSP": 62}
    assert epoch.n_scan_req == 62 and epoch.n_connect_ind == 1
    assert 29 < epoch.adv_interval_ms < 32
    assert -60 < epoch.rssi_mean < -30

    # hardware time must be monotonic within the epoch
    ts = [p.t_hw_us for p in a.epochs[0].packets]
    assert ts == sorted(ts)


def test_wireshark_coverage_captures_parse_without_malformed_adv():
    a = _analyze("btle_rf_coverage.pcap.gz")
    assert a.result.capture.link_types == ["BLUETOOTH_LE_LL_WITH_PHDR (256)"]
    assert a.result.capture.n_malformed == 0
    assert {e.local_name for e in a.result.epochs} == {"RF-cov", None}

    a = _analyze("btle_coverage.pcapng.gz")
    assert "NORDIC_BLE (272)" in a.result.capture.link_types
    assert a.result.capture.n_unsupported_link > 0   # it also has a DLT 251 interface
    assert any(e.local_name == "LE-cov" for e in a.result.epochs)
