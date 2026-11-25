import json

from fixtures import make_capture, make_rotation_capture

from blestitch.cli import main


def test_cli_prints_trails(tmp_path, capsys):
    capture, _ = make_rotation_capture(minutes=6)
    path = tmp_path / "walk.pcapng"
    path.write_bytes(capture)

    assert main([str(path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("walk.pcapng: 6 min 0 s, ")
    assert "NORDIC_BLE (272)" in out
    assert "5 devices (estimated) · 5 trails · " in out
    assert " rotations linked" in out
    header = next(line for line in out.splitlines() if line.startswith("TRAIL"))
    assert header.split() == ["TRAIL", "TYPE", "ADDRS", "FIRST", "SEEN", "SPAN", "PACKETS", "WEAKEST", "LINK", "IDENTITY"]
    assert any(line.startswith("D1 ") and "Find My" in line for line in out.splitlines())
    assert "“Band-42”" in out


def test_cli_writes_json(tmp_path, capsys):
    path = tmp_path / "cap.pcap"
    path.write_bytes(make_capture())
    out_path = tmp_path / "result.json"

    assert main([str(path), "--json", str(out_path)]) == 0
    result = json.loads(out_path.read_text())
    # four addresses, two of them one device before and after a rotation
    assert result["n_epochs"] == 4 and len(result["tracks"]) == 3
    assert str(out_path) in capsys.readouterr().out


def test_cli_max_gap_option(tmp_path, capsys):
    path = tmp_path / "cap.pcap"
    path.write_bytes(make_capture())
    assert main([str(path), "--max-gap", "0.05"]) == 0
    assert "8 address epochs" in capsys.readouterr().out


def test_cli_reports_unreadable_input(tmp_path, capsys):
    bad = tmp_path / "notes.txt"
    bad.write_bytes(b"this is not a capture file, not even close")
    assert main([str(bad)]) == 1
    assert "not a capture this can read" in capsys.readouterr().err

    assert main([str(tmp_path / "missing.pcapng")]) == 1
    assert "cannot read" in capsys.readouterr().err
