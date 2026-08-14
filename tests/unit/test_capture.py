from __future__ import annotations

from pathlib import Path

from umat.capture import pcap_has_complete_packet, pcap_header_ready


def test_pcap_header_validation_rejects_size_without_pcap_magic(tmp_path: Path) -> None:
    capture = tmp_path / "invalid.pcap"
    capture.write_bytes(b"not-a-pcap" * 4)
    assert pcap_header_ready(capture) is False


def test_pcap_header_validation_accepts_pcap_and_pcapng(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    for magic in (b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
        capture.write_bytes(magic + b"\0" * 20)
        assert pcap_header_ready(capture) is True


def test_complete_packet_validation_checks_record_payload(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    global_header = b"\xd4\xc3\xb2\xa1" + b"\0" * 20
    packet_header = b"\0" * 8 + (4).to_bytes(4, "little") + (4).to_bytes(4, "little")
    capture.write_bytes(global_header + packet_header + b"test")
    assert pcap_has_complete_packet(capture) is True
    capture.write_bytes(global_header + packet_header + b"no")
    assert pcap_has_complete_packet(capture) is False
