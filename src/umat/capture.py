from __future__ import annotations

import subprocess
import time
from pathlib import Path

PCAP_GLOBAL_HEADER_BYTES = 24
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


def pcap_header_ready(path: Path) -> bool:
    try:
        if path.stat().st_size < PCAP_GLOBAL_HEADER_BYTES:
            return False
        with path.open("rb") as source:
            return source.read(4) in PCAP_MAGICS
    except OSError:
        return False


def pcap_has_complete_packet(path: Path) -> bool:
    """Validate the first classic-PCAP record, including its captured payload."""
    try:
        data = path.read_bytes()
    except OSError:
        return False
    if len(data) < PCAP_GLOBAL_HEADER_BYTES + 16:
        return False
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        byte_order = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        byte_order = ">"
    else:
        # The broker invokes tcpdump's classic-PCAP writer. Do not mistake a
        # pcapng section header for packet evidence.
        return False
    included_length = int.from_bytes(
        data[32:36], byteorder="little" if byte_order == "<" else "big"
    )
    return included_length > 0 and len(data) >= PCAP_GLOBAL_HEADER_BYTES + 16 + included_length


def capture_diagnostic(log_path: Path) -> str:
    try:
        value = log_path.read_bytes()[-2000:].decode(errors="replace").strip()
    except OSError:
        value = ""
    return value or "tcpdump exited without a diagnostic"


def wait_for_pcap_writer(
    process: subprocess.Popen[bytes],
    capture_path: Path,
    log_path: Path,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    """Do not release a guest until its capture writer has opened a valid PCAP."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(
                f"tcpdump failed to start (exit {return_code}): {capture_diagnostic(log_path)}"
            )
        if pcap_header_ready(capture_path):
            return
        time.sleep(0.05)
    raise RuntimeError(
        "tcpdump did not open a valid PCAP before the capture startup deadline: "
        + capture_diagnostic(log_path)
    )
