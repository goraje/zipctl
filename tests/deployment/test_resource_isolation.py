"""Hostile fixtures processed in a bounded worker with a parent wall-clock timeout."""

import io
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from zipctl import ZipFile


@pytest.mark.skipif(sys.platform != "linux", reason="Linux RLIMIT_AS worker fixture")
@pytest.mark.parametrize("kind", ["expansion", "forged-size", "metadata", "dictionary"])
def test_hostile_archive_in_bounded_worker(tmp_path: Path, kind: str) -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=14 if kind == "dictionary" else 8) as archive:
        if kind == "metadata":
            archive.comment = b"x" * 9000
        archive.writestr("payload", b"x" * (1024 if kind == "dictionary" else 4 << 20))
    data = bytearray(buffer.getvalue())
    if kind == "forged-size":
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<L", data, 22, 1)
        struct.pack_into("<L", data, central + 24, 1)
    source = tmp_path / "hostile.zip"
    source.write_bytes(data)
    destination = tmp_path / "output"
    worker = Path(__file__).with_name("resource_worker.py")
    completed = subprocess.run(
        [sys.executable, str(worker), str(source), str(destination)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not destination.exists() or list(destination.iterdir()) == []
