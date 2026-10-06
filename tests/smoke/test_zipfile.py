"""Smoke tests for ZipFile round-trips.

Covers write/read behavior across encryption and compression combinations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import zipctl
from zipctl.compression.zstd import compression_entry as zstd_entry

PASSWORD = b"ruhsuc-6wazmI-xicbib"
CONTENT = "This is a test file."

COMPRESSIONS = [
    pytest.param(zipctl.ZIP_STORED, id="ZIP_STORED"),
    pytest.param(zipctl.ZIP_DEFLATED, id="ZIP_DEFLATED"),
    pytest.param(zipctl.ZIP_BZIP2, id="ZIP_BZIP2"),
    pytest.param(zipctl.ZIP_LZMA, id="ZIP_LZMA"),
    pytest.param(
        zipctl.ZIP_ZSTANDARD,
        id="ZIP_ZSTANDARD",
        marks=pytest.mark.skipif(
            zstd_entry is None,
            reason="zstandard backend is unavailable",
        ),
    ),
]

# Columns: encryption on write, encryption on read, whether a password is needed.
ENCRYPTIONS = [
    pytest.param(None, None, False, id="None"),
    pytest.param(zipctl.WZ_AES, zipctl.WZ_AES, True, id="WZ_AES"),
    pytest.param(zipctl.ZIP_CRYPTO, None, True, id="ZipCrypto"),
]


@pytest.mark.parametrize("compression", COMPRESSIONS)
@pytest.mark.parametrize(("enc_write", "enc_read", "needs_pwd"), ENCRYPTIONS)
def test_round_trip(
    tmp_path: Path,
    compression: int,
    enc_write: str | None,
    enc_read: str | None,
    needs_pwd: bool,
) -> None:
    path = tmp_path / "test.zip"

    with zipctl.ZipFile(
        path,
        "w",
        compression=compression,
        encryption=enc_write,
    ) as zf:
        if needs_pwd:
            zf.setpassword(PASSWORD)
        zf.writestr("test.txt", CONTENT)

    with zipctl.ZipFile(path, "r", encryption=enc_read) as zf:
        if needs_pwd:
            zf.setpassword(PASSWORD)
        result = zf.read("test.txt").decode()

    assert result == CONTENT
