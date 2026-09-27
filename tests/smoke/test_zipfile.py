"""Smoke tests for ZipFile round-trips.

Covers write/read behavior across encryption and compression combinations.
"""

from __future__ import annotations

import sys
import zipfile as _stdlib_zipfile
from pathlib import Path
from unittest import mock

import pytest

import zipctl

PASSWORD = b"Cefzuj-hetveg-xifve5"
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
            sys.version_info < (3, 14),
            reason="zstandard tests require Python >= 3.14",
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


def test_zip64_eocd_round_trip(tmp_path: Path) -> None:
    """Create a ZIP64 archive with stdlib (via patched ZIP64_LIMIT) and read it."""
    path = tmp_path / "zip64.zip"
    with mock.patch.object(_stdlib_zipfile, "ZIP64_LIMIT", -1):
        with _stdlib_zipfile.ZipFile(path, "w", allowZip64=True) as zf:
            zf.writestr("test.txt", CONTENT)

    with zipctl.ZipFile(path, "r") as zf:
        assert zf.read("test.txt").decode() == CONTENT
