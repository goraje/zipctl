from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import zipctl
from zipctl.exceptions import BadPassword


def test_mixed_per_entry_encryption_and_passwords(tmp_path: Path) -> None:
    archive = tmp_path / "mixed.zip"
    with zipctl.ZipFile(archive, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(b"default")
        zf.writestr("default.txt", b"default")
        zf.writestr("public.txt", b"public", encryption=None)
        # ZipCrypto checks a single header byte, so a wrong password can slip
        # through 1 time in 256 and fail later as a CRC error.  Fix the random
        # header bytes so the wrong-password read below is deterministic.
        with patch(
            "zipctl.cryptography.zipcrypto.os.urandom", return_value=b"\x00" * 11
        ):
            zf.writestr(
                "legacy.txt",
                b"legacy",
                encryption=zipctl.ZIP_CRYPTO,
                password=b"legacy-password",
            )
        zf.writestr(
            "private.txt",
            b"private",
            encryption=zipctl.WZ_AES,
            password=b"private-password",
            extra=zipctl.ZipFileExtra(force_wz_aes_version=1),
        )

    with zipctl.ZipFile(archive) as zf:
        zf.setpassword(b"default")
        assert zf.read("default.txt") == b"default"
        assert zf.read("public.txt") == b"public"
        assert zf.read("legacy.txt", pwd=b"legacy-password") == b"legacy"
        assert zf.read("private.txt", pwd=b"private-password") == b"private"
        with pytest.raises(BadPassword):
            zf.read("legacy.txt")


def test_inherit_encryption_sentinel_is_explicit(tmp_path: Path) -> None:
    archive = tmp_path / "inherit.zip"
    with zipctl.ZipFile(archive, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(b"password")
        zf.writestr(
            "inherited.txt",
            b"payload",
            encryption=zipctl.INHERIT_ENCRYPTION,
        )

    with zipctl.ZipFile(archive) as zf:
        zf.setpassword(b"password")
        assert zf.read("inherited.txt") == b"payload"
