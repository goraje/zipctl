from __future__ import annotations

import io
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
        assert zf.getinfo("inherited.txt").aes_bits == 256
        zf.setpassword(b"password")
        assert zf.read("inherited.txt") == b"payload"


@pytest.mark.parametrize("encryption", [zipctl.ZIP_CRYPTO, zipctl.WZ_AES])
def test_directory_entries_do_not_inherit_archive_encryption(encryption: str) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w", encryption=encryption) as zf:
        zf.setpassword(b"password")
        zf.writestr("plain/", b"")
        zf.writestr("locked/", b"", encryption=encryption)
        zf.mkdir("made")
        with pytest.raises(ValueError, match="unencrypted entry"):
            zf.writestr("refused/", b"", password=b"other")

    with zipctl.ZipFile(buffer) as zf:
        assert zf.namelist() == ["plain/", "locked/", "made/"]
        assert not zf.getinfo("plain/").is_encrypted
        assert not zf.getinfo("made/").is_encrypted
        assert zf.getinfo("locked/").is_encrypted


@pytest.mark.parametrize("encryption", [zipctl.ZIP_CRYPTO, zipctl.WZ_AES])
def test_empty_entry_password_is_rejected(encryption: str) -> None:
    with zipctl.ZipFile(io.BytesIO(), "w", encryption=encryption) as zf:
        with pytest.raises(ValueError, match="non-empty password"):
            zf.writestr("x", b"y", password=b"")
        assert zf.namelist() == []
