from __future__ import annotations

import io
from typing import cast

import pytest

from zipctl.cryptography.aes import AesZipDecrypter
from zipctl.cryptography.zipcrypto import ZipCryptoDecrypter
from zipctl.exceptions import PasswordRequired
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream


def _stream(data: bytes = b"") -> ClosableZipStream:
    return cast(
        "ClosableZipStream",
        io.BytesIO(data),  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in
    )


def _make_ext() -> ZipExtFile:
    ext = ZipExtFile.__new__(ZipExtFile)
    ext._close_fileobj = False
    ext._fileobj = _stream()
    return ext


class TestZipExtFileSetupDecrypter:
    def test_aes_missing_password_raises(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra(wz_aes_version=2, wz_aes_strength=3)
        ext._zinfo = zinfo
        ext._pwd = None
        ext.name = "secret.txt"

        with pytest.raises(PasswordRequired, match="password required"):
            ext._setup_decrypter()

    def test_zipcrypto_missing_password_raises(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra()
        ext._zinfo = zinfo
        ext._pwd = None
        ext.name = "secret.txt"

        with pytest.raises(PasswordRequired, match="password required"):
            ext._setup_decrypter()

    def test_aes_branch_reads_header_and_subtracts_hmac(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra(wz_aes_version=2, wz_aes_strength=3)
        ext._zinfo = zinfo
        ext._pwd = b"pw"
        ext.name = "secret.txt"
        ext._fileobj = _stream(b"x" * 128)
        ext._orig_compress_left = 100

        cls = ext._setup_decrypter()

        header_len = AesZipDecrypter.header_length(ext._zinfo)
        assert cls is AesZipDecrypter
        assert len(ext.encryption_header) == header_len
        assert ext._orig_compress_left == (100 - header_len - AesZipDecrypter.hmac_size)

    def test_zipcrypto_branch_reads_header(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra()
        ext._zinfo = zinfo
        ext._pwd = b"pw"
        ext.name = "secret.txt"
        ext._fileobj = _stream(b"x" * 64)
        ext._orig_compress_left = 80

        cls = ext._setup_decrypter()

        assert cls is ZipCryptoDecrypter
        assert len(ext.encryption_header) == 12
        assert ext._orig_compress_left == 80 - 12
