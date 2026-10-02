"""Derived WZ-AES keys are reused within one archive, and only then."""

from __future__ import annotations

import io
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import zipctl
from zipctl import ZipFile
from zipctl.cryptography import aes
from zipctl.cryptography.aes import AesKeyCache, AesZipDecrypter
from zipctl.exceptions import BadPassword
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.password import PasswordStatus

PASSWORD = b"correct horse"
DATA = b"payload " * 500


def test_negative_cache_size_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        AesKeyCache(-1)


@pytest.fixture
def archive() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("a.txt", DATA)
        zf.writestr("b.txt", DATA)
    return buffer.getvalue()


@pytest.fixture
def derivations(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The salt of every PBKDF2 run from now on."""
    salts: list[bytes] = []

    def counting(
        *, algorithm: hashes.HashAlgorithm, length: int, salt: bytes, iterations: int
    ) -> PBKDF2HMAC:
        salts.append(salt)
        return PBKDF2HMAC(
            algorithm=algorithm, length=length, salt=salt, iterations=iterations
        )

    monkeypatch.setattr(aes, "PBKDF2HMAC", counting)
    return salts


def test_checking_a_password_and_then_reading_derives_the_key_once(
    archive: bytes, derivations: list[bytes]
) -> None:
    with ZipFile(io.BytesIO(archive)) as zf:
        result = zf.check_password(PASSWORD, members=["a.txt"])
        assert result.members[0].status is PasswordStatus.ACCEPTED
        assert zf.read("a.txt", pwd=PASSWORD) == DATA
    assert len(derivations) == 1


def test_seeking_backwards_does_not_derive_again(
    archive: bytes, derivations: list[bytes]
) -> None:
    with ZipFile(io.BytesIO(archive)) as zf, zf.open("a.txt", pwd=PASSWORD) as stream:
        assert stream.read() == DATA  # past the read buffer, so a seek replays
        stream.seek(0)
        assert stream.read(8) == DATA[:8]
    assert len(derivations) == 1


def test_each_member_has_its_own_salt_so_each_is_derived(
    archive: bytes, derivations: list[bytes]
) -> None:
    with ZipFile(io.BytesIO(archive)) as zf:
        zf.read("a.txt", pwd=PASSWORD)
        zf.read("b.txt", pwd=PASSWORD)
        zf.read("a.txt", pwd=PASSWORD)
    assert len(derivations) == 2


def test_a_wrong_password_is_derived_every_time_and_never_cached(
    archive: bytes, derivations: list[bytes]
) -> None:
    with ZipFile(io.BytesIO(archive)) as zf:
        for _ in range(2):
            with pytest.raises(BadPassword):
                zf.read("a.txt", pwd=b"wrong")
        assert zf.read("a.txt", pwd=PASSWORD) == DATA
    assert len(derivations) == 3


def test_a_cached_key_is_still_checked_against_the_header_verifier(
    archive: bytes,
) -> None:
    """Same password and salt but another verifier: rejected, not trusted."""
    with ZipFile(io.BytesIO(archive)) as zf, zf.open("a.txt", pwd=PASSWORD) as stream:
        header = cast("ZipExtFile", stream).encryption_header  # pyright: ignore[reportInvalidCast]  # open() is typed IO[bytes]
        info = zf.getinfo("a.txt")
    cache = AesKeyCache()
    AesZipDecrypter(info, PASSWORD, header, cache)
    AesZipDecrypter(info, PASSWORD, header, cache)  # a hit is accepted
    forged = header[:-1] + bytes([header[-1] ^ 0xFF])
    with pytest.raises(BadPassword):
        AesZipDecrypter(info, PASSWORD, forged, cache)


def test_closing_the_archive_forgets_the_keys(
    archive: bytes, derivations: list[bytes]
) -> None:
    zf = ZipFile(io.BytesIO(archive))
    zf.read("a.txt", pwd=PASSWORD)
    zf.close()
    assert zf._reader.keys.get(PASSWORD, derivations[0], 66) is None


def test_the_cache_keeps_only_the_most_recently_used_entries() -> None:
    cache = AesKeyCache(maxsize=2)
    cache.put(b"p", b"1", 66, b"k1")
    cache.put(b"p", b"2", 66, b"k2")
    assert cache.get(b"p", b"1", 66) == b"k1"  # refreshed: "2" is now the oldest
    cache.put(b"p", b"3", 66, b"k3")
    assert cache.get(b"p", b"2", 66) is None
    assert cache.get(b"p", b"1", 66) == b"k1"
    assert cache.get(b"p", b"3", 66) == b"k3"
