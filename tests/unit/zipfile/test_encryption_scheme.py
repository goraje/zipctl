"""The encryption scheme of an entry, seen through ZipFile alone."""

from __future__ import annotations

import io
import struct

import pytest

import zipctl
from tests.helpers import NonSeekableBytesIO
from zipctl import ZipFile, ZipFileExtra
from zipctl.exceptions import BadPassword, BadZipFile, PasswordRequired
from zipctl.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    MASK_ENCRYPTED,
    MASK_USE_DATA_DESCRIPTOR,
)

PASSWORD = b"password"
PAYLOAD = b"scheme payload " * 4


def _aes_archive(nbits: int = 256, version: int | None = None) -> bytes:
    buffer = io.BytesIO()
    extra = ZipFileExtra(force_wz_aes_version=version, wz_aes_nbits=nbits)
    with ZipFile(buffer, "w", encryption=zipctl.WZ_AES, extra=extra) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("f", PAYLOAD)
    return buffer.getvalue()


def _read(archive: bytes) -> bytes:
    with ZipFile(io.BytesIO(archive)) as zf:
        return zf.read("f", pwd=PASSWORD)


def _set_crc(archive: bytearray, crc: int) -> None:
    central = archive.index(CENTRAL_DIR_SIGNATURE)
    struct.pack_into("<L", archive, 14, crc)
    struct.pack_into("<L", archive, central + 16, crc)


@pytest.mark.parametrize(("nbits", "strength"), [(128, 1), (192, 2), (256, 3)])
@pytest.mark.parametrize(
    ("version", "written", "stores_crc"),
    [(None, zipctl.WZ_AES_V2, False), (1, 1, True), (2, 2, False)],
)
def test_an_aes_entry_reads_back_its_settings(
    nbits: int, strength: int, version: int | None, written: int, stores_crc: bool
) -> None:
    archive = _aes_archive(nbits, version)
    with ZipFile(io.BytesIO(archive)) as zf:
        info = zf.infolist()[0]
    assert info.aes_extra is not None
    assert (
        info.aes_extra.wz_aes_version,
        info.aes_extra.wz_aes_vendor_id,
        info.aes_extra.wz_aes_strength,
    ) == (written, b"AE", strength)
    assert (info.encryption_scheme, info.aes_bits, info.stores_crc) == (
        zipctl.WZ_AES,
        nbits,
        stores_crc,
    )
    central = archive.index(CENTRAL_DIR_SIGNATURE)
    assert struct.unpack_from("<H", archive, 8) == (99,)
    assert struct.unpack_from("<H", archive, central + 10) == (99,)
    assert _read(archive) == PAYLOAD


@pytest.mark.parametrize("sink", [io.BytesIO, NonSeekableBytesIO])
def test_a_zipcrypto_entry_uses_a_data_descriptor(sink: type[io.BytesIO]) -> None:
    buffer = sink()
    with ZipFile(buffer, "w", encryption=zipctl.ZIP_CRYPTO) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("f", PAYLOAD)
    archive = buffer.getvalue()
    with ZipFile(io.BytesIO(archive)) as zf:
        info = zf.infolist()[0]
    assert info.flag_bits & MASK_USE_DATA_DESCRIPTOR
    assert (info.encryption_scheme, info.aes_extra, info.stores_crc) == (
        zipctl.ZIP_CRYPTO,
        None,
        True,
    )
    assert _read(archive) == PAYLOAD


def test_an_aes_1_entry_checks_its_crc() -> None:
    archive = bytearray(_aes_archive(version=1))
    _set_crc(archive, 0x12345678)
    with pytest.raises(BadZipFile, match="Bad CRC-32"):
        _read(bytes(archive))


def test_an_aes_2_entry_ignores_its_crc_field() -> None:
    archive = bytearray(_aes_archive(version=2))
    _set_crc(archive, 0x12345678)
    assert _read(bytes(archive)) == PAYLOAD


def test_the_hmac_is_checked_before_the_crc() -> None:
    archive = bytearray(_aes_archive(version=1))
    name_length, extra_length = struct.unpack_from("<HH", archive, 26)
    salt_and_verifier = 18  # AES-256
    archive[30 + name_length + extra_length + salt_and_verifier] ^= 0xFF
    with pytest.raises(BadZipFile, match="Bad HMAC"):
        _read(bytes(archive))


def test_a_zipcrypto_entry_checks_its_crc() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=zipctl.ZIP_CRYPTO) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("f", PAYLOAD)
    archive = bytearray(buffer.getvalue())
    name_length, extra_length = struct.unpack_from("<HH", archive, 26)
    archive[30 + name_length + extra_length + 12] ^= 0xFF  # past the header
    with pytest.raises(BadZipFile, match="Bad CRC-32"):
        _read(bytes(archive))


@pytest.mark.parametrize("encryption", [zipctl.ZIP_CRYPTO, zipctl.WZ_AES])
def test_encryption_adds_its_flags_to_the_entry_s_own(encryption: str) -> None:
    def flags(encryption: str | None) -> int:
        buffer = io.BytesIO()
        with ZipFile(buffer, "w", zipctl.ZIP_LZMA, encryption=encryption) as zf:
            zf.setpassword(PASSWORD)
            zf.writestr("ünïcode", PAYLOAD)
        with ZipFile(buffer) as zf:
            return zf.infolist()[0].flag_bits

    plain = flags(None)
    added = MASK_ENCRYPTED
    if encryption == zipctl.ZIP_CRYPTO:
        added |= MASK_USE_DATA_DESCRIPTOR
    assert plain & ~MASK_USE_DATA_DESCRIPTOR  # the name and LZMA flags
    assert flags(encryption) == plain | added


@pytest.mark.parametrize("encryption", [zipctl.ZIP_CRYPTO, zipctl.WZ_AES])
def test_password_errors_name_the_entry(
    encryption: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # fixed random bytes: a wrong password then never passes the header check
    monkeypatch.setattr("os.urandom", bytes)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=encryption) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("f", PAYLOAD)
    with ZipFile(buffer) as zf:
        with pytest.raises(BadPassword, match="Bad password for file 'f'"):
            zf.read("f", pwd=b"wrong")
        with pytest.raises(PasswordRequired, match="File 'f' is encrypted"):
            zf.read("f")
