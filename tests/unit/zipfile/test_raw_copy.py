"""Copying compressed member data into another archive, without compressing it."""

from __future__ import annotations

import io
import random
import struct
import zlib
from typing import NoReturn, cast

import pytest

import zipctl
from zipctl import ZipFile
from zipctl.compression import registry
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.info import ZipInfo

PASSWORD = b"correct horse"
OTHER = b"staple"
_RANDOM = random.Random(7)
# Text with enough structure that level 9 and the default level give different bytes.
DATA = b" ".join(
    bytes(_RANDOM.choices(b"abcdefghij", k=_RANDOM.randint(2, 30))) for _ in range(3000)
)
CRC = zlib.crc32(DATA)
DATA_SIZE = len(DATA)

# name -> (scheme, AES version); the password is PASSWORD for every encrypted one
PROTECTIONS: dict[str, tuple[str | None, int | None]] = {
    "plain": (None, None),
    "zipcrypto": (zipctl.ZIP_CRYPTO, None),
    "aes1": (zipctl.WZ_AES, 1),
    "aes2": (zipctl.WZ_AES, 2),
}


def make(
    protection: str, compression: int = zipctl.ZIP_DEFLATED, level: int = 9
) -> bytes:
    scheme, version = PROTECTIONS[protection]
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=compression, compresslevel=level) as zf:
        info = ZipInfo("f.bin", (2020, 1, 2, 3, 4, 6))
        info.compress_type = compression
        info.compress_level = level
        zf.writestr(
            info,
            DATA,
            encryption=scheme,
            password=PASSWORD if scheme else None,
            extra=zipctl.ZipFileExtra(force_wz_aes_version=version)
            if version
            else None,
        )
    return buffer.getvalue()


def flip_data_byte(archive: bytes, offset: int) -> bytes:
    """*archive* with one bit changed *offset* bytes into the only member's data."""
    with ZipFile(io.BytesIO(archive)) as zf:
        info = zf.infolist()[0]
    name_size, extra_size = struct.unpack_from("<HH", archive, info.header_offset + 26)
    data = bytearray(archive)
    data[info.header_offset + 30 + name_size + extra_size + offset] ^= 1
    return bytes(data)


def payload(zf: ZipFile, pwd: bytes | None) -> bytes:
    """The compressed bytes of the only member, decrypted."""
    reader = cast(ZipExtFile, zf.open("f.bin", "r", pwd))  # pyright: ignore[reportInvalidCast]  # open() is typed IO[bytes]
    return b"".join(reader._raw_chunks())


def copy(source: bytes, target: str, *, crc: int = CRC, size: int = DATA_SIZE) -> bytes:
    scheme, version = PROTECTIONS[target]
    out = io.BytesIO()
    with ZipFile(io.BytesIO(source)) as src, ZipFile(out, "w") as dst:
        info = src.infolist()[0]
        new = ZipInfo(info.filename, info.date_time)
        dst._copy_raw(
            src,
            info,
            new,
            crc=crc,
            size=size,
            pwd=PASSWORD,
            encryption=scheme,
            password=OTHER if scheme else None,
            extra=zipctl.ZipFileExtra(force_wz_aes_version=version)
            if version
            else None,
        )
    return out.getvalue()


@pytest.mark.parametrize("target", PROTECTIONS)
@pytest.mark.parametrize("source", PROTECTIONS)
def test_the_compressed_data_survives_any_change_of_protection(
    source: str, target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = make(source)

    def no_compressor(
        _compress_type: int, _compresslevel: int | None = None
    ) -> NoReturn:
        raise AssertionError("a raw copy must not compress")

    monkeypatch.setattr(registry, "get_compressor", no_compressor)
    copied = copy(original, target)
    monkeypatch.undo()
    with ZipFile(io.BytesIO(original)) as before, ZipFile(io.BytesIO(copied)) as after:
        assert payload(after, OTHER if PROTECTIONS[target][0] else None) == payload(
            before, PASSWORD if PROTECTIONS[source][0] else None
        )
        assert after.read("f.bin", OTHER if PROTECTIONS[target][0] else None) == DATA
        if PROTECTIONS[target][0] is None:
            assert after.testzip() is None
        info = after.infolist()[0]
        assert info.file_size == len(DATA)
        assert bool(info.is_encrypted) == (PROTECTIONS[target][0] is not None)


def test_the_directory_carries_the_crc_except_for_aes_2() -> None:
    for target, expected in (("plain", CRC), ("aes1", CRC), ("aes2", 0)):
        with ZipFile(io.BytesIO(copy(make("plain"), target))) as zf:
            assert zf.infolist()[0].CRC == expected


def test_a_corrupt_member_is_copied_as_it_is_and_still_reported_later() -> None:
    copied = copy(flip_data_byte(make("plain"), 60), "plain")
    with ZipFile(io.BytesIO(copied)) as zf:
        with pytest.raises((BadZipFile, zlib.error)):
            zf.read("f.bin")


def test_a_tampered_aes_member_is_refused() -> None:
    tampered = flip_data_byte(make("aes2"), 100)  # past the salt, inside the ciphertext
    with pytest.raises(BadZipFile, match="HMAC"):
        copy(tampered, "plain")


def test_the_wrong_password_is_refused() -> None:
    with ZipFile(io.BytesIO(make("aes2"))) as src, ZipFile(io.BytesIO(), "w") as dst:
        info = src.infolist()[0]
        with pytest.raises(zipctl.BadPassword):
            dst._copy_raw(
                src, info, ZipInfo("f.bin"), crc=0, size=len(DATA), pwd=b"nope"
            )


@pytest.mark.parametrize("compression", [zipctl.ZIP_BZIP2, zipctl.ZIP_LZMA])
def test_other_compression_methods_are_copied_too(compression: int) -> None:
    copied = copy(make("plain", compression, level=6), "aes2")
    with ZipFile(io.BytesIO(copied)) as zf:
        assert zf.infolist()[0].compress_type == compression
        assert zf.read("f.bin", OTHER) == DATA


def test_the_compression_option_bits_come_from_the_source() -> None:
    source = make("plain", zipctl.ZIP_LZMA, level=6)
    out = io.BytesIO()
    with ZipFile(io.BytesIO(source)) as src, ZipFile(out, "w") as dst:
        info = src.infolist()[0]
        assert info.flag_bits & 0b010  # this writer sets the LZMA end-marker bit
        info.flag_bits = (info.flag_bits & ~0b010) | 0b100
        dst._copy_raw(src, info, ZipInfo("f.bin"), crc=CRC, size=len(DATA))
    with ZipFile(io.BytesIO(out.getvalue())) as zf:
        assert zf.infolist()[0].flag_bits & 0b110 == 0b100


def test_a_raw_entry_takes_raw_writes_only() -> None:
    with ZipFile(io.BytesIO(), "w") as zf:
        zinfo = ZipInfo("a")
        zinfo.file_size = zinfo.CRC = 0
        raw = zf._open_to_write(zinfo, raw=True)
        with pytest.raises(ValueError, match="_write_raw"):
            raw.write(b"x")
        raw.close()
        plain = zf._open_to_write(ZipInfo("b"))
        with pytest.raises(ValueError, match="raw entry"):
            plain._write_raw(b"x")
        plain.close()
