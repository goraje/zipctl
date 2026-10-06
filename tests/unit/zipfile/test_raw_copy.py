"""Copying compressed member data into another archive, without compressing it."""

from __future__ import annotations

import copy as copy_module
import gc
import io
import random
import struct
import zlib
from collections.abc import Generator
from typing import NoReturn, cast

import pytest
from typing_extensions import override

import zipctl
from tests.helpers import NonSeekableBytesIO
from zipctl import ZipFile
from zipctl.compression import registry
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.file.ext import ZipExtFile
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
    return b"".join(reader.raw_chunks())


def copy(source: bytes, target: str) -> bytes:
    scheme, version = PROTECTIONS[target]
    out = io.BytesIO()
    with ZipFile(io.BytesIO(source)) as src, ZipFile(out, "w") as dst:
        result = dst.copy_member(
            src,
            src.infolist()[0],
            pwd=PASSWORD,
            encryption=scheme,
            password=OTHER if scheme else None,
            extra=zipctl.ZipFileExtra(force_wz_aes_version=version)
            if version
            else None,
        )
        assert result.raw
        assert (result.crc, result.size) == (CRC, DATA_SIZE)
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


def test_a_corrupt_member_is_refused_before_it_is_copied() -> None:
    out = io.BytesIO()
    with ZipFile(io.BytesIO(flip_data_byte(make("plain"), 60))) as src:
        with ZipFile(out, "w") as dst, pytest.raises(BadZipFile):
            dst.copy_member(src, src.infolist()[0])
    with ZipFile(out) as written:
        assert written.namelist() == []  # nothing half-copied


def test_a_tampered_aes_member_is_refused() -> None:
    tampered = flip_data_byte(make("aes2"), 100)  # past the salt, inside the ciphertext
    # Read in full before copying: the damage shows in the data or the HMAC.
    with pytest.raises(BadZipFile, match="HMAC|Invalid DEFLATE"):
        copy(tampered, "plain")


def test_the_wrong_password_is_refused() -> None:
    with ZipFile(io.BytesIO(make("aes2"))) as src, ZipFile(io.BytesIO(), "w") as dst:
        info = src.infolist()[0]
        with pytest.raises(zipctl.BadPassword):
            dst.copy_member(src, info, pwd=b"nope")


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
        dst.copy_member(src, info)
    with ZipFile(io.BytesIO(out.getvalue())) as zf:
        assert zf.infolist()[0].flag_bits & 0b110 == 0b100


def test_a_raw_entry_takes_raw_writes_only() -> None:
    with ZipFile(io.BytesIO(), "w") as zf:
        zinfo = ZipInfo("a")
        zinfo.file_size = zinfo.CRC = 0
        raw = zf._writer.open(zinfo, raw=True)
        with pytest.raises(ValueError, match="write_raw"):
            raw.write(b"x")
        raw.close()
        plain = zf._writer.open(ZipInfo("b"))
        with pytest.raises(ValueError, match="raw entry"):
            plain.write_raw(b"x")
        plain.close()


@pytest.mark.parametrize("protection", ["zipcrypto", "aes1", "aes2"])
def test_keep_encryption_copies_the_stored_bytes_without_the_password(
    protection: str,
) -> None:
    original = make(protection)
    out = io.BytesIO()
    with ZipFile(io.BytesIO(original)) as src, ZipFile(out, "w") as dst:
        result = dst.copy_member(src, "f.bin", keep_encryption=True)
    assert result.raw
    with ZipFile(io.BytesIO(original)) as before, ZipFile(out) as after:
        old, new = before.getinfo("f.bin"), after.getinfo("f.bin")
        assert (new.CRC, new.compress_size, new.flag_bits) == (
            old.CRC,
            old.compress_size,
            old.flag_bits,
        )
        assert after.read("f.bin", PASSWORD) == DATA


def test_keep_encryption_cannot_also_recompress() -> None:
    with ZipFile(io.BytesIO(make("aes2"))) as src, ZipFile(io.BytesIO(), "w") as dst:
        with pytest.raises(ValueError, match="keep_encryption"):
            dst.copy_member(
                src, "f.bin", keep_encryption=True, compress_type=zipctl.ZIP_STORED
            )


def test_keep_encryption_cannot_also_change_the_aes_settings() -> None:
    with ZipFile(io.BytesIO(make("aes2"))) as src, ZipFile(io.BytesIO(), "w") as dst:
        with pytest.raises(ValueError, match="keep_encryption"):
            dst.copy_member(
                src,
                "f.bin",
                keep_encryption=True,
                extra=zipctl.ZipFileExtra(wz_aes_nbits=128),
            )
        assert dst.namelist() == []


@pytest.mark.parametrize("protection", ["aes1", "aes2"])
def test_keep_encryption_copies_aes_into_an_unseekable_archive(protection: str) -> None:
    out = NonSeekableBytesIO()
    with ZipFile(io.BytesIO(make(protection))) as src, ZipFile(out, "w") as dst:
        result = dst.copy_member(src, "f.bin", keep_encryption=True)
    assert result.crc == (None if protection == "aes2" else CRC)
    with ZipFile(io.BytesIO(out.getvalue())) as zf:
        assert zf.read("f.bin", PASSWORD) == DATA


def test_keep_encryption_refuses_zipcrypto_into_an_unseekable_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with (
        ZipFile(io.BytesIO(make("zipcrypto"))) as src,
        ZipFile(NonSeekableBytesIO(), "w") as dst,
    ):
        info = copy_module.copy(src.getinfo("f.bin"))
        info.flag_bits &= ~0x08  # as if written without a data descriptor

        def no_chunks(_info: ZipInfo) -> Generator[bytes, None, None]:
            yield from ()

        monkeypatch.setattr(src, "stored_chunks", no_chunks)
        with pytest.raises(ValueError, match="ZipCrypto"):
            dst.copy_member(src, info, keep_encryption=True)


@pytest.mark.parametrize("stream", [io.BytesIO, NonSeekableBytesIO])
def test_a_corrupt_member_is_refused_when_compressed_again(
    stream: type[io.BytesIO],
) -> None:
    out = stream()
    # stored, so the damage only shows in the CRC at the very end
    source = flip_data_byte(make("plain", zipctl.ZIP_STORED), 5000)
    with ZipFile(io.BytesIO(source)) as src:
        with ZipFile(out, "w") as dst:
            dst.writestr("ok.txt", b"ok")
            with pytest.raises(BadZipFile, match="CRC"):
                dst.copy_member(src, "f.bin", compress_type=zipctl.ZIP_STORED)
    data = out.getvalue()
    assert data.rfind(b"PK\x05\x06") == len(data) - 22  # nothing left past the end
    with ZipFile(io.BytesIO(data)) as written:
        assert written.namelist() == ["ok.txt"]
        assert written.testzip() is None


def test_a_bad_local_header_is_refused_before_a_kept_copy_writes() -> None:
    data = bytearray(make("aes2"))
    data[0] ^= 1  # the local header signature
    out = NonSeekableBytesIO()
    with ZipFile(io.BytesIO(bytes(data))) as src, ZipFile(out, "w") as dst:
        with pytest.raises(BadZipFile):
            dst.copy_member(src, "f.bin", keep_encryption=True)
        dst.writestr("ok.txt", b"ok")  # the archive is still usable
    with ZipFile(io.BytesIO(out.getvalue())) as written:
        assert written.namelist() == ["ok.txt"]


def test_a_write_handle_collected_in_a_cycle_frees_the_archive() -> None:
    with ZipFile(io.BytesIO(), "w") as zf:
        handle = zf.open("a.txt", "w")
        handle.write(b"a")
        cycle: list[object] = [handle]
        cycle.append(cycle)
        del handle, cycle
        gc.collect()
        assert zf.read("a.txt") == b"a"


class EndsAt(io.BytesIO):
    """Reads stop at *cut*, as if the file ended there."""

    cut: int = 1 << 30

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        limit = max(self.cut - self.tell(), 0)
        return super().read(limit if size is None or not 0 <= size <= limit else size)


def test_stored_data_that_ends_early_is_truncated() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"x" * 200)
    stream = EndsAt(buffer.getvalue())
    with ZipFile(stream) as zf:
        info = zf.getinfo("a.txt")
        stream.cut = info.header_offset + 40  # 5 bytes into the data
        with pytest.raises(BadZipFile, match="Truncated data for 'a.txt'"):
            list(zf.stored_chunks(info))
