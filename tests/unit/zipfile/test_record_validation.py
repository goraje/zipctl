"""ZIP record validation, bounded I/O, ZIP64 and codec termination."""

from __future__ import annotations

import io
import struct
import zipfile

import pytest
from typing_extensions import override

from zipctl import WZ_AES, ZIP_CRYPTO, ZipFile, is_zipfile
from zipctl.compression import zstd
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.info import ZipInfo


def _archive(method: int = 0) -> bytearray:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=method) as archive:
        archive.writestr("file.txt", b"payload")
    return bytearray(buffer.getvalue())


ZSTD = pytest.param(
    93,
    marks=pytest.mark.skipif(
        zstd.compression_entry is None, reason="zstandard backend is unavailable"
    ),
)


@pytest.mark.parametrize("method", [0, 8, 12, 14, ZSTD])
def test_declared_size_must_match_output(method: int) -> None:
    data = _archive(method)
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<L", data, 22, 100)
    struct.pack_into("<L", data, central + 24, 100)
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(BadZipFile, match="size mismatch"):
            archive.read("file.txt")
        assert archive.testzip() == "file.txt"


def test_deflate_requires_end_of_stream() -> None:
    data = _archive(8)
    central = data.index(b"PK\x01\x02")
    size = struct.unpack_from("<L", data, central + 20)[0]
    struct.pack_into("<L", data, 18, size - 1)
    struct.pack_into("<L", data, central + 20, size - 1)
    # The byte the sizes no longer cover is caught on open, before the stream is.
    with pytest.raises(BadZipFile, match="Unaccounted bytes"):
        ZipFile(io.BytesIO(data))


@pytest.mark.parametrize("version", [b"\x13\x00", b"\x09\x14"])
def test_lzma_sdk_version_does_not_change_format(version: bytes) -> None:
    data = _archive(14)
    data[38:40] = version
    with (
        ZipFile(io.BytesIO(data)) as archive,
        zipfile.ZipFile(io.BytesIO(data)) as stdlib,
    ):
        assert archive.read("file.txt") == stdlib.read("file.txt") == b"payload"


@pytest.mark.parametrize("offset", [4, 6])
def test_classic_multidisk_end_record_is_rejected(offset: int) -> None:
    data = _archive()
    end = data.index(b"PK\x05\x06")
    struct.pack_into("<H", data, end + offset, 1)
    with pytest.raises(BadZipFile, match="multiple disks"):
        ZipFile(io.BytesIO(data))


def test_member_on_another_disk_is_rejected() -> None:
    data = _archive()
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 34, 1)
    with pytest.raises(BadZipFile, match="multiple disks"):
        ZipFile(io.BytesIO(data))


def test_directory_field_cannot_extend_into_end_record() -> None:
    data = _archive()
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 32, 10)
    with pytest.raises(BadZipFile, match="Truncated central"):
        ZipFile(io.BytesIO(data))


def test_directory_is_read_record_by_record() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        for index in range(2000):
            archive.writestr(f"file-{index}", b"")

    class BoundedReader(io.BytesIO):
        @override
        def read(self, size: int | None = -1) -> bytes:
            assert size is not None
            assert 0 <= size <= 65557
            return super().read(size)

    with ZipFile(BoundedReader(buffer.getvalue())) as archive:
        assert len(archive.infolist()) == 2000


@pytest.mark.parametrize("encryption", [None, WZ_AES, ZIP_CRYPTO])
def test_short_reads_are_supported_in_headers_and_payloads(
    encryption: str | None,
) -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=encryption, compression=8) as archive:
        archive.setpassword(b"password")
        archive.writestr("file.txt", b"payload" * 20)
        archive.comment = b"comment"

    class ShortReader(io.BytesIO):
        @override
        def read(self, size: int | None = -1) -> bytes:
            return super().read(min(3, size) if size is not None and size >= 0 else 3)

    with ZipFile(ShortReader(buffer.getvalue())) as archive:
        assert archive.read("file.txt", pwd=b"password") == b"payload" * 20


def test_is_zipfile_restores_position_after_corrupt_zip64() -> None:
    data = _archive()
    end = data.index(b"PK\x05\x06")
    data[end - 20 : end] = struct.pack("<4sLQL", b"PK\x06\x07", 1, 0, 2)
    buffer = io.BytesIO(data)
    buffer.seek(5)
    assert not is_zipfile(buffer)
    assert buffer.tell() == 5


@pytest.mark.parametrize("method", [8, 12, 14, ZSTD])
def test_corrupt_codec_raises_bad_zipfile(method: int) -> None:
    data = _archive(method)
    data[38] = 7
    if method == 14:
        data[42] = 255
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(BadZipFile):
            archive.read("file.txt")


@pytest.mark.parametrize("count", [0, 2])
def test_directory_count_mismatch_is_rejected(count: int) -> None:
    data = _archive()
    end = data.index(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, count, count)
    with pytest.raises(BadZipFile, match="count mismatch"):
        ZipFile(io.BytesIO(data))


def test_forced_zip64_small_member_uses_sentinels_and_version() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        with archive.open("file.txt", "w", force_zip64=True) as stream:
            stream.write(b"payload")
    data = buffer.getvalue()
    assert struct.unpack_from("<H", data, 4)[0] >= 45
    assert struct.unpack_from("<LL", data, 18) == (0xFFFFFFFF, 0xFFFFFFFF)
    with zipfile.ZipFile(buffer) as archive:
        assert archive.read("file.txt") == b"payload"


@pytest.mark.parametrize("disk", [0, 1])
def test_zip64_disk_number_is_decoded_and_validated(disk: int) -> None:
    info = ZipInfo("file.txt")
    info.volume = 0xFFFF
    info.extra = struct.pack("<HHL", 1, 4, disk)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(info, b"payload")
    # The central writer clears disk metadata; patch its sentinel back in.
    data = bytearray(buffer.getvalue())
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 34, 0xFFFF)
    # ZIP64 output removes stale fields, so insert the disk field into the directory.
    extra = struct.pack("<HHL", 1, 4, disk)
    position = central + 46 + len("file.txt")
    data[position:position] = extra
    struct.pack_into("<H", data, central + 30, len(extra))
    end = data.index(b"PK\x05\x06")
    size = struct.unpack_from("<L", data, end + 12)[0]
    struct.pack_into("<L", data, end + 12, size + len(extra))
    if disk:
        with pytest.raises(BadZipFile, match="multiple disks"):
            ZipFile(io.BytesIO(data))
    else:
        with ZipFile(io.BytesIO(data)) as archive:
            assert archive.read("file.txt") == b"payload"
