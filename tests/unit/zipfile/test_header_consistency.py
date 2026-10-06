"""Ambiguous end records, forged extra fields and local/central header agreement."""

import io
import struct

import pytest

from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import WZ_AES, ArchiveLimits, BadZipFile, WzAesExtra, ZipFile, ZipInfo


def test_empty_end_record_inside_comment_is_refused() -> None:
    buffer = io.BytesIO(archive_bytes())
    with ZipFile(buffer, "a") as archive:
        # Would make the archive's end ambiguous: refuse before writing it.
        with pytest.raises(ValueError, match="end of central directory"):
            archive.comment = b"PK\x05\x06" + bytes(18)
    with ZipFile(buffer) as archive:
        assert archive.comment == b""
        assert archive.read("file.txt") == b"payload"


@pytest.mark.parametrize(
    "comment", [b"PK\x05\x06", b"comment PK\x05\x06 inside comment"]
)
def test_end_signature_in_comment(comment: bytes) -> None:
    buffer = io.BytesIO(archive_bytes())
    with ZipFile(buffer, "a") as archive:
        archive.comment = comment
    with ZipFile(buffer) as archive:
        assert archive.comment == comment
        assert archive.read("file.txt") == b"payload"


@pytest.mark.parametrize("declared", [0, 1, 65535])
def test_mutated_extra_length_fails_boundedly(declared: int) -> None:
    data = bytearray(archive_bytes())
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 30, declared)
    if declared:
        with pytest.raises(BadZipFile):
            ZipFile(io.BytesIO(data), limits=ArchiveLimits(max_metadata_bytes=1024))
    else:
        with ZipFile(io.BytesIO(data)) as archive:
            assert archive.read("file.txt") == b"payload"


def test_forged_zip64_extra_size_rejected_without_payload_read() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        with archive.open("file", "w", force_zip64=True) as writer:
            writer.write(b"payload")
    data = bytearray(buffer.getvalue())
    struct.pack_into("<H", data, 36, 65535)
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(BadZipFile, match="extra field"):
            archive.read("file")


def test_aes_flag_consistency() -> None:
    data = bytearray(archive_bytes(encryption=WZ_AES))
    central = data.index(b"PK\x01\x02")
    data[central + 8] &= ~1
    with pytest.raises(BadZipFile, match="AES metadata"):
        ZipFile(io.BytesIO(data))


@pytest.mark.parametrize("offset", [6, 8, 14, 18, 22])
def test_inconsistent_local_fields_rejected(offset: int) -> None:
    data = bytearray(archive_bytes())
    data[offset] ^= 1
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(BadZipFile, match="Local and central"):
            archive.read("file.txt")


@pytest.mark.parametrize("local_crc", [0, 0x12345678])
def test_ae2_entry_with_a_nonzero_crc_reads(local_crc: int) -> None:
    # Some writers store the real CRC in AE-2 entries; 7-Zip accepts it.
    data = bytearray(archive_bytes(encryption=WZ_AES))
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<L", data, central + 16, 0x12345678)
    struct.pack_into("<L", data, 14, local_crc)
    with ZipFile(io.BytesIO(data)) as archive:
        assert archive.getinfo("file.txt").aes_extra == WzAesExtra(2, b"AE", 3)
        assert archive.read("file.txt", pwd=b"password") == b"payload"


def test_ae2_local_crc_must_match_a_nonzero_central_one() -> None:
    data = bytearray(archive_bytes(encryption=WZ_AES))
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<L", data, central + 16, 0x12345678)
    struct.pack_into("<L", data, 14, 0x9ABCDEF0)
    with ZipFile(io.BytesIO(data)) as archive, pytest.raises(BadZipFile, match="CRC"):
        archive.read("file.txt", pwd=b"password")


def test_aes_metadata_only_in_the_local_header_is_refused() -> None:
    body = struct.pack("<H2sBH", 2, b"AE", 3, 0)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        info = ZipInfo("file.txt")
        info.extra = struct.pack("<HH", 0xCAFE, len(body)) + body
        archive.writestr(info, b"payload")
    data = bytearray(buffer.getvalue())
    local_tag = data.index(struct.pack("<H", 0xCAFE))  # the local copy comes first
    struct.pack_into("<H", data, local_tag, 0x9901)
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(BadZipFile, match="Unexpected local AES metadata"):
            archive.read("file.txt")


@pytest.mark.parametrize("size", [5, 20])  # inside the salt, inside the HMAC
def test_an_aes_entry_shorter_than_its_overhead_is_refused(size: int) -> None:
    data = bytearray(archive_bytes(encryption=WZ_AES))
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    start = 30 + name_len + extra_len
    central = data.index(b"PK\x01\x02")
    cut = data[: start + size] + data[central:]
    struct.pack_into("<L", cut, 18, size)
    struct.pack_into("<L", cut, start + size + 20, size)
    struct.pack_into("<L", cut, cut.index(b"PK\x05\x06") + 16, start + size)
    with ZipFile(io.BytesIO(cut)) as archive:
        with pytest.raises(BadZipFile, match="shorter than its encryption overhead"):
            archive.read("file.txt", pwd=b"password")
