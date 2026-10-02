"""Ambiguous end records, forged extra fields and local/central header agreement."""

import io
import struct

import pytest

from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import WZ_AES, ArchiveLimits, BadZipFile, ZipFile


def test_empty_end_record_inside_comment_is_refused() -> None:
    buffer = io.BytesIO(archive_bytes())
    with ZipFile(buffer, "a") as archive:
        archive.comment = b"PK\x05\x06" + bytes(18)
    # CPython would read the fake record; refuse rather than pick one.
    with pytest.raises(BadZipFile, match="Ambiguous"):
        ZipFile(buffer)


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
