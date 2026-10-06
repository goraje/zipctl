from __future__ import annotations

import io
import struct

import pytest

import zipctl
from zipctl.exceptions import BadZipFile, LargeZipFile
from zipctl.zipfile import shared
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.records import Directory, looks_like_zip, read_end_record
from zipctl.zipfile.shared import (
    END_ARCHIVE64_LOCATOR_SIGNATURE,
)


def _archive(names: tuple[str, ...] = ("a.txt",), comment: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        for name in names:
            zf.writestr(name, name.encode())
        zf.comment = comment
    return buffer.getvalue()


def test_end_record_of_empty_archive() -> None:
    record = read_end_record(io.BytesIO(_archive(())))
    assert record is not None
    assert (record.entries_total, record.size, record.offset) == (0, 0, 0)
    assert record.comment == b""
    assert record.prepended_bytes == 0


def test_end_record_reads_archive_comment() -> None:
    data = _archive(comment=b"hello comment")
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.comment == b"hello comment"
    assert record.entries_total == 1
    assert record.directory_start == record.offset


@pytest.mark.parametrize("data", [b"", b"not a zip file at all", b"PK\x05\x06"])
def test_end_record_missing_returns_none(data: bytes) -> None:
    assert read_end_record(io.BytesIO(data)) is None


def test_truncated_comment_returns_none() -> None:
    data = _archive(comment=b"0123456789")
    assert read_end_record(io.BytesIO(data[:-4])) is None


def test_prepended_data_is_accounted_for() -> None:
    prefix = b"#!/bin/sh\nexit 0\n" * 10
    data = prefix + _archive()
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.prepended_bytes == len(prefix)
    with pytest.raises(BadZipFile, match="self-extracting"):
        zipctl.ZipFile(io.BytesIO(data))
    with zipctl.ZipFile(io.BytesIO(data), allow_prepended_data=True) as zf:
        assert zf.read("a.txt") == b"a.txt"


def test_read_directory_rejects_non_zip() -> None:
    with pytest.raises(BadZipFile, match="not a zip file"):
        Directory().load(io.BytesIO(b"plain text"))


def test_read_directory_rejects_truncated_central_directory() -> None:
    data = bytearray(_archive())
    record = read_end_record(io.BytesIO(bytes(data)))
    assert record is not None
    # Claim a larger directory than the bytes that follow the first entry.
    size_offset = len(data) - 22 + 12
    struct.pack_into("<L", data, size_offset, record.size + 100)
    with pytest.raises(BadZipFile):
        Directory().load(io.BytesIO(bytes(data)))


def test_looks_like_zip() -> None:
    assert looks_like_zip(io.BytesIO(_archive()))
    assert looks_like_zip(io.BytesIO(_archive(())))
    assert not looks_like_zip(io.BytesIO(b"definitely not a zip archive"))
    assert not looks_like_zip(io.BytesIO(b""))


@pytest.fixture
def force_zip64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shared, "ZIP_FILECOUNT_LIMIT", 1)


@pytest.mark.usefixtures("force_zip64")
def test_zip64_end_records_round_trip() -> None:
    data = _archive(("a.txt", "b.txt", "c.txt"))
    assert END_ARCHIVE64_LOCATOR_SIGNATURE in data
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.entries_total == 3
    with zipctl.ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == ["a.txt", "b.txt", "c.txt"]


@pytest.mark.usefixtures("force_zip64")
def test_zip64_required_but_disallowed_raises() -> None:
    directory = Directory()
    for offset, name in enumerate("ab"):
        info = ZipInfo(name)
        info.CRC = 0
        info.header_offset = offset
        directory.add(info, 0)
    with pytest.raises(LargeZipFile, match="Files count"):
        directory.write(io.BytesIO(), allow_zip64=False, truncate=False)


@pytest.mark.usefixtures("force_zip64")
def test_multi_disk_zip64_locator_is_rejected() -> None:
    data = bytearray(_archive(("a.txt", "b.txt")))
    locator = data.index(END_ARCHIVE64_LOCATOR_SIGNATURE)
    struct.pack_into("<L", data, locator + 16, 2)  # total number of disks
    with pytest.raises(BadZipFile, match="multiple disks"):
        read_end_record(io.BytesIO(bytes(data)))


def _corrupt_local_header(offset_in_header: int, value: bytes) -> io.BytesIO:
    data = bytearray(_archive())
    data[offset_in_header : offset_in_header + len(value)] = value
    return io.BytesIO(bytes(data))


def test_local_header_bad_signature_is_rejected() -> None:
    with zipctl.ZipFile(_corrupt_local_header(0, b"XXXX")) as zf:
        with pytest.raises(BadZipFile, match="Bad magic number"):
            zf.read("a.txt")


def test_local_header_name_mismatch_is_rejected() -> None:
    with zipctl.ZipFile(_corrupt_local_header(30, b"z")) as zf:
        with pytest.raises(BadZipFile, match="differ"):
            zf.read("a.txt")


@pytest.mark.parametrize("inner_comment", [b"", b"c"])
def test_polyglot_end_records_are_ambiguous(inner_comment: bytes) -> None:
    # CPython would pick the last record, others the first: refuse to choose.
    inner = _archive(("evil.txt",), comment=inner_comment)
    outer = bytearray(_archive(("good.txt",)))
    outer[-2:] = len(inner).to_bytes(2, "little")
    with pytest.raises(BadZipFile, match="Ambiguous"):
        read_end_record(io.BytesIO(bytes(outer) + inner))


def test_signature_inside_comment_is_not_an_end_record() -> None:
    comment = b"x" + b"PK\x05\x06" + b"\x01" * 20 + b"y"
    record = read_end_record(io.BytesIO(_archive(comment=comment)))
    assert record is not None
    assert record.comment == comment
    assert record.entries_total == 1
