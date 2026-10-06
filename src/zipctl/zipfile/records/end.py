"""The end-of-central-directory record, with its ZIP64 record and locator."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import IO

from zipctl.exceptions import BadZipFile
from zipctl.zipfile.io_wrappers import write_all
from zipctl.zipfile.records.local import read_exactly
from zipctl.zipfile.shared import (
    END_ARCHIVE64_LOCATOR_SIGNATURE,
    END_ARCHIVE64_LOCATOR_SIZE,
    END_ARCHIVE64_LOCATOR_STRUCT,
    END_ARCHIVE64_SIGNATURE,
    END_ARCHIVE64_SIZE,
    END_ARCHIVE64_STRUCT,
    END_ARCHIVE_SIGNATURE,
    END_ARCHIVE_SIZE,
    END_ARCHIVE_STRUCT,
    ZIP64_VERSION,
    ZIP_MAX_COMMENT,
)

__all__ = [
    "EndRecord",
    "comment_forges_end_record",
    "read_end_record",
    "write_end_records",
]

_UINT16_MAX = 0xFFFF
_UINT32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class EndRecord:
    """The end-of-central-directory record, upgraded with ZIP64 values.

    Attributes:
        location: File offset of the record (or of the ZIP64 record, when the
            archive uses ZIP64 and no data is prepended).
    """

    disk_number: int
    disk_start: int
    entries_this_disk: int
    entries_total: int
    size: int
    offset: int
    comment: bytes
    location: int

    @property
    def directory_start(self) -> int:
        """Actual file offset of the central directory.

        Differs from :attr:`offset` when data was prepended to the archive
        (e.g. a self-extracting stub).
        """
        return self.location - self.size

    @property
    def prepended_bytes(self) -> int:
        """Number of bytes preceding the ZIP data (zero for a plain archive)."""
        return self.directory_start - self.offset


def _apply_zip64_end_record(fp: IO[bytes], record: EndRecord) -> EndRecord:
    """Return *record* upgraded with values from the ZIP64 end record, if any."""
    offset = record.location - END_ARCHIVE64_LOCATOR_SIZE
    if offset < 0:
        return record
    fp.seek(offset)
    data = read_exactly(fp, END_ARCHIVE64_LOCATOR_SIZE)
    signature, disk_number, zip64_offset, disk_count = struct.unpack(
        END_ARCHIVE64_LOCATOR_STRUCT, data
    )
    if signature != END_ARCHIVE64_LOCATOR_SIGNATURE:
        return record

    if disk_number != 0 or disk_count > 1:
        raise BadZipFile("zipfiles that span multiple disks are not supported")

    offset -= END_ARCHIVE64_SIZE
    if zip64_offset > offset:
        raise BadZipFile("Corrupt zip64 end of central directory locator")
    fp.seek(zip64_offset)
    extra_size = offset - zip64_offset
    data = read_exactly(fp, END_ARCHIVE64_SIZE)
    if not data.startswith(END_ARCHIVE64_SIGNATURE) and zip64_offset != offset:
        fp.seek(offset)
        extra_size = 0
        data = read_exactly(fp, END_ARCHIVE64_SIZE)
    if not data.startswith(END_ARCHIVE64_SIGNATURE):
        raise BadZipFile("Zip64 end of central directory record not found")

    (
        _signature,
        record_size,
        _create_version,
        _extract_version,
        disk_number,
        disk_start,
        entries_this_disk,
        entries_total,
        directory_size,
        directory_offset,
    ) = struct.unpack(END_ARCHIVE64_STRUCT, data)
    if (
        directory_offset + directory_size != zip64_offset
        or record_size + 12 != END_ARCHIVE64_SIZE + extra_size
    ):
        raise BadZipFile("Corrupt zip64 end of central directory record")

    return EndRecord(
        disk_number=disk_number,
        disk_start=disk_start,
        entries_this_disk=entries_this_disk,
        entries_total=entries_total,
        size=directory_size,
        offset=directory_offset,
        comment=record.comment,
        location=offset - extra_size,
    )


def _unpack_end_record(data: bytes, comment: bytes, location: int) -> EndRecord:
    (
        _signature,
        disk_number,
        disk_start,
        entries_this_disk,
        entries_total,
        size,
        offset,
        _comment_size,
    ) = struct.unpack(END_ARCHIVE_STRUCT, data)
    return EndRecord(
        disk_number=disk_number,
        disk_start=disk_start,
        entries_this_disk=entries_this_disk,
        entries_total=entries_total,
        size=size,
        offset=offset,
        comment=comment,
        location=location,
    )


def read_end_record(fp: IO[bytes]) -> EndRecord | None:
    """Locate and parse the end-of-central-directory record of *fp*.

    Searches the tail of the file (allowing for an archive comment) and
    upgrades the result with ZIP64 values when applicable.

    Returns:
        The record, or ``None`` if *fp* does not end with one.

    Raises:
        OSError: If a required structure cannot be fully read.
        BadZipFile: If the ZIP64 structures are corrupt or the archive spans
            multiple disks.
    """
    fp.seek(0, 2)
    file_size = fp.tell()
    if file_size < END_ARCHIVE_SIZE:
        return None

    tail_start = max(file_size - ZIP_MAX_COMMENT - END_ARCHIVE_SIZE, 0)
    fp.seek(tail_start)
    tail = read_exactly(fp, file_size - tail_start)
    return _find_end_record(fp, tail, tail_start)


def comment_forges_end_record(comment: bytes) -> bool:
    """Return ``True`` if *comment* holds an end record ending where it ends.

    Such a comment would make the archive's end ambiguous on the next read.
    """
    start = comment.find(END_ARCHIVE_SIGNATURE)
    while start >= 0:
        raw = comment[start : start + END_ARCHIVE_SIZE]
        if len(raw) == END_ARCHIVE_SIZE:
            size = struct.unpack(END_ARCHIVE_STRUCT, raw)[-1]
            if start + END_ARCHIVE_SIZE + size == len(comment):
                return True
        start = comment.find(END_ARCHIVE_SIGNATURE, start + 4)
    return False


def _find_end_record(fp: IO[bytes], tail: bytes, tail_start: int) -> EndRecord | None:
    """Pick the record whose declared comment reaches the physical end.

    Raises:
        BadZipFile: If several records qualify. Parsers that pick a different
            one would disagree about the archive's contents.
    """
    reaching: list[EndRecord] = []
    trailing: list[EndRecord] = []
    start = tail.find(END_ARCHIVE_SIGNATURE)
    while start >= 0:
        raw = tail[start : start + END_ARCHIVE_SIZE]
        if len(raw) == END_ARCHIVE_SIZE:
            size = struct.unpack(END_ARCHIVE_STRUCT, raw)[-1]
            end = start + END_ARCHIVE_SIZE + size
            if end <= len(tail):
                record = _unpack_end_record(
                    raw, tail[start + END_ARCHIVE_SIZE : end], tail_start + start
                )
                (reaching if end == len(tail) else trailing).append(record)
        start = tail.find(END_ARCHIVE_SIGNATURE, start + 4)
    if len(reaching) > 1:
        raise BadZipFile("Ambiguous end of central directory")
    if not reaching:
        if trailing:
            raise BadZipFile("Data after the end of the central directory")
        return None
    return _apply_zip64_end_record(fp, reaching[0])


def write_end_records(
    fp: IO[bytes], count: int, size: int, offset: int, comment: bytes, *, zip64: bool
) -> None:
    """Write the end records of a directory of *count* entries just written.

    *size* is the directory's length and *offset* where it starts; with
    *zip64* the ZIP64 record and locator come first.
    """
    if zip64:
        directory_end = fp.tell()
        write_all(
            fp,
            struct.pack(
                END_ARCHIVE64_STRUCT,
                END_ARCHIVE64_SIGNATURE,
                END_ARCHIVE64_SIZE - 12,
                ZIP64_VERSION,
                ZIP64_VERSION,
                0,
                0,
                count,
                count,
                size,
                offset,
            ),
        )
        write_all(
            fp,
            struct.pack(
                END_ARCHIVE64_LOCATOR_STRUCT,
                END_ARCHIVE64_LOCATOR_SIGNATURE,
                0,
                directory_end,
                1,
            ),
        )
        count = min(count, _UINT16_MAX)
        size = min(size, _UINT32_MAX)
        offset = min(offset, _UINT32_MAX)

    write_all(
        fp,
        struct.pack(
            END_ARCHIVE_STRUCT,
            END_ARCHIVE_SIGNATURE,
            0,
            0,
            count,
            count,
            size,
            offset,
            len(comment),
        ),
    )
    write_all(fp, comment)
