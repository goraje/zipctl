"""The local file header and data descriptor of an entry."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import IO

from zipctl.cryptography.aes import WZ_AES_COMPRESS_TYPE
from zipctl.exceptions import BadZipFile
from zipctl.format import Readable
from zipctl.format import read_exactly as _read_exactly
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.info.extra import EXTRA_UNICODE_PATH, EXTRA_ZIP64, iter_extra
from zipctl.zipfile.io_wrappers import ClosableZipStream
from zipctl.zipfile.records.extra import decode_extra
from zipctl.zipfile.records.header import encode_filename_flags
from zipctl.zipfile.shared import (
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_SIZE,
    FILE_HEADER_STRUCT,
    MASK_COMPRESSED_PATCH,
    MASK_ENCRYPTED,
    MASK_STRONG_ENCRYPTION,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
    crc32,
)

__all__ = [
    "DirectoryEntry",
    "data_end",
    "raise_for_unsupported_flags",
    "read_exactly",
    "read_local_header",
]

# Field positions in the unpacked struct tuple.
_FH_SIGNATURE = 0
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESS_TYPE = 4
_FH_CRC = 7
_FH_COMPRESSED_SIZE = 8
_FH_UNCOMPRESSED_SIZE = 9
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

# Flag bits the local header must share with the central directory.
_FLAGS_MUST_MATCH = MASK_ENCRYPTED | MASK_USE_DATA_DESCRIPTOR | MASK_UTF_FILENAME

DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"  # optional in front of a data descriptor


@dataclass
class DirectoryEntry:
    """An entry and what the codec keeps of its records beside its ZipInfo.

    Attributes:
        info: The entry.
        dos_time: The DOS time in its headers, which ``info.date_time`` may no
            longer match; ZipCrypto checks passwords against it.
        stored_name: The name's bytes and the flag bits as read, so the
            directory is written back as it was; ``None`` for an entry
            written here.
        end_offset: Where the next entry (or the directory) starts; ``None``
            for an entry written here.
    """

    info: ZipInfo
    dos_time: int
    stored_name: tuple[bytes, int] | None = None
    end_offset: int | None = None


def read_exactly(fp: Readable, size: int) -> bytes:
    """Read *size* bytes of a record.

    Raises:
        BadZipFile: If the file ends first.
    """
    try:
        return _read_exactly(fp, size)
    except EOFError as exc:
        raise BadZipFile("Truncated ZIP record") from exc


def raise_for_unsupported_flags(info: ZipInfo) -> None:
    """Raise :exc:`NotImplementedError` for flag combinations we cannot read."""
    if info.flag_bits & MASK_COMPRESSED_PATCH:
        raise NotImplementedError("compressed patched data (flag bit 5)")
    if info.flag_bits & MASK_STRONG_ENCRYPTION:
        raise NotImplementedError("strong encryption (flag bit 6)")


def data_end(fp: IO[bytes], info: ZipInfo) -> int | None:
    """Where the data of *info* ends, by its local header's lengths.

    Returns ``None`` if no local header is there; reading the entry reports it.
    """
    fp.seek(info.header_offset)
    header = struct.unpack(FILE_HEADER_STRUCT, read_exactly(fp, FILE_HEADER_SIZE))
    if header[_FH_SIGNATURE] != FILE_HEADER_SIGNATURE:
        return None
    end: int = (
        info.header_offset
        + FILE_HEADER_SIZE
        + header[_FH_FILENAME_LENGTH]
        + header[_FH_EXTRA_FIELD_LENGTH]
        + info.compress_size
    )
    return end


def read_local_header(
    stream: ClosableZipStream, entry: DirectoryEntry, metadata_encoding: str | None
) -> None:
    """Validate the local file header of *entry* and skip past it.

    On return *stream* is positioned at the start of the entry payload.

    Raises:
        BadZipFile: If the header is truncated, has a bad signature, its
            file name differs from the central directory, or its data runs
            into the next entry.
        NotImplementedError: If the entry uses unsupported flag bits.
    """
    info = entry.info
    raw = read_exactly(stream, FILE_HEADER_SIZE)
    header = struct.unpack(FILE_HEADER_STRUCT, raw)
    if header[_FH_SIGNATURE] != FILE_HEADER_SIGNATURE:
        raise BadZipFile("Bad magic number for file header")

    name = read_exactly(stream, header[_FH_FILENAME_LENGTH])
    extra = read_exactly(stream, header[_FH_EXTRA_FIELD_LENGTH])
    raise_for_unsupported_flags(info)
    _validate_local_metadata(
        header[_FH_GENERAL_PURPOSE_FLAG_BITS],
        header[_FH_COMPRESS_TYPE],
        header[_FH_CRC],
        header[_FH_COMPRESSED_SIZE],
        header[_FH_UNCOMPRESSED_SIZE],
        extra,
        name,
        entry,
    )

    encoding = (
        "utf-8"
        if header[_FH_GENERAL_PURPOSE_FLAG_BITS] & MASK_UTF_FILENAME
        else metadata_encoding or "cp437"
    )
    try:
        header_name = name.decode(encoding)
    except UnicodeDecodeError as exc:
        raise BadZipFile("Invalid local filename encoding") from exc
    if header_name != info.orig_filename:
        raise BadZipFile(
            f"File name in directory {info.orig_filename!r} and header {name!r} differ."
        )
    zip64 = any(tag == EXTRA_ZIP64 for tag, _ in iter_extra(extra))
    _check_extent(stream, info, entry.end_offset, zip64=zip64)


def _check_extent(
    stream: ClosableZipStream, info: ZipInfo, end: int | None, *, zip64: bool
) -> None:
    """Require the entry to fill exactly the space up to the next one.

    Data running into the next entry is the overlapping-entries zip bomb;
    bytes left over between entries are data no reader accounts for.  A data
    descriptor is read and must agree with the central directory.  On return
    *stream* is back at the start of the payload.
    """
    data_start = stream.tell()
    data_end = data_start + info.compress_size
    if end is not None and data_end > end:
        raise BadZipFile(
            f"Overlapped entries: {info.orig_filename!r} (possible zip bomb)"
        )
    if info.use_data_descriptor:
        stream.seek(data_end)
        # Writers disagree on whether a ZIP64 extra means 64-bit descriptor
        # sizes, so where the next entry starts the gap decides.
        if end is not None and end - data_end in (20, 24):
            zip64 = True
        elif end is not None and end - data_end in (12, 16):
            zip64 = False
        data_end += _read_data_descriptor(stream, info, zip64=zip64)
        stream.seek(data_start)
    if end is not None and data_end != end:
        raise BadZipFile(f"Unaccounted bytes after {info.orig_filename!r}")


def _read_data_descriptor(
    stream: ClosableZipStream, info: ZipInfo, *, zip64: bool
) -> int:
    """Check the data descriptor at the stream position; return its length."""
    fields = "<LQQ" if zip64 else "<LLL"
    size = struct.calcsize(fields)
    head = read_exactly(stream, 4)
    length = size
    if head == DATA_DESCRIPTOR_SIGNATURE:
        head = b""
        length += 4
    raw = head + read_exactly(stream, size - len(head))
    fields_read: tuple[int, int, int] = struct.unpack(fields, raw)
    crc, compressed, file_size = fields_read
    if crc not in _header_crcs(info) or (compressed, file_size) != (
        info.compress_size,
        info.file_size,
    ):
        raise BadZipFile(
            f"Data descriptor and central directory differ for {info.orig_filename!r}"
        )
    return length


def _validate_local_metadata(
    flags: int,
    method: int,
    crc: int,
    compressed: int,
    size: int,
    extra: bytes,
    name: bytes,
    entry: DirectoryEntry,
) -> None:
    """Cross-check fields that are not deferred to a data descriptor."""
    info = entry.info
    expected_method = WZ_AES_COMPRESS_TYPE if info.is_aes else info.compress_type
    expected_flags = (entry.stored_name or encode_filename_flags(info))[1]
    if method != expected_method or (flags ^ expected_flags) & _FLAGS_MUST_MATCH:
        raise BadZipFile("Local and central flags or compression method differ")
    local = ZipInfo(info.orig_filename)
    local.extra = extra
    local.header_offset = 0  # a local ZIP64 field carries no offset
    local.file_size, local.compress_size = size, compressed
    decode_extra(local, crc32(name))
    # Many writers put the Unicode Path field in the central directory only.
    has_local_path = any(tag == EXTRA_UNICODE_PATH for tag, _ in iter_extra(extra))
    if has_local_path and local.filename != info.filename:
        raise BadZipFile("Local and central Unicode path fields differ")
    if expected_method == WZ_AES_COMPRESS_TYPE:
        if (
            local.aes_extra != info.aes_extra
            or local.compress_type != info.compress_type
        ):
            raise BadZipFile("Local and central AES metadata differ")
    elif local.is_aes:
        raise BadZipFile("Unexpected local AES metadata")
    if not info.use_data_descriptor and (
        crc not in _header_crcs(info)
        or (local.compress_size, local.file_size)
        != (info.compress_size, info.file_size)
    ):
        raise BadZipFile("Local and central CRC or sizes differ")


def _header_crcs(info: ZipInfo) -> tuple[int, ...]:
    """The CRC values the local records of *info* may hold.

    WZ-AES 2 entries should store 0, but some writers store the real CRC and
    7-Zip accepts either; the CRC is not checked for them (the HMAC is).
    """
    return (info.CRC,) if info.stores_crc else (0, info.CRC)
