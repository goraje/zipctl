"""The extra fields the record codec reads and writes.

ZIP64, WinZip AES and the Unicode Path field; other fields pass through.
"""

from __future__ import annotations

import struct
import warnings

from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.info.extra import (
    EXTRA_UNICODE_PATH,
    EXTRA_ZIP64,
    iter_extra,
)
from zipctl.zipfile.records.header import user_extra
from zipctl.zipfile.shared import (
    ZIP64_VERSION,
    needs_zip64,
    sanitize_filename,
    user_stacklevel,
)

__all__ = [
    "decode_extra",
    "zip64_central_extra",
]


def zip64_central_extra(
    info: ZipInfo,
) -> tuple[bytes, int, int, int, int]:
    """Build the ZIP64 extra field bytes for a central directory entry.

    Any existing extra data on ``info.extra`` is preserved; a stale ZIP64
    field (if present) is stripped and replaced.

    Returns:
        A tuple of
        ``(extra_bytes, file_size, compress_size, header_offset, min_version)``
        where each size/offset is replaced with ``0xFFFFFFFF`` when its
        value exceeds ``ZIP64_LIMIT``, and ``min_version`` is
        ``ZIP64_VERSION`` when any ZIP64 field is emitted.
    """
    zip64_fields: list[int] = []
    if needs_zip64(info.file_size):
        zip64_fields.append(info.file_size)
        file_size = 0xFFFFFFFF
    else:
        file_size = info.file_size

    if needs_zip64(info.compress_size):
        zip64_fields.append(info.compress_size)
        compress_size = 0xFFFFFFFF
    else:
        compress_size = info.compress_size

    if needs_zip64(info.header_offset):
        zip64_fields.append(info.header_offset)
        header_offset = 0xFFFFFFFF
    else:
        header_offset = info.header_offset

    min_version = 0
    if zip64_fields:
        zip64_extra = struct.pack(
            "<HH" + "Q" * len(zip64_fields),
            EXTRA_ZIP64,
            8 * len(zip64_fields),
            *zip64_fields,
        )
        min_version = ZIP64_VERSION
    else:
        zip64_extra = b""
    extra_data = zip64_extra + user_extra(info)
    return extra_data, file_size, compress_size, header_offset, min_version


def decode_zip64_extra(
    info: ZipInfo, data: bytes, is_central_directory: bool = True
) -> None:
    """Decode a ZIP64 extended information extra field (tag 0x0001).

    Updates ``file_size``, ``compress_size``, and ``header_offset`` on
    ``info`` when the corresponding sentinel value (``0xFFFFFFFF``) is
    present. Fields are consumed in the order mandated by the ZIP spec:
    file size, then compress size, then header offset.

    Args:
        data: The field body, without its tag and length.
        is_central_directory: When ``True``, also attempts to decode the
            header offset field (only present in central directory records).

    Raises:
        BadZipFile: If a required 8-byte Q field cannot be unpacked.
    """
    field = "unknown"
    try:
        if info.file_size == 0xFFFF_FFFF:
            field = "File size"
            (info.file_size,) = struct.unpack("<Q", data[:8])
            data = data[8:]

        if info.compress_size == 0xFFFF_FFFF:
            field = "Compress size"
            (info.compress_size,) = struct.unpack("<Q", data[:8])
            data = data[8:]

        if is_central_directory and info.header_offset == 0xFFFF_FFFF:
            field = "Header offset"
            (info.header_offset,) = struct.unpack("<Q", data[:8])
            data = data[8:]
        if is_central_directory and info.volume == 0xFFFF:
            field = "Disk number"
            (info.volume,) = struct.unpack("<L", data[:4])
    except struct.error:
        raise BadZipFile(f"Corrupt zip64 extra field. {field} not found.") from None


def decode_wz_aes_extra(info: ZipInfo, data: bytes) -> None:
    """Decode a WinZip AES extra field (tag 0x9901).

    Sets ``aes_extra`` and ``compress_type`` from the field body.

    Args:
        data: The field body, without its tag and length; must be 7 bytes.

    Raises:
        BadZipFile: If *data* is not 7 bytes long or holds an invalid field.
    """
    if len(data) != 7:
        raise BadZipFile(f"Corrupt extra field {EXTRA_WZ_AES:04x} (size={len(data)})")
    version, vendor_id, strength, info.compress_type = struct.unpack("<H2sBH", data)
    try:
        info.aes_extra = WzAesExtra(version, vendor_id, strength)
    except ValueError as exc:
        raise BadZipFile(str(exc)) from None


def decode_extra(info: ZipInfo, filename_crc: int) -> None:
    """Parse ``info.extra`` and update ``info`` with the fields it knows.

    Handles ZIP64 (0x0001), WinZip AES (0x9901) and the Unicode Path field
    (0x7075); other tags are skipped.

    Args:
        filename_crc: CRC-32 of the raw (non-Unicode) filename bytes, used
            to validate the Unicode Path extra field.

    Raises:
        BadZipFile: If a field overruns the block, a known field is given
            twice, or a known field's payload is invalid.
    """
    seen: set[int] = set()
    for tag, data in iter_extra(info.extra):
        if tag in (EXTRA_ZIP64, EXTRA_WZ_AES, EXTRA_UNICODE_PATH):
            if tag in seen:
                raise BadZipFile(f"Duplicate extra field {tag:04x}")
            seen.add(tag)
        if tag == EXTRA_ZIP64:
            decode_zip64_extra(info, data)
        elif tag == EXTRA_WZ_AES:
            decode_wz_aes_extra(info, data)
        elif tag == EXTRA_UNICODE_PATH:
            _decode_unicode_path(info, data, filename_crc)


def _decode_unicode_path(info: ZipInfo, data: bytes, filename_crc: int) -> None:
    """Rename *info* from a Unicode Path field that matches its stored name."""
    try:
        version, name_crc = struct.unpack("<BL", data[:5])
    except struct.error as e:
        raise BadZipFile("Corrupt unicode path extra field (0x7075)") from e
    if version != 1 or name_crc != filename_crc:
        return
    try:
        name = data[5:].decode("utf-8")
    except UnicodeDecodeError as e:
        raise BadZipFile(
            "Corrupt unicode path extra field (0x7075): invalid utf-8 bytes"
        ) from e
    if name:
        info.filename = sanitize_filename(name)
    else:
        warnings.warn(
            "Empty unicode path extra field (0x7075)", stacklevel=user_stacklevel()
        )
