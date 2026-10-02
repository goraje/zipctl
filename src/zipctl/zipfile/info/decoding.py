"""Reading the extra-data block of a ZipInfo."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

import struct
import warnings
from typing import TYPE_CHECKING

from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.info.extra import EXTRA_UNICODE_PATH, sanitize_filename

if TYPE_CHECKING:
    from zipctl.zipfile.info import ZipInfo

__all__ = ["decode_extra", "decode_wz_aes_extra", "decode_zip64_extra"]


def decode_zip64_extra(
    info: ZipInfo, ln: int, extra: bytes, is_central_directory: bool = True
) -> None:
    """Decode a ZIP64 extended information extra field (tag 0x0001).

    Updates ``file_size``, ``compress_size``, and ``header_offset`` on
    ``info`` when the corresponding sentinel value (``0xFFFFFFFF``) is
    present. Fields are consumed in the order mandated by the ZIP spec:
    file size, then compress size, then header offset.

    Args:
        ln: Length of the extra field body in bytes (excluding the 4-byte
            tag/length header).
        extra: The full extra-data block; the field body is read from
            offset 4.
        is_central_directory: When ``True``, also attempts to decode the
            header offset field (only present in central directory records).

    Raises:
        BadZipFile: If a required 8-byte Q field cannot be unpacked.
    """
    # offset = len(extra block tag) + len(extra block size)
    offset = 4
    data = extra[offset : offset + ln]
    field = "unknown"
    try:
        if info.file_size in (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF):
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


def decode_wz_aes_extra(info: ZipInfo, ln: int, extra: bytes) -> None:
    """Decode a WinZip AES extra field (tag 0x9901).

    Populates ``aes_extra.wz_aes_version``, ``aes_extra.wz_aes_vendor_id``,
    ``aes_extra.wz_aes_strength``, and ``compress_type`` from the field body.

    Args:
        ln: Length of the extra field body in bytes; must be exactly 7.
        extra: The full extra-data block; the field body is read from
            offset 4.

    Raises:
        BadZipFile: If *ln* is not 7.
    """
    if ln != 7:
        raise BadZipFile(f"Corrupt extra field {EXTRA_WZ_AES:04x} (size={ln})")
    (
        info.aes_extra.wz_aes_version,
        info.aes_extra.wz_aes_vendor_id,
        info.aes_extra.wz_aes_strength,
        info.compress_type,
    ) = struct.unpack("<H2sBH", extra[4 : ln + 4])
    if info.aes_extra.wz_aes_version not in (1, 2):
        raise BadZipFile("Unsupported WinZip AES version")
    if info.aes_extra.wz_aes_vendor_id != b"AE":
        raise BadZipFile("Invalid WinZip AES vendor ID")
    if info.aes_extra.wz_aes_strength not in (1, 2, 3):
        raise BadZipFile("Invalid WinZip AES strength")


def decode_extra(info: ZipInfo, filename_crc: int) -> None:
    """Parse the extra-data block and update ``info`` with decoded field values.

    Iterates over every extra field in ``info.extra`` and dispatches to the
    appropriate decoder returned by ``_extra_decoders``. The Unicode
    Path extra field (0x7075) is handled inline because it requires the
    *filename_crc* context. Unknown tags are silently ignored.

    Args:
        filename_crc: CRC-32 of the raw (non-Unicode) filename bytes, used
            to validate the Unicode Path extra field.

    Raises:
        BadZipFile: If any field's declared length overflows the buffer, or
            if a known field's payload is structurally invalid.
    """
    # Try to decode the extra field.
    extra = info.extra
    unpack = struct.unpack
    extra_decoders = info._extra_decoders()
    while len(extra) >= 4:
        tp, ln = unpack("<HH", extra[:4])
        if ln + 4 > len(extra):
            raise BadZipFile(f"Corrupt extra field {tp:04x} (size={ln})")
        if tp == EXTRA_UNICODE_PATH:
            # Unicode Path Extra Field — needs filename_crc, handle inline
            data = extra[4 : ln + 4]
            try:
                up_version, up_name_crc = unpack("<BL", data[:5])
                if up_version == 1 and up_name_crc == filename_crc:
                    up_unicode_name = data[5:].decode("utf-8")
                    if up_unicode_name:
                        info.filename = sanitize_filename(up_unicode_name)
                    else:
                        warnings.warn(
                            "Empty unicode path extra field (0x7075)", stacklevel=2
                        )
            except struct.error as e:
                raise BadZipFile("Corrupt unicode path extra field (0x7075)") from e
            except UnicodeDecodeError as e:
                raise BadZipFile(
                    "Corrupt unicode path extra field (0x7075): invalid utf-8 bytes"
                ) from e
        else:
            try:
                extra_decoders[tp](ln, extra)
            except KeyError:
                pass  # Unknown extra field — skip
        extra = extra[ln + 4 :]
    if extra:
        raise BadZipFile("Corrupt trailing extra field data")
