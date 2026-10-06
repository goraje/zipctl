"""Encoding an entry's local file header and data descriptor.

Imports neither ``ZipInfo`` nor the rest of the codec, not even to annotate:
``ZipInfo.FileHeader()`` imports this module, and basedpyright counts every
import when it looks for cycles.  Merged into ``local.py`` it would bring the
info/records cycle back.  The entry is typed by :class:`HeaderFields`, the
fields a header is built from.
"""

from __future__ import annotations

import struct
from typing import Protocol

from zipctl.compression import ZIP_BZIP2, ZIP_LZMA, ZIP_ZSTANDARD
from zipctl.compression.methods import (
    BZIP2_VERSION,
    LZMA_VERSION,
    ZSTANDARD_VERSION,
)
from zipctl.cryptography import wz_aes_stores_crc
from zipctl.cryptography.aes import EXTRA_WZ_AES, WZ_AES_COMPRESS_TYPE
from zipctl.exceptions import LargeZipFile
from zipctl.zipfile.info.extra import EXTRA_ZIP64, WzAesExtra, strip_extra
from zipctl.zipfile.shared import (
    DD_SIGNATURE,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_STRUCT,
    MASK_UTF_FILENAME,
    ZIP64_VERSION,
    needs_zip64,
)

__all__ = [
    "HeaderFields",
    "data_descriptor",
    "encode_extra",
    "encode_filename_flags",
    "file_header",
    "minimum_version",
    "user_extra",
    "zip64_local_extra",
]


class HeaderFields(Protocol):
    """The fields of an entry its local header is built from; a ZipInfo."""

    @property
    def filename(self) -> str: ...
    @property
    def flag_bits(self) -> int: ...
    @property
    def compress_type(self) -> int: ...
    @property
    def extract_version(self) -> int: ...
    @property
    def reserved(self) -> int: ...
    @property
    def CRC(self) -> int: ...
    @property
    def compress_size(self) -> int: ...
    @property
    def file_size(self) -> int: ...
    @property
    def extra(self) -> bytes: ...
    @property
    def aes_extra(self) -> WzAesExtra | None: ...
    @property
    def use_data_descriptor(self) -> bool: ...
    def get_dostime(self) -> int: ...
    def get_dosdate(self) -> int: ...


def zip64_local_extra(
    zip64: bool | None, file_size: int, compress_size: int
) -> tuple[bytes, int, int, int]:
    """Compute the ZIP64 extra field and placeholder sizes for a local file header.

    Args:
        zip64: Force ZIP64 on (``True``), off (``False``), or auto-detect
            (``None``). Auto-detect enables ZIP64 when either size exceeds
            ``ZIP64_LIMIT``.
        file_size: Uncompressed file size in bytes.
        compress_size: Compressed size in bytes.

    Returns:
        A tuple of ``(extra_bytes, file_size, compress_size, min_version)``
        where sizes are replaced with ``0xFFFFFFFF`` when ZIP64 is active
        and ``min_version`` is ``ZIP64_VERSION`` or 0.

    Raises:
        LargeZipFile: If either size exceeds ``ZIP64_LIMIT`` and *zip64*
            is ``False``.
    """
    min_version = 0
    extra = b""
    requires_zip64 = needs_zip64(file_size, compress_size)
    if zip64 is None:
        zip64 = requires_zip64
    if zip64:
        extra = struct.pack(
            "<HHQQ",
            EXTRA_ZIP64,
            8 * 2,  # two Q fields
            file_size,
            compress_size,
        )
        file_size = 0xFFFFFFFF
        compress_size = 0xFFFFFFFF
        min_version = ZIP64_VERSION
    elif requires_zip64:
        raise LargeZipFile("Filesize would require ZIP64 extensions")
    return extra, file_size, compress_size, min_version


def user_extra(info: HeaderFields) -> bytes:
    """The extra fields of *info* other than the ones the writer builds."""
    return strip_extra(info.extra, (EXTRA_ZIP64, EXTRA_WZ_AES))


def encode_extra(
    info: HeaderFields, crc: int, compress_type: int
) -> tuple[bytes, int, int]:
    """Encode the WinZip AES extra field and adjust CRC and compression type.

    For an entry that is not AES this is a no-op: the extra bytes are empty
    and *crc* and *compress_type* are returned unchanged.

    For AES entries, *compress_type* is overridden to
    ``WZ_AES_COMPRESS_TYPE`` (99), and version 2 entries have their CRC zeroed.

    Args:
        crc: CRC-32 of the uncompressed data.
        compress_type: Compression method code before AES wrapping.

    Returns:
        A tuple of ``(extra_bytes, crc, compress_type)`` containing the
        AES extra field bytes (may be empty), the adjusted CRC, and the
        adjusted compression type.
    """
    aes = info.aes_extra
    if aes is None:
        return b"", crc, compress_type
    wz_aes_extra = struct.pack(
        "<3H2sBH",
        EXTRA_WZ_AES,
        7,  # extra block body length: H2sBH
        aes.wz_aes_version,
        aes.wz_aes_vendor_id,
        aes.wz_aes_strength,
        info.compress_type,
    )
    crc = crc if wz_aes_stores_crc(aes.wz_aes_version) else 0
    return wz_aes_extra, crc, WZ_AES_COMPRESS_TYPE


def encode_filename_flags(info: HeaderFields) -> tuple[bytes, int]:
    """Encode the filename and determine the UTF-8 flag.

    Attempts ASCII encoding first; falls back to UTF-8 and sets
    ``MASK_UTF_FILENAME`` in the returned flags when the name contains
    non-ASCII characters.

    Returns:
        A tuple of ``(encoded_filename_bytes, flag_bits)``.
    """
    try:
        return info.filename.encode("ascii"), info.flag_bits
    except UnicodeEncodeError:
        return info.filename.encode("utf-8"), info.flag_bits | MASK_UTF_FILENAME


def minimum_version(info: HeaderFields, zip64_version: int = 0) -> int:
    """Return the minimum ZIP version required by this entry."""
    versions = {
        ZIP_BZIP2: BZIP2_VERSION,
        ZIP_LZMA: LZMA_VERSION,
        ZIP_ZSTANDARD: ZSTANDARD_VERSION,
    }
    return max(zip64_version, versions.get(info.compress_type, 0))


def file_header(info: HeaderFields, zip64: bool | None = None) -> bytes:
    """Serialize the local file header of *info*.

    The effective ``extract_version`` accounts for ZIP64 and the
    compression type but is not written back to ``info``.

    Args:
        zip64: Force ZIP64 on (``True``), off (``False``), or auto-detect
            (``None``). Auto-detect enables ZIP64 when either stored size
            exceeds ``ZIP64_LIMIT``.

    Returns:
        Packed local file header followed by the encoded filename and
        extra-data bytes.
    """
    if info.use_data_descriptor:
        # Set these to zero because we write them after the file data
        crc = compress_size = file_size = 0
    else:
        crc = info.CRC
        compress_size = info.compress_size
        file_size = info.file_size
    extra, file_size, compress_size, zip64_version = zip64_local_extra(
        zip64, file_size, compress_size
    )
    min_version = minimum_version(info, zip64_version)
    filename, flag_bits = encode_filename_flags(info)
    wz_aes_extra, crc, compress_type = encode_extra(info, crc, info.compress_type)
    extra += user_extra(info) + wz_aes_extra
    header = struct.pack(
        FILE_HEADER_STRUCT,
        FILE_HEADER_SIGNATURE,
        max(min_version, info.extract_version),
        info.reserved,
        flag_bits,
        compress_type,
        info.get_dostime(),
        info.get_dosdate(),
        crc,
        compress_size,
        file_size,
        len(filename),
        len(extra),
    )
    return header + filename + extra


def data_descriptor(info: HeaderFields, zip64: bool) -> bytes:
    """Encode the data descriptor of *info*, from its CRC and sizes.

    Args:
        zip64: When ``True``, use 64-bit fields for the sizes.

    Returns:
        Packed data descriptor including the ``PK\x07\x08`` signature.
    """
    _, crc, _ = encode_extra(info, info.CRC, info.compress_type)
    fmt = "<LLQQ" if zip64 else "<LLLL"
    return struct.pack(fmt, DD_SIGNATURE, crc, info.compress_size, info.file_size)
