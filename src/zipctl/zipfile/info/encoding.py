"""Serialising a ZipInfo into local and central directory records."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from zipctl.compression import ZIP_BZIP2, ZIP_LZMA, ZIP_ZSTANDARD
from zipctl.compression.methods import (
    BZIP2_VERSION,
    LZMA_VERSION,
    ZSTANDARD_VERSION,
)
from zipctl.cryptography import (
    WZ_AES_DEFAULT_VERSION,
    WZ_AES_V1,
    WZ_AES_V2,
    wz_aes_stores_crc,
)
from zipctl.cryptography.aes import EXTRA_WZ_AES, WZ_AES_COMPRESS_TYPE
from zipctl.exceptions import LargeZipFile
from zipctl.zipfile.info.extra import EXTRA_ZIP64, _Extra
from zipctl.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_STRUCT,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_STRUCT,
    MASK_UTF_FILENAME,
    ZIP64_LIMIT,
    ZIP64_VERSION,
)

if TYPE_CHECKING:
    from zipctl.zipfile.info import ZipInfo

__all__ = ["central_directory", "encode_extra", "encode_filename_flags", "file_header"]


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
    requires_zip64 = file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT
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
    if zip64:
        file_size = 0xFFFFFFFF
        compress_size = 0xFFFFFFFF
        min_version = ZIP64_VERSION
    elif requires_zip64:
        raise LargeZipFile("Filesize would require ZIP64 extensions")
    return extra, file_size, compress_size, min_version


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
    if info.file_size > ZIP64_LIMIT:
        zip64_fields.append(info.file_size)
        file_size = 0xFFFFFFFF
    else:
        file_size = info.file_size

    if info.compress_size > ZIP64_LIMIT:
        zip64_fields.append(info.compress_size)
        compress_size = 0xFFFFFFFF
    else:
        compress_size = info.compress_size

    if info.header_offset > ZIP64_LIMIT:
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
    # Preserve existing extra data, stripping any old ZIP64 entry first
    existing_extra = _Extra.strip(info.extra, (EXTRA_ZIP64, EXTRA_WZ_AES))
    extra_data = zip64_extra + existing_extra
    return extra_data, file_size, compress_size, header_offset, min_version


def minimum_version(info: ZipInfo, zip64_version: int = 0) -> int:
    """Return the minimum ZIP version required by this entry."""
    versions = {
        ZIP_BZIP2: BZIP2_VERSION,
        ZIP_LZMA: LZMA_VERSION,
        ZIP_ZSTANDARD: ZSTANDARD_VERSION,
    }
    return max(zip64_version, versions.get(info.compress_type, 0))


def encode_extra(info: ZipInfo, crc: int, compress_type: int) -> tuple[bytes, int, int]:
    """Encode the WinZip AES extra field and adjust CRC and compression type.

    When ``aes_extra.wz_aes_vendor_id`` is ``None`` (non-AES entry) this
    method is a no-op: the extra bytes are empty and *crc* and
    *compress_type* are returned unchanged.

    For AES entries, *compress_type* is overridden to
    ``WZ_AES_COMPRESS_TYPE`` (99). When ``wz_aes_version`` is ``None``,
    ``WZ_AES_V2`` is selected. Version 2 entries have their CRC zeroed;
    version 1 is retained only when explicitly requested for compatibility.

    Args:
        crc: CRC-32 of the uncompressed data.
        compress_type: Compression method code before AES wrapping.

    Returns:
        A tuple of ``(extra_bytes, crc, compress_type)`` containing the
        AES extra field bytes (may be empty), the adjusted CRC, and the
        adjusted compression type.
    """
    wz_aes_extra = b""
    if info.aes_extra.wz_aes_vendor_id is not None:
        compress_type = WZ_AES_COMPRESS_TYPE
        aes_version = info.aes_extra.wz_aes_version
        if aes_version is None:
            aes_version = WZ_AES_DEFAULT_VERSION
        if aes_version not in (WZ_AES_V1, WZ_AES_V2):
            raise ValueError("force_wz_aes_version must be 1 or 2")
        if not wz_aes_stores_crc(aes_version):
            crc = 0
        wz_aes_extra = struct.pack(
            "<3H2sBH",
            EXTRA_WZ_AES,
            7,  # extra block body length: H2sBH
            aes_version,
            info.aes_extra.wz_aes_vendor_id,
            info.aes_extra.wz_aes_strength,
            info.compress_type,
        )
    return wz_aes_extra, crc, compress_type


def encode_local_header(
    info: ZipInfo,
    *,
    filename: bytes,
    extract_version: int,
    reserved: int,
    flag_bits: int,
    compress_type: int,
    dostime: int,
    dosdate: int,
    crc: int,
    compress_size: int,
    file_size: int,
    extra: bytes,
) -> bytes:
    """Serialize a local file header record.

    Appends any WinZip AES extra bytes after the caller-supplied *extra*
    data before packing the header struct.

    Args:
        filename: Encoded filename bytes.
        extract_version: Minimum version needed to extract.
        reserved: Reserved field value (must be 0).
        flag_bits: General-purpose bit flags.
        compress_type: Compression method code.
        dostime: DOS-encoded time word.
        dosdate: DOS-encoded date word.
        crc: CRC-32 of the uncompressed data.
        compress_size: Compressed size in bytes.
        file_size: Uncompressed size in bytes.
        extra: ZIP64 (and any other) extra-data bytes.

    Returns:
        Packed local file header followed by *filename* and *extra* bytes.
    """
    wz_aes_extra, crc, compress_type = encode_extra(info, crc, compress_type)
    extra = extra + wz_aes_extra
    header = struct.pack(
        FILE_HEADER_STRUCT,
        FILE_HEADER_SIGNATURE,
        extract_version,
        reserved,
        flag_bits,
        compress_type,
        dostime,
        dosdate,
        crc,
        compress_size,
        file_size,
        len(filename),
        len(extra),
    )
    return header + filename + extra


def encode_central_directory(
    info: ZipInfo,
    *,
    filename: bytes,
    create_version: int,
    create_system: int,
    extract_version: int,
    reserved: int,
    flag_bits: int,
    compress_type: int,
    dostime: int,
    dosdate: int,
    crc: int,
    compress_size: int,
    file_size: int,
    disk_start: int,
    internal_attr: int,
    external_attr: int,
    header_offset: int,
    extra_data: bytes,
    comment: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Serialize a central directory record for this entry.

    Appends any WinZip AES extra bytes after the caller-supplied
    *extra_data* before packing the central directory struct.

    Args:
        filename: Encoded filename bytes.
        create_version: ZIP spec version used when the entry was created.
        create_system: OS code for the system that created the entry.
        extract_version: Minimum version needed to extract.
        reserved: Reserved field value (must be 0).
        flag_bits: General-purpose bit flags.
        compress_type: Compression method code.
        dostime: DOS-encoded time word.
        dosdate: DOS-encoded date word.
        crc: CRC-32 of the uncompressed data.
        compress_size: Compressed size in bytes.
        file_size: Uncompressed size in bytes.
        disk_start: Disk number where the local header resides.
        internal_attr: Internal file attributes.
        external_attr: External file attributes.
        header_offset: Byte offset of the local file header.
        extra_data: ZIP64 (and any other) extra-data bytes.
        comment: Per-file comment bytes.

    Returns:
        A tuple of ``(centdir_bytes, filename_bytes, extra_data_bytes)``.
    """
    wz_aes_extra, crc, compress_type = encode_extra(info, crc, compress_type)
    extra_data = extra_data + wz_aes_extra
    centdir = struct.pack(
        CENTRAL_DIR_STRUCT,
        CENTRAL_DIR_SIGNATURE,
        create_version,
        create_system,
        extract_version,
        reserved,
        flag_bits,
        compress_type,
        dostime,
        dosdate,
        crc,
        compress_size,
        file_size,
        len(filename),
        len(extra_data),
        len(comment),
        disk_start,
        internal_attr,
        external_attr,
        header_offset,
    )
    return centdir, filename, extra_data


def central_directory(
    info: ZipInfo,
) -> tuple[bytes, bytes, bytes]:
    """Serialize this entry's central directory record.

    Computes the minimum required ZIP specification version from the
    compression type and ZIP64 requirements, then delegates to
    ``_encode_central_directory``.

    Returns:
        A tuple of ``(centdir_bytes, filename_bytes, extra_data_bytes)``
        suitable for writing directly into the central directory.
    """
    dosdate = info.get_dosdate()
    dostime = info.get_dostime()
    (
        extra_data,
        file_size,
        compress_size,
        header_offset,
        min_version,
    ) = zip64_central_extra(info)

    min_version = minimum_version(info, min_version)

    extract_version = max(min_version, info.extract_version)
    create_version = max(min_version, info.create_version)
    filename, flag_bits = info._stored_filename or encode_filename_flags(info)
    # Writing multi-disk archives is not supported so disk_start is always 0
    disk_start = 0
    return encode_central_directory(
        info,
        filename=filename,
        create_version=create_version,
        create_system=info.create_system,
        extract_version=extract_version,
        reserved=info.reserved,
        flag_bits=flag_bits,
        compress_type=info.compress_type,
        dostime=dostime,
        dosdate=dosdate,
        crc=info.CRC,
        compress_size=compress_size,
        file_size=file_size,
        disk_start=disk_start,
        internal_attr=info.internal_attr,
        external_attr=info.external_attr,
        header_offset=header_offset,
        extra_data=extra_data,
        comment=info.comment,
    )


def file_header(info: ZipInfo, zip64: bool | None = None) -> bytes:
    """Serialize the local file header for this entry.

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
    dosdate = info.get_dosdate()
    dostime = info.get_dostime()
    if info.use_data_descriptor:
        # Set these to zero because we write them after the file data
        crc = compress_size = file_size = 0
    else:
        crc = info.CRC
        compress_size = info.compress_size
        file_size = info.file_size

    min_version = 0
    extra, file_size, compress_size, zip64_min_version = zip64_local_extra(
        zip64, file_size, compress_size
    )
    min_version = max(min_version, zip64_min_version)

    min_version = minimum_version(info, min_version)

    extract_version = max(min_version, info.extract_version)
    filename, flag_bits = encode_filename_flags(info)
    return encode_local_header(
        info,
        filename=filename,
        extract_version=extract_version,
        reserved=info.reserved,
        flag_bits=flag_bits,
        compress_type=info.compress_type,
        dostime=dostime,
        dosdate=dosdate,
        crc=crc,
        compress_size=compress_size,
        file_size=file_size,
        extra=extra,
    )


def encode_filename_flags(
    info: ZipInfo,
) -> tuple[bytes, int]:
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
