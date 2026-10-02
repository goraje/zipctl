"""Opening a member of a ZipFile for writing, and copying one raw."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, cast

from zipctl.compression import ZIP_LZMA
from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import LargeZipFile
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.file.encryption import (
    INHERIT_ENCRYPTION,
    EncryptionOverride,
    ZipFileExtra,
    entry_encryptor,
)
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.info.extra import _Extra
from zipctl.zipfile.shared import (
    MASK_COMPRESS_OPTION_1,
    MASK_COMPRESS_OPTIONS,
    MASK_USE_DATA_DESCRIPTOR,
    ZIP64_LIMIT,
    ZIP_FILECOUNT_LIMIT,
)
from zipctl.zipfile.write import ZipWriteFile

if TYPE_CHECKING:
    from zipctl.zipfile.file import ZipFile


def open_to_write(
    zf: ZipFile,
    zinfo: ZipInfo,
    force_zip64: bool = False,
    *,
    encryption: EncryptionOverride = INHERIT_ENCRYPTION,
    password: bytes | None = None,
    extra: ZipFileExtra | None = None,
    raw: bool = False,
) -> ZipWriteFile:
    """Open *zinfo* for writing and return a ZipWriteFile.

    Initialises CRC and size fields, computes the ZIP64 requirement,
    writes the local file header, sets up encryption if configured, and
    registers the returned handle as the active write handle.

    Args:
        zinfo: Metadata for the new entry. Modified in place (CRC, sizes,
            flags, ``header_offset``).
        force_zip64: When ``True``, force ZIP64 local header fields
            regardless of file size.
        raw: The entry takes compressed data (:meth:`_copy_raw`): *zinfo*
            keeps its CRC, sizes and compression option bits, and its
            ``compress_size`` says how much is coming.

    Returns:
        A :class:`~zipctl.zipfile.write.ZipWriteFile` ready to
        accept data.

    Raises:
        ValueError: If *force_zip64* is ``True`` but ZIP64 is not allowed,
            or if a write handle is already open.
        LargeZipFile: If ZIP64 is required but not allowed.
    """
    if force_zip64 and not zf._allow_zip64:
        raise ValueError(
            "force_zip64 is True, but allowZip64 was False when opening the ZIP file."
        )
    reservation = zf._write_coordinator.reserve()
    try:
        if zf._write_failed:
            raise ValueError("Cannot recover a failed write on a non-seekable archive")
        if zf.fp is None:
            raise ValueError("Attempt to write ZIP archive that was already closed")
        zip64 = prepare_header(zf, zinfo, force_zip64=force_zip64, raw=raw)

        assert zf.fp is not None
        if zf._seekable:
            zf.fp.seek(zf.start_dir)
        zinfo.header_offset = zf.fp.tell()

        check_writable(zf, zinfo)
        zf._mark_modified()

        encryptor = entry_encryptor(zf, zinfo, encryption, password, extra)

        return ZipWriteFile(
            zf,
            zinfo,
            zip64,
            encryptor,
            zf._compression_registry,
            reservation,
            raw,
        )
    except BaseException:
        if not zf._seekable:
            zf._write_failed = True
        zf._write_coordinator.release(reservation)
        raise


def prepare_header(
    zf: ZipFile, zinfo: ZipInfo, *, force_zip64: bool, raw: bool
) -> bool:
    """Set the flags and default attributes of an entry about to be written.

    Returns whether the local header needs ZIP64 fields.
    """
    coming = zinfo.compress_size
    zinfo._stored_filename = None
    zinfo.aes_extra = WzAesExtra()
    zinfo.extra = _Extra.strip(zinfo.extra, (EXTRA_WZ_AES,))
    zinfo.compress_size = 0
    if raw:
        zinfo.flag_bits &= MASK_COMPRESS_OPTIONS
    else:
        zinfo.CRC = 0
        zinfo.flag_bits = 0x00
        if zinfo.compress_type == ZIP_LZMA:
            zinfo.flag_bits |= MASK_COMPRESS_OPTION_1
    if not zf._seekable:
        zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

    if not zinfo.external_attr:
        zinfo.external_attr = 0o600 << 16

    zip64 = force_zip64 or (
        zinfo.file_size + zinfo.file_size // 20 > ZIP64_LIMIT
        # the encryption adds a few bytes of its own to what is coming
        or (raw and coming + 64 > ZIP64_LIMIT)
    )
    if not zf._allow_zip64 and zip64:
        raise LargeZipFile("Filesize would require ZIP64 extensions")
    return zip64


def check_writable(zf: ZipFile, zinfo: ZipInfo) -> None:
    """Validate that *zinfo* can be written to the archive.

    Issues a warning for duplicate names and raises on invalid archive
    state, unsupported compression, or ZIP64 violations.

    Args:
        zinfo: Metadata for the entry about to be written.

    Raises:
        ValueError: If the archive is not open for writing or is already
            closed.
        LargeZipFile: If a size or count threshold would require ZIP64
            extensions that are not enabled.
    """
    if zinfo.filename in zf.NameToInfo:
        warnings.warn("Duplicate name: %r" % zinfo.filename, stacklevel=4)
    if zf.mode not in ("w", "x", "a"):
        raise ValueError("write() requires mode 'w', 'x', or 'a'")
    if not zf.fp:
        raise ValueError("Attempt to write ZIP archive that was already closed")
    zf._compression_registry.check_compression(zinfo.compress_type)
    if not zf._allow_zip64:
        requires_zip64 = None
        if len(zf.filelist) >= ZIP_FILECOUNT_LIMIT:
            requires_zip64 = "Files count"
        elif zinfo.file_size > ZIP64_LIMIT:
            requires_zip64 = "Filesize"
        elif zinfo.header_offset > ZIP64_LIMIT:
            requires_zip64 = "Zipfile size"
        if requires_zip64:
            raise LargeZipFile(requires_zip64 + " would require ZIP64 extensions")


def copy_raw(
    zf: ZipFile,
    source: ZipFile,
    info: ZipInfo,
    zinfo: ZipInfo,
    *,
    crc: int,
    size: int,
    pwd: bytes | None = None,
    encryption: EncryptionOverride = INHERIT_ENCRYPTION,
    password: bytes | None = None,
    extra: ZipFileExtra | None = None,
) -> None:
    """Copy member *info* of *source* into this archive as *zinfo*, without
    decompressing or compressing it.

    The compressed bytes are decrypted with *pwd* and written again under
    *encryption* and *password*, so a copy that keeps the compression stays
    byte for byte the same inside.  Nothing is decompressed, so the caller
    vouches for *crc* and *size* (the CRC-32 and length of the uncompressed
    data); a plain or ZipCrypto member is not checked here at all.  The
    entry keeps *info*'s compression method and compression option bits.
    ``zinfo`` needs the filename, date and attributes; its compression,
    sizes and option bits are set here.

    Private, but a contract for zipctl's own copy commands (``encrypt``,
    ``decrypt`` and ``rewrite``); ``tests/unit/zipfile/test_raw_copy.py``
    pins it.
    """
    zinfo.compress_type = info.compress_type
    zinfo.flag_bits = info.flag_bits
    zinfo.compress_size = info.compress_size
    zinfo.CRC = crc
    zinfo.file_size = size
    with (
        cast(ZipExtFile, source.open(info, "r", pwd)) as reader,  # pyright: ignore[reportInvalidCast]
        zf._open_to_write(
            zinfo, encryption=encryption, password=password, extra=extra, raw=True
        ) as writer,
    ):
        for chunk in reader._raw_chunks():
            writer._write_raw(chunk)
