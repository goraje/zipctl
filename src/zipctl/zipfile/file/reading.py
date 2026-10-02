"""Opening a member of a ZipFile for reading."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream
from zipctl.zipfile.records import read_local_header
from zipctl.zipfile.shared import MASK_ENCRYPTED, ReadWriteMode

if TYPE_CHECKING:
    from zipctl.zipfile.file import ZipFile


def open_to_read(
    zf: ZipFile, mode: ReadWriteMode, zinfo: ZipInfo, pwd: bytes | None
) -> ZipExtFile:
    """Open *zinfo* for reading and return a ZipExtFile.

    Validates the local file header, checks for overlapping entries, sets
    up decryption when the entry is encrypted, and returns a
    :class:`~zipctl.zipfile.ext.ZipExtFile` backed by the archive
    stream.

    Args:
        mode: Read mode (always ``'r'``).
        zinfo: Metadata for the entry to open.
        pwd: Decryption password, or ``None`` for unencrypted entries.

    Returns:
        A :class:`~zipctl.zipfile.ext.ZipExtFile` positioned at the
        start of the compressed data.

    Raises:
        BadZipFile: If the local header is truncated, has a bad signature,
            the filename mismatches the central directory, or entries
            overlap.
        NotImplementedError: If compressed patch data or strong encryption
            are detected.
        PasswordRequired: If the entry is encrypted and no password is
            available.
        BadPassword: If the password does not match the entry.
        TypeError: If *pwd* is not ``bytes``.
    """
    with zf._lock:
        if zf.fp is None:
            raise ValueError("Attempt to read ZIP archive that was already closed")
        zf._write_coordinator.ensure_readable()
        zf._file_ref_cnt += 1
        zef_file = ClosableZipStream(
            zf.fp,
            zinfo.header_offset,
            zf._fpclose,
            zf._lock,
            lambda: zf._write_coordinator.active,
        )
    try:
        read_local_header(zef_file, zinfo, zf.metadata_encoding)

        if (
            zinfo._end_offset is not None
            and zef_file.tell() + zinfo.compress_size > zinfo._end_offset
        ):
            if zinfo._end_offset == zinfo.header_offset:
                warnings.warn(
                    f"Overlapped entries: {zinfo.orig_filename!r} (possible zip bomb)",
                    stacklevel=2,
                )
            else:
                raise BadZipFile(
                    f"Overlapped entries: {zinfo.orig_filename!r} (possible zip bomb)"
                )

        is_encrypted = zinfo.flag_bits & MASK_ENCRYPTED
        if is_encrypted:
            if not pwd:
                pwd = zf.pwd
            if pwd and not isinstance(pwd, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise TypeError("pwd: expected bytes, got %s" % type(pwd).__name__)  # pyright: ignore[reportUnreachable]
            if not pwd:
                raise PasswordRequired(
                    "File %r is encrypted, password "
                    "required for extraction" % zinfo.orig_filename
                )
        else:
            pwd = None

        return ZipExtFile(
            zef_file,
            mode,
            zinfo,
            True,
            pwd,
            zf._compression_registry,
            zf._aes_keys,
            zf.limits,
        )
    except BaseException:
        zef_file.close()
        raise
