"""Writing the entries of a ZipFile, one at a time."""

from __future__ import annotations

import threading
import warnings
from typing import IO

from zipctl.compression import ZIP_LZMA, Registry
from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import LargeZipFile
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.file.directory import CentralDirectory
from zipctl.zipfile.file.encryption import (
    INHERIT_ENCRYPTION,
    EncryptionOverride,
    EncryptionSettings,
    ZipFileExtra,
)
from zipctl.zipfile.file.stream import ArchiveStream
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.info.extra import Extra
from zipctl.zipfile.shared import (
    MASK_COMPRESS_OPTION_1,
    MASK_COMPRESS_OPTIONS,
    MASK_USE_DATA_DESCRIPTOR,
    ZIP64_LIMIT,
    ZIP_FILECOUNT_LIMIT,
    user_stacklevel,
)
from zipctl.zipfile.write import ZipWriteFile

__all__ = ["ArchiveWriter"]


class ArchiveWriter:
    """Adds entries to an archive opened for writing or appending.

    A ZIP archive is written front to back, so at most one entry is open at a
    time: :attr:`current`.  While it is open the archive can be neither read
    nor closed; every step runs under the stream's lock, which the open entry
    also holds while it writes or finishes, so a close from another thread
    waits for an entry that is finishing rather than failing.

    On a stream that cannot seek, an entry that fails leaves bytes that cannot
    be taken back, so the archive is :attr:`failed` for good.

    Attributes:
        current: The entry being written, if any.
        failed: A failed entry on an unseekable stream ruined the archive.
    """

    def __init__(
        self,
        mode: str,
        stream: ArchiveStream,
        directory: CentralDirectory,
        encryption: EncryptionSettings,
        registry: Registry,
        *,
        allow_zip64: bool,
    ) -> None:
        self.mode: str = mode
        self.current: ZipWriteFile | None = None
        self.failed: bool = False
        self.allow_zip64: bool = allow_zip64
        self._stream: ArchiveStream = stream
        self._directory: CentralDirectory = directory
        self._encryption: EncryptionSettings = encryption
        self._registry: Registry = registry

    # -- EntryOwner, for the open ZipWriteFile ------------------------------

    @property
    def fp(self) -> IO[bytes]:
        return self._stream.require_open("write")

    @property
    def lock(self) -> threading.RLock:
        return self._stream.lock

    def entry_written(self, entry: ZipWriteFile, zinfo: ZipInfo, end: int) -> None:
        self._directory.add(zinfo)
        self._directory.start_dir = end
        if self.current is entry:
            self.current = None

    def entry_failed(self, entry: ZipWriteFile) -> None:
        if not self._stream.seekable:
            self.failed = True
        if self.current is entry:
            self.current = None

    # -----------------------------------------------------------------------

    def ensure_idle(self, action: str) -> None:
        """Raise ``ValueError`` if an entry is open, naming the refused *action*."""
        if self.current is not None:
            raise ValueError(
                f"Can't {action} the ZIP file while there is an open writing "
                "handle on it. Close the writing handle first."
            )

    def open(
        self,
        zinfo: ZipInfo,
        *,
        force_zip64: bool = False,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
        raw: bool = False,
    ) -> ZipWriteFile:
        """Write *zinfo*'s local header and return the open entry.

        *zinfo* is updated in place (CRC, sizes, flags, ``header_offset``).
        With *raw* the entry takes compressed data (:meth:`copy_raw`): *zinfo*
        keeps its CRC, sizes and compression option bits, and its
        ``compress_size`` says how much is coming.

        Raises:
            ValueError: If the archive is closed, not writable, failed, or
                already has an open entry, or *force_zip64* is not allowed.
            LargeZipFile: If ZIP64 is required but not allowed.
        """
        with self.lock:
            fp = self.fp
            if self.mode not in ("w", "x", "a"):
                raise ValueError("write() requires mode 'w', 'x', or 'a'")
            if self.failed:
                raise ValueError(
                    "Cannot recover a failed write on a non-seekable archive"
                )
            if self.current is not None:
                raise ValueError(
                    "Can't write to the ZIP file while there is "
                    "another write handle open"
                )
            if force_zip64 and not self.allow_zip64:
                raise ValueError(
                    "force_zip64 is True, but allowZip64 was False when opening "
                    "the ZIP file."
                )
            self._registry.check_compression(zinfo.compress_type)
            try:
                entry = self._start_entry(
                    fp, zinfo, force_zip64, encryption, password, extra, raw
                )
            except BaseException:
                if not self._stream.seekable:
                    self.failed = True
                raise
            self.current = entry
            return entry

    def _start_entry(
        self,
        fp: IO[bytes],
        zinfo: ZipInfo,
        force_zip64: bool,
        encryption: EncryptionOverride,
        password: bytes | None,
        extra: ZipFileExtra | None,
        raw: bool,
    ) -> ZipWriteFile:
        zip64 = self._prepare_header(zinfo, force_zip64=force_zip64, raw=raw)
        if self._stream.seekable:
            fp.seek(self._directory.start_dir)
        zinfo.header_offset = fp.tell()
        self._check_limits(zinfo)
        if zinfo.filename in self._directory.by_name:
            warnings.warn(
                f"Duplicate name: {zinfo.filename!r}", stacklevel=user_stacklevel()
            )
        encryptor = self._encryption.for_entry(zinfo, encryption, password, extra)
        self._directory.modified = True
        return ZipWriteFile(self, zinfo, zip64, encryptor, self._registry, raw)

    def _prepare_header(self, zinfo: ZipInfo, *, force_zip64: bool, raw: bool) -> bool:
        """Set the flags and default attributes of an entry about to be written.

        Returns whether the local header needs ZIP64 fields.
        """
        coming = zinfo.compress_size
        zinfo._stored_filename = None  # pyright: ignore[reportPrivateUsage]  # re-encoded for this archive
        zinfo.aes_extra = WzAesExtra()
        zinfo.extra = Extra.strip(zinfo.extra, (EXTRA_WZ_AES,))
        zinfo.compress_size = 0
        if raw:
            zinfo.flag_bits &= MASK_COMPRESS_OPTIONS
        else:
            zinfo.CRC = 0
            zinfo.flag_bits = 0x00
            if zinfo.compress_type == ZIP_LZMA:
                zinfo.flag_bits |= MASK_COMPRESS_OPTION_1
        if not self._stream.seekable:
            zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR
        if not zinfo.external_attr:
            zinfo.external_attr = 0o600 << 16

        zip64 = force_zip64 or (
            zinfo.file_size + zinfo.file_size // 20 > ZIP64_LIMIT
            # the encryption adds a few bytes of its own to what is coming
            or (raw and coming + 64 > ZIP64_LIMIT)
        )
        if not self.allow_zip64 and zip64:
            raise LargeZipFile("Filesize would require ZIP64 extensions")
        return zip64

    def _check_limits(self, zinfo: ZipInfo) -> None:
        """Raise ``LargeZipFile`` if *zinfo* needs ZIP64 and it is not allowed."""
        if self.allow_zip64:
            return
        requires_zip64 = None
        if len(self._directory.infos) >= ZIP_FILECOUNT_LIMIT:
            requires_zip64 = "Files count"
        elif zinfo.file_size > ZIP64_LIMIT:
            requires_zip64 = "Filesize"
        elif zinfo.header_offset > ZIP64_LIMIT:
            requires_zip64 = "Zipfile size"
        if requires_zip64:
            raise LargeZipFile(requires_zip64 + " would require ZIP64 extensions")

    def copy_raw(
        self,
        reader: ZipExtFile,
        info: ZipInfo,
        zinfo: ZipInfo,
        *,
        crc: int,
        size: int,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Copy the member *reader* reads (*info*) here as *zinfo*, as it is.

        The compressed bytes are decrypted by *reader* and written again under
        *encryption* and *password*, so a copy that keeps the compression stays
        byte for byte the same inside.  Nothing is decompressed, so the caller
        vouches for *crc* and *size* (the CRC-32 and length of the uncompressed
        data); a plain or ZipCrypto member is not checked here at all.  The
        entry keeps *info*'s compression method and compression option bits.
        ``zinfo`` needs the filename, date and attributes; its compression,
        sizes and option bits are set here.
        """
        zinfo.compress_type = info.compress_type
        zinfo.flag_bits = info.flag_bits
        zinfo.compress_size = info.compress_size
        zinfo.CRC = crc
        zinfo.file_size = size
        with self.open(
            zinfo, encryption=encryption, password=password, extra=extra, raw=True
        ) as writer:
            for chunk in reader.raw_chunks():
                writer.write_raw(chunk)

    def finish(self) -> None:
        """Write the central directory if anything changed, for closing.

        Raises:
            ValueError: If an entry is still open, or a failed entry ruined an
                unseekable archive.
        """
        self.ensure_idle("close")
        if self.failed:
            raise ValueError("Cannot finalize a failed non-seekable archive")
        if self.mode in ("w", "x", "a") and self._directory.modified:
            self._directory.write(
                self.fp, allow_zip64=self.allow_zip64, truncate=self._stream.seekable
            )
