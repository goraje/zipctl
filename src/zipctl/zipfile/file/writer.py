"""Writing the entries of a ZipFile, one at a time."""

from __future__ import annotations

import copy
import threading
import weakref
from collections.abc import Iterable
from typing import IO

from zipctl.compression import Registry
from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import LargeZipFile
from zipctl.zipfile.encryption import (
    INHERIT_ENCRYPTION,
    EncryptionOverride,
    EncryptionSettings,
    ZipFileExtra,
)
from zipctl.zipfile.file.stream import ArchiveStream
from zipctl.zipfile.file.write import ZipWriteFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.info.extra import strip_extra
from zipctl.zipfile.records import Directory
from zipctl.zipfile.shared import (
    MASK_COMPRESS_OPTIONS,
    MASK_USE_DATA_DESCRIPTOR,
    needs_zip64,
)

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
        directory: Directory,
        encryption: EncryptionSettings,
        registry: Registry,
        *,
        allow_zip64: bool,
    ) -> None:
        self.mode: str = mode
        # weak, as in CPython: a handle dropped unclosed is finished when collected
        self._current: weakref.ref[ZipWriteFile] | None = None
        self.failed: bool = False
        self.allow_zip64: bool = allow_zip64
        self._stream: ArchiveStream = stream
        self._directory: Directory = directory
        self._encryption: EncryptionSettings = encryption
        self._registry: Registry = registry

    @property
    def current(self) -> ZipWriteFile | None:
        return None if self._current is None else self._current()

    @current.setter
    def current(self, entry: ZipWriteFile | None) -> None:
        self._current = None if entry is None else weakref.ref(entry)
        self._stream.writing = entry is not None  # what readers check

    def abort(self, exc: BaseException) -> None:
        """Abandon the open entry, if any, as if its ``with`` block raised *exc*."""
        with self.lock:
            entry = self.current
            if entry is not None:
                entry.__exit__(type(exc), exc, exc.__traceback__)

    # -- EntryOwner, for the open ZipWriteFile ------------------------------

    @property
    def fp(self) -> IO[bytes]:
        return self._stream.require_open("write")

    @property
    def lock(self) -> threading.RLock:
        return self._stream.lock

    def entry_written(self, entry: ZipWriteFile, zinfo: ZipInfo, end: int) -> None:
        if not self.allow_zip64 and needs_zip64(end):
            # Refused while the directory can still go where this entry began.
            raise LargeZipFile("Zipfile size would require ZIP64 extensions")
        self._directory.add(zinfo, end)
        self._release(entry)

    def entry_failed(self, entry: ZipWriteFile) -> None:
        if not self._stream.seekable:
            self.failed = True
        self._release(entry)

    def _release(self, entry: ZipWriteFile) -> None:
        # None: the cyclic GC cleared the weakref before finalising *entry*
        if self.current is entry or self.current is None:
            self.current = None

    # -----------------------------------------------------------------------

    def ensure_idle(self, action: str) -> None:
        """Raise ``ValueError`` if an entry is open, naming the refused *action*."""
        self._stream.ensure_not_writing(action)

    def open(
        self,
        zinfo: ZipInfo,
        *,
        force_zip64: bool = False,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
        raw: bool = False,
        verbatim: bool = False,
    ) -> ZipWriteFile:
        """Write *zinfo*'s local header and return the open entry.

        *zinfo* is copied, never changed: the open entry's ``zinfo`` holds the
        CRC, sizes, flags and ``header_offset`` that get written.
        With *raw* the entry takes compressed data (:meth:`copy_raw`): *zinfo*
        keeps its CRC, sizes and compression option bits, and its
        ``compress_size`` says how much is coming.  With *verbatim* as well the
        data is also already encrypted (:meth:`copy_stored`): *zinfo* keeps all
        its flags and its WZ-AES fields, and nothing is encrypted here.

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
            if self._stream.writing:
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
            if zinfo.filename in self._directory.by_name:
                raise ValueError(f"Duplicate name: {zinfo.filename!r}")
            zinfo = copy.copy(zinfo)
            start = fp.tell()
            try:
                entry = self._start_entry(
                    fp, zinfo, force_zip64, encryption, password, extra, raw, verbatim
                )
            except BaseException:
                # refused before a byte was written: the archive is still fine
                if not self._stream.seekable and fp.tell() != start:
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
        verbatim: bool,
    ) -> ZipWriteFile:
        zip64 = self._prepare_header(
            zinfo, force_zip64=force_zip64, raw=raw, verbatim=verbatim
        )
        if self._stream.seekable:
            fp.seek(self._directory.start_dir)
        zinfo.header_offset = fp.tell()
        self._check_limits(zinfo)
        encryptor = (
            None
            if verbatim
            else self._encryption.for_entry(zinfo, encryption, password, extra)
        )
        self._directory.modified = True
        return ZipWriteFile(self, zinfo, zip64, encryptor, self._registry, raw)

    def _prepare_header(
        self, zinfo: ZipInfo, *, force_zip64: bool, raw: bool, verbatim: bool
    ) -> bool:
        """Set the flags of an entry about to be written.

        Returns whether the local header needs ZIP64 fields.
        """
        coming = zinfo.compress_size
        if not verbatim:
            zinfo.aes_extra = None
        zinfo.extra = strip_extra(zinfo.extra, (EXTRA_WZ_AES,))
        zinfo.compress_size = 0
        if verbatim:
            if (
                not zinfo.is_aes
                and not self._stream.seekable
                and not zinfo.use_data_descriptor
            ):
                # ZipCrypto checks its header against the CRC unless bit 3 is
                # set, so the bit cannot be added to bytes already encrypted;
                # WZ-AES data does not depend on it.
                raise ValueError(
                    "A ZipCrypto member without a data descriptor cannot be "
                    "copied as it is to an unseekable archive"
                )
        elif raw:
            zinfo.flag_bits &= MASK_COMPRESS_OPTIONS
        else:
            zinfo.CRC = 0
            zinfo.flag_bits = 0x00
        if not self._stream.seekable:
            zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

        zip64 = force_zip64 or needs_zip64(
            zinfo.file_size + zinfo.file_size // 20,
            # the encryption adds a few bytes of its own to what is coming
            coming + 64 if raw else 0,
        )
        if not self.allow_zip64 and zip64:
            raise LargeZipFile("Filesize would require ZIP64 extensions")
        return zip64

    def _check_limits(self, zinfo: ZipInfo) -> None:
        """Raise ``LargeZipFile`` if *zinfo* needs ZIP64 and it is not allowed."""
        if self.allow_zip64:
            return
        # The file size was checked with the header.  Counted with the entry
        # being added, which must not make the count reach 0xFFFF.
        if needs_zip64(count=len(self._directory.infos) + 1):
            raise LargeZipFile("Files count would require ZIP64 extensions")
        if needs_zip64(zinfo.header_offset):
            raise LargeZipFile("Zipfile size would require ZIP64 extensions")

    def copy_raw(
        self,
        chunks: Iterable[bytes],
        info: ZipInfo,
        zinfo: ZipInfo,
        *,
        crc: int,
        size: int,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Write *info*'s compressed data, from *chunks*, here as *zinfo*.

        *chunks* are the decrypted but still compressed bytes (see
        :meth:`ZipExtFile.raw_chunks`); they are written again under
        *encryption* and *password*, so the compressed data stays byte for
        byte the same.  Nothing is decompressed, so the caller vouches for
        *crc* and *size* (the CRC-32 and length of the uncompressed data), as
        :meth:`ZipFile.copy_member` does by reading the member first.  The
        entry keeps *info*'s compression method and option bits; ``zinfo``
        gives the filename, date and attributes.
        """
        zinfo = copy.copy(zinfo)
        zinfo.compress_type = info.compress_type
        zinfo.flag_bits = info.flag_bits
        zinfo.compress_size = info.compress_size
        zinfo.CRC = crc
        zinfo.file_size = size
        with self.open(
            zinfo, encryption=encryption, password=password, extra=extra, raw=True
        ) as writer:
            for chunk in chunks:
                writer.write_raw(chunk)

    def copy_stored(
        self, chunks: Iterable[bytes], info: ZipInfo, zinfo: ZipInfo
    ) -> None:
        """Write the member *info* describes as *zinfo*, from its stored bytes.

        *chunks* are the data exactly as stored in the source archive (see
        :meth:`ArchiveReader.stored_chunks`), encryption included, so the
        member keeps its protection without its password being known.  The
        entry takes *info*'s method, flags, CRC, sizes and WZ-AES fields;
        ``zinfo`` gives the name, date and attributes.
        """
        zinfo = copy.copy(zinfo)
        zinfo.compress_type = info.compress_type
        zinfo.flag_bits = info.flag_bits
        zinfo.aes_extra = info.aes_extra
        zinfo.compress_size = info.compress_size
        zinfo.CRC = info.CRC
        zinfo.file_size = info.file_size
        chunks = iter(chunks)
        # a bad source header fails here, before anything is written
        first = next(chunks, b"")
        with self.open(zinfo, raw=True, verbatim=True) as writer:
            writer.write_raw(first)
            for chunk in chunks:
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
