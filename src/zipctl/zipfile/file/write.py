"""Writable file-like object for streaming data into a ZIP archive entry."""

from __future__ import annotations

import io
import threading
from enum import Enum
from types import TracebackType
from typing import IO, TYPE_CHECKING, Protocol

from typing_extensions import override

from zipctl.compression import Registry, registry
from zipctl.compression.methods import CompressorBase

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

from zipctl.zipfile.encryption import Encryptor
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import write_all
from zipctl.zipfile.records import data_descriptor, file_header
from zipctl.zipfile.shared import crc32, needs_zip64

__all__ = ["EntryOwner", "ZipWriteFile"]


class WriteState(str, Enum):
    ACTIVE = "active"
    COMMITTED = "committed"
    FAILED = "failed"
    CLOSED = "closed"  # never written to: not built yet, or nothing to do


class EntryOwner(Protocol):
    """What a :class:`ZipWriteFile` needs from the archive it writes into."""

    @property
    def fp(self) -> IO[bytes]: ...

    @property
    def lock(self) -> threading.RLock: ...

    def entry_written(self, entry: ZipWriteFile, zinfo: ZipInfo, end: int) -> None:
        """*entry* is complete; the archive continues at offset *end*."""
        ...

    def entry_failed(self, entry: ZipWriteFile) -> None:
        """*entry* failed and is abandoned."""
        ...


class ZipWriteFile(io.BufferedIOBase):
    """Writable, file-like object returned by :meth:`ZipFile.open` in write mode.

    Streams data through an optional compressor and encryptor before writing
    it to the underlying ZIP archive.  The local file header is emitted
    during construction; CRC-32, compressed size, and uncompressed size are
    finalised when :meth:`close` is called.

    Do not instantiate this class directly — use :meth:`ZipFile.open` or
    :meth:`ZipFile.writestr`.
    """

    def __init__(
        self,
        owner: EntryOwner,
        zinfo: ZipInfo,
        zip64: bool,
        encryptor: Encryptor | None = None,
        compression_registry: Registry = registry,
        raw: bool = False,
    ) -> None:
        """Initialise the write-file, emit the local header, and (if requested)
        the encryption header.

        Writes and closing hold the owner's lock, so the archive cannot be
        closed or read from another thread in the middle of either.

        Args:
            owner: The archive being written.
            zinfo: Metadata for the entry being written.
            zip64: Whether to use ZIP64 extensions for this entry.
            encryptor: Optional encryptor, for a *zinfo* already marked
                encrypted; its header is written right after the local header.
            raw: The data is already compressed (see :meth:`write_raw`); the
                CRC-32 and sizes come from *zinfo* and nothing is compressed.
        """
        # Inert until fully built, so a failure below (say, an unusable
        # compression level) does not make close() misbehave when the
        # half-built object is finalised.
        self._state: WriteState = WriteState.CLOSED
        self._lock: threading.RLock = owner.lock
        self._zinfo: ZipInfo = zinfo
        self._zip64: bool = zip64
        self._owner: EntryOwner = owner
        self._raw: bool = raw
        self._compressor: CompressorBase | None = (
            None
            if raw
            else compression_registry.get_compressor(
                zinfo.compress_type, zinfo.compress_level
            )
        )
        self._encryptor: Encryptor | None = encryptor
        self._file_size: int = zinfo.file_size if raw else 0
        self._compress_size: int = 0
        self._crc: int = zinfo.CRC if raw else 0
        self._error: BaseException | None = None

        if self._compressor is not None:
            zinfo.flag_bits |= self._compressor.flag_bits
        self._write_local_header()

        if self._encryptor:
            self._write_encryption_header()
        self._state = WriteState.ACTIVE

    @property
    def _fileobj(self) -> IO[bytes]:
        """The archive's file object."""
        return self._owner.fp

    @property
    def name(self) -> str:
        """The filename of the ZIP entry being written."""
        return self._zinfo.filename

    @property
    def mode(self) -> str:
        """Always ``'wb'`` for a write-mode entry."""
        return "wb"

    @override
    def writable(self) -> bool:
        """Return ``True``; this stream is always writable."""
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True

    def _write_local_header(self) -> None:
        """Serialise and write the local file header to the archive."""
        write_all(self._fileobj, file_header(self._zinfo, self._zip64))

    def _write_encryption_header(self) -> None:
        """Request the encryption header from the encryptor and write it.

        The encryption header bytes are counted toward :attr:`_compress_size`
        because they appear before the compressed ciphertext in the stream.
        """
        assert self._encryptor is not None
        buf = self._encryptor.encryption_header()
        self._compress_size += len(buf)
        write_all(self._fileobj, buf)

    @override
    def write(self, data: ReadableBuffer, /) -> int:
        """Write *data* to the ZIP entry, compressing and encrypting as needed.

        Accepts any object that supports the buffer protocol (``bytes``,
        ``bytearray``, ``memoryview``, ``array.array``, or any object
        implementing ``__buffer__``).

        Args:
            data: The plaintext bytes to write.

        Returns:
            The number of uncompressed bytes consumed from *data*.

        Raises:
            ValueError: If the file has already been closed.
        """
        with self._lock:
            self._ensure_active()
            if self._raw:
                raise ValueError("a raw entry takes write_raw, not write")
            if not isinstance(data, (bytes, bytearray)):
                data = memoryview(data)  # a bad argument must not fail the entry
            try:
                return self._write(data)
            except BaseException as exc:
                self._fail(exc)
                raise

    def _ensure_active(self) -> None:
        if self._state == WriteState.FAILED:
            assert self._error is not None
            raise self._error
        if self.closed or self._state != WriteState.ACTIVE:
            raise ValueError("I/O operation on closed file.")

    def _write(self, data: bytes | bytearray | memoryview) -> int:
        assert self._compressor is not None

        nbytes = len(data) if isinstance(data, (bytes, bytearray)) else data.nbytes
        self._file_size += nbytes

        self._crc = crc32(data, self._crc)
        raw = data if isinstance(data, bytes) else bytes(data)
        raw = self._compressor.compress(raw)
        if self._encryptor:
            raw = self._encryptor.encrypt(raw)
        self._compress_size += len(raw)
        write_all(self._fileobj, raw)
        return nbytes

    def write_raw(self, data: bytes) -> None:
        """Write already compressed *data*, encrypted if the entry is.

        Only for an entry opened raw, where the CRC-32 and the uncompressed
        size were given up front and are trusted, not checked.
        """
        with self._lock:
            self._ensure_active()
            if not self._raw:
                raise ValueError("write_raw needs a raw entry")
            try:
                if self._encryptor:
                    data = self._encryptor.encrypt(data)
                self._compress_size += len(data)
                write_all(self._fileobj, data)
            except BaseException as exc:
                self._fail(exc)
                raise

    @override
    def __exit__(  # pyright: ignore[reportMissingSuperCall]  # close() is what the base does
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Commit the entry, or abort it if the ``with`` block raised.

        An aborted entry is never added to the archive: a seekable archive
        writes over its bytes, an unseekable one is failed for good.
        """
        if exc_val is not None:
            with self._lock:
                if self._state is WriteState.ACTIVE:
                    self._fail(exc_val)
            return
        self.close()

    @override
    def close(self) -> None:
        """Flush, finalise, and close the entry.

        Flushes any remaining bytes from the compressor and encryptor,
        updates :attr:`ZipInfo.compress_size`, :attr:`ZipInfo.CRC`, and
        :attr:`ZipInfo.file_size`, then writes either a data descriptor or
        an updated local file header back into the archive.  Also registers
        the entry in the parent :class:`ZipFile`'s internal caches.

        Raises:
            RuntimeError: If a non-ZIP64 entry exceeds ``ZIP64_LIMIT`` (2 GiB - 1
                bytes) for either the uncompressed or compressed size.
            LargeZipFile: If ZIP64 is not allowed and the entry ends past
                ``ZIP64_LIMIT``; on a non-seekable stream the archive can then
                no longer be finished.
        """
        with self._lock:
            self._close_entry()

    def _close_entry(self) -> None:
        if self._state in (WriteState.COMMITTED, WriteState.CLOSED):
            return
        self._ensure_active()
        try:
            self._write_final_payload()
            self._update_metadata()
            self._validate_sizes()
            end = self._write_entry_trailer()
            self._state = WriteState.COMMITTED
            self._owner.entry_written(self, self._zinfo, end)
        except BaseException as exc:
            self._fail(exc)
            raise
        finally:
            super().close()

    def _fail(self, exc: BaseException) -> None:
        self._error = exc
        self._state = WriteState.FAILED
        self._owner.entry_failed(self)
        super().close()

    def _write_final_payload(self) -> None:
        """Flush compression/encryption and write the final payload bytes."""
        data = b"" if self._compressor is None else self._compressor.flush()
        if self._encryptor:
            data = self._encryptor.encrypt(data) + self._encryptor.flush()
        self._compress_size += len(data)
        write_all(self._fileobj, data)

    def _update_metadata(self) -> None:
        self._zinfo.compress_size = self._compress_size
        self._zinfo.CRC = self._crc
        self._zinfo.file_size = self._file_size

    def _validate_sizes(self) -> None:
        if not self._zip64 and needs_zip64(self._file_size):
            raise RuntimeError("File size unexpectedly exceeded ZIP64 limit")
        if not self._zip64 and needs_zip64(self._compress_size):
            raise RuntimeError("Compressed size unexpectedly exceeded ZIP64 limit")

    def _write_entry_trailer(self) -> int:
        """Finish the entry's records and return the offset just after it."""
        if self._zinfo.use_data_descriptor:
            write_all(self._fileobj, data_descriptor(self._zinfo, self._zip64))
            return self._fileobj.tell()
        end = self._fileobj.tell()
        self._fileobj.seek(self._zinfo.header_offset)
        write_all(self._fileobj, file_header(self._zinfo, self._zip64))
        self._fileobj.seek(end)
        return end
