from __future__ import annotations

import io
import os
from collections.abc import Iterator

from typing_extensions import override

from zipctl.compression import (
    ZIP_STORED,
    Registry,
    compressor_names,
    registry,
)
from zipctl.compression.methods import DecompressorBase
from zipctl.cryptography.aes import AesKeyCache
from zipctl.cryptography.base import BaseZipDecrypter
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.ext.decryption import read_encryption_header
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream
from zipctl.zipfile.shared import ReadWriteMode, crc32

__all__ = [
    "ZipExtFile",
]


class ZipExtFile(io.BufferedIOBase):
    """Readable file-like object for a single ZIP entry.

    Wraps a :class:`~zipctl.zipfile.io_wrappers.ClosableZipStream` and
    transparently decrypts (ZipCrypto or WZ-AES) and decompresses data on
    demand.  Supports :meth:`read`, :meth:`readline`, :meth:`peek`,
    :meth:`read1`, and — for uncompressed or seekable streams — :meth:`seek`
    and :meth:`tell`.

    Attributes:
        MAX_N (int): Maximum byte count passed to a single decompressor call.
        MIN_READ_SIZE (int): Minimum read from the underlying stream (4 KiB).
        MAX_SEEK_READ (int): Maximum bytes consumed per seek-forward step (16 MiB).
        encryption_header (bytes): Raw encryption header read from the stream.
            Set by :meth:`_setup_decrypter`; only present on encrypted entries.
        mode (str): Opening mode, always ``'r'``.
        name (str): Filename of the ZIP entry.
        newlines (None): Unused compatibility attribute for the ``io`` layer.
    """

    # Max size supported by decompressor.
    MAX_N: int = (1 << 31) - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE: int = 4096

    # Keep a forged compressed-size field from turning one logical read into
    # an oversized allocation.  Large entries are still streamed over calls.
    MAX_READ_SIZE: int = 1 << 20

    # Chunk size to read during seek
    MAX_SEEK_READ: int = 1 << 24

    # Set by _setup_decrypter before _get_decrypter
    encryption_header: bytes

    def __init__(
        self,
        fileobj: ClosableZipStream,
        mode: ReadWriteMode,
        zipinfo: ZipInfo,
        close_fileobj: bool = False,
        pwd: bytes | None = None,
        compression_registry: Registry = registry,
        key_cache: AesKeyCache | None = None,
        limits: ArchiveLimits | None = None,
    ) -> None:
        """Initialise a :class:`ZipExtFile` for reading a single ZIP entry.

        Reads and validates any encryption header, then initialises all
        reading state ready for the first :meth:`read` call.

        Args:
            fileobj (ClosableZipStream): Stream positioned at the start of this
                entry's data (immediately after the local file header).
            mode (str): Opening mode.  Only ``'r'`` is supported by this class.
            zipinfo (ZipInfo): Metadata for the entry being read.
            close_fileobj (bool): If ``True``, *fileobj* is closed when this
                object is closed.  Defaults to ``False``.
            pwd (bytes | None): Decryption password.  Required when the entry
                is encrypted; ignored otherwise.  Defaults to ``None``.
            compression_registry (Registry): Where decompressors come from.
            key_cache (AesKeyCache | None): Derived WZ-AES keys shared with
                other entries of the same archive, so that a backward seek or
                a second open does not derive them again.

        Raises:
            PasswordRequired: If the entry is encrypted but *pwd* is ``None``
                or empty.
            BadPassword: If *pwd* does not match the entry's password
                verifier.

        Note:
            The local file header must already have been validated, which
            :meth:`ZipFile.open` does; that is also where entries using
            compressed-patch data or strong encryption are rejected.
        """
        self._fileobj: ClosableZipStream = fileobj
        self._zinfo: ZipInfo = zipinfo
        self._close_fileobj: bool = close_fileobj
        self._pwd: bytes | None = pwd
        self._compression_registry: Registry = compression_registry
        self._key_cache: AesKeyCache | None = key_cache
        self._limits: ArchiveLimits = limits or ArchiveLimits()

        self._compress_type: int = zipinfo.compress_type
        self._orig_compress_left: int = zipinfo.compress_size
        self.newlines: None = None

        self.mode: ReadWriteMode = mode
        self.name: str = zipinfo.filename

        self._expected_crc: int | None
        self._orig_start_crc: int | None
        if hasattr(zipinfo, "CRC"):
            self._expected_crc = zipinfo.CRC
            self._orig_start_crc = crc32(b"")
        else:
            self._expected_crc = None
            self._orig_start_crc = None

        self._seekable: bool = False
        try:
            if fileobj.seekable():
                self._seekable = True
        except AttributeError:
            pass

        self._decrypter_cls: type[BaseZipDecrypter] | None
        if self._zinfo.is_encrypted:
            self._decrypter_cls = self._setup_decrypter()
        else:
            self._decrypter_cls = None

        # _compress_start is the file position after any encryption header.
        # Used for seek-backwards resets.
        self._compress_start: int = fileobj.tell()
        self._init_read_state()

    def _setup_decrypter(self) -> type[BaseZipDecrypter]:
        """Read the encryption header and return the appropriate decrypter class.

        Reads the encryption header bytes from the stream, stores them in
        :attr:`encryption_header`, and subtracts their length (plus the
        HMAC trailer for WZ-AES) from ``_orig_compress_left``.

        Returns:
            type[BaseZipDecrypter]: The decrypter class to use for this entry.

        Raises:
            PasswordRequired: If the entry is encrypted but no password was
                supplied.
        """
        decrypter_cls, self.encryption_header = read_encryption_header(
            self._fileobj, self._zinfo, self._pwd
        )
        self._orig_compress_left -= (
            len(self.encryption_header) + decrypter_cls.authentication_trailer_length
        )
        if self._orig_compress_left < 0:
            raise BadZipFile("Encrypted entry is shorter than its encryption overhead")
        return decrypter_cls

    def _get_decrypter(self) -> BaseZipDecrypter | None:
        """Instantiate and return the decrypter for this entry.

        Returns:
            BaseZipDecrypter | None: A ready-to-use decrypter instance, or
            ``None`` if the entry is not encrypted.

        Raises:
            BadPassword: If the password verifier of the entry's decrypter
                rejects the password.
        """
        if self._decrypter_cls is None:
            return None
        assert self._pwd is not None, (
            "an encrypted entry is only opened with a password"
        )
        return self._decrypter_cls(
            self._zinfo, self._pwd, self.encryption_header, self._key_cache
        )

    def _init_read_state(self) -> None:
        """(Re-)initialise all reading state.

        Called at construction time and whenever a backwards seek resets the
        stream to :attr:`_compress_start`.  Resets the CRC accumulator, byte
        counters, read buffer, EOF flag, and creates fresh decrypter and
        decompressor instances.
        """
        self._expected_crc = (
            self._zinfo.CRC if self._orig_start_crc is not None else None
        )
        self._running_crc: int | None = self._orig_start_crc
        self._compress_left: int = self._orig_compress_left
        self._left: int = self._zinfo.file_size
        self._readbuffer: bytes = b""
        self._offset: int = 0
        self._eof: bool = False
        self._decrypter: BaseZipDecrypter | None = self._get_decrypter()
        self._decompressor: DecompressorBase = (
            self._compression_registry.get_decompressor(self._compress_type)
        )
        self._decompressor.configure_limits(self._limits)

    def verify_integrity(self) -> None:
        """Check the whole entry against its integrity data.

        An entry whose decrypter authenticates the ciphertext (WinZip AES, with
        its HMAC) is checked without decompressing anything.  Other entries
        are read to the end, which verifies their CRC-32.  The stream position
        is not preserved.

        Raises:
            BadZipFile: If the HMAC or CRC-32 does not match, or the entry is
                truncated.
        """
        if self.closed:
            raise ValueError("verify on closed file")
        self._fileobj.seek(self._compress_start)
        self._init_read_state()
        if self._decrypter is not None and self._decrypter.authenticates_ciphertext:
            for _ in self._raw_chunks():
                pass
            self._eof = True
            self._left = 0
        else:
            while self.read(self.MAX_READ_SIZE):
                pass

    def _raw_chunks(self) -> Iterator[bytes]:
        """Yield the entry's decrypted but still compressed bytes, to the end.

        For copying an entry into another archive without compressing it
        again.  Nothing is decompressed, so no CRC-32 is checked here; a
        decrypter that authenticates the ciphertext (WZ-AES) checks it after the
        last chunk.  Do not mix with :meth:`read`.

        Raises:
            BadZipFile: If the entry is truncated or fails authentication.
        """
        while self._compress_left > 0:
            yield self._read2(self.MAX_READ_SIZE)
        if self._decrypter is not None:
            self._decrypter.finalize(self._expected_crc, None, self._fileobj)

    def _check_integrity(self) -> None:
        """Verify the integrity of a fully-read entry.

        Called automatically by :meth:`_read1` once EOF is reached.
        Delegates to the active decrypter's
        :meth:`~zipctl.cryptography.base.BaseZipDecrypter.finalize`.
        Unencrypted entries check the CRC-32 directly.

        Authentication of the ciphertext always covers all of it, including
        any padding following the compressed stream.

        Raises:
            BadZipFile: If the HMAC tag does not match, or if the CRC-32 of
                the decompressed data does not equal the expected value.
        """
        if self._decrypter is not None and self._decrypter.authenticates_ciphertext:
            while self._compress_left > 0:
                self._read2(self.MAX_READ_SIZE)
        if self._decrypter is not None:
            self._decrypter.finalize(
                self._expected_crc,
                self._running_crc if self._eof else None,
                self._fileobj,
            )
        elif (
            self._eof
            and self._expected_crc is not None
            and self._running_crc != self._expected_crc
        ):
            raise BadZipFile(f"Bad CRC-32 for file {self.name!r}")

    @override
    def __repr__(self) -> str:
        """Return a developer-friendly string representation.

        Returns:
            str: A string of the form
            ``<package.ZipExtFile name='...' compress_type=deflate>``
            while open, or ``<package.ZipExtFile [closed]>`` after closing.
        """
        result = [f"<{self.__class__.__module__}.{self.__class__.__qualname__}"]
        if not self.closed:
            result.append(f" name={self.name!r}")
            if self._compress_type != ZIP_STORED:
                compressor_type = compressor_names.get(
                    self._compress_type,
                    self._compress_type,
                )
                result.append(f" compress_type={compressor_type}")
        else:
            result.append(" [closed]")
        result.append(">")
        return "".join(result)

    @override
    def readline(self, limit: int | None = -1) -> bytes:
        """Read and return one line from the stream.

        Args:
            limit (int | None): Maximum number of bytes to read.  A negative
                value or ``None`` means no limit.

        Returns:
            bytes: Bytes up to and including the next ``b'\\n'``, or until
            EOF if no newline is found.  Returns ``b''`` at EOF.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if limit is None:
            limit = -1
        if limit < 0:
            # Shortcut common case - newline found in buffer.
            i = self._readbuffer.find(b"\n", self._offset) + 1
            if i > 0:
                line = self._readbuffer[self._offset : i]
                self._offset = i
                return line

        # peek() may return more than its hint. BufferedIOBase.readline() can
        # overrun a finite limit with such a peek implementation, so cap every
        # consumed chunk ourselves.
        chunks: list[bytes] = []
        remaining = limit
        while remaining != 0:
            available = self.peek(1)
            if remaining > 0:
                available = available[:remaining]
            if not available:
                break
            newline = available.find(b"\n")
            count = newline + 1 if newline >= 0 else len(available)
            chunks.append(self.read(count))
            if remaining > 0:
                remaining -= count
            if newline >= 0:
                break
        return b"".join(chunks)

    def peek(self, n: int = 1) -> bytes:
        """Return buffered bytes without advancing the position.

        If fewer than *n* bytes are buffered a read is attempted to fill the
        buffer, but the stream position is not advanced.

        Args:
            n (int): Hint for the minimum number of bytes to buffer.
                Defaults to ``1``.

        Returns:
            bytes: Up to 512 bytes from the current position.  May return
            fewer bytes than *n* if near EOF.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if n > len(self._readbuffer) - self._offset:
            chunk = self.read(n)
            if len(chunk) > self._offset:
                self._readbuffer = chunk + self._readbuffer[self._offset :]
                self._offset = 0
            else:
                self._offset -= len(chunk)

        # Return up to 512 bytes to reduce allocation overhead for tight loops.
        return self._readbuffer[self._offset : self._offset + 512]

    @override
    def readable(self) -> bool:
        """Return ``True`` since this stream is always readable.

        Returns:
            bool: Always ``True``.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True

    @override
    def read(self, n: int | None = -1) -> bytes:
        """Read and return up to *n* bytes.

        Args:
            n (int | None): Number of bytes to read.  If omitted, ``None``,
                or negative, reads and returns all remaining data until EOF.

        Returns:
            bytes: The requested bytes, or fewer if EOF is reached first.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if n is None or n < 0:
            chunks = [self._readbuffer[self._offset :]]
            self._readbuffer = b""
            self._offset = 0
            while not self._eof:
                chunks.append(self._read1(self.MAX_READ_SIZE))
            return b"".join(chunks)

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset : end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset :]
        self._readbuffer = b""
        self._offset = 0
        while n > 0 and not self._eof:
            data = self._read1(n)
            if n < len(data):
                self._readbuffer = data
                self._offset = n
                buf += data[:n]
                break
            buf += data
            n -= len(data)
        return buf

    def _update_crc(self, newdata: bytes) -> None:
        """Accumulate *newdata* into the running CRC-32 checksum.

        Does nothing if no expected CRC was recorded (i.e. the entry had no
        ``CRC`` field, or CRC checking was disabled by a seek operation).

        Args:
            newdata (bytes): Freshly decompressed bytes to include in the
                checksum.
        """
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        assert self._running_crc is not None
        self._running_crc = crc32(newdata, self._running_crc)

    @override
    def read1(self, n: int | None = -1) -> bytes:
        """Read up to *n* bytes with at most one read() system call.

        Args:
            n (int | None): Maximum number of bytes to return.  A negative
                value or ``None`` reads all remaining data, draining any
                buffered bytes first before issuing a single further read.

        Returns:
            bytes: Decompressed bytes, possibly fewer than *n*.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if n is None or n < 0:
            buf = self._readbuffer[self._offset :]
            self._readbuffer = b""
            self._offset = 0
            while not self._eof:
                data = self._read1(self.MAX_N)
                if data:
                    buf += data
                    break
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset : end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset :]
        self._readbuffer = b""
        self._offset = 0
        if n > 0:
            while not self._eof:
                data = self._read1(n)
                if n < len(data):
                    self._readbuffer = data
                    self._offset = n
                    buf += data[:n]
                    break
                if data:
                    buf += data
                    break
        return buf

    def _read1(self, n: int) -> bytes:
        """Read, decrypt, and decompress up to *n* bytes.

        Reads raw compressed bytes via :meth:`_read2`, optionally decrypts
        them, decompresses them according to :attr:`_compress_type`, updates
        the running CRC, and calls :meth:`_check_integrity` once EOF is
        detected.

        Args:
            n (int): Target number of decompressed bytes to return.

        Returns:
            bytes: Decompressed plaintext bytes.  Returns ``b''`` if already
            at EOF or *n* is non-positive.
        """
        if self._eof or n <= 0:
            return b""

        data = self._decompress(self._read_input(n), n)
        if len(data) > self._left:
            raise BadZipFile(
                f"More data found than indicated by uncompressed size for '{self.name}'"
            )
        self._left -= len(data)
        if (
            self._compress_type != ZIP_STORED
            and self._compress_left <= 0
            and not self._eof
            and not data
        ):
            raise BadZipFile(f"Truncated compressed stream for '{self.name}'")
        self._update_crc(data)
        if self._eof:
            if self._left:
                raise BadZipFile(f"Uncompressed size mismatch for {self.name!r}")
            self._check_integrity()
        return data

    def _read_input(self, n: int) -> bytes:
        """Raw bytes for the decompressor, none while it has input of its own."""
        if self._decompressor.needs_input:
            return self._read2(n)
        return b""

    def _decompress(self, data: bytes, n: int) -> bytes:
        """Decompress up to *n* bytes of *data* and set ``_eof``."""
        if self._compress_type == ZIP_STORED:
            # Stored data is its own output; the caller buffers any excess.
            self._eof = self._compress_left <= 0
            return data
        data = self._decompressor.decompress(data, n)
        if self._decompressor.concatenated:
            # The stream ends with its input, which may hold several frames.
            self._eof = self._decompressor.eof and self._compress_left <= 0
        else:
            # Only the decompressor's end-of-stream marker proves the entry was
            # not truncated; deliberately stricter than CPython, which also
            # accepts exhausted deflate input without a final block.  A bounded
            # decompressor may also still hold output after its input is gone.
            self._eof = self._decompressor.eof
        return data

    def _read2(self, n: int) -> bytes:
        """Read up to *n* raw (compressed and encrypted) bytes from the stream.

        Enforces :attr:`MIN_READ_SIZE` as a lower bound and
        ``_compress_left`` as an upper bound, then decrypts the data if a
        decrypter is active.

        Args:
            n (int): Maximum number of compressed bytes to read.

        Returns:
            bytes: Raw decrypted (but still compressed) bytes.  Returns
            ``b''`` when no compressed data remains.

        Raises:
            BadZipFile: If the underlying stream returns empty bytes before
                ``_compress_left`` reaches zero.
        """
        if self._compress_left <= 0:
            return b""

        n = min(max(n, self.MIN_READ_SIZE), self.MAX_READ_SIZE)
        n = min(n, self._compress_left)

        data = self._fileobj.read(n)
        self._compress_left -= len(data)
        if not data:
            raise BadZipFile(f"Truncated data for file {self.name!r}")

        if self._decrypter is not None:
            data = self._decrypter.decrypt(data)
        return data

    @override
    def close(self) -> None:
        """Close this file object.

        Also closes the underlying
        :class:`~zipctl.zipfile.io_wrappers.ClosableZipStream` if
        ``close_fileobj`` was ``True`` at construction time.
        """
        try:
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super().close()

    @override
    def seekable(self) -> bool:
        """Return whether this stream supports random access.

        Returns:
            bool: ``True`` if the underlying stream is seekable.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._seekable

    @override
    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Set the stream position to *offset*.

        Seeking forward is always supported (by consuming and discarding
        data).  Seeking backward resets and replays the stream from
        :attr:`_compress_start`.  Uncompressed, unencrypted streams also
        support direct forward seeks via the underlying file object without
        decompressing data.

        Args:
            offset (int): Target position expressed as decompressed byte
                offset.
            whence (int): How *offset* is interpreted: ``os.SEEK_SET`` (0),
                ``os.SEEK_CUR`` (1), or ``os.SEEK_END`` (2).  Defaults to
                ``os.SEEK_SET``.

        Returns:
            int: New stream position as a byte offset from the start of the
            decompressed entry data.

        Raises:
            ValueError: If the file has already been closed, or if *whence*
                is not one of the three recognised values.
            io.UnsupportedOperation: If the underlying stream is not seekable.
        """
        if self.closed:
            raise ValueError("seek on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        curr_pos = self.tell()
        new_pos = self._clamped_position(offset, whence, curr_pos)
        read_offset = new_pos - curr_pos
        buff_offset = read_offset + self._offset

        if buff_offset >= 0 and buff_offset < len(self._readbuffer):
            # Just move the _offset index if the new position is in the _readbuffer
            self._offset = buff_offset
            read_offset = 0
        # Fast seek for uncompressed unencrypted files
        elif (
            self._compress_type == ZIP_STORED
            and self._decrypter is None
            and read_offset != 0
        ):
            read_offset = self._seek_stored(read_offset)
        elif read_offset < 0:
            # Position is before the current position. Reset state.
            self._fileobj.seek(self._compress_start)
            self._init_read_state()
            read_offset = new_pos

        while read_offset > 0:
            read_len = min(self.MAX_SEEK_READ, read_offset)
            self.read(read_len)
            read_offset -= read_len

        return self.tell()

    def _clamped_position(self, offset: int, whence: int, curr_pos: int) -> int:
        """The absolute position *offset* and *whence* name, kept inside the entry."""
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = curr_pos + offset
        elif whence == os.SEEK_END:
            new_pos = self._zinfo.file_size + offset
        else:
            raise ValueError(
                "whence must be os.SEEK_SET (0), os.SEEK_CUR (1), or os.SEEK_END (2)"
            )
        return max(0, min(new_pos, self._zinfo.file_size))

    def _seek_stored(self, read_offset: int) -> int:
        """Skip *read_offset* bytes of an uncompressed, unencrypted entry directly.

        Returns 0, the number of bytes left to read and discard.
        """
        # Disable CRC checking after first seeking - it would be invalid
        self._expected_crc = None
        # Seek actual file taking already buffered data into account
        read_offset -= len(self._readbuffer) - self._offset
        self._fileobj.seek(read_offset, os.SEEK_CUR)
        self._left -= read_offset
        self._compress_left -= read_offset
        self._eof = self._left <= 0
        # Flush read buffer
        self._readbuffer = b""
        self._offset = 0
        return 0

    @override
    def tell(self) -> int:
        """Return the current stream position.

        The position is computed as the number of decompressed bytes
        delivered to the caller, accounting for data still held in the
        internal read buffer.

        Returns:
            int: Byte offset from the start of the decompressed entry data.

        Raises:
            ValueError: If the file has already been closed.
            io.UnsupportedOperation: If the underlying stream is not seekable.
        """
        if self.closed:
            raise ValueError("tell on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        filepos = (
            self._zinfo.file_size - self._left - len(self._readbuffer) + self._offset
        )
        return filepos
