from __future__ import annotations

import io
import threading
from collections.abc import Callable
from typing import IO, Protocol


class Readable(Protocol):
    def read(self, size: int, /) -> bytes: ...


def write_all(file: IO[bytes], data: bytes) -> None:
    """Write a complete record, including on streams that accept partial writes."""
    view = memoryview(data)
    while view:
        count = file.write(view)
        if count is None or count <= 0:  # pyright: ignore[reportUnnecessaryComparison]
            raise BlockingIOError("Stream made no progress while writing")
        if count > len(view):
            raise OSError("Stream reported more bytes written than supplied")
        view = view[count:]


def read_exactly(file: Readable, size: int) -> bytes:
    """Read a bounded ZIP record, tolerating short reads but not truncation."""
    parts: list[bytes] = []
    remaining = size
    while remaining:
        data = file.read(remaining)
        if not data:
            raise EOFError("Truncated ZIP record")
        if len(data) > remaining:
            raise OSError("Stream returned more bytes than requested")
        parts.append(data)
        remaining -= len(data)
    return b"".join(parts)


class ClosableZipStream:
    """A thread-safe, position-tracking view over a shared ZIP file stream.

    Coordinates access to the underlying file object through a shared lock,
    and delegates reference-counted teardown to a caller-supplied close
    callback.  Multiple ``ClosableZipStream`` instances may coexist over the
    same file object as long as they share the same lock.
    """

    def __init__(
        self,
        file: IO[bytes],
        pos: int,
        close: Callable[[IO[bytes]], None],
        lock: threading.RLock,
        writing: Callable[[], bool],
    ) -> None:
        """Initialise a ClosableZipStream.

        Args:
            file: The shared underlying file object to read from.
            pos: Initial byte offset within *file* for this stream.
            close: Callback invoked with the underlying file object when this
                stream is closed.  Typically decrements a reference count and
                closes the file when it reaches zero.
            lock: Reentrant lock shared across all streams that access *file*.
            writing: Zero-argument callable that returns ``True`` while a
                write handle on the ZIP archive is open.
        """
        self._file: IO[bytes] | None = file
        self._pos: int = pos
        self._close: Callable[[IO[bytes]], None] = close
        self._lock: threading.RLock = lock
        self._writing: Callable[[], bool] = writing
        self.seekable: Callable[[], bool] = file.seekable

    def tell(self) -> int:
        """Return the current stream position.

        Returns:
            The byte offset of the next read operation.
        """
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        """Move the stream position to *offset*.

        Args:
            offset: Byte offset for the seek operation.
            whence: How to interpret *offset*.  ``io.SEEK_SET`` (0) is
                relative to the start of the stream, ``io.SEEK_CUR`` (1) is
                relative to the current position, and ``io.SEEK_END`` (2) is
                relative to the end of the stream.  Defaults to
                ``io.SEEK_SET``.

        Returns:
            The new absolute stream position.

        Raises:
            ValueError: If a write handle on the ZIP archive is currently
                open, or if the stream has already been closed.
        """
        with self._lock:
            if self._writing():
                raise ValueError(
                    "Can't reposition in the ZIP file while "
                    "there is an open writing handle on it. "
                    "Close the writing handle before trying to read."
                )
            if self._file is None:
                raise ValueError("I/O operation on closed file.")
            if whence == io.SEEK_CUR:
                self._file.seek(self._pos + offset)
            else:
                self._file.seek(offset, whence)
            self._pos = self._file.tell()
            return self._pos

    def read(self, n: int = -1) -> bytes:
        """Read and return up to *n* bytes from the stream.

        Seeks the underlying file to the current position before reading so
        that multiple ``ClosableZipStream`` instances over the same file can
        interleave safely under the shared lock.

        Args:
            n: Maximum number of bytes to read.  ``-1`` (the default) reads
                until the end of the entry.

        Returns:
            The bytes read.  May be shorter than *n* if fewer bytes are
            available.

        Raises:
            ValueError: If a write handle on the ZIP archive is currently
                open, or if the stream has already been closed.
        """
        with self._lock:
            if self._writing():
                raise ValueError(
                    "Can't read from the ZIP file while there "
                    "is an open writing handle on it. "
                    "Close the writing handle before trying to read."
                )
            if self._file is None:
                raise ValueError("I/O operation on closed file.")
            self._file.seek(self._pos)
            data = self._file.read(n)
            self._pos = self._file.tell()
            return data

    def close(self) -> None:
        """Close the stream and invoke the teardown callback.

        Safe to call multiple times; only the first call triggers the
        callback.  The close callback is invoked outside the lock to avoid
        holding it during potentially expensive teardown.
        """
        with self._lock:
            fileobj = self._file
            self._file = None
        if fileobj is not None:
            self._close(fileobj)


class Tellable:
    """Wrap an unseekable stream to provide a ``tell()`` method.

    Tracks the number of bytes written so that callers can query the current
    write position even when the underlying stream does not support seeking.
    All other operations are forwarded directly to the wrapped stream.
    """

    def __init__(self, fp: IO[bytes]) -> None:
        """Initialise a Tellable wrapper.

        Args:
            fp: The unseekable stream to wrap.
        """
        self.fp: IO[bytes] = fp
        self.offset: int = 0

    def write(self, data: bytes) -> int:
        """Write *data* to the underlying stream and advance the offset.

        Args:
            data: Bytes to write.

        Returns:
            The number of bytes written.
        """
        n = self.fp.write(data)
        if n is None or n <= 0 and data:  # pyright: ignore[reportUnnecessaryComparison]
            raise BlockingIOError("Stream made no progress while writing")
        self.offset += n
        return n

    def seek(self, offset: int, whence: int = 0) -> int:  # pyright: ignore[reportUnusedParameter]  # fixed by io.IOBase.seek
        """Seeking is not supported.

        Args:
            offset: Ignored.
            whence: Ignored.

        Raises:
            io.UnsupportedOperation: Always, because the underlying stream is
                unseekable.
        """
        raise io.UnsupportedOperation("seek")

    def tell(self) -> int:
        """Return the current write position.

        Returns:
            The total number of bytes written since construction.
        """
        return self.offset

    def flush(self) -> None:
        """Flush the underlying stream's write buffer."""
        self.fp.flush()

    def close(self) -> None:
        """Close the underlying stream."""
        self.fp.close()
