"""The file behind a ZipFile: who closes it, who shares it, and its lock."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from typing import IO, cast

from zipctl.zipfile.io_wrappers import ClosableZipStream, Tellable
from zipctl.zipfile.shared import StrPath

__all__ = ["ArchiveStream"]

# File modes tried in order when opening an archive path: a read/write handle
# falls back to write-only.  Appending needs a readable file, and creates one
# only when nothing is there yet.
_OPEN_MODES = {
    "r": ("rb",),
    "w": ("w+b", "wb"),
    "x": ("x+b", "xb"),
}


def _open_path(path: str, mode: str) -> IO[bytes]:
    if mode == "a":
        try:
            return open(path, "r+b")
        except FileNotFoundError:
            return open(path, "x+b")
    *fallbacks, last = _OPEN_MODES[mode]
    for file_mode in fallbacks:
        try:
            return open(path, file_mode)
        except OSError:
            continue
    return open(path, last)


class ArchiveStream:
    """The archive's file object, shared by the archive and its open members.

    Every member being read holds a reference; the file is closed once the
    archive and all of them are done with it, and only if it was opened here
    from a path.  One reentrant :attr:`lock` serialises every use of it.

    Attributes:
        fp: The file object, or ``None`` once the archive is closed.
        name: The path it was opened from, or the file object's ``name``.
        seekable: Whether positions can be revisited (header rewrites,
            truncation); ``False`` for pipes and sockets.
        lock: Guards the file position and the archive's shared state.
    """

    def __init__(self, file: StrPath | IO[bytes], mode: str) -> None:
        if isinstance(file, os.PathLike):
            file = os.fspath(file)
        self._owned: bool = isinstance(file, str)
        if isinstance(file, str):
            self.fp: IO[bytes] | None = _open_path(file, mode)
            self.name: str | None = file
        else:
            self.fp = file
            self.name = getattr(file, "name", None)
        self.writing: bool = False  # an entry is open for writing
        self.seekable: bool = True
        self.lock: threading.RLock = threading.RLock()
        self._users: int = 1  # the archive itself

    @property
    def owned(self) -> bool:
        """Whether the file was opened here (and is therefore closed here)."""
        return self._owned

    def ensure_not_writing(self, action: str) -> None:
        """Raise ``ValueError`` if an entry is being written, naming *action*."""
        if self.writing:
            raise ValueError(
                f"Can't {action} the ZIP file while there is an open writing "
                "handle on it. Close the writing handle first."
            )

    def require_open(self, action: str) -> IO[bytes]:
        """The file object, or ``ValueError`` naming *action* if closed."""
        if self.fp is None:
            raise ValueError(f"Attempt to {action} ZIP archive that was already closed")
        return self.fp

    def is_empty(self) -> bool:
        """Whether the file holds no bytes at all (a new archive for ``'a'``)."""
        fp = self.require_open("use")
        try:
            empty = fp.seek(0, os.SEEK_END) == 0
            fp.seek(0)
        except (AttributeError, OSError):
            return False
        return empty

    def start_writing(self) -> int:
        """Prepare a new archive at the current offset and return that offset.

        A stream that cannot even tell its position is wrapped to count the
        bytes written; one that cannot seek is marked not :attr:`seekable`.
        """
        fp = self.require_open("write")
        try:
            start = fp.tell()
        except (AttributeError, OSError):
            self.fp = cast(IO[bytes], Tellable(fp))  # pyright: ignore[reportInvalidCast]  # duck-typed
            self.seekable = False
            return 0
        try:
            fp.seek(start)
        except (AttributeError, OSError):
            self.seekable = False
        return start

    def share(self, offset: int, writing: Callable[[], bool]) -> ClosableZipStream:
        """A reader's own view of the file, starting at *offset*.

        Must be called with :attr:`lock` held; the view keeps the file open
        until it is closed.
        """
        fp = self.require_open("read")
        self._users += 1
        return ClosableZipStream(fp, offset, self._release, self.lock, writing)

    def close(self) -> None:
        """Give up the archive's own reference to the file."""
        with self.lock:
            fp, self.fp = self.fp, None
        if fp is not None:
            self._release(fp)

    def _release(self, fp: IO[bytes]) -> None:
        with self.lock:
            assert self._users > 0
            self._users -= 1
            if not self._users and self._owned:
                fp.close()
