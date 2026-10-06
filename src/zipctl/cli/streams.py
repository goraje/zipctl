"""Normalize Windows CRT pipe errors at the output operation that raises them."""

from __future__ import annotations

import errno
import os
import stat
from typing import TextIO, cast


class PipeOutput:
    """Delegate a text stream, translating EINVAL only from pipe writes/flushes."""

    def __init__(self, stream: TextIO) -> None:
        self._stream: TextIO = stream

    def __getattr__(self, name: str) -> object:
        return cast(object, getattr(self._stream, name))

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except OSError as exc:
            self._translate(exc)
            raise

    def flush(self) -> None:
        try:
            self._stream.flush()
        except OSError as exc:
            self._translate(exc)
            raise

    @staticmethod
    def _translate(exc: OSError) -> None:
        if exc.errno == errno.EINVAL:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe") from exc


def normalize_output(stream: TextIO) -> TextIO:
    """Wrap only native Windows pipes; regular files retain their I/O errors."""
    if os.name == "nt":
        try:
            is_pipe = stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode)
        except (OSError, ValueError):
            is_pipe = False
        if is_pipe:
            return cast(TextIO, cast(object, PipeOutput(stream)))
    return stream
