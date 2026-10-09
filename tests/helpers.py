"""Helpers shared by tests in more than one package."""

from __future__ import annotations

import io
import os

import pytest
from typing_extensions import override

# Extraction creates a FIFO relative to a directory descriptor or not at
# all; Python builds for older macOS take no dir_fd for os.mkfifo.
needs_fifo_dir_fd = pytest.mark.skipif(
    not hasattr(os, "mkfifo")
    or not all(
        op in os.supports_dir_fd for op in (os.mkfifo, os.link, os.rename, os.unlink)
    ),
    reason="needs FIFOs created relative to a directory descriptor",
)


class NonSeekableBytesIO(io.BytesIO):
    """In-memory stream that behaves like a pipe: writable, not seekable."""

    @override
    def seekable(self) -> bool:
        return False

    @override
    def seek(self, pos: int, whence: int = 0, /) -> int:
        raise io.UnsupportedOperation("not seekable")
