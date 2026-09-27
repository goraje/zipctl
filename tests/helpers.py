"""Helpers shared by tests in more than one package."""

from __future__ import annotations

import io

from typing_extensions import override


class NonSeekableBytesIO(io.BytesIO):
    """In-memory stream that behaves like a pipe: writable, not seekable."""

    @override
    def seekable(self) -> bool:
        return False

    @override
    def seek(self, pos: int, whence: int = 0, /) -> int:
        raise io.UnsupportedOperation("not seekable")
