"""Helpers shared by tests in more than one package."""

from __future__ import annotations

import io
from typing import Any


class NonSeekableBytesIO(io.BytesIO):
    """In-memory stream that behaves like a pipe: writable, not seekable."""

    def seekable(self) -> bool:
        return False

    def seek(self, *args: Any, **kwargs: Any) -> int:
        raise io.UnsupportedOperation("not seekable")
