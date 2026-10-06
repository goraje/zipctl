"""ZIP format primitives shared by every layer, so none imports one above it."""

from __future__ import annotations

from typing import Protocol

__all__ = ["MASK_USE_DATA_DESCRIPTOR", "Readable", "read_exactly"]

# General purpose flag bit 3: CRC-32 and sizes follow the data.
MASK_USE_DATA_DESCRIPTOR = 1 << 3


class Readable(Protocol):
    def read(self, size: int, /) -> bytes: ...


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
