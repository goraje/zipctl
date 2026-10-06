"""Extra-field records and names that ZipInfo is built from."""

from __future__ import annotations

import struct
from collections.abc import Collection, Iterator
from dataclasses import dataclass

from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import BadZipFile

__all__ = [
    "EXTRA_NOT_CARRIED",
    "EXTRA_UNICODE_PATH",
    "EXTRA_ZIP64",
    "WzAesExtra",
    "iter_extra",
    "strip_extra",
]

# ---------------------------------------------------------------------------
# AES extra-field dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WzAesExtra:
    """The WinZip AES extra field of an AES entry (``ZipInfo.aes_extra``).

    Attributes:
        wz_aes_version: AES encryption version (``WZ_AES_V1`` or ``WZ_AES_V2``).
        wz_aes_vendor_id: Two-byte vendor ID, always ``b"AE"``.
        wz_aes_strength: AES key strength (1=128-bit, 2=192-bit, 3=256-bit).

    Raises:
        ValueError: If a field holds a value the format does not define.
    """

    wz_aes_version: int
    wz_aes_vendor_id: bytes
    wz_aes_strength: int

    def __post_init__(self) -> None:
        if self.wz_aes_version not in (1, 2):
            raise ValueError("Unsupported WinZip AES version")
        if self.wz_aes_vendor_id != b"AE":
            raise ValueError("Invalid WinZip AES vendor ID")
        if self.wz_aes_strength not in (1, 2, 3):
            raise ValueError("Invalid WinZip AES strength")


# ---------------------------------------------------------------------------
# Extensible data field codes
# ---------------------------------------------------------------------------
EXTRA_ZIP64 = 0x0001
EXTRA_UNICODE_PATH = 0x7075
# What a copy of an entry does not carry over: the ZIP64 sizes and the AES
# settings (the writer builds them again) and the Unicode path (it is checksummed
# against the name bytes as first stored).
EXTRA_NOT_CARRIED = (EXTRA_ZIP64, EXTRA_WZ_AES, EXTRA_UNICODE_PATH)

_FIELD_HEADER = struct.Struct("<HH")


def iter_extra(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(tag, body)`` for each field of the extra-data block *data*.

    Up to three trailing bytes cannot hold a field header; some writers (Android
    zipalign among them) pad with them, and 7-Zip ignores them, so they are skipped.

    Raises:
        BadZipFile: If a field overruns *data*.
    """
    offset = 0
    while len(data) - offset >= _FIELD_HEADER.size:
        tag = int.from_bytes(data[offset : offset + 2], "little")
        length = int.from_bytes(data[offset + 2 : offset + 4], "little")
        offset += _FIELD_HEADER.size
        if offset + length > len(data):
            raise BadZipFile(f"Corrupt extra field {tag:04x} (size={length})")
        yield tag, data[offset : offset + length]
        offset += length


def strip_extra(data: bytes, tags: Collection[int]) -> bytes:
    """Return *data* without the fields whose tag is in *tags*."""
    return b"".join(
        _FIELD_HEADER.pack(tag, len(body)) + body
        for tag, body in iter_extra(data)
        if tag not in tags
    )
