"""Extra-field records and names that ZipInfo is built from."""

from __future__ import annotations

import os
import struct
from collections.abc import Generator, Iterable
from dataclasses import dataclass
from typing import ClassVar, cast

from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.exceptions import BadZipFile

__all__ = [
    "DD_SIGNATURE",
    "EXTRA_NOT_CARRIED",
    "EXTRA_UNICODE_PATH",
    "EXTRA_ZIP64",
    "WzAesExtra",
]

# ---------------------------------------------------------------------------
# AES extra-field dataclass
# ---------------------------------------------------------------------------


@dataclass
class WzAesExtra:
    """AES extra-field metadata stored on a ``ZipInfo`` instance.

    Populated automatically by ``ZipInfo._decode_extra`` when the 0x9901
    extra field is present, or supplied explicitly via
    ``ZipInfo.__init__(aes_extra=...)``.  All fields default to ``None``
    for non-AES entries.

    Attributes:
        wz_aes_version: AES encryption version (``WZ_AES_V1`` or ``WZ_AES_V2``),
            or ``None`` for non-AES entries.
        wz_aes_vendor_id: Two-byte vendor ID bytes (``b"AE"``), or ``None``
            for non-AES entries.
        wz_aes_strength: AES key strength indicator (1=128-bit, 2=192-bit,
            3=256-bit), or ``None`` for non-AES entries.
    """

    wz_aes_version: int | None = None
    wz_aes_vendor_id: bytes | None = None
    wz_aes_strength: int | None = None


# ---------------------------------------------------------------------------
# Extensible data field codes
# ---------------------------------------------------------------------------
EXTRA_ZIP64 = 0x0001
EXTRA_UNICODE_PATH = 0x7075
# What a copy of an entry does not carry over: the ZIP64 sizes and the AES
# settings (the writer builds them again) and the Unicode path (it is checksummed
# against the name bytes as first stored).
EXTRA_NOT_CARRIED = (EXTRA_ZIP64, EXTRA_WZ_AES, EXTRA_UNICODE_PATH)

# ---------------------------------------------------------------------------
# # Data descriptor signature
# ---------------------------------------------------------------------------
DD_SIGNATURE = 0x08074B50


def sanitize_filename(filename: str) -> str:
    """Terminate the file name at the first null byte and normalize separators.

    Strips the filename at the first null byte, then replaces any OS-native
    path separator characters with forward slashes.

    Args:
        filename: Raw filename string from a ZIP archive record or filesystem.

    Returns:
        Sanitized filename using only forward slashes as directory separators.
    """
    null_byte = filename.find("\x00")
    if null_byte >= 0:
        filename = filename[:null_byte]
    if os.sep != "/" and os.sep in filename:
        filename = filename.replace(os.sep, "/")
    if os.altsep and os.altsep != "/" and os.altsep in filename:
        filename = filename.replace(os.altsep, "/")
    return filename


class Extra:
    """A single ZIP extra-data field (tag + length + body).

    Attributes:
        data: Raw bytes of the complete field including the 4-byte header.
        id: The 2-byte field tag, or ``None`` if the header was malformed.
    """

    FIELD_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HH")

    def __init__(self, data: bytes | memoryview, field_id: int | None = None) -> None:
        """Initialize an extra field record.

        Args:
            data: Raw bytes of the complete field including the 4-byte
                tag/length header.
            field_id: The 2-byte field tag, or ``None`` for a malformed header.
        """
        self.data: bytes = bytes(data)
        self.id: int | None = field_id

    @classmethod
    def read_one(cls, raw: bytes | memoryview) -> tuple[Extra, bytes | memoryview]:
        """Parse one extra field from the start of *raw*.

        Args:
            raw: Byte buffer starting at the beginning of an extra field.

        Returns:
            A tuple of the parsed ``Extra`` instance and the remaining
            unconsumed bytes after the field.
        """
        try:
            xid, xlen = cast("tuple[int, int]", cls.FIELD_STRUCT.unpack(raw[:4]))
        except struct.error:
            xid = None
            xlen = 0
        return cls(raw[: 4 + xlen], xid), raw[4 + xlen :]

    @classmethod
    def iter_fields(cls, data: bytes) -> Generator[Extra, None, None]:
        """Yield each extra field parsed from *data*.

        Uses a zero-copy ``memoryview`` internally for efficient slicing.

        Args:
            data: Raw bytes of a ZIP extra-data block.

        Yields:
            One ``Extra`` instance per field in the block.
        """
        # use memoryview for zero-copy slices
        rest: bytes | memoryview = memoryview(data)
        while rest:
            if len(rest) < 4:
                raise BadZipFile("Corrupt extra field header")
            _, field_length = cast("tuple[int, int]", cls.FIELD_STRUCT.unpack(rest[:4]))
            if len(rest) < 4 + field_length:
                raise BadZipFile("Corrupt extra field data")
            extra, rest = cls.read_one(rest)
            yield extra

    @classmethod
    def strip(cls, data: bytes, xids: Iterable[int | None]) -> bytes:
        """Remove all extra fields whose tag is in *xids*.

        Args:
            data: Raw bytes of a ZIP extra-data block.
            xids: Collection of field tags to remove.

        Returns:
            A new bytes object containing all remaining fields concatenated.
        """
        return b"".join(ex.data for ex in cls.iter_fields(data) if ex.id not in xids)
