import dataclasses
import os
import struct
import sys
from types import FrameType
from typing import IO, Literal, TypeAlias

from zipctl.format import MASK_USE_DATA_DESCRIPTOR

try:
    from zlib import crc32
except ImportError:  # pragma: no cover - zlib is optional in some builds
    from binascii import crc32

__all__ = [
    "CHUNK",
    "ReadWriteMode",
    "StrPath",
    "checksum",
    "crc32",
    "sanitize_filename",
    "DD_SIGNATURE",
    "DEFAULT_VERSION",
    "ZIP64_VERSION",
    "MAX_EXTRACT_VERSION",
    "END_ARCHIVE_STRUCT",
    "END_ARCHIVE_SIGNATURE",
    "END_ARCHIVE_SIZE",
    "CENTRAL_DIR_STRUCT",
    "CENTRAL_DIR_SIGNATURE",
    "CENTRAL_DIR_SIZE",
    "FILE_HEADER_STRUCT",
    "FILE_HEADER_SIGNATURE",
    "FILE_HEADER_SIZE",
    "END_ARCHIVE64_LOCATOR_STRUCT",
    "END_ARCHIVE64_LOCATOR_SIGNATURE",
    "END_ARCHIVE64_LOCATOR_SIZE",
    "END_ARCHIVE64_STRUCT",
    "END_ARCHIVE64_SIGNATURE",
    "END_ARCHIVE64_SIZE",
    "ZIP64_LIMIT",
    "ZIP_FILECOUNT_LIMIT",
    "ZIP_MAX_COMMENT",
    "needs_zip64",
    "MASK_ENCRYPTED",
    "MASK_COMPRESS_OPTION_1",
    "MASK_COMPRESS_OPTIONS",
    "MASK_COMPRESSED_PATCH",
    "MASK_STRONG_ENCRYPTION",
    "MASK_UTF_FILENAME",
    "MASK_USE_DATA_DESCRIPTOR",
]

# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------
DEFAULT_VERSION = 20
ZIP64_VERSION = 45
MAX_EXTRACT_VERSION = 63

# ---------------------------------------------------------------------------
# Struct formats, magic strings and sizes
# ---------------------------------------------------------------------------

# End of central directory
END_ARCHIVE_STRUCT = b"<4s4H2LH"
END_ARCHIVE_SIGNATURE = b"PK\005\006"
END_ARCHIVE_SIZE = struct.calcsize(END_ARCHIVE_STRUCT)

# Central directory
CENTRAL_DIR_STRUCT = "<4s4B4HL2L5H2L"
CENTRAL_DIR_SIGNATURE = b"PK\001\002"
CENTRAL_DIR_SIZE = struct.calcsize(CENTRAL_DIR_STRUCT)

# Local file header
FILE_HEADER_STRUCT = "<4s2B4HL2L2H"
FILE_HEADER_SIGNATURE = b"PK\003\004"
FILE_HEADER_SIZE = struct.calcsize(FILE_HEADER_STRUCT)

# Zip64 end-of-central-directory locator
END_ARCHIVE64_LOCATOR_STRUCT = "<4sLQL"
END_ARCHIVE64_LOCATOR_SIGNATURE = b"PK\x06\x07"
END_ARCHIVE64_LOCATOR_SIZE = struct.calcsize(END_ARCHIVE64_LOCATOR_STRUCT)

# Zip64 end-of-central-directory record
END_ARCHIVE64_STRUCT = "<4sQ2H2L4Q"
END_ARCHIVE64_SIGNATURE = b"PK\x06\x06"
END_ARCHIVE64_SIZE = struct.calcsize(END_ARCHIVE64_STRUCT)

# Data descriptor
DD_SIGNATURE = 0x08074B50

# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------
ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1


def needs_zip64(*values: int, count: int = 0) -> bool:
    """Whether a size or offset, or an entry *count*, needs ZIP64 fields.

    A count of ``0xFFFF`` itself means "see the ZIP64 record", so it needs one.
    """
    return count >= ZIP_FILECOUNT_LIMIT or any(value > ZIP64_LIMIT for value in values)


CHUNK = 1 << 20  # bytes read at a time when streaming a member


def checksum(stream: IO[bytes]) -> tuple[int, int]:
    """The CRC-32 and length of what is left in *stream*, read to the end."""
    crc = size = 0
    while chunk := stream.read(CHUNK):
        crc = crc32(chunk, crc)
        size += len(chunk)
    return crc, size


# ---------------------------------------------------------------------------
# General purpose bit flags
# ---------------------------------------------------------------------------
MASK_ENCRYPTED = 1 << 0
MASK_COMPRESS_OPTION_1 = 1 << 1
# Bits 1 and 2: how the compressed stream was made (deflate level, LZMA end
# marker). A raw copy carries them over from the source.
MASK_COMPRESS_OPTIONS = 0b110
MASK_COMPRESSED_PATCH = 1 << 5
MASK_STRONG_ENCRYPTION = 1 << 6
MASK_UTF_FILENAME = 1 << 11

# ---------------------------------------------------------------------------
# Type aliases shared by the public-facing modules
# ---------------------------------------------------------------------------
StrPath: TypeAlias = str | os.PathLike[str]
ReadWriteMode: TypeAlias = Literal["r", "w"]


def sanitize_filename(filename: str) -> str:
    """Cut *filename* at its first null byte and use ``/`` as the only separator.

    A backslash is a separator on every platform, not only on Windows, so an
    archive means the same tree wherever it is read.
    """
    null_byte = filename.find("\x00")
    if null_byte >= 0:
        filename = filename[:null_byte]
    return filename.replace("\\", "/")


_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep


def user_stacklevel() -> int:
    """The ``stacklevel`` that makes a warning point at the caller of zipctl.

    Calls reach the warning through different depths of zipctl code
    (``writestr`` and ``write`` go through ``open``), so count them.  Dataclass
    machinery between zipctl frames counts as zipctl.
    """
    level = 1
    frame: FrameType | None = sys._getframe(1)  # pyright: ignore[reportPrivateUsage]  # documented CPython API
    while frame is not None and _is_internal(frame):
        frame = frame.f_back
        level += 1
    return level


def _is_internal(frame: FrameType) -> bool:
    """Whether *frame* runs zipctl code, or the dataclass code that calls it."""
    code = frame.f_code
    if code.co_filename.startswith(_PACKAGE_DIR):
        return True
    # A dataclass's generated ``__init__`` calling ``__post_init__``, and
    # ``dataclasses.replace`` calling that ``__init__``.
    return (code.co_filename == "<string>" and code.co_name == "__init__") or (
        code.co_filename == dataclasses.__file__
    )
