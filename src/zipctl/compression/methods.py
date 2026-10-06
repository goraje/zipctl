from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from typing_extensions import override

from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits

__all__ = [
    "BZIP2_VERSION",
    "LZMA_VERSION",
    "ZSTANDARD_VERSION",
    "ZIP_STORED",
    "ZIP_DEFLATED",
    "ZIP_BZIP2",
    "ZIP_LZMA",
    "ZIP_ZSTANDARD",
    "CompressorBase",
    "DecompressorBase",
    "CompressionEntry",
    "NoopCompressor",
    "NoopDecompressor",
]

# ---------------------------------------------------------------------------
# ZIP compression method IDs
# ---------------------------------------------------------------------------
ZIP_STORED = 0
ZIP_DEFLATED = 8
ZIP_BZIP2 = 12
ZIP_LZMA = 14
ZIP_ZSTANDARD = 93

# ---------------------------------------------------------------------------
# Minimum ZIP version-needed-to-extract for each compression method
# ---------------------------------------------------------------------------
BZIP2_VERSION = 46
LZMA_VERSION = 63
ZSTANDARD_VERSION = 63


class CompressorBase(ABC):
    """Abstract base class for all compressors."""

    @abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Compresses a chunk of data.

        Args:
            data: The raw bytes to compress.

        Returns:
            Compressed bytes. May be empty if data is buffered internally.
        """
        ...

    flag_bits: int = 0
    """General purpose flag bits the entry's headers carry for this stream."""

    @abstractmethod
    def flush(self) -> bytes:
        """Flushes any remaining buffered data and finalizes the stream."""
        ...


class NoopCompressor(CompressorBase):
    """Pass-through compressor used for ``ZIP_STORED`` entries."""

    @override
    def compress(self, data: bytes) -> bytes:
        return data

    @override
    def flush(self) -> bytes:
        return b""


class DecompressorBase(ABC):
    """Abstract base class defining the interface of every decompressor.

    A reader calls :meth:`decompress` with new input while :attr:`needs_input`
    is ``True`` and with ``b""`` while the decompressor still holds input or
    output of its own.  Once all input is in and a call returns nothing, it
    calls :meth:`finish`.  The decompressor decides where its stream ends: it
    raises :exc:`~zipctl.exceptions.BadZipFile` for input after the end, and
    :meth:`finish` raises it for a stream that has not ended.
    """

    @property
    def needs_input(self) -> bool:
        """Whether the decompressor wants more compressed input.

        ``False`` while it can still produce output from input it was given
        earlier; such a decompressor must override this.  ``True`` again once
        its stream has ended, so input after the end reaches :meth:`decompress`,
        which refuses it.
        """
        return True

    @abstractmethod
    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        """Decompress a chunk of data.

        Raises:
            BadZipFile: If *data* is invalid or comes after the stream's end.
        """
        ...

    @abstractmethod
    def finish(self) -> None:
        """Check that the stream ended, now that all input is in.

        Raises:
            BadZipFile: If it did not.
        """
        ...


def after_end(data: bytes) -> bytes:
    """What a decompressor whose stream has ended returns for *data*.

    Raises:
        BadZipFile: If there is any.
    """
    if data:
        raise BadZipFile("Data after the end of the compressed stream")
    return b""


def truncated() -> BadZipFile:
    """The error for a stream that ends before its end marker."""
    return BadZipFile("Truncated compressed stream")


class NoopDecompressor(DecompressorBase):
    """Pass-through decompressor used for ``ZIP_STORED`` entries.

    Input past *max_length* is kept and returned by later calls.
    """

    def __init__(self) -> None:
        self._buffer: bytes = b""

    @property
    @override
    def needs_input(self) -> bool:
        return not self._buffer

    @override
    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        data = self._buffer + data
        if max_length < 0:
            max_length = len(data)
        self._buffer = data[max_length:]
        return data[:max_length]

    @override
    def finish(self) -> None:
        pass


@dataclass(frozen=True)
class CompressionEntry:
    """Registry entry pairing a compressor and decompressor factory for a ZIP method.

    Attributes:
        compression_method: The ZIP compression method ID this entry handles.
        compressor_factory: Callable that accepts an optional compression level
            and returns a CompressorBase instance, or None.
        decompressor_factory: Callable that takes the entry's general purpose
            flag bits and the archive's limits and returns a DecompressorBase
            instance, or None.
        levels: The compression levels the compressor accepts, or ``None``
            when it takes none (a level given anyway is ignored).
    """

    compression_method: int
    compressor_factory: Callable[[int | None], CompressorBase | None]
    decompressor_factory: Callable[[int, ArchiveLimits], DecompressorBase | None]
    levels: range | None = None
